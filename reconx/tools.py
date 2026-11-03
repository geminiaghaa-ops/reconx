"""External tool integration layer.

ReconX is an orchestrator: it prefers best-in-class community tools when they
are installed, and transparently falls back to built-in pure-Python
implementations when they are not. This module detects what is available and
runs tools as subprocesses, streaming NDJSON/line output back to callers.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass


# Recommended tools, grouped by stage. Each maps the logical capability to the
# binary we shell out to. All are optional.
TOOLCHAIN = {
    "subdomains": ["subfinder", "assetfinder", "amass"],
    "dns": ["dnsx", "puredns", "massdns"],
    "ports": ["naabu"],
    "http": ["httpx"],
    "crawl": ["katana", "gau", "waybackurls", "gospider"],
    "js": ["retire"],          # retire.js for known-CVE library detection
    "vuln": ["nuclei"],
    "screenshot": ["gowitness"],
}


@dataclass
class ToolResult:
    ok: bool
    lines: list[str]
    error: str = ""


def which(name: str) -> str | None:
    return shutil.which(name)


def availability() -> dict[str, dict]:
    """Report which tools in the toolchain are installed."""
    out: dict[str, dict] = {}
    for stage, tools in TOOLCHAIN.items():
        out[stage] = {t: bool(which(t)) for t in tools}
    return out


async def verify_pd(name: str) -> bool:
    """Confirm a binary is the ProjectDiscovery tool and not a name collision
    (e.g. the Python `httpx` CLI shadowing ProjectDiscovery `httpx`)."""
    if not which(name):
        return False
    res = await run([name, "-version"], timeout=15)
    blob = (" ".join(res.lines) + " " + res.error).lower()
    import re as _re
    return ("projectdiscovery" in blob or "current version" in blob
            or bool(_re.search(r"v?\d+\.\d+\.\d+", blob)) and "could not run" not in blob)


def first_available(stage: str) -> str | None:
    for t in TOOLCHAIN.get(stage, []):
        if which(t):
            return t
    return None


# Human description of the built-in fallback for each stage (None = no fallback).
FALLBACK = {
    "subdomains": "crt.sh (Certificate Transparency)",
    "dns": "stdlib / dnspython resolver",
    "ports": "async TCP connect scan (top ports)",
    "http": "async HTTP probe + WAF/CDN fingerprint",
    "crawl": "built-in crawler",
    "js": "built-in JS analyzer (retire.js adds CVE libs)",
    "screenshot": "headless Chrome/Chromium",
    "vuln": None,  # nuclei has no built-in fallback
}

# One-line install hints per tool.
INSTALL = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "puredns": "go install github.com/d3mondev/puredns/v2@latest",
    "massdns": "https://github.com/blechschmidt/massdns",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "gospider": "go install github.com/jaeles-project/gospider@latest",
    "retire": "npm install -g retire",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
}


def _chrome_present() -> bool:
    import glob as _g
    if any(which(n) for n in ("google-chrome", "chromium", "chromium-browser", "chrome")):
        return True
    return bool(_g.glob("/opt/pw-browsers/chromium*/chrome-linux*/chrome")
                or _g.glob("/opt/pw-browsers/chromium*/chrome-linux*/headless_shell"))


async def plan() -> list[dict]:
    """What each stage will actually run, right now: the chosen engine (external
    tool or built-in fallback), plus which tools are missing and how to install
    them. Used by `cli.py tools` and the dashboard so nothing is a black box."""
    rows = []
    for stage, tool_list in TOOLCHAIN.items():
        installed = [t for t in tool_list if which(t)]
        missing = [t for t in tool_list if not which(t)]
        chosen = None
        note = ""

        if stage == "http":
            if "httpx" in installed and await verify_pd("httpx"):
                chosen = "httpx (ProjectDiscovery)"
            elif "httpx" in installed:
                note = "a non-ProjectDiscovery 'httpx' is on PATH and is ignored"
        elif stage == "js":
            chosen = "retire.js" if "retire" in installed else None
        elif stage == "screenshot":
            chosen = "gowitness" if "gowitness" in installed else None
        else:
            chosen = installed[0] if installed else None

        if chosen:
            engine, using_tool = chosen, True
        else:
            fb = FALLBACK.get(stage)
            if stage == "screenshot" and not _chrome_present():
                engine, using_tool = "DISABLED (no gowitness and no Chrome)", False
            elif fb:
                engine, using_tool = f"built-in: {fb}", False
            else:
                engine, using_tool = "DISABLED (no tool, no fallback)", False

        rows.append({
            "stage": stage, "engine": engine, "using_tool": using_tool,
            "note": note, "installed": installed, "missing": missing,
            "install": {t: INSTALL.get(t, "") for t in missing},
            "has_fallback": FALLBACK.get(stage) is not None or stage == "screenshot",
        })
    return rows


async def run(cmd: list[str], stdin: str | None = None, timeout: float = 900) -> ToolResult:
    """Run a subprocess, feed optional stdin, return stdout lines."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return ToolResult(False, [], f"not found: {cmd[0]}")
    except Exception as e:  # noqa: BLE001
        return ToolResult(False, [], f"spawn error: {e}")

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin else None), timeout=timeout
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return ToolResult(False, [], f"timeout after {timeout}s")

    lines = [l for l in stdout.decode("utf-8", "replace").splitlines() if l.strip()]
    err = stderr.decode("utf-8", "replace")[-2000:]
    return ToolResult(proc.returncode == 0 or bool(lines), lines, err)


def parse_jsonl(lines: list[str]) -> list[dict]:
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out
