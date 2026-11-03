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
