"""Screenshots of live hosts for fast visual triage.

Preferred: gowitness. Fallback: a headless Chrome/Chromium invocation (the same
browser Playwright/Puppeteer use). Eyeballing a wall of screenshots is one of
the fastest ways to spot login panels, dev/staging, default pages and oddities.
"""
from __future__ import annotations

import asyncio
import glob
import hashlib
import os
import shutil
from pathlib import Path

from .. import tools

_CHROME_FLAGS = [
    "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
    "--disable-background-networking", "--disable-component-update",
    "--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-features=Translate,BackForwardCache",
]


def find_chrome() -> str | None:
    if os.environ.get("CHROME_PATH") and Path(os.environ["CHROME_PATH"]).exists():
        return os.environ["CHROME_PATH"]
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "headless_shell"):
        p = shutil.which(name)
        if p:
            return p
    for pat in ("/opt/pw-browsers/chromium-*/chrome-linux*/chrome",
                "/opt/pw-browsers/chromium-*/chrome-linux*/headless_shell",
                "/opt/pw-browsers/chromium_headless_shell-*/chrome-linux*/headless_shell"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def _name_for(url: str) -> str:
    return hashlib.sha1(url.encode()).hexdigest()[:16] + ".png"


async def capture(urls: list[str], out_dir: str | Path, concurrency: int = 3,
                  timeout: float = 30) -> dict[str, str]:
    """Return {url: screenshot_path} for successful captures."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Preferred: gowitness.
    if tools.which("gowitness"):
        res = await tools.run(["gowitness", "scan", "single", "--screenshot-path", str(out_dir)],
                              timeout=60)  # probed below per-url if this form unsupported
        # gowitness CLIs vary a lot across versions; fall through to chrome if nothing produced.

    chrome = find_chrome()
    if not chrome:
        return {}

    sem = asyncio.Semaphore(concurrency)
    results: dict[str, str] = {}

    async def shot(url: str):
        async with sem:
            out = out_dir / _name_for(url)
            cmd = [chrome, *_CHROME_FLAGS, f"--screenshot={out}", "--window-size=1440,900", url]
            r = await tools.run(cmd, timeout=timeout)
            if out.exists() and out.stat().st_size > 0:
                results[url] = str(out)

    await asyncio.gather(*(shot(u) for u in urls))
    return results
