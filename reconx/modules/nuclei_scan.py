"""Vulnerability scanning via nuclei (optional, authoritative).

Runs nuclei over the live URL surface with rate limiting. Skipped cleanly if
nuclei isn't installed. Only in-scope URLs reach this stage (enforced upstream
by the pipeline), and concurrency/rate are kept polite.
"""
from __future__ import annotations

from .. import tools


async def scan(urls: list[str], severity: str = "low,medium,high,critical",
               rate_limit: int = 50) -> list[dict]:
    if not tools.which("nuclei") or not urls:
        return []
    args = [
        "nuclei", "-silent", "-jsonl", "-no-color",
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-concurrency", "25",
    ]
    res = await tools.run(args, stdin="\n".join(urls), timeout=1800)
    findings = []
    for obj in tools.parse_jsonl(res.lines):
        info = obj.get("info", {})
        findings.append({
            "template": obj.get("template-id") or obj.get("templateID", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "matched_at": obj.get("matched-at") or obj.get("host", ""),
            "info": {
                "tags": info.get("tags", []),
                "description": (info.get("description") or "")[:500],
                "type": obj.get("type", ""),
            },
        })
    return findings
