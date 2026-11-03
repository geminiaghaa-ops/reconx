"""Scope enforcement.

Nothing is scanned unless it matches the target's in-scope rules and does not
match out-of-scope rules. This is the single most important guardrail for
authorized testing, so every module routes candidate hosts/URLs through here.
"""
from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse


def _strip_port(h: str) -> str:
    # strip a trailing :<digits> (e.g. example.com:8443 -> example.com); leave
    # bracketed IPv6 and plain hostnames untouched.
    import re as _re
    return _re.sub(r":\d+$", "", h)


def _host_of(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        return (urlparse(v).hostname or "").strip(".")
    # strip any path/port if present
    v = v.split("/")[0]
    v = v.split(":")[0]
    return v.strip(".")


class Scope:
    def __init__(self, root_domain: str, scope_in: str = "", scope_out: str = ""):
        self.root = _strip_port(root_domain.lower().strip().lstrip("*."))
        self.includes = [_strip_port(p) for p in (self._parse(scope_in) or [f"*.{self.root}", self.root])]
        self.excludes = [_strip_port(p) for p in self._parse(scope_out)]

    @staticmethod
    def _parse(blob: str) -> list[str]:
        if not blob:
            return []
        parts = re.split(r"[\s,;\n]+", blob.strip())
        return [p.lower().strip() for p in parts if p.strip()]

    def _matches(self, host: str, patterns: list[str]) -> bool:
        for pat in patterns:
            pat = pat.lstrip("*.")  # normalize: treat example.com and *.example.com the same for inclusion
            if host == pat or host.endswith("." + pat):
                return True
        return False

    def in_scope(self, value: str) -> bool:
        host = _host_of(value)
        if not host:
            return False
        if self.excludes and self._matches(host, [p.lstrip("*.") for p in self.excludes]):
            # also honor explicit exact exclusions / glob exclusions
            pass
        # exclusions first
        for pat in self.excludes:
            if fnmatch.fnmatch(host, pat) or host == pat.lstrip("*.") or host.endswith("." + pat.lstrip("*.")):
                return False
        # then inclusions
        for pat in self.includes:
            if fnmatch.fnmatch(host, pat) or host == pat.lstrip("*.") or host.endswith("." + pat.lstrip("*.")):
                return True
        return False

    def filter(self, values):
        return [v for v in values if self.in_scope(v)]
