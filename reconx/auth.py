"""Authenticated recon: inject a session (cookie / headers) into requests.

For sites behind a login you authenticate once in a browser and hand ReconX the
session cookie and/or an Authorization header. ReconX then sends it on every
HTTP request — but ONLY to in-scope hosts: the request event hook strips the
auth headers on any request (including a redirect) whose host is out of scope,
so your session can never leak to a third party / parent domain.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx

from .config import settings


@dataclass
class Auth:
    cookie: str = ""
    headers: dict = field(default_factory=dict)

    @classmethod
    def from_target(cls, t: dict | None) -> "Auth":
        t = t or {}
        cookie = (t.get("auth_cookie") or "").strip()
        raw = t.get("auth_headers") or ""
        hdrs: dict = {}
        if raw:
            try:
                hdrs = {str(k): str(v) for k, v in json.loads(raw).items()}
            except Exception:
                hdrs = {}
        return cls(cookie=cookie, headers=hdrs)

    @property
    def active(self) -> bool:
        return bool(self.cookie or self.headers)

    def auth_headers(self) -> dict:
        h = dict(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        return h

    def default_headers(self) -> dict:
        h = {"User-Agent": settings.user_agent}
        h.update(self.auth_headers())
        return h

    def client(self, scope=None, **kw) -> httpx.AsyncClient:
        """An AsyncClient that carries the auth headers but drops them for any
        out-of-scope host (initial request or redirect)."""
        auth_keys = {k.lower() for k in self.auth_headers()}

        async def _strip_hook(request: httpx.Request):
            if not auth_keys:
                return
            host = request.url.host or ""
            if scope is not None and not scope.in_scope(host):
                for k in list(request.headers.keys()):
                    if k.lower() in auth_keys:
                        del request.headers[k]

        kw.setdefault("timeout", settings.http_timeout)
        kw.setdefault("verify", False)
        return httpx.AsyncClient(
            headers=self.default_headers(),
            event_hooks={"request": [_strip_hook]},
            **kw,
        )

    def header_pairs(self) -> list[str]:
        """'-H'-style 'Name: value' pairs for external tools (nuclei, katana)."""
        return [f"{k}: {v}" for k, v in self.auth_headers().items()]


NO_AUTH = Auth()
