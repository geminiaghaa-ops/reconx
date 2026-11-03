"""Small shared helpers."""
from __future__ import annotations

import re
from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    """Turn whatever the user typed into a bare hostname.

    Accepts full URLs, host:port, trailing paths, wildcards, etc.
      https://centinsur.ir/fa-ir/portal/1/page/x  -> centinsur.ir
      http://sub.example.com:8443/a?b=1            -> sub.example.com
      *.example.com                                -> example.com
      EXAMPLE.com.                                 -> example.com
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if "://" in s:
        host = urlparse(s).hostname or ""
    else:
        # strip any path, query, or fragment the user pasted
        host = re.split(r"[/?#]", s, 1)[0]
    host = host.strip().strip(".").lower().lstrip("*.")
    host = re.sub(r":\d+$", "", host)          # drop port
    return host
