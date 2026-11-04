"""Central configuration for ReconX.

API keys and tunables are read from environment variables so nothing secret
is ever hard-coded. External tool paths are auto-detected at runtime.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    return val if val not in (None, "") else default


@dataclass
class Settings:
    # Where the SQLite database and downloaded artifacts live.
    data_dir: Path = field(default_factory=lambda: Path(_env("RECONX_DATA_DIR", str(Path.home() / ".reconx"))))

    # Concurrency / politeness knobs (also enforced by the health monitor).
    http_concurrency: int = int(_env("RECONX_HTTP_CONCURRENCY", "30"))
    http_timeout: float = float(_env("RECONX_HTTP_TIMEOUT", "12"))
    request_delay_ms: int = int(_env("RECONX_REQUEST_DELAY_MS", "0"))
    user_agent: str = _env(
        "RECONX_USER_AGENT",
        "ReconX/0.1 (+authorized-bugbounty-recon)",
    )

    # Health monitor thresholds. If a target breaches these, heavy stages pause.
    health_interval_s: int = int(_env("RECONX_HEALTH_INTERVAL_S", "15"))
    health_timeout: float = float(_env("RECONX_HEALTH_TIMEOUT", "10"))
    health_fail_threshold: int = int(_env("RECONX_HEALTH_FAIL_THRESHOLD", "3"))
    health_slow_ms: int = int(_env("RECONX_HEALTH_SLOW_MS", "5000"))
    health_recover_threshold: int = int(_env("RECONX_HEALTH_RECOVER_THRESHOLD", "2"))

    # Asset discovery
    brute_force: bool = _env("RECONX_BRUTE", "1") not in ("0", "false", "no")
    subdomain_wordlist: str | None = _env("RECONX_SUBDOMAIN_WORDLIST")

    # Optional passive-source API keys (all optional; sources are skipped if absent).
    securitytrails_key: str | None = _env("SECURITYTRAILS_API_KEY")
    virustotal_key: str | None = _env("VIRUSTOTAL_API_KEY")
    shodan_key: str | None = _env("SHODAN_API_KEY")

    # Notification webhooks (optional).
    discord_webhook: str | None = _env("RECONX_DISCORD_WEBHOOK")
    slack_webhook: str | None = _env("RECONX_SLACK_WEBHOOK")
    telegram_bot_token: str | None = _env("RECONX_TELEGRAM_BOT_TOKEN")
    telegram_chat_id: str | None = _env("RECONX_TELEGRAM_CHAT_ID")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "reconx.db"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
