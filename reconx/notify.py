"""Outbound notifications (Discord / Slack / Telegram).

Used for: new assets discovered on re-scan, high-severity findings, and health
alerts (target went down/degraded during scanning). All channels optional.
"""
from __future__ import annotations

import httpx

from .config import settings


async def send(message: str) -> None:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            if settings.discord_webhook:
                await client.post(settings.discord_webhook, json={"content": message[:1900]})
            if settings.slack_webhook:
                await client.post(settings.slack_webhook, json={"text": message[:3000]})
            if settings.telegram_bot_token and settings.telegram_chat_id:
                await client.post(
                    f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
                    json={"chat_id": settings.telegram_chat_id, "text": message[:4000]},
                )
        except Exception:
            pass
