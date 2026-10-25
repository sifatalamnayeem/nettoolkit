"""Alert channels. Telegram is the main one; console is the fallback."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Optional, Protocol


class Notifier(Protocol):
    def send(self, text: str) -> bool: ...


class ConsoleNotifier:
    """Prints alerts to stdout. Used when Telegram is not configured."""

    def send(self, text: str) -> bool:
        print(f"[ALERT] {text}", flush=True)
        return True


class TelegramNotifier:
    API = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, token: str, chat_id: str, timeout: float = 10.0):
        if not token or not chat_id:
            raise ValueError("Telegram token and chat_id are required")
        self._token = token
        self.chat_id = str(chat_id)
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> Optional["TelegramNotifier"]:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat_id:
            return None
        return cls(token, chat_id)

    def send(self, text: str) -> bool:
        payload = json.dumps({"chat_id": self.chat_id, "text": text}).encode()
        req = urllib.request.Request(
            self.API.format(token=self._token),
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode() or "{}")
                return bool(body.get("ok"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # Deliberately print only the exception type: messages for some
            # errors can contain the request URL, which includes the bot token.
            print(f"telegram: send failed ({type(exc).__name__})", file=sys.stderr)
            return False


def notifier_from_env() -> tuple[Notifier, bool]:
    """Return (notifier, is_telegram). Falls back to console output."""
    tg = TelegramNotifier.from_env()
    if tg is not None:
        return tg, True
    return ConsoleNotifier(), False
