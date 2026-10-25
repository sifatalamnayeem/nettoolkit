import contextlib
import io
import json
import os
import urllib.error
from unittest import mock

from nettoolkit.alerts import TelegramNotifier, notifier_from_env, ConsoleNotifier

TOKEN = "123456:SECRET-TOKEN"


def _fake_response(body):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(body).encode()
    resp.__enter__.return_value = resp
    return resp


def test_telegram_send_builds_correct_request():
    with mock.patch("urllib.request.urlopen", return_value=_fake_response({"ok": True})) as urlopen:
        assert TelegramNotifier(TOKEN, "42").send("hello") is True
    req = urlopen.call_args[0][0]
    assert req.full_url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert json.loads(req.data) == {"chat_id": "42", "text": "hello"}


def test_telegram_failure_returns_false_and_hides_token():
    err = urllib.error.URLError("network down")
    stderr = io.StringIO()
    with mock.patch("urllib.request.urlopen", side_effect=err):
        with contextlib.redirect_stderr(stderr):
            assert TelegramNotifier(TOKEN, "42").send("hello") is False
    assert "SECRET-TOKEN" not in stderr.getvalue()


def test_from_env_fallback_to_console():
    with mock.patch.dict(os.environ, {}, clear=True):
        notifier, is_telegram = notifier_from_env()
    assert isinstance(notifier, ConsoleNotifier) and not is_telegram


def test_from_env_uses_telegram_when_configured():
    env = {"TELEGRAM_BOT_TOKEN": TOKEN, "TELEGRAM_CHAT_ID": "42"}
    with mock.patch.dict(os.environ, env, clear=True):
        notifier, is_telegram = notifier_from_env()
    assert isinstance(notifier, TelegramNotifier) and is_telegram
