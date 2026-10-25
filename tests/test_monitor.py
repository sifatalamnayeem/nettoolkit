import json
import os
import tempfile

import pytest

from nettoolkit import storage
from nettoolkit.monitor import CheckResult, Monitor, Target, load_config, run_check
from tests._servers import local_server


class FakeNotifier:
    def __init__(self):
        self.messages = []

    def send(self, text):
        self.messages.append(text)
        return True


def _scripted_checker(sequence):
    """Return a checker that yields up/down results from `sequence` in order."""
    it = iter(sequence)

    def checker(target):
        up = next(it)
        return CheckResult(target.name, "http", up, 10.0 if up else None, "ok" if up else "boom")

    return checker


def _http_target(name="site"):
    return Target.from_dict({"type": "http", "name": name, "url": "http://example.invalid"})


# ---- target validation ---------------------------------------------------

def test_target_rejects_unknown_type():
    with pytest.raises(ValueError):
        Target.from_dict({"type": "ftp", "host": "x"})


def test_target_rejects_non_http_urls():
    with pytest.raises(ValueError):
        Target.from_dict({"type": "http", "url": "file:///etc/passwd"})


def test_tcp_target_needs_port():
    with pytest.raises(ValueError):
        Target.from_dict({"type": "tcp", "host": "example.com"})


# ---- real checks against a local server ----------------------------------

def test_http_check_up_and_down():
    with local_server(200) as url:
        res = run_check(Target.from_dict({"type": "http", "url": url}))
        assert res.up and res.detail == "HTTP 200" and res.latency_ms is not None
    with local_server(500) as url:
        res = run_check(Target.from_dict({"type": "http", "url": url}))
        assert not res.up and res.detail == "HTTP 500"


def test_http_expect_status():
    with local_server(404) as url:
        res = run_check(Target.from_dict({"type": "http", "url": url, "expect_status": 404}))
        assert res.up


def test_http_unreachable():
    res = run_check(Target.from_dict({"type": "http", "url": "http://127.0.0.1:1", "timeout": 1}))
    assert not res.up and res.latency_ms is None


def test_tcp_check():
    with local_server() as url:
        port = int(url.rsplit(":", 1)[1])
        assert run_check(Target.from_dict({"type": "tcp", "host": "127.0.0.1", "port": port})).up
    assert not run_check(Target.from_dict({"type": "tcp", "host": "127.0.0.1", "port": 1})).up


# ---- alert state machine -------------------------------------------------

def test_alerts_only_on_state_change():
    notifier = FakeNotifier()
    seq = [False, False, False, False, True, True]
    mon = Monitor([_http_target()], notifier, fail_threshold=2, checker=_scripted_checker(seq))
    for _ in seq:
        mon.run_once()
    assert len(notifier.messages) == 2
    assert "DOWN" in notifier.messages[0]
    assert "RECOVERED" in notifier.messages[1]


def test_single_failure_does_not_alert():
    notifier = FakeNotifier()
    seq = [True, False, True, True]
    mon = Monitor([_http_target()], notifier, fail_threshold=2, checker=_scripted_checker(seq))
    for _ in seq:
        mon.run_once()
    assert notifier.messages == []


def test_results_are_stored():
    conn = storage.connect(":memory:")
    mon = Monitor([_http_target()], FakeNotifier(), conn=conn, checker=_scripted_checker([True, False]))
    mon.run_once()
    mon.run_once()
    assert conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 2
    latest = storage.latest_checks(conn)
    assert len(latest) == 1 and latest[0]["up"] == 0
    summary = storage.uptime_summary(conn, hours=1)
    assert summary[0]["uptime_pct"] == 50.0


# ---- config --------------------------------------------------------------

def _write_config(directory, data):
    path = os.path.join(directory, "monitor.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def test_load_config_ok():
    with tempfile.TemporaryDirectory() as d:
        path = _write_config(d, {
            "interval": 30,
            "targets": [{"type": "tcp", "host": "example.com", "port": 22}],
        })
        targets, settings = load_config(path)
        assert targets[0].name == "example.com:22"
        assert settings == {"interval": 30, "fail_threshold": 2}


def test_load_config_errors():
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError):
            load_config(os.path.join(d, "missing.json"))
        with pytest.raises(ValueError):
            load_config(_write_config(d, {"targets": []}))
        dup = {"type": "tcp", "name": "a", "host": "h", "port": 1}
        with pytest.raises(ValueError):
            load_config(_write_config(d, {"targets": [dup, dup]}))
