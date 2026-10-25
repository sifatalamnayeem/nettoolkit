import json
import os
import tempfile
from unittest import mock

from nettoolkit.cli import main
from tests._servers import local_server

NO_TELEGRAM = {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}


def test_monitor_once_and_status(capsys):
    with local_server() as url, tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "monitor.json")
        db = os.path.join(d, "test.db")
        with open(cfg, "w", encoding="utf-8") as fh:
            json.dump({"targets": [{"type": "http", "name": "local", "url": url}]}, fh)

        with mock.patch.dict(os.environ, NO_TELEGRAM):
            assert main(["monitor", "run", "-c", cfg, "--once", "--db", db]) == 0
        out = capsys.readouterr().out
        assert "UP" in out and "local" in out

        assert main(["monitor", "status", "--db", db, "--json"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data[0]["target"] == "local" and data[0]["currently_up"] is True


def test_monitor_once_exit_code_when_down(capsys):
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "monitor.json")
        with open(cfg, "w", encoding="utf-8") as fh:
            json.dump({"targets": [{"type": "tcp", "name": "dead", "host": "127.0.0.1", "port": 1}]}, fh)
        with mock.patch.dict(os.environ, NO_TELEGRAM):
            assert main(["monitor", "run", "-c", cfg, "--once", "--db", os.path.join(d, "t.db")]) == 1


def test_missing_config_is_clean_error(capsys):
    assert main(["monitor", "run", "-c", "/nonexistent/monitor.json", "--once"]) == 2
    assert "error" in capsys.readouterr().err


def test_speedlog_run_history_export(capsys):
    with local_server() as url, tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        assert main(["speedlog", "run", "--server", url, "--size", "0.1", "--db", db]) == 0
        capsys.readouterr()
        assert main(["speedlog", "history", "--db", db, "--json"]) == 0
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1 and rows[0]["download_mbps"] > 0

        csv_path = os.path.join(d, "out.csv")
        assert main(["speedlog", "export", csv_path, "--db", db]) == 0
        with open(csv_path, encoding="utf-8") as fh:
            assert len(fh.read().strip().splitlines()) == 2  # header + 1 row
