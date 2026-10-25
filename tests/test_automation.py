import json
import os
import stat
import tempfile

import nettoolkit.cli_automation as cli_automation
from nettoolkit.automation import Credentials, Device, backup_devices, load_inventory, run_commands
from nettoolkit.automation.backup import normalize
from nettoolkit.cli import main

CONFIG_V1 = "Building configuration...\n! Last configuration change at 10:00\nhostname sw1\ninterface Gi0/1\n shutdown\n"
CONFIG_V2 = "Building configuration...\n! Last configuration change at 11:30\nhostname sw1\ninterface Gi0/1\n no shutdown\n"


class FakeConn:
    def __init__(self, config, log):
        self.config, self.log = config, log

    def send_command(self, cmd):
        self.log.append(("cmd", cmd))
        return self.config

    def send_config_set(self, cmds):
        self.log.append(("config", list(cmds)))
        return "configured"

    def disconnect(self):
        self.log.append(("disconnect",))


def fake_connect(configs, log):
    def connect(device):
        value = configs[device.name]
        if isinstance(value, Exception):
            raise value
        return FakeConn(value, log)
    return connect


DEV = Device("sw1", "192.0.2.1", "cisco_ios")


# ---- inventory ------------------------------------------------------------

def _inv(d, data):
    path = os.path.join(d, "inv.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def test_inventory_ok_and_defaults():
    with tempfile.TemporaryDirectory() as d:
        devs = load_inventory(_inv(d, {"devices": [{"name": "sw1", "host": "10.0.0.1", "device_type": "cisco_ios"}]}))
    assert devs == [Device("sw1", "10.0.0.1", "cisco_ios", 22)]


def test_inventory_rejects_stored_passwords_and_bad_names():
    ok = {"name": "sw1", "host": "10.0.0.1", "device_type": "cisco_ios"}
    cases = [
        {**ok, "password": "hunter2"},
        {**ok, "Password": "hunter2"},
        {**ok, "name": "../../etc"},
        {**ok, "name": "a/b"},
        {**ok, "host": "10.0.0.1; rm -rf /"},
        {**ok, "device_type": ""},
        {**ok, "port": 70000},
    ]
    with tempfile.TemporaryDirectory() as d:
        for bad in cases:
            try:
                load_inventory(_inv(d, {"devices": [bad]}))
            except ValueError:
                continue
            raise AssertionError(f"accepted bad device: {bad}")
        try:
            load_inventory(_inv(d, {"devices": [ok, ok]}))
            raise AssertionError("duplicate accepted")
        except ValueError:
            pass


def test_credentials_repr_hides_password():
    assert "hunter2" not in repr(Credentials("admin", "hunter2", "enablepw"))


# ---- backup ---------------------------------------------------------------

def test_backup_new_unchanged_changed_and_private_files():
    log = []
    with tempfile.TemporaryDirectory() as out:
        r1 = backup_devices([DEV], fake_connect({"sw1": CONFIG_V1}, log), out)[0]
        assert r1.status == "new" and os.path.exists(r1.path)
        assert stat.S_IMODE(os.stat(r1.path).st_mode) == 0o600

        # Only volatile lines differ -> unchanged, and no new file is written
        r2 = backup_devices([DEV], fake_connect({"sw1": CONFIG_V1.replace("10:00", "10:05")}, log), out)[0]
        assert r2.status == "unchanged"
        assert len(os.listdir(os.path.join(out, "sw1"))) == 1

        import time; time.sleep(1.1)  # backup file names have 1 second resolution
        r3 = backup_devices([DEV], fake_connect({"sw1": CONFIG_V2}, log), out)[0]
        assert r3.status == "changed" and (r3.added, r3.removed) == (1, 1)
        assert "+ no shutdown" in r3.diff and "\n- shutdown" in r3.diff
        assert len(os.listdir(os.path.join(out, "sw1"))) == 2
    assert ("disconnect",) in log


def test_failure_of_one_device_does_not_stop_the_others():
    devs = [Device("a", "10.0.0.1", "cisco_ios"), Device("b", "10.0.0.2", "cisco_ios"), Device("c", "10.0.0.3", "cisco_ios")]
    configs = {"a": CONFIG_V1, "b": TimeoutError("timed out"), "c": ""}
    with tempfile.TemporaryDirectory() as out:
        results = backup_devices(devs, fake_connect(configs, []), out)
    assert [r.device for r in results] == ["a", "b", "c"]            # inventory order kept
    assert [r.status for r in results] == ["new", "failed", "failed"]
    assert "TimeoutError" in results[1].error and "empty" in results[2].error


def test_normalize_ignores_volatile_lines_and_blank_lines():
    assert normalize(CONFIG_V1) == ["hostname sw1", "interface Gi0/1", " shutdown"]


# ---- run ------------------------------------------------------------------

def test_show_commands_run_and_non_show_is_refused():
    log = []
    res = run_commands([DEV], fake_connect({"sw1": "ok"}, log), ["show version"])
    assert res[0].ok and "$ show version" in res[0].output
    for bad in (["reload"], ["show version", "write erase"], ["configure terminal"]):
        try:
            run_commands([DEV], fake_connect({"sw1": "ok"}, log), bad)
            raise AssertionError(f"allowed {bad}")
        except ValueError:
            pass


def test_config_is_dry_run_unless_applied():
    log = []
    res = run_commands([DEV], fake_connect({"sw1": "ok"}, log), ["interface Gi0/1", "no shutdown"], config_mode=True)
    assert res[0].sent is False and "(dry run) no shutdown" in res[0].output
    assert log == []                                   # never even connected

    res = run_commands([DEV], fake_connect({"sw1": "ok"}, log), ["no shutdown"], config_mode=True, apply=True)
    assert res[0].output == "configured" and ("config", ["no shutdown"]) in log


def test_comments_and_blank_lines_are_skipped():
    log = []
    run_commands([DEV], fake_connect({"sw1": "x"}, log), ["# comment", "", "show clock"])
    assert ("cmd", "show clock") in log and len([e for e in log if e[0] == "cmd"]) == 1


# ---- cli ------------------------------------------------------------------

def test_cli_backup_and_run(capsys):
    original = cli_automation.make_connect
    cli_automation.make_connect = lambda: fake_connect({"sw1": CONFIG_V1}, [])
    try:
        with tempfile.TemporaryDirectory() as d:
            inv = _inv(d, {"devices": [{"name": "sw1", "host": "10.0.0.1", "device_type": "cisco_ios"}]})
            assert main(["netauto", "backup", "-i", inv, "-o", os.path.join(d, "bk")]) == 0
            assert "NEW" in capsys.readouterr().out

            assert main(["netauto", "run", "-i", inv, "-c", "show version"]) == 0
            assert "=== sw1" in capsys.readouterr().out

            cfg = os.path.join(d, "change.txt")
            open(cfg, "w").write("interface Gi0/1\nno shutdown\n")
            assert main(["netauto", "run", "-i", inv, "--config-file", cfg]) == 0
            captured = capsys.readouterr()
            assert "Dry run only" in captured.err and "(dry run) no shutdown" in captured.out

            assert main(["netauto", "run", "-i", inv, "-c", "reload"]) == 2
            assert "not a read-only command" in capsys.readouterr().err
    finally:
        cli_automation.make_connect = original


def test_cli_missing_credentials_is_clean_error(capsys, monkeypatch=None):
    saved = {k: os.environ.pop(k, None) for k in ("NETTOOL_USER", "NETTOOL_PASS")}
    try:
        with tempfile.TemporaryDirectory() as d:
            inv = _inv(d, {"devices": [{"name": "sw1", "host": "10.0.0.1", "device_type": "cisco_ios"}]})
            assert main(["netauto", "backup", "-i", inv, "-o", os.path.join(d, "bk")]) == 2
        assert "NETTOOL_USER" in capsys.readouterr().err
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
