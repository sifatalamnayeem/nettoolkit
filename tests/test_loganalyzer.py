import json
import os
import tempfile
from datetime import datetime

from nettoolkit.cli import main
from nettoolkit.loganalyzer import analyze, format_report, parse_lines
from nettoolkit.loganalyzer.parser import clean_text, parse_line

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "auth.sample.log")
NOW = datetime(2026, 10, 25, 20, 0, 0)


def _events(path=SAMPLE):
    with open(path, encoding="utf-8") as fh:
        return list(parse_lines(fh, year=2026, now=NOW))


# ---- parser ---------------------------------------------------------------

def test_parse_failed_invalid_and_accepted():
    failed = parse_line("Oct 25 02:14:03 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 5 ssh2", 2026)
    assert (failed.kind, failed.user, failed.ip, failed.method) == ("failed", "admin", "203.0.113.7", "password")
    invalid = parse_line("Oct 25 02:14:01 web01 sshd[1]: Invalid user admin from 203.0.113.7 port 5", 2026)
    assert invalid.kind == "invalid_user"
    ok = parse_line("Oct 25 09:02:11 web01 sshd[1]: Accepted publickey for deploy from 192.0.2.10 port 4 ssh2: ED25519 SHA256:x", 2026)
    assert (ok.kind, ok.user, ok.method) == ("accepted", "deploy", "publickey")


def test_parse_iso_timestamp_and_ipv6():
    line = "2026-10-25T02:14:03.123456+06:00 web01 sshd[9]: Failed password for root from 2001:db8::5 port 22 ssh2"
    event = parse_line(line)
    assert event.ip == "2001:db8::5"
    assert event.ts == datetime(2026, 10, 24, 20, 14, 3, 123456)  # converted to UTC


def test_unrelated_and_malformed_lines_are_ignored():
    assert parse_line("Oct 25 14:25:00 web01 sudo: alice : COMMAND=/bin/bash", 2026) is None
    assert parse_line("random text", 2026) is None
    assert parse_line("Oct 25 02:14:03 web01 sshd[1]: Failed password for root from 999.1.1.1 port 5 ssh2", 2026) is None
    assert parse_line("Feb 30 02:14:03 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2", 2026) is None


def test_year_inference_rolls_back_for_future_dates():
    now = datetime(2027, 1, 3, 12, 0, 0)
    event = parse_line("Dec 31 23:59:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2", now=now)
    assert event.ts.year == 2026


def test_clean_text_strips_terminal_escapes():
    nasty = "bob\x1b[31m\x07evil"
    assert "\x1b" not in clean_text(nasty) and "\x07" not in clean_text(nasty)
    assert len(clean_text("a" * 500)) <= 65


# ---- analyzer -------------------------------------------------------------

def test_sample_log_findings():
    report = analyze(_events(), threshold=5, window_minutes=10)
    ips = {b.ip: b for b in report.brute_force}
    assert set(ips) == {"203.0.113.7", "198.51.100.23"}
    # 8 Failed lines; the 3 matching "Invalid user" lines must not be double counted
    assert ips["203.0.113.7"].failures == 8
    assert ips["203.0.113.7"].distinct_users == 4
    assert report.brute_force[0].ip == "203.0.113.7"  # most failures first


def test_login_after_failures_is_flagged_but_normal_login_is_not():
    report = analyze(_events(), threshold=5)
    assert [s.ip for s in report.suspicious_logins] == ["198.51.100.23"]
    assert report.suspicious_logins[0].prior_failures == 6
    assert report.accepted_logins == 3


def test_window_matters():
    report = analyze(_events(), threshold=7, window_minutes=1)
    # 203.0.113.7 makes 8 attempts in ~50s, 198.51.100.23 only 6 in 32s
    assert [b.ip for b in report.brute_force] == ["203.0.113.7"]


def test_slow_attack_below_window_is_not_flagged():
    lines = [
        f"Oct 25 0{h}:00:00 h sshd[1]: Failed password for root from 192.0.2.99 port 5 ssh2"
        for h in range(1, 8)
    ]
    report = analyze(parse_lines(lines, year=2026), threshold=5, window_minutes=10)
    assert report.brute_force == []


def test_invalid_user_only_logs_still_count():
    lines = [
        f"Oct 25 02:00:{s:02d} h sshd[1]: Invalid user x{s} from 192.0.2.99 port 5" for s in range(6)
    ]
    report = analyze(parse_lines(lines, year=2026), threshold=5)
    assert report.brute_force and report.brute_force[0].failures == 6


def test_format_report_mentions_findings():
    text = format_report(analyze(_events()))
    assert "203.0.113.7" in text and "198.51.100.23" in text and "review these first" in text


# ---- cli ------------------------------------------------------------------

def test_cli_text_json_and_ips_only(capsys):
    assert main(["logscan", SAMPLE, "--year", "2026"]) == 0
    assert "203.0.113.7" in capsys.readouterr().out

    assert main(["logscan", SAMPLE, "--year", "2026", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["failed_attempts"] == 15

    assert main(["logscan", SAMPLE, "--year", "2026", "--ips-only"]) == 0
    assert capsys.readouterr().out.split() == ["203.0.113.7", "198.51.100.23"]


def test_cli_missing_file_is_clean_error(capsys):
    assert main(["logscan", "/nonexistent/auth.log"]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_empty_file_warns(capsys):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "empty.log")
        open(path, "w").close()
        assert main(["logscan", path]) == 0
    assert "No sshd login events" in capsys.readouterr().err
