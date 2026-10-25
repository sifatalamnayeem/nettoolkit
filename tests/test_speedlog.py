import pytest

from nettoolkit import storage
from nettoolkit.speedlog import run_speedtest
from tests._servers import local_server


def test_speedtest_against_local_server():
    with local_server() as url:
        res = run_speedtest(server=url, download_mb=0.2, upload_mb=0.1)
    assert res.ping_ms is not None
    assert res.download_mbps and res.download_mbps > 0
    assert res.upload_mbps and res.upload_mbps > 0


def test_speedtest_without_upload():
    with local_server() as url:
        res = run_speedtest(server=url, download_mb=0.1, do_upload=False)
    assert res.upload_mbps is None


def test_unreachable_server_raises():
    with pytest.raises(RuntimeError):
        run_speedtest(server="http://127.0.0.1:1", download_mb=0.1, timeout=1)


def test_invalid_server_url():
    with pytest.raises(ValueError):
        run_speedtest(server="ftp://example.com")


def test_speed_storage_roundtrip():
    conn = storage.connect(":memory:")
    assert storage.speed_averages(conn) is None
    storage.save_speed(conn, storage.now_iso(), 20.0, 100.0, 50.0, "s")
    storage.save_speed(conn, storage.now_iso(), 40.0, 200.0, None, "s")
    rows = storage.recent_speed(conn, 10)
    assert [r["ping_ms"] for r in rows] == [20.0, 40.0]
    avg = storage.speed_averages(conn)
    assert avg["runs"] == 2 and avg["download_mbps"] == 150.0
