import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from nettoolkit import demo, storage
from nettoolkit.dashboard import api, make_server


def _seeded_conn():
    conn = storage.connect(":memory:")
    demo.seed(conn, days=1)
    return conn


# ---- api ------------------------------------------------------------------

def test_overview_lists_targets_problems_first():
    conn = storage.connect(":memory:")
    ts = storage.now_iso()
    storage.save_check(conn, ts, "good", "http", True, 10.0, "HTTP 200")
    storage.save_check(conn, ts, "bad", "tcp", False, None, "refused")
    data = api.overview(conn, hours=1)
    assert [t["name"] for t in data["targets"]] == ["bad", "good"]
    assert data["targets"][0]["up"] is False
    assert data["speed"] == {"latest": None, "averages": None}


def test_series_is_downsampled_and_keeps_last_point():
    conn = _seeded_conn()
    data = api.check_series(conn, "Google", hours=48, max_points=50)
    assert len(data["points"]) <= 51
    newest = conn.execute(
        "SELECT ts FROM checks WHERE target='Google' ORDER BY ts DESC LIMIT 1"
    ).fetchone()[0]
    assert data["points"][-1]["ts"] == newest


def test_demo_data_contains_an_outage():
    conn = _seeded_conn()
    summary = {r["target"]: r["uptime_pct"] for r in storage.uptime_summary(conn, hours=48)}
    assert summary["Google"] == 100.0
    assert summary["Office SSH"] < 100.0


# ---- http server ----------------------------------------------------------

@contextmanager
def running_dashboard():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "t.db")
        conn = storage.connect(db)
        demo.seed(conn, days=1)
        conn.close()
        server = make_server(db, "127.0.0.1", 0, quiet=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_index_and_static_files_with_security_headers():
    with running_dashboard() as base:
        status, headers, body = _get(base + "/")
        assert status == 200 and b"NetToolkit" in body
        assert "script-src 'self'" in headers["Content-Security-Policy"]
        assert headers["X-Content-Type-Options"] == "nosniff"
        for name, kind in (("app.js", "javascript"), ("style.css", "css")):
            status, headers, _ = _get(f"{base}/static/{name}")
            assert status == 200 and kind in headers["Content-Type"]


def test_api_endpoints():
    with running_dashboard() as base:
        status, _, body = _get(base + "/api/overview?hours=24")
        data = json.loads(body)
        assert status == 200 and len(data["targets"]) == 4
        assert data["speed"]["latest"]["download_mbps"] > 0

        status, _, body = _get(base + "/api/series?target=Google&hours=24")
        assert status == 200 and len(json.loads(body)["points"]) > 10

        status, _, body = _get(base + "/api/speed?limit=5")
        assert status == 200 and len(json.loads(body)["points"]) == 5


def test_bad_requests_are_rejected():
    with running_dashboard() as base:
        assert _get(base + "/api/overview?hours=abc")[0] == 400
        assert _get(base + "/api/overview?hours=0")[0] == 400
        assert _get(base + "/api/series")[0] == 400
        assert _get(base + "/api/speed?limit=99999")[0] == 400
        assert _get(base + "/api/nope")[0] == 404
        assert _get(base + "/nope")[0] == 404


def test_static_path_traversal_is_blocked():
    with running_dashboard() as base:
        for path in ("/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/api.py"):
            assert _get(base + path)[0] == 404
