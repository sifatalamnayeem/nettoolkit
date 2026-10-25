"""Tiny read-only web server for the dashboard (standard library only).

There is no authentication, so it binds to 127.0.0.1 by default. Do not expose
it to the internet without putting a reverse proxy with auth in front of it.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .. import storage
from . import api

STATIC_DIR = Path(__file__).parent / "static"
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class BadRequest(Exception):
    pass


def _int_param(query: dict, name: str, default: int, low: int, high: int) -> int:
    raw = query.get(name, [str(default)])[0]
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"'{name}' must be an integer")
    if not low <= value <= high:
        raise BadRequest(f"'{name}' must be between {low} and {high}")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "NetToolkitDashboard"

    def log_message(self, fmt, *args):
        if not getattr(self.server, "quiet", False):
            super().log_message(fmt, *args)

    # -- helpers --------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def _static(self, name: str) -> None:
        if name not in STATIC_FILES:  # whitelist: no path traversal possible
            return self._json(404, {"error": "not found"})
        body = (STATIC_DIR / name).read_bytes()
        self._send(200, body, STATIC_FILES[name])

    # -- routing --------------------------------------------------------
    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        path = url.path

        if path == "/":
            return self._static("index.html")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if not path.startswith("/api/"):
            return self._json(404, {"error": "not found"})

        conn = storage.connect(self.server.db_path)
        try:
            if path == "/api/overview":
                hours = _int_param(query, "hours", 24, 1, 24 * 90)
                return self._json(200, api.overview(conn, hours))
            if path == "/api/series":
                target = query.get("target", [""])[0]
                if not target:
                    raise BadRequest("'target' is required")
                hours = _int_param(query, "hours", 24, 1, 24 * 90)
                return self._json(200, api.check_series(conn, target, hours))
            if path == "/api/speed":
                limit = _int_param(query, "limit", 100, 1, 1000)
                return self._json(200, api.speed_series(conn, limit))
            return self._json(404, {"error": "not found"})
        except BadRequest as exc:
            return self._json(400, {"error": str(exc)})
        finally:
            conn.close()


def make_server(
    db_path: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 8000,
    quiet: bool = False,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.db_path = db_path
    server.quiet = quiet
    return server
