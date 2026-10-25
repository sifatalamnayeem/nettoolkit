"""A tiny local HTTP server used by the tests (no internet needed)."""

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _reply(self, status, body=b"ok"):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/__down":
            size = int(parse_qs(url.query)["bytes"][0])
            self._reply(200, bytes(size))
        else:
            self._reply(self.server.status)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._reply(200)


@contextmanager
def local_server(status=200):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.status = status
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
