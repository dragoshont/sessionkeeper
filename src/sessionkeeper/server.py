"""Minimal HTTP server: /metrics, /healthz, /readyz, /status.

Cluster-internal only (scraped by Prometheus). Uses stdlib http.server in a
background thread so the scheduler owns the main thread.
"""
from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .metrics import Metrics

log = logging.getLogger("sessionkeeper.server")


def _make_handler(metrics: Metrics, ready: threading.Event):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
            payload = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                self._send(200, metrics.render(),
                           "text/plain; version=0.0.4; charset=utf-8")
            elif path == "/healthz":
                self._send(200, "ok\n")
            elif path == "/readyz":
                self._send(200 if ready.is_set() else 503,
                           "ready\n" if ready.is_set() else "not-ready\n")
            elif path == "/status":
                self._send(200, metrics.render(),
                           "text/plain; charset=utf-8")
            else:
                self._send(404, "not found\n")

        def log_message(self, *args) -> None:  # silence default stderr spam
            return

    return Handler


def serve(metrics: Metrics, port: int, ready: threading.Event) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _make_handler(metrics, ready))
    thread = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    thread.start()
    log.info("metrics/health server on :%d", port)
    return httpd
