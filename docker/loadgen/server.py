#!/usr/bin/env python3
"""CPU-burning HTTP server for load testing + HPA demos.

Tiny, dependency-free (stdlib only) HTTP service. Every request to /work
spends ~BURN_MS (env, default 100) of CPU doing sha256 work, so HTTP traffic
from Locust translates directly into sustained CPU utilisation — which is what
the HorizontalPodAutoscaler reacts to.
"""

import hashlib
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BURN_MS = int(os.environ.get("BURN_MS", "100"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))


def burn(ms: int) -> None:
    payload = bytes(1024 * 256)
    end = time.monotonic() + ms / 1000.0
    while time.monotonic() < end:
        hashlib.sha256(payload).digest()


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/work"):
            burn(BURN_MS)
            self._reply(200, b"ok\n")
        elif self.path in ("/", "/healthz", "/readyz"):
            self._reply(200, b"ok\n")
        else:
            self._reply(404, b"not found\n")

    def log_message(self, *args) -> None:  # keep the noise down
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()