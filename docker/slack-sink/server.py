#!/usr/bin/env python3
"""Local Slack (webhook) sink for the observability platform.

The platform's SlackNotifier POSTs to SLACK_WEBHOOK_URL. Instead of a real
Slack workspace, this tiny inbox accepts any POST, replies 200 ok (what the
Slack API would return), and appends the payload to a log file so you can
inspect what "Slack" notifications the platform would have sent.

    docker compose exec slack-sink cat /data/messages.log
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = os.environ.get("LOG_PATH", "/data/messages.log")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "5050"))

os.makedirs(os.path.dirname(LOG), exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "path": self.path,
            "body": body,
        }
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # keep the noise down
        pass


if __name__ == "__main__":
    HTTPServer((HOST, PORT), Handler).serve_forever()