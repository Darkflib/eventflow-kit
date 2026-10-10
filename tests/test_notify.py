import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from eventflow_kit import notify


@pytest.fixture
def hub():
    received = []

    class Handler(BaseHTTPRequestHandler):
        status = 200

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers["Content-Type"], json.loads(body)))
            self.send_response(Handler.status)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server.url = f"http://127.0.0.1:{server.server_port}/notify/infra"
    server.received = received
    server.handler = Handler
    yield server
    server.shutdown()
    server.server_close()


def test_posts_the_hub_contract(hub):
    assert notify("Balance low", "namecheap: $4.20", type="warning", url=hub.url)
    path, content_type, payload = hub.received[0]
    assert path == "/notify/infra" and content_type == "application/json"
    assert payload == {
        "title": "Balance low",
        "body": "namecheap: $4.20",
        "type": "warning",
        "tag": "alerts",
    }


def test_url_from_environment_and_empty_body(hub, monkeypatch):
    monkeypatch.setenv("NOTIFY_URL", hub.url)
    assert notify("Just a title")
    assert hub.received[0][2]["body"] == "Just a title"
    assert hub.received[0][2]["type"] == "info"


def test_long_body_is_truncated(hub):
    assert notify("t", "x" * 10_000, url=hub.url)
    body = hub.received[0][2]["body"]
    assert len(body) == 3000 and body.endswith("…")


def test_unconfigured_is_a_noop(monkeypatch):
    monkeypatch.delenv("NOTIFY_URL", raising=False)
    assert notify("t") is False


def test_failures_return_false_and_never_raise(hub):
    hub.handler.status = 500
    assert notify("t", url=hub.url) is False
    assert notify("t", url="http://127.0.0.1:1/notify/infra", timeout=1) is False
    assert notify("t", url="file:///etc/passwd") is False
