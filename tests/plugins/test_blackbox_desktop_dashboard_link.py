"""Hermes Desktop's door to the dashboard's API (desktop/dashboard_link.py), 2026-11-06.

The Desktop page shows every dashboard panel by forwarding an allowlisted set of the running
dashboard's own routes. These tests run a small fake dashboard on loopback and check: reads are
forwarded with the dashboard's Host and no Origin; a change carries the dashboard's change token,
fetched from /api/session and fetched again when the dashboard restarts (403); a route outside
the allowlist or a ``..`` path is refused without reaching the dashboard; and a dashboard that is
not running is a calm 503 ``dashboardDown`` answer.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from plugins.blackbox.desktop.dashboard_link import DashboardLink


class _FakeDashboard:
    """A loopback dashboard that records each request and enforces a change token like the real one."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.token = "token-1"
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):   # keep pytest output clean
                pass

            def _answer(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                fake.requests.append({"method": "GET", "path": self.path, "origin": self.headers.get("Origin"),
                                      "host": self.headers.get("Host")})
                if self.path == "/api/session":
                    return self._answer(200, {"token": fake.token})
                return self._answer(200, {"path": self.path})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                fake.requests.append({"method": "POST", "path": self.path, "token": self.headers.get("X-Blackbox-Token"),
                                      "body": body})
                if self.headers.get("X-Blackbox-Token") != fake.token:
                    return self._answer(403, {"error": "bad token"})
                return self._answer(200, {"ok": True, "saved": body})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def dashboard():
    fake = _FakeDashboard()
    yield fake
    fake.close()


def test_a_read_is_forwarded_like_the_dashboards_own_page(dashboard):
    answer = DashboardLink(dashboard.port).forward("GET", "api/graph-status", "tier=community")
    assert answer.status == 200 and answer.body == {"path": "/api/graph-status?tier=community"}
    seen = dashboard.requests[-1]
    assert seen["origin"] is None and seen["host"] == f"127.0.0.1:{dashboard.port}"


def test_a_change_carries_the_dashboards_change_token(dashboard):
    answer = DashboardLink(dashboard.port).forward("POST", "api/settings", "", {"mode": "block"})
    assert answer.status == 200 and answer.body["saved"] == {"mode": "block"}
    assert dashboard.requests[-1]["token"] == "token-1"


def test_a_restarted_dashboards_new_token_is_fetched_once(dashboard):
    link = DashboardLink(dashboard.port)
    link.forward("POST", "api/settings", "", {"mode": "audit"})
    dashboard.token = "token-2"            # the dashboard restarted
    answer = link.forward("POST", "api/settings", "", {"mode": "block"})
    assert answer.status == 200 and dashboard.requests[-1]["token"] == "token-2"


@pytest.mark.parametrize("method,path", [
    ("GET", "api/blackbox-chat"),
    ("GET", "api/session"),
    ("GET", "api/../api/session"),
    ("POST", "api/graph-status"),
    ("DELETE", "api/settings"),
    ("GET", "docs"),
])
def test_a_route_outside_the_allowlist_never_reaches_the_dashboard(dashboard, method, path):
    answer = DashboardLink(dashboard.port).forward(method, path)
    assert answer.status == 404 and dashboard.requests == []


def test_a_dashboard_that_is_not_running_is_a_calm_answer():
    fake = _FakeDashboard()
    port = fake.port
    fake.close()
    for method in ("GET", "POST"):
        answer = DashboardLink(port).forward(method, "api/settings", "", {"mode": "block"})
        assert answer.status == 503 and answer.body["dashboardDown"] is True


def test_every_panel_route_is_allowed():
    """The routes the Desktop panels read and change (keep in step with desktop/plugin.js)."""
    reads = ["api/findings", "api/audit", "api/graph-status", "api/verified-sync", "api/graph", "api/threat",
             "api/shields", "api/shields/trader/events", "api/agents", "api/community-stats", "api/reports",
             "api/trust", "api/settings", "shields/trader/content.json"]
    writes = ["api/settings", "api/agents/protection", "api/agents/rescan", "api/sync", "api/blackbox-chat",
              "api/playground/run", "api/playground/wallets/run"]
    assert all(DashboardLink.allowed("GET", path) for path in reads)
    assert all(DashboardLink.allowed("POST", path) for path in writes)


def test_every_route_the_desktop_panels_call_is_allowed():
    """desktop/plugin.js and the allowlist move together: a panel calling a route the link refuses
    would show "Could not load" in Desktop with no test to say why."""
    import re
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "desktop" / "plugin.js").read_text(encoding="utf-8")
    calls = re.findall(r"dash\(\s*'([^'?`]+)[^']*'\s*,\s*\{\s*method:\s*'POST'", source)
    reads = re.findall(r"useDash\(\s*'[^']+'\s*,\s*[`']([^'?`$]+)", source)
    assert calls and reads
    assert [path for path in calls if not DashboardLink.allowed("POST", path)] == []
    assert [path for path in reads if not DashboardLink.allowed("GET", path)] == []



def test_an_assistant_turn_and_a_playground_test_get_the_long_timeout(dashboard, monkeypatch):
    """A chat turn takes up to 120 s on the dashboard and a Playground test ~90 s; the 15 s read
    limit would cut both off (Desktop parity, 2026-11-07)."""
    import importlib
    link_module = importlib.import_module("plugins.blackbox.desktop.dashboard_link")   # the package's dashboard_link() shadows the name
    seen = []
    real = link_module.urllib.request.urlopen
    monkeypatch.setattr(link_module.urllib.request, "urlopen", lambda request, timeout: seen.append(timeout) or real(request, timeout=timeout))
    link = DashboardLink(dashboard.port)
    link.forward("POST", "api/blackbox-chat", "", {"message": "hi"})
    link.forward("POST", "api/settings", "", {"mode": "block"})
    assert seen[-1] == link_module._TIMEOUT_S and link_module._LONG_TIMEOUT_S in seen
