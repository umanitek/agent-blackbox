"""The Hermes Desktop Audit / Block switch answers exactly as the dashboard's Settings does (review 2026-11-26, HIGH).

Turning Block off is a weakening change: through the dashboard's ``POST /api/settings`` it waits for
the person (the approvals gate answers 428 and applies nothing). The Hermes Desktop route
``POST /api/plugins/blackbox/mode`` (``desktop.set_mode``) used to write the config directly, so the
same change applied at once there. These contracts hold both doors to one answer:

- switching to Audit through ``set_mode`` is held, unapplied, with the same approval the dashboard
  gives for the same body;
- switching to Block (strengthening) applies at once on both doors;
- with no dashboard running, Audit is refused (nothing is written), never applied unconfirmed.
"""

from __future__ import annotations

import json

import pytest
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox import desktop
from plugins.blackbox.approvals import terminal as approvals_terminal
from plugins.blackbox.approvals.store import Approvals
from plugins.blackbox.dashboard import approval_routes as gate
from plugins.blackbox.desktop.dashboard_link import LinkAnswer
from plugins.blackbox.kernel import settings
from plugins.blackbox.kernel.browser_boundary import LOOPBACK_HOSTS, BrowserBoundary
from plugins.blackbox.kernel.config import load_blackbox_config

TOKEN = "session-token"


class _ClientLink:
    """Stands in for :class:`DashboardLink`: forwards to an in-process dashboard with its token."""

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def forward(self, method: str, path: str, query: str = "", body=None) -> LinkAnswer:
        answer = self.client.post("/" + path, content=json.dumps(body or {}),
                                  headers={"content-type": "application/json", "X-Blackbox-Token": TOKEN})
        return LinkAnswer(answer.status_code, answer.json())


@pytest.fixture
def gated(monkeypatch):
    """A dashboard as the plugin builds it — boundary, real settings writer, gate innermost — and
    ``desktop.dashboard_link`` pointing at it. Protection starts in Block mode."""
    monkeypatch.setattr(approvals_terminal, "needed", lambda: False)
    assert settings.write_settings({"mode": "block"}).get("ok")
    app = FastAPI()
    BrowserBoundary(LOOPBACK_HOSTS, lambda _request: TOKEN).install(app)

    @app.post("/api/settings")
    def post_settings(payload: dict = Body(...)):
        return settings.write_settings(payload)

    gate.register(app, store=Approvals())
    client = TestClient(app, base_url="http://127.0.0.1")
    monkeypatch.setattr(desktop, "dashboard_link", lambda: _ClientLink(client))
    return client


def test_audit_through_the_desktop_switch_waits_like_the_dashboard(gated):
    held = desktop.set_mode("audit")
    assert held["ok"] is False and held["mode"] == "block"
    assert held.get("approval", {}).get("reasons"), held
    assert load_blackbox_config().mode == "block"
    direct = gated.post("/api/settings", json={"mode": "audit"}, headers={"X-Blackbox-Token": TOKEN})
    assert direct.status_code == gate.HELD_STATUS
    assert direct.json()["approval"]["reasons"] == held["approval"]["reasons"]


def test_block_applies_at_once_on_the_desktop_switch(gated):
    settings.write_settings({"mode": "audit"})
    assert desktop.set_mode("block") == {"ok": True, "mode": "block", "errors": []}


def test_audit_with_no_dashboard_running_is_refused_and_writes_nothing(monkeypatch):
    assert settings.write_settings({"mode": "block"}).get("ok")

    class _Down:
        def forward(self, *_args, **_kwargs):
            return LinkAnswer(503, {"error": "the Blackbox dashboard is not running", "dashboardDown": True})

    monkeypatch.setattr(desktop, "dashboard_link", lambda: _Down())
    result = desktop.set_mode("audit")
    assert result["ok"] is False and result["errors"]
    assert load_blackbox_config().mode == "block"
