"""One press finishes a held change (owner decision 7, engine build 2026-11-27;
plugins/blackbox/approvals/store.py ``Approvals.state``, dashboard/approval_routes ``GET
/api/approvals/{id}``, desktop/dashboard_link.py, desktop/plugin.js ``setMode``).

The Hermes Desktop page's Audit button is held for the person's approval (428). Before, once they
approved it the person had to press Audit a second time. Now the page reads where the held change
is and sends it again itself once it is approved. Contracts (red on the base 138eafb5bd):
* a held change reads ``waiting`` until the person answers, ``approved`` once they approve, and
  ``gone`` once it is applied, refused or never held — so a page never resends a refused change;
* sending the same change again after approval applies it exactly once;
* the Hermes Desktop link lets its page read that state (and nothing wider).
"""

from __future__ import annotations

import json

import pytest
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox.approvals import terminal as approvals_terminal, weakening
from plugins.blackbox.approvals.store import APPROVED, GONE, WAITING, Approvals
from plugins.blackbox.dashboard import approval_routes as gate
from plugins.blackbox.desktop.dashboard_link import DashboardLink
from plugins.blackbox.kernel.browser_boundary import LOOPBACK_HOSTS, BrowserBoundary

TOKEN = "session-token"
CURRENT = weakening.Current(settings={"mode": "block", "block_severity": "high"}, shields={})


@pytest.fixture
def dashboard(monkeypatch):
    monkeypatch.setattr(approvals_terminal, "needed", lambda: False)
    app, applied, store = FastAPI(), [], Approvals()
    BrowserBoundary(LOOPBACK_HOSTS, lambda _request: TOKEN).install(app)

    @app.post("/api/settings")
    def post_settings(payload: dict = Body(...)):
        applied.append(payload)
        return {"ok": True}

    gate.register(app, store=store)
    for layer in app.user_middleware:
        if layer.cls is gate.Gate:
            layer.kwargs["current"] = lambda: CURRENT
    client = TestClient(app, base_url="http://127.0.0.1")
    client.headers["X-Blackbox-Token"] = TOKEN
    return client, applied, store


def _audit(client):
    return client.post("/api/settings", content=json.dumps({"mode": "audit"}), headers={"content-type": "application/json"})


def _state(client, request_id):
    return client.get(f"/api/approvals/{request_id}").json()["state"]


def test_a_held_change_is_waiting_then_approved_then_gone_once_resent(dashboard):
    client, applied, store = dashboard
    held = _audit(client).json()["approval"]
    assert _state(client, held["id"]) == WAITING and applied == []
    assert store.approve_confirmed(held["id"])
    assert _state(client, held["id"]) == APPROVED
    assert _audit(client).status_code == 200 and applied == [{"mode": "audit"}]   # the page's resend
    assert _state(client, held["id"]) == GONE


def test_a_refused_or_unknown_change_reads_gone(dashboard):
    client, applied, store = dashboard
    assert _state(client, "0" * 24) == GONE
    held = _audit(client).json()["approval"]
    store.pair(bytes(range(32)).hex())
    from plugins.blackbox.approvals.store import answer_message, sign, Held
    proof = sign(bytes(range(32)), answer_message("deny", Held(held["id"], held["route"], held["body_sha256"], (), 0)))
    assert store.answer(held["id"], False, proof)
    assert _state(client, held["id"]) == GONE and applied == []


def test_the_hermes_desktop_page_may_read_a_held_changes_state_only():
    assert DashboardLink.allowed("GET", "api/approvals/0123456789abcdef01234567")
    assert not DashboardLink.allowed("GET", "api/approvals/confirm")
    assert not DashboardLink.allowed("POST", "api/approvals/0123456789abcdef01234567")
    assert not DashboardLink.allowed("GET", "api/approvals/../settings")
