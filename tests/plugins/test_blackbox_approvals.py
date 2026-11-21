"""Turning protection DOWN needs the person's confirmation (Amos, 2026-11-21; moved from the Desktop
add-on into the core the same day).

Contracts: a weakening change is held (428) until the Desktop app answers with its key; an
approval applies exactly that change, once; strengthening applies at once; a request without the
dashboard's token is refused before it can raise a dialog; a program without the app's key can
neither approve nor re-pair.
"""

from __future__ import annotations

import json

import pytest
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox.kernel.browser_boundary import LOOPBACK_HOSTS, BrowserBoundary
from plugins.blackbox.approvals import store as store_mod, weakening
from plugins.blackbox.approvals.store import Approvals, answer_message, pair_message, sign
from plugins.blackbox.dashboard import approval_routes as gate

TOKEN = "session-token"
KEY = bytes(range(32))
CURRENT = weakening.Current(
    settings={"mode": "block", "block_severity": "high", "discover": True, "protected_paths": ["~/.ssh/*", "*.pem"],
              "categories": {"injection": {"enabled": True, "min_severity": "info"}}},
    shields={"network-shield": {"enabled": True, "protections": ["dns", "firewall"]}},
)


@pytest.fixture
def dashboard():
    """A dashboard as the plugin builds it: the token boundary, then the add-on's routes."""
    app, applied, approvals = FastAPI(), [], Approvals()
    BrowserBoundary(LOOPBACK_HOSTS, lambda _request: TOKEN).install(app)

    @app.post("/api/settings")
    def post_settings(payload: dict = Body(...)):
        applied.append(payload)
        return {"ok": True}

    gate.register(app, approvals)
    # The judge reads what is on now from a fixed view (the real one reads the plugin's settings).
    for layer in app.user_middleware:
        if layer.cls is gate.Gate:
            layer.kwargs["current"] = lambda: CURRENT
    client = TestClient(app, base_url="http://127.0.0.1")
    client.headers["X-Blackbox-Token"] = TOKEN
    return client, applied, approvals


def _post(client, body):
    return client.post("/api/settings", content=json.dumps(body), headers={"content-type": "application/json"})


def _approve(client, approvals, held_json, verb="approve", key=KEY):
    held = store_mod.Held(held_json["id"], held_json["route"], held_json["body_sha256"], (), 0)
    return client.post("/api/desktop/approvals/answer",
                       json={"id": held.id, "approve": verb == "approve", "proof": sign(key, answer_message(verb, held))})


def test_a_weakening_change_waits_for_the_person(dashboard):
    client, applied, approvals = dashboard
    approvals.pair(KEY.hex())
    answer = _post(client, {"mode": "audit"})
    assert answer.status_code == gate.HELD_STATUS and applied == []
    assert answer.json()["approval"]["reasons"] and "Audit" in answer.json()["approval"]["reasons"][0]


def test_approved_it_applies_exactly_that_change_once(dashboard):
    client, applied, approvals = dashboard
    approvals.pair(KEY.hex())
    held = _post(client, {"mode": "audit"}).json()["approval"]
    assert _approve(client, approvals, held).status_code == 200
    assert _post(client, {"mode": "audit", "discover": False}).status_code == gate.HELD_STATUS   # another body: not approved
    assert _post(client, {"mode": "audit"}).status_code == 200 and applied == [{"mode": "audit"}]
    assert _post(client, {"mode": "audit"}).status_code == gate.HELD_STATUS                      # once only


def test_denied_it_is_dropped(dashboard):
    client, applied, approvals = dashboard
    approvals.pair(KEY.hex())
    held = _post(client, {"mode": "audit"}).json()["approval"]
    assert _approve(client, approvals, held, verb="deny").status_code == 200
    assert approvals.waiting() == [] and _post(client, {"mode": "audit"}).status_code == gate.HELD_STATUS and applied == []


def test_without_the_apps_key_nobody_can_approve(dashboard):
    client, applied, approvals = dashboard
    approvals.pair(KEY.hex())
    held = _post(client, {"mode": "audit"}).json()["approval"]
    assert _approve(client, approvals, held, key=b"\x01" * 32).status_code == 403
    assert client.post("/api/desktop/approvals/answer", json={"id": held["id"], "approve": True}).status_code == 403
    assert _post(client, {"mode": "audit"}).status_code == gate.HELD_STATUS and applied == []


def test_before_desktop_pairs_a_weakening_change_still_waits(dashboard):
    client, applied, _approvals = dashboard
    answer = _post(client, {"mode": "audit"})
    assert answer.status_code == gate.HELD_STATUS and gate.NOT_PAIRED in answer.json()["errors"] and applied == []


def test_strengthening_and_unrelated_changes_apply_at_once(dashboard):
    client, applied, _approvals = dashboard
    for body in ({"mode": "block"}, {"block_severity": "medium"}, {"protected_paths": ["~/.ssh/*", "*.pem", ".env"]},
                 {"shields": {"network-shield": {"enabled": True, "protections": ["dns", "firewall", "agents"]}}}, {"report": False}):
        assert _post(client, body).status_code == 200
    assert len(applied) == 5


def test_a_request_without_the_dashboards_token_raises_no_dialog(dashboard):
    client, applied, approvals = dashboard
    answer = client.post("/api/settings", json={"mode": "audit"}, headers={"X-Blackbox-Token": "wrong"})
    assert answer.status_code == 403 and approvals.waiting() == [] and applied == []


def test_only_the_paired_app_can_pair_a_new_key(dashboard):
    client, _applied, _approvals = dashboard
    assert client.post("/api/desktop/approvals/pair", json={"key": KEY.hex()}).status_code == 200
    other = ("ab" * 32)
    assert client.post("/api/desktop/approvals/pair", json={"key": other}).status_code == 403          # an impostor
    assert client.post("/api/desktop/approvals/pair", json={"key": other, "proof": sign(KEY, pair_message(other))}).status_code == 200
    assert client.get("/api/desktop/approvals").json()["paired"] is True


def test_an_unanswered_request_expires():
    clock = {"now": 1000.0}
    approvals = Approvals(clock=lambda: clock["now"])
    approvals.pair(KEY.hex())
    approvals.hold("/api/settings", b"{}", ["x"])
    clock["now"] += store_mod.APPROVAL_TTL_SECONDS + 1
    assert approvals.waiting() == []


@pytest.mark.parametrize("route, body", [
    ("/api/settings", {"mode": "audit"}),
    ("/api/settings", {"block_severity": "critical"}),
    ("/api/settings", {"discover": False}),
    ("/api/settings", {"categories": {"injection": {"enabled": False}}}),
    ("/api/settings", {"categories": {"injection": {"min_severity": "high"}}}),
    ("/api/settings", {"protected_paths": ["~/.ssh/*"]}),
    ("/api/settings", {"shields": {"network-shield": {"enabled": False}}}),
    ("/api/settings", {"shields": {"network-shield": {"protections": ["dns"]}}}),
    ("/api/agents/protection", {"targets": [{"kind": "hermes", "target": "default", "enabled": False}]}),
    ("/api/agent-hooks/protection", {"kind": "claude-code", "enabled": False}),
    ("/api/shields/network-shield/api/tamper-guard", {"on": False}),
    ("/api/shields/network-shield/api/unblock-address", {"address": "203.0.113.9"}),
    ("/api/shields/network-shield/api/remote-settings", {"lock": False}),
    ("/api/shields/network-shield/api/remote-settings", {"brute_force": {"enabled": False}}),
])
def test_each_way_of_turning_protection_down_is_recognised(route, body):
    assert weakening.reasons(route, body, CURRENT)


@pytest.mark.parametrize("route, body", [
    ("/api/agents/protection", {"targets": [{"kind": "hermes", "target": "default", "enabled": True}]}),
    ("/api/agent-hooks/protection", {"kind": "claude-code", "enabled": True}),
    ("/api/shields/network-shield/api/tamper-guard", {"on": True}),
    ("/api/shields/network-shield/api/remote-settings", {"lock": True}),
])
def test_turning_protection_on_is_not_held(route, body):
    assert weakening.reasons(route, body, CURRENT) == []


def test_when_the_current_mode_cannot_be_read_audit_still_asks():
    assert weakening.reasons("/api/settings", {"mode": "audit"}, weakening.Current())

