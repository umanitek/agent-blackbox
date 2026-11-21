"""Every list has a DIRECTION, and a shield judges its own writes (E2E on bb-e2e-1121, 2026-11-21).

Found on the VM: widening the SSH allow-list applied with no confirmation (200, no 428) — the
gate only treated REMOVING entries as weakening. Contracts: on an allow-list (names never
blocked, hosts an agent may reach, who may SSH in) ADDING an entry waits for the person; on every
other list REMOVING one does; Network Shield's own writes that turn protection down (remote
unlock, a looser brute-force rule, unblocking, the tamper guard off, undoing a posture fix) wait
too, and the writes that only strengthen apply at once.
"""

from __future__ import annotations

import json

import pytest
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox.approvals import weakening
from plugins.blackbox.approvals.store import Approvals
from plugins.blackbox.dashboard import approval_routes as gate
from plugins.blackbox.kernel.browser_boundary import LOOPBACK_HOSTS, BrowserBoundary
from plugins.blackbox.shields.network.protect import posture_fix, remote_lock, tamper_guard

NET = "network-shield"
ALLOW = frozenset({"allow", "agent_hosts", "ssh_allow"})
NOW = {"enabled": True, "protections": ["dns", "firewall"], "lists": ["hagezi-multi"], "allow": ["ok.example"],
       "block": ["bad.example"], "agent_hosts": ["github.com"], "ssh_allow": ["192.168.1.5"]}
CURRENT = weakening.Current(settings={"mode": "block"}, shields={NET: NOW}, allow_lists={NET: ALLOW})


def _reasons(option, values):
    return weakening.reasons("/api/settings", {"shields": {NET: {option: values}}}, CURRENT)


@pytest.mark.parametrize("option, wider", [
    ("ssh_allow", ["192.168.1.5", "192.168.64.0/24"]),
    ("allow", ["ok.example", "tracker.example"]),
    ("agent_hosts", ["github.com", "paste.example"]),
])
def test_adding_to_an_allow_list_waits_and_removing_from_it_does_not(option, wider):
    assert _reasons(option, wider), f"growing {option} must ask"
    assert _reasons(option, []) == [], f"shrinking {option} only protects more"


@pytest.mark.parametrize("option, narrower, wider", [
    ("block", [], ["bad.example", "worse.example"]),
    ("protections", ["dns"], ["dns", "firewall", "cut"]),
    ("lists", [], ["hagezi-multi", "oisd-small"]),
])
def test_removing_from_a_protecting_list_waits_and_adding_to_it_does_not(option, narrower, wider):
    assert _reasons(option, narrower), f"shrinking {option} must ask"
    assert _reasons(option, wider) == []


def test_the_registry_declares_network_shield_allow_lists():
    assert ALLOW <= weakening.Current.read().allow_lists.get(NET, frozenset())


@pytest.fixture
def state(monkeypatch):
    rules = {"lock": True, "brute_force": {"enabled": True, "failures": 5, "window_minutes": 10, "block_minutes": 60},
             "blocked": []}
    monkeypatch.setattr(remote_lock, "settings", lambda now=None: rules)
    monkeypatch.setattr(tamper_guard, "is_on", lambda: True)
    monkeypatch.setattr(posture_fix, "wanted", lambda: ["firewall-on"])
    return rules


def _shield_reasons(name, body):
    return weakening.reasons(f"/api/shields/{NET}/api/{name}", body, CURRENT)


@pytest.mark.parametrize("name, body", [
    ("remote-settings", {"lock": False}),
    ("remote-settings", {"brute_force": {"enabled": False}}),
    ("remote-settings", {"brute_force": {"failures": 20}}),
    ("remote-settings", {"brute_force": {"window_minutes": 2}}),
    ("remote-settings", {"brute_force": {"block_minutes": 5}}),
    ("unblock-address", {"ip": "203.0.113.9"}),
    ("tamper-guard", {"on": False}),
    ("posture-fix", {"fix": "firewall-on", "apply": False}),
])
def test_network_shield_writes_that_weaken_wait(state, name, body):
    assert weakening.gated(f"/api/shields/{NET}/api/{name}")
    assert _shield_reasons(name, body), f"{name} {body} must ask"


@pytest.mark.parametrize("name, body", [
    ("remote-settings", {"lock": True}),
    ("remote-settings", {"brute_force": {"failures": 3, "window_minutes": 30, "block_minutes": 120}}),
    ("tamper-guard", {"on": True}),
    ("posture-fix", {"fix": "stealth-on", "apply": True}),
])
def test_network_shield_writes_that_strengthen_apply_at_once(state, name, body):
    assert _shield_reasons(name, body) == []


def test_a_write_with_no_judge_is_not_gated():
    assert not weakening.gated(f"/api/shields/{NET}/api/block-address")
    assert not weakening.gated("/api/shields/no-such-shield/api/anything")


def test_the_gate_holds_a_widened_ssh_allow_list_end_to_end(state):
    app, applied = FastAPI(), []
    BrowserBoundary(LOOPBACK_HOSTS, lambda _request: "t").install(app)

    @app.post(f"/api/shields/{NET}/api/remote-settings")
    def remote(payload: dict = Body(...)):
        applied.append(payload)
        return {"ok": True}

    gate.register(app, store=Approvals())
    for layer in app.user_middleware:
        if layer.cls is gate.Gate:
            layer.kwargs["current"] = lambda: CURRENT
    client = TestClient(app, base_url="http://127.0.0.1")
    answer = client.post(f"/api/shields/{NET}/api/remote-settings", content=json.dumps({"lock": False}),
                         headers={"content-type": "application/json", "X-Blackbox-Token": "t"})
    assert answer.status_code == gate.HELD_STATUS and applied == []
    stronger = client.post(f"/api/shields/{NET}/api/remote-settings", content=json.dumps({"lock": True}),
                           headers={"content-type": "application/json", "X-Blackbox-Token": "t"})
    assert stronger.status_code == 200 and applied == [{"lock": True}]
