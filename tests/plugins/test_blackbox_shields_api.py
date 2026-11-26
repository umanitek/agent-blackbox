"""A shield's own API (plugins/blackbox/shields/shield_api.py, shields.call_api and
dashboard/shields_routes/api_routes.py).

The contract: endpoints are looked up through the registry only (the dashboard never names a
shield); a read gets its query parameters and a write its JSON body, each with the context the
dashboard injects; an unknown shield or endpoint, or the wrong method, is 404; a refusal keeps
its status and message; anything else an endpoint raises is a plain 500; a write needs the
session token like every POST, and its body is capped before it is parsed.
"""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import shields
from plugins.blackbox.dashboard import server
from plugins.blackbox.shields.shield_api import MAX_WRITE_BYTES, ShieldApi, ShieldApiError

LOCAL = "http://127.0.0.1:9700"


def _context(**overrides):
    values = dict(network_indicators=lambda: None, ask_assistant=lambda message: shields.AssistantAnswer(ok=True, answer=message))
    values.update(overrides)
    return shields.ShieldContext(**values)


def _refuse(_context, _data):
    raise ShieldApiError(409, "switch the shield on first")


def _break(_context, _data):
    raise RuntimeError("boom")


API = ShieldApi(
    reads={"echo": lambda context, params: {"params": dict(params), "blocking": context.blocking},
           "refuse": _refuse, "break": _break},
    writes={"echo": lambda context, body: {"body": dict(body), "asked": context.ask_assistant("hi").answer}},
)


@pytest.fixture
def fake_shield(monkeypatch):
    """A registered shield with an API (the trader record, renamed and given endpoints)."""
    fake = dataclasses.replace(shields.get("trader"), id="fake", api=API)
    real_get = shields.get
    monkeypatch.setattr(shields, "get", lambda shield_id: fake if shield_id == "fake" else real_get(shield_id))
    return fake


def test_reads_get_params_and_writes_get_the_body_with_the_context(fake_shield):
    assert shields.call_api("fake", "GET", "echo", _context(blocking=True), {"a": "1"}) == {"params": {"a": "1"}, "blocking": True}
    assert shields.call_api("fake", "POST", "echo", _context(), {"x": 2}) == {"body": {"x": 2}, "asked": "hi"}


@pytest.mark.parametrize("shield_id, method, name", [
    ("nope", "GET", "echo"),       # unknown shield
    ("fake", "GET", "missing"),    # unknown endpoint
    ("fake", "DELETE", "echo"),    # no such method
    ("trader", "GET", "echo"),     # a shield without an API
])
def test_unknown_endpoints_are_404(fake_shield, shield_id, method, name):
    with pytest.raises(ShieldApiError) as refused:
        shields.call_api(shield_id, method, name, _context(), {})
    assert refused.value.status == 404


def test_a_refusal_keeps_its_status_and_a_crash_is_a_plain_500(fake_shield):
    with pytest.raises(ShieldApiError) as refused:
        shields.call_api("fake", "GET", "refuse", _context(), {})
    assert (refused.value.status, refused.value.message) == (409, "switch the shield on first")
    with pytest.raises(ShieldApiError) as crashed:
        shields.call_api("fake", "GET", "break", _context(), {})
    assert (crashed.value.status, crashed.value.message) == (500, "the shield could not answer")


@pytest.fixture
def client(tmp_path, monkeypatch, fake_shield):
    monkeypatch.setenv("HOME", str(tmp_path))   # never the real ~/.hermes
    with TestClient(server.create_app(), base_url=LOCAL) as test_client:
        yield test_client


def _token(client) -> dict:
    return {"X-Blackbox-Token": client.get("/api/session").json()["token"]}


def test_the_routes_serve_a_shields_endpoints_uncached(client):
    read = client.get("/api/shields/fake/api/echo?a=1")
    assert read.status_code == 200 and read.json()["params"] == {"a": "1"}
    assert read.headers["cache-control"] == "no-store"
    assert client.get("/api/shields/fake/api/refuse").json() == {"error": "switch the shield on first"}
    assert client.get("/api/shields/fake/api/Bad_Name").status_code == 404


def test_a_write_needs_the_session_token_and_a_bounded_json_object(client):
    assert client.post("/api/shields/fake/api/echo", json={"x": 1}).status_code in (401, 403)
    headers = _token(client)
    ok = client.post("/api/shields/fake/api/echo", headers=headers, json={"x": 1})
    assert ok.status_code == 200 and ok.json()["body"] == {"x": 1}
    assert client.post("/api/shields/fake/api/echo", headers=headers, json=[1, 2]).status_code == 400
    too_big = client.post("/api/shields/fake/api/echo", headers={**headers, "content-type": "application/json"},
                          content=b'{"x": "' + b"a" * MAX_WRITE_BYTES + b'"}')
    assert too_big.status_code == 413
