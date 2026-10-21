"""Approval queue withdrawal when a WebSocket client cannot answer requests."""

import time

from tests.tui_gateway.test_protocol import _silent_ws, _ws_session

pytest_plugins = ["tests.tui_gateway.test_protocol"]


def test_approval_for_a_ws_client_that_never_advertised_settles_the_queue_entry(server, monkeypatch):
    """The approval wait is owned by ``tools.approval``'s queue, not by ``server_requests``. When the request
    cannot be sent (the only client predates server→client requests) the queue entry must be withdrawn too,
    otherwise ``_await_gateway_decision`` idles for the whole approvals.timeout with no prompt anywhere
    (#112548). The decision is a withdrawal (``cancelled`` cause), never a user deny."""
    from tools import approval as approval_mod
    from tools import approval_gateway_wait as wait_mod

    peer = _silent_ws()
    _ws_session(server, "ws-old-approval", peer)
    monkeypatch.setattr(wait_mod._ctx, "_get_approval_timeout", lambda: 3)
    monkeypatch.setattr(wait_mod._ctx, "_fire_approval_hook", lambda name, **kw: None)
    # Plugin discovery is outside this queue-withdrawal timing contract.
    monkeypatch.setattr("tools.human_input_hooks._fire", lambda name, payload: None)
    approval_mod.register_gateway_notify("ws-old-approval", lambda data: server._emit_approval_request("ws-old-approval", data))
    try:
        t0 = time.monotonic()
        decision = wait_mod._await_gateway_decision(
            "ws-old-approval", approval_mod._gateway_notify_cbs["ws-old-approval"],
            {"command": "rm -rf build", "description": "", "pattern_key": "dangerous", "pattern_keys": ["dangerous"]})
        waited = time.monotonic() - t0
    finally:
        approval_mod.unregister_gateway_notify("ws-old-approval")
    assert waited < 1, decision
    assert decision["choice"] is None and decision["cancelled"]
    assert peer.frames == []
    assert "ws-old-approval" not in approval_mod._gateway_queues
