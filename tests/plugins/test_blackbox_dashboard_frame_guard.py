"""No other page may frame the dashboard (clickjacking; review 2026-11-26, MED).

Contracts:
- every dashboard answer — the page, an API read, a refusal by the browser boundary — carries
  ``X-Frame-Options: DENY`` and ``Content-Security-Policy: frame-ancestors 'none'``;
- a route's own policy (a pack logo's ``default-src 'none'; …; sandbox``) keeps every directive and
  gains ``frame-ancestors 'none'``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox.dashboard import frame_guard, server
from plugins.blackbox.dashboard.shields_routes import LOGO_HEADERS


@pytest.fixture(scope="module")
def client():
    return TestClient(server.create_app(), base_url="http://127.0.0.1:9700")   # no startup: no background loops


@pytest.mark.parametrize("path,host", [("/", "127.0.0.1:9700"), ("/api/session", "127.0.0.1:9700"),
                                       ("/api/session", "evil.example")])
def test_every_answer_forbids_framing(client, path, host):
    answer = client.get(path, headers={"host": host})
    assert answer.headers.get("x-frame-options") == "DENY"
    assert "frame-ancestors 'none'" in answer.headers.get("content-security-policy", "")


def test_a_routes_own_policy_keeps_its_directives():
    headers = [(name.lower().encode(), value.encode()) for name, value in LOGO_HEADERS.items()]
    policy = dict(frame_guard.framed_headers(headers))[b"content-security-policy"].decode()
    assert policy.startswith(LOGO_HEADERS["Content-Security-Policy"]) and policy.endswith("frame-ancestors 'none'")
