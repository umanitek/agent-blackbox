"""B7 contract: the dashboard's community tier is live AND hardened.

* /api/community-stats shape + zero-state.
* /api/graph?tier=community serves aggregated rows (sanitized).
* /api/reports serves live data + the outbound ledger (KI-006).
* Settings round-trip flips `report` (KI-005).
* KI-028 (LES-006): foreign Host/Origin rejected; mutations require the
  session token — loopback is not a browser boundary.
* Hostile community strings come back escaped + clamped (LES-001/002).
* No coming-soon strings in served payloads.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import ruleset as rs_mod
from plugins.blackbox.dashboard import server
from plugins.blackbox.ruleset import Ruleset


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
HOSTILE = "<script>alert(1)</script>\x1b[2J" + "A" * 600


def _community_ruleset() -> Ruleset:
    rs = Ruleset()
    rs.community = {
        "ioc:domain:evil.example": {
            "identifier": "ioc:domain:evil.example", "severity": "high",
            "source": "community", "reporterCount": 3, "iocType": "domain",
            "firstSeen": 1000.0, "lastSeen": 2000.0, "name": "ioc:domain:evil.example",
            "category": "ioc",
        },
        "dep:npm:evil@1": {
            "identifier": "dep:npm:evil@1", "severity": "critical",
            "source": "community", "reporterCount": 1, "name": HOSTILE,
            "category": "dep", "firstSeen": 1000.0, "lastSeen": 2000.0,
        },
    }
    rs.synced_at = 1234.5
    return rs


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setenv("BLACKBOX_COMMUNITY_GRAPH_ID", DEV_GRAPH)
    monkeypatch.setattr(rs_mod, "peek", lambda cfg: _community_ruleset())
    app = server.create_app()
    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c


# ---------------------------------------------------------------------------
# Browser boundary (KI-028 / LES-006)
# ---------------------------------------------------------------------------


def test_foreign_host_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    app = server.create_app()
    with TestClient(app, base_url="http://evil.example") as c:
        assert c.get("/api/settings").status_code == 403


def test_foreign_origin_rejected(client):
    res = client.post(
        "/api/settings",
        json={"report": True},
        headers={"Origin": "https://attacker.example"},
    )
    assert res.status_code == 403


def test_mutation_without_token_rejected(client):
    res = client.post("/api/settings", json={"report": True})
    assert res.status_code == 403
    assert "token" in res.json().get("error", "")


def test_mutation_with_token_passes_boundary(client, monkeypatch):
    from plugins.blackbox import settings as settings_mod

    saved = {}
    monkeypatch.setattr(settings_mod, "_persist", lambda updates: saved.update(updates) or True)
    token = client.get("/api/session").json()["token"]
    res = client.post(
        "/api/settings", json={"report": True}, headers={"X-Blackbox-Token": token}
    )
    assert res.status_code == 200
    assert saved.get("report") is True  # KI-005: the key round-trips


def test_reads_allowed_from_local_origin(client):
    res = client.get("/api/graph-status", headers={"Origin": "http://127.0.0.1:9700"})
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Live community surfaces
# ---------------------------------------------------------------------------


def test_community_stats_shape(client):
    stats = client.get("/api/community-stats").json()
    assert stats["configured"] is True
    assert stats["community_threats"] == 2
    assert stats["corroborated_2plus"] == 1
    assert stats["paused"] is False
    assert "last_refresh" in stats and "contributing_agents" in stats


def test_graph_tier_community_serves_rows(client):
    graph = client.get("/api/graph?tier=community").json()
    assert graph["tier"] == "community"
    idents = {t["identifier"] for t in graph["threats"]}
    assert "ioc:domain:evil.example" in idents
    by_id = {t["identifier"]: t for t in graph["threats"]}
    assert by_id["ioc:domain:evil.example"]["reporterCount"] == 3
    assert "coming_soon" not in graph


def test_hostile_community_strings_escaped_and_clamped(client):
    graph = client.get("/api/graph?tier=community").json()
    payload = json.dumps(graph)
    assert "<script>" not in payload  # escaped
    assert "\\u001b" not in payload  # control chars stripped
    for threat in graph["threats"]:
        assert len(threat.get("name") or "") <= 300  # clamped (256 + escapes)


def test_threat_detail_community(client):
    detail = client.get("/api/threat?tier=community&identifier=ioc:domain:evil.example").json()
    assert detail["found"] is True
    assert detail["reporters"] == 3
    assert "coming_soon" not in detail


def test_reports_endpoint_live_with_outbound_ledger(client, monkeypatch, tmp_path):
    from plugins.blackbox import audit

    audit.record_share_outcome(
        identifier="dep:npm:evil@1", category="dependency", severity="high",
        subject="urn:guardian:report:0xabc:dead", asset_name="report-x", ok=True,
    )
    payload = client.get("/api/reports").json()
    assert "coming_soon" not in payload
    assert isinstance(payload.get("outbound"), list)
    assert payload["outbound"][0]["identifier"] == "dep:npm:evil@1"


def test_no_coming_soon_in_key_payloads(client):
    for path in ("/api/graph-status", "/api/graph?tier=community", "/api/reports", "/api/community-stats"):
        body = json.dumps(client.get(path).json()).lower()
        assert "coming soon" not in body and "coming-soon" not in body, path
