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
            "category": "ioc", "stage": "corroborated", "enforcement": "flag",
            "stageReason": "corroborated by 1 partner and 2 established cluster(s)", "disputed": "no",
        },
        "dep:npm:evil@1": {
            "identifier": "dep:npm:evil@1", "severity": "critical",
            "source": "community", "reporterCount": 1, "name": HOSTILE,
            "category": "dep", "firstSeen": 1000.0, "lastSeen": 2000.0,
        },
    }
    rs.synced_at = 1234.5
    rs.community_fingerprint = "fp-community-v1"
    return rs


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setenv("BLACKBOX_CONTEXT_GRAPH_ID", DEV_GRAPH)   # the community lives in this graph (one graph since 2026-10-16)
    monkeypatch.setattr(rs_mod, "peek", lambda cfg: _community_ruleset())
    app = server.create_app()
    with TestClient(app, base_url="http://127.0.0.1:9700") as c:   # the dashboard's own port (KI-390: the Origin must match it)
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
    from plugins.blackbox.kernel import settings as settings_mod

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


def test_hostile_community_strings_stripped_and_clamped(client):
    """R8 / KI-191: JSON carries plain text — the page HTML-escapes exactly
    once at insertion, so the payload is NOT entity-escaped (that produced the
    double-escaped ``&amp;lt;`` on the benches); controls are stripped, free
    text clamped, hostnames in free text defanged."""
    graph = client.get("/api/graph?tier=community").json()
    payload = json.dumps(graph)
    assert "&lt;" not in payload  # not escaped here
    assert "\\u001b" not in payload  # control chars stripped
    for threat in graph["threats"]:
        assert len(threat.get("name") or "") <= 256 + 3 * 16  # clamped before defanging adds "[.]"


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


def test_agents_endpoint_returns_ok(client):
    """FIX-0010 regression: /api/agents crashed with a TypeError because the
    reporters lookup called _swr() without its required `default` argument —
    the dashboard's connected-agents panel hung on "Loading agents…" forever.
    """
    resp = client.get("/api/agents")
    assert resp.status_code == 200
    assert "agents" in resp.json()


def test_graph_tier_community_categories_are_canonical_and_carry_the_stage(client):
    """KI-197: a store entry named `dep` reaches the page as `dependency` (the only names the colour
    table knows); KI-198: the R3 stage fields the leaves show are served, not dropped."""
    graph = client.get("/api/graph?tier=community").json()
    by_id = {t["identifier"]: t for t in graph["threats"]}
    assert by_id["dep:npm:evil@1"]["category"] == "dependency"
    assert set(graph["category_totals"]) <= {"dependency", "injection", "escalation", "fileaccess", "skill", "secret", "ioc", "other"}
    evil = by_id["ioc:domain:evil.example"]
    assert (evil["stage"], evil["enforcement"], evil["disputed"]) == ("corroborated", "flag", "no")
    assert evil["stageReason"].startswith("corroborated by")


# ---------------------------------------------------------------------------
# FIX-0038: the Community tab reloads on the tier's OWN version
# ---------------------------------------------------------------------------


def test_graph_status_carries_the_community_tier_version(client):
    """A pulse changes the community tier without moving last_sync; the page
    needs a version that moves with the tier (the content fingerprint)."""
    status = client.get("/api/graph-status").json()
    assert status["community_version"] == "fp-community-v1"
    assert status["last_sync"] == 1234.5


def test_graph_status_community_version_is_null_before_any_tier(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setattr(rs_mod, "peek", lambda cfg: Ruleset())
    with TestClient(server.create_app(), base_url="http://127.0.0.1") as c:
        assert c.get("/api/graph-status").json()["community_version"] is None


def test_dashboard_page_keys_community_reload_on_the_tier_version():
    """Server key and page key must move together (the earlier fix, 58b963c119,
    keyed the Community reload on last_sync only and went blind on a node that
    never syncs the verified graph)."""
    from pathlib import Path

    from plugins.blackbox import dashboard as dashboard_pkg

    page = (Path(dashboard_pkg.__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    assert "status.community_version" in page
    assert 'resetGraphOnVersionChange("community", previousCommunityVersion' in page
