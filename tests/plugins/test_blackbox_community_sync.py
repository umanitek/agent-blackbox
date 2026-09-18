"""B4 contract: agents join the community graph automatically; status tells the truth.

* _ensure_community_subscription: idempotent subscribe WITH shared memory
  (KI-007, B1-proven), optional enrollment join (KI-040), fail-open always.
* Status renders the real community state for on/off/unconfigured configs.
* The empty ruleset is a loud UNPROTECTED state (KI-023).
* Terminal output of community-derived strings is ANSI-safe (KI-009).
"""

from __future__ import annotations

import argparse

import pytest

from plugins.blackbox import audit, cli
from plugins.blackbox.config import BlackboxConfig


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
CURATOR_PEER = "12D3KooWCyWdwd5NA2H9XnJ1B1ZUe4GLcw9wsu3SdKTAvCvuPfgA"


@pytest.fixture
def bb_home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


class FakeClient:
    def __init__(self, subscribe_fails=False, join_fails=False):
        self.subscribes = []
        self.joins = []
        self._subscribe_fails = subscribe_fails
        self._join_fails = join_fails

    def subscribe_context_graph(self, cg_id, include_shared_memory=False):
        if self._subscribe_fails:
            raise RuntimeError("node down")
        self.subscribes.append((cg_id, include_shared_memory))
        return {"jobId": "j1"}

    def request_join(self, cg_id, peer_id, agent_name="agent-blackbox"):
        if self._join_fails:
            raise RuntimeError("curator unreachable")
        self.joins.append((cg_id, peer_id))
        return {"delivered": 1}

    def reachable(self):
        return True


# ---------------------------------------------------------------------------
# _ensure_community_subscription
# ---------------------------------------------------------------------------


def test_subscribe_includes_shared_memory():
    """KI-007: community reports live in SWM; the default subscribe excludes it."""
    cfg = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH)
    client = FakeClient()
    ok, _ = cli._ensure_community_subscription(client, cfg)
    assert ok is True
    assert client.subscribes == [(DEV_GRAPH, True)]


def test_no_graph_id_means_no_subscribe():
    client = FakeClient()
    ok, detail = cli._ensure_community_subscription(client, BlackboxConfig())
    assert ok is False
    assert client.subscribes == []
    assert "no community graph" in detail


def test_subscribe_failure_is_fail_open():
    cfg = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH)
    ok, detail = cli._ensure_community_subscription(FakeClient(subscribe_fails=True), cfg)
    assert ok is False
    assert "failed" in detail  # reported, never raised


def test_join_requested_when_curator_peer_known():
    cfg = BlackboxConfig(
        report=True, community_graph_id=DEV_GRAPH, community_graph_peer_id=CURATOR_PEER
    )
    client = FakeClient()
    ok, _ = cli._ensure_community_subscription(client, cfg)
    assert ok is True
    assert client.joins == [(DEV_GRAPH, CURATOR_PEER)]


def test_join_failure_never_breaks_subscription():
    cfg = BlackboxConfig(
        report=True, community_graph_id=DEV_GRAPH, community_graph_peer_id=CURATOR_PEER
    )
    ok, _ = cli._ensure_community_subscription(FakeClient(join_fails=True), cfg)
    assert ok is True


# ---------------------------------------------------------------------------
# Status truth
# ---------------------------------------------------------------------------


def test_status_lines_sharing_on(bb_home, capsys):
    cfg = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH, daily_report_limit=50)
    cli._print_community_status(cfg)
    out = capsys.readouterr().out
    assert DEV_GRAPH in out
    assert "threat sharing:    on (min severity high, cap 50/day)" in out
    assert "reports shared:    0" in out


def test_status_lines_sharing_off(bb_home, capsys):
    cfg = BlackboxConfig(report=False, community_graph_id=DEV_GRAPH)
    cli._print_community_status(cfg)
    out = capsys.readouterr().out
    assert "threat sharing:    off (config key `report` is false)" in out


def test_status_lines_unconfigured(bb_home, capsys):
    cli._print_community_status(BlackboxConfig())
    out = capsys.readouterr().out
    assert "not configured" in out
    assert "threat sharing" not in out  # no misleading sharing line without a graph


def test_status_shows_last_share_from_ledger(bb_home, capsys):
    audit.record_share_outcome(
        identifier="dep:npm:evil@1", category="dependency", severity="high",
        subject="urn:guardian:report:0xabc:deadbeef", asset_name="report-x", ok=True,
    )
    cfg = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH)
    cli._print_community_status(cfg)
    out = capsys.readouterr().out
    assert "reports shared:    1" in out
    assert "dep:npm:evil@1" in out
    assert "ok" in out


def test_ledger_identifiers_render_ansi_safe(bb_home, capsys):
    """KI-009: a hostile identifier cannot drive the terminal."""
    audit.record_share_outcome(
        identifier="dep:npm:evil\x1b[2J\x07@1", category="dependency", severity="high",
        subject="urn:guardian:report:0xabc:deadbeef", asset_name="report-x", ok=True,
    )
    cfg = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH)
    cli._print_community_status(cfg)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x07" not in out


def test_term_safe_strips_controls_and_clamps():
    hostile = "evil\x1b[31mred\x9b2Jwipe" + "A" * 500
    safe = cli._term_safe(hostile, limit=100)
    assert "\x1b" not in safe and "\x9b" not in safe
    assert len(safe) <= 100


# ---------------------------------------------------------------------------
# UNPROTECTED state (KI-023)
# ---------------------------------------------------------------------------


def test_status_screams_when_ruleset_empty(bb_home, monkeypatch, capsys):
    class EmptyRs:
        def counts(self):
            return {"injection": 0, "escalation": 0, "dependency": 0, "fileaccess": 0, "skill": 0}

    class QuietClient:
        def reachable(self):
            return False

    monkeypatch.setattr(cli, "load_blackbox_config", lambda: BlackboxConfig())
    monkeypatch.setattr(cli, "DkgClient", lambda **kw: QuietClient())
    monkeypatch.setattr(cli.ruleset, "get", lambda cfg: EmptyRs())
    monkeypatch.setattr(cli.audit, "count_findings", lambda: 0)
    monkeypatch.setattr(cli, "_print_attached_targets", lambda: None)
    cli._cmd_status(argparse.Namespace())
    out = capsys.readouterr().out
    assert "UNPROTECTED" in out
    assert "blackbox sync" in out


def test_status_quiet_when_rules_present(bb_home, monkeypatch, capsys):
    class FullRs:
        def counts(self):
            return {"injection": 5, "escalation": 3, "dependency": 9, "fileaccess": 2, "skill": 1}

    class QuietClient:
        def reachable(self):
            return True

    monkeypatch.setattr(cli, "load_blackbox_config", lambda: BlackboxConfig())
    monkeypatch.setattr(cli, "DkgClient", lambda **kw: QuietClient())
    monkeypatch.setattr(cli.ruleset, "get", lambda cfg: FullRs())
    monkeypatch.setattr(cli.audit, "count_findings", lambda: 0)
    monkeypatch.setattr(cli, "_print_attached_targets", lambda: None)
    cli._cmd_status(argparse.Namespace())
    out = capsys.readouterr().out
    assert "UNPROTECTED" not in out
