"""B4 contract: agents join the community automatically; status tells the truth.

* ensure_community_subscription: idempotent subscribe of the verified graph WITH
  its shared memory, where the community lives (KI-007; one graph since
  2026-10-16), no join step for the public graph, fail-open always.
* Status renders the real community state for on/off/unconfigured configs.
* The empty ruleset is a loud UNPROTECTED state (KI-023).
* Terminal output of community-derived strings is ANSI-safe (KI-009).
"""

from __future__ import annotations

import argparse

import pytest

from plugins.blackbox import audit, cli
from plugins.blackbox.kernel import display_safety
from plugins.blackbox.community import membership
from plugins.blackbox.community.report_cli import report_command
from plugins.blackbox.sync import command as sync_command
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"


@pytest.fixture
def bb_home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


class FakeClient:
    def __init__(self, subscribe_fails=False):
        self.subscribes = []
        self.joins = []
        self.dials = []
        self._subscribe_fails = subscribe_fails

    def subscribe_context_graph(self, cg_id, include_shared_memory=False):
        if self._subscribe_fails:
            raise DkgError("node down")
        self.subscribes.append((cg_id, include_shared_memory))
        return {"jobId": "j1"}

    def request_join(self, cg_id, peer_id, agent_name="agent-blackbox"):
        self.joins.append((cg_id, peer_id))
        return {"delivered": 1}

    def connect_peer(self, peer_id):
        self.dials.append(peer_id)

    def reachable(self):
        return True

    def context_graphs(self):
        # The node lists a graph only once subscribed.
        return [{"id": cg_id, "subscribed": True, "accessPolicy": "public"} for cg_id, _ in self.subscribes]


# ---------------------------------------------------------------------------
# _ensure_community_subscription
# ---------------------------------------------------------------------------


def test_subscribe_includes_shared_memory():
    """KI-007: community reports live in SWM; the default subscribe excludes it."""
    cfg = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH)
    client = FakeClient()
    ok, _ = membership.ensure_community_subscription(client, cfg)
    assert ok is True
    assert client.subscribes == [(DEV_GRAPH, True)]


def test_no_graph_id_means_no_subscribe():
    client = FakeClient()
    ok, detail = membership.ensure_community_subscription(client, BlackboxConfig(context_graph_id=""))
    assert ok is False
    assert client.subscribes == []
    assert "no graph" in detail


def test_subscribe_failure_is_fail_open():
    cfg = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH)
    ok, detail = membership.ensure_community_subscription(FakeClient(subscribe_fails=True), cfg)
    assert ok is False
    assert "failed" in detail  # reported, never raised


def test_the_registered_public_graph_needs_no_owner_dial_and_no_join():
    """One graph (2026-10-16): the verified graph is registered on chain, so a fresh
    node finds it without dialling an owner peer (KI-216 was the unregistered community
    graph's problem), and it is public, so there is no join step (D-040)."""
    client = FakeClient()
    ok, _ = membership.ensure_community_subscription(client, BlackboxConfig(report=True, context_graph_id=DEV_GRAPH))
    assert ok is True
    assert client.subscribes == [(DEV_GRAPH, True)] and client.dials == [] and client.joins == []


# ---------------------------------------------------------------------------
# Status truth
# ---------------------------------------------------------------------------


def test_status_lines_sharing_on(bb_home, capsys):
    cfg = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH, daily_report_limit=50)
    report_command.print_community_status(cfg)
    out = capsys.readouterr().out
    assert DEV_GRAPH in out
    assert "threat sharing:    on (min severity high, cap 50/day)" in out
    assert "reports shared:    0" in out


def test_status_lines_sharing_off(bb_home, capsys):
    cfg = BlackboxConfig(report=False, context_graph_id=DEV_GRAPH)
    report_command.print_community_status(cfg)
    out = capsys.readouterr().out
    assert "threat sharing:    off — opt-in; `blackbox report --enable-sharing` turns it on" in out


def test_status_lines_switch_on_without_an_opt_in_reads_off(bb_home, capsys, real_consent):
    """`report: true` alone (a hand edit) is not sharing: status agrees with the share gate."""
    report_command.print_community_status(BlackboxConfig(report=True, context_graph_id=DEV_GRAPH))
    out = capsys.readouterr().out
    assert "threat sharing:    off — community sharing is off — `blackbox report --enable-sharing`" in out


def test_status_lines_unconfigured(bb_home, capsys):
    report_command.print_community_status(BlackboxConfig(context_graph_id=""))
    out = capsys.readouterr().out
    assert "no graph configured" in out
    assert "threat sharing" not in out  # no misleading sharing line without a graph


def test_status_shows_last_share_from_ledger(bb_home, capsys):
    audit.record_share_outcome(
        identifier="dep:npm:evil@1", category="dependency", severity="high",
        subject="urn:guardian:report:0xabc:deadbeef", asset_name="report-x", ok=True,
    )
    cfg = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH)
    report_command.print_community_status(cfg)
    out = capsys.readouterr().out
    assert "reports shared:    1" in out
    assert "dep:npm:evil@1" in out
    assert "ok" in out


def test_status_says_already_shared_for_a_refused_re_share_not_failed(bb_home, capsys):
    """KI-415: the network refuses a second copy of a report this node already shared (one
    report per reporter per threat) — the ledger records outcome "already-shared" with ok=False,
    and status printed FAILED for it (seen on the trader bench, 2026-10-15)."""
    audit.record_share_outcome(
        identifier="injection:abc", category="injection", severity="high",
        subject="urn:guardian:report:0xabc:feed", asset_name="report-y", ok=False,
        outcome="already-shared", error="already shared earlier; a same-version re-share is refused by peers",
    )
    report_command.print_community_status(BlackboxConfig(report=True, context_graph_id=DEV_GRAPH))
    out = capsys.readouterr().out
    assert "· already shared ·" in out and "FAILED" not in out


def test_status_still_says_failed_for_a_real_failure(bb_home, capsys):
    audit.record_share_outcome(
        identifier="injection:abc", category="injection", severity="high",
        subject="urn:guardian:report:0xabc:feed", asset_name="report-y", ok=False,
        outcome="failed", error="node unreachable",
    )
    report_command.print_community_status(BlackboxConfig(report=True, context_graph_id=DEV_GRAPH))
    assert "· FAILED ·" in capsys.readouterr().out


def test_ledger_identifiers_render_ansi_safe(bb_home, capsys):
    """KI-009: a hostile identifier cannot drive the terminal."""
    audit.record_share_outcome(
        identifier="dep:npm:evil\x1b[2J\x07@1", category="dependency", severity="high",
        subject="urn:guardian:report:0xabc:deadbeef", asset_name="report-x", ok=True,
    )
    cfg = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH)
    report_command.print_community_status(cfg)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x07" not in out


def test_term_safe_strips_controls_and_clamps():
    hostile = "evil\x1b[31mred\x9b2Jwipe" + "A" * 500
    safe = display_safety.term_safe(hostile, limit=100)
    assert "\x1b" not in safe and "\x9b" not in safe
    assert len(safe) <= 100


# ---------------------------------------------------------------------------
# UNPROTECTED state (KI-023)
# ---------------------------------------------------------------------------


def test_status_screams_when_ruleset_empty(bb_home, tmp_path, monkeypatch, capsys):
    """KI-023 on a machine that HAS Blackbox's DKG node (setup ran) but no rules yet. A machine
    where setup never ran says "SETUP NEEDED" instead (test_blackbox_catalog_only_install.py)."""
    dkg_command = tmp_path / "dkg"
    dkg_command.write_text("#!/bin/sh\n", encoding="utf-8")

    class EmptyRs:
        def counts(self):
            return {"injection": 0, "escalation": 0, "dependency": 0, "fileaccess": 0, "skill": 0, "ioc": 0, "community": 0}

    class QuietClient:
        def reachable(self):
            return False

    monkeypatch.setattr(cli, "load_blackbox_config", lambda: BlackboxConfig(dkg_bin=str(dkg_command)))
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
            return {"injection": 5, "escalation": 3, "dependency": 9, "fileaccess": 2, "skill": 1, "ioc": 4, "community": 0}

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
