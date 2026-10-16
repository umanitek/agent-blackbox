"""Refine R15 — the shadow phase: stages computed and logged on the real
network, only MONITOR enforced, nothing community-derived user-visible; the
§12 metrics come from the refresh log, and the newcomer calibration gap from
the curator's ledger.

* With community_shadow on, every community rule records the enforcement it
  WOULD have had and is clamped to monitor; nothing materializes into the
  matchable lookups, so the hook never flags a community match.
* Each refresh appends one snapshot (bounded file); the snapshot carries the
  stage / would-enforce distributions, delta share, reporters, time to
  corroborated, counted vs unlisted.
* The calibration gap is rejection rate unlisted / counted; > 2× flags a review.
* The config flag parses from the entry and the environment.
"""

from __future__ import annotations

import json
import os

import pytest

from _community_rows import GRAPH
from plugins.blackbox.community import reputation, shadow
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import community_tier, compiler, refresh_cycle
from test_blackbox_community_ruleset import FakeClient

NOW = 1_800_000_000.0
THREAT = "ioc:domain:shadowed.example"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


def _listed_view():
    keys = [f"p{i:02d}".ljust(64, "0") for i in range(3)]
    counted = {k: cv.CountedAuthor(k, "0x" + k[:40], "partner", f"org{i}", "2027-01-01") for i, k in enumerate(keys)}
    return cv.CuratorView(counted=counted), keys


def test_shadow_clamps_every_community_rule_to_monitor_and_keeps_what_it_computed():
    community = {THREAT: {"identifier": THREAT, "stage": "corroborated", "enforcement": "flag", "stageReason": "corroborated by 3 partner cluster(s)"},
                 "dep:npm:x@1": {"identifier": "dep:npm:x@1", "stage": "reported", "enforcement": "monitor", "stageReason": "unlisted"}}
    assert shadow.clamp_to_monitor(community) == 1
    assert community[THREAT]["enforcement"] == "monitor" and community[THREAT]["shadowEnforcement"] == "flag"
    assert community[THREAT]["stageReason"].endswith(shadow.SHADOW_SUFFIX)
    assert community["dep:npm:x@1"]["shadowEnforcement"] == "monitor"
    assert shadow.clamp_to_monitor(community) == 0 and community[THREAT]["stageReason"].count("shadow") == 1   # idempotent


def test_in_shadow_mode_nothing_community_derived_becomes_matchable(monkeypatch):
    """A corroborated threat from three partner clusters WOULD flag; in shadow it is monitor-only and never materializes."""
    view, keys = _listed_view()
    monkeypatch.setattr(community_tier.community, "read_verified_reports",
                        lambda client, cfg, **kw: type("R", (), {"available": True, "reports": _reports(keys), "curator": view,
                                                                   "disputes": (), "retractions": (), "state": None})())
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    monkeypatch.setattr(community_tier.community, "community_pause_active", lambda client, cfg: False)
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW)
    prior = compiler.Ruleset()                                                # seen 10 days ago: the span is met
    prior.community = {THREAT: {"identifier": THREAT, "firstSeen": NOW - 10 * 86_400}}
    live = compiler.Ruleset()
    community_tier.apply_community_tier(live, FakeClient(), BlackboxConfig(context_graph_id=GRAPH), prior)
    assert live.community[THREAT]["enforcement"] == "flag" and THREAT in live.ioc
    shadowed = compiler.Ruleset()
    community_tier.apply_community_tier(shadowed, FakeClient(), BlackboxConfig(context_graph_id=GRAPH, community_shadow=True), prior)
    assert shadowed.community[THREAT]["enforcement"] == "monitor" and shadowed.community[THREAT]["shadowEnforcement"] == "flag"
    assert THREAT not in shadowed.ioc                                        # the hook can never match it
    assert shadowed.community[THREAT]["stage"] == "corroborated"             # the stage is still computed and logged


def _reports(keys):
    from plugins.blackbox.community import VerifiedReport
    return tuple(VerifiedReport(subject=f"urn:guardian:report:0x{k[:40]}:{i}", identifier=THREAT, author=k, reporter="0x" + k[:40],
                                severity="high", fields=(("ioc_type", "domain"),)) for i, k in enumerate(keys))


def test_the_snapshot_carries_the_section_12_numbers_and_the_file_is_bounded(tmp_path):
    rs = compiler.Ruleset(synced_at=NOW)
    rs.community = {
        THREAT: {"identifier": THREAT, "stage": "corroborated", "enforcement": "monitor", "shadowEnforcement": "flag",
                 "reporterCount": 3, "counted": "3", "firstSeen": NOW - 4 * 86_400},
        "dep:npm:known@1": {"identifier": "dep:npm:known@1", "stage": "reported", "enforcement": "monitor", "shadowEnforcement": "monitor",
                            "reporterCount": 1, "counted": "0", "firstSeen": NOW - 86_400},
    }
    rs.dependency["npm:known@1"] = {"identifier": "dep:npm:known@1", "source": "public", "severity": "high"}
    snapshot = shadow.build_snapshot(rs, NOW)
    assert snapshot.stages == {"corroborated": 1, "reported": 1} and snapshot.would_enforce == {"flag": 1, "monitor": 1}
    assert (snapshot.community_total, snapshot.already_verified, snapshot.counted, snapshot.unlisted) == (2, 1, 1, 1)
    assert snapshot.delta_share == 0.5 and snapshot.reporters_median == 2.0 and snapshot.days_to_corroborated_median == 4.0
    path = tmp_path / "shadow_metrics.jsonl"
    for _ in range(shadow.MAX_SNAPSHOTS + 5):
        shadow.write_snapshot(snapshot, path)
    assert len(path.read_text(encoding="utf-8").splitlines()) == shadow.MAX_SNAPSHOTS
    assert shadow.latest(path) == snapshot and len(shadow.read_all(path)) == shadow.MAX_SNAPSHOTS
    assert shadow.latest(tmp_path / "missing.jsonl") is None
    (tmp_path / "garbage.jsonl").write_text("{nope\n", encoding="utf-8")
    assert shadow.read_all(tmp_path / "garbage.jsonl") == []


def test_the_refresh_logs_a_snapshot_only_in_shadow_mode(monkeypatch):
    written = []
    monkeypatch.setattr(community_tier.community.shadow, "write_snapshot", lambda snap: written.append(snap))
    rs = compiler.Ruleset(synced_at=NOW)
    community_tier.record_shadow_metrics(rs, BlackboxConfig(context_graph_id=GRAPH))
    assert written == []
    community_tier.record_shadow_metrics(rs, BlackboxConfig(context_graph_id=GRAPH, community_shadow=True))
    assert len(written) == 1 and written[0].community_total == 0


def test_the_newcomer_calibration_gap_comes_from_the_ledger(tmp_path):
    ledger = reputation.ReputationLedger(tmp_path / "rep.json")
    counted_key, newcomer = "c" * 64, "n" * 64
    ledger.set_standing(reputation.ReporterStanding(key=counted_key, band=reputation.ReputationBand.ESTABLISHED, first_seen_day="2026-01-01"))
    for confirmed in (True, True, True, False):                      # counted: 25% rejected
        ledger.record(counted_key, reputation.Outcome("2026-09-30", confirmed))
    for confirmed in (True, False, False, False):                    # newcomers: 75% rejected
        ledger.record(newcomer, reputation.Outcome("2026-09-30", confirmed), first_seen_day="2026-09-01")
    unlisted, counted, ratio = shadow.calibration_gap(ledger, "2026-10-02")
    assert (unlisted, counted, ratio) == (0.75, 0.25, 3.0)
    assert shadow.calibration_gap(reputation.ReputationLedger(tmp_path / "empty.json"), "2026-10-02") == (0.0, 0.0, 0.0)


def test_the_shadow_flag_parses_from_the_entry_and_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(json.dumps({"plugins": {"entries": {"blackbox": {"community_shadow": True}}}}), encoding="utf-8")
    assert config_mod.load_blackbox_config().community_shadow is True
    monkeypatch.setenv("BLACKBOX_COMMUNITY_SHADOW", "false")
    assert config_mod.load_blackbox_config().community_shadow is False
    assert BlackboxConfig().community_shadow is False
    os.environ.pop("BLACKBOX_COMMUNITY_SHADOW", None)
