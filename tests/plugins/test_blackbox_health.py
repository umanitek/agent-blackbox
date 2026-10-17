"""Refine R10 — reporter + operator surfaces lite.

One health item feeds both surfaces: every operator state carries a
what-to-do line, INFO never renders red, ACTION/SECURITY sort first.
`report --status` says what happened to each report (share outcome, then the
threat's local stage and reason); `--standing` says counted or probation with
a co-sighting estimate; the dashboard serves the same health items and the
"My reports" rows.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.community import CommunityRead, ReadState
from plugins.blackbox.community.report_cli import report_tracking
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.community.statements.digests import HeatEstimate
from plugins.blackbox.community.verification import VerifiedReport
from plugins.blackbox.dashboard import community_routes
from plugins.blackbox.kernel import health
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import compiler

GRAPH = "0x51E5dE758A45/agent-blackbox-community-dev"
THREAT = "dep:npm:evil@1.0.0"


def _inputs(**over):
    base = dict(node_reachable=True, ruleset_age_s=60.0, sync_interval_s=300.0, rule_count=10,
                community_configured=True, curator_trusted=True)
    base.update(over)
    return health.HealthInputs(**base)


# ------------------------------------------------------------------ the health rules


def test_a_healthy_node_has_nothing_to_do():
    assert health.operator_health(_inputs()) == []
    assert health.render_lines([]) == ["  health:            ok — nothing to do"]


@pytest.mark.parametrize("over, klass, needle", [
    ({"node_reachable": False}, health.HealthClass.ACTION, "stale"),
    ({"ruleset_age_s": 2_000.0}, health.HealthClass.ACTION, "stale"),
    ({"ruleset_age_s": None}, health.HealthClass.ACTION, "stale"),
    ({"rule_count": 0}, health.HealthClass.ACTION, "UNPROTECTED"),
    ({"read_unavailable_reason": "node status unavailable"}, health.HealthClass.INFO, "could not be read"),
    ({"community_paused": True}, health.HealthClass.INFO, "paused"),
    ({"backlog": "3,4,5"}, health.HealthClass.INFO, "BACKLOG"),
    ({"away_keys": 1}, health.HealthClass.INFO, "away"),
    ({"revoked": {THREAT: 0}}, health.HealthClass.INFO, "REVOKED"),
    ({"revoked": {THREAT: 3}}, health.HealthClass.ACTION, "blocked 3"),
    ({"held_back": 7}, health.HealthClass.INFO, "held"),
    ({"pending_shares": 2}, health.HealthClass.INFO, "waiting for the network"),      # R16: retried automatically
    ({"shares_given_up": 1}, health.HealthClass.ACTION, "could not be shared"),       # R16: the operator must look
])
def test_every_operator_state_has_a_class_and_a_what_to_do(over, klass, needle):
    items = health.operator_health(_inputs(**over))
    assert len(items) == 1 and items[0].klass is klass and needle in items[0].message + " " + items[0].what_to_do
    assert items[0].what_to_do and items[0].audience == "operator"


def test_info_is_never_red_and_action_sorts_first():
    items = health.operator_health(_inputs(node_reachable=False, community_paused=True, held_back=2))
    assert next(i.klass for i in items) is health.HealthClass.ACTION
    assert all(not health.red(i) for i in items if i.klass is health.HealthClass.INFO)
    assert health.red(items[0])


def test_gather_reads_the_ruleset_and_the_community_read():
    rs = compiler.Ruleset()
    rs.synced_at = 1_000.0
    rs.community_paused = True
    rs.ioc = {"ioc:domain:x.example": {"identifier": "ioc:domain:x.example", "source": "public"}}
    manifest = km.KeyManifest(environment="n", graph="vm", chain="", root_epoch=1, version=1, curator_keys=("a" * 64, "b" * 64),
                              curator_operators=("operator-a", "operator-b"), threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    revoked = CuratorRecord(kind=Kind.REVOCATION, identifier=THREAT, sequence=2, day="2026-10-02",
                            fields=(("reason", "false-positive"),), signers=frozenset({"a" * 64}))
    read = CommunityRead(ReadState.ROWS, held_back=4, curator=cv.CuratorView(manifest=manifest, verdicts={THREAT: revoked}))
    inputs = health.gather(BlackboxConfig(context_graph_id=GRAPH, sync_interval=300), rs, True, read, {THREAT: 2}, 1_600.0)
    assert (inputs.ruleset_age_s, inputs.rule_count, inputs.community_paused, inputs.curator_trusted) == (600.0, 1, True, True)
    assert inputs.revoked == {THREAT: 2} and inputs.held_back == 4
    assert health.ruleset_age_text(inputs.ruleset_age_s) == "10 min ago"



def test_an_ignored_manifest_conflict_is_a_security_item_on_both_authorities():
    # T1 (D31): a root-signed list at or below the order this node acts on cannot move
    # it, but someone holding a root key signed it — never a silent no-op.
    items = health.operator_health(_inputs(manifest_conflict_ignored=True))
    assert len(items) == 1 and items[0].klass is health.HealthClass.SECURITY
    assert "IGNORED" in items[0].message and "root key may be compromised" in items[0].what_to_do
    read = CommunityRead(ReadState.ROWS, curator=cv.CuratorView(manifest_conflict_ignored=True))
    inputs = health.gather(BlackboxConfig(context_graph_id=GRAPH, sync_interval=300), compiler.Ruleset(), True,
                           read, {}, 1_600.0)
    assert inputs.manifest_conflict_ignored and not inputs.manifest_conflict
    community = health.community_authority.gather(cv.CuratorView(manifest_conflict_ignored=True), "2026-10-11")
    alarms = health.community_authority.alarms(community)
    assert [(level, "IGNORED" in message) for level, message, _ in alarms] == [("security", True)]

# ------------------------------------------------------------------ what happened to my report


def test_outcome_line_carries_the_share_outcome_then_the_stage_and_reason():
    row = {"ts": "2026-10-02T06:00:00Z", "identifier": THREAT, "category": "dependency", "ok": True, "outcome": "accepted"}
    compiled = {THREAT: {"stage": "corroborated", "enforcement": "flag", "stageReason": "corroborated by 3 partner clusters"}}
    line = report_tracking.outcome_line(row, compiled)
    assert "[ok]" in line and "corroborated (flag)" in line and "3 partner" in line
    assert "not in the compiled community tier" in report_tracking.outcome_line(row, {})
    assert "[already shared]" in report_tracking.outcome_line({**row, "outcome": "already-shared"}, {})


def test_standing_says_counted_or_probation_with_co_sightings():
    own, other = "c" * 64, "d" * 64
    reports = (VerifiedReport("s1", THREAT, own, "0x1cb7a2e9afbed1e81860f3dd4e4e3b795be5b95a", "high"), VerifiedReport("s2", "ioc:domain:x", other, "0x6b865327cda5d374298777f79af02ba0b90512d5", "high"))
    heat = {THREAT: HeatEstimate(THREAT, "2026-W40", 56, 2)}
    manifest = km.KeyManifest(environment="n", graph="vm", chain="", root_epoch=1, version=1, curator_keys=("a" * 64, "b" * 64),
                              curator_operators=("operator-a", "operator-b"), threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    counted = cv.CuratorView(manifest=manifest, counted={own: cv.CountedAuthor(own, "0x1cb7a2e9afbed1e81860f3dd4e4e3b795be5b95a", "partner", "acme", "2027-01-01")})
    lines = report_tracking.standing_lines(own, CommunityRead(ReadState.ROWS, reports=reports, heat=heat, curator=counted))
    assert lines[0].startswith("Standing: COUNTED (partner, acme)") and "~56 agent" in lines[1] and "1 verified report" in lines[1]
    probation = report_tracking.standing_lines(own, CommunityRead(ReadState.ROWS, reports=reports, curator=cv.CuratorView(manifest=manifest)))
    assert probation[0].startswith("Standing: PROBATION")
    no_manifest = report_tracking.standing_lines(own, CommunityRead(ReadState.ROWS, reports=reports))
    assert "no curator key manifest" in no_manifest[0]
    assert "do not build reputation" in lines[-1]


# ------------------------------------------------------------------ the dashboard


def test_api_health_and_my_reports_serve_the_same_facts(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from plugins.blackbox import audit
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    rs = compiler.Ruleset()
    rs.community = {THREAT: {"stage": "reported", "enforcement": "monitor", "stageReason": "reported by unlisted authors only"}}
    monkeypatch.setattr("plugins.blackbox.ruleset.peek", lambda cfg=None: rs)
    monkeypatch.setattr("plugins.blackbox.kernel.config.load_blackbox_config", lambda: BlackboxConfig(context_graph_id=GRAPH))
    audit.record_share_outcome(identifier=THREAT, category="dependency", severity="high", subject="s", asset_name="n",
                               ok=True, outcome="accepted")
    app = FastAPI()
    community_routes.register_community_routes(app, community_read=lambda cfg: None, node_reachable=lambda cfg: False)
    client = TestClient(app)
    items = client.get("/api/health").json()["items"]
    assert any(i["class"] == "action" and i["red"] for i in items)          # node unreachable -> ACTION, red
    assert all(not i["red"] for i in items if i["class"] == "info")        # INFO never red
    row = client.get("/api/reports").json()["outbound"][0]
    assert (row["identifier"], row["outcome"], row["stage"]) == (THREAT, "accepted", "reported")
    assert "unlisted" in row["stage_reason"]


def test_the_audit_counts_only_the_firings_that_blocked(monkeypatch, tmp_path):
    """KI-189: the hook's decision travels with the finding; a flag-only firing is not a lost action."""
    from plugins.blackbox import audit
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    finding = {"identifier": THREAT, "category": "dependency", "severity": "critical", "title": "t"}
    audit.record(event="pre_tool_call", findings=[finding], detail={"tool_name": "terminal", "decision": "block"})
    audit.record(event="pre_tool_call", findings=[finding], detail={"tool_name": "terminal", "decision": "flag"})
    audit.record(event="pre_tool_call", findings=[finding], detail={"tool_name": "terminal"})      # a pre-KI-189 row
    assert audit.blocked_counts_by_identifier() == {THREAT: 1}
    assert [row["decision"] for row in audit.read_findings(limit=10)].count("block") == 1


# ------------------------------------------------------------------ the manifest watcher (trust-and-threat-lab W1)

from datetime import datetime, timedelta, timezone, UTC

from plugins.blackbox.kernel.health import manifest_watch as mw

CURATOR_A, CURATOR_B = "a" * 64, "b" * 64
ISSUED = "2026-08-01"
_ISSUED_NOON = datetime(2026, 8, 1, 12, tzinfo=UTC).timestamp()


def _on_day(day: int) -> float:
    """The injected clock: noon UTC *day* days after the manifest was issued."""
    return _ISSUED_NOON + timedelta(days=day).total_seconds()


def _watch(**over):
    base = dict(manifest_order=(1, 3), issued_day=ISSUED, now=_on_day(10))
    base.update(over)
    return health.operator_health(_inputs(manifest_watch=mw.ManifestWatchInputs(**base)))


def test_a_root_signed_list_newer_than_the_recorded_one_is_a_security_item():
    items = _watch(seen_orders=((1, 3), (1, 4)), recorded_order=(1, 3))
    assert [i.klass for i in items] == [health.HealthClass.SECURITY]
    assert "newer than the last one this node recorded (epoch 1, version 3)" in items[0].message
    assert "epoch 1, version 4" in items[0].message and "blackbox.key-manifest" in items[0].message


def test_the_same_order_as_recorded_raises_nothing():
    assert _watch(seen_orders=((1, 2), (1, 3)), recorded_order=(1, 3)) == []


def test_a_new_epoch_counts_as_newer_whatever_its_version():
    items = _watch(seen_orders=((2, 1),), recorded_order=(1, 9))
    assert items and items[0].klass is health.HealthClass.SECURITY and "epoch 2, version 1" in items[0].message


def test_the_record_baselines_once_then_alarms_until_acknowledged(tmp_path):
    record = mw.SeenOrderRecord(tmp_path / mw.SEEN_ORDER_FILE)
    first = mw.watch_inputs(record, [(1, 3)], heartbeats={}, beat_interval_s=300, manifest_order=None, issued_day="", now=0)
    assert first.recorded_order == (1, 3) and mw.alarms(first) == []          # a fresh node trusts what is already there
    later = mw.watch_inputs(record, [(1, 3), (1, 4)], heartbeats={}, beat_interval_s=300, manifest_order=None, issued_day="", now=0)
    assert [a[0] for a in mw.alarms(later)] == ["security"]                    # stays up on every poll ...
    record.acknowledge((1, 4))
    record.acknowledge((1, 2))                                                 # ... a lower order never lowers the record
    assert record.read() == (1, 4)
    assert mw.alarms(mw.watch_inputs(record, [(1, 4)], heartbeats={}, beat_interval_s=300, manifest_order=None,
                                     issued_day="", now=0)) == []


def test_a_damaged_record_alarms_instead_of_resetting(tmp_path):
    path = tmp_path / mw.SEEN_ORDER_FILE
    path.write_text("not json", encoding="utf-8")
    inputs = mw.watch_inputs(mw.SeenOrderRecord(path), [(1, 9)], heartbeats={}, beat_interval_s=300,
                             manifest_order=None, issued_day="", now=0)
    assert inputs.record_unreadable and [a[0] for a in mw.alarms(inputs)] == ["security"]
    assert path.read_text(encoding="utf-8") == "not json"                     # never silently re-baselined


@pytest.mark.parametrize("silence_s, expected", [
    (2 * 300 + 299, []),                                   # 2 beats missed: nothing
    (3 * 300, [health.HealthClass.ACTION]),                # 3 missed beats → warning
    (2 * 3600, [health.HealthClass.ACTION]),               # exactly 2 h: still a warning
    (2 * 3600 + 60, [health.HealthClass.SECURITY]),        # 2 h 1 min silence → alarm
])
def test_heartbeat_gaps_warn_at_three_missed_beats_and_alarm_after_two_hours(silence_s, expected):
    now = _on_day(10)
    items = _watch(heartbeats={CURATOR_A: now - silence_s, CURATOR_B: now - 60}, beat_interval_s=300, now=now)
    assert [i.klass for i in items] == expected
    if items:
        assert CURATOR_A[:16] in items[0].message and CURATOR_A not in items[0].message   # a fingerprint, never the key


def test_without_a_known_beat_interval_only_the_two_hour_alarm_applies():
    now = _on_day(10)
    assert _watch(heartbeats={CURATOR_A: now - 3600}, beat_interval_s=0, now=now) == []
    assert [i.klass for i in _watch(heartbeats={CURATOR_A: now - 7300}, beat_interval_s=0, now=now)] == [health.HealthClass.SECURITY]


@pytest.mark.parametrize("day, klass, needle", [
    (39, None, ""),
    (40, health.HealthClass.ACTION, "reached day 40 of 60"),
    (49, health.HealthClass.ACTION, "reached day 40 of 60"),     # the message holds steady until the next step
    (50, health.HealthClass.ACTION, "reached day 50 of 60"),
    (55, health.HealthClass.ACTION, "reached day 55 of 60"),
    (56, health.HealthClass.SECURITY, "expires on 2026-09-30"),   # inside 5 days of MANIFEST_VALID_DAYS → alarm
    (61, health.HealthClass.SECURITY, "EXPIRED on 2026-09-30"),
])
def test_manifest_renewal_reminders_and_the_expiry_alarm(day, klass, needle):
    items = _watch(now=_on_day(day))
    if klass is None:
        assert items == []
    else:
        assert [i.klass for i in items] == [klass] and needle in items[0].message
        assert "epoch 1, version 3" in items[0].message


def test_watch_items_show_without_a_community_and_reach_gather():
    watch = mw.ManifestWatchInputs(seen_orders=((1, 4),), recorded_order=(1, 3))
    items = health.operator_health(_inputs(community_configured=False, manifest_watch=watch))
    assert [i.klass for i in items] == [health.HealthClass.SECURITY] and items[0].audience == "operator"
    rs = compiler.Ruleset()
    rs.synced_at = 1_000.0
    inputs = health.gather(BlackboxConfig(sync_interval=300), rs, True, None, {}, 1_600.0, watch=watch)
    assert inputs.manifest_watch is watch
    assert health.gather(BlackboxConfig(sync_interval=300), rs, True, None, {}, 1_600.0).manifest_watch == mw.ManifestWatchInputs()


def test_no_watch_message_names_a_threat_identifier():
    """alarm text names statement kinds, key fingerprints, counts and times — never a report's identifier."""
    now = _on_day(57)
    watch = mw.ManifestWatchInputs(seen_orders=((1, 3), (1, 4), (1, 5)), recorded_order=(1, 3),
                                   heartbeats={CURATOR_A: now - 3 * 300, CURATOR_B: now - 3 * 3600}, beat_interval_s=300,
                                   manifest_order=(1, 3), issued_day=ISSUED, now=now)
    base = _inputs(revoked={THREAT: 0})                            # the fixture's threat is in the same inputs
    added = set(health.operator_health(_inputs(revoked={THREAT: 0}, manifest_watch=watch))) - set(health.operator_health(base))
    assert len(added) == 4                                         # new list, warning, alarm, expiry
    for item in added:
        assert THREAT not in item.message and THREAT not in item.what_to_do
        assert CURATOR_A not in item.message and CURATOR_B not in item.message


def test_the_health_package_stays_under_its_size_alarm():
    from pathlib import Path
    assert len(Path(health.__file__).read_text(encoding="utf-8").splitlines()) < 400


def test_an_untrusted_network_raises_no_item():
    """No pinned curator manifest is the normal state, not an alarm: neither `blackbox status` nor the
    dashboard banner (both render operator_health) may say "no trusted curator keys" (removed 2026-10-12)."""
    items = health.operator_health(_inputs(curator_trusted=False))
    assert items == []
    assert not any("curator keys" in line for line in health.render_lines(items))
