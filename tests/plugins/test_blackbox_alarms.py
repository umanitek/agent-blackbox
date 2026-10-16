"""Refine R10b — the full §12 alarm set: every operator state with audience,
class and what-to-do; the curator audience delivered only to the curator
webhook, once per message; the facts behind them gathered from real inputs.

* operator: curators silent, heartbeat missing per key, manifest CONFLICT
  (SECURITY), minReaderVersion above mine (ACTION), environment-mismatch rows
  (ACTION), future-dated rows (SECURITY), kill list refused (SECURITY).
* curator: lane SLA, queue depth, reputation drift, velocity > 3σ, re-share
  failures, listings expiring within 30 days.
* the verifier counts WHY rows were dropped; the view carries heartbeats and
  the manifest conflict; an optional minReaderVersion leaves old manifests'
  payloads and hashes unchanged.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from plugins.blackbox.community import CommunityRead, ReadState, reputation, verification
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust import manifests as trust_manifests
from plugins.blackbox.curate import intake, verbs
from plugins.blackbox.kernel import health, signing
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.kernel.signing.trust_anchors import RootPins
from plugins.blackbox.ruleset import compiler
from test_blackbox_curate import FakeNode, _ctx, curators
from test_blackbox_curator_view import _curator_row

TODAY = "2026-10-02"
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


def _inputs(**over):
    base = dict(node_reachable=True, ruleset_age_s=60.0, sync_interval_s=300.0, rule_count=10,
                community_configured=True, curator_trusted=True, today=TODAY, my_version="1.1.0")
    base.update(over)
    return health.HealthInputs(**base)


def _by_class(items):
    return {item.message: item.klass for item in items}


# ------------------------------------------------------------------ the operator set


@pytest.mark.parametrize("over, klass, needle", [
    ({"curators_last_day": "2026-09-01"}, health.HealthClass.INFO, "have not published since 2026-09-01"),
    ({"heartbeat_missing_keys": 2}, health.HealthClass.INFO, "heartbeat missing for 2 key(s)"),
    ({"manifest_conflict": True}, health.HealthClass.SECURITY, "manifest CONFLICT"),
    ({"min_reader_version": "2.0.0"}, health.HealthClass.ACTION, "require Blackbox 2.0.0"),
    ({"env_mismatch_rows": 3}, health.HealthClass.ACTION, "signed for another network"),
    ({"future_dated_rows": 1}, health.HealthClass.SECURITY, "future-dated"),
    ({"kill_list_refused": "21 new disables", "kill_list_version": 4}, health.HealthClass.SECURITY, "kill list was refused"),
])
def test_every_new_operator_state_has_its_class_and_a_what_to_do(over, klass, needle):
    items = health.operator_health(_inputs(**over))
    hit = [i for i in items if needle in i.message]
    assert len(hit) == 1 and hit[0].klass is klass and hit[0].what_to_do and hit[0].audience == "operator"
    assert health.red(hit[0]) is (klass is not health.HealthClass.INFO)


def test_quiet_curators_and_an_older_floor_are_not_alarms():
    assert health.operator_health(_inputs(curators_last_day="2026-09-25")) == []       # 7 days: fine
    assert health.operator_health(_inputs(min_reader_version="1.0.9")) == []            # my 1.1.0 is newer
    assert health.operator_health(_inputs(curator_trusted=False, curators_last_day="2020-01-01")) == []   # untrusted: nothing to say


# ------------------------------------------------------------------ the curator set


def test_curator_alarms_cover_sla_depth_drift_velocity_failures_and_expiry():
    inputs = health.CuratorInputs(lane_depth={1: 2, 3: 5}, lane_over_sla={3: 4}, established_below_floor=3, established_total=10,
                                  reports_today=40, velocity_mean=5.0, velocity_sigma=2.0, shares_given_up=1, expiring_keys=2)
    items = health.curator_health(inputs)
    assert all(item.audience == "curator" for item in items)
    classes = _by_class(items)
    assert [k for m, k in classes.items() if "beyond their lane SLA" in m] == [health.HealthClass.ACTION]
    assert [k for m, k in classes.items() if "queue depth 7" in m] == [health.HealthClass.INFO]
    assert [k for m, k in classes.items() if "reputation drift" in m] == [health.HealthClass.ACTION]
    assert [k for m, k in classes.items() if "3σ" in m] == [health.HealthClass.SECURITY]
    assert [k for m, k in classes.items() if "failed after retries" in m] == [health.HealthClass.ACTION]
    assert [k for m, k in classes.items() if "expire within 30 days" in m] == [health.HealthClass.INFO]
    assert items[0].klass is not health.HealthClass.INFO                                # ACTION/SECURITY first
    assert health.curator_health(health.CuratorInputs(established_below_floor=1, established_total=10, reports_today=6,
                                                      velocity_mean=5.0, velocity_sigma=2.0)) == []


# ------------------------------------------------------------------ the facts behind them


def test_the_verifier_counts_why_rows_were_dropped():
    good = signed_row("ioc:domain:a.example", Reporter("0xa"))
    # signed_row dates its rows by the real clock, so this reader takes the real day too:
    # a fixed date here made every row "future-dated" two days after it was written (KI-280)
    verifier = verification.ReportVerifier(NETWORK, GRAPH)
    assert verifier.verify(good) is not None
    other_network = signed_row("ioc:domain:b.example", Reporter("0xb"), environment="another-network")
    assert verifier.verify(other_network) is None
    envelope_text = json.loads(json.dumps(good["signedStatement"]))
    future = dict(good)
    future["signedStatement"] = envelope_text
    unsigned = dict(good)
    unsigned["signedStatement"] = "not an envelope"
    assert verifier.verify(unsigned) is None
    assert verifier.drops == {"env_mismatch": 1, "future_dated": 0, "schema": 0, "other": 1}
    # a reader whose "today" is far behind the row's signed day sees a future-dated row (clock skew > 1 day)
    behind = verification.ReportVerifier(NETWORK, GRAPH, today="2020-01-01")
    assert behind.verify(signed_row("ioc:domain:f.example", Reporter("0xf"))) is None and behind.drops["future_dated"] == 1


def test_the_view_carries_heartbeats_and_detects_a_manifest_conflict(monkeypatch, curators):
    manifest = curators["manifest"]
    root = Ed25519PrivateKey.generate()
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", signing.public_key_hex(root))
    key_a = curators["a"]
    beat = _curator_row(Kind.HEARTBEAT, "curator", {"key": signing.public_key_hex(key_a)}, [key_a], manifest, graph=GRAPH, sequence=1)
    other = _curator_row(Kind.HEARTBEAT, "curator", {"key": signing.public_key_hex(curators["b"])}, [key_a], manifest, graph=GRAPH, sequence=2)
    view = cv.build_view(manifest, [], [beat, other], verified_graph=manifest.graph, community_graph=GRAPH, today=TODAY)
    assert view.heartbeats == {signing.public_key_hex(key_a): "2026-10-02"}           # a key beats only for itself
    assert view.last_statement_day == "2026-10-02"
    twin = km.KeyManifest(**{**manifest.__dict__, "promotion_author": "0x" + "2" * 40})
    assert trust_manifests.manifests_conflict([manifest, twin]) and not trust_manifests.manifests_conflict([manifest, manifest])
    assert cv.build_view(None, [], [], verified_graph=manifest.graph, community_graph=GRAPH, manifest_conflict=True).manifest_conflict


def test_min_reader_version_is_optional_and_leaves_old_payloads_unchanged(curators):
    manifest = curators["manifest"]
    assert "minReaderVersion" not in manifest.to_payload()
    newer = km.KeyManifest(**{**manifest.__dict__, "min_reader_version": "1.2.0"})
    assert newer.to_payload()["minReaderVersion"] == "1.2.0" and newer.content_hash() != manifest.content_hash()
    root = Ed25519PrivateKey.generate()
    parsed = km.verify_manifest(km.sign_manifest(newer, root), environment=manifest.environment, graph=manifest.graph,
                                roots=RootPins.unbound([signing.public_key_hex(root)]))
    assert parsed is not None and parsed.manifest.min_reader_version == "1.2.0"


def test_gather_fills_the_new_inputs_from_the_read_and_the_ruleset(curators):
    manifest = km.KeyManifest(**{**curators["manifest"].__dict__, "min_reader_version": "9.0.0"})
    view = cv.CuratorView(manifest=manifest, last_statement_day="2026-01-01", heartbeats={}, manifest_conflict=True)
    read = CommunityRead(ReadState.ROWS, curator=view, env_mismatch=2, future_dated=1)
    rs = compiler.Ruleset(synced_at=NOW)
    rs.kill_list = {"version": 3, "day": TODAY, "entries": [{"registry": "skill", "identifier": "x", "action": "warn", "reason": "malware"}]}
    rs.kill_list_refused = "bad"
    inputs = health.gather(BlackboxConfigStub(), rs, True, read, {}, NOW)
    assert (inputs.curators_last_day, inputs.heartbeat_missing_keys, inputs.manifest_conflict) == ("2026-01-01", 3, True)
    assert (inputs.min_reader_version, inputs.env_mismatch_rows, inputs.future_dated_rows) == ("9.0.0", 2, 1)
    assert (inputs.kill_list_version, inputs.kill_list_refused, inputs.today) == (3, "bad", "2027-01-15")
    messages = [i.message for i in health.operator_health(inputs)]
    assert any("require Blackbox 9.0.0" in m for m in messages) and any("CONFLICT" in m for m in messages)


class BlackboxConfigStub:
    context_graph_id = GRAPH   # the community lives in the verified graph (one graph since 2026-10-16)
    sync_interval = 3600


# ------------------------------------------------------------------ delivery: once per message, curator webhook only


class _Sink:
    def __init__(self):
        self.events, self.alarms = [], []

    def notify(self, event):
        self.events.append(event)

    def notify_alarm(self, item):
        self.alarms.append(item.as_dict())


def test_curator_alarms_are_delivered_once_per_message(tmp_path):
    watcher = intake.AlarmWatcher(tmp_path / "alarms_seen.json")
    sink = _Sink()
    items = health.curator_health(health.CuratorInputs(shares_given_up=2, expiring_keys=1))
    assert len(watcher.poll(items, sink)) == 2 and len(sink.alarms) == 2 and sink.alarms[0]["audience"] == "curator"
    assert watcher.poll(items, sink) == [] and len(sink.alarms) == 2                   # same messages: silent
    assert len(watcher.poll(health.curator_health(health.CuratorInputs(shares_given_up=3)), sink)) == 1


def test_curator_alarms_are_computed_from_the_queue_the_ledger_and_the_listings(tmp_path, curators):
    ledger = reputation.ReputationLedger(tmp_path / "rep.json")
    for i in range(4):
        key = f"e{i:02d}".ljust(64, "0")
        ledger.set_standing(reputation.ReporterStanding(key=key, band=reputation.ReputationBand.ESTABLISHED, first_seen_day="2026-01-01"))
        for _ in range(3):
            ledger.record(key, reputation.Outcome("2026-09-30", confirmed=(i == 0)))      # three of four sink under the floor
    counted = {"k" * 64: cv.CountedAuthor("k" * 64, "0x" + "a" * 40, "established", "", "2026-10-20")}
    view = cv.CuratorView(manifest=curators["manifest"], counted=counted)
    ctx = _ctx(FakeNode(), curators["manifest"])
    ctx = type(ctx)(**{**ctx.__dict__, "view": view})

    class Compiled:
        community = {"dep:npm:old@1": {"identifier": "dep:npm:old@1", "severity": "high", "source": "community", "reporterCount": 3,
                                       "firstSeen": NOW - 30 * 86_400, "stage": "corroborated", "enforcement": "flag", "counted": "3",
                                       "reason": "advisory:X"}}

        def iter_rules(self):
            return iter(())

    items = verbs.curator_alarms(ctx, Compiled(), today=TODAY, now=NOW, ledger=ledger)
    messages = [i.message for i in items]
    assert any("beyond their lane SLA (lane 2: 1)" in m for m in messages)
    assert any("reputation drift: 3 of 4" in m for m in messages)
    assert any("expire within 30 days" in m for m in messages)
