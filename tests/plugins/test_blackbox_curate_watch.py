"""curate/watch — the signature reconciler, the verified-graph watch, the wallet watch,
the proposal-rate warning and the daily dead-man beat (trust-and-threat-lab W2), and
their delivery: the alarm watcher, each node's own sink credential and the F-035
metrics record (W3, the delivery section at the end).

Each comparison is pure; the purity test keeps them that way.
"""

from __future__ import annotations

import argparse
import ast
import calendar
import dataclasses
import json
import os
import urllib.request
from decimal import Decimal
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.curate import commands, console, intake, verbs, watch
from plugins.blackbox.curate.console import METRIC_NAMES, UNAVAILABLE, MetricsSources, PipelineMetrics, WalletBalance
from plugins.blackbox.curate.context import PromotionDraft
from plugins.blackbox.curate.publishing.ledger import BatchEntry, PublishLedger, PublishState
from plugins.blackbox.curate.watch import (ChainRecord, CosignExpectation, GraphAsset, LedgerExpectation,
                                           PublishedStatement, SigningLog, SigningRow, dead_man_beat, proposal_rate,
                                           reconcile, unexpected_assets, wallet_drift)
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.health import HealthClass, HealthItem
from test_blackbox_curate import VM_GRAPH, FakeNode, _ctx, _machine, curators

WATCH = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "curate" / "watch"
T0 = 1_790_000_000.0


def _classes(items):
    return [item.klass for item in items]


def _published(envelope: signing.SignedEnvelope, key: Ed25519PrivateKey) -> PublishedStatement:
    return PublishedStatement(envelope.statement_type, signing.content_id(envelope), signing.public_key_hex(key))


# -- reconciler ------------------------------------------------------------------


def test_a_statement_missing_from_the_signing_log_is_security(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    log = SigningLog(tmp_path / "signing_log.jsonl")
    ctx = dataclasses.replace(_ctx(FakeNode(), curators["manifest"]), signing_log=log)
    mine = ctx.sign(PromotionDraft({"identifier": "dep:npm:evil-pkg@1.0.0"}, sequence=1), curators["a"])
    # The same key used elsewhere: signed outside the choke point, so the log never saw it.
    unlogged = signing.sign(curators["a"], statement_type=mine.statement_type, environment=mine.environment,
                          graph=VM_GRAPH, payload={"identifier": "dep:npm:other@2.0.0"}, sequence=2)

    assert reconcile(log, [_published(mine, curators["a"])]) == []
    items = reconcile(log, [_published(mine, curators["a"]), _published(unlogged, curators["a"])])
    assert _classes(items) == [HealthClass.SECURITY]
    assert signing.public_key_hex(curators["a"])[:16] in items[0].message and "1 statement" in items[0].message
    assert "dep:npm" not in items[0].message                     # kinds, fingerprints, counts — never identifiers


def test_a_cosignature_explains_the_statement_but_only_for_the_key_that_made_it(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    log = SigningLog(tmp_path / "signing_log.jsonl")
    ctx = dataclasses.replace(_ctx(FakeNode(), curators["manifest"]), signing_log=log)
    envelope = signing.sign(curators["a"], statement_type="blackbox.promotion", environment="testnet", graph=VM_GRAPH,
                            payload={"identifier": "x"}, sequence=1)
    cosigned = ctx.cosign(envelope, curators["b"])

    assert reconcile(log, [_published(cosigned, curators["b"])]) == []
    assert _classes(reconcile(log, [_published(cosigned, curators["c"])])) == [HealthClass.SECURITY]


def test_one_item_per_key_with_unexplained_statements():
    rows = [SigningRow("k", "d1", "aa" * 32, "sign", T0)]
    published = [PublishedStatement("k", "d2", "AA" * 32), PublishedStatement("k", "d3", "aa" * 32),
                 PublishedStatement("k", "d2", "aa" * 32), PublishedStatement("k", "d4", "bb" * 32)]

    class Reader:
        def rows(self):
            return rows

    items = reconcile(Reader(), published)
    assert len(items) == 2 and "2 statement" in items[0].message and "1 statement" in items[1].message


# -- verified-graph watch ----------------------------------------------------------


def _bound_ledger(tmp_path: Path) -> PublishLedger:
    clock = iter(T0 + step for step in range(100))
    ledger = PublishLedger(tmp_path / "publish_ledger.jsonl", clock=lambda: next(clock))
    ledger.queue("b-1", [BatchEntry("npm:evil@1.0.0", "dependency")])
    ledger.advance("b-1", PublishState.SEALED)
    ledger.advance("b-1", PublishState.SUBMITTED)
    ledger.advance("b-1", PublishState.BOUND, ual="did:dkg:ours/1", cost_trac="0.40", cost_bytes=1000)
    return ledger


def test_ledger_mode_an_asset_absent_from_the_publish_ledger_is_security(tmp_path):
    ledger = _bound_ledger(tmp_path)
    ours = GraphAsset("did:dkg:ours/1", ("d1",), T0 + 10)
    theirs = GraphAsset("did:dkg:theirs/9", ("d9",), T0 + 11)

    assert unexpected_assets([ours], LedgerExpectation(ledger.transitions())) == []
    items = unexpected_assets([ours, theirs], LedgerExpectation(ledger.transitions()))
    assert _classes(items) == [HealthClass.SECURITY] and items[0].message.startswith("1 verified-graph asset")


def test_ledger_mode_an_in_flight_batch_is_could_not_tell_for_one_later_asset_only(tmp_path):
    ledger = _bound_ledger(tmp_path)
    ledger.queue("b-2", [BatchEntry("npm:evil@2.0.0", "dependency")])
    ledger.advance("b-2", PublishState.SEALED)
    ledger.advance("b-2", PublishState.SUBMITTED)            # no answer recorded yet: its UAL is unknown
    submitted_at = ledger.get("b-2").at
    before = GraphAsset("did:dkg:x/1", (), submitted_at - 5)     # appeared before the submit: not ours
    after = GraphAsset("did:dkg:x/2", (), submitted_at + 5)
    another = GraphAsset("did:dkg:x/3", (), submitted_at + 6)

    assert _classes(unexpected_assets([after], LedgerExpectation(ledger.transitions()))) == [HealthClass.INFO]
    assert _classes(unexpected_assets([before], LedgerExpectation(ledger.transitions()))) == [HealthClass.SECURITY]
    assert _classes(unexpected_assets([after, another], LedgerExpectation(ledger.transitions()))) == [
        HealthClass.SECURITY, HealthClass.INFO]


def test_ledger_mode_a_minted_batch_without_its_ual_still_accounts_for_its_asset(tmp_path):
    # A 207 whose answer carried no UAL: the asset is on chain under the wallet and the ledger
    # cannot name it yet. The watch saw it while the batch was SUBMITTED; the next beat re-feeds
    # it after MINTED was recorded — that must stay "could not tell", never an unexplained-signature alarm.
    ledger = _bound_ledger(tmp_path)
    ledger.queue("b-2", [BatchEntry("npm:evil@2.0.0", "dependency")])
    ledger.advance("b-2", PublishState.SEALED)
    ledger.advance("b-2", PublishState.SUBMITTED)
    submitted_at = ledger.get("b-2").at
    seen = GraphAsset("did:dkg:x/2", (), submitted_at + 0.5)    # seen before the 207 was recorded

    assert _classes(unexpected_assets([seen], LedgerExpectation(ledger.transitions()))) == [HealthClass.INFO]
    ledger.advance("b-2", PublishState.MINTED, cost_trac="0.40", cost_bytes=1000)
    assert ledger.get("b-2").at > seen.seen_at
    assert _classes(unexpected_assets([seen], LedgerExpectation(ledger.transitions()))) == [HealthClass.INFO]
    ledger.reconcile_minted("b-2", readable_ual="did:dkg:x/2")
    assert unexpected_assets([seen], LedgerExpectation(ledger.transitions())) == []


def test_ledger_mode_a_written_off_batch_claims_no_asset(tmp_path):
    ledger = _bound_ledger(tmp_path)
    ledger.queue("b-2", [BatchEntry("npm:evil@2.0.0", "dependency")])
    ledger.advance("b-2", PublishState.SEALED)
    ledger.advance("b-2", PublishState.SUBMITTED)
    ledger.advance("b-2", PublishState.MINTED, cost_trac="0.40", cost_bytes=1000)
    ledger.reconcile_minted("b-2", readable_ual=None, note="never read back")
    later = GraphAsset("did:dkg:x/9", (), ledger.get("b-2").at + 3600)
    assert _classes(unexpected_assets([later], LedgerExpectation(ledger.transitions()))) == [HealthClass.SECURITY]


def test_cosign_mode_an_asset_whose_envelope_this_node_never_cosigned_is_security(curators):
    me = signing.public_key_hex(curators["b"])
    rows = [SigningRow("blackbox.promotion", "d1", me, "cosign", T0), SigningRow("blackbox.promotion", "d2", me, "sign", T0),
            SigningRow("blackbox.promotion", "d3", "ff" * 32, "cosign", T0)]   # another key's row explains nothing
    expected = CosignExpectation(rows, me.upper())

    assert unexpected_assets([GraphAsset("did:dkg:a/1", ("d1", "d2"), T0)], expected) == []
    for asset in (GraphAsset("did:dkg:a/2", ("d1", "d9"), T0),     # one envelope never co-signed here
                  GraphAsset("did:dkg:a/3", ("d3",), T0),          # co-signed by some other key
                  GraphAsset("did:dkg:a/4", (), T0)):              # no envelope at all: the wallet alone
        assert _classes(unexpected_assets([asset], expected)) == [HealthClass.SECURITY], asset


def test_cosign_mode_reads_a_real_signing_log(tmp_path, curators):
    log = SigningLog(tmp_path / "signing_log.jsonl", clock=lambda: T0)
    envelope = signing.sign(curators["a"], statement_type="blackbox.promotion", environment="testnet", graph=VM_GRAPH,
                            payload={"identifier": "x"}, sequence=1)
    log.record(envelope, curators["b"], action="cosign")
    expected = CosignExpectation(log.rows(), signing.public_key_hex(curators["b"]))
    assert unexpected_assets([GraphAsset("did:dkg:a/1", (signing.content_id(envelope),), T0)], expected) == []


# -- proposal rate -----------------------------------------------------------------


def test_a_lane_at_five_times_its_normal_warns():
    items = proposal_rate({"dependency": 40, "domain": 39, "skill": 3}, {"dependency": 8.0, "domain": 8.0})
    assert _classes(items) == [HealthClass.ACTION] and items[0].message.startswith("lane dependency: 40")


def test_a_lane_with_no_history_warns_at_five_proposals():
    assert proposal_rate({"new": 4}, {}) == []
    assert _classes(proposal_rate({"new": 5}, {})) == [HealthClass.ACTION]


def test_a_normal_that_is_not_a_number_counts_as_no_history():
    # A normal computed as 0/0 must not switch the warning off (max(nan, 1.0) is nan).
    assert _classes(proposal_rate({"dependency": 5}, {"dependency": float("nan")})) == [HealthClass.ACTION]
    assert _classes(proposal_rate({"dependency": 5}, {"dependency": -3.0})) == [HealthClass.ACTION]


# -- wallet watch ------------------------------------------------------------------


def test_a_balance_drop_the_ledger_explains_is_nothing_and_one_it_does_not_is_security(tmp_path):
    ledger = _bound_ledger(tmp_path)                           # spent 0.40 TRAC at T0 + 3
    window = dict(since=T0, until=T0 + 3600)

    assert wallet_drift(ChainRecord(start_balance=Decimal(10), end_balance=Decimal("9.60"), **window),
                        ledger.transitions()) == []
    assert wallet_drift(ChainRecord(start_balance=Decimal(10), end_balance=Decimal("10.60"),
                                    top_ups=Decimal(1), **window), ledger.transitions()) == []
    items = wallet_drift(ChainRecord(start_balance=Decimal(10), end_balance=Decimal("4.60"), **window),
                         ledger.transitions())
    assert _classes(items) == [HealthClass.SECURITY] and "5.00 TRAC" in items[0].message


def test_a_spend_outside_the_window_does_not_explain_a_drop(tmp_path):
    ledger = _bound_ledger(tmp_path)
    later = ChainRecord(since=T0 + 60, until=T0 + 3600, start_balance=Decimal(10), end_balance=Decimal("9.60"))
    assert _classes(wallet_drift(later, ledger.transitions())) == [HealthClass.SECURITY]


def test_a_minted_then_bound_batch_counts_its_cost_once(tmp_path):
    clock = iter(T0 + step for step in range(100))
    ledger = PublishLedger(tmp_path / "publish_ledger.jsonl", clock=lambda: next(clock))
    ledger.queue("b-1", [BatchEntry("npm:evil@1.0.0", "dependency")])
    ledger.advance("b-1", PublishState.SEALED)
    ledger.advance("b-1", PublishState.SUBMITTED)
    ledger.advance("b-1", PublishState.MINTED, ual="did:dkg:ours/1", cost_trac="0.40", cost_bytes=1000)
    ledger.reconcile_minted("b-1", readable_ual="did:dkg:ours/1")
    record = ChainRecord(since=T0, until=T0 + 3600, start_balance=Decimal(10), end_balance=Decimal("9.20"))
    assert _classes(wallet_drift(record, ledger.transitions())) == [HealthClass.SECURITY]   # 0.40 spent, not 0.80
    # The money left at MINTED, not at the later BOUND line that carries the same cost.
    minted_at, bound_at = (step.record.at for step in ledger.transitions()
                           if step.record.state in (PublishState.MINTED, PublishState.BOUND))
    up_to_bound = ChainRecord(since=T0, until=bound_at, start_balance=Decimal(10), end_balance=Decimal("9.60"))
    assert minted_at < bound_at and wallet_drift(up_to_bound, ledger.transitions()) == []


# -- dead-man beat -----------------------------------------------------------------


def test_the_dead_man_record_is_produced_once_per_utc_day():
    midnight = calendar.timegm((2026, 10, 11, 0, 0, 0))
    first = dead_man_beat(midnight + 60, "2026-10-10", [])
    assert first is not None and first.day == "2026-10-11" and first.quiet
    assert "all quiet" in first.as_health_item().message and first.as_health_item().klass is HealthClass.INFO
    assert dead_man_beat(midnight + 86_399, first.day, []) is None          # same UTC day: no second record
    assert dead_man_beat(midnight + 86_400, first.day, []).day == "2026-10-12"


def test_the_dead_man_record_counts_todays_alarms_not_info():
    alarms = [HealthItem("curator", HealthClass.SECURITY, "m", "w"), HealthItem("curator", HealthClass.INFO, "m", "w")]
    beat = dead_man_beat(T0, "", alarms)
    assert beat.alarms == 1 and not beat.quiet and "1 alarm" in beat.as_health_item().message


# -- purity (criterion 2) ----------------------------------------------------------

#: Names whose use in a watch comparison would be I/O of its own.
_IO_NAMES = {"open", "os", "pathlib", "Path", "socket", "requests", "httpx", "urllib", "subprocess", "sqlite3",
             "keys", "client", "read_text", "write_text", "time.time", "datetime.now"}


def test_the_comparison_modules_do_no_io_of_their_own():
    found = []
    for name in ("reconciler.py", "graph_watch.py", "wallet_watch.py"):
        tree = ast.parse((WATCH / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in _IO_NAMES:
                found.append(f"{name}:{node.lineno} {node.id}")
            if isinstance(node, ast.Attribute) and (node.attr in _IO_NAMES or ast.unparse(node) in _IO_NAMES):
                found.append(f"{name}:{node.lineno} {ast.unparse(node)}")
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [alias.name for alias in node.names] + [node.module or ""] if isinstance(
                    node, ast.ImportFrom) else [alias.name for alias in node.names]
                found += [f"{name}:{node.lineno} import {m}" for m in modules if m.split(".")[0] in _IO_NAMES]
    assert not found, found


# -- delivery (W3): the alarm watcher, the node's own credential, the metrics record --------

SLACK_A = "https://hooks.slack.com/services/T0/NODE-A/secret-a"
SLACK_B = "https://hooks.slack.com/services/T0/NODE-B/secret-b"
TELEGRAM_TOKEN = "123456789:" + "A" * 35


class _Posts:
    """Captures what the sinks POST (urlopen is the only network call); ``fail`` refuses them."""

    def __init__(self):
        self.calls, self.fail = [], False

    def __call__(self, request, timeout):
        if self.fail:
            raise OSError("down")
        self.calls.append((request.full_url, json.loads(request.data)))
        return _Answer()


class _Answer:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def posts(monkeypatch):
    sent = _Posts()
    monkeypatch.setattr(urllib.request, "urlopen", sent)
    return sent


def _credential(home: Path, body: dict, mode: int = 0o600) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / watch.NODE_SINK_FILE
    path.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(path, mode)
    return path


def _security_item(monkeypatch, tmp_path, curators) -> HealthItem:
    """A real SECURITY item: a statement under this key that the signing log never saw."""
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    unlogged = signing.sign(curators["a"], statement_type="blackbox.promotion", environment="testnet", graph=VM_GRAPH,
                          payload={"identifier": "dep:npm:evil@1.0.0"}, sequence=9)
    (item,) = reconcile(SigningLog(tmp_path / "signing_log.jsonl"), [_published(unlogged, curators["a"])])
    assert item.klass is HealthClass.SECURITY
    return item


def test_a_new_security_item_is_posted_once_and_not_again(monkeypatch, tmp_path, curators, posts):
    item = _security_item(monkeypatch, tmp_path, curators)
    _credential(tmp_path / "A" / "curate", {"kind": "slack", "url": SLACK_A})
    watcher, sink = intake.AlarmWatcher(), watch.node_sink()

    assert watcher.poll([item], sink) == [item.message]
    assert watcher.poll([item], sink) == [] and watcher.poll([item], sink) == []        # the next rounds stay silent
    assert len(posts.calls) == 1
    url, body = posts.calls[0]
    assert url == SLACK_A and body["text"].startswith("[SECURITY] ") and item.message in body["text"]
    assert json.loads((tmp_path / "A" / "curate" / "alarms_seen.json").read_text()) == [item.message]


def test_an_undelivered_security_item_is_tried_again_next_round(monkeypatch, tmp_path, curators, posts):
    item = _security_item(monkeypatch, tmp_path, curators)
    watcher, sink = intake.AlarmWatcher(), watch.WebhookSink(SLACK_A, chat=True)
    posts.fail = True
    assert watcher.poll([item], sink) == []
    posts.fail = False
    assert watcher.poll([item], sink) == [item.message] and len(posts.calls) == 1


def test_a_newer_root_signed_list_from_the_manifest_watcher_is_posted_once(monkeypatch, tmp_path, curators, posts):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    watcher, sink = intake.AlarmWatcher(), watch.WebhookSink(SLACK_A, chat=True)
    v1, v2 = curators["manifest"], dataclasses.replace(curators["manifest"], version=2)

    assert watch.manifest_items(v1, T0) == []                       # a fresh node records the list in force
    items = watch.manifest_items(v2, T0)
    assert _classes(items) == [HealthClass.SECURITY] and "version 2" in items[0].message
    assert watcher.poll(items, sink) == [items[0].message]
    assert watcher.poll(watch.manifest_items(v2, T0 + 60), sink) == [] and len(posts.calls) == 1   # no auto-acknowledge
    assert watch.manifest_items(v2, T0) == items                    # still raised until the key console acknowledges


def test_a_second_nodes_credential_file_is_not_read(monkeypatch, tmp_path, curators, posts):
    item = _security_item(monkeypatch, tmp_path, curators)            # this process is node A
    _credential(tmp_path / "A" / "curate", {"kind": "slack", "url": SLACK_A})
    node_b = _credential(tmp_path / "B" / "curate", {"kind": "slack", "url": SLACK_B})
    touched = []
    real_stat, real_read = Path.stat, Path.read_text
    monkeypatch.setattr(Path, "stat", lambda self, *a, **k: touched.append(self) or real_stat(self, *a, **k))
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: touched.append(self) or real_read(self, *a, **k))

    sink = watch.node_sink()
    monkeypatch.setattr(Path, "stat", real_stat)
    monkeypatch.setattr(Path, "read_text", real_read)
    intake.AlarmWatcher().poll([item], sink)

    assert node_b not in touched and all("/B/" not in str(path) for path in touched)
    assert [url for url, _ in posts.calls] == [SLACK_A]


@pytest.mark.parametrize("body, mode, why", [
    (None, 0o600, "no readable"),
    ({"kind": "slack", "url": SLACK_A}, 0o644, "readable by other users"),
    ("{not json", 0o600, "damaged"),
    ({"kind": "slack", "url": "http://hooks.slack.com/x"}, 0o600, "https"),
    ({"kind": "telegram", "bot_token": "1/../evil", "chat_id": "42"}, 0o600, "bot_token"),
    ({"kind": "pager", "url": SLACK_A}, 0o600, "kind must be"),
])
def test_a_missing_exposed_or_damaged_credential_fails_closed(tmp_path, body, mode, why):
    home = tmp_path / "curate"
    if body is not None:
        path = _credential(home, {})
        path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")
        os.chmod(path, mode)
    with pytest.raises(watch.SinkCredentialError, match=why):
        watch.node_sink(home)


def test_a_telegram_credential_posts_through_this_nodes_bot_and_never_shows_the_token(tmp_path, posts):
    sink = watch.node_sink(_credential(tmp_path, {"kind": "telegram", "bot_token": TELEGRAM_TOKEN,
                                                   "chat_id": "-1001234"}).parent)
    item = HealthItem("curator", HealthClass.SECURITY, "1 statement(s) under key abcd not in the signing log", "act")
    assert sink.notify_alarm(item) is True
    url, body = posts.calls[0]
    assert url == f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    assert body == {"chat_id": "-1001234", "text": watch.delivery.alarm_text(item)}
    assert TELEGRAM_TOKEN not in repr(sink) and "secret" not in repr(watch.WebhookSink(SLACK_A))


def test_a_failed_post_is_logged_without_the_credential(caplog, monkeypatch):
    def refuse(request, timeout):
        raise ValueError(f"unknown url type: {request.full_url}")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    assert watch.WebhookSink(SLACK_A).notify_metrics(PipelineMetrics()) is False
    assert "secret-a" not in caplog.text and "metrics" in caplog.text


def test_the_metrics_payload_matches_the_shared_record_type(tmp_path, posts):
    """The sinks post C4's record (curate.console.PipelineMetrics) as it is — W3 keeps no copy of its own."""
    ledger = _bound_ledger(tmp_path)
    sources = MetricsSources(publish_ledger=lambda: ledger, lab_jobs=None, delivery=None, signing_log=None,
                             wallet=lambda: WalletBalance(trac=Decimal("12.5"), gas=Decimal(3)))
    record = console.collect_metrics(sources, context=None, now=T0 + 3600)
    assert type(record) is PipelineMetrics

    watch.WebhookSink("https://example.test/hook").notify_metrics(record)
    watch.WebhookSink(SLACK_A, chat=True).notify_metrics(record)
    (_, structured), (_, chat) = posts.calls
    assert structured == record.as_payload() and structured["kind"] == "metrics"
    metrics = structured["metrics"]
    assert tuple(metrics) == METRIC_NAMES                              # every C4 name, in the record's order
    assert metrics["publish_207s"] == 0 and metrics["publish_failures"] == 0
    assert metrics["month_spend_trac"] == "0.40" and metrics["month_spend_bytes"] == 1000
    assert metrics["wallet_trac"] == "12.5" and metrics["wallet_trac_floor"] == "0.80"
    assert metrics["lab_queue_depth"] == UNAVAILABLE and metrics["queue_depth_by_lane"] == UNAVAILABLE   # missing ≠ 0
    assert chat == {"text": watch.delivery.metrics_text(record)}
    assert all(line in chat["text"].splitlines() for line in record.lines())


def test_the_metrics_record_has_one_definition():
    """A second copy of the F-035 record drifts from the console's names (the W3/C4 merge found 15 renamed fields)."""
    curate = WATCH.parent
    defined = [path.relative_to(curate).as_posix() for path in curate.rglob("*.py")
               if any(isinstance(node, ast.ClassDef) and node.name == "PipelineMetrics"
                      for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))))]
    assert defined == ["console/metrics.py"]


def test_the_metrics_record_goes_out_at_most_hourly_and_is_built_only_when_due(tmp_path, posts):
    watcher, sink = intake.AlarmWatcher(tmp_path / "alarms_seen.json"), watch.WebhookSink(SLACK_A, chat=True)
    built = []

    def record_of():
        built.append(1)
        return PipelineMetrics()

    assert watcher.post_metrics(record_of, sink, T0) is True
    assert watcher.post_metrics(record_of, sink, T0 + 3599) is False
    assert watcher.post_metrics(record_of, sink, T0 + 3600) is True and len(posts.calls) == 2
    assert len(built) == 2                                               # the stores are read only for a due post


def test_an_undelivered_metrics_record_is_tried_again_next_round(tmp_path, posts):
    watcher, sink = intake.AlarmWatcher(tmp_path / "alarms_seen.json"), watch.WebhookSink(SLACK_A, chat=True)
    posts.fail = True
    assert watcher.post_metrics(PipelineMetrics, sink, T0) is False
    posts.fail = False
    assert watcher.post_metrics(PipelineMetrics, sink, T0 + 60) is True


def test_the_dead_man_beat_is_posted_once_per_utc_day(tmp_path, posts):
    watcher, sink = intake.AlarmWatcher(tmp_path / "alarms_seen.json"), watch.WebhookSink(SLACK_A, chat=True)
    midnight = calendar.timegm((2026, 10, 11, 0, 0, 0))
    first = watcher.poll([], sink, now=midnight + 60)
    assert first == ["watcher beat 2026-10-11: all quiet"]
    warning = HealthItem("curator", HealthClass.ACTION, "lane 2 at 5x its normal", "look")
    assert watcher.poll([warning], sink, now=midnight + 3600) == [warning.message]       # the alarm, no second beat
    assert watcher.poll([], sink, now=midnight + 86_400) == ["watcher beat 2026-10-12: all quiet"]
    assert len(posts.calls) == 3


def test_the_watch_verb_reads_this_nodes_credential_and_delivers(monkeypatch, tmp_path, curators, posts):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    _credential(tmp_path / "A" / "curate", {"kind": "slack", "url": SLACK_A})
    monkeypatch.setattr(commands, "_ctx", lambda args: _ctx(FakeNode(), curators["manifest"]))
    monkeypatch.setattr(verbs, "curator_alarms", lambda *a, **k: [
        HealthItem("curator", HealthClass.SECURITY, "1 statement(s) under key abcd not in the signing log", "act")])
    args = argparse.Namespace(webhook="", once=True, interval=60.0)

    assert commands._watch(args) == 0 and commands._watch(args) == 0
    texts = [body["text"] for _, body in posts.calls]
    assert [t for t in texts if t.startswith("[SECURITY]")] == ["[SECURITY] 1 statement(s) under key abcd not in "
                                                                 "the signing log — act"]
    metrics_posts = [t for t in texts if t.startswith("Blackbox curation metrics")]
    assert len(metrics_posts) == 2                                       # one per process start, then hourly
    assert [line.split(":")[0] for line in metrics_posts[0].splitlines()[1:]] == list(METRIC_NAMES)   # C4's record
    assert all(url == SLACK_A for url, _ in posts.calls)


def test_the_watch_verb_without_a_credential_refuses_to_run_deaf(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    with pytest.raises(verbs.VerbError, match="alarm_sink.json"):
        commands._watch(argparse.Namespace(webhook="", once=True, interval=60.0))


def test_curate_watch_raises_the_beats_alarms_a_suspended_self_test_included(monkeypatch, tmp_path):
    """`curate watch` assembled its alarms separately from the curator service's beat and left out
    the self-test's items: a curator suspended by a failing self-test raised no alarm through it."""
    from types import SimpleNamespace

    from plugins.blackbox.curate.service import self_test

    suspended = HealthItem(audience="curator", klass=HealthClass.SECURITY, message="curator self-test failed", what_to_do="rerun it")
    monkeypatch.setattr(self_test, "health_items", lambda result: [suspended])
    monkeypatch.setattr(verbs, "curator_alarms", lambda *a, **k: [])
    monkeypatch.setattr(watch, "manifest_items", lambda *a, **k: [])
    monkeypatch.setattr(commands, "_ctx", lambda args: SimpleNamespace(compiled=None, manifest=None))
    polled = []
    monkeypatch.setattr(intake.AlarmWatcher, "poll", lambda self, items, sink, now=None: polled.extend(items) or [])
    monkeypatch.setattr(intake.AlarmWatcher, "post_metrics", lambda self, build, sink, now: None)
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path))
    args = argparse.Namespace(webhook="https://alarms.example.test/hook", once=True)
    assert commands._watch(args) == 0
    assert suspended in polled
