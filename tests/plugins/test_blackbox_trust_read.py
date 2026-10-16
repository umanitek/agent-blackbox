"""Community Curation C3 — reading from a graph anyone can write.

Bench finding 2026-10-03 (KI-262, KI-263): a DKG node answers a query that
TIMED OUT with an empty result and a normal success status, after 10-20
seconds; while a store ingests a flood, every query shape does this, on every
graph of that node. "The node returned no rows" is therefore not proof that
nothing is there. These tests pin the rules that follow:

* an empty answer that took as long as a timeout is a failed read;
* a page that goes empty that way mid-read fails the whole read;
* the pulse infers no change from it;
* the report tier is not cleared by one empty read: the emptiness must last.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row

from plugins.blackbox.community import ReadState, pulse, read_curator_view, read_verified_reports
from plugins.blackbox.community.statements import curator_view
from plugins.blackbox.community.trust import trust_store
from plugins.blackbox.kernel import sparql_text
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import community_tier, compiler

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)   # one graph: its shared memory is the community's
VIEW = "shared-working-memory"
THREAT = "ioc:ip:203.0.113.7"


class Clock:
    """A monotonic clock the fake node advances while it "works"."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(sparql_text.time, "monotonic", clock)
    return clock


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    pulse.PULSE.reset()


class SlowNode:
    """A node whose answers take *seconds* of clock time each. ``answers`` is
    the list of row lists it returns, in order (the last one repeats); an
    entry of ``FAIL`` returns the caller's error sentinel."""

    FAIL = object()

    def __init__(self, clock, answers, seconds=0.0):
        self.clock, self.answers, self.seconds, self.calls = clock, list(answers), seconds, 0

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        self.clock.now += self.seconds
        return on_error if answer is SlowNode.FAIL else list(answer)


# ------------------------------------------------------------------ one query


def test_a_prompt_empty_answer_is_empty_and_a_slow_empty_answer_is_a_failed_read(clock):
    assert sparql_text.query_rows(SlowNode(clock, [[]], seconds=0.2), "q", GRAPH, VIEW) == []
    assert sparql_text.query_rows(SlowNode(clock, [[]], seconds=10.2), "q", GRAPH, VIEW) is None


def test_a_slow_answer_with_rows_is_believed_and_a_failed_query_is_not(clock):
    rows = [{"r": "urn:x:1"}]
    assert sparql_text.query_rows(SlowNode(clock, [rows], seconds=19.0), "q", GRAPH, VIEW) == rows
    assert sparql_text.query_rows(SlowNode(clock, [SlowNode.FAIL]), "q", GRAPH, VIEW) is None


def test_the_threshold_sits_below_the_measured_timeout():
    assert 5.0 < sparql_text.SLOW_EMPTY_SECONDS < 10.0    # the bench saw 10.06-20.21 s; a real empty graph answers in < 1 s


# ------------------------------------------------------------------ paged reads


def test_a_page_that_goes_empty_after_a_timeout_fails_the_whole_read(clock):
    """The bench case: the first page of 5,000 rows arrived, the second came back empty
    after 30 s. A partial list must never pass as the graph's contents."""
    first = [{"r": f"urn:x:{i:05d}"} for i in range(5000)]

    class Node(SlowNode):
        def query(self, sparql, cg_id, view=None, on_error=None, **kw):
            self.seconds = 0.3 if self.calls == 0 else 30.0
            return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)

    assert sparql_text.page_rows(Node(clock, [first, []]), GRAPH, VIEW, lambda after: "q") is None


def test_a_prompt_short_read_still_returns_its_rows(clock):
    rows = [{"r": "urn:x:1"}, {"r": "urn:x:2"}]
    assert sparql_text.page_rows(SlowNode(clock, [rows], seconds=0.1), GRAPH, VIEW, lambda after: "q") == rows


# ------------------------------------------------------------------ the pulse and the report read


def test_the_pulse_infers_no_change_from_a_timed_out_probe(clock):
    assert pulse.fingerprint(SlowNode(clock, [[]], seconds=10.3), CFG) is None      # looks like an empty graph; is not believed
    assert pulse.fingerprint(SlowNode(clock, [[]], seconds=0.1), CFG) == ""         # a prompt empty answer is an empty graph


def test_a_timed_out_report_read_is_unavailable_even_on_a_subscribed_synced_node(clock):
    read = read_verified_reports(SlowNode(clock, [[]], seconds=10.2), CFG)
    assert read.state is ReadState.UNAVAILABLE and not read.available


def test_the_pulse_counts_key_manifests_so_a_new_manifest_is_noticed():
    assert "g:KeyManifest" in pulse._FINGERPRINT_SPARQL and "g:CuratorStatement" in pulse._FINGERPRINT_SPARQL


# ------------------------------------------------------------------ the report tier needs a second witness


class Reports:
    """A prompt node: subscribed, synced, serving *rows* as its reports and nothing else."""

    def __init__(self, rows=()):
        self.rows = list(rows)

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        return list(self.rows) if "g:ThreatReport" in sparql and "COUNT" not in sparql else []


def _generation(node, prior, monkeypatch, now):
    monkeypatch.setattr(community_tier.time, "time", lambda: now)
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, node, CFG, prior)
    return rs


def test_one_empty_read_does_not_clear_the_tier_and_a_lasting_one_does(monkeypatch):
    """KI-262: an unlisted reporter's threat (nothing would carry it) survives empty reads until
    the emptiness has lasted EMPTY_READ_WITNESS_SECONDS, and keeps its first-seen time."""
    start = 1_800_000_000.0
    first = _generation(Reports([signed_row(THREAT, Reporter("0xa"))]), None, monkeypatch, start)
    seen = first.community[THREAT]["firstSeen"]

    empty_once = _generation(Reports(), first, monkeypatch, start + 60)
    assert THREAT in empty_once.community and empty_once.community_empty_since == start + 60
    still = _generation(Reports(), empty_once, monkeypatch, start + 60 + community_tier.EMPTY_READ_WITNESS_SECONDS - 1)
    assert THREAT in still.community and still.community[THREAT]["firstSeen"] == seen

    lasted = _generation(Reports(), still, monkeypatch, start + 60 + community_tier.EMPTY_READ_WITNESS_SECONDS)
    assert lasted.community == {}


def test_a_read_with_reports_ends_the_empty_spell(monkeypatch):
    start = 1_800_000_000.0
    rows = [signed_row(THREAT, Reporter("0xa"))]
    first = _generation(Reports(rows), None, monkeypatch, start)
    empty = _generation(Reports(), first, monkeypatch, start + 60)
    back = _generation(Reports(rows), empty, monkeypatch, start + 120)
    assert back.community_empty_since == 0.0 and THREAT in back.community
    empty_again = _generation(Reports(), back, monkeypatch, start + 4000)
    assert THREAT in empty_again.community                      # the clock restarted: not yet believed


def test_the_empty_spell_survives_the_disk_cache(monkeypatch, tmp_path):
    from plugins.blackbox.ruleset import disk_cache
    rs = compiler.Ruleset()
    rs.community_empty_since = 1_800_000_060.0
    assert disk_cache._deserialize(disk_cache._serialize(rs)).community_empty_since == 1_800_000_060.0


# ------------------------------------------------------------------ T1: the list a reader acts on (D31)

def _verified_side(monkeypatch, today):
    """A trusted verified root and its v1 list (in force since long before *today*)."""
    from test_blackbox_authority import VM_GRAPH, Side
    side = Side(VM_GRAPH)
    side.manifest = dataclasses.replace(side.manifest, issued_day="2026-09-01")
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(curator_view, "_today", lambda: today[0])
    return side


def _node(side, *manifests):
    from test_blackbox_authority import Graphs
    from test_blackbox_curator_view import _manifest_row
    return Graphs(verified=[_manifest_row(manifest, side.root) for manifest in manifests])


def _narrowed(side, issued):
    """*side*'s list without its first curator: removal-only, so it may act at once."""
    keep = slice(1, None)
    return dataclasses.replace(side.manifest, version=2, issued_day=issued,
                               curator_keys=side.manifest.curator_keys[keep],
                               curator_operators=side.manifest.curator_operators[keep])


@pytest.mark.usefixtures("time_lock_one_day")
def test_a_narrowing_list_is_effective_at_once_and_sticky_after_its_own_time_lock(monkeypatch):
    today = ["2026-10-11"]
    side = _verified_side(monkeypatch, today)
    narrowed = _narrowed(side, issued="2026-10-11")
    assert narrowed.narrows(side.manifest)
    node = _node(side, side.manifest, narrowed)
    assert read_curator_view(node, CFG).manifest == narrowed            # no 3-day wait for a removal
    store = trust_store.TrustStore()
    assert store.load(CFG.context_graph_id).effective_order == side.manifest.order   # not sticky yet
    today[0] = "2026-10-14"
    assert read_curator_view(node, CFG).manifest == narrowed
    assert store.load(CFG.context_graph_id).effective_order == narrowed.order        # its challenge window passed


def test_the_sticky_order_is_persisted_and_reloaded_from_community_trust_json(monkeypatch, tmp_path):
    today = ["2026-10-11"]
    side = _verified_side(monkeypatch, today)
    read_curator_view(_node(side, side.manifest), CFG)
    path = tmp_path / "bbhome" / "community_trust.json"
    stored = json.loads(path.read_text())["graphs"][CFG.context_graph_id]
    assert stored["effective_order"] == [1, 1] and stored["effective_hash"] == side.manifest.content_hash()
    reloaded = trust_store.TrustStore(path).load(CFG.context_graph_id)
    assert (reloaded.effective_order, reloaded.effective_hash) == ((1, 1), side.manifest.content_hash())
    # The reloaded memory holds the reader: a later conflict at that order cannot un-effect the list.
    conflicting = dataclasses.replace(side.manifest, promotion_author="0x" + "9" * 40)
    view = read_curator_view(_node(side, side.manifest, conflicting), CFG)
    assert view.manifest == side.manifest and view.manifest_conflict_ignored and not view.manifest_conflict


def test_the_sticky_order_only_moves_forward_and_survives_remember(tmp_path):
    store = trust_store.TrustStore(tmp_path / "community_trust.json")
    store.remember_effective(GRAPH, (1, 4), "hash-4")
    assert store.remember_effective(GRAPH, (1, 3), "hash-3").effective_order == (1, 4)
    assert store.remember_effective(GRAPH, None, "").effective_order == (1, 4)
    after = store.remember(GRAPH, [], [])
    assert (after.effective_order, after.effective_hash) == ((1, 4), "hash-4")


def test_an_old_store_file_without_effective_order_loads_as_none(tmp_path):
    path = tmp_path / "community_trust.json"
    entry = {"manifests": [], "statements": [], "admitted": {}, "baseline_until": 1_800_000_000.0}
    path.write_text(json.dumps({"version": 1, "graphs": {GRAPH: entry,
                                                         "malformed": {**entry, "effective_order": [1, "x"],
                                                                       "effective_hash": "h"},
                                                         "boolean": {**entry, "effective_order": [True, 2]}}}))
    store = trust_store.TrustStore(path)
    old = store.load(GRAPH)
    assert old.effective_order is None and old.effective_hash == "" and old.baseline_until == 1_800_000_000.0
    assert store.load("malformed").effective_order is None and store.load("malformed").effective_hash == ""
    assert store.load("boolean").effective_order is None


# ------------------------------------------------------- T2: the successor graph readers follow

OLD_GRAPH = CFG.context_graph_id
NEW_GRAPH = "0x9a0cE11e/agent-blackbox-vm"


class MigrationNode:
    """A node whose configured verified graph holds graph-migration rows; it
    records every subscription it is asked for (the sync test)."""

    def __init__(self, *rows, failing=False):
        self.rows, self.failing, self.subscribed = list(rows), failing, []

    def status(self):
        return {"networkId": NETWORK}

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if self.failing:
            return on_error
        return list(self.rows) if "g:GraphMigration" in sparql and cg_id == OLD_GRAPH else []

    def subscribe_context_graph(self, cg_id, **kw):
        self.subscribed.append(cg_id)
        return {}


def _migration(**changes):
    from plugins.blackbox.kernel.signing import graph_migration as gm
    fields = dict(environment=NETWORK, from_graph=OLD_GRAPH, to_graph=NEW_GRAPH, from_day="2026-10-10",
                  issued_day="2026-10-11", root_epoch=1, sequence=1)
    fields.update(changes)
    return gm.GraphMigration(**fields)


def _migration_row(migration, root):
    from plugins.blackbox.kernel import signing
    from plugins.blackbox.kernel.signing import graph_migration as gm
    subject = f"urn:guardian:graph-migration:{migration.root_epoch}:{migration.sequence}:{migration.to_graph}"
    return {"r": subject, "signedStatement": signing.canonical_text(gm.sign_migration(migration, root))}


@pytest.fixture
def root(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from plugins.blackbox.kernel import signing
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", signing.public_key_hex(key))
    return key


@pytest.fixture
def today(monkeypatch):
    day = ["2026-10-11"]
    monkeypatch.setattr(curator_view, "_today", lambda: day[0])
    return day


def _active(node):
    from plugins.blackbox.community import active_verified_graph
    return active_verified_graph(node, CFG)


@pytest.mark.usefixtures("time_lock_one_day")
def test_a_migration_pending_inside_its_time_lock_leaves_the_old_graph_active_and_then_the_successor_is(root, today):
    node = MigrationNode(_migration_row(_migration(), root))
    for day in ("2026-10-10", "2026-10-11"):
        today[0] = day
        active = _active(node)
        assert active.graph == OLD_GRAPH and active.migration is None and active.subscriptions == (OLD_GRAPH,)
    today[0] = "2026-10-12"                                     # issued 10-11 + the 1-day time-lock
    active = _active(node)
    assert active.graph == NEW_GRAPH and active.migration == _migration() and active.migration.from_day == "2026-10-10"
    assert active.subscriptions == (OLD_GRAPH, NEW_GRAPH) and not active.frozen
    stored = trust_store.TrustStore().load(OLD_GRAPH).successor
    assert (stored.order, stored.to_graph, stored.from_day) == ((1, 1), NEW_GRAPH, "2026-10-10")


def test_a_migration_another_graph_or_an_untrusted_root_signed_is_never_followed(root, today):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    today[0] = "2026-10-20"
    stranger = _migration_row(_migration(sequence=2), Ed25519PrivateKey.generate())
    elsewhere = _migration_row(_migration(from_graph="0xother/agent-blackbox-vm", sequence=3), root)
    assert _active(MigrationNode(stranger, elsewhere)).graph == OLD_GRAPH


def test_a_conflicting_migration_at_the_same_order_freezes_and_the_old_graph_stays(root, today):
    conflicting = _migration(to_graph="0xdead/agent-blackbox-vm")
    today[0] = "2026-10-20"                                     # both long past their time-lock
    active = _active(MigrationNode(_migration_row(_migration(), root), _migration_row(conflicting, root)))
    assert active.graph == OLD_GRAPH and active.frozen and active.migration is None
    # A counter-statement freezes at once, while the conflicting migration is still pending.
    trust_store.TrustStore().forget()
    today[0] = "2026-10-12"
    pending_conflicting = _migration_row(_migration(sequence=2, issued_day="2026-10-12"), root)
    counter = _migration_row(_migration(sequence=2, issued_day="2026-10-12", to_graph=OLD_GRAPH + "-x"), root)
    node = MigrationNode(pending_conflicting, counter)
    for day in ("2026-10-12", "2026-10-30"):
        today[0] = day
        assert _active(node).frozen and _active(node).graph == OLD_GRAPH


def test_a_freeze_at_an_order_also_stops_every_higher_migration(root, today):
    today[0] = "2026-10-20"
    honest = _migration_row(_migration(), root)
    conflict = [_migration_row(_migration(sequence=2, to_graph=f"0x{n}/g"), root) for n in (1, 2)]
    flood = [_migration_row(_migration(sequence=sequence, to_graph=f"0x{sequence}/conflicting"), root)
             for sequence in range(3, 3 + trust_store.MAX_STORED_MIGRATIONS + 2)]
    node = MigrationNode(honest, *conflict, *flood)
    active = _active(node)
    assert active.frozen and active.migration == _migration()   # the honest (1,1) below the freeze is followed
    node.rows = [honest, *flood]                                # the conflict hidden by a junk flood
    active = _active(node)
    assert active.frozen and active.migration == _migration()   # the store kept the freeze's rows


def test_the_sticky_rule_a_later_conflict_at_the_followed_order_never_moves_the_reader_back(root, today):
    today[0] = "2026-10-14"
    node = MigrationNode(_migration_row(_migration(), root))
    assert _active(node).graph == NEW_GRAPH                     # followed once its time-lock passed: sticky
    node.rows.append(_migration_row(_migration(to_graph="0xdead/agent-blackbox-vm"), root))
    active = _active(node)
    assert active.graph == NEW_GRAPH and active.conflict_ignored and not active.frozen
    # A fresh install that never followed it sees the same rows as a freeze.
    trust_store.TrustStore().forget()
    assert _active(node).graph == OLD_GRAPH and _active(node).frozen


def test_a_freeze_only_migration_is_never_followed_and_freezes_its_order_and_above():
    from plugins.blackbox.community.trust import migrations
    from plugins.blackbox.kernel.signing.graph_migration import MigrationVerdict
    honest = MigrationVerdict(_migration())
    other_epoch = MigrationVerdict(_migration(sequence=2, to_graph="0xdead/g"), freeze_only=True)
    higher = MigrationVerdict(_migration(sequence=3, to_graph="0x3/g"))
    late = "2026-10-30"
    assert migrations.effective_migration([honest, other_epoch, higher], late) == _migration()
    assert migrations.freeze_order([honest, other_epoch, higher]) == (1, 2)
    assert migrations.effective_migration([other_epoch], late) is None   # alone: frozen, never followed


def test_at_the_sticky_order_only_the_stored_content_is_followed_whatever_the_row_order():
    from plugins.blackbox.community.trust import migrations
    from plugins.blackbox.kernel.signing.graph_migration import MigrationVerdict
    honest, conflicting = _migration(), _migration(to_graph="0xdead/agent-blackbox-vm")
    verdicts = [MigrationVerdict(conflicting), MigrationVerdict(honest)]       # the conflicting one first
    late = "2026-10-30"
    for followed in (honest, conflicting):
        chosen = migrations.effective_migration(verdicts, late, (1, 1), sticky_hash=migrations.content_hash(followed))
        assert chosen == followed
    assert migrations.effective_migration(verdicts, late, (1, 1)) is None  # no hash: never guessed


def test_the_stored_successor_only_moves_forward():
    store = trust_store.TrustStore()
    newer = trust_store.StoredSuccessor((1, 2), "h2", NEW_GRAPH, "2026-10-10")
    store.remember_migrations(OLD_GRAPH, [], newer)
    assert store.remember_migrations(OLD_GRAPH, [], trust_store.StoredSuccessor((1, 1), "h1", "0xold/g")).successor == newer
    assert store.remember_migrations(OLD_GRAPH, [], None).successor == newer
    newest = trust_store.StoredSuccessor((2, 1), "h3", "0x2/g")
    assert store.remember_migrations(OLD_GRAPH, [], newest).successor == newest


def test_a_curator_statement_write_keeps_the_followed_successor_and_its_rows(root, today):
    # Every verified read also rewrites the graph's manifests and statements
    # (remember). Dropping the successor there would erase the sticky memory, and
    # a later conflict at the followed order would then move the reader back.
    today[0] = "2026-10-14"
    node = MigrationNode(_migration_row(_migration(), root))
    assert _active(node).graph == NEW_GRAPH
    store = trust_store.TrustStore()
    before = store.load(OLD_GRAPH)
    after = store.remember(OLD_GRAPH, [], [])
    assert after.successor == before.successor and after.migrations == before.migrations
    assert store.load(OLD_GRAPH).successor == before.successor
    node.rows.append(_migration_row(_migration(to_graph="0xdead/agent-blackbox-vm"), root))
    active = _active(node)
    assert active.graph == NEW_GRAPH and active.conflict_ignored and not active.frozen


def test_an_unreadable_graph_follows_the_stored_migration_and_an_edited_store_only_loses_it(root, today, tmp_path):
    today[0] = "2026-10-14"
    assert _active(MigrationNode(_migration_row(_migration(), root))).graph == NEW_GRAPH
    active = _active(MigrationNode(failing=True))
    assert active.graph == NEW_GRAPH and active.unavailable
    path = tmp_path / "bbhome" / "community_trust.json"
    data = json.loads(path.read_text())
    data["graphs"][OLD_GRAPH]["migrations"] = []                # the verified row is gone
    path.write_text(json.dumps(data))
    assert _active(MigrationNode(failing=True)).graph == OLD_GRAPH
    data["graphs"][OLD_GRAPH]["successor"] = {"order": [1, "x"], "content_hash": "h"}
    path.write_text(json.dumps(data))
    assert trust_store.TrustStore(path).load(OLD_GRAPH).successor is None


def test_with_no_root_pinned_nothing_is_read_and_the_old_graph_stays(monkeypatch, today):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    node = MigrationNode()
    node.query = lambda *a, **k: pytest.fail("no root: the graph is not read")
    assert _active(node).graph == OLD_GRAPH


def _run_sync(monkeypatch, node):
    import argparse
    from plugins.blackbox.kernel import config as config_mod
    from plugins.blackbox.kernel import constants
    from plugins.blackbox.sync import command as sync_command
    from plugins.blackbox.sync import managed_node, native

    class Rules:
        def counts(self):
            return {"injection": 0, "escalation": 0, "dependency": 1, "fileaccess": 0, "skill": 0}

    monkeypatch.setattr(native, "handles", lambda _cfg: False)
    monkeypatch.setattr(sync_command, "_request_join", lambda *args, **kwargs: None)
    monkeypatch.setattr(sync_command, "DkgClient", lambda url, **_kw: node)
    monkeypatch.setattr(managed_node, "DkgClient", lambda url, **_kw: node)
    monkeypatch.setattr(sync_command, "load_blackbox_config",
                        lambda: config_mod.BlackboxConfig(context_graph_id=OLD_GRAPH, dkg_url=constants.DEFAULT_DKG_URL))
    monkeypatch.setattr(sync_command.ruleset, "refresh", lambda cfg, client, **_kw: Rules())
    assert sync_command.cmd_sync(argparse.Namespace(wait=False, timeout=180, require_rules=True)) == 0
    return node.subscribed


@pytest.mark.usefixtures("time_lock_one_day")
def test_sync_subscribes_the_successor_and_keeps_the_old_graph_only_when_a_successor_is_active(monkeypatch, root, today):
    today[0] = "2026-10-11"                                     # migration still inside its time-lock
    assert _run_sync(monkeypatch, MigrationNode(_migration_row(_migration(), root))) == [OLD_GRAPH]
    trust_store.TrustStore().forget()
    today[0] = "2026-10-12"                                     # in effect
    assert sorted(_run_sync(monkeypatch, MigrationNode(_migration_row(_migration(), root)))) == sorted([OLD_GRAPH, NEW_GRAPH])
