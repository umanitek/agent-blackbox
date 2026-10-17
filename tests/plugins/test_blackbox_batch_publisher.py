"""The batch publisher (trust-and-threat-lab §03.4).

Precheck section (P3): immediately before a paid publish, an entry the live
``verified_subset`` lookup now lists is dropped and logged, ``pkg@1.2.3`` is closed
by a verified ``pkg@*``, untouched entries pass, and the lookup is injected — no HTTP.

BatchPublisher section (P4): 49 entries wait and 50 publish; 6 h publishes one; a
block-tier entry with 3 reporters publishes within the hour; one asset per batch; a
forced 207 is reconciled, never re-minted; a revocation never enters a batch; a failed
publish leaves the ledger resumable and the next run retries only the unsent batch.

Corrections section (P5): a correction with no effective manifest is refused; never-flag
refuses a CIDR range, a shared-hosting apex and a package identifier; every published
revocation or correction is followed by its advisory twin in the community graph; a
correction never enters a batch; both verbs parse through the real Hermes parser.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import logging

import pytest

from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.curate.proposal import Proposal, ProposalState, ProposalStore
from plugins.blackbox.curate.publishing import batch as batch_module
from plugins.blackbox.curate.publishing import row_builders as rb
from plugins.blackbox.curate.publishing.batch import BatchPublisher
from plugins.blackbox.curate.publishing.ledger import PublishLedger, PublishState
from plugins.blackbox.curate.publishing.node_writers import NodeBatchWriter, SubmitReply, definite_refusal
from plugins.blackbox.curate.publishing.precheck import (
    ALREADY_VERIFIED,
    COVERED_BY_WHOLE_PACKAGE,
    DUPLICATE_IN_BATCH,
    PrecheckUnavailable,
    canonical_identifier,
    precheck,
    strict_verified_subset,
)
from plugins.blackbox.curate.publishing.row_builders import ConfirmedEntry
from plugins.blackbox.kernel import constants, signing, threat_ids
from plugins.blackbox.kernel.dkg_client import DkgError
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import promotion_statement as statement

# The package re-exports the precheck FUNCTION under the submodule's name, so the module is
# taken from the import system, never by attribute.
precheck_module = importlib.import_module("plugins.blackbox.curate.publishing.precheck")

# ---------------------------------------------------------------------------
# BatchPublisher (P4)
# ---------------------------------------------------------------------------

NETWORK = "sandbox-net"
VERIFIED_GRAPH = "0xabc/agent-blackbox-vm"
START = 1_800_000_000.0
HOUR = 3600.0
UAL = "did:dkg:base:8453/0xka/42"


def _report(identifier):
    """The community report each promotion here was made from (its provenance, the one-graph flow)."""
    return statement.ReportRef(identifier, threat_ids.report_uri(identifier, "0x" + "e" * 40), "d" * 64, "e" * 64)


@pytest.fixture(scope="module")
def curator_keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def ctx(curator_keys):
    pairs = sorted((signing.public_key_hex(key), f"operator-{i}") for i, key in enumerate(curator_keys))
    manifest = km.KeyManifest(environment=NETWORK, graph=VERIFIED_GRAPH, chain="", root_epoch=1, version=1,
                              curator_keys=tuple(key for key, _ in pairs), curator_operators=tuple(op for _, op in pairs),
                              threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    return SimpleNamespace(manifest=manifest, verified_graph=VERIFIED_GRAPH, compiled=None, client=None)


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now


class FakeWriter:
    """The node side: records every call; ``readable`` / ``ual_known`` / errors are set per test."""

    def __init__(self):
        self.sealed, self.submitted, self.reads = [], [], 0
        self.readable_answer = True
        self.seal_errors, self.submit_errors = [], []
        self.ual_known = None

    def seal(self, name, quads):
        if self.seal_errors:
            raise self.seal_errors.pop(0)
        self.sealed.append((name, list(quads)))

    def submit(self, name):
        self.submitted.append(name)
        if self.submit_errors:
            raise self.submit_errors.pop(0)
        return SubmitReply(UAL, "0xtx")

    def asset_ual(self, name):
        return self.ual_known

    def readable(self, signed):
        self.reads += 1
        return self.readable_answer


@pytest.fixture
def world(tmp_path, ctx, curator_keys):
    clock = Clock()
    store = ProposalStore(tmp_path / "proposals")
    ledger = PublishLedger(tmp_path / "publish_ledger.jsonl", clock=clock)
    writer = FakeWriter()
    lookup = FakeVerifiedSubset()
    publisher = BatchPublisher(store, ledger, writer=writer, verified_subset=lookup, clock=clock)
    sequence = iter(range(1, 10_000))
    # the community tier's verified-reporter counts (the fast lane reads them; a promotion names ONE report)
    ctx = SimpleNamespace(**{**vars(ctx), "compiled": SimpleNamespace(community={})})

    def approve(identifier, *, reporters=1, at=None, kind=rb.PROMOTION_STATEMENT):
        entry = ConfirmedEntry(identifier, "high", "malware", _report(identifier), "advisory MAL-2026-9")
        payload = rb.promotion_payload(entry) if kind == rb.PROMOTION_STATEMENT else {"identifier": identifier, "reason": "fp"}
        first = signing.sign(curator_keys[0], statement_type=kind, environment=NETWORK, graph=VERIFIED_GRAPH,
                             payload=payload, root_epoch=1, sequence=next(sequence))
        envelope = signing.cosign(first, curator_keys[1])
        when = clock.now if at is None else at
        proposal = Proposal.new(kind, identifier, envelope, VERIFIED_GRAPH, checks={"k": "osv:MAL-2026-9"}, now=when)
        proposal = proposal.transition(ProposalState.PROPOSED, now=when).transition(ProposalState.APPROVED, now=when)
        store.save(proposal)
        ctx.compiled.community[identifier] = {"reporterCount": reporters}
        return proposal

    return SimpleNamespace(ctx=ctx, clock=clock, store=store, ledger=ledger, writer=writer, lookup=lookup,
                           publisher=publisher, approve=approve, keys=curator_keys)


def _dep(n):
    return f"dep:npm:bad-{n}@1.0.0"


def _ioc(n):
    return threat_ids.ioc_identifier("domain", f"bad-{n}.example")


def test_49_entries_wait_and_the_50th_publishes_them_all(world):
    for n in range(49):
        world.approve(_ioc(n))
    assert world.publisher.run(world.ctx).action == "waiting"
    assert world.ledger.batches() == () and world.writer.submitted == []
    world.approve(_ioc(49))
    report = world.publisher.run(world.ctx)
    assert (report.action, report.entries) == ("published", 50)
    [record] = world.ledger.batches()
    assert record.state is PublishState.BOUND and len(record.entries) == 50


def test_six_hours_elapsed_publishes_a_single_entry(world):
    world.approve(_ioc(1))
    world.clock.now = START + 6 * HOUR - 1
    assert world.publisher.run(world.ctx).action == "waiting"
    world.clock.now = START + 6 * HOUR
    report = world.publisher.run(world.ctx)
    assert (report.action, report.entries) == ("published", 1)


def test_a_block_tier_entry_with_three_reporters_publishes_within_the_hour(world):
    world.approve(_dep(1), reporters=3)
    world.approve(_ioc(1), reporters=5)   # an address is flag-tier: it rides along, never triggers
    world.clock.now = START + batch_module.FAST_LANE_HOLD_SECONDS - 1
    assert world.publisher.run(world.ctx).action == "waiting"
    world.clock.now = START + batch_module.FAST_LANE_HOLD_SECONDS
    assert batch_module.FAST_LANE_HOLD_SECONDS < HOUR
    report = world.publisher.run(world.ctx)
    assert (report.action, report.entries) == ("published", 2)


@pytest.mark.parametrize("identifier,reporters", [
    (_ioc(7), 3),                                                                  # not block tier
    ("dep:npm:two-reporters@1.0.0", 2),                                            # too few reporters
])
def test_only_block_tier_with_three_reporters_takes_the_fast_lane(world, identifier, reporters):
    world.approve(identifier, reporters=reporters)
    world.clock.now = START + HOUR
    assert world.publisher.run(world.ctx).action == "waiting"


def test_a_skill_fingerprint_is_block_tier(world):
    world.approve(threat_ids.skill_artifact_identifier("a" * 64, "exec-remote"), reporters=3)
    world.clock.now = START + batch_module.FAST_LANE_HOLD_SECONDS
    assert world.publisher.run(world.ctx).action == "published"


def test_one_asset_per_batch_one_subject_per_threat(world):
    identifiers = [_dep(n) for n in range(30)] + [_ioc(n) for n in range(30)]
    for identifier in identifiers:
        world.approve(identifier)
    world.publisher.run(world.ctx)
    [(name, quads)] = world.writer.sealed
    assert world.writer.submitted == [name]
    subjects = {quad["subject"] for quad in quads}
    [record] = world.ledger.batches()
    assert subjects == {threat_ids.threat_uri(entry.identifier) for entry in record.entries}
    assert len(subjects) == 50 == len(record.entries)
    signed = [q for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED]
    assert len(signed) == 50   # every row carries its own envelope
    # the ten left over are the next batch, never a second copy of the first
    world.clock.now = START + 6 * HOUR
    world.publisher.run(world.ctx)
    first, second = world.ledger.batches()
    assert len(second.entries) == 10
    assert not {e.identifier for e in first.entries} & {e.identifier for e in second.entries}
    assert {e.identifier for e in first.entries} | {e.identifier for e in second.entries} == set(identifiers)


def test_a_forced_207_is_reconciled_and_never_re_minted(world):
    proposal = world.approve(_ioc(1), at=START - 6 * HOUR)
    world.writer.readable_answer = False   # minted on chain, graph binding failed
    report = world.publisher.run(world.ctx)
    [record] = world.ledger.batches()
    assert report.action == "minted" and record.state is PublishState.MINTED and record.ual == UAL
    assert world.store.get(proposal.id).state is ProposalState.APPROVED
    world.approve(_ioc(2), at=START - 6 * HOUR)   # new work waits behind the unsettled 207
    assert world.publisher.run(world.ctx).action == "held"
    assert len(world.writer.submitted) == 1 and len(world.ledger.batches()) == 1
    world.writer.readable_answer = True
    assert world.publisher.run(world.ctx).action == "published"   # the 207 is bound, then the waiting entry goes
    first, _second = world.ledger.batches()
    assert (first.state, first.ual) == (PublishState.BOUND, UAL)
    assert len(world.writer.submitted) == 2 and world.writer.submitted[0] != world.writer.submitted[1]
    assert world.ledger.metrics().minted_207s == 1
    assert world.store.get(proposal.id).state is ProposalState.PUBLISHED


def test_a_revocation_never_enters_a_batch(world):
    revocation = world.approve(_dep(999), kind="blackbox.revocation")
    for n in range(50):
        world.approve(_ioc(n))
    world.publisher.run(world.ctx)
    [record] = world.ledger.batches()
    assert _dep(999) not in {entry.identifier for entry in record.entries}
    assert world.store.get(revocation.id).state is ProposalState.APPROVED   # left for the at-once path


def test_revocations_alone_never_start_a_batch(world):
    for n in range(60):
        world.approve(_dep(n), kind="blackbox.revocation", at=START - 7 * HOUR)
    assert world.publisher.run(world.ctx).action == "waiting"
    assert world.ledger.batches() == ()


def test_a_definite_refusal_leaves_the_batch_sealed_and_the_next_run_retries_only_it(world):
    world.approve(_ioc(1), at=START - 6 * HOUR)
    world.writer.submit_errors.append(DkgError("409 not finalized", status_code=409))
    assert world.publisher.run(world.ctx).action == "failed"
    [record] = world.ledger.batches()
    assert record.state is PublishState.SEALED and "refused" in record.note
    world.approve(_ioc(2))   # fresh, below every trigger
    assert world.publisher.run(world.ctx).action == "published"
    [record] = world.ledger.batches()
    assert record.state is PublishState.BOUND
    assert len(world.writer.sealed) == 1 and world.writer.submitted == [world.writer.sealed[0][0]] * 2
    assert world.ledger.metrics().failures == 1


def test_a_failed_working_memory_write_is_retried_as_the_same_batch(world):
    world.approve(_ioc(1), at=START - 6 * HOUR)
    world.writer.seal_errors.append(DkgError("transport error"))
    assert world.publisher.run(world.ctx).action == "failed"
    [queued] = world.ledger.batches()
    assert queued.state is PublishState.QUEUED and world.writer.submitted == []
    assert world.publisher.run(world.ctx).action == "published"
    [record] = world.ledger.batches()
    assert record.batch_id == queued.batch_id and record.state is PublishState.BOUND


def test_a_publish_that_could_not_tell_is_never_submitted_again(world):
    world.approve(_ioc(1), at=START - 6 * HOUR)
    world.writer.submit_errors.append(DkgError("POST … -> 503: busy", status_code=503))
    assert world.publisher.run(world.ctx).action == "could-not-tell"
    assert world.ledger.batches()[0].state is PublishState.SUBMITTED
    assert world.publisher.run(world.ctx).action == "held"   # the node names no UAL yet
    world.writer.ual_known = UAL
    assert world.publisher.run(world.ctx).action == "published"
    assert len(world.writer.submitted) == 1
    assert world.ledger.batches()[0].state is PublishState.BOUND


def test_a_pre_check_that_cannot_tell_publishes_nothing(world):
    world.approve(_ioc(1), at=START - 6 * HOUR)

    def unavailable(_identifiers):
        raise PrecheckUnavailable("store busy")
    world.publisher._verified_subset = unavailable
    assert world.publisher.run(world.ctx).action == "could-not-tell"
    assert world.ledger.batches() == () and world.writer.sealed == []


def test_an_entry_the_verified_graph_now_lists_is_dropped_and_its_proposal_closed(world):
    listed = world.approve(_dep(1), at=START - 6 * HOUR)
    world.approve(_dep(2), at=START - 6 * HOUR)
    world.lookup.listed.add(_dep(1))
    report = world.publisher.run(world.ctx)
    assert (report.entries, report.dropped) == (1, 1)
    assert [e.identifier for e in world.ledger.batches()[0].entries] == [_dep(2)]
    assert world.store.get(listed.id).state is ProposalState.REJECTED


def test_a_promotion_with_one_signature_is_not_batched(world, curator_keys):
    entry = ConfirmedEntry(_ioc(5), "high", "malware", _report(_ioc(5)))
    single = signing.sign(curator_keys[0], statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK,
                          graph=VERIFIED_GRAPH, payload=rb.promotion_payload(entry), root_epoch=1, sequence=9_999)
    proposal = Proposal.new(rb.PROMOTION_STATEMENT, entry.identifier, single, VERIFIED_GRAPH, checks={}, now=START - 7 * HOUR)
    world.store.save(proposal.transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED, now=START - 7 * HOUR))
    assert world.publisher.run(world.ctx).action == "waiting"


def test_metrics_are_a_typed_record(world):
    world.approve(_dep(1), reporters=3, at=START - 600)
    world.approve(_ioc(1), at=START - 1200)
    stalled = Proposal.new(rb.PROMOTION_STATEMENT, _ioc(9), signing.sign(
        Ed25519PrivateKey.generate(), statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK, graph=VERIFIED_GRAPH,
        payload={"identifier": _ioc(9)}, root_epoch=1, sequence=1), VERIFIED_GRAPH, checks={}, now=START - 3 * 300 - 1)
    world.store.save(stalled.transition(ProposalState.PROPOSED, now=START - 3 * 300 - 1))
    world.publisher._wallet_balance = lambda: None
    metrics = world.publisher.metrics(world.ctx)
    assert dict(metrics.waiting_per_lane) == {"fast": 1, "batched": 1}
    assert metrics.oldest_waiting_seconds == 1200
    assert metrics.proposals_awaiting_cosign == 1
    assert (metrics.unsettled_batches, metrics.failures, metrics.minted_207s) == (0, 0, 0)
    assert metrics.seconds_since_last_batch is None
    assert (metrics.wallet_trac, metrics.wallet_floor_trac, metrics.below_wallet_floor) == (None, None, None)


# --------------------------------------------------------------- the node side and the strict lookup


class _Answer:
    def __init__(self, rules=None, known=True, reason=""):
        self.rules, self.known, self.reason = rules or {}, known, reason


class _Compiled:
    def __init__(self, public=(), live=None):
        self._public, self._live = public, live

    def iter_rules(self):
        return [("x", {"identifier": ident, "source": "public"}) for ident in self._public]

    def live_lookup(self):
        return self._live


class _Live:
    def __init__(self, answer):
        self.answer = answer

    def dependencies(self, _candidates):
        return self.answer

    def iocs(self, _identifiers):
        return self.answer


def test_the_strict_lookup_raises_when_the_store_cannot_tell():
    with pytest.raises(PrecheckUnavailable):
        strict_verified_subset(_Compiled(live=_Live(_Answer(known=False, reason="timeout"))))(["dep:npm:x@1.0.0"])
    with pytest.raises(PrecheckUnavailable):
        strict_verified_subset(_Compiled(live=None))(["dep:npm:x@1.0.0"])
    with pytest.raises(PrecheckUnavailable):
        strict_verified_subset(None)(["dep:npm:x@1.0.0"])


def test_the_strict_lookup_answers_from_compiled_and_live_rules():
    live = _Live(_Answer({"npm:x@1.0.0": {"identifier": "dep:npm:x@1.0.0"}}))
    lookup = strict_verified_subset(_Compiled(public=["skill:old@1.0"], live=live))
    assert lookup(["dep:npm:x@1.0.0", "skill:old@1.0", "skill:new@1.0"]) == {"dep:npm:x@1.0.0", "skill:old@1.0"}
    assert strict_verified_subset(_Compiled(public=["skill:old@1.0"]))(["skill:old@1.0"]) == {"skill:old@1.0"}


def test_only_a_4xx_is_a_definite_refusal():
    assert definite_refusal(DkgError("bad", status_code=400))
    assert not definite_refusal(DkgError("busy", status_code=503))
    assert not definite_refusal(DkgError("transport error"))
    assert not definite_refusal(TimeoutError())


class _Client:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def query(self, sparql, graph, view=None, on_error=None):
        self.calls.append((sparql, graph, view))
        return on_error if self.rows is None else self.rows

    def request(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        return {"ual": UAL, "txHash": "0xtx", "status": "partial"}


def test_the_node_writer_reads_back_every_signed_row_exactly(curator_keys):
    envelope = signing.cosign(signing.sign(curator_keys[0], statement_type=rb.PROMOTION_STATEMENT, environment=NETWORK,
                                           graph=VERIFIED_GRAPH, payload={"identifier": "x"}, root_epoch=1, sequence=1),
                              curator_keys[1])
    subject = threat_ids.threat_uri("x")
    signed = {subject: envelope.to_text()}
    assert NodeBatchWriter(_Client([{"r": subject, "o": envelope.to_text()}]), VERIFIED_GRAPH).readable(signed) is True
    assert NodeBatchWriter(_Client([]), VERIFIED_GRAPH).readable(signed) is False
    assert NodeBatchWriter(_Client(None), VERIFIED_GRAPH).readable(signed) is None
    client = _Client([])
    assert NodeBatchWriter(client, VERIFIED_GRAPH).submit("verified-batch-b-1") == SubmitReply(UAL, "0xtx")
    assert client.calls[-1][:2] == ("POST", "/api/knowledge-assets/verified-batch-b-1/vm/publish")


# --------------------------------------------------------------- P4 review (T-06): guards the first suite left open


@pytest.mark.parametrize("kind", ["blackbox.revocation", "blackbox.correction"])
def test_a_buildable_revocation_or_correction_never_enters_a_batch(world, kind):
    # The revocation tests above pass even without the kind filter, because their payload
    # cannot be row-built. Here the payload is promotion-shaped (buildable), so only the
    # promotion-only collection keeps it out (F-032: reductions go at once, never batched).
    entry = ConfirmedEntry(_dep(7), "high", "malware", _report(_dep(7)), "advisory MAL-2026-9")
    envelope = signing.cosign(signing.sign(world.keys[0], statement_type=kind, environment=NETWORK,
                                           graph=VERIFIED_GRAPH, payload=rb.promotion_payload(entry), root_epoch=1,
                                           sequence=7_777), world.keys[1])
    proposal = Proposal.new(kind, entry.identifier, envelope, VERIFIED_GRAPH, checks={}, now=START - 7 * HOUR)
    world.store.save(proposal.transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED, now=START - 7 * HOUR))
    for n in range(50):
        world.approve(_ioc(n))
    assert world.publisher.run(world.ctx).action == "published"
    [record] = world.ledger.batches()
    assert _dep(7) not in {e.identifier for e in record.entries}
    assert world.store.get(proposal.id).state is ProposalState.APPROVED   # left for the at-once path


class _SealingNode:
    """A node that seals a KA name once: a second POST of the same name is refused as
    'already finalized' (dkg_client's create rule), and every sealed signed row reads back."""

    # The exact 10.0.20+ reply (community.ALREADY_SEALED_REPLY) and the older daemons' text.
    REPLIES = ("POST /api/knowledge-assets -> 400: Assertion verified-batch is not an active Working Memory draft; "
               "reopen it before mutating it", "POST /api/knowledge-assets -> 409: assertion already finalized")

    def __init__(self, *, lose_first_reply=False, reply=REPLIES[0]):
        self.sealed, self.lose_first_reply, self.published, self.reply = {}, lose_first_reply, [], reply
        self.calls: list = []   # the node routes in the order they were hit (KI-351)

    def write_private_knowledge_asset(self, graph, name, quads):
        if name in self.sealed:
            raise DkgError(self.reply, status_code=400)
        self.sealed[name] = list(quads)
        self.calls.append(("seal", name))
        if self.lose_first_reply:   # the node finished the write; our side timed out
            self.lose_first_reply = False
            raise DkgError("transport error: timed out")

    def share_finalized_knowledge_asset(self, graph, name):
        self.calls.append(("share", name))
        return {"state": "succeeded"}

    def request(self, method, path, body=None, timeout=None):
        self.published.append(path)
        self.calls.append(("publish", path))
        return {"ual": UAL, "txHash": "0xtx"}

    def query(self, sparql, graph, view=None, on_error=None):
        return [{"r": q["subject"], "o": q["object"]} for quads in self.sealed.values() for q in quads
                if q["predicate"] == constants.SIGNED_STATEMENT_PRED]


@pytest.mark.parametrize("reply", _SealingNode.REPLIES)
def test_a_seal_the_node_already_finished_is_not_a_failure(reply):
    node = _SealingNode(reply=reply)
    writer = NodeBatchWriter(node, VERIFIED_GRAPH)
    writer.seal("verified-batch-b-1", [])
    writer.seal("verified-batch-b-1", [])   # re-sealing the same batch name: already sealed, carry on
    node.write_private_knowledge_asset = lambda *_: (_ for _ in ()).throw(DkgError("400 literal too large", status_code=400))
    with pytest.raises(DkgError):
        writer.seal("verified-batch-b-2", [])   # any other refusal still fails the step


def test_a_batch_is_shared_in_full_before_it_is_published(world):
    """KI-351: DKG 10.0.23 refuses /vm/publish for anything that is not a complete
    shared-memory share (409 PUBLISH_NOT_FULL_SHARE), so the free share rides the seal step."""
    node = _SealingNode()
    world.publisher._writer = NodeBatchWriter(node, VERIFIED_GRAPH)
    world.approve(_ioc(1), at=START - 6 * HOUR)
    assert world.publisher.run(world.ctx).action == "published"
    assert [step for step, _ in node.calls] == ["seal", "share", "publish"]


def test_a_failed_share_fails_the_free_step_and_pays_for_nothing():
    node = _SealingNode()
    node.share_finalized_knowledge_asset = lambda *_: (_ for _ in ()).throw(DkgError("SWM share job j failed"))
    with pytest.raises(DkgError):
        NodeBatchWriter(node, VERIFIED_GRAPH).seal("verified-batch-b-1", [])
    assert node.published == []


def test_a_seal_that_timed_out_after_the_node_wrote_it_resumes_the_same_batch(world):
    # Resumability (P4 acceptance 2): the node sealed the batch but the reply was lost, so the
    # ledger stays QUEUED. The next run must move that SAME batch on, not fail on every beat
    # and hold every later batch behind it.
    node = _SealingNode(lose_first_reply=True)
    world.publisher._writer = NodeBatchWriter(node, VERIFIED_GRAPH)
    world.approve(_ioc(1), at=START - 6 * HOUR)
    assert world.publisher.run(world.ctx).action == "failed"
    [queued] = world.ledger.batches()
    assert queued.state is PublishState.QUEUED
    assert world.publisher.run(world.ctx).action == "published"
    [record] = world.ledger.batches()
    assert record.batch_id == queued.batch_id and record.state is PublishState.BOUND
    assert len(node.sealed) == 1 and len(node.published) == 1


# ---------------------------------------------------------------------------
# Precheck (P3)
# ---------------------------------------------------------------------------


def _entry(identifier: str) -> ConfirmedEntry:
    return ConfirmedEntry(identifier, "high", "malware")


class FakeVerifiedSubset:
    """``Ruleset.verified_subset``'s shape over a fixed listing; records every question."""

    def __init__(self, listed=()):
        self.listed = set(listed)
        self.asked = []

    def __call__(self, identifiers):
        wanted = list(identifiers)
        self.asked.append(wanted)
        return {identifier for identifier in wanted if identifier in self.listed}


def test_an_entry_the_lookup_now_lists_is_dropped_and_logged(caplog):
    listed = "dep:npm:evil-pkg@1.0.0"
    lookup = FakeVerifiedSubset([listed])
    with caplog.at_level(logging.INFO, logger=precheck_module.__name__):
        result = precheck([_entry(listed)], lookup)
    assert result.kept == ()
    [dropped] = result.dropped
    assert (dropped.entry.identifier, dropped.reason, dropped.covered_by) == (listed, ALREADY_VERIFIED, listed)
    assert listed in caplog.text and ALREADY_VERIFIED in caplog.text


def test_a_version_exact_entry_is_closed_by_a_whole_package_rule():
    lookup = FakeVerifiedSubset(["dep:npm:pkg@*"])
    result = precheck([_entry("dep:npm:pkg@1.2.3")], lookup)
    assert result.kept == ()
    [dropped] = result.dropped
    assert (dropped.reason, dropped.covered_by) == (COVERED_BY_WHOLE_PACKAGE, "dep:npm:pkg@*")
    assert "dep:npm:pkg@*" in lookup.asked[0]


def test_untouched_entries_pass_in_order_with_one_lookup_call():
    entries = [_entry("dep:npm:clean@2.0.0"), _entry(threat_ids.ioc_identifier("domain", "fresh.example")),
               _entry(threat_ids.skill_version_identifier("new-helper", "1.0.0"))]
    lookup = FakeVerifiedSubset(["dep:npm:other@*", "dep:npm:clean@1.0.0"])
    result = precheck(entries, lookup)
    assert result.kept == tuple(entries)
    assert result.dropped == ()
    assert len(lookup.asked) == 1


def test_a_whole_package_entry_is_not_closed_by_itself_unless_listed():
    assert precheck([_entry("dep:npm:pkg@*")], FakeVerifiedSubset()).kept == (_entry("dep:npm:pkg@*"),)
    [dropped] = precheck([_entry("dep:npm:pkg@*")], FakeVerifiedSubset(["dep:npm:pkg@*"])).dropped
    assert dropped.reason == ALREADY_VERIFIED


def test_identifiers_are_compared_in_compiler_canonical_form():
    # PyPI names collapse case and separators; the lookup is asked the canonical text.
    lookup = FakeVerifiedSubset(["dep:pypi:foo-bar@*"])
    result = precheck([_entry("dep:PyPI:Foo_Bar@1.0")], lookup)
    assert [dropped.reason for dropped in result.dropped] == [COVERED_BY_WHOLE_PACKAGE]
    assert canonical_identifier("dep:PyPI:Foo_Bar@1.0") == threat_ids.dependency_identifier("pypi", "foo-bar", "1.0")


def test_a_lookup_answering_in_another_spelling_still_matches():
    # The lookup's answer is canonicalised too, so an alias spelling it reports counts.
    lookup = lambda identifiers: {"dep:npm:Evil-Pkg@1.0.0"}
    assert precheck([_entry("dep:npm:evil-pkg@1.0.0")], lookup).kept == ()


def test_two_spellings_of_one_threat_in_a_batch_publish_once():
    first, second = _entry("dep:npm:twice@1.0.0"), _entry("dep:npm:TWICE@1.0.0")
    result = precheck([first, second], FakeVerifiedSubset())
    assert result.kept == (first,)
    assert [(d.entry, d.reason) for d in result.dropped] == [(second, DUPLICATE_IN_BATCH)]


def test_a_lookup_that_cannot_tell_publishes_nothing():
    def unavailable(_identifiers):
        raise TimeoutError("store busy")
    with pytest.raises(TimeoutError):
        precheck([_entry("dep:npm:x@1.0.0")], unavailable)


def test_an_empty_batch_asks_nothing():
    lookup = FakeVerifiedSubset()
    assert precheck([], lookup).kept == ()
    assert lookup.asked == []


def test_the_precheck_module_makes_no_network_calls():
    tree = ast.parse(inspect.getsource(precheck_module))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"requests", "httpx", "urllib", "http", "socket", "aiohttp"}
    assert "DkgClient" not in inspect.getsource(precheck_module)
    assert "StoreClient" not in inspect.getsource(precheck_module)


# --- Checker additions (verify pass, 2026-10-11): the gaps the builder's ten tests left ---


def test_ioc_entries_are_compared_in_their_normalised_form(caplog):
    # canonical_identifier's ioc branch: case, trailing dot and an IP's port fold away
    # exactly as threat_ids.ioc_identifier keys them; the log line carries the prefix.
    lookup = FakeVerifiedSubset([threat_ids.ioc_identifier("domain", "evil.example"), "ioc:ip:203.0.113.9"])
    entries = [_entry("ioc:Domain:EVIL.Example."), _entry("ioc:ip:203.0.113.9:443"), _entry("ioc:domain:clean.example")]
    with caplog.at_level(logging.INFO, logger=precheck_module.__name__):
        result = precheck(entries, lookup)
    assert result.kept == (entries[2],)
    assert [d.covered_by for d in result.dropped] == ["ioc:domain:evil.example", "ioc:ip:203.0.113.9"]
    assert lookup.asked == [["ioc:domain:clean.example", "ioc:domain:evil.example", "ioc:ip:203.0.113.9"]]
    assert caplog.text.count("[precheck]") == 2


def test_non_dependency_non_ioc_identifiers_pass_through_unchanged():
    for identifier in ("skill:helper@1.0.0", "injection:abc123", "escalation:shell:remote-script-pipe", "ioc:nonsense"):
        assert canonical_identifier(identifier) == identifier
        assert precheck_module.whole_package_identifier(identifier) == ""


def test_the_question_is_sorted_and_asks_one_whole_package_sibling_per_package():
    lookup = FakeVerifiedSubset()
    precheck([_entry("dep:npm:b@2.0.0"), _entry("dep:npm:b@1.0.0"), _entry("dep:npm:a@*")], lookup)
    assert lookup.asked == [["dep:npm:a@*", "dep:npm:b@*", "dep:npm:b@1.0.0", "dep:npm:b@2.0.0"]]


def test_a_listed_or_covered_identifier_beats_the_duplicate_reason():
    # Reason precedence: listed, then covered by @*, then duplicate — a repeat of a
    # closed entry reports WHY it is closed, not merely that it repeats.
    lookup = FakeVerifiedSubset(["dep:npm:listed@1.0.0", "dep:npm:whole@*"])
    entries = [_entry("dep:npm:listed@1.0.0"), _entry("dep:npm:LISTED@1.0.0"),
               _entry("dep:npm:whole@1.0.0"), _entry("dep:npm:whole@1.0.0")]
    result = precheck(entries, lookup)
    assert result.kept == ()
    assert [d.reason for d in result.dropped] == [ALREADY_VERIFIED, ALREADY_VERIFIED,
                                                   COVERED_BY_WHOLE_PACKAGE, COVERED_BY_WHOLE_PACKAGE]


def test_a_whole_package_entry_in_the_same_batch_does_not_close_its_exact_version():
    # Only a VERIFIED @* rule closes pkg@1.2.3 (§03.4 F-030 b); an unpublished sibling
    # in the batch is not yet a rule, so both go out.
    entries = [_entry("dep:npm:pkg@*"), _entry("dep:npm:pkg@1.2.3")]
    assert precheck(entries, FakeVerifiedSubset()).kept == tuple(entries)


def test_precheck_fits_the_real_ruleset_verified_subset():
    # Contract: the injected lookup is Ruleset.verified_subset itself (compiled dicts,
    # no live scope). A public @* rule closes the exact version; a community rule and
    # an unknown package do not count.
    from plugins.blackbox.ruleset import compiler
    rs = compiler.Ruleset(dependency={
        "npm:whole@*": {"identifier": "dep:npm:whole@*", "source": "public"},
        "npm:exact@1.0.0": {"identifier": "dep:npm:exact@1.0.0", "source": "public"},
        "npm:comm@1.0.0": {"identifier": "dep:npm:comm@1.0.0", "source": "community"},
    })
    entries = [_entry("dep:npm:whole@2.0.0"), _entry("dep:npm:exact@1.0.0"),
               _entry("dep:npm:comm@1.0.0"), _entry("dep:npm:new@1.0.0")]
    result = precheck(entries, rs.verified_subset)
    assert result.kept == (entries[2], entries[3])
    assert [(d.reason, d.covered_by) for d in result.dropped] == [
        (COVERED_BY_WHOLE_PACKAGE, "dep:npm:whole@*"), (ALREADY_VERIFIED, "dep:npm:exact@1.0.0")]


def test_result_and_dropped_entries_are_immutable_records():
    result = precheck([_entry("dep:npm:x@1.0.0")], FakeVerifiedSubset(["dep:npm:x@1.0.0"]))
    with pytest.raises((AttributeError, TypeError)):
        result.kept = ()  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        result.dropped[0].reason = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Corrections, never-flag and the advisory twin (P5)
# ---------------------------------------------------------------------------

import json
import re

from plugins.blackbox.community.statements import curator_statements
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import verbs
from plugins.blackbox.curate.context import CurateContext
from plugins.blackbox.curate.publishing import commands as correction_verbs
from plugins.blackbox.curate.publishing import never_flag
from plugins.blackbox.curate.publishing.errors import VerbError
from test_blackbox_curate import CFG, COMMUNITY, VM_GRAPH, FakeNode, _machine

LEGACY_8888 = "urn:defender:signal:94f04f19bc0000000000000000000000"
publish_module = importlib.import_module("plugins.blackbox.curate.publishing.publish")   # not the re-exported function


@pytest.fixture
def curators():
    """Curator A, curator B and the sealed break-glass key (D32) on a 2-of-3 list."""
    a, b, glass = (Ed25519PrivateKey.generate() for _ in range(3))
    operators = {signing.public_key_hex(a): "Umanitek", signing.public_key_hex(b): "Umoja Ark",
                 signing.public_key_hex(glass): "Sealed"}
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]),
                              break_glass_key=signing.public_key_hex(glass), **km.roster(operators))
    return SimpleNamespace(a=a, b=b, glass=glass, manifest=manifest)


def _verified_ctx(node, manifest, *, state="", state_day=""):
    view = cv.CuratorView(manifest=manifest, manifest_state=state, manifest_state_day=state_day)
    return CurateContext(cfg=CFG, client=node, environment=NETWORK, view=view, sandbox=True, compiled=None)


def _args(**overrides):
    base = {"identifier": "ioc:ip:8.8.8.8", "reason": "public DNS resolver", "source": "misp-warninglists:public-dns-v4",
            "code": None, "yes": False, "to": "", "verb": "correct", "compiled_ruleset": None}
    return SimpleNamespace(**{**base, **overrides})


def _lookup(held):
    """The verified graph's subjects per identifier, as ``verified_subjects`` returns them."""
    return lambda ctx, identifiers: {identifier: held[identifier] for identifier in identifiers if identifier in held}


def _shown_code(output):
    return re.search(r"--code ([0-9a-f]{8})", output).group(1)


def _propose_correction(monkeypatch, tmp_path, capsys, curators, node, identifier="ioc:ip:8.8.8.8"):
    """Curator A: shown first, then signed under the typed code; returns (proposal, A's store)."""
    _machine(monkeypatch, tmp_path, "A", curators.a)
    store = ProposalStore()
    ctx = _verified_ctx(node, curators.manifest)
    lookup = _lookup({identifier: (LEGACY_8888,)})
    assert correction_verbs.cmd_correct(_args(identifier=identifier), context=ctx, lookup=lookup, store=store) == 2
    assert store.all() == []                                                   # shown, nothing signed
    code = _shown_code(capsys.readouterr().out)
    assert correction_verbs.cmd_correct(_args(identifier=identifier, code=code), context=ctx, lookup=lookup, store=store) == 0
    [proposal] = store.all()
    return proposal, store


def _approve_on(monkeypatch, tmp_path, machine, key, node, manifest, proposal):
    _machine(monkeypatch, tmp_path, machine, key)
    store = ProposalStore()
    store.save(proposal)
    return verbs.approve(_verified_ctx(node, manifest), store, proposal.id, evidence="", typed_code=None, yes=True)


# -- no effective manifest -------------------------------------------------------------


@pytest.mark.parametrize("manifest_present, state, refused", [
    (False, "", "no trusted key manifest is in force"),
    (True, "pending", "takes effect on 2026-10-14"),
])
def test_a_correction_with_no_effective_manifest_is_refused(monkeypatch, tmp_path, curators, manifest_present, state, refused):
    _machine(monkeypatch, tmp_path, "A", curators.a)
    ctx = _verified_ctx(FakeNode(), curators.manifest if manifest_present else None, state=state, state_day="2026-10-14")
    store = ProposalStore()
    with pytest.raises(VerbError, match=refused):
        correction_verbs.cmd_correct(_args(yes=True), context=ctx, lookup=_lookup({"ioc:ip:8.8.8.8": (LEGACY_8888,)}),
                                     store=store)
    assert store.all() == []


def test_an_approved_correction_is_not_published_while_the_manifest_is_pending(monkeypatch, tmp_path, capsys, curators):
    """The publish side refuses too: a list still inside its time-lock signs nothing readers honour."""
    node = FakeNode()
    proposal, _ = _propose_correction(monkeypatch, tmp_path, capsys, curators, node)
    cosigned = proposal.with_envelope(signing.cosign(proposal.parsed(), curators.b), {}).transition(ProposalState.APPROVED)
    store = ProposalStore()
    store.save(cosigned)
    pending = _verified_ctx(node, curators.manifest, state="pending", state_day="2026-10-14")
    with pytest.raises(VerbError, match="takes effect on"):
        publish_module.publish(pending, store, cosigned.id, typed_code=None, yes=True)
    assert node.vm_published == [] and node.shared == []


def test_a_community_curator_cannot_correct_verified_rows(monkeypatch, tmp_path, curators):
    """Review guard (P5 b): `correct` is the verified authority's verb; a machine acting for the
    community authority is refused before any lookup, even with a manifest in force."""
    from plugins.blackbox.kernel.signing.authority import Authority

    _machine(monkeypatch, tmp_path, "A", curators.a)
    view = cv.CuratorView(manifest=curators.manifest, community=cv.CuratorView(manifest=curators.manifest))
    ctx = CurateContext(cfg=CFG, client=FakeNode(), environment=NETWORK, view=view, sandbox=True, compiled=None,
                        authority=Authority.COMMUNITY)
    store = ProposalStore()
    with pytest.raises(VerbError, match="only the verified graph's curators"):
        correction_verbs.cmd_correct(_args(yes=True), context=ctx, lookup=lambda *a: pytest.fail("refused before any lookup"),
                                     store=store)
    assert store.all() == []


def test_the_cli_prints_a_refusal_and_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(correction_verbs, "build_context", lambda *a, **k: pytest.fail("refused before reading the node"))
    run = correction_verbs._guarded(correction_verbs.cmd_correct)
    assert run(_args(identifier="dep:npm:left-pad@1.3.0")) == 2
    assert capsys.readouterr().out.startswith("Refused: a correction suppresses an ADDRESS")


# -- never-flag: exact addresses only ---------------------------------------------------


def _warninglist(values, list_type="cidr"):
    return {"name": "List of known IPv4 public DNS resolvers", "type": list_type, "list": values}


@pytest.mark.parametrize("value, reason", [
    ("8.8.8.0/24", "a range"),
    ("2001:4860::/32", "a range"),
    ("*.google.com", "a range or pattern"),
    ("1.1.1.1-1.1.1.5", "not an exact IP address or hostname"),
    ("github.io", "a shared-hosting apex"),
    ("evil.github.io", "a shared-hosting apex"),
    ("amazonaws.com", "a shared-hosting apex"),
    ("pages.dev", "a shared-hosting apex"),
    ("dep:npm:left-pad@1.3.0", "not an address"),
    ("npm:left-pad@1.3.0", "not an address"),
    ("skill:totally-safe-helper@2.1.0", "not an address"),
    ("ioc:url:https://dns.google/resolve", "not an address"),
])
def test_never_flag_refuses_ranges_shared_hosting_apexes_and_packages(value, reason):
    batch = never_flag.review(_warninglist([value]))
    assert batch.accepted == ()
    [refusal] = batch.refused
    assert refusal.value == value and reason in refusal.reason


def test_never_flag_accepts_exact_resolver_addresses_and_hostnames_canonically():
    batch = never_flag.review(_warninglist(["8.8.8.8", "2001:4860:4860:0:0:0:0:8888", "Dns.Google.", "ioc:ip:1.1.1.1",
                                            "8.8.8.8", ""]))
    assert batch.accepted == ("ioc:ip:8.8.8.8", "ioc:ip:2001:4860:4860::8888", "ioc:domain:dns.google", "ioc:ip:1.1.1.1")
    assert batch.refused == () and batch.source == "misp-warninglists:List of known IPv4 public DNS resolvers"


@pytest.mark.parametrize("document, refused", [
    (_warninglist(["google"], list_type="substring"), "holds patterns"),
    (_warninglist([".*\\.google\\.com"], list_type="regex"), "holds patterns"),
    ({"list": ["8.8.8.8"]}, "not a MISP warninglist"),
    (_warninglist(["8.8.8.8"] * (never_flag.MAX_ENTRIES + 1)), "at most"),
])
def test_a_file_that_is_not_an_exact_value_list_is_refused_whole(document, refused):
    with pytest.raises(never_flag.NeverFlagError, match=refused):
        never_flag.review(document)


def test_the_never_flag_verb_signs_only_reviewed_addresses_the_verified_graph_holds(monkeypatch, tmp_path, capsys, curators):
    _machine(monkeypatch, tmp_path, "A", curators.a)
    listing = tmp_path / "list.json"
    listing.write_text(json.dumps(_warninglist(["8.8.8.8", "1.1.1.1", "10.0.0.0/8", "github.io", "dep:npm:x@1"])))
    ctx, store = _verified_ctx(FakeNode(), curators.manifest), ProposalStore()
    lookup = _lookup({"ioc:ip:8.8.8.8": (LEGACY_8888,), "ioc:ip:10.0.0.0/8": ("urn:defender:signal:range",)})
    args = _args(file=str(listing), reason="known-good address (never-flag list)", verb="never-flag")
    assert correction_verbs.cmd_never_flag(args, context=ctx, lookup=lookup, store=store) == 2
    review = capsys.readouterr().out
    assert "2 exact address(es) accepted, 3 refused, 1 held by the verified graph" in review
    assert store.all() == []                                                   # reviewed first: nothing signed
    args.code = _shown_code(review)
    assert correction_verbs.cmd_never_flag(args, context=ctx, lookup=lookup, store=store) == 0
    [proposal] = store.all()                                                   # 1.1.1.1 is not held: nothing to correct
    payload = proposal.parsed().payload
    assert (proposal.kind, proposal.identifier, payload["targetSubjects"]) == ("blackbox.correction", "ioc:ip:8.8.8.8", LEGACY_8888)
    assert payload["source"] == "misp-warninglists:List of known IPv4 public DNS resolvers"


def test_a_package_identifier_is_never_corrected(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators.a)
    for identifier in ("dep:npm:left-pad@1.3.0", "skill:x@1", "ioc:ip:08.8.8.8 ", "IOC:ip:8.8.8.8"):
        with pytest.raises(VerbError):
            correction_verbs.cmd_correct(_args(identifier=identifier, yes=True), context=_verified_ctx(FakeNode(), curators.manifest),
                                         lookup=lambda *a: pytest.fail("refused before any lookup"), store=ProposalStore())


# -- the subjects come from the verified graph -----------------------------------------------


class SubjectNode:
    """Answers the subject query: rows per stored value; None = the read cannot be believed."""

    def __init__(self, held, fail=False):
        self.held, self.fail, self.queries = held, fail, []

    def query(self, sparql, cg_id=None, view=None, on_error=None, **kw):
        self.queries.append((sparql, cg_id, view))
        if self.fail:
            return on_error
        return [{"t": subject, "val": value} for value, subjects in self.held.items()
                if json.dumps(value) in sparql for subject in subjects]


def test_every_subject_the_verified_graph_holds_is_returned_and_could_not_tell_refuses(curators):
    node = SubjectNode({"8.8.8.8": [LEGACY_8888, threat_ids.threat_uri("ioc:ip:8.8.8.8")]})
    found = correction_verbs.verified_subjects(_verified_ctx(node, curators.manifest), ["ioc:ip:8.8.8.8", "ioc:ip:1.1.1.1"])
    assert found == {"ioc:ip:8.8.8.8": tuple(sorted([LEGACY_8888, threat_ids.threat_uri("ioc:ip:8.8.8.8")]))}
    [(sparql, graph, view)] = [query for query in node.queries if "VALUES ?val" in query[0]]
    assert (graph, view) == (VM_GRAPH, constants.VIEW_VERIFIABLE_MEMORY) and "LIMIT" in sparql
    with pytest.raises(VerbError, match="could not be read"):
        correction_verbs.verified_subjects(_verified_ctx(SubjectNode({}, fail=True), curators.manifest), ["ioc:ip:8.8.8.8"])


def test_subject_queries_are_chunked(curators):
    node = SubjectNode({})
    identifiers = [f"ioc:ip:10.0.{n // 256}.{n % 256}" for n in range(correction_verbs.LOOKUP_CHUNK + 1)]
    assert correction_verbs.verified_subjects(_verified_ctx(node, curators.manifest), identifiers) == {}
    assert sum("VALUES ?val" in query[0] for query in node.queries) == 2


# -- published at once, then the advisory twin -----------------------------------------------


def _twins(node):
    return [(graph, name, quads) for graph, name, quads in node.shared if name.startswith("curator-twin-")]


def _published_envelope(node):
    (_graph, _path, quads), = node.vm_published
    return json.loads(next(q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED))


@pytest.mark.parametrize("second", ["b", "glass"])
def test_a_correction_is_published_at_once_and_followed_by_its_advisory_twin(monkeypatch, tmp_path, capsys, curators, second):
    """Amos's code on A; B's or the break-glass key's signature second (a reduction, K2)."""
    node = FakeNode()
    proposal, _ = _propose_correction(monkeypatch, tmp_path, capsys, curators, node)
    _published, outcome = _approve_on(monkeypatch, tmp_path, second, getattr(curators, second), node, curators.manifest, proposal)
    assert outcome.startswith(f"published to {VM_GRAPH} as correction-") and "advisory twin posted to " + COMMUNITY in outcome
    (_g, _p, quads), = node.vm_published
    assert {q["object"] for q in quads if q["predicate"] == constants.DEFENDER_CORRECTION_TARGET_PRED} == {LEGACY_8888}
    [(graph, _name, twin)] = _twins(node)
    assert graph == COMMUNITY and json.loads(twin[1]["object"]) == _published_envelope(node)


def test_a_revocation_is_followed_by_its_advisory_twin(monkeypatch, tmp_path, curators):
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators.a)
    revocation = verbs.propose_statement(_verified_ctx(node, curators.manifest), ProposalStore(),
                                         kind=publish_module.CuratorStatement.REVOCATION, identifier="dep:npm:old@1",
                                         fields={"reason": "false-positive"})
    _published, outcome = _approve_on(monkeypatch, tmp_path, "B", curators.b, node, curators.manifest, revocation)
    assert "advisory twin posted" in outcome
    [(graph, name, twin)] = _twins(node)
    assert graph == COMMUNITY and name.startswith("curator-twin-revocation-")
    assert json.loads(twin[1]["object"]) == _published_envelope(node)


def test_the_twin_waits_for_the_read_back_and_other_statements_have_none(monkeypatch, tmp_path, capsys, curators):
    class UnreadableNode(FakeNode):
        def query(self, sparql, cg_id=None, view=None, on_error=None, **kw):
            return on_error

    node = UnreadableNode()
    proposal, _ = _propose_correction(monkeypatch, tmp_path, capsys, curators, node)
    _published, outcome = _approve_on(monkeypatch, tmp_path, "B", curators.b, node, curators.manifest, proposal)
    assert outcome.startswith("not published") and _twins(node) == []   # the pulse would find nothing yet
    with pytest.raises(VerbError, match="advisory twin"):
        publish_module.advisory_twin(signing.sign(curators.a, statement_type="blackbox.rejection", environment=NETWORK,
                                                  graph=COMMUNITY, payload={"identifier": "x"}))


def test_the_twin_changes_the_pulse_fingerprint_but_no_reader_acts_on_it(curators):
    """Typed g:CuratorStatement (the pulse counts it), no g:identifier (every statement read
    requires one), and the envelope is bound to the verified graph — never a community verdict."""
    envelope = signing.cosign(signing.sign(curators.a, statement_type="blackbox.revocation", environment=NETWORK,
                                           graph=VM_GRAPH, payload={"identifier": "dep:npm:old@1", "day": "2026-10-11",
                                                                    "reason": "false-positive"}, root_epoch=1, sequence=7),
                              curators.b)
    name, quads = publish_module.advisory_twin(envelope)
    assert name.startswith("curator-twin-revocation-")
    assert {q["predicate"] for q in quads} == {constants.RDF_TYPE, constants.SIGNED_STATEMENT_PRED}
    assert [q["object"] for q in quads if q["predicate"] == constants.RDF_TYPE] == [constants.CURATOR_STATEMENT_TYPE_IRI]
    row = {"r": quads[0]["subject"], "identifier": "dep:npm:old@1", "signedStatement": json.loads(quads[1]["object"])}
    assert curator_statements.parse_statement(row, curators.manifest, graph=COMMUNITY) is None
    assert publish_module.advisory_twin(envelope) == (name, quads)            # deterministic: a retry is the same asset


def test_the_verb_signs_every_subject_the_verified_graph_holds(monkeypatch, tmp_path, capsys, curators):
    """Review guard (P5): the live lookup keeps one rule per identifier, so a correction that
    named only the first subject would expose the next — the verb signs ALL of them."""
    _machine(monkeypatch, tmp_path, "A", curators.a)
    node, store = FakeNode(), ProposalStore()
    own_uri = threat_ids.threat_uri("ioc:ip:8.8.8.8")
    lookup = _lookup({"ioc:ip:8.8.8.8": (own_uri, LEGACY_8888)})
    ctx = _verified_ctx(node, curators.manifest)
    assert correction_verbs.cmd_correct(_args(), context=ctx, lookup=lookup, store=store) == 2
    code = _shown_code(capsys.readouterr().out)
    assert correction_verbs.cmd_correct(_args(code=code), context=ctx, lookup=lookup, store=store) == 0
    [proposal] = store.all()
    assert set(proposal.parsed().payload["targetSubjects"].split()) == {own_uri, LEGACY_8888}
    _published, outcome = _approve_on(monkeypatch, tmp_path, "B", curators.b, node, curators.manifest, proposal)
    assert outcome.startswith("published")
    (_g, _p, quads), = node.vm_published
    assert {q["object"] for q in quads if q["predicate"] == constants.DEFENDER_CORRECTION_TARGET_PRED} == {own_uri, LEGACY_8888}


def test_a_twin_the_community_graph_refuses_never_undoes_the_publication(monkeypatch, tmp_path, capsys, curators):
    """Review guard (P5): the twin is best effort — the correction stays published and the
    outcome says the twin was not posted; readers withdraw on their next full refresh."""
    class TwinRefusingNode(FakeNode):
        def share_knowledge_asset(self, cg, name, quads, **kw):
            raise RuntimeError("node 503")

    node = TwinRefusingNode()
    proposal, _ = _propose_correction(monkeypatch, tmp_path, capsys, curators, node)
    _published, outcome = _approve_on(monkeypatch, tmp_path, "B", curators.b, node, curators.manifest, proposal)
    assert outcome.startswith(f"published to {VM_GRAPH} as correction-") and "advisory twin NOT posted (node 503)" in outcome
    assert ProposalStore().get(proposal.id).state is ProposalState.PUBLISHED   # B's store, as the approve left it
    assert len(node.vm_published) == 1 and node.shared == []


def test_a_correction_never_enters_a_batch(world):
    correction = world.approve(_dep(998), kind="blackbox.correction")
    for n in range(50):
        world.approve(_ioc(n))
    world.publisher.run(world.ctx)
    [record] = world.ledger.batches()
    assert _dep(998) not in {entry.identifier for entry in record.entries}
    assert world.store.get(correction.id).state is ProposalState.APPROVED   # left for the at-once path
    # Review guard: filtered out by KIND, not merely refused by a row builder — it is not "held back" either.
    assert world.publisher.metrics(world.ctx).held_back == 0


# -- the verbs reach the plugin through the real Hermes parser -------------------------------


@pytest.mark.parametrize("argv, attribute, value, function", [
    (["blackbox", "curate", "correct", "ioc:ip:8.8.8.8", "--reason", "public DNS resolver", "--source", "misp"],
     "identifier", "ioc:ip:8.8.8.8", "cmd_correct"),
    (["blackbox", "curate", "never-flag", "list.json", "--code", "0123abcd"], "file", "list.json", "cmd_never_flag"),
])
def test_both_verbs_parse_through_the_real_hermes_parser(tmp_path, argv, attribute, value, function):
    import os
    import subprocess
    import sys
    from pathlib import Path

    from test_blackbox_host_arg_names import _REAL_PARSE

    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "hermes"), "PYTHONPATH": str(root)}
    probe = _REAL_PARSE + "print(json.dumps([args.func.__module__, args.func.__name__]))\n"
    done = subprocess.run([sys.executable, "-c", probe, json.dumps(argv), attribute], cwd=root, env=env,
                          capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    parsed, (module, name) = (json.loads(line) for line in done.stdout.strip().splitlines()[-2:])
    assert parsed == {"version": False, "command": "blackbox", "value": value}
    assert module.endswith("curate.publishing.commands") and name == function


def test_the_verbs_register_from_the_publishing_package_not_curate_commands():
    from pathlib import Path

    curate = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "curate"
    for verb in ('"correct"', '"never-flag"'):
        assert verb not in (curate / "commands.py").read_text(encoding="utf-8")
        assert verb in (curate / "publishing" / "commands.py").read_text(encoding="utf-8")


def test_the_curate_parser_keeps_every_lanes_verbs_after_a_merge():
    """curate/parser.py is a shared registry: a merge resolved by dropping one lane's
    lines would lose that lane's verbs silently. The lab (L4), watch (W3) and
    publishing (P5) verbs must all be registered on the same ``curate`` parser."""
    import argparse

    from plugins.blackbox.curate.parser import add_curate_parser

    cli = argparse.ArgumentParser()
    add_curate_parser(cli.add_subparsers(dest="command"))
    curate = cli._subparsers._group_actions[0].choices["curate"]
    verbs = curate._subparsers._group_actions[0].choices
    assert {"lab", "watch", "correct", "never-flag", "console", "publish"} <= set(verbs)
    assert verbs["lab"].get_default("func").__module__.endswith("curate.lab.commands")
    for verb in ("correct", "never-flag"):
        assert verbs[verb].get_default("func").__module__.endswith("curate.publishing.commands")
