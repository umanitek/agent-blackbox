"""The member-asset way of the one-graph flow: a community report is promoted AS ITSELF.

Not the active way (``publishing.strategies``: it waits for the DKG to let a
curator publish a member's shared asset on this graph type), so every test here
selects it. Two curator keys sign a promotion statement that points at one
report in the verified graph's shared memory (sub-graph ``reports``); the
publisher publishes the reporter's own asset to Verified Memory (the node
resolves its author, this node pays) and the statement beside it; the verified
reader then serves it as a blocking rule. Every key and the publisher re-check
the report on their own node first; a report is paid for once; the batch
publishes each report before the one statement asset of its batch.
"""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from _community_rows import Reporter
from _one_graph import (NETWORK, SHARED, STORE_URL, SUB_GRAPH, VERIFIED, VM_GRAPH, NodeStore, promotion_envelope,
                        shared_report, use_store)
from plugins.blackbox import community
from plugins.blackbox.community.statements.curator_view import CuratorView
from plugins.blackbox.curate import promotion, transport, verbs
from plugins.blackbox.curate.context import CurateContext
from plugins.blackbox.curate.proposal import Proposal, ProposalState, ProposalStore
from plugins.blackbox.curate.publishing import commands as correction_verbs
from plugins.blackbox.curate.publishing import strategies
from plugins.blackbox.curate.publishing.batch import BatchPublisher
from plugins.blackbox.curate.publishing.ledger import PublishLedger, PublishState
from plugins.blackbox.curate.publishing.sequences import next_sequence
from plugins.blackbox.kernel import constants, node_routes, signing, threat_ids
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import promotion_statement as statement
from plugins.blackbox.ruleset import compiler
from plugins.blackbox.ruleset.live import promoted
from test_blackbox_curate import _machine

# The package re-exports the publish FUNCTION under the submodule's name.
publish_module = importlib.import_module("plugins.blackbox.curate.publishing.publish")

CFG = BlackboxConfig(report=True, context_graph_id=VM_GRAPH)
EVIL = "dep:npm:evil-pkg@1.0.0"
EDGE = Reporter("edge-1")
START = 1_800_000_000.0
HOUR = 3600.0


class CuratorNode:
    """The curator's node over one store: the edges' shared reports, its own publishes, its inbox."""

    def __init__(self, store: NodeStore):
        self.store = store
        self.assets: dict[str, dict] = {}          # "<author>:<number>" -> the shared asset
        self.sealed: dict[str, list] = {}
        self.statements: list = []                 # published statement assets: (graph, name, quads)
        self.member_publishes: list = []           # (asset name, request body)
        self.member_errors: list = []              # raised by the next member publishes
        self.bind = True                           # False: a 207 — minted, the report not readable
        self.messages: list = []

    def share(self, report, *, number=5, name=""):
        """The edge's share, as this node received it: the report's asset in the reports sub-graph."""
        author = report.reporter.address.lower()
        name = name or f"report-{threat_ids.stable_hash(report.identifier + report.reporter.address, 16)}-e{number}"
        self.store.hold(report, layer=SHARED, number=number)
        self.assets[f"{author}:{number}"] = {"name": name, "report": report, "number": number, "author": author}
        return name

    def status(self, timeout=None):
        return {"networkId": NETWORK, "storeUrl": STORE_URL}

    def _signed(self):
        return [(q["subject"], q["object"], next((p["object"] for p in quads if p["subject"] == q["subject"]
                                                  and p["predicate"] == statement.PROMOTES_REPORT_PRED), ""))
                for _graph, _name, quads in self.statements for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED]

    def query(self, sparql, cg_id=None, view=None, on_error=None, **_kw):
        if "promotesReport" in sparql:
            return [{"r": subject, "report": report, "signedStatement": text} for subject, text, report in self._signed()]
        if "VALUES ?r" in sparql and view == constants.VIEW_VERIFIABLE_MEMORY:
            return [{"r": subject, "o": text} for subject, text, _ in self._signed() if f"<{subject}>" in sparql]
        if "VALUES ?val" in sparql:                       # the corrections' subject lookup: no corpus rows here
            return []
        return on_error

    def write_private_knowledge_asset(self, cg, name, quads):
        self.sealed[name] = list(quads)
        return {"name": name}

    def share_finalized_knowledge_asset(self, cg, name, sub_graph=""):
        return {"state": "succeeded"}

    def request(self, method, path, body=None, timeout=None):
        parts = urlsplit(path)
        if method == "GET" and parts.path.startswith("/api/knowledge-assets/"):
            return self._descriptor(unquote(parts.path.rsplit("/", 1)[-1]), parse_qs(parts.query))
        if path.endswith("/vm/publish"):
            name = unquote(path.split("/")[3])
            if "selectedAuthorAgentAddress" in body:
                return self._publish_member(name, body)
            self.statements.append((body["contextGraphId"], name, self.sealed[name]))
            return {"ual": f"did:dkg:31337/0xc0/{len(self.statements)}", "txHash": "0xtx", "status": "confirmed"}
        if path == "/api/chat":
            self.messages.append(body)
            return {"delivered": True}
        if path.startswith("/api/messages"):
            return {"messages": [{"id": i + 1, "ts": 1000 + i, "peer": "A", "text": m["text"]}
                                 for i, m in enumerate(self.messages)]}
        raise AssertionError(path)

    def _descriptor(self, identifier, query):
        asset = self.assets.get(identifier) or next(
            (a for a in self.assets.values() if a["name"] == identifier and a["author"] == query["agentAddress"][0].lower()), None)
        if asset is None:
            raise DkgError(f"GET {identifier} -> 404", status_code=404)
        published = {"vmCurrentAssertion": "cd" * 32, "publishedUal": asset["ual"]} if asset.get("ual") else {}
        return {"name": asset["name"], "agentAddress": asset["author"], "swmCurrentAssertion": "ab" * 32, **published}

    def _publish_member(self, name, body):
        self.member_publishes.append((name, dict(body)))
        if self.member_errors:
            raise self.member_errors.pop(0)
        asset = next(a for a in self.assets.values() if a["name"] == name
                     and a["author"] == body["selectedAuthorAgentAddress"].lower())
        ual = f"did:dkg:31337/{asset['author']}/{asset['number']}"
        asset["ual"] = ual
        if self.bind:
            self.store.hold(asset["report"], layer=VERIFIED, number=asset["number"])
        return {"ual": ual, "txHash": "0xtx", "status": "confirmed" if self.bind else "partial"}


@pytest.fixture(autouse=True)
def member_asset(monkeypatch):
    """New promotions take the member-asset way here."""
    monkeypatch.setattr(strategies, "ACTIVE", strategies.MEMBER_ASSET)


@pytest.fixture
def curators():
    """Three curator keys and their 2-of-3 manifest for the verified graph."""
    a, b, c = (Ed25519PrivateKey.generate() for _ in range(3))
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1,
                              curator_keys=tuple(sorted(signing.public_key_hex(k) for k in (a, b, c))),
                              curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    return {"a": a, "b": b, "c": c, "manifest": manifest}


@pytest.fixture
def node(monkeypatch):
    store = NodeStore()
    use_store(monkeypatch, store)
    return CuratorNode(store)


def _ctx(node, manifest):
    return CurateContext(cfg=CFG, client=node, environment=NETWORK, view=CuratorView(manifest=manifest), sandbox=True,
                         compiled=None)


def _proposed(monkeypatch, tmp_path, node, curators, report, *, severity="critical"):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    return verbs.propose_promotion(_ctx(node, curators["manifest"]), ProposalStore(), report=report.verified,
                                   severity=severity, evidence="advisory:MAL-2026-0001", reason="")


def _on_b(monkeypatch, tmp_path, node, curators, proposal):
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store = ProposalStore()
    store.save(proposal)
    return store


# ------------------------------------------------------------------ the two-key flow, end to end


def test_a_report_is_promoted_by_two_keys_and_published_as_itself(monkeypatch, tmp_path, node, curators):
    report = shared_report(EVIL, EDGE)
    asset = node.share(report, number=5)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    envelope = proposal.parsed()
    assert envelope.payload == {"identifier": EVIL, "report": report.subject, "reportDigest": report.digest,
                                "reporterKey": EDGE.author, "severity": "critical",
                                "day": envelope.payload["day"]}   # a pointer to one report: nothing copied
    verbs.send(_ctx(node, curators["manifest"]), proposal, "B")
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    [received] = transport.receive_proposals(node, transport.InboxCursor())
    store_b = ProposalStore()
    store_b.save(received)
    _, outcome = verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id,
                               evidence="advisory:MAL-2026-0001", typed_code=None, yes=True)
    assert outcome.startswith(f"published to {VM_GRAPH} as promotion-")
    assert store_b.get(proposal.id).state is ProposalState.PUBLISHED
    # 1. the reporter's own asset, from the reports sub-graph, its author selected — nothing rewritten
    assert node.member_publishes == [(asset, {"contextGraphId": VM_GRAPH, "selectedAuthorAgentAddress": EDGE.address,
                                              "subGraphName": SUB_GRAPH})]
    # 2. the two-key statement beside it
    [(graph, _name, quads)] = node.statements
    cosigned = signing.from_text(json.loads(next(q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED)))
    assert graph == VM_GRAPH and curators["manifest"].has_quorum(cosigned, statement_type=statement.PROMOTION_STATEMENT, graph=VM_GRAPH)
    assert quads == statement.statement_quads(cosigned)
    # 3. a reader serves it as a blocking verified rule
    monkeypatch.setattr(community, "verified_manifest_history", lambda client, graph, env: (curators["manifest"],))
    rs = compiler.Ruleset()
    promoted.apply_promoted_reports(rs, node, CFG, CuratorView(manifest=curators["manifest"]))
    rule = rs.dependency[threat_ids.dependency_key("npm", "evil-pkg", "1.0.0")]
    assert (rule["source"], rule["kind"], rule["severity"], rule[promoted.PROMOTED_REPORT]) == (
        "public", "malware", "critical", report.subject)


def test_the_proposer_sees_its_promotion_published_by_the_other_curator(monkeypatch, tmp_path, node, curators):
    """"Whoever signs second publishes": the first signer's beat closes its own proposal from the graph."""
    from plugins.blackbox.curate.service import inbox
    report = shared_report(EVIL, EDGE)
    node.share(report)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    ctx = _ctx(node, curators["manifest"])
    assert not inbox.published_elsewhere(ctx, proposal, proposal.parsed())
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    verbs.approve(ctx, store_b, proposal.id, evidence="advisory:x", typed_code=None, yes=True)
    assert inbox.published_elsewhere(ctx, proposal, proposal.parsed())


def test_the_second_key_refuses_a_report_its_own_node_does_not_hold(monkeypatch, tmp_path, node, curators):
    report = shared_report(EVIL, EDGE)
    node.share(report)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    node.store.graphs.clear()                       # B's node has not received the share
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    with pytest.raises(verbs.VerbError, match="does not hold the report"):
        verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:MAL-1",
                      typed_code=None, yes=True)
    assert store_b.get(proposal.id).state is ProposalState.PROPOSED and node.member_publishes == []


def test_the_second_key_refuses_another_report_under_the_same_subject(monkeypatch, tmp_path, node, curators):
    """A report signed by another key naming the reporter's address has the same subject, not the same digest."""
    report = shared_report(EVIL, EDGE)
    node.share(report)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    node.store.graphs.clear()
    node.share(shared_report(EVIL, Reporter(EDGE.address)), number=6)
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    with pytest.raises(verbs.VerbError, match="signed digest and reporter key"):
        verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:MAL-1",
                      typed_code=None, yes=True)


def test_a_report_already_in_verified_memory_is_never_paid_for_again(monkeypatch, tmp_path, node, curators):
    report = shared_report(EVIL, EDGE)
    node.share(report)
    node.store.hold(report, layer=VERIFIED, number=5)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    _, outcome = verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:MAL-1",
                               typed_code=None, yes=True)
    assert outcome.startswith("published") and node.member_publishes == [] and len(node.statements) == 1


def test_the_nodes_lifecycle_record_never_decides_that_a_report_was_promoted(monkeypatch, tmp_path, node, curators):
    """The record names Verified Memory pointers whatever the store holds (and keeps the shared-memory one after a
    publish): only a copy in this node's Verified Memory counts, so the report is published."""
    report = shared_report(EVIL, EDGE)
    asset = node.share(report)
    node.assets[f"{EDGE.address.lower()}:5"]["ual"] = "did:dkg:31337/edge/5"   # the record says "published"
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    _, outcome = verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:MAL-1",
                               typed_code=None, yes=True)
    assert outcome.startswith("published") and [name for name, _body in node.member_publishes] == [asset]


def test_a_refused_report_publish_pays_for_no_statement_and_can_be_published_again(monkeypatch, tmp_path, node, curators):
    report = shared_report(EVIL, EDGE)
    node.share(report)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    node.member_errors.append(DkgError("POST … -> 409: PUBLISH_NOT_FULL_SHARE", status_code=409))
    with pytest.raises(verbs.VerbError, match="refused to publish the report .* nothing was paid"):
        verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:MAL-1",
                      typed_code=None, yes=True)
    assert store_b.get(proposal.id).state is ProposalState.APPROVED and node.statements == []
    _, outcome = publish_module.publish(_ctx(node, curators["manifest"]), store_b, proposal.id, typed_code=None, yes=True)
    assert outcome.startswith("published") and len(node.member_publishes) == 2 and len(node.statements) == 1


def test_the_consent_summary_names_the_report_it_makes_permanent_and_a_whole_package_scope(monkeypatch, tmp_path,
                                                                                           node, curators):
    report = shared_report(EVIL, EDGE)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report, severity="high")
    summary = publish_module.summary(proposal)
    assert (f"PROMOTES THE REPORT {report.subject} (permanent; names its reporter) · severity high · publishes the "
            "reporter's own asset") in summary and "WHOLE" not in summary
    whole = shared_report("dep:npm:evil-pkg@*", EDGE)            # a typosquat report names every version
    proposal = verbs.propose_promotion(_ctx(node, curators["manifest"]), ProposalStore(), report=whole.verified,
                                       severity="critical", evidence="advisory:MAL-1", reason="typosquat")
    assert "WHOLE PACKAGE (every version)" in publish_module.summary(proposal)


# ------------------------------------------------------------------ which report, and which may be promoted


def test_the_earliest_report_is_chosen_unless_one_is_named():
    late = shared_report(EVIL, Reporter("edge-late"))
    early = shared_report(EVIL, EDGE)
    early_record = early.verified.__class__(**{**early.verified.__dict__, "day": "2026-10-01"})
    assert promotion.choose_report([late.verified, early_record], EVIL) is early_record
    assert promotion.choose_report([late.verified, early_record], EVIL, subject=late.subject) is late.verified
    with pytest.raises(promotion.PromotionError, match="no verified community report"):
        promotion.choose_report([late.verified], "dep:npm:nobody@1.0.0")


def test_only_a_malware_dependency_and_whole_reports_of_promotable_types_are_promoted():
    report = shared_report(EVIL, EDGE).verified
    vulnerable = report.__class__(**{**report.__dict__, "fields": tuple((k, "vulnerability" if k == "kind" else v)
                                                                         for k, v in report.fields)})
    with pytest.raises(promotion.PromotionError, match="malware dependencies only"):
        promotion.report_reference(vulnerable)
    injection = report.__class__(**{**report.__dict__, "identifier": threat_ids.injection_identifier("ignore all")})
    with pytest.raises(promotion.PromotionError, match="injection report carries no pattern"):
        promotion.report_reference(injection)
    for strategy in strategies.STRATEGIES.values():   # neither way signs one
        with pytest.raises(promotion.PromotionError):
            strategy.payload(vulnerable, severity="high", advisory="", display_name="")


# ------------------------------------------------------------------ the batch publisher (step 8)


class _Lookup:
    def __call__(self, identifiers):
        return set()


@pytest.fixture
def batch(monkeypatch, tmp_path, node, curators):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "publisher"))
    clock = SimpleNamespace(now=START)
    store = ProposalStore(tmp_path / "proposals")
    ledger = PublishLedger(tmp_path / "publish_ledger.jsonl", clock=lambda: clock.now)
    publisher = BatchPublisher(store, ledger, verified_subset=_Lookup(), clock=lambda: clock.now)
    keys = (curators["a"], curators["b"])
    sequence = iter(range(1, 1000))

    def approve(report, *, at=START - 7 * HOUR):
        envelope = promotion_envelope(report, keys, sequence=next(sequence))
        proposal = Proposal.new(statement.PROMOTION_STATEMENT, report.identifier, envelope, VM_GRAPH, checks={}, now=at)
        store.save(proposal.transition(ProposalState.PROPOSED, now=at).transition(ProposalState.APPROVED, now=at))
        return proposal

    return SimpleNamespace(ctx=_ctx(node, curators["manifest"]), node=node, store=store, ledger=ledger,
                           publisher=publisher, approve=approve, clock=clock, keys=keys)


def _reports(ledger):
    return [record for record in ledger.batches() if record.batch_id.startswith("report:")]


def _statement_batches(ledger):
    return [record for record in ledger.batches() if not record.batch_id.startswith("report:")]


def test_a_batch_publishes_each_report_as_itself_then_one_statement_asset(batch):
    first, second = shared_report(EVIL, EDGE), shared_report(threat_ids.ioc_identifier("domain", "drainer.example"), EDGE)
    batch.node.share(first, number=5)
    batch.node.share(second, number=6)
    proposals = [batch.approve(first), batch.approve(second)]
    report = batch.publisher.run(batch.ctx)
    assert (report.action, report.entries) == ("published", 2)
    assert sorted(body["selectedAuthorAgentAddress"] for _name, body in batch.node.member_publishes) == [EDGE.address] * 2
    assert [record.state for record in _reports(batch.ledger)] == [PublishState.BOUND, PublishState.BOUND]
    [record] = _statement_batches(batch.ledger)
    [(_graph, _name, quads)] = batch.node.statements
    assert record.state is PublishState.BOUND and {q["subject"] for q in quads} == {
        statement.statement_subject(p.identifier, p.parsed().sequence) for p in proposals}
    assert all(batch.store.get(p.id).state is ProposalState.PUBLISHED for p in proposals)


def test_a_promotion_whose_report_is_not_held_here_waits_outside_every_batch(batch):
    held, missing = shared_report(EVIL, EDGE), shared_report("dep:npm:later@1.0.0", EDGE)
    batch.node.share(held)
    waiting = batch.approve(missing)
    batch.approve(held)
    report = batch.publisher.run(batch.ctx)
    assert (report.action, report.entries) == ("published", 1)
    assert [e.identifier for e in _statement_batches(batch.ledger)[0].entries] == [EVIL]
    assert batch.store.get(waiting.id).state is ProposalState.APPROVED
    batch.node.share(missing, number=9)                       # the share arrives
    assert batch.publisher.run(batch.ctx).action == "published"
    assert batch.store.get(waiting.id).state is ProposalState.PUBLISHED


def test_a_curator_asset_promotion_never_waits_for_a_member_asset_report(batch):
    """Both ways in one store: the curator-asset entry (the default way) is batched at once as its rule row; the
    member-asset one waits outside every batch until its report reads back."""
    held_nowhere, other = shared_report("dep:npm:later@1.0.0", EDGE), shared_report(EVIL, Reporter("edge-2"))
    waiting = batch.approve(held_nowhere)
    payload = strategies.STRATEGIES[strategies.CURATOR_ASSET].payload(other.verified, severity="high", advisory="",
                                                                       display_name="")
    envelope = signing.cosign(signing.sign(batch.keys[0], statement_type=statement.PROMOTION_STATEMENT,
                                           environment=NETWORK, graph=VM_GRAPH, payload=payload, root_epoch=1,
                                           sequence=500), batch.keys[1])
    at = START - 7 * HOUR
    rule = Proposal.new(statement.PROMOTION_STATEMENT, EVIL, envelope, VM_GRAPH, checks={}, now=at)
    batch.store.save(rule.transition(ProposalState.PROPOSED, now=at).transition(ProposalState.APPROVED, now=at))
    report = batch.publisher.run(batch.ctx)
    assert (report.action, report.entries) == ("published", 1) and batch.node.member_publishes == []
    [(_graph, _name, quads)] = batch.node.statements
    assert {q["subject"] for q in quads} == {threat_ids.threat_uri(EVIL)}      # the rule row, not a pointer
    assert batch.store.get(rule.id).state is ProposalState.PUBLISHED
    assert batch.store.get(waiting.id).state is ProposalState.APPROVED


def test_a_refused_report_publish_is_retried_as_the_same_asset_and_no_statement_is_paid(batch):
    report = shared_report(EVIL, EDGE)
    asset = batch.node.share(report)
    batch.approve(report)
    batch.node.member_errors.append(DkgError("POST … -> 409: PUBLISH_NOT_FULL_SHARE", status_code=409))
    run = batch.publisher.run(batch.ctx)
    assert run.action == "failed" and "refused" in run.note
    [record] = _reports(batch.ledger)
    assert record.state is PublishState.SEALED and _statement_batches(batch.ledger) == [] and batch.node.statements == []
    assert batch.publisher.run(batch.ctx).action == "published"
    assert [name for name, _body in batch.node.member_publishes] == [asset, asset]
    assert _reports(batch.ledger)[0].state is PublishState.BOUND and batch.ledger.metrics().failures == 1


def test_a_report_minted_without_binding_is_never_submitted_again(batch):
    report = shared_report(EVIL, EDGE)
    batch.node.share(report)
    batch.approve(report)
    batch.node.bind = False                                       # a 207: paid, not readable
    assert batch.publisher.run(batch.ctx).action == "minted"
    assert _reports(batch.ledger)[0].state is PublishState.MINTED
    assert batch.publisher.run(batch.ctx).action == "held"       # read back, never re-minted
    assert len(batch.node.member_publishes) == 1 and batch.node.statements == []
    batch.node.store.hold(report, layer=VERIFIED, number=5)       # the binding lands
    assert batch.publisher.run(batch.ctx).action == "published"
    assert len(batch.node.member_publishes) == 1 and _reports(batch.ledger)[0].state is PublishState.BOUND


def test_a_report_publish_that_could_not_tell_moves_on_only_from_what_the_node_says(batch):
    report = shared_report(EVIL, EDGE)
    batch.node.share(report)
    batch.approve(report)
    batch.node.member_errors.append(DkgError("POST … -> 503: busy", status_code=503))
    assert batch.publisher.run(batch.ctx).action == "could-not-tell"
    assert _reports(batch.ledger)[0].state is PublishState.SUBMITTED
    assert batch.publisher.run(batch.ctx).action == "held"       # the node names no UAL yet
    asset = next(iter(batch.node.assets.values()))
    asset["ual"] = "did:dkg:31337/edge/5"                          # it was published after all
    batch.node.store.hold(report, layer=VERIFIED, number=5)
    assert batch.publisher.run(batch.ctx).action == "published"
    assert len(batch.node.member_publishes) == 1


# ------------------------------------------------------------------ corrections and numbering see promotions


def test_a_correction_can_target_a_promoted_report(monkeypatch, tmp_path, node, curators):
    report = shared_report(threat_ids.ioc_identifier("ip", "8.8.8.8"), EDGE)
    node.share(report)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:x", typed_code=None, yes=True)
    found = correction_verbs.verified_subjects(_ctx(node, curators["manifest"]), ["ioc:ip:8.8.8.8"])
    assert found == {"ioc:ip:8.8.8.8": (report.subject,)}


def test_numbering_continues_after_a_published_promotion(monkeypatch, tmp_path, node, curators):
    report = shared_report(EVIL, EDGE)
    node.share(report)
    proposal = _proposed(monkeypatch, tmp_path, node, curators, report)
    store_b = _on_b(monkeypatch, tmp_path, node, curators, proposal)
    verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:x", typed_code=None, yes=True)
    _machine(monkeypatch, tmp_path, "C", curators["c"])        # a third machine that never saw the proposal
    assert next_sequence(_ctx(node, curators["manifest"]), ProposalStore(), EVIL) == proposal.parsed().sequence + 1


# ------------------------------------------------------------------ the node routes


class _Recorder:
    def __init__(self, reply=None, error=None):
        self.calls, self.reply, self.error = [], reply or {}, error

    def request(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body, timeout))
        if self.error:
            raise self.error
        return self.reply


def test_a_member_asset_is_published_with_its_author_selected_and_time_for_the_chain():
    client = _Recorder({"ual": "did:dkg:31337/0xe/5"})
    node_routes.publish_shared_asset(client, VM_GRAPH, "report-ab-e5", author=EDGE.address, sub_graph=SUB_GRAPH)
    [(method, path, body, timeout)] = client.calls
    assert (method, path) == ("POST", "/api/knowledge-assets/report-ab-e5/vm/publish")
    assert body == {"contextGraphId": VM_GRAPH, "selectedAuthorAgentAddress": EDGE.address, "subGraphName": SUB_GRAPH}
    assert timeout == node_routes.PUBLISH_TIMEOUT_SECONDS > 60


def test_a_missing_asset_descriptor_is_none_and_other_failures_raise():
    assert node_routes.shared_asset(_Recorder(error=DkgError("404", status_code=404)), VM_GRAPH, "x", author=EDGE.address) is None
    with pytest.raises(DkgError):
        node_routes.shared_asset(_Recorder(error=DkgError("503", status_code=503)), VM_GRAPH, "x", author=EDGE.address)
    client = _Recorder({"name": "report-ab-e5"})
    assert node_routes.shared_asset(client, VM_GRAPH, f"{EDGE.address}:5", author=EDGE.address,
                                    sub_graph=SUB_GRAPH) == {"name": "report-ab-e5"}
    path = client.calls[0][1]
    assert path.startswith(f"/api/knowledge-assets/{EDGE.address}%3A5?") and "subGraphName=reports" in path
