"""Refine R6 — curator tooling lite.

The two-key flow end to end with a fake node: machine A proposes (checklist,
first key, private message), machine B receives, co-signs, consents and
publishes — a malware dependency's community report ends up as a BLOCKING
verified rule that names that report as its provenance (the curator-asset
way, ``publishing.strategies``, which a node that does not report DKG 10.0.25
takes, as these fake nodes do). Plus the plan's tests: a blockable kind needs
evidence; the second key re-checks what it co-signs; proposal expiry; consent
refused on any byte change; no browser endpoint can publish; an
already-verified threat never reaches a lane. (The member-asset way — the
report published as itself — is ``test_blackbox_one_graph_curator.py``.)
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox import ruleset
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import consent, dossier, keys, node_ui_views, publishing, queue, transport, verbs
from plugins.blackbox.curate.context import CurateContext, PromotionDraft
from plugins.blackbox.curate.proposal import Proposal, ProposalError, ProposalState, ProposalStore
from plugins.blackbox.curate.publishing import strategies
from plugins.blackbox.kernel import constants, node_routes, signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from _community_rows import Reporter
from _one_graph import SHARED, NodeStore, shared_report, use_store

NETWORK = "sandbox-net"
VM_GRAPH = "0xabc/agent-blackbox-vm"
COMMUNITY = VM_GRAPH   # one graph (2026-10-16): advisory statements go to the verified graph's shared memory
THREAT = "dep:npm:evil-pkg@1.0.0"
#: The community report every promotion here points at (signed for the verified graph: one graph).
REPORT = shared_report(THREAT, Reporter("edge-1"), graph=VM_GRAPH, network=NETWORK)
CFG = BlackboxConfig(report=True, context_graph_id=VM_GRAPH)
DAY = 86_400


class FakeNode:
    """Records every outward write; serves nothing (the curate verbs only need writes here)."""

    def __init__(self):
        self.vm_published, self.shared, self.messages, self.sealed = [], [], [], []
        self.order: list = []   # seal / share / publish, in call order (KI-351)

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id=None, view=None, on_error=None, **kw):
        """Answers only the read-back after a publish: is this signed statement among what was written?"""
        written = [quad for _, _, quads in (*self.vm_published, *self.shared) for quad in quads]
        if "VALUES ?r" in sparql and any(f"<{quad['subject']}>" in sparql and quad["object"] in sparql
                                         for quad in written if quad["predicate"].endswith("signedStatement")):
            return [{"r": "readable"}]
        return on_error

    def write_private_knowledge_asset(self, cg, name, quads):
        self.sealed.append((cg, name, quads))
        self.order.append("seal")
        return {"name": name}

    def request(self, method, path, body=None, timeout=None):
        if path.endswith("/vm/publish"):
            self.vm_published.append((body["contextGraphId"], path, self.sealed[-1][2]))
            self.order.append("publish")
            return {"status": "confirmed"}
        if path == "/api/chat":
            self.messages.append(body)
            return {"delivered": True}
        if path.startswith("/api/messages"):
            return {"messages": [{"id": i + 1, "ts": 1000 + i, "peer": "A", "text": m["text"]}
                                 for i, m in enumerate(self.messages)]}
        raise AssertionError(path)

    def share_finalized_knowledge_asset(self, cg, name):
        self.order.append("share")
        return {"state": "succeeded"}

    def share_knowledge_asset(self, cg, name, quads, **kw):
        self.shared.append((cg, name, quads))
        return {"state": "succeeded"}


@pytest.fixture
def curators():
    a, b, c = (Ed25519PrivateKey.generate() for _ in range(3))
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1,
                              curator_keys=tuple(sorted(signing.public_key_hex(k) for k in (a, b, c))),
                              curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    return {"a": a, "b": b, "c": c, "manifest": manifest}


def _ctx(node, manifest, compiled=None):
    view = cv.CuratorView(manifest=manifest)
    return CurateContext(cfg=CFG, client=node, environment=NETWORK, view=view, sandbox=True, compiled=compiled)


def _machine(monkeypatch, tmp_path, name, key):
    """A curator machine: its own BLACKBOX_HOME holding its curator key."""
    home = tmp_path / name
    monkeypatch.setenv("BLACKBOX_HOME", str(home))
    (home / "curate").mkdir(parents=True)
    store = keys.curator_key_store()
    store.install_pem(key.private_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
                                        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.PKCS8,
                                        __import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption()))
    return home


# ------------------------------------------------------------------ the two-key flow


class StoreNode(FakeNode):
    """A fake node that also reports its local store (``_one_graph.NodeStore``)."""

    def status(self, timeout=None):
        return {"networkId": NETWORK, "storeUrl": "http://127.0.0.1:7878/query"}


def _holding(monkeypatch, *reports):
    """Every curator machine's node store holds *reports* in the graph's shared memory."""
    store = NodeStore()
    for number, report in enumerate(reports, start=5):
        store.hold(report, layer=SHARED, number=number)
    use_store(monkeypatch, store)
    return store


def test_a_malware_dependency_is_promoted_by_two_keys_on_two_machines_with_one_hand_off(monkeypatch, tmp_path, curators):
    node = StoreNode()
    _holding(monkeypatch, REPORT)
    # Machine A: propose (checklist passes with an advisory), first signature, send.
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    proposal = verbs.propose_promotion(_ctx(node, curators["manifest"]), ProposalStore(), report=REPORT.verified,
                                       severity="critical", evidence="advisory:MAL-2026-0001", reason="")
    assert proposal.state is ProposalState.PROPOSED and len(proposal.parsed().signatures) == 1
    verbs.send(_ctx(node, curators["manifest"]), proposal, "B")
    # Machine B: receive, approve (own evidence; it re-reads the report on its node), consent (sandbox --yes), publish.
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    received = transport.receive_proposals(node, transport.InboxCursor())
    assert [p.id for p in received] == [proposal.id]
    store_b = ProposalStore()
    store_b.save(received[0])
    _published, outcome = verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id,
                                       evidence="advisory:MAL-2026-0001", typed_code=None, yes=True)
    assert outcome.startswith("published to " + VM_GRAPH)
    assert store_b.get(proposal.id).state is ProposalState.PUBLISHED
    # The write: the curators' own verified-rule KA, two curator signatures, the report as its provenance;
    # nothing of the reporter's is published or shared.
    (graph, _path, quads), = node.vm_published
    assert graph == VM_GRAPH and node.shared == []
    envelope = signing.from_text(json.loads(next(q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED)))
    assert curators["manifest"].has_quorum(envelope, statement_type=Kind.PROMOTION.value)
    assert (envelope.payload["report"], envelope.payload["reportDigest"], envelope.payload["reporterKey"]) == (
        REPORT.subject, REPORT.digest, REPORT.verified.author)                     # it names its reporter, permanently
    provenance = json.loads(json.loads(next(q["object"] for q in quads if q["predicate"] == constants.SOURCE_OBSERVATION_PROVENANCE_JSON_PRED)))
    assert provenance == [REPORT.subject]                                          # never a random id
    # The verified reader compiles it into a BLOCKING rule (kind malware, source public).
    row = {"threat": quads[0]["subject"], "rdfType": constants.DEFENDER_DEPENDENCY_TYPE_IRI}
    var_for = {constants.IDENTIFIER_PRED: "identifier", constants.SEVERITY_PRED: "severity", constants.KIND_PRED: "kind",
               constants.PACKAGE_NAME_PRED: "packageName", constants.PACKAGE_VERSION_PRED: "packageVersion",
               constants.PACKAGE_ECOSYSTEM_PRED: "packageEcosystem", constants.SCHEMA_NAME_PRED: "name",
               constants.SCHEMA_IDENTIFIER_PRED: "advisoryId"}
    for q in quads:
        if q["predicate"] in var_for:
            row[var_for[q["predicate"]]] = json.loads(q["object"])
    rs = ruleset.build_from_rows([(row, "public")])
    rule = rs.dependency["npm:evil-pkg@1.0.0"]
    assert (rule["kind"], rule["source"], rule["advisoryId"]) == ("malware", "public", "MAL-2026-0001")


def test_the_proposer_cannot_be_the_second_signer(monkeypatch, tmp_path, curators):
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    store = ProposalStore()
    proposal = verbs.propose_promotion(_ctx(node, curators["manifest"]), store, report=REPORT.verified, severity="high",
                                       evidence="advisory:MAL-1", reason="")
    with pytest.raises(verbs.VerbError, match="SECOND signature"):
        verbs.approve(_ctx(node, curators["manifest"]), store, proposal.id, evidence="advisory:MAL-1", typed_code=None, yes=True)
    assert node.vm_published == []


def test_a_proposal_signed_outside_the_manifest_is_refused(monkeypatch, tmp_path, curators):
    node = FakeNode()
    outsider = Ed25519PrivateKey.generate()
    _machine(monkeypatch, tmp_path, "X", outsider)
    store_x = ProposalStore()
    proposal = verbs.propose_promotion(_ctx(node, curators["manifest"]), store_x, report=REPORT.verified, severity="high",
                                       evidence="advisory:MAL-1", reason="")
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store_b = ProposalStore()
    store_b.save(proposal)
    with pytest.raises(verbs.VerbError, match="not signed by a curator key"):
        verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="advisory:MAL-1", typed_code=None, yes=True)


def test_a_blockable_promotion_without_evidence_is_refused(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    ctx = _ctx(FakeNode(), curators["manifest"])
    with pytest.raises(verbs.VerbError, match="checklist failed"):   # a blockable kind without evidence
        verbs.propose_promotion(ctx, ProposalStore(), report=REPORT.verified, severity="high", evidence="", reason="")
    assert dossier.passes(dossier.checklist("dep:npm:evil-pkg@*", kind="malware", evidence="advisory:MAL-1", reason="typosquat"))


def test_without_a_trusted_manifest_nothing_can_be_proposed(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    with pytest.raises(verbs.VerbError, match="no trusted key manifest"):
        verbs.propose_promotion(_ctx(FakeNode(), None), ProposalStore(), report=REPORT.verified, severity="high",
                                evidence="advisory:MAL-1", reason="")


def test_advisory_statements_go_to_the_community_graph_enforcement_to_the_verified_graph(monkeypatch, tmp_path, curators):
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    ctx_a, store_a = _ctx(node, curators["manifest"]), ProposalStore()
    rejection = verbs.propose_statement(ctx_a, store_a, kind=Kind.REJECTION, identifier=THREAT, fields={"reason": "benign"})
    revocation = verbs.propose_statement(ctx_a, store_a, kind=Kind.REVOCATION, identifier="dep:npm:old@1", fields={"reason": "false-positive"})
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store_b = ProposalStore()
    for p in (rejection, revocation):
        store_b.save(p)
        verbs.approve(_ctx(node, curators["manifest"]), store_b, p.id, evidence="", typed_code=None, yes=True)
    # rejection: advisory; then the revocation's advisory twin (trust-and-threat-lab P5, D26)
    assert [(cg, name.split("-")[1]) for cg, name, _q in node.shared] == [(COMMUNITY, "rejection"), (COMMUNITY, "twin")]
    assert [cg for cg, _p, _q in node.vm_published] == [VM_GRAPH]              # revocation: enforcement


def test_a_verified_confirmation_signs_the_evidence_given_and_stays_valid_without(monkeypatch, tmp_path, curators):
    """One graph: the verified curators confirm the community's threats, and the curator service's co-signer
    checks the advisory a confirmation cites — so a verified confirmation carries the evidence it is given."""
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    ctx = _ctx(FakeNode(), curators["manifest"])
    cited = verbs.propose_statement(ctx, ProposalStore(), kind=Kind.CONFIRMATION, identifier=THREAT, fields={},
                                    evidence="advisory:MAL-2026-0001")
    plain = verbs.propose_statement(ctx, ProposalStore(), kind=Kind.CONFIRMATION, identifier="dep:npm:other@1.0.0", fields={})
    assert cited.parsed().payload["evidence"] == "advisory:MAL-2026-0001" and "evidence" not in plain.parsed().payload
    with pytest.raises(verbs.VerbError, match="a confirmation's evidence is"):
        verbs.propose_statement(ctx, ProposalStore(), kind=Kind.CONFIRMATION, identifier=THREAT, fields={},
                                evidence="see the forum thread")


# ------------------------------------------------------------------ lifecycle + consent


def test_proposal_lifecycle_and_expiry(tmp_path):
    key = Ed25519PrivateKey.generate()
    envelope = signing.sign(key, statement_type="blackbox.rejection", environment=NETWORK, graph=COMMUNITY,
                            payload={"identifier": THREAT, "day": "2026-10-02", "reason": "benign"}, root_epoch=1, sequence=1)
    store = ProposalStore(tmp_path / "proposals")
    proposal = Proposal.new("blackbox.rejection", THREAT, envelope, COMMUNITY, checks={}, now=1000.0)
    with pytest.raises(ProposalError):
        proposal.transition(ProposalState.PUBLISHED)                            # DRAFT cannot jump to PUBLISHED
    store.save(proposal.transition(ProposalState.PROPOSED, now=1000.0))
    assert [p.id for p in store.open(now=1000.0 + 6 * DAY)] == [proposal.id]
    assert store.open(now=1000.0 + 8 * DAY) == []                              # 7-day expiry
    assert store.get(proposal.id).state is ProposalState.EXPIRED


def test_consent_is_bound_to_the_content_single_use_and_sandbox_gated(tmp_path):
    clock = {"t": 1000.0}
    ledger = consent.ConsentLedger(tmp_path / "consent.jsonl", clock=lambda: clock["t"])
    content = '{"a":1}'
    assert ledger.consent(content, typed=None, sandbox=False, yes=True)[0] is False      # no --yes outside the sandbox
    assert ledger.consent('{"other":2}', typed=None, sandbox=True, yes=True)[0] is True  # sandbox: --yes consents
    code = ledger.show(content, "promotion …")
    assert ledger.consent(content + " ", typed=code, sandbox=False, yes=False)[0] is False  # any byte change
    assert ledger.consent(content, typed=code, sandbox=False, yes=False)[0] is True
    assert ledger.consent(content, typed=code, sandbox=False, yes=False)[0] is False     # single-use
    code2 = ledger.show(content, "again")
    clock["t"] += 601
    assert ledger.consent(content, typed=code2, sandbox=False, yes=False)[0] is False    # 10-minute expiry


def test_no_browser_endpoint_can_publish():
    """`/api/curate/*` may prepare, never consent or publish (LES-006): today there is none at all."""
    pytest.importorskip("fastapi")
    from plugins.blackbox.dashboard import server
    app = server.create_app()
    assert not [r.path for r in app.routes if getattr(r, "path", "").startswith("/api/curate")]


# ------------------------------------------------------------------ queue + views


def test_already_verified_threats_never_reach_a_lane_and_lanes_order_the_rest():
    community_rules = {
        "dep:npm:known@1": {"identifier": "dep:npm:known@1", "stage": "corroborated", "enforcement": "flag", "reporterCount": 9, "counted": "3"},
        "dep:npm:evidenced@1": {"identifier": "dep:npm:evidenced@1", "stage": "reported", "enforcement": "flag",
                                "reporterCount": 2, "reason": "advisory:MAL-9", "counted": "1"},
        "dep:npm:bare@1": {"identifier": "dep:npm:bare@1", "stage": "reported", "enforcement": "monitor", "reporterCount": 1, "counted": "0"},
        "ioc:domain:x.example": {"identifier": "ioc:domain:x.example", "stage": "corroborated", "enforcement": "monitor",
                                 "reporterCount": 5, "disputed": "yes", "counted": "0"},
        "ioc:ip:1.2.3.4": {"identifier": "ioc:ip:1.2.3.4", "stage": "reported", "enforcement": "flag", "reporterCount": 1, "counted": "1"},
    }
    view = queue.delta_view(community_rules, {"dep:npm:known@1"})
    assert view.already_verified == ("dep:npm:known@1",)
    # §05 admission (KI-194): counted weight or a dispute reaches a lane; an unlisted-only, undisputed report does not.
    assert [(i.identifier, i.lane.value) for i in view.new] == [
        ("ioc:domain:x.example", 1), ("dep:npm:evidenced@1", 2), ("ioc:ip:1.2.3.4", 5)]
    assert view.unlisted_only == ("dep:npm:bare@1",)


def test_a_flood_of_unlisted_singletons_reaches_no_lane_and_no_webhook(tmp_path):
    """KI-194: 5,000 fresh single-author reports are stored and labelled, never queued or announced."""
    from plugins.blackbox.curate import intake
    rules = {f"dep:npm:flood-{i}@1": {"identifier": f"dep:npm:flood-{i}@1", "stage": "reported", "enforcement": "monitor",
                                      "reporterCount": 1, "counted": "0"} for i in range(5000)}
    rules["dep:npm:real@1"] = {"identifier": "dep:npm:real@1", "stage": "reported", "enforcement": "flag", "reporterCount": 2,
                               "counted": "1"}
    view = queue.delta_view(rules, set())
    assert [i.identifier for i in view.new] == ["dep:npm:real@1"] and len(view.unlisted_only) == 5000
    announced = []
    class _Sink:
        def notify(self, event):
            announced.append(event)
    assert intake.IntakeWatcher(tmp_path / "seen.json").poll(view, _Sink()) == ["dep:npm:real@1"] and len(announced) == 1


def _payload(report=REPORT, **change):
    """What the curators sign to promote *report* the curator-asset way, with *change* applied."""
    payload = strategies.STRATEGIES[strategies.CURATOR_ASSET].payload(report.verified, severity="critical",
                                                                       advisory="MAL-1", display_name="")
    return {**payload, **change}


def test_the_second_signer_refuses_a_crafted_promotion_payload(monkeypatch, tmp_path, curators):
    """KI-195: a modified client on machine A can sign any payload; machine B checks it and re-reads the report
    on its OWN node before cosigning."""
    node = StoreNode()
    _holding(monkeypatch, REPORT)
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    earlier_shape = {**{k: v for k, v in _payload().items() if k not in ("report", "reportDigest", "reporterKey")},
                     "provenance": "0123456789abcdef"}                       # random ids, no report: proposed again
    crafted = [(_payload(kind="vulnerability"), "promoted as malware only"),
               (_payload(packageName="left-pad"), "do not match its identifier"),
               (earlier_shape, "not a well-formed promotion"),
               (_payload(reportDigest="ab" * 32), "does not hold the report")]
    proposals = [Proposal.new(Kind.PROMOTION.value, THREAT, _ctx(node, curators["manifest"]).sign(PromotionDraft(payload, sequence=1), curators["a"]),
                              VM_GRAPH, checks={}).transition(ProposalState.PROPOSED) for payload, _why in crafted]
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store = ProposalStore()
    for proposal, (_payload_, why) in zip(proposals, crafted):
        store.save(proposal)
        with pytest.raises(verbs.VerbError, match=why):
            verbs.approve(_ctx(node, curators["manifest"]), store, proposal.id, evidence="advisory:MAL-1", typed_code=None, yes=True)
        assert store.get(proposal.id).state is ProposalState.PROPOSED
    assert node.vm_published == []
    whole = shared_report("dep:npm:evil-pkg@*", Reporter("edge-1"), graph=VM_GRAPH, network=NETWORK)
    envelope = _ctx(node, curators["manifest"]).sign(PromotionDraft(_payload(whole), sequence=2), curators["b"])
    proposal = Proposal.new(Kind.PROMOTION.value, "dep:npm:evil-pkg@*", envelope, VM_GRAPH, checks={})
    assert "WHOLE PACKAGE" in publishing.summary(proposal) and f"PROMOTES THE REPORT {whole.subject}" in publishing.summary(proposal)


@pytest.mark.parametrize("operators,break_glass,signed_by,publishes", [
    (("acme", "acme", "globex"), False, (0, 1), False),        # one organisation's two keys are one vote
    (("acme", "acme", "globex"), False, (0, 2), True),
    (("acme", "globex", "vault"), True, (0, 2), False),        # break-glass never counts on a raise (R7b)
])
def test_the_promotion_publish_gate_counts_one_key_per_operator(monkeypatch, tmp_path, operators, break_glass,
                                                                signed_by, publishes):
    """K2: publish's PROMOTION gate used to count raw keys, so it would write a promotion every reader refuses."""
    node = FakeNode()
    curator_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    hexes = [signing.public_key_hex(k) for k in curator_keys]
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              **km.roster(dict(zip(hexes, operators))), promotion_author="0x" + "1" * 40,
                              legacy_assets_hash=km.legacy_assets_hash([]),
                              break_glass_key=hexes[2] if break_glass else "")
    _machine(monkeypatch, tmp_path, "A", curator_keys[signed_by[1]])
    payload = _payload()
    publish_module = __import__("importlib").import_module("plugins.blackbox.curate.publishing.publish")
    monkeypatch.setattr(publish_module, "_write", lambda ctx, proposal, envelope:   # the gate is under test, not the write
                        ("promotion-x", VM_GRAPH, publish_module.PublishOutcome.PUBLISHED))
    envelope = _ctx(node, manifest).cosign(_ctx(node, manifest).sign(PromotionDraft(payload, sequence=1), curator_keys[signed_by[0]]),
                                         curator_keys[signed_by[1]])
    proposal = (Proposal.new(Kind.PROMOTION.value, THREAT, envelope, VM_GRAPH, checks={})
                .transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED))
    store = ProposalStore()
    store.save(proposal)
    if publishes:
        _, outcome = publishing.publish(_ctx(node, manifest), store, proposal.id, typed_code=None, yes=True)
        assert outcome.startswith("published")
    else:
        with pytest.raises(verbs.VerbError, match="enough curator signatures"):
            publishing.publish(_ctx(node, manifest), store, proposal.id, typed_code=None, yes=True)
        assert node.vm_published == []


def test_saved_views_are_catalog_entries_in_the_nodes_vocabulary():
    quads = node_ui_views.catalog_quads(node_ui_views.COMMUNITY_VIEWS, COMMUNITY)
    types = [q for q in quads if q["predicate"] == node_ui_views.RDF_TYPE]
    assert sum(1 for q in types if q["object"].endswith("SavedQuery")) == len(node_ui_views.COMMUNITY_VIEWS)
    for view in (*node_ui_views.COMMUNITY_VIEWS, *node_ui_views.VERIFIED_VIEWS):
        assert "SELECT" in view.sparql and "PREFIX g:" in view.sparql and "{{" not in view.sparql


def test_the_dossier_names_sources_and_never_a_verdict():
    built = (dossier.DossierBuilder(THREAT, clock=lambda: 1_700_000_000.0)
             .community({"stage": "reported", "enforcement": "flag", "stageReason": "r", "reporterCount": 2})
             .advisories(lambda eco, name, version: {"advisory_id": "MAL-1", "kind": "malware", "severity": "critical"})
             .curator(None, 0).heat(None).history([]).build())
    text = "\n".join(dossier.render(built))
    assert "MAL-1" in text and "verdict: none" in text and "promote" not in text.lower()


def test_publish_to_verified_memory_seals_then_publishes():
    node = FakeNode()
    quads = [{"subject": "urn:x", "predicate": constants.IDENTIFIER_PRED, "object": '"dep:npm:x@1"'}]
    node_routes.publish_to_verified_memory(node, VM_GRAPH, "threat-x", quads)
    assert node.sealed[0][1] == "threat-x" and node.vm_published[0][1] == "/api/knowledge-assets/threat-x/vm/publish"
    assert node.order == ["seal", "share", "publish"]   # KI-351: shared in full before the paid publish


def test_a_stage_attestation_needs_two_keys_and_lands_in_the_community_graph(monkeypatch, tmp_path, curators):
    """R3-attest: `curate propose --attest corroborated <id>` → second key approves → shared to the community graph."""
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    proposal = verbs.propose_statement(_ctx(node, curators["manifest"]), ProposalStore(), kind=Kind.ATTESTATION,
                                       identifier=THREAT, fields={"stage": "corroborated"})
    assert proposal.kind == Kind.ATTESTATION.value and node.shared == []           # one key: nothing published
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store_b = ProposalStore()
    store_b.save(proposal)
    _published, outcome = verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="", typed_code=None, yes=True)
    assert outcome.startswith("published to " + COMMUNITY)
    (graph, name, quads), = node.shared
    assert graph == COMMUNITY and name.startswith("curator-stage-attestation-")
    envelope = signing.from_text(json.loads(next(q["object"] for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED)))
    assert envelope.payload["stage"] == "corroborated"
    assert len(curators["manifest"].curator_signers(envelope, statement_type=Kind.ATTESTATION.value, graph=COMMUNITY)) == 2
