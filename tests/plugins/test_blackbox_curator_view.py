"""Refine R2 — readers honour verified curator statements.

Trust starts at a ROOT this network trusts (pinned in constants; sandbox
networks only may take one from the environment). From a root-signed key
manifest, curator statements count only from the right memory of the one graph
(enforcement in its Verified Memory, advisory in its shared memory — one graph
since 2026-10-16) and only with enough curator keys. Rejected or revoked threats stop counting; revoked verified
rules are withdrawn from the ruleset; counted authors are keyed by reporter
KEY; an unlisted author's dispute weighs nothing.
"""

from __future__ import annotations

import json
from datetime import date

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.community import read_curator_view, read_verified_reports
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.disputes import VerifiedDispute
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import trust_anchors
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import compiler, curator_tier

VM_GRAPH = GRAPH   # one graph (2026-10-16): the community lives in the verified graph's shared memory
CFG = BlackboxConfig(report=True, context_graph_id=VM_GRAPH)
THREAT = "ioc:domain:evil.example"
DAY = date(2026, 10, 2)


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


@pytest.fixture(scope="module")
def keys():
    return {"root": Ed25519PrivateKey.generate(), "curators": [Ed25519PrivateKey.generate() for _ in range(3)]}


@pytest.fixture(scope="module")
def manifest(keys):
    return km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1,
                          curator_keys=tuple(sorted(signing.public_key_hex(k) for k in keys["curators"])),
                          curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2, promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))


@pytest.fixture
def trust(monkeypatch, keys):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", signing.public_key_hex(keys["root"]))


def _rows(quads):
    row = {"r": quads[0]["subject"]}
    for quad in quads:
        name = quad["predicate"].rsplit("/", 1)[-1]
        if quad["object"].startswith('"'):
            row[name] = json.loads(quad["object"])
    return row


def _manifest_row(manifest, root):
    return _rows(cs.manifest_quads(km.sign_manifest(manifest, root)))


def _curator_row(kind, identifier, fields, signers, manifest, *, graph, sequence=1):
    envelope = cs.sign_statement(kind, identifier, sequence=sequence, fields=fields, key=signers[0],
                                 manifest=manifest, graph=graph, day=DAY)
    for key in signers[1:]:
        envelope = signing.cosign(envelope, key)
    return _rows(cs.statement_quads(envelope))


class _Node:
    """Serves the graph's Verified Memory (manifests + curator statements) and its shared memory."""

    def __init__(self, verified=(), community_statements=(), reports=(), disputes=()):
        self.verified = list(verified)
        self.community = {"curator": list(community_statements), "report": list(reports), "dispute": list(disputes)}

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if view != constants.VIEW_SHARED_WORKING_MEMORY:
            if "g:KeyManifest" in sparql:
                return [r for r in self.verified if "manifest" in r["r"]]
            return [r for r in self.verified if "curator:" in r["r"]] if "g:CuratorStatement" in sparql else []
        kind = ("curator" if "g:CuratorStatement" in sparql else "dispute" if "g:FalsePositive" in sparql
                else "none" if "g:Retraction" in sparql else "report")
        served, self.community[kind] = self.community.get(kind, []), []
        return served


# ------------------------------------------------------------------ trust


def test_a_pinned_network_cannot_be_overridden_from_the_environment(monkeypatch):
    pinned, sandbox = "a" * 64, "b" * 64
    monkeypatch.setattr(constants, "CURATOR_ROOT_KEYS", {NETWORK: {1: (pinned,)}})
    env = {"BLACKBOX_CURATOR_ROOT_KEYS": sandbox}
    assert trust_anchors.trusted_roots(NETWORK, env) == {pinned}
    assert trust_anchors.trusted_roots("sandbox-network", env) == {sandbox}
    assert trust_anchors.trusted_roots("sandbox-network", {"BLACKBOX_CURATOR_ROOT_KEYS": "not-a-key, ,"}) == frozenset()


def test_without_a_trusted_root_no_curator_statement_counts(keys, manifest):
    node = _Node([_manifest_row(manifest, keys["root"]),
                  _curator_row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, keys["curators"][:2],
                               manifest, graph=VM_GRAPH)])
    assert read_curator_view(node, CFG).revoked == frozenset()   # no BLACKBOX_CURATOR_ROOT_KEYS set


def test_a_manifest_signed_by_anyone_but_the_root_is_not_trusted(trust, keys, manifest):
    impostor = Ed25519PrivateKey.generate()
    node = _Node([_manifest_row(manifest, impostor),
                  _curator_row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, keys["curators"][:2],
                               manifest, graph=VM_GRAPH)])
    assert read_curator_view(node, CFG).manifest is None


# ------------------------------------------------------------------ placement + verdicts


def test_statements_count_only_from_their_own_graph(trust, keys, manifest):
    two = keys["curators"][:2]
    node = _Node([_manifest_row(manifest, keys["root"]),
                  _curator_row(Kind.REJECTION, "ioc:domain:a.example", {"reason": "benign"}, two, manifest,
                               graph=VM_GRAPH)],                                  # advisory, but in Verified Memory
                 community_statements=[
                     _curator_row(Kind.REVOCATION, "ioc:domain:b.example", {"reason": "false-positive"}, two,
                                  manifest, graph=GRAPH)])                        # enforcement, but in shared memory
    view = read_curator_view(node, CFG)
    assert view.manifest is not None and view.verdicts == {}


def test_a_revocation_beats_an_earlier_confirmation_and_a_replay(trust, keys, manifest):
    two = keys["curators"][:2]
    node = _Node([_manifest_row(manifest, keys["root"]),
                  _curator_row(Kind.REVOCATION, THREAT, {"reason": "dispute-upheld"}, two, manifest,
                               graph=VM_GRAPH, sequence=5)],
                 community_statements=[_curator_row(Kind.CONFIRMATION, THREAT, {}, two, manifest, graph=GRAPH,
                                                    sequence=3)])
    view = read_curator_view(node, CFG)
    assert view.revoked == {THREAT} and view.verdict(THREAT) is Kind.REVOCATION


# ------------------------------------------------------------------ honoured before counting


def test_reports_of_a_rejected_threat_stop_counting(trust, keys, manifest):
    two = keys["curators"][:2]
    reporters = [Reporter(f"0xr{i}") for i in range(2)]
    node = _Node([_manifest_row(manifest, keys["root"])],
                 community_statements=[_curator_row(Kind.REJECTION, THREAT, {"reason": "duplicate"}, two, manifest,
                                                    graph=GRAPH)],
                 reports=[signed_row(THREAT, r) for r in reporters] + [signed_row("ioc:domain:other.example",
                                                                                 reporters[0])])
    read = read_verified_reports(node, CFG)
    assert {r.identifier for r in read.reports} == {"ioc:domain:other.example"}
    assert read.curator.rejected(THREAT)


def test_a_curator_revocation_withdraws_the_verified_rule(trust, keys, manifest):
    rs = compiler.Ruleset()
    rs.ioc = {THREAT: {"identifier": THREAT, "source": "public"},
              "ioc:domain:keep.example": {"identifier": "ioc:domain:keep.example", "source": "public"}}
    rs.dependency = {"npm:x@1": {"identifier": "dep:npm:x@1", "source": "public"}}
    node = _Node([_manifest_row(manifest, keys["root"]),
                  _curator_row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, keys["curators"][:2],
                               manifest, graph=VM_GRAPH)])
    assert curator_tier.apply_curator_tier(rs, node, BlackboxConfig(context_graph_id=VM_GRAPH)) == 1
    assert set(rs.ioc) == {"ioc:domain:keep.example"} and rs.dependency


def test_one_curator_key_cannot_revoke(trust, keys, manifest):
    rs = compiler.Ruleset()
    rs.ioc = {THREAT: {"identifier": THREAT, "source": "public"}}
    node = _Node([_manifest_row(manifest, keys["root"]),
                  _curator_row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, keys["curators"][:1],
                               manifest, graph=VM_GRAPH)])
    assert curator_tier.apply_curator_tier(rs, node, BlackboxConfig(context_graph_id=VM_GRAPH)) == 0


# ------------------------------------------------------------------ counted authors + dispute weight


def _entry(key_hex, *, listed="yes", expires="2027-01-01", address="0x" + "a" * 40):
    return {"listed": listed, "class": "established", "org": "", "expires": expires, "address": address}


def test_counted_authors_are_keyed_by_reporter_key_and_can_be_delisted(trust, keys, manifest):
    two = keys["curators"][:2]
    alice, bob, carol = (Reporter(f"0x{c}" * 1) for c in "abc")
    rows = [_manifest_row(manifest, keys["root"]),
            _curator_row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author), two, manifest,
                         graph=VM_GRAPH, sequence=1),
            _curator_row(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _entry(bob.author), two, manifest,
                         graph=VM_GRAPH, sequence=1),
            _curator_row(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _entry(bob.author, listed="no"), two,
                         manifest, graph=VM_GRAPH, sequence=2),
            _curator_row(Kind.COUNTED_AUTHORS, f"author:{carol.author}", _entry(carol.author, expires="2020-01-01"),
                         two, manifest, graph=VM_GRAPH, sequence=1)]
    view = read_curator_view(_Node(rows), CFG)
    assert set(view.counted) == {alice.author}                 # bob delisted (the denylist), carol expired
    impostor = Reporter("0x" + "a" * 40)                       # claims alice's address, different key
    assert not view.is_counted(impostor.author)


def test_an_unlisted_authors_dispute_weighs_nothing():
    counted, unlisted = "c" * 64, "u" * 64
    view = cv.CuratorView(counted={counted: cv.CountedAuthor(counted, "0x1cb7a2e9afbed1e81860f3dd4e4e3b795be5b95a", "established", "", "2027-01-01")})
    disputes = [VerifiedDispute("s1", THREAT, counted, "0x1cb7a2e9afbed1e81860f3dd4e4e3b795be5b95a", "wrong", "2026-10-02"),
                VerifiedDispute("s2", THREAT, unlisted, "0x6b865327cda5d374298777f79af02ba0b90512d5", "wrong", "2026-10-02"),
                VerifiedDispute("s3", "ioc:domain:b.example", unlisted, "0x6b865327cda5d374298777f79af02ba0b90512d5", "wrong", "2026-10-02")]
    assert cv.counted_dispute_weight(disputes, view) == {THREAT: 1}


# ------------------------------------------------------------------ R3-attest


def test_the_newest_attestation_wins_and_a_replayed_older_one_loses(trust, keys, manifest):
    two = keys["curators"][:2]
    node = _Node([_manifest_row(manifest, keys["root"])],
                 community_statements=[_curator_row(Kind.ATTESTATION, THREAT, {"stage": "corroborated"}, two, manifest, graph=GRAPH, sequence=4),
                                       _curator_row(Kind.ATTESTATION, THREAT, {"stage": "held"}, two, manifest, graph=GRAPH, sequence=2)])
    view = read_curator_view(node, CFG)
    assert view.attestation(THREAT).field("stage") == "corroborated" and view.attestation(THREAT).sequence == 4
    assert view.verdict(THREAT) is None                                           # an attestation is not a verdict


def test_one_curator_key_cannot_attest_and_the_payload_is_closed(trust, keys, manifest):
    one = keys["curators"][:1]
    node = _Node([_manifest_row(manifest, keys["root"])],
                 community_statements=[_curator_row(Kind.ATTESTATION, THREAT, {"stage": "corroborated"}, one, manifest, graph=GRAPH)])
    assert read_curator_view(node, CFG).attestation(THREAT) is None
    with pytest.raises(ValueError):
        cs.sign_statement(Kind.ATTESTATION, THREAT, sequence=1, fields={"stage": "rejected"}, key=one[0], manifest=manifest, graph=GRAPH)
    with pytest.raises(ValueError):
        cs.sign_statement(Kind.ATTESTATION, THREAT, sequence=1, fields={"stage": "held", "note": "x"}, key=one[0], manifest=manifest, graph=GRAPH)


# ------------------------------------------------------------------ KI-228: a failed curator page freezes, never erases


class _PageFailsNode(_Node):
    """The verified graph answers with the caller's failure sentinel for *failing* queries."""

    def __init__(self, *args, failing="g:KeyManifest", **kw):
        super().__init__(*args, **kw)
        self.failing = failing

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if view != constants.VIEW_SHARED_WORKING_MEMORY and self.failing in sparql:
            return on_error
        return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)


def test_a_failed_manifest_page_makes_the_curator_view_unavailable_not_empty(trust, keys, manifest):
    node = _PageFailsNode([_manifest_row(manifest, keys["root"])], failing="g:KeyManifest")
    view = read_curator_view(node, CFG)
    assert view.unavailable is True and view.manifest is None


def test_a_failed_curator_statement_page_makes_the_view_unavailable(trust, keys, manifest):
    node = _PageFailsNode([_manifest_row(manifest, keys["root"])], failing="g:CuratorStatement")
    view = read_curator_view(node, CFG)
    assert view.unavailable is True and view.manifest is not None


def test_a_failed_curator_page_freezes_the_community_read(trust, keys, manifest):
    """Before KI-228 an empty view de-listed every counted author and recomputed every
    community threat to MONITOR; now the whole read is UNAVAILABLE and readers keep last-good."""
    from plugins.blackbox.community.reader import ReadState

    node = _PageFailsNode([_manifest_row(manifest, keys["root"])], failing="g:KeyManifest",
                          reports=[signed_row(THREAT, Reporter("0xr1"))])
    read = read_verified_reports(node, CFG)
    assert read.state is ReadState.UNAVAILABLE or not read.available
    assert "curator" in (read.reason or "")
