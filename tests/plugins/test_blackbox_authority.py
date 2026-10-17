"""Community Curation C2 — two authorities that cannot speak for each other.

The VERIFIED authority (roots pinned per network, manifest in the verified
graph) may say everything. The COMMUNITY authority (roots pinned per community
graph, manifest and statements in the community graph) may list and delist
counted authors, confirm, reject, defer and attest community threats, pause
community intake and publish notices — and nothing that touches the verified
tier. Each authority is verified against its own manifest and ordered in its
own sequence; between them the most restrictive current word wins.

Every test here drives one attack or one rule from the proposal (KI-242,
KI-243, KI-245), on rows served by a fake node — keys are generated at runtime.

One graph (2026-10-16): the community lives in the verified graph's shared
memory, and the two authorities may never share a graph. There are no community
curators for now (the project lead's decision), so the community authority is
DORMANT: kept, not deleted, so that curators can be added later. What an active
community authority would do is not tested while it sleeps; these tests pin what
dormant means — a community root and a community quorum grant nothing, and the
verified authority's word reads the same whatever is signed beside it.
"""

from __future__ import annotations

from datetime import date

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_blackbox_curator_view import _curator_row, _entry, _manifest_row

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing import trust_anchors
from plugins.blackbox.kernel.signing.authority import Authority, allowed_kinds, home_graph
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

VM_GRAPH = GRAPH   # one graph (2026-10-16): Verified Memory and the community's shared memory
CFG = BlackboxConfig(report=True, context_graph_id=VM_GRAPH)
SHARED = "shared-working-memory"
THREAT = "ioc:domain:evil.example"
TODAY = date(2026, 10, 2).isoformat()   # the day the helper rows are signed
#: What a community confirmation must carry: the signed reference to the evidence its curators checked.
CITED = {"evidence": "advisory:MAL-2026-0001"}


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


class Side:
    """One authority's keys and manifest: a root, three curator keys, 2-of-3."""

    def __init__(self, graph: str) -> None:
        self.root = Ed25519PrivateKey.generate()
        self.curators = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.graph = graph
        self.manifest = km.KeyManifest(
            environment=NETWORK, graph=graph, chain="", root_epoch=1, version=1,
            curator_keys=tuple(sorted(signing.public_key_hex(k) for k in self.curators)),
            curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2,
            promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))

    @property
    def root_hex(self) -> str:
        return signing.public_key_hex(self.root)

    def manifest_row(self):
        return _manifest_row(self.manifest, self.root)

    def row(self, kind, identifier, fields, *, graph=None, sequence=1, signers=2):
        return _curator_row(kind, identifier, fields, self.curators[:signers], self.manifest,
                            graph=graph or self.graph, sequence=sequence)


class Graphs:
    """A node serving the graph's Verified Memory and its shared memory. Rows are
    never consumed; a memory listed in *failing* (``SHARED`` or ``"verified"``)
    answers every query with the caller's error sentinel."""

    def __init__(self, verified=(), community=(), failing=()):
        self.rows = {"verified": list(verified), SHARED: list(community)}
        self.failing = set(failing)

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        memory = SHARED if view == SHARED else "verified"
        if memory in self.failing:
            return on_error
        rows = self.rows[memory]
        if "g:KeyManifest" in sparql:
            return [r for r in rows if "key-manifest" in r["r"]]
        if "g:CuratorStatement" in sparql:
            return [r for r in rows if "curator:" in r["r"]]
        return []


@pytest.fixture
def verified():
    return Side(VM_GRAPH)


@pytest.fixture
def community():
    return Side(GRAPH)


@pytest.fixture
def both_trusted(monkeypatch, verified, community):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", community.root_hex)


@pytest.fixture
def community_trusted(monkeypatch, community):
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", community.root_hex)


# ------------------------------------------------------------------ the table

#: Every statement kind, decided explicitly: (verified authority's home, community authority's home).
EXPECTED_HOMES = {
    Kind.PROMOTION: ("verified", None),
    Kind.REVOCATION: ("verified", None),
    Kind.PAUSE: ("verified", "community"),
    Kind.COUNTED_AUTHORS: ("verified", "community"),
    Kind.CONFIRMATION: ("community", "community"),
    Kind.REJECTION: ("community", "community"),
    Kind.ATTESTATION: ("community", "community"),
    Kind.IN_REVIEW: ("community", "community"),
    Kind.DEFERRAL: ("community", "community"),
    Kind.DEFERRAL_LAPSED: ("community", "community"),
    Kind.BACKLOG: ("community", "community"),
    Kind.AWAY: ("community", "community"),
    Kind.HEARTBEAT: ("community", "community"),
}


def test_every_statement_kind_has_a_decided_home_for_both_authorities():
    assert set(EXPECTED_HOMES) == set(Kind), "a new statement kind needs a row in the authority table and here"
    for kind, (verified_home, community_home) in EXPECTED_HOMES.items():
        assert home_graph(Authority.VERIFIED, kind) == verified_home, kind
        assert home_graph(Authority.COMMUNITY, kind) == community_home, kind


def test_the_community_authority_has_no_place_in_the_verified_graph_and_no_verified_tier_powers():
    assert allowed_kinds(Authority.COMMUNITY, in_verified_graph=True) == frozenset()
    in_community = allowed_kinds(Authority.COMMUNITY, in_verified_graph=False)
    assert Kind.PROMOTION not in in_community and Kind.REVOCATION not in in_community


# ------------------------------------------------------------------ roots are separated


def test_a_community_root_cannot_sign_a_manifest_for_the_verified_graph(community_trusted, community):
    """KI-242: the community root is trusted for the community graph only."""
    forged = Side(VM_GRAPH)
    forged.root = community.root   # the community root signs a VERIFIED-graph manifest
    alice = Reporter("0xa")
    node = Graphs(verified=[forged.manifest_row(),
                            forged.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author)),
                            forged.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"})])
    view = read_curator_view(node, CFG)
    assert view.manifest is None and not view.counted and view.revoked == frozenset()


def test_a_verified_root_is_not_accepted_for_a_community_manifest(monkeypatch, verified):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    impostor = Side(GRAPH)
    impostor.root = verified.root   # the verified root signs a COMMUNITY-graph manifest
    alice = Reporter("0xa")
    node = Graphs(community=[impostor.manifest_row(),
                             impostor.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))])
    view = read_curator_view(node, CFG)
    assert not view.counted and view.community is None


def test_without_any_trusted_root_nothing_counts(verified, community):
    alice = Reporter("0xa")
    node = Graphs(verified=[verified.manifest_row()],
                  community=[community.manifest_row(),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))])
    assert read_curator_view(node, CFG) == cv.CuratorView()


def test_a_pinned_community_graph_ignores_the_environment(monkeypatch, community):
    pinned = "ab" * 32
    monkeypatch.setattr(trust_anchors, "COMMUNITY_ROOT_KEYS", {GRAPH: (pinned, "cd" * 32)})
    env = {"BLACKBOX_COMMUNITY_ROOT_KEYS": community.root_hex}
    assert trust_anchors.community_roots(GRAPH, env) == {pinned, "cd" * 32}
    assert trust_anchors.community_roots("0xother/dev-graph", env) == {community.root_hex}
    assert trust_anchors.community_root_pinned(GRAPH) and not trust_anchors.community_root_pinned("0xother/dev-graph")
    assert trust_anchors.community_roots("", env) == frozenset()


def _community_statement(side, kind):
    """One quorum-signed statement of *kind*, as the community authority would publish it."""
    alice = Reporter("0xa")
    identifier, fields = {Kind.COUNTED_AUTHORS: (f"author:{alice.author}", _entry(alice.author)),
                          Kind.CONFIRMATION: (THREAT, CITED),
                          Kind.REJECTION: (THREAT, {"reason": "benign"}),
                          Kind.ATTESTATION: (THREAT, {"stage": "corroborated"}),
                          Kind.DEFERRAL: (THREAT, {}),
                          Kind.IN_REVIEW: (THREAT, {}),
                          Kind.PAUSE: ("curator", {"until": "2026-10-05"})}[kind]
    return side.row(kind, identifier, fields)


@pytest.mark.parametrize("kind", [Kind.COUNTED_AUTHORS, Kind.CONFIRMATION, Kind.REJECTION, Kind.ATTESTATION,
                                  Kind.DEFERRAL, Kind.IN_REVIEW, Kind.PAUSE])
def test_the_two_authorities_never_share_a_graph(both_trusted, verified, community, kind):
    """One graph (2026-10-16): the community authority would share the verified
    authority's graph, so it is dormant. With its root trusted and its manifest
    published, a quorum-signed statement of any kind it may publish changes
    nothing the reader sees."""
    alone = read_curator_view(Graphs(verified=[verified.manifest_row()]), CFG)
    beside = read_curator_view(Graphs(verified=[verified.manifest_row()],
                                      community=[community.manifest_row(), _community_statement(community, kind)]), CFG)
    assert beside == alone and beside.manifest == verified.manifest and beside.community is None


def test_the_community_authority_cannot_revoke_whatever_its_keys_sign(community_trusted, community):
    """A revocation acts on the verified tier: refused from the community authority in either graph."""
    in_community = community.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"})
    in_verified = community.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, graph=VM_GRAPH)
    node = Graphs(verified=[in_verified], community=[community.manifest_row(), in_community])
    view = read_curator_view(node, CFG)
    assert view.revoked == frozenset() and view.verdict(THREAT) is None


# ------------------------------------------------------------------ between the two: only the verified word counts


def _both(verified, community, *, verified_rows=(), community_rows=()):
    return Graphs(verified=[verified.manifest_row(), *verified_rows],
                  community=[community.manifest_row(), *community_rows])


def test_a_community_confirmation_never_displaces_a_verified_revocation(both_trusted, verified, community):
    """KI-243: each authority counts in its own sequence — a higher community number wins nothing."""
    node = _both(verified, community,
                 verified_rows=[verified.row(Kind.REVOCATION, THREAT, {"reason": "false-positive"}, sequence=1)],
                 community_rows=[community.row(Kind.CONFIRMATION, THREAT, CITED, sequence=99)])
    view = read_curator_view(node, CFG)
    assert view.verdict(THREAT) is Kind.REVOCATION and THREAT in view.revoked


def test_beside_the_verified_authority_a_community_quorum_changes_no_word(both_trusted, verified, community):
    """What the most-restrictive-wins rule would combine never reaches the view while
    the community authority is dormant: every line read is the verified authority's own."""
    alice, bob = Reporter("0xa"), Reporter("0xb")
    held, other = "ioc:domain:held.example", "ioc:domain:other.example"
    node = _both(verified, community,
                 verified_rows=[verified.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author)),
                                verified.row(Kind.PAUSE, "curator", {"until": "2026-10-03"})],
                 community_rows=[verified.row(Kind.REJECTION, THREAT, {"reason": "benign"}),
                                 verified.row(Kind.ATTESTATION, held, {"stage": "held"}),
                                 community.row(Kind.CONFIRMATION, THREAT, CITED, sequence=7),
                                 community.row(Kind.REJECTION, other, {"reason": "benign"}),
                                 community.row(Kind.ATTESTATION, held, {"stage": "corroborated"}, sequence=9),
                                 community.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author, listed="no")),
                                 community.row(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _entry(bob.author)),
                                 community.row(Kind.PAUSE, "curator", {"until": "2026-10-06"})])
    view = read_curator_view(node, CFG, interest=[THREAT, held, other, f"author:{alice.author}", f"author:{bob.author}"])
    assert set(view.counted) == {alice.author} and not view.delisted       # no community listing or delisting
    assert view.rejected(THREAT) and view.verdict(other) is None             # no community confirmation or rejection
    assert view.attestation(held).field("stage") == "held"                  # no community attestation
    assert view.pause_until == "2026-10-03"                                 # no community pause
    assert view.manifest == verified.manifest and view.community is None


# ------------------------------------------------------------------ failure is not emptiness


def test_a_failed_shared_memory_page_freezes_the_view_instead_of_dropping_verdicts(monkeypatch, verified):
    """KI-244: the verified authority's advisory statements live in the shared memory; a
    page that fails there, with nothing stored yet, must not read as 'no statements'."""
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    view = read_curator_view(Graphs(verified=[verified.manifest_row()], failing={SHARED}), CFG)
    assert view.unavailable and view.manifest == verified.manifest


def test_a_node_with_no_community_root_reads_exactly_as_before(monkeypatch, verified, community):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    alice = Reporter("0xa")
    node = Graphs(verified=[verified.manifest_row(),
                            verified.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))],
                  community=[community.manifest_row(),
                             community.row(Kind.COUNTED_AUTHORS, f"author:{Reporter('0xb').author}", _entry(Reporter("0xb").author))])
    view = read_curator_view(node, CFG)
    assert set(view.counted) == {alice.author} and view.community is None


# ------------------------------------------------------------------ end to end: what makes the community tier fire


class Network(Graphs):
    """Graphs plus the community graph's reports, on a node that says it is subscribed and synced."""

    def __init__(self, reports=(), **kw):
        super().__init__(**kw)
        self.reports = list(reports)

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if view == SHARED and "g:ThreatReport" in sparql and SHARED not in self.failing:
            return list(self.reports)
        return super().query(sparql, cg_id, view=view, on_error=on_error, **kw)


def _tier(node):
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, node, CFG, None)
    return rs


def test_a_report_fires_on_the_verified_authoritys_listing_never_on_a_community_one(monkeypatch, both_trusted,
                                                                                    verified, community):
    """A report stops being 'reported, monitor only' and can fire on another node once
    the verified authority lists its reporter. A community quorum's listing, with its
    root trusted, leaves it monitor-only while the community authority is dormant."""
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    alice = Reporter("0xa")
    threat = "ioc:ip:203.0.113.7"
    reports = [signed_row(threat, alice)]
    listing = f"author:{alice.author}"

    rs = _tier(Network(reports=reports, verified=[verified.manifest_row()],
                       community=[community.manifest_row(), community.row(Kind.COUNTED_AUTHORS, listing, _entry(alice.author))]))
    assert rs.community[threat]["enforcement"] == "monitor" and threat not in rs.ioc

    rs = _tier(Network(reports=reports, verified=[verified.manifest_row(),
                                                  verified.row(Kind.COUNTED_AUTHORS, listing, _entry(alice.author))]))
    assert (rs.community[threat]["stage"], rs.community[threat]["enforcement"], rs.community[threat]["counted"]) == ("reported", "flag", "1")
    assert threat in rs.ioc and rs.ioc[threat]["source"] == "community"


def test_a_verified_rejection_in_shared_memory_ends_a_listed_reporters_threat(monkeypatch, verified):
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", verified.root_hex)
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    alice = Reporter("0xa")
    threat = "ioc:ip:203.0.113.7"
    node = Network(reports=[signed_row(threat, alice)],
                   verified=[verified.manifest_row(),
                             verified.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))],
                   community=[verified.row(Kind.REJECTION, threat, {"reason": "benign"})])
    rs = _tier(node)
    assert threat not in rs.ioc and threat not in rs.community    # rejected reports stop counting (terminal)
