"""Publishing a statement to Verified Memory a second time pays once.

A publish to Verified Memory is paid. When the first attempt's read-back did not
see the statement yet (UNCONFIRMED), the next `curate publish` — by hand or by
the curator service's next beat — went straight to the paid publish again
without looking first. And a publish that timed out was reported as "nothing was
published" although it may have been paid (LES-011). Everything runs on a fake node.
"""

from __future__ import annotations

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_blackbox_curate import NETWORK, VM_GRAPH, FakeNode, _ctx, _machine
from plugins.blackbox.curate import verbs
from plugins.blackbox.curate.proposals.proposal import ProposalStore
from plugins.blackbox.kernel.dkg_client import DkgError
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind


@pytest.fixture
def curators():
    """Three curator keys under a 2-of-3 manifest for the verified graph."""
    from plugins.blackbox.kernel import signing
    from plugins.blackbox.kernel.signing import key_manifest as km

    a, b, c = (Ed25519PrivateKey.generate() for _ in range(3))
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1,
                              curator_keys=tuple(sorted(signing.public_key_hex(k) for k in (a, b, c))),
                              curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    return {"a": a, "b": b, "c": c, "manifest": manifest}


class LaggingNode(FakeNode):
    """Verified Memory reads back nothing until `caught_up`; `/vm/publish` may time out."""

    def __init__(self):
        super().__init__()
        self.caught_up = False
        self.publish_fails: DkgError | None = None

    def query(self, sparql, cg_id=None, view=None, on_error=None, **kw):
        return super().query(sparql, cg_id, view, on_error, **kw) if self.caught_up else on_error

    def request(self, method, path, body=None, timeout=None):
        if path.endswith("/vm/publish") and self.publish_fails is not None:
            self.vm_published.append((body["contextGraphId"], path, self.sealed[-1][2]))   # it may have been paid
            raise self.publish_fails
        return super().request(method, path, body, timeout)


def _approved_revocation(monkeypatch, tmp_path, curators, node):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    revocation = verbs.propose_statement(_ctx(node, curators["manifest"]), ProposalStore(), kind=Kind.REVOCATION,
                                         identifier="dep:npm:old@1", fields={"reason": "false-positive"})
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store = ProposalStore()
    store.save(revocation)
    return store, revocation


def test_a_retry_after_an_unconfirmed_publish_looks_first_and_pays_once(monkeypatch, tmp_path, curators):
    node = LaggingNode()
    store, revocation = _approved_revocation(monkeypatch, tmp_path, curators, node)
    _p, first = verbs.approve(_ctx(node, curators["manifest"]), store, revocation.id, evidence="", typed_code=None, yes=True)
    assert first.startswith("not published") and len(node.vm_published) == 1
    node.caught_up = True                                          # the first publish lands on the node
    from plugins.blackbox.curate import publishing
    _p, second = publishing.publish(_ctx(node, curators["manifest"]), store, revocation.id, typed_code=None, yes=True)
    assert second.startswith("published") and "already held it" in second
    assert len(node.vm_published) == 1                             # paid once


def test_a_publish_that_timed_out_says_it_may_have_been_paid(monkeypatch, tmp_path, curators):
    node = LaggingNode()
    node.publish_fails = DkgError("POST /vm/publish -> 504: gateway timeout", status_code=504)
    store, revocation = _approved_revocation(monkeypatch, tmp_path, curators, node)
    with pytest.raises(verbs.VerbError) as raised:
        verbs.approve(_ctx(node, curators["manifest"]), store, revocation.id, evidence="", typed_code=None, yes=True)
    assert "nothing was published" not in str(raised.value) and "could not tell" in str(raised.value)


def test_a_definite_refusal_still_says_nothing_was_published(monkeypatch, tmp_path, curators):
    node = LaggingNode()
    node.publish_fails = DkgError("POST /vm/publish -> 400: bad request", status_code=400)
    store, revocation = _approved_revocation(monkeypatch, tmp_path, curators, node)
    with pytest.raises(verbs.VerbError, match="nothing was published"):
        verbs.approve(_ctx(node, curators["manifest"]), store, revocation.id, evidence="", typed_code=None, yes=True)


# --- a promotion first-signed by the break-glass key is refused at once, not stuck at publish ---

def test_a_promotion_signed_only_by_the_break_glass_key_is_refused_before_anyone_cosigns_it():
    """The break-glass key only ever reduces enforcement (R7b), so it never counts toward a
    promotion. Approve and inbox admission checked "a curator key signed this" by hand, without
    that rule: such a promotion was co-signed, saved APPROVED, then stuck at publish."""
    from test_blackbox_curate import THREAT, _payload
    from plugins.blackbox.curate.context import PromotionDraft
    from plugins.blackbox.curate.proposals.proposal import Proposal
    from plugins.blackbox.curate.service import inbox
    from plugins.blackbox.kernel import signing
    from plugins.blackbox.kernel.signing import key_manifest as km

    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    hexes = [signing.public_key_hex(k) for k in keys]
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              **km.roster(dict(zip(hexes, ("acme", "globex", "vault")))), promotion_author="0x" + "1" * 40,
                              legacy_assets_hash=km.legacy_assets_hash([]), break_glass_key=hexes[2])
    ctx = _ctx(FakeNode(), manifest)
    envelope = ctx.sign(PromotionDraft(_payload(), sequence=1), keys[2])          # the break-glass key alone
    proposal = Proposal.new(Kind.PROMOTION.value, THREAT, envelope, VM_GRAPH, checks={})
    with pytest.raises(verbs.VerbError, match="not signed by a curator key"):
        verbs._check_first_signer(ctx, envelope, proposal, hexes[0])
    assert inbox.from_a_curator(manifest, proposal) is False
    honest = Proposal.new(Kind.PROMOTION.value, THREAT, ctx.sign(PromotionDraft(_payload(), sequence=1), keys[1]), VM_GRAPH,
                          checks={})
    verbs._check_first_signer(ctx, honest.parsed(), honest, hexes[0])               # an ordinary curator's: fine
    assert inbox.from_a_curator(manifest, honest) is True
