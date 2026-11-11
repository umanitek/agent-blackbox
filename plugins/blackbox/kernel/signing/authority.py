"""The two trust authorities — who may say what, and in which graph.

An authority is a root key, the curator keys its manifest names, the graph it
speaks in and the CLOSED list of statement kinds it may sign there:

* ``VERIFIED`` — the verified graph's owner. Its manifest and its
  enforcement statements (promotion, revocation, pause, the counted-author
  list) live in the verified graph; its advisory statements live in the
  community graph. It may say everything.
* ``COMMUNITY`` — the community's own curators. Everything it says lives in
  the community graph. It may list and delist counted authors, confirm,
  reject, defer and attest community threats, pause community intake and
  publish notices. It may NEVER promote into the verified graph, revoke a
  verified rule or sign a kill list: the strongest thing it can cause is FLAG.

Statements a ROOT signs (:class:`RootStatement`: the key manifest, a graph
migration) are not curator statements and have their own small table: each
authority's manifest lives in its own graph, and only the verified authority
may name a successor for its verified graph.

Readers enforce this table for every statement they parse; curators use it to
route what they publish. Adding a statement kind without deciding its row
fails the table test in ``tests/plugins/test_blackbox_authority.py``.

Pattern: Constant table behind two pure functions (a Strategy table keyed by
authority and graph).

Usage::

    from ..kernel.signing.authority import Authority, allowed_kinds, home_graph
    allowed_kinds(Authority.COMMUNITY, in_verified_graph=False)   # frozenset of CuratorStatement
    home_graph(Authority.COMMUNITY, CuratorStatement.COUNTED_AUTHORS)   # "community"
    home_graph(Authority.COMMUNITY, CuratorStatement.REVOCATION)        # None — may not sign it
    home_graph(Authority.VERIFIED, RootStatement.GRAPH_MIGRATION)       # "verified"
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping, Optional

from .graph_migration import GRAPH_MIGRATION_STATEMENT
from .key_manifest import KEY_MANIFEST_STATEMENT
from .statement_order import CuratorStatement

#: Where a statement lives (the value :func:`home_graph` returns).
VERIFIED_GRAPH = "verified"
COMMUNITY_GRAPH = "community"


class Authority(Enum):
    """Who is speaking: the verified graph's owner, or the community's curators."""

    VERIFIED = "verified"
    COMMUNITY = "community"


class RootStatement(Enum):
    """The statements a ROOT key signs (never curator keys; the envelope's
    ``statement_type``). Kept apart from :class:`CuratorStatement` because
    readers turn :func:`allowed_kinds` into curator-statement filters."""

    KEY_MANIFEST = KEY_MANIFEST_STATEMENT          # which curator keys may sign (kernel.signing.key_manifest)
    GRAPH_MIGRATION = GRAPH_MIGRATION_STATEMENT    # the verified graph's successor (kernel.signing.graph_migration)


#: What the verified authority publishes in the VERIFIED graph (plan §06 of
#: Community Graph Refine): everything that affects enforcement of its tier.
_VERIFIED_IN_VERIFIED = frozenset({CuratorStatement.PROMOTION, CuratorStatement.REVOCATION,
                                   CuratorStatement.PAUSE, CuratorStatement.COUNTED_AUTHORS})
#: What the verified authority publishes in the COMMUNITY graph: its advisory statements.
_VERIFIED_IN_COMMUNITY = frozenset(CuratorStatement) - _VERIFIED_IN_VERIFIED
#: What the community authority may sign — all of it in the COMMUNITY graph.
#: PROMOTION and REVOCATION are absent on purpose: they act on the verified tier.
_COMMUNITY_IN_COMMUNITY = frozenset({
    CuratorStatement.COUNTED_AUTHORS, CuratorStatement.PAUSE, CuratorStatement.CONFIRMATION,
    CuratorStatement.REJECTION, CuratorStatement.ATTESTATION, CuratorStatement.IN_REVIEW,
    CuratorStatement.DEFERRAL, CuratorStatement.DEFERRAL_LAPSED, CuratorStatement.BACKLOG,
    CuratorStatement.AWAY, CuratorStatement.HEARTBEAT,
})

_ALLOWED = {
    (Authority.VERIFIED, True): _VERIFIED_IN_VERIFIED,
    (Authority.VERIFIED, False): _VERIFIED_IN_COMMUNITY,
    (Authority.COMMUNITY, True): frozenset(),
    (Authority.COMMUNITY, False): _COMMUNITY_IN_COMMUNITY,
}


#: Where each authority publishes each root statement; a missing pair may not be signed.
#: A successor graph acts on the verified tier, so the community authority never names one.
_ROOT_HOMES: Mapping[tuple[Authority, RootStatement], str] = {
    (Authority.VERIFIED, RootStatement.KEY_MANIFEST): VERIFIED_GRAPH,
    (Authority.VERIFIED, RootStatement.GRAPH_MIGRATION): VERIFIED_GRAPH,
    (Authority.COMMUNITY, RootStatement.KEY_MANIFEST): COMMUNITY_GRAPH,
}


def allowed_kinds(authority: Authority, *, in_verified_graph: bool) -> frozenset[CuratorStatement]:
    """The CURATOR statement kinds a reader accepts from *authority* in that
    graph (root statements: :func:`home_graph`)."""
    return _ALLOWED[(authority, in_verified_graph)]


def home_graph(authority: Authority, kind: CuratorStatement | RootStatement) -> Optional[str]:
    """Where *authority* publishes a *kind* statement (curator- or root-signed):
    ``"verified"``, ``"community"``, or None when it may not sign that kind at all."""
    if isinstance(kind, RootStatement):
        return _ROOT_HOMES.get((authority, kind))
    if kind in _ALLOWED[(authority, True)]:
        return VERIFIED_GRAPH
    if kind in _ALLOWED[(authority, False)]:
        return COMMUNITY_GRAPH
    return None
