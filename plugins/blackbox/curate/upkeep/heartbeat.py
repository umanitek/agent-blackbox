"""The curator heartbeat — "this key is alive" (Community Curation C5).

Readers tell a silent curator from an absent one by heartbeats: a key that has
not beaten for 48 hours raises an alarm, and when NO key of an authority has
beaten for 7 days its root alone may sign reductions. Before this module
nothing ever published a heartbeat, so the first could never be told from the
second (KI-247).

A heartbeat is one statement signed by ONE curator key, naming that key; it
lives in the community graph and is not kept alive (a fresh one is published
every day).

Usage::

    proposal, outcome = heartbeat.publish_heartbeat(ctx, ProposalStore(), yes=True)
"""

from __future__ import annotations

from typing import Optional, Tuple

from ...kernel import signing
from ...kernel.signing import CuratorStatement
from .. import keys, publishing, verbs
from ..context import CurateContext
from ..proposals import Proposal, ProposalState, ProposalStore

#: The identifier every curator notice carries.
CURATOR = "curator"


def publish_heartbeat(ctx: CurateContext, store: ProposalStore, *, typed_code: Optional[str] = None,
                      yes: bool = False, standing: str = "") -> tuple[Proposal, publishing.PublishResult]:
    """Sign and publish this machine's heartbeat for the acting authority.
    Refused when this machine's key is not one of that authority's curator keys."""
    key = keys.curator_key_store().load_or_create()
    key_hex = signing.public_key_hex(key)
    if ctx.manifest is None or key_hex not in ctx.manifest.curator_keys:
        raise verbs.VerbError(f"this machine's key is not a curator key of the {ctx.authority.value} authority's manifest")
    proposal = verbs.propose_statement(ctx, store, kind=CuratorStatement.HEARTBEAT, identifier=CURATOR,
                                       fields={"key": key_hex})
    store.save(proposal.transition(ProposalState.APPROVED))   # a heartbeat needs one key: its own
    return publishing.publish(ctx, store, proposal.id, typed_code=typed_code, yes=yes, standing=standing)
