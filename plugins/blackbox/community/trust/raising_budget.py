"""The reader's daily cap on what the community curators can RAISE (Community Curation C3).

The community authority's curator keys sign routine statements on their own,
so they are online keys (KI-258). Two stolen keys must not be able to turn the
whole flag tier on in an afternoon. Every reader therefore admits at most

* ``CONFIRMATIONS_PER_DAY`` new confirmations and stage attestations, and
* ``LISTINGS_PER_DAY`` new counted-author listings

per day of ITS OWN clock, from the community authority. The rest are HELD:
not dropped, just not acted on yet. Held statements are admitted on the
following days, oldest first, so a burst is slowed to the daily rate and a
reader returning from a week offline catches up in a few days — and every
reader reaches the same state in the end.

Safety is asymmetric (LES-016): only statements that raise enforcement are
ever held. Rejections, delistings, deferrals, pauses and notices pass at once,
whatever their number.

The first read of a node is a baseline: everything it finds is admitted (a new
node must not start a hundred statements behind).

Pattern: pure function over verified rows and the stored admissions.

Usage::

    admission = admit(community_rows, stored.admitted, first_read=stored.baseline_until is None, today=today)
    acted_on = [row for row in community_rows if statement_key(row) not in admission.held]
    store.remember(graph, manifests, rows, admitted=admission.admitted)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

from ...kernel import signing
from ...kernel.signing import CuratorStatement
from .trust_store import statement_key

#: New raising statements one reader admits per day from the community authority.
CONFIRMATIONS_PER_DAY = 100
LISTINGS_PER_DAY = 20

_CONFIRMING = frozenset({CuratorStatement.CONFIRMATION.value, CuratorStatement.ATTESTATION.value})
_LIMITS = {"confirm": CONFIRMATIONS_PER_DAY, "list": LISTINGS_PER_DAY}


@dataclass(frozen=True)
class Admission:
    """What :func:`admit` decided. ``held`` — the keys of raising statements
    not acted on today. ``admitted`` — every admitted raising statement's key
    and the reader-day it was admitted (what the trust store keeps)."""

    held: frozenset[str] = frozenset()
    admitted: Mapping[str, str] = field(default_factory=dict)


def bucket(row: Mapping[str, str]) -> Optional[tuple[str, str, int]]:
    """``(bucket, signed day, sequence)`` when *row* RAISES enforcement — a
    confirmation or attestation (``confirm``) or a listing with ``listed: yes``
    (``list``) — else None: reductions and notices are never held."""
    envelope = signing.from_text(row.get("signedStatement", ""))
    if envelope is None:
        return None
    if envelope.statement_type in _CONFIRMING:
        name = "confirm"
    elif envelope.statement_type == CuratorStatement.COUNTED_AUTHORS.value and envelope.payload.get("listed") == "yes":
        name = "list"
    else:
        return None
    return name, str(envelope.payload.get("day", "")), envelope.sequence


def admit(rows: Iterable[Mapping[str, str]], already: Mapping[str, str], *, first_read: bool, today: str) -> Admission:
    """Decide which of the community authority's verified *rows* are acted on
    today. *already* — the stored admissions (statement key -> reader-day);
    *first_read* — this node has never stored trust for this graph (baseline);
    *today* — the reader's UTC day."""
    classified = [(statement_key(row), bucket(row)) for row in rows]
    bucket_of = {key: raising[0] for key, raising in classified if raising is not None}
    admitted: dict[str, str] = {}
    pending: dict[str, list[tuple[str, int, str]]] = {name: [] for name in _LIMITS}
    for key, raising in classified:
        if raising is None or key in admitted:
            continue
        name, day, sequence = raising
        if key in already:
            admitted[key] = already[key]
        elif first_read:
            admitted[key] = ""          # the baseline: admitted, and charged to no day
        else:
            pending[name].append((day, sequence, key))
    held = set()
    for name, waiting in pending.items():
        used = sum(1 for key, day in admitted.items() if day == today and bucket_of.get(key) == name)
        room = max(0, _LIMITS[name] - used)
        waiting = sorted(set(waiting))   # oldest signed day first, then sequence: every reader drains in the same order
        for _, _, key in waiting[:room]:
            admitted[key] = today
        held.update(key for _, _, key in waiting[room:])
    return Admission(held=frozenset(held), admitted=admitted)
