"""Curator statement types and which statement about a threat is current (Refine R7a).

Curator statements are signed blobs that any node can re-share, so "latest"
can never come from when a row arrived or from the sender's ``publishedAt``
clock (KI-105/109). It comes from the per-threat SEQUENCE number inside the
signed envelope (:mod:`.envelope`):

* per (threat, statement type), the highest sequence wins;
* across types, a TERMINAL statement (revocation, rejection) dominates every
  statement with a lower sequence, so an old promotion replayed after a
  revocation loses (KI-143). A later, higher-sequence promotion (a deliberate
  re-promotion) still wins. At an equal sequence the terminal one wins:
  safety is asymmetric (LES-016).

Each type is also classified as raising or reducing enforcement, which is
what reader policy (R7b) needs: holds, freezes and caps apply only to
statements that RAISE enforcement; reducing ones always get through.

Pattern: Enum (:class:`CuratorStatement`) + Value Object
(:class:`OrderedStatement`) + pure resolution functions.

Usage::

    from ..kernel.signing import statement_order as order
    seen = [order.OrderedStatement("dep:npm:x@1", order.CuratorStatement.PROMOTION, 3),
            order.OrderedStatement("dep:npm:x@1", order.CuratorStatement.REVOCATION, 5)]
    order.current_by_threat(seen)["dep:npm:x@1"].kind   # CuratorStatement.REVOCATION
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Tuple


class CuratorStatement(Enum):
    """The curator statement types (the envelope's ``statement_type``).

    Where each lives (plan §06): enforcement-affecting ones (promotion,
    revocation, pause, counted-author list) in the verified graph under the
    pinned author; advisory ones (confirmation, in-review, deferral-lapsed,
    rejection of a community report, backlog, away) in community shared
    memory. Every one is signer-verified against the key manifest.
    """

    PROMOTION = "blackbox.promotion"             # a threat enters the verified tier (raises)
    PAUSE = "blackbox.pause"                     # community ingest paused — the two-key pause flag (raises; KI-118)
    CONFIRMATION = "blackbox.confirmation"       # curator confirms a community threat (raises)
    ATTESTATION = "blackbox.stage-attestation"   # the curator's stage for a threat; readers prefer it (R3-attest; raises)
    COUNTED_AUTHORS = "blackbox.counted-authors"  # the Phase 1 counted-author list (raises; removal = denylist)
    BACKLOG = "blackbox.backlog"                 # SLA suspended for some lanes (suppresses an alarm; raises)
    REVOCATION = "blackbox.revocation"           # a verified threat is withdrawn (reduces; terminal)
    REJECTION = "blackbox.rejection"             # a reported threat is refused (reduces; terminal)
    IN_REVIEW = "blackbox.in-review"             # the curator acknowledged a report (advisory)
    DEFERRAL = "blackbox.deferral"               # corroborated but no independent evidence yet (advisory; §09: single-key)
    DEFERRAL_LAPSED = "blackbox.deferral-lapsed"  # a DEFERRED threat lapsed after 30 d (advisory)
    AWAY = "blackbox.away"                       # one curator key is away {key, from, until} (advisory)
    HEARTBEAT = "blackbox.heartbeat"             # one curator key is alive {key} (advisory; R10b: silent >48 h alarms)

    @property
    def terminal(self) -> bool:
        """True for statements that end a threat's run (revocation, rejection)."""
        return self in _TERMINAL

    @property
    def raises_enforcement(self) -> bool:
        """True when the statement can make Blackbox block or flag MORE."""
        return self in _RAISING

    @property
    def needs_quorum(self) -> bool:
        """True when the statement needs the manifest's full threshold of
        curator keys (2-of-3). Plan §09: promotion, rejection, revocation, the
        denylist (counted-author list) and anything raising enforcement or
        suppressing an alarm. Only in-review, deferral, deferral-lapsed and
        away notices are single-key: they never raise enforcement (deferring
        is single-key by §09)."""
        return self not in _SINGLE_KEY


_TERMINAL = frozenset({CuratorStatement.REVOCATION, CuratorStatement.REJECTION})
#: The statement type a reporter signs its report as (a community node's own statement, so not a curator verdict).
REPORT_STATEMENT = "blackbox.report"
#: The statement type of a signed correction: it withdraws a threat from every tier (not a curator verdict either).
CORRECTION_STATEMENT = "blackbox.correction"
#: Every statement type that can only make Blackbox block or flag LESS.
_REDUCING = frozenset({kind.value for kind in _TERMINAL} | {CORRECTION_STATEMENT})


def reduces_enforcement(statement_type: str) -> bool:
    """True when a statement of this type can only REDUCE enforcement: the terminal curator
    verdicts (revocation, rejection) and a correction. The one list behind every rule that
    treats reductions differently from raises (LES-016) — add a new reducing type here."""
    return statement_type in _REDUCING
#: Statements that raise enforcement or suppress an alarm (KI-134).
_RAISING = frozenset({CuratorStatement.PROMOTION, CuratorStatement.PAUSE, CuratorStatement.CONFIRMATION,
                      CuratorStatement.ATTESTATION,
                      CuratorStatement.COUNTED_AUTHORS, CuratorStatement.BACKLOG})
#: The only statements one curator key may make alone.
_SINGLE_KEY = frozenset({CuratorStatement.IN_REVIEW, CuratorStatement.DEFERRAL, CuratorStatement.DEFERRAL_LAPSED,
                         CuratorStatement.AWAY, CuratorStatement.HEARTBEAT})

#: A curator's DEFERRAL holds a threat for this many whole UTC days after the day it was signed
#: and lapses on the next (plan §12). Readers, the curator authorities' combined verdict and the
#: curator service all ask :func:`deferral_in_force`, so they end a deferral on the same day.
DEFERRAL_LAPSE_DAYS = 30


def deferral_in_force(age_days: int) -> bool:
    """Whether a deferral signed *age_days* whole UTC days ago still holds. A day that could not
    be read counts as age 0 at the callers: it never ends a hold early."""
    return age_days <= DEFERRAL_LAPSE_DAYS



def restriction(kind: CuratorStatement) -> int:
    """How strongly a verdict holds enforcement DOWN — the order used whenever
    two current statements about one threat must be ranked without a sequence
    number to decide (a tie, or two authorities): terminal (3) > deferral (2)
    > a notice such as in-review or deferral-lapsed (1) > confirmation (0)."""
    if kind.terminal:
        return 3
    if kind is CuratorStatement.DEFERRAL:
        return 2
    return 0 if kind is CuratorStatement.CONFIRMATION else 1


@dataclass(frozen=True)
class OrderedStatement:
    """One verified curator statement about a threat: ``threat`` (identifier),
    ``kind`` (:class:`CuratorStatement`), ``sequence`` (the signed per-threat
    sequence number)."""

    threat: str
    kind: CuratorStatement
    sequence: int

    @property
    def rank(self) -> tuple[int, int]:
        """Sort key: higher sequence first; at a tie the statement that enforces
        LESS wins (terminal, then deferral, then a notice, then confirmation),
        so the outcome never depends on which row was read first."""
        return self.sequence, restriction(self.kind)


def current_by_type(statements: Iterable[OrderedStatement]) -> dict[tuple[str, CuratorStatement], OrderedStatement]:
    """The highest-sequence statement per (threat, type)."""
    current: dict[tuple[str, CuratorStatement], OrderedStatement] = {}
    for statement in statements:
        key = (statement.threat, statement.kind)
        if key not in current or statement.sequence > current[key].sequence:
            current[key] = statement
    return current


def current_by_threat(statements: Iterable[OrderedStatement]) -> dict[str, OrderedStatement]:
    """The one statement that decides each threat: the highest sequence, a
    terminal statement winning a tie. A replayed lower-sequence statement
    never overrides a terminal one."""
    current: dict[str, OrderedStatement] = {}
    for statement in current_by_type(statements).values():
        held = current.get(statement.threat)
        if held is None or statement.rank > held.rank:
            current[statement.threat] = statement
    return current
