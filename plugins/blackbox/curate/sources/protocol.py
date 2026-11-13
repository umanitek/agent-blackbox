"""The source Strategy and the registry that asks every source within a beat's budget (§03.3, F-029).

Pattern: Strategy — each outside threat source (OSV, abuse.ch, PhishTank…) is
one :class:`Source`; :class:`SourceRegistry` is the context that runs them,
each behind its own :class:`~.budget.TokenBucket` and the shared
:class:`~.cache.NotListedCache`.

The answer reuses :class:`curate.service.evidence.Lookup` — there is no second
verdict enum. "Could not tell" (UNAVAILABLE: rate-limited, network down, the
source raised) is NEVER read as clean (LES-028): only a CLEAN answer the
source actually gave, or one it gave in the last 24 h, is cached and reported
as clean.

Usage::

    registry = SourceRegistry(SOURCES)
    for result in registry.lookup(items, LookupBudget(), today=today):
        if any(v.status is Lookup.FOUND for v in result.verdicts): ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Sequence

from ..service.evidence import Lookup, OwnCheck
from .budget import LookupBudget, LookupItem, TokenBucket, select_for_lookup
from .cache import NotListedCache

#: D20 reuse states (§03.3 terms table): cleared to cite, look-up only until
#: the founder clears it, or not yet re-checked.
REUSE_CLEARED = "cleared"
REUSE_LOOKUP_ONLY = "look-up only"
REUSE_NEEDS_FOUNDER = "needs founder"
REUSE_STATES = frozenset({REUSE_CLEARED, REUSE_LOOKUP_ONLY, REUSE_NEEDS_FOUNDER})


@dataclass(frozen=True)
class SourceTerms:
    """What a source's publisher allows (§03.3 terms table, D20).

    ``citable`` — a published confirmation may cite this source's id; only a
    ``cleared`` source can be citable. ``reuse_state`` — one of
    :data:`REUSE_STATES`. ``limit_requests`` per ``limit_seconds`` — the
    publisher's published rate limit, which sizes the source's token bucket.
    """

    citable: bool
    reuse_state: str
    limit_requests: int
    limit_seconds: float

    def __post_init__(self) -> None:
        if self.reuse_state not in REUSE_STATES:
            raise ValueError(f"unknown reuse state {self.reuse_state!r}")
        if self.citable and self.reuse_state != REUSE_CLEARED:
            raise ValueError("only a cleared source may be cited")
        if self.limit_requests < 1 or self.limit_seconds <= 0:
            raise ValueError("a published limit needs at least one request per positive period")


@dataclass(frozen=True)
class SourceVerdict(OwnCheck):
    """One source's answer about one identifier: the :class:`OwnCheck` status
    (and ``advisory`` when FOUND), plus which ``source`` said it and the
    source's own ``reference_id`` for the listing (a URLhaus id, a PhishTank
    phish id; "" when not FOUND)."""

    source: str = ""
    reference_id: str = ""


class Source(Protocol):
    """One outside threat source (Strategy). ``check`` must return
    UNAVAILABLE — never CLEAN — whenever it could not get a real answer."""

    name: str
    terms: SourceTerms

    def applies(self, identifier: str) -> bool:
        """Whether this source can answer about *identifier* at all — from the identifier alone,
        no network. :meth:`check` answers NOT_APPLICABLE exactly where this is False."""
        ...

    def check(self, identifier: str) -> SourceVerdict: ...


@dataclass(frozen=True)
class LookupResult:
    """Every source's verdict on one looked-up item, in registry order."""

    item: LookupItem
    verdicts: tuple[SourceVerdict, ...]


class SourceRegistry:
    """Runs the :class:`Source` strategies for the items a beat may look up.

    One :class:`TokenBucket` per source, sized from its terms; one
    :class:`NotListedCache`. A drained bucket or a raising source gives
    UNAVAILABLE; a FOUND answer evicts any cached "not listed" and is never
    cached itself.
    """

    def __init__(self, sources: Sequence[Source], *, cache: Optional[NotListedCache] = None,
                 buckets: Optional[dict[str, TokenBucket]] = None) -> None:
        self._sources = tuple(sources)
        self._cache = cache if cache is not None else NotListedCache()
        self._buckets = buckets if buckets is not None else {
            source.name: TokenBucket(source.terms.limit_requests, source.terms.limit_seconds) for source in self._sources}

    def lookup(self, items: Sequence[LookupItem], budget: LookupBudget, *, today: str) -> tuple[LookupResult, ...]:
        """Ask every source about the items *budget* selects for *today*
        (at most ``budget.items_per_beat``, lane order, oldest first)."""
        with self._cache.session():   # one read and one merged write of the cache per beat
            return tuple(LookupResult(item, tuple(self._ask(source, item.identifier) for source in self._sources))
                         for item in select_for_lookup(items, budget, today))

    def _ask(self, source: Source, identifier: str) -> SourceVerdict:
        # Before the cache and the rate limit: an item a source cannot answer about spends none
        # of its requests (they used to drain it, and the items it CAN answer read "could not tell").
        applies = getattr(source, "applies", None)   # a source without it is asked about everything
        if applies is not None and not applies(identifier):
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=source.name)
        if self._cache.is_not_listed(source.name, identifier):
            return SourceVerdict(Lookup.CLEAN, source=source.name)
        if not self._buckets[source.name].take():
            return SourceVerdict(Lookup.UNAVAILABLE, source=source.name)
        try:
            verdict = source.check(identifier)
        except Exception:
            return SourceVerdict(Lookup.UNAVAILABLE, source=source.name)
        if verdict.status is Lookup.CLEAN:
            self._cache.remember_not_listed(source.name, identifier)
        elif verdict.status is Lookup.FOUND:
            self._cache.forget(source.name, identifier)
        return verdict
