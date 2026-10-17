"""The batch-time pre-check: the last look at the verified graph before a PAID publish.

The curate queue already closes threats the verified graph lists (``queue.delta_view``),
but between a threat's confirmation and its batch an earlier batch or the feed may have
published it (§03.4, F-030). :func:`precheck` asks the live lookup once more, immediately
before the publish, and drops:

* an entry the verified graph now lists — :data:`ALREADY_VERIFIED`;
* a version-exact dependency (``dep:npm:pkg@1.2.3``) whose whole package
  (``dep:npm:pkg@*``) a verified rule already covers — :data:`COVERED_BY_WHOLE_PACKAGE`;
* a second entry for an identifier already in the batch (two spellings that canonicalise
  to the same text) — :data:`DUPLICATE_IN_BATCH`.

Every drop is logged. Identifiers are compared in their compiler-equivalent canonical form
(:func:`canonical_identifier`); package-name aliases are the lookup's job
(``VerifiedScope.spellings``). :func:`precheck` is pure: the lookup is injected and no HTTP
happens in it. Usage, with a compiled ruleset ``rs``::

    result = precheck(entries, strict_verified_subset(rs))
    publish(result.kept)

A lookup that cannot tell must RAISE (LES-011): an exception propagates, so nothing is
published on a guess, and an empty set is read as a definite "none listed".
:func:`strict_verified_subset` is that lookup over a compiled ruleset (it raises
:class:`PrecheckUnavailable` where ``Ruleset.verified_subset`` would answer "none listed").
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import AbstractSet, Any, Callable, Iterable, Optional, Protocol, Sequence, Tuple

from ...kernel import threat_ids

logger = logging.getLogger(__name__)

#: The injected lookup — ``Ruleset.verified_subset``'s shape: which of these identifiers
#: the verified graph lists.
VerifiedSubset = Callable[[Iterable[str]], AbstractSet[str]]


class Entry(Protocol):
    """What the pre-check reads of a batch entry: the identifier it would publish."""

    @property
    def identifier(self) -> str: ...


class PrecheckUnavailable(RuntimeError):
    """The verified store could not tell whether an entry is listed: nothing is published."""


ALREADY_VERIFIED = "already-verified"
COVERED_BY_WHOLE_PACKAGE = "covered-by-whole-package"
DUPLICATE_IN_BATCH = "duplicate-in-batch"

#: The version of a whole-package rule (``dep:eco:pkg@*``).
WHOLE_PACKAGE_VERSION = "*"


@dataclass(frozen=True)
class DroppedEntry:
    """An entry the pre-check kept out of the batch: ``reason`` is one of the module's
    reason constants; ``covered_by`` is the canonical identifier that made it redundant."""

    entry: Entry
    reason: str
    covered_by: str


@dataclass(frozen=True)
class PrecheckResult:
    """``kept`` — the entries to publish, in their original order; ``dropped`` — the rest."""

    kept: tuple[Entry, ...]
    dropped: tuple[DroppedEntry, ...]


def canonical_identifier(identifier: str) -> str:
    """The identifier as the compiler keys it: dependency names canonicalised per
    ecosystem (``threat_ids.dependency_identifier``), IOC values normalised
    (``threat_ids.ioc_identifier``); every other category is already canonical text."""
    text = str(identifier).strip()
    parsed = threat_ids.parse_dependency_identifier(text)
    if parsed is not None:
        return threat_ids.dependency_identifier(*parsed)
    if text.startswith("ioc:") and text.count(":") >= 2:
        _, ioc_type, value = text.split(":", 2)
        return threat_ids.ioc_identifier(ioc_type, value)
    return text


def whole_package_identifier(identifier: str) -> str:
    """``dep:eco:pkg@*`` for a version-exact canonical dependency identifier, else ``""``."""
    parsed = threat_ids.parse_dependency_identifier(identifier)
    if parsed is None or parsed[2] == WHOLE_PACKAGE_VERSION:
        return ""
    ecosystem, name, _version = parsed
    return threat_ids.dependency_identifier(ecosystem, name, WHOLE_PACKAGE_VERSION)


def precheck(entries: Sequence[Entry], verified_subset: VerifiedSubset) -> PrecheckResult:
    """Split *entries* into kept and dropped against one *verified_subset* call (see the
    module doc). Exceptions from the lookup propagate: no answer, no publish."""
    canonical = [canonical_identifier(entry.identifier) for entry in entries]
    wanted = set(canonical) | {whole for ident in canonical if (whole := whole_package_identifier(ident))}
    listed = {canonical_identifier(ident) for ident in verified_subset(sorted(wanted))} if wanted else set()
    kept, dropped, seen = [], [], set()
    for entry, identifier in zip(entries, canonical):
        drop = _drop_reason(entry, identifier, listed, seen)
        seen.add(identifier)
        if drop is None:
            kept.append(entry)
        else:
            logger.info("[precheck] dropped %s before publish: %s (%s)", entry.identifier, drop.reason, drop.covered_by)
            dropped.append(drop)
    return PrecheckResult(kept=tuple(kept), dropped=tuple(dropped))


def _drop_reason(entry: Entry, identifier: str, listed: AbstractSet[str],
                 seen: AbstractSet[str]) -> Optional[DroppedEntry]:
    if identifier in listed:
        return DroppedEntry(entry, ALREADY_VERIFIED, identifier)
    whole = whole_package_identifier(identifier)
    if whole and whole in listed:
        return DroppedEntry(entry, COVERED_BY_WHOLE_PACKAGE, whole)
    if identifier in seen:
        return DroppedEntry(entry, DUPLICATE_IN_BATCH, identifier)
    return None


def strict_verified_subset(compiled: Any) -> VerifiedSubset:
    """``Ruleset.verified_subset`` that RAISES :class:`PrecheckUnavailable` instead of
    reading a store that could not tell as "none listed" (precheck's contract)."""

    def lookup(identifiers: Iterable[str]) -> set[str]:
        wanted = {str(identifier) for identifier in identifiers}
        if compiled is None:
            raise PrecheckUnavailable("no compiled ruleset to check against")
        found = {str(rule.get("identifier") or "") for _category, rule in compiled.iter_rules()
                 if rule.get("source") == "public" and rule.get("identifier") in wanted}
        dependencies = [parsed for ident in wanted if (parsed := threat_ids.parse_dependency_identifier(ident))]
        iocs = [ident for ident in wanted if ident.startswith("ioc:")]
        if not dependencies and not iocs:
            return found
        live = compiled.live_lookup() if callable(getattr(compiled, "live_lookup", None)) else None
        if live is None:
            raise PrecheckUnavailable("the live verified lookup is not ready")
        for answer in ([live.dependencies(dependencies)] if dependencies else []) + ([live.iocs(iocs)] if iocs else []):
            if not answer.known:
                raise PrecheckUnavailable(f"the verified store could not tell ({answer.reason or 'no reason'})")
            found |= {rule["identifier"] for rule in answer.rules.values() if rule.get("identifier") in wanted}
        return found

    return lookup
