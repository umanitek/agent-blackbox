"""What a ruleset generation ANSWERS at check time — the live side of :class:`Ruleset`.

Pattern: Mixin. :class:`~..compiler.Ruleset` is a dataclass of compiled rules plus
the verified scope; these methods read ``verified_scope`` and the compiled
``dependency`` / ``ioc`` dicts and ask the node's local store for the rest.
They live here, not in compiler.py, because that file sits at its size alarm and
because asking is a different concern from compiling.

* :meth:`LiveAnswering.dependency_rules` / :meth:`LiveAnswering.ioc_rules` — what
  detection calls: live public rules first, compiled (community) rules fill the gaps.
* :meth:`LiveAnswering.verified_subset` — "which of these identifiers are verified?"
  for the curate queue, the confirmed pool and the shadow metrics.
* :meth:`LiveAnswering.live_browse` — one page of the live tiers for the dashboard.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from ...kernel import threat_ids
from ...kernel.store import StoreClient
from . import browse, fallback_index
from .lookup import CLEAN, HIT, LookupAnswer, VerifiedLookup
from .scope import VerifiedScope


class LiveAnswering:
    """Mixed into :class:`~..compiler.Ruleset`; expects ``verified_scope``,
    ``dependency``, ``ioc`` and ``iter_rules()`` on ``self``."""

    verified_scope: Optional[VerifiedScope]
    dependency: dict[str, dict[str, Any]]
    ioc: dict[str, dict[str, Any]]

    def iter_rules(self):  # pragma: no cover - provided by Ruleset
        raise NotImplementedError

    def live_lookup(self) -> Optional[VerifiedLookup]:
        """The live verified lookup for this generation, or None when no usable
        scope has been built yet (the compiled dicts then stand alone)."""
        scope = self.verified_scope
        if scope is None or not scope.ready:
            return None
        return VerifiedLookup(scope, StoreClient(scope.store_url), fallback=fallback_index.OnDemandIndex.for_scope(scope))

    def dependency_rules(self, candidates: Sequence[tuple[str, str, str]]) -> LookupAnswer:
        """Rules for these ``(ecosystem, name, version)`` candidates, keyed as
        ``dependency_key`` keys. PUBLIC rules come from the live lookup when this
        generation has one; the compiled ``dependency`` dict fills the keys it did
        not answer (community-materialised rules, or a fully compiled tier). Public
        therefore beats community by construction. A lookup that could not tell
        keeps that outcome even when the dict filled a hit."""
        lookup = self.live_lookup()
        answer = lookup.dependencies(candidates) if lookup else LookupAnswer({}, CLEAN)
        keys = [threat_ids.dependency_key(ecosystem, name, version) for ecosystem, name, version in candidates]
        return _fill_from_dict(answer, keys, self.dependency)

    def ioc_rules(self, identifiers: Sequence[str]) -> LookupAnswer:
        """Rules among these ``ioc:type:value`` identifiers (see :meth:`dependency_rules`
        for the live-then-compiled precedence and the outcome)."""
        lookup = self.live_lookup()
        answer = lookup.iocs(identifiers) if lookup else LookupAnswer({}, CLEAN)
        return _fill_from_dict(answer, identifiers, self.ioc)

    def verified_subset(self, identifiers: Iterable[str]) -> set:
        """Which of *identifiers* the verified (public) tier lists: compiled public
        rules, plus live lookups for the ``dep:`` / ``ioc:`` ones. The curate queue,
        the confirmed pool and the shadow metrics ask this instead of materialising
        every public identifier (there are half a million)."""
        wanted = {str(identifier) for identifier in identifiers}
        found = {rule.get("identifier") for _cat, rule in self.iter_rules()
                 if rule.get("source") == "public" and rule.get("identifier") in wanted}
        lookup = self.live_lookup()
        if lookup is None:
            return found
        dependencies = [parsed for identifier in wanted
                        if (parsed := threat_ids.parse_dependency_identifier(identifier)) is not None]
        if dependencies:
            found |= {rule["identifier"] for rule in lookup.dependencies(dependencies).rules.values()
                      if rule.get("identifier") in wanted}
        iocs = [identifier for identifier in wanted if identifier.startswith("ioc:")]
        if iocs:
            found |= {rule["identifier"] for rule in lookup.iocs(iocs).rules.values()
                      if rule.get("identifier") in wanted}
        return found

    def live_browse(self, **filters: Any) -> Optional[browse.LivePage]:
        """One page of the live public tiers for the dashboard (``category``,
        ``ecosystem``, ``needle``, ``offset``, ``limit`` — see :func:`browse.public_page`);
        None when this generation has no ready scope."""
        scope = self.verified_scope
        if scope is None or not scope.ready:
            return None
        return browse.public_page(scope, StoreClient(scope.store_url), **filters)



def _fill_from_dict(answer: LookupAnswer, keys: Sequence[str],
                    compiled: dict[str, dict[str, Any]]) -> LookupAnswer:
    """The live answer plus every *key* the compiled dict holds that the lookup
    did not; HIT when anything matched unless the lookup could not tell."""
    rules = dict(answer.rules)
    for key in keys:
        if key not in rules and key in compiled:
            rules[key] = compiled[key]
    outcome = answer.outcome
    if outcome == CLEAN and rules:
        outcome = HIT
    return LookupAnswer(rules, outcome, answer.reason)
