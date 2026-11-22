"""Live verified lookups — the graph is the rule store (DKG-lookup build).

WHY (KI-322): compiling every verified dependency / IOC rule into
``ruleset.json`` made that file 352 MB on a fully synced node; one load cost
1.4 GB and 3.7 s, every process paid it, and 8 GB machines ran out of memory.
The rules already live in the DKG node's local store, which answers an exact
lookup in about 2 ms. So the hot path asks the store at check time, and only a
small scope travels in ``ruleset.json``.

* :class:`VerifiedScope` — what a lookup may believe: the owner-pinned confirmed
  assertion graphs, suppressed subjects, curator-revoked identifiers, the
  mixed-case package spellings, and the store endpoint. Rebuilt every refresh.
* :func:`refresh_scope` / :func:`scope_for_generation` — build the next scope
  from the node (fail-open: a part that could not be read keeps its previous
  value); the refresh cycle calls the latter on every path.
* :class:`VerifiedLookup` — exact dependency / IOC lookups against the store,
  answered as :class:`LookupAnswer` with three outcomes (``HIT``, ``CLEAN``,
  ``COULD_NOT_TELL``). Rows come back as triples and go through the SAME
  row builder and row adapters that compiled today's rules, so a verdict is
  byte-identical to the compiled one (bench 2026-10-10: 60/60 sampled rules).
* :class:`LiveAnswering` — the mixin that gives :class:`~..compiler.Ruleset` its
  check-time answers (``dependency_rules``, ``ioc_rules``, ``verified_subset``, ``live_browse``).
* :func:`public_page` / :class:`LivePage` — one bounded page of the live tiers for
  the dashboard (filtered window + whole-result totals), through the same builders.
* :class:`FallbackIndex` / :func:`maintain_fallback_index` — the OPT-IN on-disk index
  (``verified_lookup_fallback: index``), a last resort that answers only after the store
  could not; off by default.
* :func:`signed_suppressions` / :class:`CorrectionPin` — which verified-graph corrections a reader honours:
  legacy ones as before, newer ones only with a quorum-signed ``blackbox.correction``
  envelope and only on the targets inside its signed payload (trust-and-threat-lab R3).
* :data:`HEALTH` — the record of what lookups could and could not answer
  (``verified_lookup_state.json``): a degraded store is an operator alarm.

Usage::

    lookup = VerifiedLookup(rs.verified_scope, StoreClient(rs.verified_scope.store_url))
    answer = lookup.dependencies([("npm", "wallet-security-checker", "2.0.3")])
    answer.rules            # {"npm:wallet-security-checker@2.0.3": rule}
    answer.outcome          # HIT | CLEAN | COULD_NOT_TELL
"""

from .answering import LiveAnswering
from .browse import LivePage, public_page
from .corrections import NO_PIN, CorrectionPin, signed_suppressions
from .fallback_index import FALLBACK_INDEX, FALLBACK_OFF, FallbackIndex
from .fallback_index import maintain as maintain_fallback_index
from .health import HEALTH, LookupHealth, LookupState
from .lookup import CLEAN, COULD_NOT_TELL, HIT, LookupAnswer, VerifiedLookup
from .network_lists import NetworkIndicators, graph_reachable, network_indicators
from .scope import VerifiedScope, refresh_scope, scope_for_generation

__all__ = ["CLEAN", "COULD_NOT_TELL", "FALLBACK_INDEX", "FALLBACK_OFF", "HEALTH", "HIT", "NO_PIN", "CorrectionPin", "FallbackIndex", "LiveAnswering", "LivePage", "LookupAnswer", "LookupHealth", "LookupState", "NetworkIndicators", "VerifiedLookup", "VerifiedScope", "graph_reachable", "maintain_fallback_index", "network_indicators", "public_page", "refresh_scope", "scope_for_generation", "signed_suppressions"]
