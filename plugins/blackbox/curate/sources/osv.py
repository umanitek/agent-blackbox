"""OSV / GHSA malicious-package advisories as a source (§03.3).

Wraps :func:`detection.osv.advisory_status` through the curator's existing
:func:`service.evidence.own_check`, so a dependency is FOUND only when a
malicious-package (``MAL-``) advisory names that exact version; a
vulnerability advisory reads CLEAN, a failed query UNAVAILABLE, and anything
that is not an exact-version ``dep:`` identifier NOT_APPLICABLE.

``advisory_status`` never reads or writes the hot path's module-level cache
(``detection.osv._cache``), so this adapter leaves the agent loop's cache
untouched.

Terms (§03.3 table): OSV ``MAL-`` (ossf/malicious-packages) is Apache-2.0 and
GHSA (which OSV aggregates) is CC-BY 4.0 — both are cited by their advisory
id. OSV publishes no rate limit; the bucket is our own courtesy cap.

Usage::

    verdict = OsvSource().check("dep:npm:evil@1.0.0")
"""

from __future__ import annotations

from ...detection import osv
from ..service.evidence import AdvisoryStatus, Lookup, osv_applies, own_check
from .protocol import REUSE_CLEARED, SourceTerms, SourceVerdict

NAME = "osv"
TERMS = SourceTerms(citable=True, reuse_state=REUSE_CLEARED, limit_requests=600, limit_seconds=60)


class OsvSource:
    """The OSV Strategy; *status* is injectable so tests can stand in for the network."""

    name = NAME
    terms = TERMS

    def __init__(self, status: AdvisoryStatus = osv.advisory_status) -> None:
        self._status = status

    def applies(self, identifier: str) -> bool:
        return osv_applies(identifier)

    def check(self, identifier: str) -> SourceVerdict:
        answer = own_check(identifier, self._status)
        reference = answer.advisory if answer.status is Lookup.FOUND else ""
        return SourceVerdict(answer.status, advisory=reference, source=NAME, reference_id=reference)
