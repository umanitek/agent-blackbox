"""PhishTank as a source (§03.3, F-004, F-005).

Checks one ``ioc:url:`` identifier against PhishTank's check-URL API:

* in the database, verified, and still valid → FOUND (``reference_id`` = the phish id);
* not in the database, or verified as NOT a phish → CLEAN;
* in the database but not yet verified, no app key, an error or an over-limit
  (HTTP 509) answer → UNAVAILABLE: a vote still in progress is not an answer.

Terms (§03.3 table): API use is allowed commercially and non-commercially, but
redistribution terms are unconfirmed — so a published row may CITE the phish
id and never copies PhishTank's fields; only the id leaves this module.
PhishTank enforces an hourly limit per app key; the bucket is sized below it.

The app key lives in ``credentials.json`` under :data:`APP_KEY_NAME`, on the
Umanitek node only (never on the lab).

Usage::

    verdict = PhishTankSource().check("ioc:url:https://login.example.test/x")
"""

from __future__ import annotations

from typing import Callable, Optional

from ...kernel import threat_ids
from ..service.evidence import Lookup
from .client import HttpClient, UrllibClient
from .credentials import key_for
from .protocol import REUSE_CLEARED, SourceTerms, SourceVerdict

NAME = "phishtank"
APP_KEY_NAME = "phishtank"
ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
TERMS = SourceTerms(citable=True, reuse_state=REUSE_CLEARED, limit_requests=250, limit_seconds=60 * 60)


_default_key = key_for(APP_KEY_NAME)   # the credentials file, read when asked


class PhishTankSource:
    """The PhishTank Strategy; *client* and *key* are injectable for tests."""

    name = NAME
    terms = TERMS

    def __init__(self, client: Optional[HttpClient] = None, *, key: Callable[[], Optional[str]] = _default_key) -> None:
        self._client = client or UrllibClient()
        self._key = key

    def applies(self, identifier: str) -> bool:
        return (threat_ids.parse_ioc_identifier(identifier) or ("", ""))[0] == "url"

    def check(self, identifier: str) -> SourceVerdict:
        if not self.applies(identifier):
            return SourceVerdict(Lookup.NOT_APPLICABLE, source=NAME)
        _ioc_type, url = threat_ids.parse_ioc_identifier(identifier)
        app_key = self._key()
        if not app_key:
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
        answer = self._client.post(ENDPOINT, headers={}, form={
            "url": url, "format": "json", "app_key": app_key})
        results = answer.get("results") if answer is not None else None
        if not isinstance(results, dict) or not isinstance(results.get("in_database"), bool):
            return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
        if not results["in_database"]:
            return SourceVerdict(Lookup.CLEAN, source=NAME)
        if results.get("verified") is True and results.get("valid") is True and results.get("phish_id"):
            return SourceVerdict(Lookup.FOUND, source=NAME, reference_id=str(results["phish_id"]))
        if results.get("verified") is True and results.get("valid") is False:
            return SourceVerdict(Lookup.CLEAN, source=NAME)
        return SourceVerdict(Lookup.UNAVAILABLE, source=NAME)
