"""What this node establishes BY ITSELF before the service signs (Community Curation C9, plan §07).

The policy (:mod:`.policy`) decides on facts. These are the two facts that
need looking up, and each is this node's own — never what the other curator
or the reporter says:

* :func:`own_check` — this node's lookup of a dependency in the independent
  public advisory source: a malicious-package advisory for that exact
  version, nothing found, or "could not ask" (which is neither).
* :func:`community_stage` / :func:`deferral_age_days` — what this node's own
  compiled tier and curator view say about one threat (its stage; how many
  days its deferral has run).
* :func:`ledger_calls_for` — what this node's own private ledger calls for a
  reporter today: list (a graduation, or the renewal of a listing in good
  standing), delist (the reputation floor or strikes), or nothing.

Pattern: pure functions over injected lookups (the beat passes them in).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple

from ...community import CuratorView, reputation
from ...detection import osv
from ...kernel import threat_ids
from ...kernel.signing import CuratorStatement

#: A listing is proposed for renewal this many days before it expires (plan §13).
RENEW_AHEAD_DAYS = 30

AdvisoryStatus = Callable[[str, str, str], tuple[str, Optional[dict[str, str]]]]


class Lookup(Enum):
    FOUND = "found"                # a malicious-package advisory names this exact version
    CLEAN = "clean"                # the source answered: no malicious-package advisory
    UNAVAILABLE = "unavailable"    # could not ask — proves nothing either way
    NOT_APPLICABLE = "n/a"         # not an exact-version dependency: no machine-checkable source


@dataclass(frozen=True)
class OwnCheck:
    """This node's own answer about one threat: ``status`` and, when FOUND,
    the ``advisory`` id (``MAL-…``)."""

    status: Lookup
    advisory: str = ""

    @property
    def evidence(self) -> str:
        """The evidence reference a confirmation would cite ("" unless FOUND)."""
        return f"advisory:{self.advisory}" if self.status is Lookup.FOUND else ""


#: What the first-signature step reads for an item this beat did not look up: could not tell.
NOT_LOOKED_UP = OwnCheck(Lookup.UNAVAILABLE)


def osv_applies(identifier: str) -> bool:
    """Whether OSV can be asked about *identifier*: an exact-version ``dep:`` identifier."""
    parts = threat_ids.parse_dependency_identifier(identifier)
    return parts is not None and parts[2] != "*"


def own_check(identifier: str, status: AdvisoryStatus = osv.advisory_status) -> OwnCheck:
    """Look *identifier* up in the public advisory source. Only an
    exact-version dependency can be asked about; a vulnerability advisory is
    NOT evidence of malware and reads as clean."""
    if not osv_applies(identifier):
        return OwnCheck(Lookup.NOT_APPLICABLE)
    parts = threat_ids.parse_dependency_identifier(identifier)
    state, finding = status(*parts)
    if state == "unavailable":
        return OwnCheck(Lookup.UNAVAILABLE)
    if finding is not None and finding.get("kind") == "malware" and finding.get("advisory_id"):
        return OwnCheck(Lookup.FOUND, advisory=str(finding["advisory_id"]))
    return OwnCheck(Lookup.CLEAN)


def community_stage(compiled: Optional[Any], identifier: str) -> str:
    """The local stage this node's compiled community tier gives *identifier* ("" when not in it)."""
    rules = compiled.community if compiled is not None else {}
    return str((rules.get(identifier) or {}).get("stage", ""))


def deferral_age_days(own_view: CuratorView, identifier: str, today: str) -> int:
    """Whole days since the acting authority deferred *identifier*; -1 when its verdict is not a deferral."""
    record = own_view.verdicts.get(identifier)
    if record is None or record.kind is not CuratorStatement.DEFERRAL:
        return -1
    try:
        return (date.fromisoformat(today) - date.fromisoformat(record.day)).days
    except ValueError:
        return -1


def renewal_due(expires: str, today: str) -> bool:
    """True when a listing that expires on *expires* is inside the renewal window (and not yet past it)."""
    try:
        left = (date.fromisoformat(expires) - date.fromisoformat(today)).days
    except ValueError:
        return False
    return 0 <= left <= RENEW_AHEAD_DAYS


def ledger_calls_for(key: str, own_view: CuratorView, ledger: reputation.ReputationLedger, today: str) -> str:
    """What this node's own ledger calls for reporter *key* today: ``delist``
    (its reputation is under the floor, or strikes), ``list`` (it graduates,
    or its plain established listing is due for renewal and in good standing),
    or "" (nothing)."""
    standing = ledger.standing(key)
    if reputation.demotion(standing, ledger.reputation(key, today), today) is not None:
        return "delist"
    if reputation.graduates(standing, today):
        return "list"
    listed = own_view.counted.get(key)
    if listed is not None and listed.author_class == "established" and not listed.org and renewal_due(listed.expires, today):
        return "list"
    return ""


def renewed_expiry(today: str, days: int) -> str:
    return (date.fromisoformat(today) + timedelta(days=days)).isoformat()
