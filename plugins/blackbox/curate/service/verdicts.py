"""The verdict rules — how a curator decides confirmed, rejected or not proven (trust-and-threat-lab §03.3).

Deterministic functions over typed facts; no network, no free text, no model.
A curator reads only these structured facts (a hostile lab page cannot talk to
it), and both curators must reach the same verdict INDEPENDENTLY from their
own facts — the quorum check is unchanged and lives where it always did.

The rules, in the order they are applied (first match wins):

1. **never-flag** — an address identifier (domain, IP, URL) that EXACTLY equals
   a never-flag entry is rejected. Exact only: a near match is not an entry,
   and never-flag never applies to packages or skills.
2. **never-promote** — a bare IP inside a CDN or cloud range
   (:mod:`.never_promote`) is not proven and never promoted. When the ranges
   cannot be read the rule cannot tell, so the IP is not promoted either.
3. **confirmed by a source** — a citable source lists this exact identifier
   (e.g. an OSV ``MAL-`` advisory for a package version): confirmed, cited.
4. **confirmed by the lab** — lab Evidence meets the proof rule for the type
   (:data:`PROOF_RULES`). Lab-only, so it is FLAG tier for every type: a
   compromised lab can lie, and a block-tier type would need a second,
   independent lab host to agree (not built yet — Lab 2, F-024).
5. **rejected** — the lab ran clean AND every source answered "not listed".
6. otherwise **not proven** — it keeps flagging for 30 days, is re-tested on
   day 7 and day 21, then drops to monitor and closes "unproven"
   (:func:`not_proven_step`, F-008).

"Could not tell" is never "clean" (LES-028): a lab run with any note
(deadline, unreachable, inconclusive, a suspicious sign) or a check it did not
answer is not clean, and a source that could not be asked is not "not listed".

Pattern: Strategy table (one proof rule set per threat type) feeding one pure
decision function that returns a frozen Value Object.

Usage::

    decision = decide_verdict("dep:npm:evil@1.0.0", VerdictFacts(citable_listing="MAL-2026-1"))
    decision.verdict, decision.tier, decision.promotable, decision.reason
    not_proven_step(opened="2026-10-01", today="2026-10-08", retests_done=0)   # NotProvenStep.RETEST
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import AbstractSet, Optional

from ..lab import Check, Evidence
from . import never_promote

#: A not-proven threat keeps flagging this many days, then drops to monitor and closes "unproven".
NOT_PROVEN_FLAG_DAYS = 30
#: Days after opening on which a not-proven threat is re-tested.
RETEST_DAYS = (7, 21)
#: Address identifiers — the only kinds never-flag applies to.
ADDRESS_PREFIXES = ("ioc:domain:", "ioc:ip:", "ioc:url:")


class Verdict(Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NOT_PROVEN = "not proven"


class Tier(Enum):
    """The most a confirmation may do on a reader: BLOCK, or FLAG only."""

    BLOCK = "block"
    FLAG = "flag"


@dataclass(frozen=True)
class ProofRule:
    """Lab evidence proves a threat when ONE run saw every check in ``seen``."""

    seen: frozenset[Check]


def _rule(*checks: Check) -> ProofRule:
    return ProofRule(frozenset(checks))


_ADDRESS_PROOF = (
    _rule(Check.BAIT_CREDENTIAL_SENT),                              # the page sent the bait credential away
    _rule(Check.WALLET_PROMPT, Check.CLIPBOARD_WRITTEN),            # a wallet drainer / clipboard swap
)
#: The proof rules per threat type (identifier prefix). Each needs a sign no
#: honest target shows — a login page that redirects (SSO) or an install
#: script that downloads a prebuilt binary is NOT proof. A type with no entry
#: (injection, escalation, file access, wallet, hash…) cannot be proven or
#: cleared by the lab — only a citable source confirms it.
PROOF_RULES: dict[str, tuple[ProofRule, ...]] = {
    "dep:": (
        _rule(Check.BAIT_CREDENTIAL_SENT),
        _rule(Check.INSTALL_SCRIPT_RAN, Check.FILE_WRITTEN_OUTSIDE_PACKAGE),
    ),
    "skill:": (
        _rule(Check.BAIT_CREDENTIAL_SENT),
        _rule(Check.FILE_WRITTEN_OUTSIDE_PACKAGE),
        _rule(Check.CLIPBOARD_WRITTEN),
    ),
    **{prefix: _ADDRESS_PROOF for prefix in ADDRESS_PREFIXES},
}


@dataclass(frozen=True)
class VerdictFacts:
    """What THIS curator established itself about one threat.

    ``citable_listing`` — the reference id of a citable source that lists this
    exact identifier (``MAL-2026-1``, a URLhaus id…; "" = none found).
    ``sources_clean`` — every applicable source ANSWERED "not listed" (a source
    that could not be asked leaves this False). ``lab`` — the lab's validated
    Evidence for this threat, one per run (empty = never tested).
    """

    citable_listing: str = ""
    sources_clean: bool = False
    lab: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class VerdictDecision:
    """``verdict`` and its one-line ``reason``; ``promotable`` — it may enter
    the verified graph; ``tier`` — what a promoted row may do (None unless
    confirmed); ``citation`` — the source reference a confirmation cites."""

    verdict: Verdict
    reason: str
    promotable: bool = False
    tier: Optional[Tier] = None
    citation: str = ""


def _rules_for(identifier: str) -> tuple[ProofRule, ...]:
    return next((rules for prefix, rules in PROOF_RULES.items() if identifier.startswith(prefix)), ())


def lab_proves(identifier: str, lab: tuple[Evidence, ...]) -> bool:
    """Whether one lab run meets a proof rule for *identifier*'s type."""
    rules = _rules_for(identifier)
    for evidence in lab:
        seen = {observation.check for observation in evidence.observations if observation.seen}
        if any(rule.seen <= seen for rule in rules):
            return True
    return False


def lab_clean(identifier: str, lab: tuple[Evidence, ...]) -> bool:
    """Whether the lab ran and every run is clean for *identifier*'s type: no
    note at all, and every check its proof rules name was answered "not seen".
    False for a type without proof rules (the lab cannot clear it)."""
    rules = _rules_for(identifier)
    if not rules or not lab:
        return False
    checks = frozenset().union(*(rule.seen for rule in rules))
    for evidence in lab:
        answered = {observation.check: observation.seen for observation in evidence.observations}
        if evidence.notes or any(answered.get(check, True) for check in checks):
            return False
    return True


def decide_verdict(identifier: str, facts: VerdictFacts, never_flag: AbstractSet[str] = frozenset()) -> VerdictDecision:
    """The verdict this curator reaches on *identifier* from its own *facts*,
    given the published *never_flag* identifiers (exact canonical identifiers)."""
    if identifier.startswith(ADDRESS_PREFIXES) and identifier in never_flag:
        return VerdictDecision(Verdict.REJECTED, "an exact never-flag entry")
    try:
        provider = never_promote.never_promoted(identifier)
    except never_promote.RangesUnavailable:
        return VerdictDecision(Verdict.NOT_PROVEN, "a bare IP, and the CDN/cloud ranges could not be read")
    if provider:
        return VerdictDecision(Verdict.NOT_PROVEN, f"a bare IP inside {provider}'s range is never promoted")
    if facts.citable_listing:
        return VerdictDecision(Verdict.CONFIRMED, f"a citable source lists it ({facts.citable_listing})",
                               promotable=True, tier=Tier.BLOCK, citation=facts.citable_listing)
    if lab_proves(identifier, facts.lab):
        return VerdictDecision(Verdict.CONFIRMED, "lab evidence meets the proof rule; lab-only, so flag tier",
                               promotable=True, tier=Tier.FLAG)
    if facts.sources_clean and lab_clean(identifier, facts.lab):
        return VerdictDecision(Verdict.REJECTED, "the lab ran clean and no source lists it")
    return VerdictDecision(Verdict.NOT_PROVEN, "no source lists it and the lab did not prove or clear it")


class NotProvenStep(Enum):
    """What happens to a not-proven threat today."""

    KEEP_FLAGGING = "keep flagging"
    RETEST = "re-test"
    CLOSE_UNPROVEN = "close unproven"      # stops flagging, drops to monitor


def not_proven_step(opened: str, today: str, retests_done: int) -> NotProvenStep:
    """The step for a threat not proven since *opened* (ISO day), on *today*,
    after *retests_done* re-tests. A missed re-test day is caught up on the
    next beat; from day 30 it closes. Raises ValueError on a malformed day."""
    age = (date.fromisoformat(today) - date.fromisoformat(opened)).days
    if age >= NOT_PROVEN_FLAG_DAYS:
        return NotProvenStep.CLOSE_UNPROVEN
    if retests_done < len(RETEST_DAYS) and age >= RETEST_DAYS[retests_done]:
        return NotProvenStep.RETEST
    return NotProvenStep.KEEP_FLAGGING
