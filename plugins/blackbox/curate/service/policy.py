"""The automation policy — what the curator service may sign on its own (Community Curation C9, plan §07).

One pure decision table. For an action and the facts THIS node established by
itself, :func:`decide` answers either "the service may sign" or "a person
must", with the reason. Nothing here reads the network: the beat gathers the
facts (:mod:`.beat`) and asks.

The table, in words (:data:`POLICY_ROWS` is the same table as data, and
:func:`policy_text` is the exact text an operator accepts):

* no judgement involved — heartbeat, in-review acknowledgement, keep-alive;
* a lookup in an independent public source — confirm a dependency when this
  node itself finds a malicious-package advisory for that exact version, and
  the statement cites that advisory;
* a clock — defer a corroborated blockable threat this node's own lookup found
  nothing for; lapse a deferral after 30 days;
* arithmetic over the public record — list a reporter, renew a listing or
  delist on the reputation floor when this node's own ledger calls for it;
* everything else is a person's: confirming anything else, rejecting, a
  strike, a partner grant, a pause, a collapse, anything with the root key.

Pattern: Strategy table (one rule per action) returning a frozen Value Object.

Usage::

    decision = decide(action_for(kind, fields), identifier, Facts(malicious_advisory="MAL-2026-1",
                                                                  evidence_cited="advisory:MAL-2026-1"))
    decision.automatic, decision.reason
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping

from ...kernel.signing import CuratorStatement, statement_order
from ..queue import BLOCKABLE_PREFIXES

#: The most the service itself signs per UTC day — below every reader's own
#: daily cap (100 confirmations, 20 listings), so the service can never be the
#: reason a reader holds statements back.
SERVICE_CONFIRMATIONS_PER_DAY = 50
SERVICE_LISTINGS_PER_DAY = 10
#: A deferral the service signed lapses after this many days (the reader's own clock is the same).
DEFERRAL_LAPSE_DAYS = statement_order.DEFERRAL_LAPSE_DAYS   # one clock for readers and curators


class Action(Enum):
    """What a curator statement DOES, in the policy's words."""

    HEARTBEAT = "heartbeat"
    ACKNOWLEDGE = "acknowledge"
    KEEP_ALIVE = "keep-alive"
    CONFIRM = "confirm"
    DEFER = "defer"
    LAPSE_DEFERRAL = "lapse-deferral"
    LIST = "list"
    DELIST = "delist"
    REJECT = "reject"
    STRIKE = "strike"
    GRANT_PARTNER = "grant-partner"
    PAUSE = "pause"
    ROOT = "root"
    OTHER = "other"


@dataclass(frozen=True)
class Facts:
    """What THIS node established by itself about one item — never what the
    other curator or the reporter says.

    ``malicious_advisory`` — the malicious-package advisory this node's own
    lookup returned for the exact version ("" = none, or the lookup failed).
    ``evidence_cited`` — the evidence reference the statement signs.
    ``corroborated`` — this node's own stage for the threat is CORROBORATED.
    ``lookup_clean`` — this node's own lookup ANSWERED and found no advisory
    (a failed lookup is not clean). ``deferral_age_days`` — days since the
    deferral in force was signed (-1 = none). ``ledger_calls_for`` — what this
    node's own ledger calls for this reporter today: ``list``, ``delist`` or "".
    """

    malicious_advisory: str = ""
    evidence_cited: str = ""
    corroborated: bool = False
    lookup_clean: bool = False
    deferral_age_days: int = -1
    ledger_calls_for: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    """``automatic`` — the service may sign it on its own; otherwise a person
    must. ``reason`` — one line, shown in the human queue and the audit log."""

    action: Action
    automatic: bool
    reason: str


def _always(reason: str) -> Callable[[str, Facts], tuple[bool, str]]:
    return lambda identifier, facts: (True, reason)


def _never(reason: str) -> Callable[[str, Facts], tuple[bool, str]]:
    return lambda identifier, facts: (False, reason)


def _exact_dependency(identifier: str) -> bool:
    return identifier.startswith("dep:") and "@" in identifier and not identifier.endswith("@*")


def _confirm(identifier: str, facts: Facts) -> tuple[bool, str]:
    if not _exact_dependency(identifier):
        return False, "no independent machine-checkable source exists for this kind of threat"
    if not facts.malicious_advisory:
        return False, "this node found no malicious-package advisory for that exact version"
    if facts.evidence_cited != f"advisory:{facts.malicious_advisory}":
        return False, "the statement does not cite the advisory this node found itself"
    return True, f"this node found {facts.malicious_advisory} for that exact version"


def _defer(identifier: str, facts: Facts) -> tuple[bool, str]:
    if not identifier.startswith(BLOCKABLE_PREFIXES):
        return False, "only a blockable kind is deferred for missing evidence"
    if not (facts.corroborated and facts.lookup_clean):
        return False, "deferring needs a corroborated threat and this node's own lookup answering 'nothing found'"
    return True, "corroborated, and this node's own lookup found no evidence yet"


def _lapse(identifier: str, facts: Facts) -> tuple[bool, str]:
    if statement_order.deferral_in_force(facts.deferral_age_days):
        return False, f"a deferral lapses after {DEFERRAL_LAPSE_DAYS} days"
    return True, f"the deferral is {facts.deferral_age_days} days old"


def _ledger(wanted: str, why: str) -> Callable[[str, Facts], tuple[bool, str]]:
    def rule(identifier: str, facts: Facts) -> tuple[bool, str]:
        if facts.ledger_calls_for != wanted:
            return False, f"this node's own ledger does not call for that ({why})"
        return True, f"this node's own ledger calls for it ({why})"
    return rule


_RULES: dict[Action, Callable[[str, Facts], tuple[bool, str]]] = {
    Action.HEARTBEAT: _always("no judgement involved"),
    Action.ACKNOWLEDGE: _always("no judgement involved"),
    Action.KEEP_ALIVE: _always("no judgement involved"),
    Action.CONFIRM: _confirm,
    Action.DEFER: _defer,
    Action.LAPSE_DEFERRAL: _lapse,
    Action.LIST: _ledger("list", "graduation or renewal in good standing"),
    Action.DELIST: _ledger("delist", "the reputation floor"),
    Action.REJECT: _never("rejecting a threat is a person's decision"),
    Action.STRIKE: _never("a strike is an accusation of bad faith"),
    Action.GRANT_PARTNER: _never("a partner grant is a relationship, not a computation"),
    Action.PAUSE: _never("the pause is an emergency brake"),
    Action.ROOT: _never("the root key is a person's, unlocked only in the key console"),
    Action.OTHER: _never("not a routine action"),
}


def decide(action: Action, identifier: str, facts: Facts) -> PolicyDecision:
    """May the service sign *action* about *identifier*, given what this node
    established itself (*facts*)?"""
    automatic, reason = _RULES[action](identifier, facts)
    return PolicyDecision(action=action, automatic=automatic, reason=reason)


_KIND_ACTIONS: dict[str, Action] = {
    CuratorStatement.HEARTBEAT.value: Action.HEARTBEAT,
    CuratorStatement.IN_REVIEW.value: Action.ACKNOWLEDGE,
    CuratorStatement.CONFIRMATION.value: Action.CONFIRM,
    CuratorStatement.DEFERRAL.value: Action.DEFER,
    CuratorStatement.DEFERRAL_LAPSED.value: Action.LAPSE_DEFERRAL,
    CuratorStatement.REJECTION.value: Action.REJECT,
    CuratorStatement.PAUSE.value: Action.PAUSE,
    "blackbox.key-manifest": Action.ROOT,
}


def action_for(kind: str, fields: Mapping[str, str]) -> Action:
    """The policy action a statement of *kind* (its statement type) with these
    signed *fields* performs. A trusted-reporter entry is a delisting, a
    partner grant, or a plain listing; one that names a shared cluster is a
    collapse — a judgement — and anything unknown is OTHER (a person)."""
    if kind == CuratorStatement.COUNTED_AUTHORS.value:
        if fields.get("listed") == "no":
            return Action.DELIST
        if fields.get("class") == "partner":
            return Action.GRANT_PARTNER
        return Action.OTHER if fields.get("org") else Action.LIST
    return _KIND_ACTIONS.get(kind, Action.OTHER)


#: The §07 table: (what, who decides, why). The text an operator accepts is built from it.
POLICY_ROWS: tuple[tuple[str, str, str], ...] = (
    ("Heartbeat, in-review acknowledgement, keep-alive", "the service", "no judgement involved"),
    ("Confirm a malicious dependency", "the service, when this node itself finds a malicious-package advisory for that "
     "exact version and the statement cites it", "the truth check is a lookup in an independent public source; two nodes do it separately"),
    ("Defer (corroborated, no evidence yet) and lapse a deferral after 30 days", "the service", "reduces or holds enforcement; a clock, not a judgement"),
    ("List a reporter on graduation; renew a listing in good standing", "the service, when its own ledger agrees", "arithmetic over the public record"),
    ("Delist on the reputation floor", "the service, when its own ledger agrees", "a reduction, and reductions must be easy"),
    ("Confirm anything else (domains, URLs, wallets, skills, injection)", "A PERSON, with a typed confirmation code", "no independent machine-checkable source exists"),
    ("Reject a threat; record a strike", "A PERSON", "an accusation of bad faith"),
    ("Grant PARTNER to an organisation; collapse several keys into one cluster", "A PERSON", "a relationship or a judgement, not a computation"),
    ("Pause intake", "A PERSON", "an emergency brake"),
    ("Anything involving the root key", "A PERSON, in the key console with the passphrase and second factor", "it is the root"),
)


def policy_text() -> str:
    """The automation policy as the exact text an operator reads and accepts.
    Standing consent is bound to it: any change to the table or the limits
    changes this text, and the service stops signing until it is accepted again."""
    lines = ["Agent Blackbox — what the curator service may sign on its own", ""]
    lines += [f"- {what}: {who} ({why})." for what, who, why in POLICY_ROWS]
    lines += ["", f"The service signs at most {SERVICE_CONFIRMATIONS_PER_DAY} confirmations and "
                  f"{SERVICE_LISTINGS_PER_DAY} listings per day. Reductions are not limited.",
              "Every statement the service signs is signed with this machine's curator key, in its operator's name."]
    return "\n".join(lines) + "\n"


def policy_hash() -> str:
    """sha256 (hex) of :func:`policy_text` — what the standing consent names."""
    return hashlib.sha256(policy_text().encode("utf-8")).hexdigest()
