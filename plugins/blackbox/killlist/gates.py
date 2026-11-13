"""Blast-radius gates and last-good (R14, plan §06 KILL LIST) — pure.

A signed kill list is not applied blindly. Reader-side, per entry:

* a WIDE kill (name- or publisher-wide) needs the ROOT as a third signer;
* a kill on a POPULAR or ALLOWLISTED artifact needs the root AND a 24-hour
  hold counted from the list's signed day;
* a version may add at most :data:`MAX_NEW_DISABLES` disables over the
  previous applied list — more, and the WHOLE list is refused.

Refused entries fall out; a refused list leaves the LAST-GOOD list in force.
Never "disable all", never "enable all": the Mozilla 2019 certificate
expiry disabled every add-on at once, which is the failure this guards.

Usage::

    decision = admit(kill_list, signers=..., root_signers=..., previous=last_good, now=time.time(),
                     is_popular=allowlist_predicate)
    decision.applied        # the entries now in force (or the previous list's when refused)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, UTC
from typing import AbstractSet, Callable, Optional

from .statement import KillEntry, KillList

#: New disables one version may add over the previous applied list.
MAX_NEW_DISABLES = 20
#: Hold on popular / allowlisted targets, counted from the signed day.
POPULAR_HOLD_SECONDS = 24 * 3600.0


@dataclass(frozen=True)
class Decision:
    """``applied`` — entries in force after this decision; ``version`` — whose
    they are; ``refused`` — why the new list was refused as a whole ("" =
    accepted); ``deferred`` — entries still inside their 24 h hold;
    ``dropped`` — entries that failed a gate, with the reason."""

    applied: tuple[KillEntry, ...]
    version: int
    refused: str = ""
    deferred: tuple[KillEntry, ...] = ()
    dropped: tuple[tuple[KillEntry, str], ...] = ()


def _held(kill_list: KillList, now: float) -> bool:
    """True while *now* is inside the 24 h hold after the list's signed day."""
    try:
        signed = datetime.combine(date.fromisoformat(kill_list.day), datetime.min.time(), tzinfo=UTC).timestamp()
    except ValueError:
        return True   # an unparseable day never releases a hold
    return now < signed + POPULAR_HOLD_SECONDS


def admit(kill_list: KillList, *, signers: AbstractSet[str], root_signers: AbstractSet[str],
          previous: Optional[KillList], now: float,
          is_popular: Callable[[KillEntry], bool] = lambda entry: False) -> Decision:
    """Decide what *kill_list* puts in force. *signers* — the manifest curator
    keys that signed it (quorum already checked by the parser); *root_signers*
    — root keys that signed it; *previous* — the last applied list."""
    previous_entries = previous.entries if previous is not None else ()
    if previous is not None and kill_list.version <= previous.version:
        return Decision(previous_entries, previous.version, refused=f"version {kill_list.version} is not newer than {previous.version}")
    root_signed = bool(root_signers)
    held = _held(kill_list, now)
    kept: list[KillEntry] = []
    deferred: list[KillEntry] = []
    dropped: list[tuple[KillEntry, str]] = []
    for entry in kill_list.entries:
        if entry.wide and not root_signed:
            dropped.append((entry, "a name- or publisher-wide kill needs the root as a third signature"))
            continue
        if is_popular(entry):
            if not root_signed:
                dropped.append((entry, "a kill on a popular or allowlisted artifact needs the root to co-sign"))
                continue
            if held:
                deferred.append(entry)
                continue
        kept.append(entry)
    previous_keys = {e.key for e in previous_entries if e.action.value == "disable"}
    new_disables = [e for e in kept if e.action.value == "disable" and e.key not in previous_keys]
    if len(new_disables) > MAX_NEW_DISABLES:
        return Decision(previous_entries, previous.version if previous else 0,
                        refused=f"{len(new_disables)} new disables in one version (limit {MAX_NEW_DISABLES}); last-good kept",
                        dropped=tuple(dropped))
    return Decision(tuple(kept), kill_list.version, deferred=tuple(deferred), dropped=tuple(dropped))
