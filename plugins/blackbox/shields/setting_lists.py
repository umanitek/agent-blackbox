"""A shield setting's list, read item by item: one bad entry drops itself, never the whole list.

Independent review 2026-11-26, finding 5: each shield read its stored lists all-or-nothing, so one
invalid entry emptied a list while the shield still read "on" — ``protected: ['~/Taxes',
'Documents/x']`` protected nothing, one unknown agent id in ``sandboxed`` took every agent out of
the sandbox, a duplicate in Network Shield's ``protections`` turned the Threat Firewall off. A
stored list is now read with :func:`kept`: every entry the reader accepts stays (normalised, in
order, de-duplicated BEFORE the length cap), each dropped one is named by its position (never its
text — a protected path is the person's own), and the problems ride on the mode
(``ShieldMode.problems``) for the card to show. A settings WRITE stays strict (:func:`strict`:
refused with its sentence and nothing stored), over the same reading.

Usage::

    found = kept(raw, canonical_item, MAX_PROTECTED, "file-shield.protected")
    found.values      # ("~/Taxes",)
    found.problems    # ("file-shield.protected[1] is not valid and is ignored",)
    strict(raw, canonical_item, MAX_PROTECTED)   # the values, or None when anything was dropped
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

#: Reads one stored entry: its normalised form, "" to skip it quietly (an empty line), None when invalid.
EntryReader = Callable[[Any], Optional[str]]


@dataclass(frozen=True)
class KeptList:
    """A stored list as read: *values* in force, *problems* one sentence per entry dropped."""

    values: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()


def kept(raw: Any, read: EntryReader, limit: int, where: str) -> KeptList:
    """Every entry of *raw* that *read* accepts, de-duplicated, the first *limit* of them."""
    if not isinstance(raw, list):
        return KeptList(problems=(f"{where} is not a list and is ignored",))
    values: list[str] = []
    problems: list[str] = []
    for index, item in enumerate(raw):
        value = read(item)
        if value is None:
            problems.append(f"{where}[{index}] is not valid and is ignored")
        elif value:
            values.append(value)
    unique = tuple(dict.fromkeys(values))
    if len(unique) > limit:
        problems.append(f"{where}: only the first {limit} are used")
    return KeptList(unique[:limit], tuple(problems))


def strict(raw: Any, read: EntryReader, limit: int) -> Optional[tuple[str, ...]]:
    """The values of *raw* when every entry reads cleanly within *limit* (duplicates folded first); None otherwise."""
    found = kept(raw, read, limit, "")
    return None if found.problems else found.values


__all__ = ["EntryReader", "KeptList", "kept", "strict"]
