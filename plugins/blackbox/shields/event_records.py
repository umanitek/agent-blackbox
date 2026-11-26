"""The records of a shield's events report (moved out of ``contract.py`` unchanged).

A shield's ``events()`` answers :class:`ShieldEvent` records: the story of one event, what to do,
its facts and the timeline of the agent session around it. ``contract.py`` re-exports them, so
callers keep importing them from the contract.
"""

from __future__ import annotations

from dataclasses import dataclass

from .json_records import JsonValue, _record_json


@dataclass(frozen=True)
class TimelineStep:
    """One step of the session around an event (model call, tool call, file read …)."""

    type: str
    ts: float
    tool: str
    label: str
    result: str = ""
    threats: tuple[str, ...] = ()
    threat_titles: tuple[str, ...] = ()
    this: bool = False

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class SessionSummary:
    """The agent session an event happened in."""

    id: str
    agent: str
    model: str
    start: str
    end: str
    status: str
    steps: int

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class EventFact:
    """One labelled fact of an event; *mono* shows the value in a fixed-width font."""

    label: str
    value: str
    mono: bool = False

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class ShieldEvent:
    """One event of a shield's local report: the story, what to do, the facts and the timeline.

    *story* is HTML-safe text with a few bold spans; the shield writes it, the page
    renders it as given (no shield prose in JavaScript).
    """

    ts: float
    identifier: str
    title: str
    severity: str
    outcome: str
    tool: str
    command: str
    asked: str
    logo: str
    story: str
    session: SessionSummary
    what_to_do: tuple[str, ...] = ()
    facts: tuple[EventFact, ...] = ()
    timeline: tuple[TimelineStep, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)
