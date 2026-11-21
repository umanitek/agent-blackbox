"""A shield's own API: named endpoints beyond the card and the events report.

Most shields need only ``status`` and ``events``. A shield that has live data of its own
(Network Shield: the connections on this machine right now, its system status) publishes it
as a :class:`ShieldApi` — named **reads** and **writes** — served by the dashboard at
``GET`` / ``POST /api/shields/<shield id>/api/<name>``. The core still never names a shield:
it looks the endpoint up through the registry.

Shields may not import the ruleset or the dashboard (one-way dependencies). What a shield's
API needs from them is handed in per call as a :class:`ShieldContext` (dependency injection):
the dashboard builds it from its own modules.

Usage::

    API = ShieldApi(reads={"connections": monitor.read_connections},
                    writes={"report": reports.record})
    # a read:  handler(context, params)  -> JsonValue
    # a write: handler(context, body)    -> JsonValue
    # either may raise ShieldApiError(status, "message") for a refusal the caller should see
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence

from .json_records import JsonValue

#: The largest write body a shield endpoint receives (the dashboard caps it before parsing).
MAX_WRITE_BYTES = 256 * 1024
#: An endpoint name: lower-case words joined by hyphens (it is part of a URL path).
NAME_PATTERN = r"[a-z][a-z0-9-]{0,47}"


class ShieldApiError(Exception):
    """A refusal a shield endpoint answers on purpose: *status* is the HTTP status, the
    message is shown to the caller as given (write it for a person)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class AssistantAnswer:
    """One answer of Blackbox's assistant: *ok*, the *answer* text, or the *error* and whether
    the reason is that no AI model is connected yet (*needs_model*)."""

    ok: bool
    answer: str = ""
    error: str = ""
    needs_model: bool = False


@dataclass(frozen=True)
class ShieldContext:
    """What the dashboard hands a shield endpoint for one call.

    * ``network_indicators()`` — the verified graph's malicious domains and IPs
      (``ruleset.network_indicators``), or None before any could be read — it may wait for a
      build (an endpoint that must have the whole list); ``network_indicators_now()`` never waits (a page);
    * ``ask_assistant(message)`` — one turn of Blackbox's assistant (the one runner,
      ``dashboard/assistant/runner.py``);
    * ``lookup_hashes(sha256s)`` — which file fingerprints (SHA-256) the verified graph lists;
    * ``blocking`` — True when Blackbox is in Block mode;
    * ``request_body`` / ``request_headers`` — a write's exact body bytes and the request's
      headers (lower-case names), for an endpoint that checks a signature over the bytes.
    """

    network_indicators: Callable[[], Optional[Any]]
    ask_assistant: Callable[[str], AssistantAnswer]
    blocking: bool = False
    network_indicators_now: Optional[Callable[[], Optional[Any]]] = None
    #: ``lookup_hashes(sha256s) -> (the ones the verified graph lists, every one could be asked)``
    #: — a shield's file verdicts; None where the graph cannot be asked.
    lookup_hashes: Optional[Callable[[Sequence[str]], tuple[frozenset[str], bool]]] = None
    request_body: bytes = b""
    request_headers: Mapping[str, str] = field(default_factory=dict)

    def indicators_now(self) -> Optional[Any]:
        """The verified network lists known now, never waiting for a build."""
        return (self.network_indicators_now or self.network_indicators)()


@dataclass(frozen=True)
class RawAnswer:
    """An endpoint's answer sent byte-for-byte, with extra headers — for an answer whose exact
    bytes are signed (the system protection helper's plan: ``X-Blackbox-Signature``). The
    dashboard sends *body* as ``application/json`` unchanged."""

    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


ReadHandler = Callable[[ShieldContext, Mapping[str, str]], JsonValue]
WriteHandler = Callable[[ShieldContext, Mapping[str, Any]], JsonValue]
#: ``judge(body) -> [reasons]``: why a write would turn protection DOWN (empty: it would not).
#: The shield judges its own writes against its own current state; a non-empty answer holds
#: the write for the person's approval (the core's ``approvals`` gate).
WeakeningJudge = Callable[[Mapping[str, Any]], list[str]]


@dataclass(frozen=True)
class ShieldApi:
    """A shield's named endpoints: *reads* answer GET, *writes* answer POST. *weakening* names
    the writes that can turn protection down and how to tell (:data:`WeakeningJudge`); a write
    without a judge never weakens anything."""

    reads: Mapping[str, ReadHandler] = field(default_factory=dict)
    writes: Mapping[str, WriteHandler] = field(default_factory=dict)
    weakening: Mapping[str, WeakeningJudge] = field(default_factory=dict)
