"""Which name a remote address was looked up as — from DNS Shield's own resolver (KI-588 c).

The root helper's resolver relays every allowed lookup and, in its report, says which addresses
each answer gave and the name that was asked (``resolved: [{ip, domain, ts}]``, helper
``dns_answers.rs``). A companion app's Activity view then shows "api.example.com" beside a
connection instead of only its address. Only lookups that went through DNS Shield are known: with
DNS Shield off, or for an app that resolves on its own (DNS over HTTPS), the answer is "" —
honest, never guessed, and nothing is ever asked of an outside service.

Privacy: the names are this machine's browsing history, so they are kept in MEMORY only (never on
disk, never shared), bounded to :data:`MAX_KEPT` addresses and forgotten after
:data:`KEEP_SECONDS`. A dashboard restart forgets them all.

Usage::

    record(validate(body.get("resolved"), now))   # from enforcement.record_report
    lookup("93.184.215.14")                       # Resolved(domain, seen_at) or None
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Optional

from ....shields.shield_api import ShieldApiError
from .. import mode as mode_module

MAX_PER_REPORT = 500
MAX_KEPT = 4000
#: How long a looked-up address keeps its name (DNS answers are short-lived; an hour covers a
#: long connection without keeping a day of history).
KEEP_SECONDS = 3600

_lock = threading.Lock()
_kept: OrderedDict[str, tuple[str, float]] = OrderedDict()


@dataclass(frozen=True)
class Resolved:
    """The *domain* an address was looked up as, and when DNS Shield relayed that answer."""

    domain: str
    seen_at: float


def _refuse() -> ShieldApiError:
    return ShieldApiError(400, f"resolved must be a list of at most {MAX_PER_REPORT} {{ip, domain, ts}} items")


def validate(raw: Any, now: float) -> list[tuple[str, str, float]]:
    """The report's ``resolved`` part as ``(ip, domain, ts)``; [] when absent (older helpers).
    Strict on shape (one malformed item refuses the whole report); a name that is not a domain
    Blackbox can show (a single-label local name such as ``printer``) is skipped, not refused —
    WHY: refusing would drop the helper's whole report over one harmless local lookup."""
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > MAX_PER_REPORT:
        raise _refuse()
    found = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("ip"), str) or len(item["ip"]) > 64:
            raise _refuse()
        try:
            ip = str(ipaddress.ip_address(item["ip"]))
        except ValueError:
            raise _refuse() from None
        ts = item.get("ts", int(now))
        if not isinstance(item.get("domain"), str) or len(item["domain"]) > 255 or type(ts) is not int or ts < 0:
            raise _refuse()
        domain = mode_module.normalise_entry(item["domain"])
        if domain is not None and domain != ip:
            found.append((ip, domain, float(min(ts, now))))
    return found


def record(found: list[tuple[str, str, float]]) -> None:
    """Keeps each address's newest name (bounded: the oldest addresses are dropped first)."""
    with _lock:
        for ip, domain, ts in found:
            _kept.pop(ip, None)
            _kept[ip] = (domain, ts)
        while len(_kept) > MAX_KEPT:
            _kept.popitem(last=False)


def lookup(ip: str, now: Optional[float] = None) -> Optional[Resolved]:
    """The name *ip* was last looked up as through DNS Shield, or None (never seen, or older
    than :data:`KEEP_SECONDS`)."""
    now = time.time() if now is None else now
    with _lock:
        found = _kept.get(ip)
    if found is None or now - found[1] > KEEP_SECONDS:
        return None
    return Resolved(domain=found[0], seen_at=found[1])


def forget() -> None:
    """Drops every kept name (tests; a person may also restart the dashboard)."""
    with _lock:
        _kept.clear()


__all__ = ["KEEP_SECONDS", "MAX_KEPT", "Resolved", "forget", "lookup", "record", "validate"]
