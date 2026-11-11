"""Never promote a bare IP on shared infrastructure (trust-and-threat-lab §03.4, F-031).

A bare IP address inside a CDN or cloud provider range (Cloudflare, Akamai,
Fastly, AWS, Azure, GCP) is shared by many tenants: one tenant's abuse must not
block everyone else behind the same address. Such an IP is automatically
"not proven" and never promoted. Only the bare IP is held back — a URL or a
domain hosted on a CDN names one tenant's content and is still promotable.

The ranges are held in code: ``never_promote_ranges.json`` beside this module,
taken from the MISP warninglists project (CC0) with each provider's upstream,
list version and fetch date recorded per provider. They are NEVER published as
never-flag entries (the hot path matches exact values only, so a range could
suppress nothing). Refreshing them is a deliberate code change: re-fetch each
``source``, collapse with :func:`ipaddress.collapse_addresses`, update
``list_version`` and ``fetched``.

Lookup: the collapsed ranges per provider and IP version are sorted
non-overlapping intervals, so one binary search per provider answers
(O(providers · log ranges)) — this runs per queued item, not on the hot path.

Usage::

    provider_for_ip("104.16.1.1")                   # "Cloudflare"
    never_promoted("ioc:ip:104.16.1.1")             # "Cloudflare" — a bare IP on a CDN
    never_promoted("ioc:url:https://104.16.1.1/x")  # None — a URL stays promotable
"""

from __future__ import annotations

import bisect
import functools
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_RANGES_FILE = Path(__file__).with_name("never_promote_ranges.json")
#: The only identifier kind the rule applies to: a bare IP address IOC.
_BARE_IP_PREFIX = "ioc:ip:"

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class RangesUnavailable(RuntimeError):
    """The held ranges could not be read — the rule cannot answer, so callers must not promote."""


@dataclass(frozen=True)
class ProviderRanges:
    """One provider's ranges: ``provider`` name, the ``source`` URL they were
    taken from, its ``list_version``, the ``fetched`` date, and per IP version
    (4, 6) the sorted, non-overlapping ``(first, last)`` address integers."""

    provider: str
    source: str
    list_version: str
    fetched: str
    intervals: dict[int, tuple[tuple[int, int], ...]]

    def contains(self, address: IPAddress) -> bool:
        """Whether *address* falls inside one of this provider's ranges."""
        spans = self.intervals.get(address.version, ())
        value = int(address)
        at = bisect.bisect_right(spans, (value, float("inf"))) - 1
        return at >= 0 and spans[at][0] <= value <= spans[at][1]


def _provider(entry: dict) -> ProviderRanges:
    networks = [ipaddress.ip_network(cidr) for cidr in entry["cidrs"]]
    intervals = {
        version: tuple((int(net.network_address), int(net.broadcast_address))
                       for net in ipaddress.collapse_addresses(n for n in networks if n.version == version))
        for version in (4, 6)
    }
    return ProviderRanges(provider=str(entry["provider"]), source=str(entry["source"]),
                          list_version=str(entry["list_version"]), fetched=str(entry["fetched"]), intervals=intervals)


@functools.lru_cache(maxsize=1)
def providers() -> tuple[ProviderRanges, ...]:
    """Every provider's held ranges (read once). Raises :class:`RangesUnavailable`
    when the file is missing or malformed — never an empty answer."""
    try:
        data = json.loads(_RANGES_FILE.read_text(encoding="utf-8-sig"))
        held = tuple(_provider(entry) for entry in data["providers"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RangesUnavailable(f"the never-promote ranges could not be read ({exc})") from exc
    if not held:
        raise RangesUnavailable("the never-promote ranges file names no provider")
    return held


def provider_for_ip(value: str) -> Optional[str]:
    """The provider whose range holds the IP address *value*, or None (also
    None when *value* is not an IP address)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return next((held.provider for held in providers() if held.contains(address)), None)


def never_promoted(identifier: str) -> Optional[str]:
    """The provider when *identifier* is a bare IP (``ioc:ip:…``) inside a CDN
    or cloud range — that threat is not proven and never promoted — else None.
    Raises :class:`RangesUnavailable` when the ranges cannot be read."""
    if not identifier.startswith(_BARE_IP_PREFIX):
        return None
    return provider_for_ip(identifier[len(_BARE_IP_PREFIX):])
