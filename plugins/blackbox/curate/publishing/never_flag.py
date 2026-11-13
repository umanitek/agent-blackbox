"""The never-flag batch: exact known-good addresses, published as corrections (trust-and-threat-lab P5, §03.4).

Input is one MISP warninglist file (CC0, github.com/MISP/misp-warninglists,
``lists/<name>/list.json``: ``{"name": …, "type": …, "list": [values]}``) —
the public DNS resolvers (IPv4, IPv6, hostnames) and the Cisco Umbrella top
1K. Every value is reviewed against the rules of D16 / F-031 before anything
is signed:

* EXACT values only. The hot path matches an IOC value exactly and a
  correction suppresses one subject, so a CIDR range, a wildcard or a pattern
  would suppress nothing: refused (a ``substring`` / ``regex`` list whole).
* ADDRESS types only (``ioc:ip``, ``ioc:domain``): a package, a skill or any
  other identifier is never a never-flag entry.
* No SHARED-HOSTING apex: a host under a Public Suffix List PRIVATE rule
  (``evil.github.io``), the rule itself (``github.io``) or a domain such rules
  sit under (``amazonaws.com``) — phishing lives there.

Pure: no I/O, no signing. The verb (``publishing.commands``) reads the file,
looks up which accepted values the verified graph holds, shows the review and
only then signs one correction per value.

Usage::

    batch = never_flag.review(json.loads(text))
    batch.source                       # "misp-warninglists:List of known IPv4 public DNS resolvers"
    [entry.identifier for entry in batch.accepted]    # ["ioc:ip:8.8.8.8", …]
    [(refusal.value, refusal.reason) for refusal in batch.refused]
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Mapping

from ...kernel import public_suffix, threat_ids

#: The most values one file may hold (the largest MISP resolver list holds ~63,000).
MAX_ENTRIES = 100_000
#: MISP list types whose values are patterns, never exact values.
_PATTERN_LIST_TYPES = frozenset({"substring", "regex"})
#: Identifier prefixes of the threat types that are never a never-flag entry.
_NON_ADDRESS_PREFIXES = ("dep:", "skill:", "injection:", "fileaccess:", "escalation:")
_ADDRESS_TYPES = frozenset({"ip", "domain"})


class NeverFlagError(ValueError):
    """The file as a whole cannot be a never-flag batch; the message says why."""


@dataclass(frozen=True)
class Refusal:
    """One value the review refused, with the rule that refused it."""

    value: str
    reason: str


@dataclass(frozen=True)
class NeverFlagReview:
    """``source`` — what every correction cites; ``accepted`` — canonical
    ``ioc:ip:…`` / ``ioc:domain:…`` identifiers (duplicates collapsed, file
    order kept); ``refused`` — every other value and why."""

    source: str
    accepted: tuple[str, ...]
    refused: tuple[Refusal, ...]


def review(warninglist: Mapping[str, Any]) -> NeverFlagReview:
    """Review a parsed MISP warninglist; raises :class:`NeverFlagError` when the
    file is not one, is a pattern list, or is too large."""
    name, values = warninglist.get("name"), warninglist.get("list")
    if not isinstance(name, str) or not name.strip() or not isinstance(values, list):
        raise NeverFlagError('not a MISP warninglist file: it needs a "name" and a "list"')
    if str(warninglist.get("type", "")).lower() in _PATTERN_LIST_TYPES:
        raise NeverFlagError(f"a {warninglist['type']} list holds patterns; never-flag entries are exact values")
    if len(values) > MAX_ENTRIES:
        raise NeverFlagError(f"{len(values)} values; one batch holds at most {MAX_ENTRIES}")
    accepted: list[str] = []
    refused: list[Refusal] = []
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        identifier, reason = classify(value)
        if reason:
            refused.append(Refusal(value, reason))
        elif identifier not in accepted:
            accepted.append(identifier)
    return NeverFlagReview(f"misp-warninglists:{name.strip()[:150]}", tuple(accepted), tuple(refused))


def classify(value: str) -> tuple[str, str]:
    """``(identifier, "")`` for an exact address that may be a never-flag entry,
    else ``("", why not)``. *value* is a bare IP or hostname, or an ``ioc:``
    identifier."""
    lowered = value.lower()
    if lowered.startswith(_NON_ADDRESS_PREFIXES) or "@" in value:
        return "", "not an address: never-flag applies to IPs and hostnames only"
    if lowered.startswith("ioc:"):
        parts = value.split(":", 2)
        if len(parts) != 3 or parts[1].lower() not in _ADDRESS_TYPES:
            return "", "not an address: never-flag applies to IPs and hostnames only"
        value = parts[2]
    if "/" in value or "*" in value or " " in value:
        return "", "a range or pattern: a correction suppresses one exact value"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return _hostname(value)
    return threat_ids.ioc_identifier("ip", str(address)), ""


def _hostname(value: str) -> tuple[str, str]:
    identifier = threat_ids.ioc_identifier("domain", value)
    host = identifier.split(":", 2)[2]
    if not threat_ids.ioc_value_is_well_formed("domain", host) or "." not in host or host.replace(".", "").isdigit():
        return "", "not an exact IP address or hostname"
    if public_suffix.is_shared_hosting(host) or host in _shared_hosting_apexes():
        return "", "a shared-hosting apex: its tenants are different parties"
    return identifier, ""


@lru_cache(maxsize=1)
def _shared_hosting_apexes() -> frozenset[str]:
    """Every domain a Public Suffix List PRIVATE rule sits under (``s3.amazonaws.com``
    → ``amazonaws.com``), the bare top-level label excluded."""
    apexes = set()
    for rule in public_suffix.load().private:
        labels = rule.removeprefix("*.").split(".")
        apexes.update(".".join(labels[start:]) for start in range(len(labels) - 1))
    return frozenset(apexes)
