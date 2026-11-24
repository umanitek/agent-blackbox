"""Names DNS Shield never refuses, whatever a list or the verified graph says (review 2026-11-21, finding 13).

A mistaken or poisoned entry in a public block list — or in the verified threat graph — must
never cut a Mac off from what keeps it working and safe: Apple's own services (updates, iCloud,
the App Store), certificate checks (OCSP / CRL — blocking them breaks every secure connection),
GitHub (where Blackbox and its lists update from) and this machine itself. These names, every
subdomain of them, and the person's own allow list are taken out of every plan Network Shield
builds; a verified-graph entry spared this way is REPORTED (``spared``) so the person sees it —
it is never silently dropped or silently enforced.

The person's own block list is theirs: an entry they typed themselves is not overridden.

**Undo:** changes no system state — it only shapes the plan :mod:`.enforcement` builds.

The Threat Firewall has the same rule for addresses (:data:`NEVER_BLOCK_IPS`, :func:`split_ips`):
the big public DNS resolvers are never dropped, so a mistaken graph entry can not take away the
resolver a person's DoH client, VPN or WARP uses (KI-674, Linux round L2: 1.1.1.1 was in the
verified graph from the SafeDep Threat Intelligence Data Hub, uncorrected, and the firewall dropped
it). A graph entry for one belongs in a curator correction (``blackbox curate never-flag`` with
MISP's public-resolver warninglists); this list is what holds until then, and after.

Usage::

    protected("swscan.apple.com")              # True
    enforce, spared = split(names, allow)      # names to refuse, names spared
    drop, spared_ips = split_ips(ips, allow)   # addresses to drop, addresses spared
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

#: Never refused, with every subdomain.
NEVER_BLOCK = frozenset({
    # Apple: updates, iCloud, App Store, notarisation and Gatekeeper's own checks.
    "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "apple-cloudkit.com", "cdn-apple.com",
    "aaplimg.com", "apple.news",
    # Certificate status (OCSP / CRL): refusing them breaks secure connections everywhere.
    "ocsp.apple.com", "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com", "ocsp.sectigo.com",
    "crl.sectigo.com", "ocsp.globalsign.com", "crl.globalsign.com", "ocsp.pki.goog", "crl.pki.goog",
    "r10.o.lencr.org", "r11.o.lencr.org", "x1.c.lencr.org", "ocsp.entrust.net", "crl.entrust.net",
    # Where Blackbox and its lists update from.
    "github.com", "githubusercontent.com",
    # This machine.
    "localhost",
})


#: Never dropped: the anycast addresses of the big public DNS resolvers — Cloudflare (1.1.1.1 and its
#: malware / family variants), Google Public DNS, Quad9, Cisco OpenDNS — exact addresses only (a
#: range would spare whatever else shares it).
NEVER_BLOCK_IPS = frozenset(str(ipaddress.ip_address(address)) for address in (
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
    "2606:4700:4700::1113", "2606:4700:4700::1003",
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
    "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123", "2620:119:35::35", "2620:119:53::53",
))


def _canonical_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return ""


def split_ips(ips: Iterable[str], allow: Iterable[str] = ()) -> tuple[list[str], list[str]]:
    """``(to drop, spared)`` — *ips* minus :data:`NEVER_BLOCK_IPS` and the addresses on the person's
    *allow* list (compared in canonical form, ``2620:FE::FE`` is ``2620:fe::fe``), both sorted."""
    spare = NEVER_BLOCK_IPS | {canonical for canonical in map(_canonical_ip, allow) if canonical}
    drop, spared = [], []
    for ip in ips:
        (spared if _canonical_ip(ip) in spare else drop).append(ip)
    return sorted(drop), sorted(spared)


def protected(name: str, allow: Iterable[str] = ()) -> bool:
    """Whether *name* (normalised, lower case) is never to be refused: on :data:`NEVER_BLOCK`
    or the person's *allow* list, itself or as a subdomain."""
    shield = NEVER_BLOCK | {entry.lower().strip(".") for entry in allow}
    labels = name.lower().strip(".").split(".")
    return any(".".join(labels[i:]) in shield for i in range(len(labels)))


def split(names: Iterable[str], allow: Iterable[str] = ()) -> tuple[list[str], list[str]]:
    """``(to refuse, spared)`` — *names* minus the never-block ones, and those spared, both sorted."""
    allow = tuple(allow)
    enforce, spared = [], []
    for name in names:
        (spared if protected(name, allow) else enforce).append(name)
    return sorted(enforce), sorted(spared)
