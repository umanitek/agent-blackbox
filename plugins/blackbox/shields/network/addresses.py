"""Which addresses a threat list may act on here: the publicly routable ones (FIX-0222).

Usage::

    public_only({"45.130.148.102", "192.168.54.1"})   # frozenset({"45.130.148.102"})
"""

from __future__ import annotations

import ipaddress
from typing import Iterable


def public_only(ips: Iterable[str]) -> frozenset[str]:
    """The publicly routable addresses in *ips*.

    WHY: a threat list's private, CGNAT, link-local or unspecified address (seen in the verified
    graph: ``192.168.54.1``, ``100.106.194.93``, ``169.254.169.254``, ``0.0.0.0``) names a host on
    *someone else's* network. Here the same address is this user's router, tailnet peer or cloud
    metadata service, so acting on it would cut the user off their own network, and a monitor
    marking it would cry wolf. Only the user's own block list may name a non-public address.
    """
    public = set()
    for entry in ips:
        try:
            if ipaddress.ip_address(entry).is_global:
                public.add(entry)
        except ValueError:
            continue
    return frozenset(public)
