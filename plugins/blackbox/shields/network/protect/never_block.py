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

Usage::

    protected("swscan.apple.com")              # True
    enforce, spared = split(names, allow)      # names to refuse, names spared
"""

from __future__ import annotations

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
