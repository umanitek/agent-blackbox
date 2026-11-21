"""Public block lists, inside Blackbox's guard: an AI agent reaching a domain on a list the user
chose for DNS Shield is a ``network:listed-host`` finding (critical, local-only like every shield
finding). The lists are DNS Shield's, so this runs only with Blackbox Desktop — added to the
public shield's own detector through the extension point (``ShieldExtension.detect``).

The hot path reads a list only from its downloaded copy (:func:`.blocklists.cached_domains`):
it never downloads.

**Undo:** refuses an agent's call only while Network Shield's lists are on; switched off, it
returns no finding and nothing was changed on the machine.
"""

from __future__ import annotations

from typing import Any

from ....detection import Finding
from ....shields.contract import FindingKind, ShieldMode
from ....shields.network import lockdown, mode as mode_module
from . import blocklists

LISTED_ID = "network:listed-host"
FINDING_KINDS = (FindingKind("data-exfil", "host-system", "T1041", identifier=LISTED_ID),)


def _chosen_lists(mode: ShieldMode) -> tuple[frozenset[str], ...]:
    """The cached names of each public list *mode* chose (empty sets for lists never downloaded)."""
    chosen = set(mode_module.option(mode, mode_module.OPT_LISTS))
    return tuple(blocklists.cached_domains(pack) for pack in mode_module.list_packs()
                 if pack.id in chosen and pack.status == "supported")


def _listed(host: str, names: frozenset[str]) -> bool:
    """True when *host* or a parent domain is in *names* (a set lookup per label, not a scan)."""
    labels = host.split(".")
    return any(".".join(labels[index:]) in names for index in range(len(labels) - 1))


def detect(tool_name: str, args: Any, mode: ShieldMode) -> list[Finding]:
    """A finding per host on a chosen public list (with DNS Shield on; the user's allow list wins)."""
    if not mode.enabled or mode_module.DNS not in mode_module.protections(mode):
        return []
    lists = _chosen_lists(mode)
    if not lists:
        return []
    allowed = mode_module.option(mode, mode_module.OPT_ALLOW)
    return [lockdown.finding(LISTED_ID, tool_name, host, "is on a public block list you chose")
            for host in lockdown.hosts_in(args)
            if not any(host == entry or host.endswith("." + entry) for entry in allowed)
            and not any(host == entry or host.endswith("." + entry) for entry in mode_module.option(mode, mode_module.OPT_BLOCK))
            and any(_listed(host, names) for names in lists)]
