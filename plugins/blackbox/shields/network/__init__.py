"""Network Shield — the second shield: AI agents kept to the hosts you allow, and, with Blackbox
Desktop, this machine's whole network watched and guarded.

What this plugin runs, each part in its own module:

* :mod:`.lockdown` — agent network lockdown and the block list, inside Blackbox's guard;
* :mod:`.monitor` — which apps talk to which servers, live (read-only, no special rights);
* :mod:`.system` — CPU, memory, disks and network interfaces, live;
* :mod:`.api` — its endpoints (``/api/shields/network-shield/api/<name>``);
* :mod:`.status` / :mod:`.events` — the card (with its Blackbox Desktop offer) and the events report;
* :mod:`.mode` — its setting, ``shields.network-shield`` (one shape, with or without Desktop).

What Blackbox Desktop adds through its add-on (:mod:`..extensions`): DNS Shield, the Threat
Firewall, cutting malicious connections, SSH lockdown and watching (its native helper applies
them), the traffic map, every process explained, the history and the security review — its
endpoints, events, page and public block lists. Without it the card and
the page offer Blackbox Desktop for those parts; lockdown works regardless.

Lockdown and block-list findings are claimed by the gate (``claims``) and counted only while the
shield is on (``allows``).

Usage::

    from plugins.blackbox import shields
    network = shields.get("network-shield")
    network.detect("terminal", {"command": "curl https://x.example"}, network.mode())
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Mapping

from ..contract import Capability, Pack, Shield, ShieldMode
from . import api, events, lockdown, mode, status

HERE = Path(__file__).resolve().parent
FINDING_KINDS = lockdown.FINDING_KINDS
_CLAIMED = tuple(kind.identifier for kind in FINDING_KINDS)

#: What Network Shield protects inside Blackbox's guard — each one proven by a row of its attack
#: table driven through the real hook.
CAPABILITIES: tuple[Capability, ...] = (
    Capability("agent-lockdown", "Agent network lockdown", "AI agents reach only the hosts you allow",
               claims=(lockdown.LOCKDOWN_ID,)),
    Capability("block-list", "Your block list", "names and addresses you never want reached", claims=(lockdown.BLOCKED_ID,)),
)


def _current_mode() -> ShieldMode:
    # Looked up on every call, not bound once: a test stands a mode in by patching mode.current.
    return mode.current()


def claims(finding: Mapping[str, Any]) -> bool:
    """True for the findings Network Shield raises."""
    identifier = str(finding.get("identifier") or "")
    return any(fnmatch.fnmatchcase(identifier, pattern) for pattern in _CLAIMED)


def allows(_finding: Mapping[str, Any], current: ShieldMode) -> bool:
    """A Network Shield finding counts only while the shield is on."""
    return current.enabled


def _use_data(packs: tuple[Pack, ...], _roots: Any) -> None:
    mode.use_packs(packs)   # its own (none) — an add-on with public lists hands in its own


NETWORK = Shield(
    id=mode.SHIELD_ID, name="Network Shield",
    tagline="Keep AI agents to the hosts you allow — and, with Blackbox Desktop, see and stop the malicious ones.",
    beta=True, mode=_current_mode, validate=mode.validate, detect=lockdown.detect,
    claims=claims, allows=allows, status=status.build, events=events.report, settings_fields=mode.fields,
    finding_kinds=FINDING_KINDS, capabilities=CAPABILITIES, packs=HERE / "lists",
    page=HERE / "page" / "network.html", attacks=HERE / "attacks.json", use_data=_use_data, api=api.API,
)
