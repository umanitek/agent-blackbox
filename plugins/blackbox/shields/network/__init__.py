"""Network Shield — the second shield: this machine's network watched and guarded, and AI agents
kept to the hosts you allow. The core of it lives here; an add-on may add richer views.

Split the same way as every protection feature — see (read-only), act (reversible), respond:

* :mod:`.monitor` — see: which apps talk to which servers (:mod:`.monitor` itself), the SSH and
  login-file watch (``watch``), who is in this machine (``remote_access``), listeners the network
  can reach and startup items (``exposure``), the posture checks (``posture``), the helper's
  system report (``system_report``), and whether a program's signature is real (``signature``);
* :mod:`.protect` — act: the plan the system protection helper applies (``enforcement`` — DNS
  Shield, the Threat Firewall, cutting, SSH lockdown; never blocking what keeps a Mac working,
  ``never_block``), public block lists (``blocklists``, ``listed``), Lock remote access and
  brute-force blocking (``remote_lock``), posture fixes and the DNS tamper guard — each documents
  its Undo;
* :mod:`.respond` — events, alerts and the Remote access page's actions;
* :mod:`.lockdown` — agent network lockdown and the block list, inside Blackbox's guard;
* :mod:`.system` — CPU, memory, disks and network interfaces, live;
* :mod:`.api` / :mod:`.system_api` — the endpoints (``/api/shields/network-shield/api/<name>``);
* :mod:`.status` — the card; :mod:`.helper` — whether the system protection helper is installed;
* :mod:`.mode` — its setting, ``shields.network-shield``.

The system protection helper (``blackbox-netd``, a small root daemon) applies the plan and reports
back; without it DNS Shield, the Threat Firewall, cutting and SSH lockdown say so plainly and
lockdown works regardless. An add-on adds its views through :mod:`..extensions`.

Lockdown, block-list and public-list findings are claimed by the gate (``claims``) and counted
only while the shield is on (``allows``).

Usage::

    from plugins.blackbox import shields
    network = shields.get("network-shield")
    network.detect("terminal", {"command": "curl https://x.example"}, network.mode())
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Mapping

from ...detection import Finding
from ..contract import Capability, Pack, Shield, ShieldEvent, ShieldMode
from . import api, events, helper, lockdown, mode, monitor, notices, status
from .monitor import listening, signature, watch
from .protect import blocklists, enforcement, listed
from .respond import events as watch_events

#: What another package (an add-on) may use: the shield, its API (``require_on``,
#: ``malicious_ips``), the helper's plan and report (``enforcement``), the SSH watch, and the
#: signature and listener readers its process views build on.
__all__ = ["CAPABILITIES", "FINDING_KINDS", "NETWORK", "api", "enforcement", "helper", "listening", "mode",
           "monitor", "signature", "watch"]

HERE = Path(__file__).resolve().parent
FINDING_KINDS = lockdown.FINDING_KINDS + listed.FINDING_KINDS
_CLAIMED = tuple(kind.identifier for kind in FINDING_KINDS)

#: What Network Shield protects inside Blackbox's guard — each one proven by a row of its attack
#: table driven through the real hook.
CAPABILITIES: tuple[Capability, ...] = (
    Capability("agent-lockdown", "Agent network lockdown", "AI agents reach only the hosts you allow",
               claims=(lockdown.LOCKDOWN_ID,)),
    Capability("block-list", "Your block list", "names and addresses you never want reached", claims=(lockdown.BLOCKED_ID,)),
    Capability("public-lists", "Public block lists", "ads, trackers and malware from the lists you chose",
               claims=(listed.LISTED_ID,)),
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


def detect(tool_name: str, args: Any, current: ShieldMode) -> list[Finding]:
    """Lockdown and the block list, then the public lists the person chose."""
    return lockdown.detect(tool_name, args, current) + listed.detect(tool_name, args, current)


def report() -> list[ShieldEvent]:
    """Every event: the guard's refusals and what the helper and the watch saw, newest first."""
    return sorted(events.report() + watch_events.report(), key=lambda event: -event.ts)[:events.MAX_EVENTS]


def _use_data(packs: tuple[Pack, ...], _roots: Any) -> None:
    mode.use_packs(packs)   # the public block lists (lists/), validated by blocklists


NETWORK = Shield(
    id=mode.SHIELD_ID, name="Network Shield",
    tagline="See and stop the malicious ones — for every app on this machine and every AI agent.",
    beta=True, mode=_current_mode, validate=mode.validate, detect=detect,
    claims=claims, allows=allows, status=status.build, events=report, settings_fields=mode.fields,
    finding_kinds=FINDING_KINDS, capabilities=CAPABILITIES, packs=HERE / "lists", detectors=(blocklists,),
    page=HERE / "page" / "network.html", attacks=HERE / "attacks.json", use_data=_use_data, api=api.API,
    # Adding to these turns protection down: names never blocked, hosts agents may reach, who may SSH in.
    allow_lists=frozenset({mode.OPT_ALLOW, mode.OPT_AGENT_HOSTS, mode.OPT_SSH_ALLOW}),
    alerts=notices.shield_alerts,
)
