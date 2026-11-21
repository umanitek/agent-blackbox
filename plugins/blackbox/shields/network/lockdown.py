"""Agent network lockdown and the block list, inside Blackbox's own guard.

Every AI-agent tool call already passes through ``shields.check``. This detector finds the hosts
a call would reach — with detection's own extractor (``iter_ioc_candidates`` over the call's
text: URLs and their hosts, bare domains, IPv4s), never a second parser — and reports:

* ``network:blocked-host`` — a host on the operator's block list (while the shield is on);
* ``network:agent-lockdown`` — under lockdown, a host not on ``agent_hosts`` / ``allow``
  (each entry covers its subdomains). Loopback and private addresses are always allowed: an
  agent working on this machine or the local network is not leaving it.

All are ``critical`` local findings (category ``network``) (``shields.check`` makes every shield finding local-only),
so Block mode refuses the call and the agent is told which host and why. Fails open: an
unreadable call yields nothing.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from ...detection import Finding, injection_scan_text, iter_ioc_candidates
from ...kernel import public_suffix
from ..contract import FindingKind, ShieldMode
from . import mode as mode_module

LOCKDOWN_ID = "network:agent-lockdown"
BLOCKED_ID = "network:blocked-host"
#: Its own category: a policy knob of its own (``detection.network``), and the classification row
#: ``community/sighting/classification.py`` keys on it.
CATEGORY = "network"
#: Hosts one call may name before the rest are ignored (a call listing thousands is itself odd,
#: and the extractor caps its own output too).
MAX_HOSTS_PER_CALL = 64
#: The sighting layer's row: data leaving through the network (classification "over-broad-network").
FINDING_KINDS: tuple[FindingKind, ...] = (
    FindingKind("data-exfil", "host-system", "T1041", identifier=LOCKDOWN_ID),
    FindingKind("data-exfil", "host-system", "T1041", identifier=BLOCKED_ID),
)


def hosts_in(args: Any) -> list[str]:
    """The hosts *args* names (domains lower-case, IPs canonical), most specific first, one per
    destination (a parent the extractor also emits — ``attacker.com`` beside
    ``exfil.attacker.com`` — is dropped).

    A host from a URL and an IP address always count. A bare name counts only when it is a real
    host by shape (:func:`_bare_name_is_host`): the extractor also yields file names, and
    ``main.py`` or ``notes.md`` end in real country domains (Paraguay, Moldova).
    """
    url_hosts: list[str] = []
    bare: list[str] = []
    for identifier in iter_ioc_candidates(injection_scan_text(args)):
        kind, _, value = identifier.partition(":")[2].partition(":")
        if kind == "url":
            url_hosts.append(value.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].rsplit(":", 1)[0].strip("[]"))
        elif kind in ("domain", "ip"):
            bare.append(value)
    hosts: list[str] = []
    for raw, from_url in [(host, True) for host in url_hosts] + [(host, False) for host in bare]:
        host = mode_module.normalise_entry(raw) or ""
        if not host or host in hosts or not (from_url or host in url_hosts or _bare_name_is_host(host)):
            continue
        hosts.append(host)
        if len(hosts) >= MAX_HOSTS_PER_CALL:
            break
    return [host for host in hosts if not any(other != host and other.endswith("." + host) for other in hosts)]


#: Top-level domains that are also common file extensions: a bare two-label name ending in one
#: (``main.py``, ``run.sh``, ``README.md``) is a file, not a host. A URL host is never judged so.
FILE_LIKE_TLDS = frozenset({"py", "sh", "md", "rs", "pl", "pm", "cc", "zip", "mov", "so", "am", "sc", "ps", "rb",
                            "ts", "js", "cs", "fs", "go", "kt", "tf", "nu", "ml", "sql", "log", "env", "conf"})


def _bare_name_is_host(host: str) -> bool:
    """True for an IP address, or a name under a real top-level domain that is not file-shaped."""
    if host.replace(".", "").isdigit() or ":" in host:
        return True
    labels = host.split(".")
    tld = labels[-1]
    if tld not in public_suffix.load().rules:
        return False
    return not (len(labels) == 2 and tld in FILE_LIKE_TLDS)


def _covered(host: str, entries: Iterable[str]) -> bool:
    """True when *host* is an entry or a subdomain of one."""
    return any(host == entry or host.endswith("." + entry) for entry in entries)


def _local(host: str) -> bool:
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def detect(tool_name: str, args: Any, mode: ShieldMode) -> list[Finding]:
    """The block-list and lockdown findings for one tool call under *mode*."""
    if not mode.enabled:
        return []
    allowed = mode_module.option(mode, mode_module.OPT_ALLOW)
    blocked = mode_module.option(mode, mode_module.OPT_BLOCK)
    lockdown = mode_module.LOCKDOWN in mode_module.protections(mode)
    agent_hosts = mode_module.agent_hosts(mode) + allowed
    findings: list[Finding] = []
    for host in hosts_in(args):
        if _covered(host, allowed):
            continue
        if _covered(host, blocked):
            findings.append(finding(BLOCKED_ID, tool_name, host, "is on your Network Shield block list"))
        elif lockdown and not _local(host) and not _covered(host, agent_hosts):
            findings.append(finding(LOCKDOWN_ID, tool_name, host,
                                     "is not on the hosts AI agents may reach (agent network lockdown)"))
    return findings


def finding(identifier: str, tool_name: str, host: str, why: str) -> Finding:
    """One Network Shield finding about *host* (an add-on's detectors raise theirs the same way)."""
    return Finding(identifier=identifier, category=CATEGORY, severity="critical",
                   title=f"Network Shield: {host} {why}", tool_name=tool_name, matched=host,
                   evidence=host, source="custom", fields={"host": host})
