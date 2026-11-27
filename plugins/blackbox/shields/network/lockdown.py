"""Agent network lockdown and the block list, inside Blackbox's own guard.

Every AI-agent tool call already passes through ``shields.check``. This detector finds the hosts
a call would reach and reports them. Bare domains and IPv4s come from detection's own extractor
(``iter_ioc_candidates`` over the call's text). A URL's host is read as the program reaching it
reads it: ``urllib.parse.urlsplit(...).hostname`` (a bracketed IPv6 host whole), and every IPv4
spelling ``inet_aton`` / ``curl`` accept — one integer, hex, octal, short dotted forms
(:func:`numeric_ipv4`) — becomes the address it names, so the lists judge the canonical value
(LES-105). A URL whose host can not be read is a lockdown finding while lockdown is on (lockdown
fails closed). It reports:

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
import re
from typing import Any, Iterable, NamedTuple, Optional
from urllib.parse import urlsplit

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
#: Unreadable URL hosts one call reports (one already refuses the call under lockdown).
MAX_UNREADABLE_PER_CALL = 4
#: The sighting layer's row: data leaving through the network (classification "over-broad-network").
FINDING_KINDS: tuple[FindingKind, ...] = (
    FindingKind("data-exfil", "host-system", "T1041", identifier=LOCKDOWN_ID),
    FindingKind("data-exfil", "host-system", "T1041", identifier=BLOCKED_ID),
)


#: A URL's scheme and authority (what ``urlsplit`` needs to find the host); the path is not read.
_URL_AUTHORITY = re.compile(r"\b[a-z][a-z0-9+.-]{0,30}://[^\s/?#'\"<>`\\]+", re.IGNORECASE)
#: One part of an ``inet_aton`` address: hex, octal (a leading 0) or decimal.
_NUMERIC_PART = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$", re.IGNORECASE)
IPV4_PARTS = 4


class CallHosts(NamedTuple):
    """The hosts one call names (:func:`read_hosts`): *hosts* canonical, most specific first;
    *unreadable* the URL hosts that are no host Blackbox can judge (as written, at most a few)."""

    hosts: list[str]
    unreadable: list[str]


def _part_value(part: str) -> Optional[int]:
    if not _NUMERIC_PART.match(part):
        return None
    if part.lower().startswith("0x"):
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8) if all(digit in "01234567" for digit in part) else None
    return int(part)


def numeric_ipv4(name: str) -> Optional[str]:
    """The IPv4 address an ``inet_aton`` spelling names (``134744072``, ``0x08080808``,
    ``010.010.010.010``, ``8.8.2056`` -> ``8.8.8.8``), None for anything else. The last part fills
    the bytes the parts before it leave, as ``inet_aton`` reads it."""
    parts = name.split(".")
    if not 1 <= len(parts) <= IPV4_PARTS:
        return None
    values = [_part_value(part) for part in parts]
    if any(value is None for value in values):
        return None
    *leading, last = values
    tail_bytes = IPV4_PARTS - len(leading)
    if any(value > 0xFF for value in leading) or last >= 1 << (8 * tail_bytes):
        return None
    number = 0
    for value in leading:
        number = number << 8 | value
    return str(ipaddress.IPv4Address(number << (8 * tail_bytes) | last))


def _url_host(url: str) -> tuple[str, bool]:
    """``(host, readable)`` for one URL's authority; ``("", True)`` when it names no host."""
    try:
        name = urlsplit(url).hostname
    except ValueError:   # an unbalanced bracket, a bad port: no host Blackbox can judge
        return url.split("://", 1)[-1], False
    if not name:
        return "", True
    host = numeric_ipv4(name) or mode_module.normalise_entry(name)
    return (host, True) if host else (name, False)


def read_hosts(args: Any) -> CallHosts:
    """The hosts *args* names (domains lower-case, IPs canonical), most specific first, one per
    destination (a parent the extractor also emits — ``attacker.com`` beside
    ``exfil.attacker.com`` — is dropped), and the URL hosts that could not be read.

    A host from a URL and an IP address always count. A bare name counts only when it is a real
    host by shape (:func:`_bare_name_is_host`): the extractor also yields file names, and
    ``main.py`` or ``notes.md`` end in real country domains (Paraguay, Moldova).
    """
    text = injection_scan_text(args)
    url_hosts: list[str] = []
    unreadable: list[str] = []
    for match in _URL_AUTHORITY.finditer(text):
        host, readable = _url_host(match.group(0))
        if host:
            (url_hosts if readable else unreadable).append(host)
    bare = [value for kind, value in (identifier.partition(":")[2].partition(":")[::2]
                                      for identifier in iter_ioc_candidates(text)) if kind in ("domain", "ip")]
    hosts: list[str] = []
    for raw, from_url in [(host, True) for host in url_hosts] + [(host, False) for host in bare]:
        host = mode_module.normalise_entry(raw) or ""
        if not host or host in hosts or not (from_url or host in url_hosts or _bare_name_is_host(host)):
            continue
        hosts.append(host)
        if len(hosts) >= MAX_HOSTS_PER_CALL:
            break
    kept = [host for host in hosts if not any(other != host and other.endswith("." + host) for other in hosts)]
    return CallHosts(kept, unreadable[:MAX_UNREADABLE_PER_CALL])


def hosts_in(args: Any) -> list[str]:
    """The readable hosts *args* names (:func:`read_hosts`)."""
    return read_hosts(args).hosts


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
    named = read_hosts(args)
    if lockdown:
        findings += [finding(LOCKDOWN_ID, tool_name, host, "is no host Blackbox can read (agent network lockdown)")
                     for host in named.unreadable]
    for host in named.hosts:
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
