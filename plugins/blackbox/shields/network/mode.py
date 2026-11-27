"""Network Shield's setting: on or off, which protections, which public lists, and the lists the
operator keeps (allow, block, and the hosts an AI agent may reach under lockdown).

Founder direction (Amos, 2026-11-20): Network Shield is the second shield, switched on in the
app like Trader Shield. Off (the default) it watches nothing and blocks nothing.

What runs where (Amos, 2026-11-21): agent network lockdown and the block list run in Blackbox's
own guard, so they always work. DNS Shield, the Threat Firewall, cutting connections and SSH
lockdown are decided here too, and applied by the system protection helper (:mod:`.helper`) — a
small root daemon Blackbox's installer offers (or a companion app installs); without it they say
so (:func:`needs_helper`). An add-on may add richer views on top. The setting is ONE shape
either way, so installing the helper keeps every choice.

Config, under ``plugins.entries.blackbox``::

    shields:
      network-shield:
        enabled: true
        protections: [dns, firewall, lockdown]   # which protections run (default: [dns])
        lists: [hagezi-multi]                    # public block lists (packs) to add to DNS
        allow: [example.com, 203.0.113.4]        # never blocked by Network Shield
        block: [tracker.example]                 # always refused by DNS (and agent lockdown)
        agent_hosts: [github.com, pypi.org]      # under lockdown, what an AI agent may reach
        ssh_allow: [192.168.1.0/24]              # under SSH lockdown, who may SSH in

The protections:

* ``dns`` — DNS Shield: the enforcer answers every lookup and refuses the verified graph's
  malicious domains (always), the chosen public lists and the block list;
* ``firewall`` — Threat Firewall: the enforcer drops traffic to and from the verified graph's
  malicious IP addresses, system-wide;
* ``lockdown`` — agent network lockdown: an AI agent's tool call that would reach a host not on
  ``agent_hosts`` (or on ``block``) is a finding — refused in Block mode, by Blackbox's own guard;
* ``cut`` — cut malicious connections: a connection this machine already has open to one of the
  verified graph's malicious IP addresses is cut by the enforcer, and the address stays blocked
  while this is on (the Threat Firewall stops new ones; this ends the ones already open);
* ``ssh-lockdown`` — SSH lockdown: the enforcer refuses SSH into this machine except from the
  addresses and networks on ``ssh_allow`` (and from this machine itself). An empty list means
  nobody may SSH in.

While the shield is on, the enforcer also watches SSH (new and ended sessions into this
machine, whether Remote Login is on) and the files that decide who may log in or where names go
(``authorized_keys``, ``known_hosts``, ``~/.ssh/config``, ``/etc/hosts``, ``sshd_config``), and
reports each change at once — never a file's contents (:mod:`.watch`).

The mode is the shields contract's :class:`~..contract.ShieldMode` (options as tuples).

Usage::

    mode = current()
    protections(mode)          # ("dns", "lockdown")
    agent_hosts(mode)          # ("github.com", ...)
"""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import Any, Iterable, Mapping, Optional

from ...kernel import threat_ids
from .. import extensions
from ..contract import Pack, SettingField, SettingOption, ShieldMode
from ..setting_lists import EntryReader, kept, strict

SHIELD_ID = "network-shield"
DNS, FIREWALL, LOCKDOWN, CUT, SSH_LOCKDOWN = "dns", "firewall", "lockdown", "cut", "ssh-lockdown"
PROTECTIONS = (DNS, FIREWALL, LOCKDOWN, CUT, SSH_LOCKDOWN)
PROTECTION_NAMES = {DNS: "DNS Shield", FIREWALL: "Threat Firewall", LOCKDOWN: "Agent network lockdown",
                    CUT: "Cut malicious connections", SSH_LOCKDOWN: "SSH lockdown"}
#: The option keys.
OPT_PROTECTIONS, OPT_LISTS, OPT_ALLOW, OPT_BLOCK, OPT_AGENT_HOSTS = "protections", "lists", "allow", "block", "agent_hosts"
OPT_SSH_ALLOW = "ssh_allow"
#: Most sources ``ssh_allow`` may hold.
MAX_SSH_ALLOW = 100
#: The pattern Settings checks each ``ssh_allow`` line against (an IP address or a network).
SOURCE_PATTERN = r"^[0-9A-Fa-f.:]{2,45}(/[0-9]{1,3})?$"
#: The protections that run in Blackbox's own guard — with this plugin alone.
IN_GUARD = (LOCKDOWN,)
#: The option status Settings shows for a protection that needs the system protection helper.
NEEDS_HELPER = "needs-helper"


def needs_helper(protection: str) -> bool:
    """True for a protection the system protection helper applies, while it is not installed (an
    extension may also unlock one — :func:`..extensions.unlocked`)."""
    from . import helper   # lazy: mode is imported by everything in the shield
    return (protection not in IN_GUARD and protection not in extensions.unlocked(SHIELD_ID)
            and not helper.installed())


def default_protections() -> tuple[str, ...]:
    """What a first switch-on runs: DNS Shield where the helper can apply it, else agent lockdown
    — the part that needs nothing more (the shield is never on doing nothing)."""
    return (DNS,) if not needs_helper(DNS) else (LOCKDOWN,)
#: Most entries each list the operator keeps may hold.
MAX_ENTRIES = {OPT_ALLOW: 500, OPT_BLOCK: 500, OPT_AGENT_HOSTS: 200}
#: What an AI agent may reach under lockdown until the operator edits the list: the code hosts,
#: package registries and model APIs a coding agent needs (each one with all its subdomains).
DEFAULT_AGENT_HOSTS = (
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "npmjs.org", "npmjs.com", "yarnpkg.com", "pypi.org", "pythonhosted.org", "crates.io", "rubygems.org",
    "golang.org", "proxy.golang.org", "anthropic.com", "openai.com", "googleapis.com", "openrouter.ai",
)
#: The pattern Settings checks each typed line against (the validator is still the authority).
ENTRY_PATTERN = r"^[A-Za-z0-9._:-]{2,253}$"

#: The public block lists (packs), handed in once by the shield (:func:`use_packs`).
_packs: tuple[Pack, ...] = ()


def use_packs(packs: Iterable[Pack]) -> None:
    """Set the list packs the mode chooses from (the shield calls this once, at import)."""
    global _packs
    _packs = tuple(packs)


def list_packs() -> tuple[Pack, ...]:
    """Every list pack in display order."""
    return _packs


def supported_lists() -> dict[str, str]:
    """The public lists that can be chosen now: pack id -> display name."""
    return {pack.id: pack.name for pack in _packs if pack.status == "supported"}


def normalise_entry(value: Any) -> Optional[str]:
    """A domain (lower case, IDNA) or an IP address in canonical form; None for anything else."""
    text = str(value or "").strip().lower().rstrip(".")
    if not text or len(text) > 253:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    domain = threat_ids.normalize_ioc_value("domain", text)
    labels = domain.split(".")
    if domain.replace(".", "").isdigit():
        return None   # WHY: all digits yet no address (999.1.1.1): no name, and no firewall entry either
    if len(labels) < 2 or not all(label and len(label) <= 63 and all(c.isalnum() or c in "-_" for c in label)
                                  for label in labels):
        return None
    return domain


def normalise_source(value: Any) -> Optional[str]:
    """An IP address or network (``192.168.1.0/24``) in canonical form; None for anything else.
    A bare address is kept as an address; host bits of a network are cleared."""
    text = str(value or "").strip()
    if not text or len(text) > 49:
        return None
    try:
        return str(ipaddress.ip_address(text)) if "/" not in text else str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def build(enabled: bool = False, protections: Optional[tuple[str, ...]] = None, lists: tuple[str, ...] = (),
          allow: tuple[str, ...] = (), block: tuple[str, ...] = (),
          agent_hosts: Optional[tuple[str, ...]] = None, ssh_allow: tuple[str, ...] = ()) -> ShieldMode:
    """Network Shield's mode (None: the defaults)."""
    return ShieldMode(enabled=enabled, options={
        OPT_PROTECTIONS: default_protections() if protections is None else protections,
        OPT_LISTS: lists, OPT_ALLOW: allow, OPT_BLOCK: block,
        OPT_AGENT_HOSTS: DEFAULT_AGENT_HOSTS if agent_hosts is None else agent_hosts,
        OPT_SSH_ALLOW: ssh_allow,
    })


def protections(mode: ShieldMode) -> tuple[str, ...]:
    """The protections *mode* runs (empty while the shield is off)."""
    return tuple(mode.options.get(OPT_PROTECTIONS, ())) if mode.enabled else ()


def option(mode: ShieldMode, key: str) -> tuple[str, ...]:
    """One list option of *mode* (``lists``, ``allow``, ``block``, ``agent_hosts``, ``ssh_allow``)."""
    return tuple(mode.options.get(key, ()))


def agent_hosts(mode: ShieldMode) -> tuple[str, ...]:
    return option(mode, OPT_AGENT_HOSTS)


def _choice_reader(allowed: Iterable[str]) -> EntryReader:
    allowed = frozenset(allowed)

    def read(item: Any) -> Optional[str]:
        chosen = str(item or "").strip().lower()
        return chosen if chosen in allowed else None
    return read


def _choices(raw: Any, allowed: Iterable[str]) -> Optional[tuple[str, ...]]:
    """*raw* as allowed ids in order, deduplicated; None when it is not such a list."""
    allowed = tuple(allowed)
    return strict(raw, _choice_reader(allowed), len(allowed))


def _entries(raw: Any, key: str) -> Optional[tuple[str, ...]]:
    """*raw* as normalised domains / IPs, deduplicated; None when anything in it is invalid."""
    return strict(raw, normalise_entry, MAX_ENTRIES[key])


def _sources(raw: Any) -> Optional[tuple[str, ...]]:
    """*raw* as normalised addresses / networks, deduplicated; None when anything is invalid."""
    return strict(raw, normalise_source, MAX_SSH_ALLOW)


def from_entry(entry: Mapping[str, Any]) -> ShieldMode:
    """The mode as the ``blackbox`` config entry states it (defaults when absent), each stored list
    read entry by entry (``setting_lists.kept``): a bad entry is dropped alone and named in the
    mode's ``problems``, every good one stays in force (a duplicate is folded, never a reason to
    drop the list)."""
    shields = entry.get("shields")
    section = shields.get(SHIELD_ID) if isinstance(shields, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    problems: list[str] = []

    def read(key: str, reader: EntryReader, limit: int) -> Optional[tuple[str, ...]]:
        if section.get(key) is None:
            return None
        found = kept(section[key], reader, limit, f"shields.{SHIELD_ID}.{key}")
        problems.extend(found.problems)
        return found.values
    lists = tuple(supported_lists())
    mode = build(
        enabled=section.get("enabled") is True,
        protections=read(OPT_PROTECTIONS, _choice_reader(PROTECTIONS), len(PROTECTIONS)),
        lists=read(OPT_LISTS, _choice_reader(lists), max(len(lists), 1)) or (),
        allow=read(OPT_ALLOW, normalise_entry, MAX_ENTRIES[OPT_ALLOW]) or (),
        block=read(OPT_BLOCK, normalise_entry, MAX_ENTRIES[OPT_BLOCK]) or (),
        agent_hosts=read(OPT_AGENT_HOSTS, normalise_entry, MAX_ENTRIES[OPT_AGENT_HOSTS]),
        ssh_allow=read(OPT_SSH_ALLOW, normalise_source, MAX_SSH_ALLOW) or (),
    )
    return replace(mode, problems=tuple(problems)) if problems else mode


def current() -> ShieldMode:
    """The mode in force now, read from the Hermes config like every other setting."""
    from ...kernel.config import shield_entry   # plugins.entries.blackbox, once per shields snapshot
    return from_entry(shield_entry())


def validate(payload: Mapping[str, Any]) -> tuple[str, dict[str, Any], list[str]]:
    """``("network", section, errors)`` for ``payload["shields"]["network"]``.

    Anything invalid is refused with a sentence and nothing is stored. A section that changes
    anything is written COMPLETE (fields the payload leaves out keep their current value).
    """
    shields = payload.get("shields")
    raw = shields.get(SHIELD_ID) if isinstance(shields, Mapping) else None
    if raw is None or raw == {}:
        return SHIELD_ID, {}, []
    if not isinstance(raw, Mapping):
        return SHIELD_ID, {}, ["shields.network-shield must be an object"]
    updates: dict[str, Any] = {}
    errors: list[str] = []
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            updates["enabled"] = raw["enabled"]
        else:
            errors.append("shields.network-shield.enabled must be true or false")
    for key, allowed in ((OPT_PROTECTIONS, PROTECTIONS), (OPT_LISTS, tuple(supported_lists()))):
        if key in raw:
            chosen = _choices(raw[key], allowed)
            if chosen is None:
                errors.append(f"shields.network-shield.{key} must be a list of: {', '.join(allowed) or '(none available)'}")
            else:
                updates[key] = list(chosen)
    for key, cap in MAX_ENTRIES.items():
        if key in raw:
            entries = _entries(raw[key], key)
            if entries is None:
                errors.append(f"shields.network-shield.{key} must be a list of up to {cap} domains or IP addresses")
            else:
                updates[key] = list(entries)
    if OPT_SSH_ALLOW in raw:
        sources = _sources(raw[OPT_SSH_ALLOW])
        if sources is None:
            errors.append(f"shields.network-shield.{OPT_SSH_ALLOW} must be a list of up to {MAX_SSH_ALLOW} "
                          "IP addresses or networks (like 192.168.1.0/24)")
        else:
            updates[OPT_SSH_ALLOW] = list(sources)
    if errors or not updates:
        return SHIELD_ID, {}, errors
    now = current()
    section = {"enabled": now.enabled, **{key: list(option(now, key)) for key in now.options}, **updates}
    return SHIELD_ID, section, []


#: The engage switch's help, as Trader Shield's (Settings draws a shield's first field as its switch;
#: every other field is greyed out while it is off).
ENGAGE_HELP = ("Keep AI agents to the hosts you allow and away from the ones you block, in Blackbox's own "
               "guard. With the system protection helper it also refuses the verified threat graph's malicious "
               "domains and addresses for every app, cuts malicious connections and locks SSH. Off stops all of it.")


def fields() -> list[SettingField]:
    """What Settings draws for Network Shield: the engage switch first, as every shield."""
    return [
        SettingField("enabled", "toggle", "Engage Network Shield", ENGAGE_HELP),
        SettingField(OPT_PROTECTIONS, "multi-pick", "Protections",
                     "Agent lockdown keeps AI agents to the hosts you allow. DNS Shield, the Threat Firewall, "
                     "cutting connections and SSH lockdown need the system protection helper.",
                     options=tuple(SettingOption(p, PROTECTION_NAMES[p], NEEDS_HELPER if needs_helper(p) else "supported")
                                   for p in PROTECTIONS)),
        SettingField(OPT_LISTS, "multi-pick", "Also block (public lists)",
                     "Ads, trackers and malware from public lists, on top of the verified threat graph.",
                     options=tuple(SettingOption(pack.id, pack.name, pack.status) for pack in _packs)),
        SettingField(OPT_ALLOW, "lines", "Always allow", "One domain or IP address per line.", pattern=ENTRY_PATTERN),
        SettingField(OPT_BLOCK, "lines", "Always block", "One domain or IP address per line.", pattern=ENTRY_PATTERN),
        SettingField(OPT_AGENT_HOSTS, "lines", "Hosts AI agents may reach under lockdown",
                     "One per line; each includes its subdomains.", pattern=ENTRY_PATTERN),
        SettingField(OPT_SSH_ALLOW, "lines", "Who may SSH in under SSH lockdown",
                     "One IP address or network (like 192.168.1.0/24) per line. Everyone else is refused; "
                     "an empty list means nobody may SSH in.", pattern=SOURCE_PATTERN),
    ]
