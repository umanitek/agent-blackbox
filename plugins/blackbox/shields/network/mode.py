"""Network Shield's setting: on or off, which protections, which public lists, and the lists the
operator keeps (allow, block, and the hosts an AI agent may reach under lockdown).

Founder direction (Amos, 2026-11-20): Network Shield is the second shield, switched on in the
app like Trader Shield. Off (the default) it watches nothing and blocks nothing.

What runs where (Amos, 2026-11-21): agent network lockdown and the block list run in Blackbox's
own guard, so they work with this plugin alone. DNS Shield, the Threat Firewall, cutting
connections, SSH lockdown and the watching need Blackbox Desktop, which installs the native
helper with the system access they take; its add-on unlocks them (:func:`needs_desktop`). The
setting is ONE shape either way, so switching to Desktop keeps every choice.

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
from typing import Any, Iterable, Mapping, Optional

from ...kernel import threat_ids
from .. import extensions
from ..contract import Pack, SettingField, SettingOption, ShieldMode

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
#: Blackbox Desktop's links — the ONE place they are kept. PLACEHOLDERS until Desktop has a
#: public release page (2026-11-21): change these and nothing else when it does.
#: ``DESKTOP_URL`` — its page; ``DESKTOP_DOWNLOADS`` — per OS, "" while not out yet;
#: ``DESKTOP_OPEN_URL`` — the app's own URL scheme, registered by the app (opens it).
DESKTOP_URL = "https://blackboxcommand.com/desktop"
DESKTOP_DOWNLOADS = {"macos": "https://blackboxcommand.com/desktop/download/macos", "windows": "", "linux": ""}
DESKTOP_OPEN_URL = "blackbox-desktop://open"
#: The add-on package Blackbox Desktop installs beside the plugin (its presence = Desktop is here).
DESKTOP_ADDON = "blackbox_desktop"
#: The option status Settings shows for a protection that needs Blackbox Desktop.
NEEDS_DESKTOP = "needs-desktop"


def needs_desktop(protection: str) -> bool:
    """True for a protection that runs only with Blackbox Desktop's add-on, while it is absent."""
    return protection not in IN_GUARD and protection not in extensions.unlocked(SHIELD_ID)


def default_protections() -> tuple[str, ...]:
    """What a first switch-on runs: DNS Shield where Blackbox Desktop can run it, else agent
    lockdown — the part that works without Desktop (the shield is never on doing nothing)."""
    return (DNS,) if not needs_desktop(DNS) else (LOCKDOWN,)
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


def _choices(raw: Any, allowed: Iterable[str]) -> Optional[tuple[str, ...]]:
    """*raw* as allowed ids in order, deduplicated; None when it is not such a list."""
    allowed = tuple(allowed)
    if not isinstance(raw, list) or len(raw) > len(allowed):
        return None
    chosen = [str(item or "").strip().lower() for item in raw]
    if any(item not in allowed for item in chosen):
        return None
    return tuple(dict.fromkeys(chosen))


def _entries(raw: Any, key: str) -> Optional[tuple[str, ...]]:
    """*raw* as normalised domains / IPs, deduplicated; None when anything in it is invalid."""
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES[key]:
        return None
    entries = [normalise_entry(item) for item in raw]
    if any(entry is None for entry in entries):
        return None
    return tuple(dict.fromkeys(entry for entry in entries if entry))


def _sources(raw: Any) -> Optional[tuple[str, ...]]:
    """*raw* as normalised addresses / networks, deduplicated; None when anything is invalid."""
    if not isinstance(raw, list) or len(raw) > MAX_SSH_ALLOW:
        return None
    sources = [normalise_source(item) for item in raw]
    if any(source is None for source in sources):
        return None
    return tuple(dict.fromkeys(source for source in sources if source))


def from_entry(entry: Mapping[str, Any]) -> ShieldMode:
    """The mode as the ``blackbox`` config entry states it (defaults when absent or invalid)."""
    shields = entry.get("shields")
    section = shields.get(SHIELD_ID) if isinstance(shields, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    return build(
        enabled=section.get("enabled") is True,
        protections=_choices(section.get(OPT_PROTECTIONS), PROTECTIONS) if OPT_PROTECTIONS in section else None,
        lists=_choices(section.get(OPT_LISTS), supported_lists()) or (),
        allow=_entries(section.get(OPT_ALLOW), OPT_ALLOW) or (),
        block=_entries(section.get(OPT_BLOCK), OPT_BLOCK) or (),
        agent_hosts=_entries(section.get(OPT_AGENT_HOSTS), OPT_AGENT_HOSTS) if OPT_AGENT_HOSTS in section else None,
        ssh_allow=_sources(section.get(OPT_SSH_ALLOW)) or (),
    )


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
               "guard. With Blackbox Desktop it also refuses the verified threat graph's malicious domains and "
               "addresses for every app, cuts malicious connections, locks SSH and shows what everything talks "
               "to. Off stops all of it.")


def fields() -> list[SettingField]:
    """What Settings draws for Network Shield: the engage switch first, as every shield."""
    return [
        SettingField("enabled", "toggle", "Engage Network Shield", ENGAGE_HELP),
        SettingField(OPT_PROTECTIONS, "multi-pick", "Protections",
                     "Agent lockdown keeps AI agents to the hosts you allow. DNS Shield, the Threat Firewall, "
                     "cutting connections and SSH lockdown run in Blackbox Desktop.",
                     options=tuple(SettingOption(p, PROTECTION_NAMES[p], NEEDS_DESKTOP if needs_desktop(p) else "supported")
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
