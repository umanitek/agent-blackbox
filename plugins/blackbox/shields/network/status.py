"""Network Shield's dashboard card: each protection, and where it runs.

Agent network lockdown runs inside Blackbox's own guard, so it is active whenever it is on.
DNS Shield, the Threat Firewall, cutting connections and SSH lockdown need Blackbox Desktop: while
its add-on is absent the card says so plainly and offers it (never "active" on the setting
alone). With the add-on installed, the add-on decorates this card with its helper's real state
(``ShieldExtension.status``).
"""

from __future__ import annotations

from ...kernel.config import load_blackbox_config
from .. import extensions
from ..contract import OfferDownload, ShieldMode, ShieldOffer, ShieldStatus, StatusRow, StatusSection
from . import mode as mode_module

#: What Blackbox Desktop adds, as the offer dialog lists it.
DESKTOP_ADDS = (
    "DNS Shield — malicious domains refused for every app",
    "Threat Firewall — traffic to malicious addresses dropped, open connections cut",
    "Live traffic map and every process explained by Blackbox's assistant",
    "SSH watch and SSH lockdown, with instant alerts",
    "File Shield — your downloads fingerprinted and checked",
    "Protection for Claude Code, Codex, Cursor and other coding agents",
)
_OS_LABELS = {"macos": "Download for macOS", "windows": "Windows", "linux": "Linux"}


def desktop_installed() -> bool:
    """True while Blackbox Desktop's add-on is registered through the extension point."""
    return mode_module.DESKTOP_ADDON in extensions.providers()


def offer() -> ShieldOffer:
    """The card's offer: "open" Blackbox Desktop when its add-on is here, else "get" it."""
    if desktop_installed():
        return ShieldOffer(kind="open", title="Open Blackbox Desktop",
                           text="Blackbox Desktop runs the rest of Network Shield on this machine.",
                           open_url=mode_module.DESKTOP_OPEN_URL)
    downloads = tuple(OfferDownload(os=name, label=_OS_LABELS[name], url=url, available=bool(url))
                      for name, url in mode_module.DESKTOP_DOWNLOADS.items())
    return ShieldOffer(kind="get", title="Network Shield runs in Blackbox Desktop",
                       text="Agent network lockdown is on now. The rest of Network Shield needs Blackbox Desktop, "
                            "which installs a small helper with the system access it takes:",
                       items=DESKTOP_ADDS, downloads=downloads)

#: What each protection does, for its row.
WHAT = {
    mode_module.DNS: "Refuses the verified threat graph's malicious domains for every app.",
    mode_module.FIREWALL: "Drops traffic to and from the verified threat graph's malicious IP addresses.",
    mode_module.CUT: "Ends connections already open to listed addresses.",
    mode_module.SSH_LOCKDOWN: "Only the addresses or networks you allow may SSH in.",
}


def _row(protection: str, mode: ShieldMode) -> StatusRow:
    name = mode_module.PROTECTION_NAMES[protection]
    on = protection in mode_module.protections(mode)
    if protection == mode_module.LOCKDOWN:
        if not on:
            return StatusRow(icon="○", state="off", text=f"{name} is off", sub="AI agents may reach any host.")
        return StatusRow(icon="●", state="active", text=f"{name} is active",
                         sub=f"AI agents may reach {len(mode_module.agent_hosts(mode))} hosts you allow, and this machine.")
    if mode_module.needs_desktop(protection):
        return StatusRow(icon="↓", state=mode_module.NEEDS_DESKTOP, text=f"{name} runs in Blackbox Desktop",
                         sub=f"{WHAT[protection]} Get Blackbox Desktop: {mode_module.DESKTOP_URL}")
    return StatusRow(icon="○" if not on else "●", state="off" if not on else "active",
                     text=f"{name} is {'on' if on else 'off'}", sub=WHAT[protection])


def build(mode: ShieldMode) -> ShieldStatus:
    """The card for *mode*."""
    rows = tuple(_row(protection, mode) for protection in mode_module.PROTECTIONS)
    return ShieldStatus(shield_id=mode_module.SHIELD_ID, mode=mode, blocking=load_blackbox_config().mode == "block",
                        sections=(StatusSection("Protections", "What Network Shield runs on this machine.", rows),),
                        offer=offer())
