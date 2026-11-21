"""Network Shield's dashboard card: each protection, where it runs, and whether it is working.

Agent network lockdown runs inside Blackbox's own guard, so it is active whenever it is on.
DNS Shield, the Threat Firewall, cutting connections and SSH lockdown are applied by the system
protection helper (:mod:`.helper`): without it a row says so plainly; with it, a switched-on
protection is shown active ONLY while the helper reports it active (its report is fresh,
:data:`.protect.enforcement.STALE_AFTER_SECONDS`) — never on the setting alone.

The card also offers Blackbox Desktop — the richer views on top of this shield ("get" it, or
"open" it once its add-on is here). An add-on may still decorate the card
(``ShieldExtension.status``).
"""

from __future__ import annotations

from typing import Any, Mapping

from ...kernel.config import load_blackbox_config
from .. import extensions
from ..contract import OfferDownload, ShieldMode, ShieldOffer, ShieldStatus, StatusRow, StatusSection
from . import helper, helper_link, mode as mode_module
from .protect import enforcement

#: What Blackbox Desktop adds on top of this shield, as the offer dialog lists it.
DESKTOP_ADDS = (
    "A live traffic map: every app and AI agent, and who it talks to",
    "Every process explained: who signed it and what it does",
    "Who is in this Mac right now — SSH, Screen Sharing and remote-control apps — live",
    "Exposure, startup items and a posture check with one-click fixes",
    "File Shield — your downloads fingerprinted and checked",
    "Mac notifications, the connection history and a security review",
)
_OS_LABELS = {"macos": "Download for macOS", "windows": "Windows", "linux": "Linux"}
#: How a person installs the helper without Blackbox Desktop.
HELPER_HOW = "Install it with Blackbox's installer (system protection), or from Blackbox Desktop."


def desktop_installed() -> bool:
    """True while Blackbox Desktop's add-on is registered through the extension point."""
    return mode_module.DESKTOP_ADDON in extensions.providers()


def offer() -> ShieldOffer:
    """The card's offer: "open" Blackbox Desktop when its add-on is here, else "get" it."""
    if desktop_installed():
        return ShieldOffer(kind="open", title="Open Blackbox Desktop",
                           text="Blackbox Desktop shows everything Network Shield sees on this machine.",
                           open_url=mode_module.DESKTOP_OPEN_URL)
    downloads = tuple(OfferDownload(os=name, label=_OS_LABELS[name], url=url, available=bool(url))
                      for name, url in mode_module.DESKTOP_DOWNLOADS.items())
    return ShieldOffer(kind="get", title="See everything with Blackbox Desktop",
                       text="Network Shield protects this machine from here. Blackbox Desktop adds the live views:",
                       items=DESKTOP_ADDS, downloads=downloads)

#: What each protection does, for its row.
WHAT = {
    mode_module.DNS: "Refuses the verified threat graph's malicious domains (and the lists you chose) for every app.",
    mode_module.FIREWALL: "Drops traffic to and from the verified threat graph's malicious IP addresses.",
    mode_module.CUT: "Ends connections already open to listed addresses.",
    mode_module.SSH_LOCKDOWN: "Only the addresses or networks you allow may SSH in.",
}
#: The helper's report key that says each protection is applied.
ACTIVE_KEY = {mode_module.DNS: "dns_active", mode_module.FIREWALL: "firewall_active",
              mode_module.CUT: "cut_active", mode_module.SSH_LOCKDOWN: "ssh_lockdown_active"}


def _row(protection: str, mode: ShieldMode, applied: Mapping[str, Any]) -> StatusRow:
    name = mode_module.PROTECTION_NAMES[protection]
    on = protection in mode_module.protections(mode)
    if protection == mode_module.LOCKDOWN:
        if not on:
            return StatusRow(icon="○", state="off", text=f"{name} is off", sub="AI agents may reach any host.")
        return StatusRow(icon="●", state="active", text=f"{name} is active",
                         sub=f"AI agents may reach {len(mode_module.agent_hosts(mode))} hosts you allow, and this machine.")
    if mode_module.needs_helper(protection):
        return StatusRow(icon="↓", state=mode_module.NEEDS_HELPER, text=f"{name} needs the system protection helper",
                         sub=f"{WHAT[protection]} {HELPER_HOW}")
    if not on:
        return StatusRow(icon="○", state="off", text=f"{name} is off", sub=WHAT[protection])
    if not applied.get(ACTIVE_KEY[protection]):
        error = (applied.get("errors") or {}).get(protection.replace("-", "_"))
        if error:
            return StatusRow(icon="!", state="warn", text=f"{name} could not be applied", sub=f"The helper says: {error}")
        return StatusRow(icon="!", state="waiting", text=f"{name} is on, waiting for the system protection helper",
                         sub="The helper has not reported it applied yet. If this stays, start or repair the helper.")
    return StatusRow(icon="●", state="active", text=f"{name} is active", sub=WHAT[protection])


#: What to do when the helper and this Blackbox do not share a key (helper/PLAN.md).
PAIR_HOW = ("Reinstall it to pair them: run Blackbox's installer with --system-protection, or use "
            "Install the helper in Blackbox Desktop. macOS asks for your admin password once.")


def _helper_rows(applied: Mapping[str, Any]) -> tuple[StatusRow, ...]:
    """The helper's health beyond running: pairing, pf, its resolver, its last error."""
    rows = []
    if applied.get("auth") == "legacy":
        rows.append(StatusRow(icon="!", state="warn", text="System protection helper is an older version",
                              sub="It accepts plans without a signature. " + PAIR_HOW))
    if applied.get("pf_enabled") is False:
        rows.append(StatusRow(icon="!", state="warn", text="The macOS packet filter is off",
                              sub="The Threat Firewall, cutting and SSH lockdown cannot work until the helper turns it back on."))
    if applied.get("resolver_ok") is False:
        rows.append(StatusRow(icon="!", state="warn", text="DNS Shield's resolver is not answering",
                              sub="The helper keeps your previous DNS servers until it answers again."))
    if applied.get("last_error"):
        rows.append(StatusRow(icon="!", state="warn", text="The helper reported a problem", sub=str(applied["last_error"])))
    return tuple(rows)


def _helper_section(applied: Mapping[str, Any]) -> StatusSection:
    pairing = helper_link.pairing()
    if not helper.installed():
        row = StatusRow(icon="↓", state=mode_module.NEEDS_HELPER, text="System protection helper not installed",
                        sub=HELPER_HOW)
    elif pairing != helper_link.PAIRED and applied.get("auth") != "legacy":
        # A keyed helper refuses every plan this Blackbox cannot sign: say so, with the fix.
        text = ("System protection helper not paired" if pairing == helper_link.NOT_PAIRED
                else "System protection helper's key file is damaged")
        row = StatusRow(icon="!", state="warn", text=text, sub=PAIR_HOW)
    elif applied.get("running"):
        row = StatusRow(icon="●", state="active", text="System protection helper running",
                        sub=f"{applied.get('blocked_total', 0):,} lookups refused · {applied.get('firewall_dropped', 0):,} "
                            f"packets dropped · {applied.get('cut_total', 0):,} connections cut")
    else:
        row = StatusRow(icon="!", state="waiting", text="System protection helper installed but not reporting",
                        sub="It may be starting. If this stays, repair it from the installer or Blackbox Desktop.")
    return StatusSection("System protection helper", "The small root helper that applies DNS Shield, the Threat "
                         "Firewall, cutting and SSH lockdown.", (row, *_helper_rows(applied)))


def build(mode: ShieldMode) -> ShieldStatus:
    """The card for *mode*."""
    applied = enforcement.summary()
    rows = tuple(_row(protection, mode, applied) for protection in mode_module.PROTECTIONS)
    return ShieldStatus(shield_id=mode_module.SHIELD_ID, mode=mode, blocking=load_blackbox_config().mode == "block",
                        sections=(StatusSection("Protections", "What Network Shield runs on this machine.", rows),
                                  _helper_section(applied)),
                        offer=offer())
