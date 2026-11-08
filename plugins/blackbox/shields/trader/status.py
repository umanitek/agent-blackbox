"""Trader Shield's dashboard card: what it found to protect on this machine, what it always
watches, and what needs the operator's attention — a :class:`~..contract.ShieldStatus`.

The card is built from the setting in force (*active*, read once by the registry's
snapshot), Blackbox's audit/block mode and the existing-stores scan the detectors already
keep (:data:`.detectors.EXISTING_STORES`: folder NAMES under the usual browser and
wallet-app places, reused for five minutes — nothing inside a store is ever opened).

Sections, in the panel's own words:

* **Found on this machine** — one row per wallet (not per browser profile), saying where
  its key store is and whether the gate counts a read of it;
* **Always watching** — seed phrases, private keys (with the COUNT of listed own
  addresses, never an address), exchange API keys, token approvals, protected files;
* **Needs attention** — health rows, only when there is one: a chosen pack that is not
  supported right now, and supported packs absent from an explicitly saved list
  (whether those switch on by themselves is an open product decision).

Text is clamped here with ``kernel.display_safety.log_safe`` (the operator's own folder
names); the dashboard sanitises every record once more where it serves them —
this module never imports the dashboard.

Usage::

    status.build(trader.mode(), trader.allows)    # TRADER.status
    status.found_wallets()   # -> [{"wallet": "MetaMask", "id": "metamask", "browser": "Chrome",
                             #      "profile": "default", "areas": ["vault"]}]
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from ...kernel import crypto_secrets
from ...kernel.config import load_blackbox_config
from ...kernel.display_safety import log_safe
from ..contract import ShieldMode, ShieldStatus, StatusRow, StatusSection
from ..packs import chosen_but_unavailable
from . import detectors, mode as trader_mode

logger = logging.getLogger(__name__)

#: The gate a found store is checked against (the shield's own ``allows``).
Gate = Callable[[Mapping[str, Any], ShieldMode], bool]

#: Which browser a key-store path belongs to, by a word in it (first match wins).
_BROWSERS = (("brave", "Brave"), ("edge", "Edge"), ("vivaldi", "Vivaldi"), ("opera", "Opera"), ("arc", "Arc"),
             ("chromium", "Chromium"), ("chrome", "Chrome"), ("firefox", "Firefox"), ("mozilla", "Firefox"))
#: Which storage area a key-store folder is (Chromium constants / Firefox storage), in plain words.
_AREAS = (("Local Extension Settings", "vault"), ("Sync Extension Settings", "synced copy"),
          ("IndexedDB", "backup copy"), ("moz-extension", "extension storage"))

#: The panel's marks: secured (blocked), watched only (audit mode), not protected, needs attention.
_SECURED, _WATCHED, _NOT_PROTECTED, _ATTENTION = ("✓", "ok"), ("~", "watch"), ("–", "none"), ("!", "warn")
#: How many protected file patterns the card names before it says " …".
_PATHS_SHOWN = 6
_MAX_PROTECTED_PATHS = 20

FOUND_HELP = ("Wallets whose key store (the encrypted vault holding your keys) exists here: in a browser "
              "profile, a desktop wallet's folder (Exodus, Electrum) or the Solana command line's key file. "
              "Blackbox only checks that the folder exists — it never opens or reads it.")


def _app_labels() -> dict[str, str]:
    """``{pack id: label}`` for the app-folder packs ("Desktop app", "Command line")."""
    return {pack.id: str(pack.data["label"]) for pack in trader_mode.wallet_packs()
            if pack.status == "supported" and isinstance(pack.data.get("label"), str)}


def browser_of(path: str) -> str:
    """The browser a key-store or profile path belongs to ("Chrome", "Brave"…), or "a browser"."""
    low = path.lower()
    return next((label for key, label in _BROWSERS if key in low), "a browser")


def found_wallets() -> list[dict[str, Any]]:
    """The wallets whose key stores exist on this machine, for the dashboard:
    ``[{wallet, id, browser, profile, areas: [...]}]`` (``id`` is the pack id, or
    ``any-extension`` for a Firefox store no pack can be named for). Built from the folder
    NAMES the archive check already found — no file is opened, nothing is read inside a store."""
    labels = _app_labels()
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path, wallet in detectors.EXISTING_STORES.get():
        low = path.lower()
        browser = labels.get(wallet.pack) or next((label for key, label in _BROWSERS if key in low), "Browser")
        area = ("key file" if low.endswith(".json") else "wallet folder") if wallet.pack in labels else \
            next((label for key, label in _AREAS if key.lower() in low), "storage")
        parts = path.split("/")
        anchor = next((i for i, part in enumerate(parts) if part in ("local extension settings", "sync extension settings",
                                                                    "indexeddb", "storage")), len(parts))   # paths are lower-cased
        profile = parts[anchor - 1] if anchor > 0 else ""
        entry = grouped.setdefault((wallet.wallet, browser, profile), {
            "wallet": wallet.wallet, "id": wallet.pack or trader_mode.ANY_EXTENSION_WALLET,
            "browser": browser, "profile": profile, "areas": []})
        if area not in entry["areas"]:
            entry["areas"].append(area)
    return list(grouped.values())


def guarded(allows: Gate, active: ShieldMode, wallet_id: str) -> bool:
    """Whether the gate counts a key-store finding for *wallet_id* under *active* (the gate's own rule)."""
    fields = {} if wallet_id == trader_mode.ANY_EXTENSION_WALLET else {"pack": wallet_id}
    return allows({"identifier": f"fileaccess:file{trader_mode.WALLET_FILE_SUFFIX}", "fields": fields}, active)


def _found_section(active: ShieldMode, allows: Gate, block: bool) -> StatusSection:
    """One row per WALLET (protected in every browser it is in), listing the browsers."""
    on = _SECURED if block else _WATCHED
    guard = "protected — blocked if the agent reaches for it" if block else "watched — flagged, not blocked (audit mode)"
    groups: dict[str, dict[str, Any]] = {}
    for found in found_wallets():
        group = groups.setdefault(found["id"], {"wallet": found["wallet"], "browsers": [], "areas": [], "profiles": 0})
        if found["browser"] not in group["browsers"]:
            group["browsers"].append(found["browser"])
        group["areas"].extend(area for area in found["areas"] if area not in group["areas"])
        group["profiles"] += 1
    rows = []
    for wallet_id, group in groups.items():
        protected = guarded(allows, active, wallet_id)
        if wallet_id == trader_mode.ANY_EXTENSION_WALLET:
            name, count = "Firefox wallets", group["profiles"]
            where = f"every extension's storage in {count} Firefox profile{'' if count == 1 else 's'}"
        else:
            name, where = group["wallet"], ", ".join(group["areas"])
        icon, state = on if protected else _NOT_PROTECTED
        rows.append(StatusRow(icon=icon, state=state,
                              text=log_safe(f"{name} · {', '.join(group['browsers'])}", 160),
                              sub=log_safe(f"{where} — " + (guard if protected else "not selected in Settings, so not protected"), 240),
                              logo=trader_mode.logo_url(wallet_id)))
    if not rows:
        rows.append(StatusRow(*_NOT_PROTECTED, text="No wallet found on this machine.",
                              sub="Blackbox checks the usual browser and wallet-app folders by name every few minutes; "
                                  "it never opens a vault."))
    return StatusSection(title="Found on this machine", help=FOUND_HELP, rows=tuple(rows))


def _watching_section(active: ShieldMode, block: bool, protected_paths: tuple[str, ...]) -> StatusSection:
    """What Trader Shield watches whatever is installed: seed phrases, keys, exchanges, approvals, files."""
    on = _SECURED if block else _WATCHED
    seed_checker = bool(crypto_secrets.wordlist_ready())
    own = len(trader_mode.addresses(active))   # the COUNT only: an address never leaves Settings
    exchanges = [entry.exchange for entry in crypto_secrets.exchange_keys.EXCHANGE_KEY_HEADERS][:10]
    paths = [log_safe(path, 120) for path in protected_paths[:_MAX_PROTECTED_PATHS]]
    rows = [
        StatusRow(*(on if seed_checker else _ATTENTION), text="Seed phrases",
                  sub="checker on — 2,048-word list, checksum verified" if seed_checker
                  else "checker OFF — the word list did not load"),
        StatusRow(*on, text="Private keys",
                  sub="labelled and Solana keys · blocked if sent · " +
                      (f"{own} own address{'' if own == 1 else 'es'} listed for raw keys" if own
                       else "list your addresses in Settings to catch raw keys")),
    ]
    if exchanges:
        rows.append(StatusRow(*on, text="Exchange API keys", sub=" · ".join(exchanges) + " — only to their own site"))
        rows.append(StatusRow(*on, text="Token approvals", sub="known drainer blocked · unlimited approvals flagged"))
    if not active.enabled:
        # Off, the shield's own checks do not run (2026-11-08: the card still ticked them while a
        # seed phrase went out unchecked); protected files are a built-in rule and stay on.
        rows = [StatusRow(*_NOT_PROTECTED, text=row.text, sub="off — engage Trader Shield to watch this") for row in rows]
    rows.append(StatusRow(*on, text="Protected files",
                          sub=" · ".join(paths[:_PATHS_SHOWN]) + (" …" if len(paths) > _PATHS_SHOWN else "") +
                              " · file tools and terminal"))   # FIX-0103: the terminal follows the same rule
    return StatusSection(title="Always watching", help="", rows=tuple(rows))


def _health_section(active: ShieldMode) -> StatusSection | None:
    """Health rows: chosen packs that are not supported now, and supported packs added since
    the operator last saved — never ones they were offered and left unticked."""
    packs = trader_mode.wallet_packs()
    chosen = trader_mode.wallets(active)
    lines = [log_safe(line, 240) for line in chosen_but_unavailable(packs, chosen)]
    added = set(trader_mode.newly_supported(active))
    unsaved = [pack.name for pack in packs if pack.id in added]
    if unsaved:
        lines.append(log_safe("new since you last saved: " + ", ".join(unsaved), 240))
    if not lines:
        return None
    return StatusSection(title="Needs attention", help="",
                         rows=tuple(StatusRow(*_ATTENTION, text=line) for line in lines))


def build(active: ShieldMode, allows: Gate) -> ShieldStatus:
    """Trader Shield's card under *active*; *allows* is the shield's own gate. Fail-open:
    a scan that cannot be read shows "No wallet found", never a broken card."""
    cfg = load_blackbox_config()
    block = bool(cfg.block_enabled)
    try:
        found = _found_section(active, allows, block)
    except Exception:   # a filesystem error means "none found", never a broken page
        logger.warning("blackbox: Trader Shield status: the wallet scan failed", exc_info=True)
        found = StatusSection(title="Found on this machine", help=FOUND_HELP,
                              rows=(StatusRow(*_NOT_PROTECTED, text="No wallet found on this machine."),))
    sections = [found, _watching_section(active, block, tuple(cfg.protected_paths or ()))]
    health = _health_section(active)
    if health is not None:
        sections.append(health)
    return ShieldStatus(shield_id="trader", mode=active, blocking=block, sections=tuple(sections))
