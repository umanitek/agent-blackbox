"""Trader Shield's setting: an opt-in mode, the wallets the operator chose, their own addresses.

Founder direction (Amos, 2026-10-12): wallet protection is a mode the operator turns
on in Settings, choosing which wallets to guard. Off (the default), the wallet rules —
key-store access, seed phrases, labelled private keys — neither flag nor block, and
the dashboard hides the wallet panel. Redaction is NOT part of the mode: seed phrases
and private keys are always scrubbed from Blackbox's own logs (privacy, never a switch).

Config, under ``plugins.entries.blackbox``::

    shields:
      trader:
        enabled: true                # the mode (default false)
        wallets: [metamask]          # which wallets (default: every supported one)
        offered: [metamask, …]       # written by the save, never by the operator: every wallet
                                     # Settings offered then, so a wallet added in a later version
                                     # is told apart from one the operator left unticked
        addresses: ["0x…"]           # the operator's OWN public addresses (optional, opt-in):
                                     # a raw 64-hex key that opens one of them is recognised

Which wallets exist is data, not code: the shield's packs (``shields/trader/wallets/``),
handed in once by :func:`use_packs`; ``supported`` ones may be chosen, ``planned`` ones
are shown as coming soon.

An install saved before shields keeps the three legacy keys ``wallet_protection`` /
``protected_wallets`` / ``wallet_addresses``; :func:`from_entry` still reads them (so it
stays engaged without a save), and the first save retires them (:func:`validate`).

The mode is the shields contract's :class:`~..contract.ShieldMode`, built by :func:`build`:
options ``wallets`` and ``addresses``, the addresses marked personal so ``as_json()``
leaves them out unless the Settings editor asks.

Usage::

    mode = current()
    wallets(mode), addresses(mode)       # ("metamask", "phantom", ...), ()
    mode.enabled                         # the shield's gate (``TRADER.allows``) reads this
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional

from ..contract import Pack, ShieldMode

#: How a key-store finding's identifier ends (it names its pack in ``fields["pack"]``).
WALLET_FILE_SUFFIX = ":crypto-wallet"
#: The id of a Firefox extension key store's wallet: Firefox names each install's
#: storage by a random UUID, so the folder cannot be tied to one wallet. It belongs to
#: EVERY chosen wallet — counted whenever the mode is on with any wallet chosen.
ANY_EXTENSION_WALLET = "any-extension"

#: The mode's options: the chosen wallet ids, and the operator's own addresses (personal).
WALLETS, ADDRESSES = "wallets", "addresses"
#: The three keys this setting lived under before shields; one save retires them.
LEGACY_KEYS = ("wallet_protection", "protected_wallets", "wallet_addresses")
#: Saved next to the chosen wallets by every save (server-made, never read from the payload):
#: the supported wallets Settings offered at that moment.
OFFERED = "offered"
#: What a save made before OFFERED was recorded had on offer: the five wallets Blackbox
#: supported from Trader Shield's first release until the save began recording it.
OFFERED_BEFORE_RECORDING = ("metamask", "phantom", "exodus", "electrum", "solana-cli")

#: Most addresses an operator may list (each costs a key derivation only when a 64-hex
#: value appears in a call, ~2 ms; the list is matched as a set).
MAX_WALLET_ADDRESSES = 50
#: One own address: what Settings accepts per line (the page reads it from the field).
ADDRESS_PATTERN = "^0x[0-9a-fA-F]{40}$"
_ADDRESS = re.compile(ADDRESS_PATTERN)
#: The dashboard route of a pack's logo; both ids are resolved through the registry there.
LOGO_URL = "/shields/trader/packs/{pack}/logo.svg"


#: Trader's wallet packs in display order, handed in once by the shield (:func:`use_packs`).
_packs: tuple[Pack, ...] = ()


def use_packs(packs: Iterable[Pack]) -> None:
    """Set the wallet packs the mode chooses from (the shield calls this once, at import)."""
    global _packs
    _packs = tuple(packs)


def wallet_packs() -> tuple[Pack, ...]:
    """Every wallet pack in display order: supported, planned, then unavailable ones."""
    return _packs


def logo_url(pack_id: str) -> str:
    """Where the dashboard serves *pack_id*'s logo (``GET /shields/trader/packs/{pack}/logo.svg``),
    when it is a supported pack that ships one; "" otherwise (the page then draws its glyph)."""
    return next((LOGO_URL.format(pack=pack.id) for pack in _packs
                 if pack.id == pack_id and pack.status == "supported" and pack.logo is not None), "")


def supported_wallets() -> dict[str, str]:
    """The wallets Blackbox can protect now: pack id -> display name, in display order."""
    return {pack.id: pack.name for pack in _packs if pack.status == "supported"}


def build(enabled: bool = False, wallets: Optional[tuple[str, ...]] = None,
          addresses: tuple[str, ...] = ()) -> ShieldMode:
    """Trader's mode: ``enabled``; ``wallets`` — supported wallet ids to guard (None:
    every supported one);
    ``addresses`` — the operator's own public addresses, lower-case (kept on this
    machine only; never put in a finding, a log line or a report)."""
    chosen = tuple(supported_wallets()) if wallets is None else tuple(wallets)
    return ShieldMode(enabled=enabled, options={WALLETS: chosen, ADDRESSES: tuple(addresses)},
                      personal=frozenset({ADDRESSES}))


def wallets(mode: ShieldMode) -> tuple[str, ...]:
    """The wallet ids *mode* guards."""
    return tuple(mode.options.get(WALLETS, ()))


def addresses(mode: ShieldMode) -> tuple[str, ...]:
    """The operator's own addresses in *mode* (personal: never shown outside Settings)."""
    return tuple(mode.options.get(ADDRESSES, ()))


def _wallet_list(raw: Any) -> tuple[str, ...]:
    """Supported wallet ids from *raw* (a list), lower-cased, deduplicated, in order."""
    supported = supported_wallets()
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        wallet = str(item or "").strip().lower()
        if wallet in supported and wallet not in out:
            out.append(wallet)
    return tuple(out)


def _address_list(raw: Any) -> tuple[str, ...]:
    """Valid addresses from *raw* (a list), lower-cased, deduplicated, at most the cap."""
    out: list[str] = []
    for item in raw if isinstance(raw, list) else []:
        address = str(item or "").strip().lower()
        if _ADDRESS.match(address) and address not in out:
            out.append(address)
    return tuple(out[:MAX_WALLET_ADDRESSES])


def _saved_section(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    """The saved ``shields.trader`` mapping; for an install that never saved since shields
    arrived, the same mapping composed from the three legacy keys."""
    shields = entry.get("shields")
    section = shields.get("trader") if isinstance(shields, Mapping) else None
    if isinstance(section, Mapping):
        return section
    legacy: dict[str, Any] = {"enabled": entry.get("wallet_protection"), ADDRESSES: entry.get("wallet_addresses")}
    if "protected_wallets" in entry:
        legacy[WALLETS] = entry["protected_wallets"]
    return legacy


def from_entry(entry: Mapping[str, Any]) -> ShieldMode:
    """The mode as the ``blackbox`` config entry states it (defaults when absent).

    ``shields.trader`` when present; otherwise the three legacy keys, so an install that
    never saved since shields arrived stays engaged."""
    section = _saved_section(entry)
    chosen = _wallet_list(section[WALLETS]) if WALLETS in section else None
    return build(enabled=section.get("enabled") is True, wallets=chosen,
                 addresses=_address_list(section.get(ADDRESSES)))


def newly_supported(mode: ShieldMode, entry: Optional[Mapping[str, Any]] = None) -> tuple[str, ...]:
    """Supported wallet ids *mode* leaves out that Settings did NOT offer when the list was
    saved — wallets this version added since, which the operator has never been asked about.
    A wallet the operator left unticked was offered, so it is never named here.

    *entry* is the ``blackbox`` config entry (default: read now). Empty when no list was
    saved: every supported wallet is then chosen, so none can be missing."""
    if entry is None:
        from ...kernel.config import _blackbox_entry   # the one reader of plugins.entries.blackbox

        entry = _blackbox_entry()
    section = _saved_section(entry)
    if WALLETS not in section:
        return ()
    raw = section.get(OFFERED)
    offered = ({str(item or "").strip().lower() for item in raw} if isinstance(raw, list)
               else set(OFFERED_BEFORE_RECORDING))
    chosen = set(wallets(mode))
    return tuple(wallet for wallet in supported_wallets() if wallet not in chosen and wallet not in offered)


def current() -> ShieldMode:
    """The mode in force now, read from the Hermes config like every other setting."""
    from ...kernel.config import _blackbox_entry   # the one reader of plugins.entries.blackbox

    return from_entry(_blackbox_entry())


def validate(payload: Mapping[str, Any]) -> tuple[str, dict[str, Any], list[str], tuple[str, ...]]:
    """``("trader", section, errors, superseded keys)`` for ``payload["shields"]["trader"]``.

    Unknown wallets and non-booleans are refused, never stored; ``wallets`` holds at most
    every supported wallet once, ``addresses`` at most :data:`MAX_WALLET_ADDRESSES`. A
    section that touches the mode is written COMPLETE — fields the payload leaves out
    keep their current value — because the same save retires the legacy keys:
    an Engage that sends only ``enabled`` keeps an earlier choice of wallets and addresses.
    """
    shields = payload.get("shields")
    raw = shields.get("trader") if isinstance(shields, Mapping) else None
    if raw is None or raw == {}:
        return "trader", {}, [], LEGACY_KEYS
    if not isinstance(raw, Mapping):
        return "trader", {}, ["shields.trader must be an object"], LEGACY_KEYS
    updates, errors = _validated_fields(raw)
    if errors or not updates:
        return "trader", {}, errors, LEGACY_KEYS
    now = current()
    section = {"enabled": now.enabled, WALLETS: list(wallets(now)), ADDRESSES: list(addresses(now)), **updates,
               OFFERED: list(supported_wallets())}   # what this save offered (never taken from the payload)
    return "trader", section, [], LEGACY_KEYS


def _validated_fields(raw: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """``(fields, errors)`` for the mode's fields in one ``shields.trader`` object."""
    updates: dict[str, Any] = {}
    errors: list[str] = []
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            updates["enabled"] = raw["enabled"]
        else:
            errors.append("shields.trader.enabled must be a boolean")
    if WALLETS in raw:
        chosen, supported = raw[WALLETS], supported_wallets()
        # No list longer than the supported set: a valid one never repeats a wallet (KI-389).
        too_long = isinstance(chosen, list) and len(chosen) > len(supported)
        unknown = [] if too_long else [w for w in (chosen if isinstance(chosen, list) else [chosen])
                                       if str(w or "").lower() not in supported]
        if not isinstance(chosen, list) or too_long or unknown:
            errors.append(f"shields.trader.wallets must be a list of: {', '.join(supported)}")
        else:
            updates[WALLETS] = list(_wallet_list(chosen))
    if ADDRESSES in raw:
        listed = raw[ADDRESSES]
        items = listed if isinstance(listed, list) and len(listed) <= MAX_WALLET_ADDRESSES else None
        bad = [a for a in items or [] if not _ADDRESS.match(str(a or "").strip())]
        if items is None or bad:
            errors.append(f"shields.trader.addresses must be a list of up to {MAX_WALLET_ADDRESSES} "
                          "addresses like 0x followed by 40 hex characters")
        else:
            updates[ADDRESSES] = list(_address_list(items))
    return updates, errors
