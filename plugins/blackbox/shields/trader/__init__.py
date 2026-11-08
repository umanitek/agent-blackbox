"""Trader Shield — opt-in protection for people who hold crypto: wallet key stores, seed
phrases, private keys, exchange keys, token approvals and the macOS keychain.

This module assembles :data:`TRADER`, the shield's record (Strategy, by composition: a
:class:`~..contract.Shield` of plain functions). Today it carries the setting (:mod:`.mode`),
its detectors (the pack kinds in :mod:`.detectors`, built from the wallet packs in
``wallets/`` and the browser folders in ``browsers.json``, plus the own-address key check
in :mod:`.detectors.own_keys`), and the gate: ``claims`` is read from :data:`FINDING_KINDS`
(what its detectors emit AND the core findings it claims — seed phrases, labelled keys,
exchange keys, token approvals, the keychain), ``allows`` reads a key-store finding's
``fields["pack"]``. Its dashboard card is :mod:`.status`; its events report, with the story
of each event told server-side, is :mod:`.events`.

Usage::

    from plugins.blackbox import shields
    trader = shields.get("trader")
    trader.allows({"identifier": "secret:seed-phrase"}, trader.mode())   # False while off
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Mapping

from ...detection import FIELD_WALLET_SECRET_SENT, Finding
from ...kernel import crypto_secrets
from ...kernel.config import load_blackbox_config
from ..contract import (Capability, FindingKind, SettingField, SettingOption, Shield, ShieldEvent, ShieldMode,
                        ShieldStatus)
from ..packs import load_packs
from ..self_test import SELF_TESTS
from . import detectors, events, mode, self_tests, status
from .detectors import own_keys

HERE = Path(__file__).resolve().parent


def _current_mode() -> ShieldMode:
    # Looked up on every call, not bound once: a test stands a mode in by patching mode.current.
    return mode.current()


def _listed_addresses() -> tuple[str, ...]:
    """The operator's own addresses, for the kernel's always-on own-key redaction."""
    return mode.addresses(mode.current())


_WALLET_KEYS = ("wallet-drain", "wallet-keys", "T1552.001")
_FUNDS = ("wallet-drain", "funds", "T1657")

#: Every finding Trader Shield emits or claims, with the sighting layer's classification
#: (``community/sighting/classification.py``). ``*:crypto-wallet`` is gated per pack.
FINDING_KINDS: tuple[FindingKind, ...] = (
    *(FindingKind(*_WALLET_KEYS, identifier=f"secret:{name}")
      for name in ("seed-phrase", "wallet-private-key", "solana-private-key", "bitcoin-private-key")),
    FindingKind("wallet-drain", "api-keys", "T1552.001", identifier="secret:exchange-api-key"),
    FindingKind(*_FUNDS, identifier="secret:token-approval-drainer"),
    FindingKind(*_FUNDS, identifier="secret:token-approval-unlimited"),
    # The classification table has no row of its own for this one; a secret finding without
    # a row reads as the generic credential theft, which is what the sighting shows today.
    FindingKind("credential-theft", "api-keys", "T1552", identifier="secret:token-approval-unchecked-spender"),
    FindingKind("wallet-drain", "wallet-keys", "T1555.003", identifier="*:crypto-wallet"),
    FindingKind("credential-theft", "password-store", "T1555.001", identifier="*:macos-keychain"),
)

#: What Trader protects that is not a wallet pack; the last two are shown, never gated by it.
CAPABILITIES: tuple[Capability, ...] = (
    Capability("exchanges", "Exchange accounts", "Binance, OKX, Bybit, Coinbase Exchange, KuCoin",
               claims=("secret:exchange-api-key",)),
    Capability("approvals", "Token approvals", "the signature a drainer needs", claims=("secret:token-approval-*",)),
    Capability("keychain", "macOS keychain", "saved passwords and the browsers' Safe Storage keys",
               claims=("*:macos-keychain",)),
    Capability("own-addresses", "Your own addresses", "a raw key that opens an address you listed",
               claims=("secret:wallet-private-key",)),
    Capability("secrets", "Keys and secrets on disk", ".env files, SSH keys — Blackbox's protected paths"),
    Capability("supply-chain", "Poisoned packages and pages", "the threat graph's rules"),
)

#: One match for every claimed identifier pattern (built once; ``claims`` runs per finding).
_CLAIMED = re.compile("|".join(fnmatch.translate(kind.identifier) for kind in FINDING_KINDS))


def claims(finding: Mapping[str, Any]) -> bool:
    """Whether *finding* is a Trader Shield finding (the mode gate applies to it).

    A wallet secret on its way off the machine is not: that is a built-in rule that counts
    with the shield off too (KI-488 — a seed phrase has no right destination)."""
    fields = finding.get("fields")
    if isinstance(fields, Mapping) and fields.get(FIELD_WALLET_SECRET_SENT) is True:
        return False
    return _CLAIMED.match(str(finding.get("identifier") or "")) is not None


def _pack_of(fields: Mapping[str, Any]) -> str:
    """The pack a key-store finding names, or "" for a store no pack can be named for."""
    if "pack" in fields:
        return str(fields["pack"])
    # A key-store finding that names only its wallet (the field from before packs). No current
    # detector or caller produces one any more, so this fallback can go in its own change.
    legacy = str(fields.get("wallet") or "")
    return "" if legacy == mode.ANY_EXTENSION_WALLET else legacy


def allows(finding: Mapping[str, Any], active: ShieldMode) -> bool:
    """Whether a claimed finding counts under *active*: only while the shield is on, and a
    key-store finding only for a chosen pack — one that names no pack is the shield's as a
    whole and counts while any pack is chosen (today's rule; changing it is a founder call)."""
    if not active.enabled:
        return not claims(finding)
    identifier = str(finding.get("identifier") or "")
    fields = finding.get("fields")
    if not identifier.endswith(mode.WALLET_FILE_SUFFIX) or not isinstance(fields, Mapping):
        return True
    pack = _pack_of(fields)
    return pack in mode.wallets(active) if pack else bool(mode.wallets(active))


def _detect(tool_name: str, args: Any, active: ShieldMode) -> list[Finding]:
    """Trader's own findings for one call: the chosen packs' key stores, then the operator's own keys."""
    return detectors.detect(tool_name, args, active) + own_keys.detect(tool_name, args, active)


#: Settings' words for Trader's group (the dashboard draws them as given).
ENGAGE_HELP = ("Keep your AI agent away from your wallets: it cannot open a wallet's key store (the encrypted vault "
               "in your browser or wallet app), and seed phrases and private keys it handles are flagged, and blocked "
               "if it tries to send them off this machine. Your own trading tools keep working. Seed phrases and keys "
               "are always kept out of Blackbox's logs, whether this is on or off.")
ADDRESSES_HELP = ("A raw private key is 64 characters that look exactly like a transaction hash. List your own public "
                  "addresses (0x…, one per line) and Trader Shield recognises a raw key that opens one of them — and "
                  "blocks it if your agent tries to send it out. Addresses stay on this machine; they are never "
                  "logged, reported or shared. Optional.")


def settings_fields() -> list[SettingField]:
    """How Settings draws Trader's group: the switch, the wallet packs in display order
    (supported, then coming soon; a pack that failed to load is left out), and the
    operator's own addresses (one per line, each a ``0x`` address)."""
    options = tuple(SettingOption(id=pack.id, name=pack.name, status=pack.status, logo=mode.logo_url(pack.id))
                    for pack in mode.wallet_packs() if pack.status != "unavailable")
    return [SettingField(key="enabled", kind="toggle", label="Engage Trader Shield", help=ENGAGE_HELP),
            SettingField(key=mode.WALLETS, kind="multi-pick", label="Wallets to protect",
                         help="Choose the wallets installed on this machine.", options=options),
            SettingField(key=mode.ADDRESSES, kind="lines", label="Your wallet addresses", help=ADDRESSES_HELP,
                         pattern=mode.ADDRESS_PATTERN)]


def _status(active: ShieldMode) -> ShieldStatus:
    """Trader's dashboard card under *active*, judged by this shield's own gate."""
    return status.build(active, allows)


def _events() -> list[ShieldEvent]:
    """Every event this shield claims, told under Blackbox's audit/block mode now."""
    return events.report(claims, blocking=bool(load_blackbox_config().block_enabled))


TRADER = Shield(
    id="trader", name="Trader Shield", beta=True,
    tagline="Keeps your AI agent away from your crypto wallets, seed phrases and keys.",
    mode=_current_mode, validate=mode.validate, detect=_detect,
    claims=claims, allows=allows, status=_status, events=_events,
    settings_fields=settings_fields, finding_kinds=FINDING_KINDS, capabilities=CAPABILITIES,
    packs=HERE / "wallets", page=HERE / "page" / "trader.html", attacks=HERE / "attacks.json",
    detectors=detectors.DETECTORS, browser_roots=HERE / "browsers.json",
)

# The mode chooses among the packs, read once here at import (never on the hot path).
# The registry reads them again for its own view (logos, health): two import-time reads.
mode.use_packs(load_packs(TRADER))

# The Playground lists Trader's self-tests through the registry, never this package.
SELF_TESTS.register(TRADER.id, self_tests.build)

# The kernel's own-key redaction needs the listed addresses but may not import a shield:
# the shield hands its reader in (dependency injection, like the settings validators).
crypto_secrets.read_listed_addresses_from(_listed_addresses)
