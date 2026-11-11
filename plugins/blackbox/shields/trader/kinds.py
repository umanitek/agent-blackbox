"""Trader Shield's finding kinds — THE one list of what the shield emits or claims.

Each row names an identifier pattern (``secret:seed-phrase``, ``*:crypto-wallet``), its row in
the sighting classification (``community/sighting/classification.py``) and the kind of event
the events report tells it as (vault, seed, key, exchange, approval, keychain). The shield's
gate (``claims``, in the package entry) and its events report (:mod:`.events`) both read it,
so a finding the shield claims is always one its report can tell.

Usage::

    from plugins.blackbox.shields.trader import kinds
    kinds.event_kind("fileaccess:terminal:crypto-wallet")   # "vault"
    kinds.event_kind("secret:aws-access-key")               # "" — not Trader's
"""

from __future__ import annotations

import fnmatch
import re

from ..contract import FindingKind

_WALLET_KEYS = ("wallet-drain", "wallet-keys", "T1552.001")
_FUNDS = ("wallet-drain", "funds", "T1657")

#: ``(event kind, finding kind)`` for every identifier pattern Trader emits or claims.
_ROWS: tuple[tuple[str, FindingKind], ...] = (
    ("seed", FindingKind(*_WALLET_KEYS, identifier="secret:seed-phrase")),
    *(("key", FindingKind(*_WALLET_KEYS, identifier=f"secret:{name}"))
      for name in ("wallet-private-key", "solana-private-key", "bitcoin-private-key")),
    ("exchange", FindingKind("wallet-drain", "api-keys", "T1552.001", identifier="secret:exchange-api-key")),
    ("approval", FindingKind(*_FUNDS, identifier="secret:token-approval-drainer")),
    ("approval", FindingKind(*_FUNDS, identifier="secret:token-approval-unlimited")),
    # The classification table has no row of its own for this one; a secret finding without
    # a row reads as the generic credential theft, which is what the sighting shows today.
    ("approval", FindingKind("credential-theft", "api-keys", "T1552",
                             identifier="secret:token-approval-unchecked-spender")),
    ("vault", FindingKind("wallet-drain", "wallet-keys", "T1555.003", identifier="*:crypto-wallet")),
    ("keychain", FindingKind("credential-theft", "password-store", "T1555.001", identifier="*:macos-keychain")),
)

#: Every finding Trader Shield emits or claims (the shield record's ``finding_kinds``).
FINDING_KINDS: tuple[FindingKind, ...] = tuple(kind for _event, kind in _ROWS)
#: Each pattern compiled once (``event_kind`` runs for every finding the gate sees).
_MATCHERS = tuple((re.compile(fnmatch.translate(kind.identifier)), event) for event, kind in _ROWS)


def event_kind(identifier: str) -> str:
    """The kind of event *identifier* is (vault, seed, key, exchange, approval, keychain),
    or "" when it is not a Trader Shield finding."""
    return next((event for pattern, event in _MATCHERS if pattern.match(identifier)), "")
