"""Which chain a transaction is for, as far as the call itself says.

Read from what the agent's tools name: Foundry's ``--chain <name|id>`` (also
``--chain-id``), the RPC endpoint (``--rpc-url`` / ``ETH_RPC_URL=``) by its host
name, and an EIP-712 ``chainId`` (typed data, viem objects). Three outcomes as
LES-011 asks: one chain named → its EIP-155 id; none named, or SEVERAL different
ones → None ("could not tell") — never a guess. A local or unknown RPC host
(``http://127.0.0.1:8545``, a private node) names no chain.

Pure function over the call's text.

Usage::

    chain_named("cast send … --rpc-url https://bsc-dataseed.binance.org")   # 56
    chain_named("cast send … --chain mainnet")                               # 1
    chain_named("cast send …")                                               # None
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit

#: Chain names Foundry and RPC hosts use -> EIP-155 chain id.
CHAIN_IDS: dict[str, int] = {
    "mainnet": 1, "ethereum": 1, "eth": 1, "optimism": 10, "op": 10, "bsc": 56, "bnb": 56, "binance": 56,
    "gnosis": 100, "xdai": 100, "polygon": 137, "matic": 137, "fantom": 250, "base": 8453,
    "arbitrum": 42161, "arb1": 42161, "avalanche": 43114, "avax": 43114, "sepolia": 11155111,
}
#: Host-name words that only say "Ethereum" when no more specific chain word is there
#: (``mainnet.optimism.io`` is Optimism, ``eth-mainnet.g.alchemy.com`` is Ethereum).
_GENERIC_HOST_WORDS = frozenset({"mainnet", "eth", "ethereum"})

_CHAIN_OPTION = re.compile(r"--chain(?:-id)?[=\s]+['\"]?([\w-]+)")
_RPC_URL = re.compile(r"(?:--rpc-url|--fork-url|\bETH_RPC_URL)[=\s]+['\"]?(https?://[^\s'\"]+)")
_CHAIN_ID_FIELD = re.compile(r"""["']?\bchainId["']?\s*[:=]\s*["']?(0x[0-9a-fA-F]+|\d+)""")


#: No chain id is near this long. A longer digit run names no chain — and ``int()`` refuses
#: decimal text past 4,300 digits, which once ended every check for the call (KI-489).
_MAX_CHAIN_ID_DIGITS = 20


def _decimal_chain_id(digits: str) -> Optional[int]:
    """A decimal chain id as written (leading zeros allowed), or None when too long to be one."""
    digits = digits.lstrip("0") or "0"
    return int(digits) if len(digits) <= _MAX_CHAIN_ID_DIGITS else None


def _chain_of_name(word: str) -> Optional[int]:
    word = word.strip().lower()
    if word.isdigit():
        return _decimal_chain_id(word)
    return CHAIN_IDS.get(word)


def _chain_id(written: str) -> Optional[int]:
    """A ``chainId`` value as written: hex (``0x38``) or decimal (leading zeros allowed)."""
    return int(written, 16) if written.lower().startswith("0x") else _decimal_chain_id(written)


def _chain_of_rpc(url: str) -> Optional[int]:
    """The chain an RPC URL's host name names (``bsc-dataseed.binance.org`` → 56), if any."""
    words = set(re.split(r"[.\-]", (urlsplit(url).hostname or "").lower()))
    specific = {CHAIN_IDS[word] for word in words - _GENERIC_HOST_WORDS if word in CHAIN_IDS}
    if specific:
        return specific.pop() if len(specific) == 1 else None
    return 1 if words & _GENERIC_HOST_WORDS else None


def chain_named(text: str) -> Optional[int]:
    """The one chain *text* names, or None when it names none or several (see the module doc)."""
    named: set[Optional[int]] = set()
    named.update(_chain_of_name(match.group(1)) for match in _CHAIN_OPTION.finditer(text))
    named.update(_chain_of_rpc(match.group(1)) for match in _RPC_URL.finditer(text))
    named.update(_chain_id(match.group(1)) for match in _CHAIN_ID_FIELD.finditer(text))
    named.discard(None)
    return named.pop() if len(named) == 1 else None
