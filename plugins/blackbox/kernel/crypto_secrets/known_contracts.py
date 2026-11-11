"""Well-known exchange contracts: never treated as a drainer, never flagged as a bad address.

An agent that trades approves and calls these routers all day. Threat feeds that
extract addresses from malicious code pick them up too — a fake trading bot
hard-codes the real Uniswap router — and Umanitek's verified graph lists seven of
them as drainer wallets (KI-370). The data lives in ``known_contracts.json`` (one
source for the plugin and ``scripts/blackbox-trader-graph-counts.py``), each entry
with how it was checked.

STOPGAP for the verified-graph entries (KI-370): the real fix is a curator
correction removing them from the graph; until then this list keeps the rules
from acting on them. As a list of routers an agent may approve, it stays.

Chain-aware (KI-388): the routers live on particular chains (PancakeSwap's on BNB
Chain, Uniswap's Universal Router v4 address on Ethereum only), so an entry lists the
EIP-155 chain ids where that address IS the router (``chains``, each with its source)
and whether it is deployed at the same address on every major chain (``any_chain``).
:func:`router_match` answers for one address on the chain a call names:

* ``ON_ITS_CHAIN`` — the call names one of its chains, or names none and the address
  is ``any_chain``: ordinary trading, exempt;
* ``CHAIN_UNKNOWN`` — the call names no chain and the address is a router on only some
  chains: the rules may flag an approval to it, never block (they cannot tell);
* ``OTHER_CHAIN`` — the call names a chain the router is not on: treated like any
  address;
* ``NOT_A_ROUTER``.

The file is read once and cached. It is checked entry by entry (KI-386): an
address that is not ``0x`` + 40 hex characters, or an entry without a name or
without chain ids, is skipped with a WARNING; a file that cannot be read or parsed gives an empty list.
Nothing here ever raises into detection — the detectors run on every tool call,
and one bad entry once switched every detector off through the hook's fail-open.

Usage::

    protocol_contract("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")   # -> "Uniswap V2 Router 02"
    protocol_contract("0xdead…")                                         # -> None
    router_match("0x10ed43c718714eb63d5aa57b78b54704e256024e", 56)      # -> RouterMatch.ON_ITS_CHAIN
    router_match("0x10ed43c718714eb63d5aa57b78b54704e256024e", 1)       # -> RouterMatch.OTHER_CHAIN
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

KNOWN_CONTRACTS_FILE = Path(__file__).with_name("known_contracts.json")
_ADDRESS = re.compile(r"0x[0-9a-f]{40}")


@dataclass(frozen=True)
class KnownContract:
    """One well-known router: its ``name``, the EIP-155 ``chains`` where this address is
    that router, and ``any_chain`` — the same address on every major chain."""

    name: str
    chains: frozenset[int]
    any_chain: bool = False


class RouterMatch(Enum):
    """What an address is on the chain a call names (see the module doc)."""

    NOT_A_ROUTER = "not-a-router"
    ON_ITS_CHAIN = "on-its-chain"
    CHAIN_UNKNOWN = "chain-unknown"
    OTHER_CHAIN = "other-chain"


def _entry(address: Any, entry: Any) -> Optional[KnownContract]:
    """The entry when *address* and *entry* are well formed, else None (logged)."""
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address.strip().lower()):
        logger.warning("blackbox: known_contracts.json: skipped an entry whose address is not 0x + 40 hex: %r", address)
        return None
    name = entry.get("name") if isinstance(entry, dict) else None
    if not isinstance(name, str) or not name.strip():
        logger.warning("blackbox: known_contracts.json: skipped %s, which has no name", address)
        return None
    chains = entry.get("chains")
    if not isinstance(chains, list) or not chains or not all(type(chain) is int and chain > 0 for chain in chains):
        logger.warning("blackbox: known_contracts.json: skipped %s, which lists no chain ids", address)
        return None
    return KnownContract(name.strip(), frozenset(chains), entry.get("any_chain") is True)


@lru_cache(maxsize=1)
def known_protocol_contracts() -> dict[str, KnownContract]:
    """``{lower-case address: KnownContract}`` from the shipped list, every entry checked
    (see the module doc); empty, with one WARNING, when the file is missing or cannot be
    read or parsed (a nesting deep enough to exhaust the parser included). Cached for the
    process, so the WARNING is logged once."""
    try:
        data = json.loads(KNOWN_CONTRACTS_FILE.read_text(encoding="utf-8-sig"))
        contracts = data["contracts"]
        if not isinstance(contracts, dict):
            raise TypeError("contracts is not an object")
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        logger.warning("blackbox: known_contracts.json could not be read (%s); no exchange router is exempt", exc)
        return {}
    out: dict[str, KnownContract] = {}
    for address, entry in contracts.items():
        known = _entry(address, entry)
        if known is not None:
            out[address.strip().lower()] = known
    return out


def protocol_contract(address: str) -> Optional[str]:
    """The name of the well-known exchange contract at *address* (on any chain), or None."""
    known = known_protocol_contracts().get(str(address or "").strip().lower())
    return known.name if known else None


def router_match(address: str, chain: Optional[int]) -> RouterMatch:
    """What *address* is on *chain* — the EIP-155 id the call names, or None when it
    names none (or several): see the module doc."""
    known = known_protocol_contracts().get(str(address or "").strip().lower())
    if known is None:
        return RouterMatch.NOT_A_ROUTER
    if chain is None:
        return RouterMatch.ON_ITS_CHAIN if known.any_chain else RouterMatch.CHAIN_UNKNOWN
    return RouterMatch.ON_ITS_CHAIN if chain in known.chains else RouterMatch.OTHER_CHAIN
