"""Raw Ethereum private keys, recognised by the address they open.

A raw key is 64 hex characters — exactly what a transaction hash, a block hash
or a file digest looks like, so its shape proves nothing. What proves it is
the address: a private key derives one address (secp256k1 public key →
Keccak-256 → last 20 bytes). When the operator has listed their own wallet
addresses (Trader Shield settings), a 64-hex value whose address is on that
list IS one of their keys; any other 64-hex value is left alone.

Keccak-256 is Ethereum's hash (the original Keccak padding, not NIST SHA3-256),
which Python's hashlib does not offer; it is implemented here from the Keccak
reference (keccak.team, Keccak-f[1600], rate 1088) and checked against
published vectors and Foundry's ``cast wallet address`` in the tests.

Usage::

    address_of(bytes.fromhex("00" * 31 + "01"))   # -> "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    own_keys_in("curl -d k=<64 hex> …", {"0x7e5f…"})   # -> 1 when the key opens a listed address
    scan_own_keys(text, {"0x7e5f…"})   # -> OwnKeyScan(spans=((8, 72),), unchecked=0)

Cost: a derivation is ~2 ms, so at most :data:`MAX_CANDIDATES` distinct values are
derived per text — labelled ones first, values labelled as hashes last, later ones
before earlier ones — and each answer is remembered by the value's SHA-256 (never the
value), so a log full of the same transaction hashes is derived once (KI-382).
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass
from typing import AbstractSet, Callable, Iterable, Optional


logger = logging.getLogger(__name__)

#: secp256k1's group order: a private key is 1 ≤ k < N.
_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#: A 64-hex value standing alone (with or without 0x) — a candidate raw key.
#: Bounded by non-hex only (KI-380): "0X…", a key followed by a letter, a key inside a
#: word all count; a longer hex run (a hash list, a signature) does not.
_CANDIDATE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
#: Most distinct 64-hex values derived per text (each ~2 ms): a text full of transaction
#: hashes must not stall the hook (65 KB of them took 2 s before the cap, KI-382).
MAX_CANDIDATES = 32
#: Just before a value: a label that says "key" (checked first) or "hash" (checked last).
_KEY_LABEL = re.compile(r"(?:key|pk|secret|priv|signer|wallet|account)[^0-9A-Za-z]{0,4}$", re.IGNORECASE)
_HASH_LABEL = re.compile(r"(?:tx|hash|block|sha\d*|digest|commit|root|id)[^0-9A-Za-z]{0,4}$", re.IGNORECASE)
_LABEL_REACH = 24
#: Ethereum address as the operator lists it.
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROTATIONS = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
_MASK = (1 << 64) - 1
_RATE = 136   # bytes: 1600-bit state minus 2 × 256-bit capacity


def _rotate(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(state: list) -> None:
    """Keccak-f[1600] on a 5×5 state of 64-bit lanes (``state[x][y]``), in place."""
    for constant in _ROUND_CONSTANTS:
        columns = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        for x in range(5):
            mix = columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1)
            for y in range(5):
                state[x][y] ^= mix
        moved = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                moved[y][(2 * x + 3 * y) % 5] = _rotate(state[x][y], _ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = moved[x][y] ^ ((~moved[(x + 1) % 5][y]) & moved[(x + 2) % 5][y])
        state[0][0] ^= constant


def keccak256(data: bytes) -> bytes:
    """Ethereum's Keccak-256 of *data* (original Keccak padding 0x01…0x80)."""
    room = _RATE - len(data) % _RATE   # bytes left in the last block (1…136)
    # One byte left: the opening 0x01 and the closing 0x80 share it (0x81).
    padded = bytearray(data) + (b"\x81" if room == 1 else b"\x01" + b"\x00" * (room - 2) + b"\x80")
    state = [[0] * 5 for _ in range(5)]
    for block in range(0, len(padded), _RATE):
        for lane in range(_RATE // 8):
            word = int.from_bytes(padded[block + 8 * lane:block + 8 * lane + 8], "little")
            state[lane % 5][lane // 5] ^= word
        _permute(state)
    return b"".join(state[lane % 5][lane // 5].to_bytes(8, "little") for lane in range(4))


def address_of(private_key: bytes) -> Optional[str]:
    """The Ethereum address (lower-case ``0x…``) a 32-byte *private_key* opens, or
    None when it is not a valid secp256k1 key."""
    number = int.from_bytes(private_key, "big")
    if len(private_key) != 32 or not 0 < number < _CURVE_ORDER:
        return None
    # Imported here, not at load (L8, the hook budget): every audit redaction imports this module,
    # and only a value shaped like a key ever reaches this line.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    public = ec.derive_private_key(number, ec.SECP256K1()).public_key()
    point = public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]   # drop the 0x04 prefix
    return "0x" + keccak256(point)[-20:].hex()


class _AddressCache:
    """The address each checked value opens, remembered by the value's SHA-256 digest
    (the key itself is never kept). Bounded: emptied when full. One lock."""

    _LIMIT = 4096

    def __init__(self) -> None:
        self._known: dict[bytes, Optional[str]] = {}
        self._lock = threading.Lock()

    def address(self, candidate: str) -> Optional[str]:
        digest = hashlib.sha256(candidate.encode("ascii")).digest()
        with self._lock:
            if digest in self._known:
                return self._known[digest]
        address = address_of(bytes.fromhex(candidate))
        with self._lock:
            if len(self._known) >= self._LIMIT:
                self._known.clear()
            self._known[digest] = address
        return address


_ADDRESSES = _AddressCache()


@dataclass(frozen=True)
class OwnKeyScan:
    """``spans`` — ``(start, end)`` of every 64-hex value in the text that opens a listed
    address; ``unchecked`` — distinct values left underived because the text held more
    than :data:`MAX_CANDIDATES` (a caller that must not miss a key treats them as
    "could not tell", never as "no key"), at ``unchecked_spans``."""

    spans: tuple[tuple[int, int], ...] = ()
    unchecked: int = 0
    unchecked_spans: tuple[tuple[int, int], ...] = ()


def _check_order(text: str, matches: list[re.Match[str]]) -> list[str]:
    """Distinct candidate values, most key-like first: labelled as a key, then unlabelled,
    then labelled as a hash; later before earlier within each (a decoy padding the front
    of a text cannot push the key out of the budget)."""
    rank: dict[str, int] = {}
    for match in reversed(matches):
        value = match.group(1).lower()
        if value in rank:
            continue
        before = text[max(0, match.start() - _LABEL_REACH):match.start()]
        rank[value] = 0 if _KEY_LABEL.search(before) else (2 if _HASH_LABEL.search(before) else 1)
    return sorted(rank, key=rank.__getitem__)   # stable: keeps last-first inside a rank


def scan_own_keys(text: str, addresses: AbstractSet[str]) -> OwnKeyScan:
    """Where *text* holds private keys of the listed *addresses* (lower-case ``0x…``).
    Nothing is derived when no address is listed or no 64-hex value is present."""
    if not text or not addresses:
        return OwnKeyScan()
    matches = list(_CANDIDATE.finditer(text))
    order = _check_order(text, matches)
    own = {value for value in order[:MAX_CANDIDATES] if _ADDRESSES.address(value) in addresses}
    skipped = set(order[MAX_CANDIDATES:])
    return OwnKeyScan(spans=tuple(match.span() for match in matches if match.group(1).lower() in own),
                      unchecked=len(skipped),
                      unchecked_spans=tuple(match.span() for match in matches if match.group(1).lower() in skipped))


#: What a redacted own key becomes (the labelled-key rule's marker: one kind of secret).
MARKER = "[REDACTED_WALLET_PRIVATE_KEY]"


#: Where the operator's listed addresses come from. Trader Shield owns that setting and
#: hands its reader in at import (:func:`read_listed_addresses_from`): the kernel never
#: imports a shield. Until one does, no address is listed and nothing is derived.
_address_source: Callable[[], Iterable[str]] = tuple


def read_listed_addresses_from(source: Callable[[], Iterable[str]]) -> None:
    """Read the operator's listed addresses from *source* (called with no arguments,
    each time a 64-hex value needs checking) — the owning shield's setting reader."""
    global _address_source
    _address_source = source


def _listed_addresses() -> frozenset[str]:
    """The operator's listed addresses (Trader Shield settings), or none when the config
    cannot be read — then no key can be proven, and nothing is derived."""
    try:
        return frozenset(_address_source())
    except Exception as exc:  # fail open: redaction must never break a log write
        logger.warning("blackbox: listed wallet addresses unreadable (%s); own keys are not redacted", exc)
        return frozenset()


def redact_own_keys(text: str, addresses: Optional[AbstractSet[str]] = None) -> str:
    """*text* with every 64-hex value that opens a listed address replaced by
    :data:`MARKER` — and, when the text holds more values than the budget, the unchecked
    ones too (logs fail closed). *addresses* defaults to the operator's listed ones, read
    only when a 64-hex value is present. A key no label marks and no listed address
    opens is indistinguishable from a transaction hash and stays."""
    if not text or not _CANDIDATE.search(text):
        return text
    scan = scan_own_keys(text, _listed_addresses() if addresses is None else addresses)
    for start, end in sorted(scan.spans + scan.unchecked_spans, reverse=True):
        text = text[:start] + MARKER + text[end:]
    return text


def own_keys_in(text: str, addresses: AbstractSet[str]) -> int:
    """How many distinct 64-hex values in *text* are private keys of the listed
    *addresses* (lower-case ``0x…``). Zero when no address is listed — nothing is derived."""
    scan = scan_own_keys(text, addresses)
    return len({text[start:end].lower().removeprefix("0x") for start, end in scan.spans})


def checksum_address(address: str) -> Optional[str]:
    """The EIP-55 mixed-case spelling of an ``0x`` + 40-hex *address* (any case), or None
    when it is not one. A hex letter is upper-cased where the Keccak-256 of the
    lower-case hex has a nibble ≥ 8 (EIP-55)."""
    if not ADDRESS.match(address or ""):
        return None
    lower = address[2:].lower()
    digest = keccak256(lower.encode("ascii")).hex()
    return "0x" + "".join(char.upper() if int(digest[index], 16) >= 8 else char for index, char in enumerate(lower))
