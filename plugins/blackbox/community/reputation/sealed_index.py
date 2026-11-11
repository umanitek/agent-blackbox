"""The ledger's index, sealed (Community Curation C11, KI-257).

The private reputation ledger is two files: the ENTRIES, keyed by a pseudonym
(an HMAC of the reporter key under a per-reporter random salt), and the INDEX
that maps each reporter key to its salt. The index is the only link from a
reporter to its entry — and it used to hold reporter keys in clear, so a
copied index re-identified every entry.

The index is now encrypted (AES-256-GCM) under a random key kept in a THIRD
owner-only file. A copied index alone identifies nobody; a copied entries
file alone never did. Both plus the key file open the ledger, which is what
the curator node itself needs. Losing the key file loses the link for good:
the entries are then unreachable, exactly as after an erasure.

Pattern: two pure functions over bytes, plus one for the key file.

Usage::

    key = load_or_create_key(path.with_name("reputation_index.key"))
    text = seal({"<reporter key>": "<salt>"}, key)           # what the index file holds
    mapping = open_sealed(text, key)                          # None when it cannot be opened
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ...kernel.bounded_files import create_once

#: The index file's layout version.
FORMAT_VERSION = 2
_KEY_BYTES = 32
_NONCE_BYTES = 12


def load_or_create_key(path: Path) -> Optional[bytes]:
    """The index key in *path* (created owner-only on first use); None when it
    exists but is unreadable or malformed — the caller must then treat the
    index as closed, never write a new key over it."""
    try:
        raw = bytes.fromhex(path.read_text(encoding="ascii").strip())
        return raw if len(raw) == _KEY_BYTES else None
    except FileNotFoundError:
        key = secrets.token_bytes(_KEY_BYTES)
        # Written whole or not at all: a key file left EMPTY by a crash would read as
        # "malformed" for good, and the ledger could never be saved again.
        if create_once(path, key.hex().encode("ascii")):
            return key
        return load_or_create_key(path)   # another process created it meanwhile: use theirs
    except (OSError, ValueError):
        return None


def seal(mapping: dict[str, str], key: bytes) -> str:
    """*mapping* (reporter key -> salt) as the text the index file holds: no reporter key is readable in it."""
    nonce = secrets.token_bytes(_NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, json.dumps(mapping, sort_keys=True).encode("utf-8"), None)
    return json.dumps({"v": FORMAT_VERSION, "sealed": (nonce + sealed).hex()})


def open_sealed(text: str, key: Optional[bytes]) -> Optional[dict[str, str]]:
    """The mapping inside a sealed index, or None when *text* is not a sealed
    index or cannot be opened with *key* (the wrong key, no key, or a damaged file)."""
    try:
        document = json.loads(text)
        if not isinstance(document, dict) or document.get("v") != FORMAT_VERSION or key is None:
            return None
        blob = bytes.fromhex(str(document["sealed"]))
        opened = json.loads(AESGCM(key).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], None).decode("utf-8"))
        return {str(k): str(v) for k, v in opened.items()} if isinstance(opened, dict) else None
    except (ValueError, KeyError, TypeError, InvalidTag):
        return None


def is_sealed(text: str) -> bool:
    """True when *text* is a sealed index (whatever key it needs) rather than the old clear map."""
    try:
        document = json.loads(text)
    except ValueError:
        return False
    return isinstance(document, dict) and document.get("v") == FORMAT_VERSION and "sealed" in document
