"""Redaction for anything written to the local audit logs.

:func:`sanitize_text` caps and scrubs one string (secret-shaped values, bearer
tokens); :func:`redact` walks nested values. Secret VALUE patterns come from
``kernel.redaction`` — the one implementation (G1).

A secret can also be ASSEMBLED from pieces that are each harmless — a seed phrase
passed as a list of words (``{"words": ["abandon", …]}``), one word per dict value, the
words as dict KEYS, or a Solana key as a list of 64 numbers. :func:`redact` reads the
pieces of a structure together first and blanks every piece that belongs to such a
secret (KI-377), then scrubs each string as before.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from ..kernel.redaction import SECRET_NAME_RE, redact_secret_values
from ..kernel import crypto_secrets, display_safety

# ---------------------------------------------------------------------------
# Redaction (ported verbatim from the original plugin/node-ui regexes)
# ---------------------------------------------------------------------------

_MAX_TEXT = 2000
#: Text past ``max_len`` is cut BEFORE redaction once it is longer than this margin
#: allows (a 4096-bit PEM key is ~3.3 KB, a 24-word phrase ~200 characters), so a
#: megabyte argument costs no more than a few kilobytes of redaction (KI-382)…
_REDACTION_MARGIN = 8192
#: …and the last characters of such a pre-cut are dropped after redaction: a secret
#: split by the cut sits there, and must never reach the log half-redacted.
_CUT_GUARD = 1024
#: Structure walks mirror :func:`redact`'s own bounds.
_MAX_DEPTH = 5
_MAX_ITEMS = 50
_SOLANA_KEY_BYTES = 64

#: A key whose NAME says it holds a secret: the kernel's one list of such names.
_SECRET_KEY_RE = SECRET_NAME_RE


def sanitize_text(value: str, max_len: int = _MAX_TEXT) -> str:
    """Redact common secret shapes from *value*, fold CR/LF and strip control
    characters (R8: a value can never forge a log line or drive a terminal
    that tails the log), then truncate to *max_len*.

    Redacts with ``kernel.redaction`` (the one implementation) BEFORE
    truncating, so a secret never lands raw — or half-cut — in the audit log.
    """
    text = str(value)
    precut = len(text) > max_len + _REDACTION_MARGIN
    if precut:
        text = text[:max_len + _REDACTION_MARGIN]
    redacted = redact_secret_values(text)
    if precut:
        redacted = redacted[:max(0, len(redacted) - _CUT_GUARD)]
    text = display_safety.log_safe(redacted, limit=max_len + 32)
    if precut or len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


# A visitor sees each piece a walk reaches: ("value" | "key", text) or ("bytes", list of
# ints); it returns the piece's replacement, or None to keep it.
_Visitor = Callable[[str, Any], Optional[Any]]


def _walk(value: Any, depth: int, visit: _Visitor) -> Any:
    """*value* rebuilt with each piece the visitor replaces (same bounds as :func:`redact`)."""
    if depth > _MAX_DEPTH:
        return value
    if isinstance(value, str):
        replaced = visit("value", value)
        return value if replaced is None else replaced
    if isinstance(value, (list, tuple)):
        items = list(value)
        if len(items) == _SOLANA_KEY_BYTES and all(type(item) is int and 0 <= item < 256 for item in items):
            replaced = visit("bytes", items)
            return items if replaced is None else replaced
        return [_walk(item, depth + 1, visit) for item in items[:_MAX_ITEMS]]
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, child in value.items():
            new_key = visit("key", key) if isinstance(key, str) else None
            out[key if new_key is None else new_key] = _walk(child, depth + 1, visit)
        return out
    return value


def _hit_pieces(pieces: list[str]) -> set[int]:
    """Indexes of the *pieces* that belong to a seed phrase read across them, joined in order."""
    starts, text = [], ""
    for piece in pieces:
        starts.append(len(text))
        text += piece + " "
    hits: set[int] = set()
    for start, end in crypto_secrets.seed_phrase_spans(text):
        hits.update(index for index, piece_start in enumerate(starts)
                    if piece_start < end and piece_start + len(pieces[index]) > start)
    return hits


def _blank_assembled_secrets(value: Any) -> Any:
    """*value* with every piece of a secret assembled across pieces replaced by its marker:
    a seed phrase across the string values (or across the dict keys), a Solana key as a
    list of 64 numbers. Values and keys are read apart — a key between two words would
    otherwise break the phrase."""
    pieces: dict[str, list[Any]] = {"value": [], "key": [], "bytes": []}
    _walk(value, 0, lambda kind, piece: pieces[kind].append(piece))
    hits = {kind: _hit_pieces(pieces[kind]) for kind in ("value", "key")}
    if not hits["value"] and not hits["key"] and not pieces["bytes"]:
        return value
    seen = {"value": 0, "key": 0}

    def blank(kind: str, piece: Any) -> Optional[Any]:
        if kind == "bytes":
            return crypto_secrets.SOLANA_KEY_MARKER if crypto_secrets.is_solana_secret_key(bytes(piece)) else None
        index = seen[kind]
        seen[kind] += 1
        if index not in hits[kind]:
            return None
        return crypto_secrets.SEED_PHRASE_MARKER if kind == "value" else f"{crypto_secrets.SEED_PHRASE_MARKER}#{index}"

    return _walk(value, 0, blank)


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact secrets from an arbitrary JSON-ish structure: secrets assembled
    across its pieces first (see module doc), then each string and each key on its own."""
    if depth == 0 and isinstance(value, (list, tuple, dict)):
        value = _blank_assembled_secrets(value)
    if depth > _MAX_DEPTH:
        return "[truncated-depth]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:_MAX_ITEMS]]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            key_str = sanitize_text(str(key), 200)   # a key is text an agent chose: scrubbed too (KI-377)
            if _SECRET_KEY_RE.search(key_str):
                out[key_str] = "[REDACTED]"
            elif key_str.lower() in {"content", "body", "input", "prompt"} and isinstance(child, str):
                out[key_str] = sanitize_text(child, 1200)
            else:
                out[key_str] = redact(child, depth + 1)
        return out
    return sanitize_text(str(value))
