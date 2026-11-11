"""Signature reconciler — statements published under this node's key vs its signing log.

Every signature this node's keys make is recorded by the signing choke point
(``CurateContext.sign`` / ``.cosign``) in the :class:`.SigningLog`. A statement
published under one of this node's keys that the log does not hold was signed
somewhere else, so it is a SECURITY item. What this cannot see: a host where
the log itself is written by whoever holds the key — the other node's watch
covers that case.

A pure comparison: the caller reads the published statements (the graph) and
hands in the log as a reader; nothing here touches a file or the network.

Usage::

    items = reconcile(SigningLog(), [PublishedStatement(kind, digest, key), ...])
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol, Sequence

from ...kernel.health import HealthClass, HealthItem
from .signing_log import SigningRow

_CURATOR = "curator"
#: Alarm text names a key by this many leading hex characters, never more.
KEY_FINGERPRINT_CHARS = 16


class SigningRecords(Protocol):
    """Anything that yields this node's signing rows (``SigningLog`` does)."""

    def rows(self) -> Sequence[SigningRow]: ...


@dataclass(frozen=True)
class PublishedStatement:
    """One statement read from a graph that carries a signature by ``key``.
    ``kind`` — its statement type; ``digest`` — ``signing.content_id`` of the
    signed bytes (the same identity the signing log records); ``key`` — the
    signer's public key (hex), one of this node's keys."""

    kind: str
    digest: str
    key: str


def key_fingerprint(key: str) -> str:
    """The short form of a public key that alarm text may name."""
    return key[:KEY_FINGERPRINT_CHARS]


def reconcile(signing_log: SigningRecords, published_under_my_key: Iterable[PublishedStatement]) -> list[HealthItem]:
    """One SECURITY item per key that has published statements its log lacks.

    A statement is explained when the log holds a row with the same digest
    signed by the same key (a first signature or a co-signature). The item
    names the key fingerprint, the count and the statement kinds — never a
    statement's content."""
    signed = {(row.digest, row.key.lower()) for row in signing_log.rows()}
    unexplained: dict[str, dict[str, str]] = {}  # key -> {digest: kind}
    for statement in published_under_my_key:
        key = statement.key.lower()
        if (statement.digest, key) not in signed:
            unexplained.setdefault(key, {})[statement.digest] = statement.kind
    return [_unexplained_signature_item(key, kinds_by_digest) for key, kinds_by_digest in sorted(unexplained.items())]


def _unexplained_signature_item(key: str, kinds_by_digest: dict[str, str]) -> HealthItem:
    kinds = ", ".join(sorted(set(kinds_by_digest.values())))
    return HealthItem(
        _CURATOR, HealthClass.SECURITY,
        f"{len(kinds_by_digest)} statement(s) published under key {key_fingerprint(key)} are not in this node's "
        f"signing log ({kinds}) — the key was used somewhere else",
        "treat the key as compromised: stop using it and replace it from the key console",
    )
