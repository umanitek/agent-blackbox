"""Signed statements — the one envelope every signed Blackbox statement uses.

Why this exists: who wrote a community report must come from a signature,
never from a field the writer fills in (LES-014). The DKG's own authorship
signals are unchecked on some delivery routes (LES-017, KI-102), so each
statement carries its author's signature INSIDE it, and a reader believes it
only after checking.

What is signed: one canonical byte string built from the DOMAIN fields —
statement ``type``, ``environment`` (the DKG network id), ``graph`` (the
context graph it belongs to), ``chain`` (the chain id), ``root_epoch`` (the
curator root's epoch), ``sequence`` (the per-threat sequence number) and
``schema_version`` — plus the payload. A signature made for one type,
environment, graph, chain, epoch or sequence can never be replayed as
another (KI-143). Reporter statements leave chain / epoch / sequence at
their defaults; curator statements (Refine R7a) set them.

One statement, one or more signatures: every signer signs the SAME bytes, so
a curator statement is built by one key (:func:`sign`) and completed by a
second (:func:`cosign`). How many valid signers a statement needs, and which
keys count, is the key manifest's job (:mod:`.key_manifest`), not this
module's. There is only ever this ONE envelope format (KI-171).

Algorithm: Ed25519 (``cryptography``, a pinned core dependency). A signer is
named by its raw public key (hex).

Pattern: Value Object (:class:`SignedEnvelope`) + pure sign/verify functions.

Usage::

    from ..kernel import signing          # the package re-exports this module's API
    envelope = signing.sign(private_key, statement_type="blackbox.report",
                            environment="sim", graph=graph_id,
                            payload={"identifier": "ioc:domain:x.example"})
    text = envelope.to_text()                 # store as one literal
    parsed = signing.from_text(text)          # None when malformed
    signer = signing.verify(parsed, statement_type="blackbox.report",
                            environment="sim", graph=graph_id)   # hex key | None

    # A two-key curator statement:
    statement = signing.cosign(signing.sign(key_a, ..., chain="base:8453",
                                            root_epoch=1, sequence=7), key_b)
    signers = signing.verified_signers(statement, statement_type=..., environment=...,
                                       graph=..., chain="base:8453", root_epoch=1)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: Bumped when the canonical encoding below changes; old signatures then fail.
#: 2 = Refine R7a (chain, root epoch, per-threat sequence; several signatures).
ENVELOPE_VERSION = 2
#: Domain tag prefixed to every signed message, so these signatures can never
#: be confused with any other Ed25519 use of the same key.
_DOMAIN_TAG = b"blackbox-signed-statement\n"
#: Hard cap on a serialized envelope (it travels as one graph literal, and
#: oversized literals break peers' sync — see kernel.rdf_terms).
MAX_ENVELOPE_CHARS = 4096
#: Most signatures one statement may carry (2-of-3 curators + a root co-sign).
MAX_SIGNATURES = 4
_PUBLIC_KEY_HEX_CHARS = 64
_SIGNATURE_HEX_CHARS = 128


@dataclass(frozen=True)
class Signature:
    """One signer's signature: ``signer`` (public key, 64 hex) and ``value`` (128 hex)."""

    signer: str
    value: str


@dataclass(frozen=True)
class SignedEnvelope:
    """One signed statement.

    Domain fields (all signed): ``statement_type``, ``environment``,
    ``graph``, ``chain``, ``root_epoch``, ``sequence``, ``schema_version``.
    ``payload`` — flat str→str mapping, the statement itself. ``signatures``
    — one or more :class:`Signature` over the same bytes, sorted by signer.
    Build with :func:`sign` / :func:`cosign`; never trust a signer before
    :func:`verify` / :func:`verified_signers`.
    """

    statement_type: str
    environment: str
    graph: str
    schema_version: int
    payload: Mapping[str, str]
    signatures: tuple[Signature, ...]
    chain: str = ""
    root_epoch: int = 0
    sequence: int = 0

    @property
    def signers(self) -> tuple[str, ...]:
        """The CLAIMED signers, in order (unverified)."""
        return tuple(signature.signer for signature in self.signatures)

    def to_text(self) -> str:
        """The envelope as compact JSON — the form stored in the graph."""
        document = _domain_document(self)
        document["sigs"] = [{"signer": s.signer, "sig": s.value} for s in self.signatures]
        return canonical_json(document)


def canonical_json(value: Any) -> str:
    """*value* as THE text that is hashed or signed: keys sorted, no spaces, ASCII only (anything
    else escaped). The same value is the same bytes on every node — so this spelling is
    written once; a digest or a signature made from another spelling would not verify.

    Usage: ``hashlib.sha256(canonical_json(payload).encode("ascii"))``."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _domain_document(envelope: SignedEnvelope) -> dict[str, Any]:
    return {
        "v": ENVELOPE_VERSION,
        "type": envelope.statement_type,
        "env": envelope.environment,
        "graph": envelope.graph,
        "chain": envelope.chain,
        "epoch": envelope.root_epoch,
        "seq": envelope.sequence,
        "schema": envelope.schema_version,
        "payload": dict(envelope.payload),
    }


def _signed_message(envelope: SignedEnvelope) -> bytes:
    """The exact bytes every signature covers: domain tag + canonical JSON."""
    return _DOMAIN_TAG + canonical_json(_domain_document(envelope)).encode("ascii")


def content_id(envelope: SignedEnvelope) -> str:
    """The identity of WHAT was signed: sha256 (hex) of the exact bytes every
    signature covers. One statement can be written as many texts that all
    verify (other spacing or key order, an ignored extra key, upper-case hex,
    more or fewer signatures) and anyone can publish such copies without a
    key — so a reader that counts, stores or de-duplicates statements keys on
    this, never on the text (KI-266)."""
    return hashlib.sha256(_signed_message(envelope)).hexdigest()


def canonical_text(envelope: SignedEnvelope) -> str:
    """*envelope* written the ONE canonical way: compact sorted JSON, its
    signatures in lower-case hex, one per signer (the first given), sorted by
    signer. A copy that differs from a statement only in how it is written
    comes back as the statement's original text. The result is as UNVERIFIED
    as any text — verify it before relying on it."""
    first: dict[str, Signature] = {}
    for signature in envelope.signatures:
        first.setdefault(signature.signer.lower(), Signature(signature.signer.lower(), signature.value.lower()))
    return replace(envelope, signatures=tuple(first[signer] for signer in sorted(first))).to_text()


def is_canonical(text: str) -> bool:
    """True when *text* is exactly its own canonical form. Parsing accepts
    more than that; a file in which every byte must matter (an export bundle)
    accepts only this."""
    envelope = from_text(text)
    return envelope is not None and canonical_text(envelope) == text


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    """The signer name for *private_key*: its raw public key as hex."""
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign(private_key: Ed25519PrivateKey, *, statement_type: str, environment: str, graph: str,
         payload: Mapping[str, str], schema_version: int = 1, chain: str = "", root_epoch: int = 0,
         sequence: int = 0) -> SignedEnvelope:
    """Sign *payload* for one statement domain (one signature).

    Raises ``ValueError`` when the payload is not a flat str→str mapping, an
    epoch or sequence is negative, or the serialized envelope would exceed
    :data:`MAX_ENVELOPE_CHARS`.
    """
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in payload.items()):
        raise ValueError("payload must map str to str")
    if root_epoch < 0 or sequence < 0:
        raise ValueError("root_epoch and sequence must be non-negative")
    unsigned = SignedEnvelope(statement_type=statement_type, environment=environment, graph=graph,
                              schema_version=schema_version, payload=dict(payload), signatures=(),
                              chain=chain, root_epoch=root_epoch, sequence=sequence)
    return cosign(unsigned, private_key)


def cosign(envelope: SignedEnvelope, private_key: Ed25519PrivateKey) -> SignedEnvelope:
    """*envelope* with one more signature over the same bytes.

    Raises ``ValueError`` when this key already signed it, the statement would
    exceed :data:`MAX_SIGNATURES`, or the envelope would grow past
    :data:`MAX_ENVELOPE_CHARS`.
    """
    signer = public_key_hex(private_key)
    if signer in envelope.signers:
        raise ValueError("this key already signed the statement")
    if len(envelope.signatures) >= MAX_SIGNATURES:
        raise ValueError(f"a statement carries at most {MAX_SIGNATURES} signatures")
    added = Signature(signer=signer, value=private_key.sign(_signed_message(envelope)).hex())
    signed = replace(envelope, signatures=tuple(sorted((*envelope.signatures, added), key=lambda s: s.signer)))
    if len(signed.to_text()) > MAX_ENVELOPE_CHARS:
        raise ValueError(f"signed envelope exceeds {MAX_ENVELOPE_CHARS} characters")
    return signed


def from_text(text: str) -> Optional[SignedEnvelope]:
    """Parse a stored envelope; None for anything malformed or oversized.

    Untrusted input (LES-001/002): size-capped first, then strict shape checks.
    Parsing does NOT verify — call :func:`verify` / :func:`verified_signers`.
    """
    if not isinstance(text, str) or len(text) > MAX_ENVELOPE_CHARS:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("v") != ENVELOPE_VERSION:
        return None
    payload, sigs = data.get("payload"), data.get("sigs")
    if not all(isinstance(data.get(k), str) for k in ("type", "env", "graph", "chain")):
        return None
    if not all(isinstance(data.get(k), int) and not isinstance(data.get(k), bool) for k in ("schema", "epoch", "seq")):
        return None
    if not isinstance(payload, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in payload.items()):
        return None
    if not isinstance(sigs, list) or not 1 <= len(sigs) <= MAX_SIGNATURES:
        return None
    if not all(isinstance(s, dict) and isinstance(s.get("signer"), str) and isinstance(s.get("sig"), str) for s in sigs):
        return None
    return SignedEnvelope(
        statement_type=data["type"], environment=data["env"], graph=data["graph"],
        schema_version=data["schema"], payload=payload,
        signatures=tuple(Signature(signer=s["signer"], value=s["sig"]) for s in sigs),
        chain=data["chain"], root_epoch=data["epoch"], sequence=data["seq"],
    )


def _valid(signature: Signature, message: bytes) -> bool:
    """Whether one signature checks out. Never raises."""
    if len(signature.signer) != _PUBLIC_KEY_HEX_CHARS or len(signature.value) != _SIGNATURE_HEX_CHARS:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature.signer)).verify(bytes.fromhex(signature.value), message)
    except (ValueError, InvalidSignature):
        return False
    return True


def verified_signers(envelope: Optional[SignedEnvelope], *, statement_type: str, environment: str, graph: str,
                     chain: Optional[str] = None, root_epoch: Optional[int] = None) -> frozenset[str]:
    """Every distinct signer (hex, lower-case) whose signature is valid for
    exactly this statement type, environment and graph — and this chain /
    root epoch when given. Empty when nothing verifies. Never raises."""
    if envelope is None:
        return frozenset()
    if (envelope.statement_type, envelope.environment, envelope.graph) != (statement_type, environment, graph):
        return frozenset()
    if (chain is not None and envelope.chain != chain) or (root_epoch is not None and envelope.root_epoch != root_epoch):
        return frozenset()
    message = _signed_message(envelope)
    return frozenset(s.signer.lower() for s in envelope.signatures if _valid(s, message))


def verify(envelope: Optional[SignedEnvelope], *, statement_type: str, environment: str,
           graph: str) -> Optional[str]:
    """The signer (hex) of a SINGLE-signer statement — a report, dispute or
    retraction — when its one signature is valid for exactly this type,
    environment and graph; otherwise None (including any statement with more
    than one signature: reporter statements are never co-signed)."""
    if envelope is None or len(envelope.signatures) != 1:
        return None
    signers = verified_signers(envelope, statement_type=statement_type, environment=environment, graph=graph)
    return next(iter(signers), None)
