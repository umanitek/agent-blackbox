"""Signing — the one envelope every signed Blackbox statement uses.

A kernel sub-package (the kernel folder reached its file alarm). The public API
is re-exported here, so callers keep writing ``from ..kernel import signing``
and ``signing.sign(...)`` / ``signing.verify(...)``:

* :mod:`.envelope` — the signed envelope: :func:`sign`, :func:`cosign`,
  :func:`verify` (one signer), :func:`verified_signers` (several),
  :func:`from_text`, :func:`public_key_hex`, :class:`SignedEnvelope`;
  :func:`content_id` (what was signed — the identity readers key on) and
  :func:`canonical_text` / :func:`is_canonical` (the one text a statement is written as).
* :mod:`.key_manifest` — the curator key manifest (Refine R7a): which keys may
  sign for an environment, the threshold, the pinned promotion author, the
  legacy-corpus pin. Imported as ``signing.key_manifest``; its verdict
  :class:`ManifestVerdict` (``freeze_only``: a pinned root at another epoch).
* :mod:`.graph_migration` — the root-signed graph migration (the authority
  names a successor graph): imported as ``signing.graph_migration``; its
  verdict :class:`MigrationVerdict` (``freeze_only`` as for a manifest).
* :mod:`.trust_anchors` — which roots are trusted: :class:`RootPins`
  (root epoch -> root keys per network; the sandbox override when unpinned).
* :mod:`.statement_order` — curator statement types and which statement about
  a threat is current (per-threat sequence; terminal statements dominate).
* :mod:`.promotion_statement` — the promotion statement: the verified authority's
  two-key pointer (report subject + digest) to ONE community report it
  promoted to Verified Memory; imported as ``signing.promotion_statement``.
"""

from .envelope import (
    ENVELOPE_VERSION,
    MAX_ENVELOPE_CHARS,
    MAX_SIGNATURES,
    Signature,
    SignedEnvelope,
    canonical_text,
    content_id,
    cosign,
    from_text,
    is_canonical,
    public_key_hex,
    sign,
    verified_signers,
    verify,
)

from . import authority, graph_migration, key_manifest, promotion_statement, statement_order, trust_anchors
from .graph_migration import MigrationVerdict
from .key_manifest import ManifestVerdict
from .trust_anchors import RootPins

__all__ = [
    "ENVELOPE_VERSION",
    "MAX_ENVELOPE_CHARS",
    "MAX_SIGNATURES",
    "ManifestVerdict",
    "MigrationVerdict",
    "RootPins",
    "Signature",
    "SignedEnvelope",
    "authority",
    "canonical_text",
    "content_id",
    "cosign",
    "from_text",
    "graph_migration",
    "is_canonical",
    "key_manifest",
    "promotion_statement",
    "public_key_hex",
    "sign",
    "statement_order",
    "trust_anchors",
    "verified_signers",
    "verify",
]
