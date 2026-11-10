"""The curator key manifest — which keys may sign what, per environment (Refine R7a).

A key manifest is a statement signed by the curator ROOT that lists, for ONE
environment (DKG network id) and ONE verified graph:

* the curator keys, the OPERATOR running each one, and the threshold a
  statement needs (2-of-3 — one key is neither enough nor a veto, KI-134). A
  quorum counts at most one key per listed operator, so two keys run by one
  organisation never make "two agree", and the threshold sits inside
  :data:`THRESHOLD_FLOOR_BY_OPERATORS`;
* the pinned PROMOTION AUTHOR — the only publisher whose verified rows count
  (KI-106);
* a content-hash pin over the LEGACY verified assets (the corpus published
  before signed statements existed), which grandfathers them so requiring
  signatures never un-serves the existing corpus (KI-118).

Manifests are ordered by ``(root_epoch, version)`` compared as a pair, so a
root rotation can reset a version counter that was pushed to its maximum.
A list that only NARROWS its predecessor (:meth:`KeyManifest.narrows` — one
key removed, nothing else loosened) may take effect without the waiting
period; that reader rule lives in ``community/trust`` (T1).
Curator keys are per environment: a key in the sandbox manifest is not a key
in the mainnet manifest, and statements are signed for one environment only,
so a sandbox signature can never count on mainnet (KI-143).

This module is the FORMAT: build, sign, parse and check a manifest, and ask
whether a statement meets its quorum. A verified manifest comes back as a
:class:`ManifestVerdict`: a root pinned for ANOTHER epoch yields
``freeze_only`` — it may conflict, never be acted on. Which manifest a reader
trusts (the time-lock, freezes) is reader policy (R7b).

Pattern: Value Objects (:class:`KeyManifest`, :class:`ManifestVerdict`) + pure functions.

Usage::

    from ..kernel.signing import key_manifest, trust_anchors
    manifest = key_manifest.KeyManifest(environment=net, graph=vm_graph, chain="base:8453",
        root_epoch=1, version=1, threshold=2,
        **key_manifest.roster({a: "Umanitek", b: "Umoja Ark", c: "Umanitek"}),   # curator_keys + curator_operators
        promotion_author="0x...", legacy_assets_hash=key_manifest.legacy_assets_hash(uals))
    envelope = key_manifest.sign_manifest(manifest, root_private_key)
    verdict = key_manifest.verify_manifest(envelope, environment=net, graph=vm_graph,
                                           roots=trust_anchors.RootPins.for_environment(net))
    if verdict is not None and not verdict.freeze_only:
        verdict.manifest.has_quorum(statement, statement_type="blackbox.promotion")   # True for a+b or b+c, never a+c
"""

from __future__ import annotations

import hashlib
import re
from datetime import date, timedelta
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import threat_ids
from . import envelope as signing
from .trust_anchors import RootPins

#: The statement type of a key manifest (signed by the root).
KEY_MANIFEST_STATEMENT = "blackbox.key-manifest"
#: The fewest keys a curator statement may need (one key is never enough).
MIN_THRESHOLD = 2
#: The ``promotion_author`` of a COMMUNITY-authority manifest: that authority
#: never promotes into a verified graph, so no publisher is pinned.
NO_PROMOTION_AUTHOR = "none"
#: The most curator keys one manifest may list (the envelope caps signatures).
MAX_CURATOR_KEYS = 8
#: R7b: a dated manifest is valid this long, and takes effect this long after its day (the time-lock).
MANIFEST_VALID_DAYS = 60
#: How many days a widened list waits before readers act on it. ZERO = no wait:
#: a new list counts the moment a reader reads it (founder decision 2026-10-12,
#: "remove the 1 day rule; we'll add it if we need the additional security"; it
#: was 3, then 1). The whole mechanism stays in place and tested at 1 day: set a
#: positive value to bring the wait back. Read at call time, never copied at import.
MANIFEST_TIME_LOCK_DAYS = 0
#: the lowest threshold a list may carry, keyed by its distinct operators
#: (the break-glass key's operator never counts here). A count missing from the
#: table (one operator) can never make a quorum, so such a list is invalid.
THRESHOLD_FLOOR_BY_OPERATORS: Mapping[int, int] = {2: 2, 3: 2, 4: 2, 5: 3, 6: 3, 7: 4, 8: 4}
#: The longest operator name (an organisation, e.g. "Umoja Ark").
MAX_OPERATOR_LENGTH = 64


class KeyManifestError(ValueError):
    """A manifest that must not be built or trusted; the message says why."""


@dataclass(frozen=True)
class KeyManifest:
    """One environment's curator keys, signed by the root.

    ``environment`` / ``graph`` / ``chain`` — where it applies (the verified
    graph). ``root_epoch`` / ``version`` — its order. ``curator_keys`` —
    Ed25519 public keys (hex), sorted. ``curator_operators`` — parallel to
    ``curator_keys``: the organisation running each key (build both with
    :func:`roster`). ``threshold`` — how many distinct OPERATORS a curator
    statement needs. ``promotion_author`` — the pinned publisher of
    verified rows. ``legacy_assets_hash`` — sha256 pin of the grandfathered
    legacy assets (:func:`legacy_assets_hash`).
    """

    environment: str
    graph: str
    chain: str
    root_epoch: int
    version: int
    curator_keys: tuple[str, ...]
    curator_operators: tuple[str, ...]
    threshold: int
    promotion_author: str
    legacy_assets_hash: str
    #: R10b: the oldest plugin version that can read the curators' newer statements
    #: ("" = no requirement); omitted from the payload when empty, so older manifests hash the same.
    min_reader_version: str = ""
    #: R7b: the UTC day the root signed it. A manifest is STALE MANIFEST_VALID_DAYS
    #: later (raising statements freeze; reductions and existing rules keep working)
    #: and takes effect only MANIFEST_TIME_LOCK_DAYS after this day. "" = no clock.
    issued_day: str = ""
    #: R7b: a sealed break-glass curator key — its signature counts ONLY on
    #: statements that reduce enforcement (revocations, rejections). "" = none.
    break_glass_key: str = ""

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def order(self) -> tuple[int, int]:
        """``(root_epoch, version)`` — compare manifests by this pair."""
        return self.root_epoch, self.version

    def to_payload(self) -> dict[str, str]:
        """The manifest as the flat str→str payload its envelope signs."""
        return {
            "environment": self.environment,
            "graph": self.graph,
            "chain": self.chain,
            "rootEpoch": str(self.root_epoch),
            "version": str(self.version),
            "curatorKeys": ",".join(self.curator_keys),
            "curatorOperators": ",".join(self.curator_operators),
            "threshold": str(self.threshold),
            "promotionAuthor": self.promotion_author,
            "legacyAssetsHash": self.legacy_assets_hash,
            **({"minReaderVersion": self.min_reader_version} if self.min_reader_version else {}),
            **({"issuedDay": self.issued_day} if self.issued_day else {}),
            **({"breakGlassKey": self.break_glass_key} if self.break_glass_key else {}),
        }

    def content_hash(self) -> str:
        """sha256 of the canonical payload — the manifest's identity."""
        canonical = "\n".join(f"{k}={v}" for k, v in sorted(self.to_payload().items()))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def grandfathers(self, legacy_uals: Iterable[str]) -> bool:
        """True when *legacy_uals* is exactly the asset set this manifest
        grandfathered — an asset added later is not legacy and must be signed."""
        return legacy_assets_hash(legacy_uals) == self.legacy_assets_hash

    def curator_signers(self, statement: Optional[signing.SignedEnvelope], *, statement_type: str,
                        graph: Optional[str] = None) -> frozenset[str]:
        """This manifest's curator keys that validly signed *statement* for its
        environment, chain and root epoch, in *graph* (default: the manifest's
        verified graph — advisory statements live in the community graph),
        keeping at most one key per listed operator (its lowest signing key,
        so the answer is deterministic)."""
        signers = signing.verified_signers(statement, statement_type=statement_type, environment=self.environment,
                                           graph=graph or self.graph, chain=self.chain, root_epoch=self.root_epoch)
        counted: dict[str, str] = {}   # operator -> the one key counted for it
        for key, operator in zip(self.curator_keys, self.curator_operators):   # keys are sorted: lowest wins
            if key not in signers or operator in counted:
                continue
            if key == self.break_glass_key and not _reduces(statement_type):
                continue   # R7b: the break-glass key (and so its operator) only ever reduces enforcement
            counted[operator] = key
        return frozenset(counted.values())

    def has_quorum(self, statement: Optional[signing.SignedEnvelope], *, statement_type: str,
                   graph: Optional[str] = None) -> bool:
        """True when at least ``threshold`` curator keys signed *statement*
        (see :meth:`curator_signers`)."""
        return len(self.curator_signers(statement, statement_type=statement_type, graph=graph)) >= self.threshold

    def narrows(self, previous: KeyManifest) -> bool:
        """True when this list only NARROWS *previous*: the same
        environment, graph, chain, promotion author, legacy hash, minimum
        reader version and break-glass key; exactly ONE curator key removed,
        every kept key with the same operator; the threshold not lowered. Such
        a list may take effect without the waiting period (reader rule T1)."""
        if any(getattr(self, field) != getattr(previous, field) for field in _NARROWING_FIXED_FIELDS):
            return False
        before = dict(zip(previous.curator_keys, previous.curator_operators))
        after = dict(zip(self.curator_keys, self.curator_operators))
        # A relabelled operator could split one organisation into two quorum votes.
        keeps_operators = all(before.get(key) == operator for key, operator in after.items())
        return keeps_operators and len(before) - len(after) == 1 and self.threshold >= previous.threshold


#: Fields a narrowing list may not change (``narrows``).
_NARROWING_FIXED_FIELDS = ("environment", "graph", "chain", "promotion_author", "legacy_assets_hash",
                           "min_reader_version", "break_glass_key")


#: Statement types a break-glass key may sign (reduction-only; the kill-list and
#: heartbeat live elsewhere and never reduce). A correction suppresses a threat.
_REDUCING_STATEMENTS = frozenset({"blackbox.revocation", "blackbox.rejection", "blackbox.correction"})


def _reduces(statement_type: str) -> bool:
    return statement_type in _REDUCING_STATEMENTS


def manifest_clock(manifest: KeyManifest, today: str) -> tuple[str, str]:
    """R7b: ("" | "pending" | "stale", detail day). A dated manifest is PENDING
    before its time-lock ends (issued + MANIFEST_TIME_LOCK_DAYS, the day it takes effect) and
    STALE after issued + 60 d (the day it expired). Undated: ""."""
    if not manifest.issued_day:
        return "", ""
    try:
        issued = date.fromisoformat(manifest.issued_day)
    except ValueError:
        return "stale", manifest.issued_day
    effective = (issued + timedelta(days=MANIFEST_TIME_LOCK_DAYS)).isoformat()
    expires = (issued + timedelta(days=MANIFEST_VALID_DAYS)).isoformat()
    if today < effective:
        return "pending", effective
    if today > expires:
        return "stale", expires
    return "", expires


def _validate(manifest: KeyManifest) -> None:
    keys = manifest.curator_keys
    if manifest.break_glass_key and manifest.break_glass_key not in keys:
        raise KeyManifestError("the break-glass key must be one of the curator keys")
    if manifest.issued_day and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", manifest.issued_day):
        raise KeyManifestError("issued_day must be a UTC day (YYYY-MM-DD)")
    if not all(threat_ids.is_hex64(k) for k in keys):
        raise KeyManifestError("curator keys must be Ed25519 public keys (64 lower-case hex)")
    if len(set(keys)) != len(keys) or tuple(sorted(keys)) != keys:
        raise KeyManifestError("curator keys must be distinct and sorted")
    if not 1 <= len(keys) <= MAX_CURATOR_KEYS:
        raise KeyManifestError(f"a manifest lists 1-{MAX_CURATOR_KEYS} curator keys")
    _validate_operators(manifest)
    _validate_threshold(manifest)
    if manifest.root_epoch < 0 or manifest.version < 1:
        raise KeyManifestError("root_epoch must be >= 0 and version >= 1")
    if not (manifest.environment and manifest.graph and manifest.promotion_author):
        raise KeyManifestError("environment, graph and promotion author are required")
    if not threat_ids.is_hex64(manifest.legacy_assets_hash):
        raise KeyManifestError("legacy_assets_hash must be a sha256 hex digest")


def _validate_operators(manifest: KeyManifest) -> None:
    operators = manifest.curator_operators
    if not isinstance(operators, tuple) or len(operators) != len(manifest.curator_keys):
        raise KeyManifestError("curator_operators must list one operator per curator key, in key order")
    for operator in operators:
        if not (isinstance(operator, str) and operator and operator == operator.strip()
                and len(operator) <= MAX_OPERATOR_LENGTH and "," not in operator):
            raise KeyManifestError(f"each curator operator must be a non-empty name of at most {MAX_OPERATOR_LENGTH} "
                                   "characters, without commas or edge spaces")


def _validate_threshold(manifest: KeyManifest) -> None:
    # raising statements never count the break-glass key, so its operator
    # never counts toward the bound — a threshold above the operators that can
    # sign a raise would halt curation.
    operators = {operator for key, operator in zip(manifest.curator_keys, manifest.curator_operators)
                 if key != manifest.break_glass_key}
    floor = THRESHOLD_FLOOR_BY_OPERATORS.get(len(operators))
    if floor is None or not max(MIN_THRESHOLD, floor) <= manifest.threshold <= len(operators):
        raise KeyManifestError(f"threshold {manifest.threshold} is outside the table for {len(operators)} distinct "
                               "operator(s), break-glass excluded: 2 operators -> 2, 3-4 -> 2, 5-6 -> 3, 7-8 -> 4, "
                               "and never more than the operators")


def roster(curators: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
    """The ``curator_keys`` and ``curator_operators`` keyword arguments of a
    :class:`KeyManifest`, from public key hex -> operator, sorted by key::

        KeyManifest(..., **roster({key_a: "Umanitek", key_b: "Umoja Ark"}))
    """
    ordered = sorted(curators.items())
    return {"curator_keys": tuple(key for key, _ in ordered),
            "curator_operators": tuple(operator for _, operator in ordered)}


def legacy_assets_hash(uals: Iterable[str]) -> str:
    """sha256 over the sorted, de-duplicated legacy asset UALs (one per line)."""
    canonical = "\n".join(sorted({str(ual).strip() for ual in uals if str(ual).strip()}))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_manifest(manifest: KeyManifest, root_key: Ed25519PrivateKey) -> signing.SignedEnvelope:
    """The manifest as a root-signed statement (its version is the sequence)."""
    return signing.sign(root_key, statement_type=KEY_MANIFEST_STATEMENT, environment=manifest.environment,
                        graph=manifest.graph, payload=manifest.to_payload(), chain=manifest.chain,
                        root_epoch=manifest.root_epoch, sequence=manifest.version)


@dataclass(frozen=True)
class ManifestVerdict:
    """A root-signed manifest and how far it may be trusted. ``freeze_only`` —
    True when the signing root is pinned, but for a different epoch: such a
    manifest may only CONFLICT with others at its order (freezing readers),
    never become the manifest they act on."""

    manifest: KeyManifest
    freeze_only: bool = False


def verify_manifest(envelope: Optional[signing.SignedEnvelope], *, environment: str, graph: str,
                    roots: RootPins) -> Optional[ManifestVerdict]:
    """The verdict when *envelope* is signed by one of *roots* for this
    environment and graph and its payload agrees with its signed domain
    fields; otherwise None. ``freeze_only`` when no signing root may sign
    the manifest's root epoch. Never raises."""
    if envelope is None:
        return None
    signers = signing.verified_signers(envelope, statement_type=KEY_MANIFEST_STATEMENT,
                                       environment=environment, graph=graph) & roots.keys
    if not signers:
        return None
    manifest = _from_payload(envelope.payload)
    if manifest is None or (manifest.environment, manifest.graph, manifest.chain, manifest.root_epoch,
                            manifest.version) != (environment, graph, envelope.chain, envelope.root_epoch,
                                                  envelope.sequence):
        return None
    return ManifestVerdict(manifest, freeze_only=not any(roots.may_sign(key, manifest.root_epoch) for key in signers))


#: Payload fields every manifest carries (the rest are optional).
_REQUIRED_PAYLOAD_FIELDS = ("environment", "graph", "chain", "rootEpoch", "version", "curatorKeys",
                            "curatorOperators", "threshold", "promotionAuthor", "legacyAssetsHash")


def parse_manifest(payload: Mapping[str, str]) -> KeyManifest:
    """The manifest a signed payload carries; raises :class:`KeyManifestError`
    saying what is missing or invalid. A manifest from before operators were
    listed (no ``curatorOperators``) is rejected: its quorum cannot be
    counted one key per operator."""
    missing = [field for field in _REQUIRED_PAYLOAD_FIELDS if field not in payload]
    if "curatorOperators" in missing:
        raise KeyManifestError("manifest payload has no curatorOperators: it predates operators per key "
                               "and must be re-signed with one operator per curator key")
    if missing:
        raise KeyManifestError(f"manifest payload is missing {', '.join(missing)}")
    try:
        root_epoch, version, threshold = int(payload["rootEpoch"]), int(payload["version"]), int(payload["threshold"])
    except (TypeError, ValueError) as exc:
        raise KeyManifestError("rootEpoch, version and threshold must be integers") from exc
    return KeyManifest(
        environment=payload["environment"], graph=payload["graph"], chain=payload["chain"],
        root_epoch=root_epoch, version=version,
        curator_keys=tuple(k for k in payload["curatorKeys"].split(",") if k),
        curator_operators=tuple(o for o in payload["curatorOperators"].split(",") if o),
        threshold=threshold, promotion_author=payload["promotionAuthor"],
        legacy_assets_hash=payload["legacyAssetsHash"], min_reader_version=str(payload.get("minReaderVersion") or ""),
        issued_day=str(payload.get("issuedDay") or ""), break_glass_key=str(payload.get("breakGlassKey") or ""),
    )


def _from_payload(payload: Mapping[str, str]) -> Optional[KeyManifest]:
    try:
        return parse_manifest(payload)
    except KeyManifestError:
        return None


def newest(manifests: Iterable[KeyManifest]) -> Optional[KeyManifest]:
    """The manifest with the highest ``(root_epoch, version)``, or None."""
    return max(manifests, key=lambda m: m.order, default=None)
