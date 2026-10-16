"""Curator statements on the wire — build, sign, and parse (Refine R2).

The curator's verdicts and notices — confirmation, rejection, revocation,
in-review, deferral-lapsed, backlog, away, the Phase 1 counted-author
list and the Phase 2 stage attestation (R3-attest: ``{stage}``) — travel as ONE kind of graph asset: a ``g:CuratorStatement`` subject
carrying the threat identifier and a signed envelope (:mod:`..kernel.signing`).
Everything a reader acts on is inside the SIGNED payload; the one shown field
(the identifier) must agree with it.

Each statement type has a CLOSED payload schema (exact key set, closed
values). The reduction-only ones — revocation and rejection — use
:data:`REDUCTION_SCHEMA`, frozen forever, so every reader version accepts them
(asymmetric safety, LES-016). A statement counts only when the trusted key
manifest's curator keys signed it: the full threshold for statements that
need it (2-of-3 — promotion, rejection, revocation, the counted-author list,
anything raising enforcement; KI-134), one curator key for in-review,
deferral-lapsed and away notices.

Every statement is a NEW asset: its subject includes the per-identifier
sequence number, so nothing is ever re-shared at the same version (KI-103);
"latest" is decided by sequence (:mod:`..kernel.signing.statement_order`).

Pattern: Value Object (:class:`CuratorRecord`) with paired build / parse
functions, and a Strategy table of per-type payload validators.

Usage (curator side, R6)::

    envelope = curator_statements.sign_statement(CuratorStatement.REVOCATION, "dep:npm:x@1",
        sequence=4, fields={"reason": "false-positive"}, key=key_a, manifest=manifest, graph=vm_graph)
    envelope = signing.cosign(envelope, key_b)
    quads = curator_statements.statement_quads(envelope)

Usage (reader side)::

    record = curator_statements.parse_statement(row, manifest, graph=vm_graph)   # None = ignore
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timezone, UTC
from typing import AbstractSet, Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ...kernel import constants, rdf_terms, signing, sparql_text, threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.signing.key_manifest import KeyManifest
from ...kernel.signing.statement_order import CuratorStatement
from .. import report_schema

#: The frozen payload schema of reduction-only statements (revocation,
#: rejection): every reader version must accept it, forever. Never edit.
REDUCTION_SCHEMA = frozenset({"identifier", "reason", "day"})

_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_LANES = frozenset({"1", "2", "3", "4", "5"})

#: The reader variable carrying the envelope.
SIGNED_STATEMENT_VAR = "signedStatement"


@dataclass(frozen=True)
class CuratorRecord:
    """One VERIFIED curator statement.

    ``kind`` — its :class:`CuratorStatement`; ``identifier`` — the threat
    (or ``author:<reporter key hex>`` for a counted-author entry, ``curator``
    for backlog / away); ``sequence`` — the signed per-identifier sequence; ``day`` — the
    signed UTC day; ``fields`` — the validated payload extras, sorted;
    ``signers`` — the manifest curator keys that signed it.
    """

    kind: CuratorStatement
    identifier: str
    sequence: int
    day: str
    fields: tuple[tuple[str, str], ...]
    signers: frozenset[str]

    def field(self, name: str) -> str:
        return dict(self.fields).get(name, "")


# -- per-type payload validators (Strategy table): extras in -> extras out, or None


def _reason_from(allowed: tuple[str, ...]) -> Callable[[Mapping[str, str]], Optional[dict[str, str]]]:
    def check(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
        reason = extras.get("reason", "")
        return {"reason": reason} if set(extras) == {"reason"} and reason in allowed else None
    return check


def _no_extras(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    return {} if not extras else None


#: What a curator checked before confirming (Community Curation, plan §08): a
#: public advisory id, a registry's own action (its URL), or the sha256 of an
#: artifact the curator reproduced. A CLOSED format — nothing else is an
#: evidence reference, and a URL may hold URL characters only.
EVIDENCE_REFERENCE = re.compile(
    r"(advisory:[A-Za-z0-9._-]{3,64}"
    r"|registry-action:https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{5,200}"
    r"|reproduced:[0-9a-f]{64})")


def _confirmation(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    """No extras, or exactly one signed evidence reference. The COMMUNITY
    authority's confirmations count only with one (``curator_view``); the
    verified authority's carry one when its curators give it (the curator
    service always does) and count either way. Only readers of the one graph
    read them, and every one of those accepts the reference."""
    if not extras:
        return {}
    ok = set(extras) == {"evidence"} and bool(EVIDENCE_REFERENCE.fullmatch(extras["evidence"]))
    return dict(extras) if ok else None


def _days(*names: str) -> Callable[[Mapping[str, str]], Optional[dict[str, str]]]:
    def check(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
        ok = set(extras) == set(names) and all(_DAY.fullmatch(extras[n]) for n in names)
        return dict(extras) if ok else None
    return check


#: Stages a curator may attest (R3-attest). Terminal ones travel as verdicts
#: (rejection / revocation) and dominate any attestation; EXPIRED is the
#: reader's own clock. Mirrors community.stages.Stage without importing it
#: (statements must not depend on the stage machine).
ATTESTABLE_STAGES = frozenset({"reported", "held", "corroborated", "deferred"})


def _attested_stage(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    return dict(extras) if set(extras) == {"stage"} and extras["stage"] in ATTESTABLE_STAGES else None


#: R7b (plan §09): a pause lasts at most this long after its signed day.
PAUSE_MAX_DAYS = 7


def _pause(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    return _days("until")(extras)


#: A counted-author listing may run this long from its signed day.
LISTING_MAX_DAYS = 366


def _within_days(day: str, until: str, limit: int) -> bool:
    try:
        return (date.fromisoformat(until) - date.fromisoformat(day)).days <= limit
    except ValueError:
        return False


def _pause_within_limit(day: str, until: str) -> bool:
    try:
        return (date.fromisoformat(until) - date.fromisoformat(day)).days <= PAUSE_MAX_DAYS
    except ValueError:
        return False


def _backlog(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    lanes = extras.get("lanes", "").split(",")
    ok = set(extras) == {"lanes", "until"} and bool(lanes) and set(lanes) <= _LANES and _DAY.fullmatch(extras["until"])
    return dict(extras) if ok else None


def _heartbeat(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    return dict(extras) if set(extras) == {"key"} and _KEY_HEX.fullmatch(extras["key"]) else None


def _away(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    ok = (set(extras) == {"key", "from", "until"} and _KEY_HEX.fullmatch(extras["key"])
          and _DAY.fullmatch(extras["from"]) and _DAY.fullmatch(extras["until"]))
    return dict(extras) if ok else None


def _counted_author(extras: Mapping[str, str]) -> Optional[dict[str, str]]:
    """One counted-author entry: listed yes/no, class, org (partners), expiry,
    and the agent address the key belongs to (display only — the identity is
    the reporter KEY in the identifier, LES-014)."""
    keys = {"listed", "class", "org", "expires", "address"}
    if set(extras) != keys or extras["listed"] not in ("yes", "no") or not _DAY.fullmatch(extras["expires"]):
        return None
    if not _ADDRESS.fullmatch(extras["address"]):
        return None
    if extras["class"] not in constants.COUNTED_AUTHOR_CLASSES:
        return None
    if extras["class"] == "partner" and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", extras["org"]):
        return None   # all of an organisation's keys share one cluster, so a partner names its org
    return dict(extras)


_VALIDATORS: dict[CuratorStatement, Callable[[Mapping[str, str]], Optional[dict[str, str]]]] = {
    CuratorStatement.REVOCATION: _reason_from(constants.REVOCATION_REASONS),
    CuratorStatement.REJECTION: _reason_from(constants.REJECTION_REASONS),
    CuratorStatement.CONFIRMATION: _confirmation,
    CuratorStatement.ATTESTATION: _attested_stage,
    CuratorStatement.IN_REVIEW: _no_extras,
    CuratorStatement.DEFERRAL: _no_extras,
    CuratorStatement.DEFERRAL_LAPSED: _no_extras,
    CuratorStatement.PAUSE: _pause,
    CuratorStatement.BACKLOG: _backlog,
    CuratorStatement.AWAY: _away,
    CuratorStatement.HEARTBEAT: _heartbeat,
    CuratorStatement.COUNTED_AUTHORS: _counted_author,
}


def _identifier_ok(kind: CuratorStatement, identifier: str) -> bool:
    if kind is CuratorStatement.COUNTED_AUTHORS:   # "author:<reporter key>" — the signer, never a claimed address
        return identifier.startswith("author:") and bool(_KEY_HEX.fullmatch(identifier[len("author:"):]))
    if kind in (CuratorStatement.BACKLOG, CuratorStatement.AWAY, CuratorStatement.PAUSE, CuratorStatement.HEARTBEAT):
        return identifier == "curator"
    try:
        return report_schema.validate_statement_identifier(identifier) == identifier
    except report_schema.ReportValidationError:
        return False


def _validated_payload(kind: CuratorStatement, payload: Mapping[str, str]) -> Optional[tuple[str, str, dict[str, str]]]:
    """(identifier, day, extras) when *payload* meets its type's closed schema."""
    if kind is CuratorStatement.PROMOTION:
        return None   # promotions are written in the verified-rule vocabulary (R6), not here
    identifier, day = payload.get("identifier", ""), payload.get("day", "")
    if not _identifier_ok(kind, identifier) or not _DAY.fullmatch(day):
        return None
    extras = _VALIDATORS[kind]({k: v for k, v in payload.items() if k not in ("identifier", "day")})
    if extras is not None and kind is CuratorStatement.PAUSE and not _pause_within_limit(day, extras["until"]):
        return None   # R7b: a pause lasts ≤ 7 days; a longer one is not a valid statement
    if extras is not None and kind is CuratorStatement.COUNTED_AUTHORS and not _within_days(day, extras["expires"], LISTING_MAX_DAYS):
        return None   # round 4: a listing lasts ≤ 12 months (DPIA §2), enforced by every reader
    return None if extras is None else (identifier, day, extras)


# -- build (curator side) ----------------------------------------------------


def sign_statement(kind: CuratorStatement, identifier: str, *, sequence: int, fields: Mapping[str, str],
                   key: Ed25519PrivateKey, manifest: KeyManifest, graph: str,
                   day: Optional[date] = None) -> signing.SignedEnvelope:
    """The first signature on a curator statement (co-sign with
    :func:`..kernel.signing.cosign`). Raises ``ValueError`` for a payload that
    does not meet the type's closed schema."""
    when = (day or datetime.now(UTC).date()).isoformat()
    payload = {"identifier": identifier, "day": when, **dict(fields)}
    if _validated_payload(kind, payload) is None:
        raise ValueError(f"not a valid {kind.value} statement")
    return signing.sign(key, statement_type=kind.value, environment=manifest.environment, graph=graph,
                        payload=payload, chain=manifest.chain, root_epoch=manifest.root_epoch, sequence=sequence)


def statement_subject(kind: CuratorStatement, identifier: str, sequence: int) -> str:
    """``urn:guardian:curator:<type>:<identifier hash>:<sequence>`` — a new
    asset per statement (never a same-version re-share)."""
    return f"urn:guardian:curator:{kind.value.split('.', 1)[1]}:{threat_ids.stable_hash(identifier, 24)}:{sequence}"


def statement_quads(envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
    """The graph quads for a signed curator statement."""
    kind = CuratorStatement(envelope.statement_type)
    identifier = envelope.payload["identifier"]
    subject = statement_subject(kind, identifier, envelope.sequence)
    return [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.CURATOR_STATEMENT_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.IDENTIFIER_PRED, rdf_terms.literal(identifier)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]


def row_for_signed(text: str) -> Optional[dict[str, str]]:
    """The graph row a signed curator statement is published as, rebuilt from
    its TEXT alone (an export bundle holds texts, not rows) — None unless the
    text is a statement in the exact canonical form :func:`statement_quads`
    writes. Still UNVERIFIED: pass it to :func:`parse_statement`."""
    envelope = signing.from_text(text) if isinstance(text, str) and signing.is_canonical(text) else None
    if envelope is None:
        return None
    try:
        kind = CuratorStatement(envelope.statement_type)
    except ValueError:
        return None
    identifier = str(envelope.payload.get("identifier", ""))
    return {"r": statement_subject(kind, identifier, envelope.sequence), "identifier": identifier,
            SIGNED_STATEMENT_VAR: text}


def manifest_quads(envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
    """The graph quads for a root-signed key manifest (published in the
    verified graph): subject ``urn:guardian:key-manifest:<root epoch>:<version>``,
    a new asset per manifest."""
    subject = f"urn:guardian:key-manifest:{envelope.root_epoch}:{envelope.sequence}"
    return [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.KEY_MANIFEST_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]


# -- parse (reader side) -----------------------------------------------------


def parse_statement(row: Mapping[str, Any], manifest: Optional[KeyManifest], *, graph: str,
                    root_keys: AbstractSet[str] = frozenset(), curators_silent: bool = False) -> Optional[CuratorRecord]:
    """The verified curator statement in *row*, or None to ignore it.

    None without a trusted *manifest*, for an unknown type, a payload outside
    its closed schema, a shown identifier that disagrees with the signed one,
    a subject that is not the statement's own, or too few curator signatures
    (the full threshold for statements that raise enforcement). Never raises.
    """
    if manifest is None:
        return None
    envelope = signing.from_text(extract_binding(row.get(SIGNED_STATEMENT_VAR)))
    if envelope is None:
        return None
    try:
        kind = CuratorStatement(envelope.statement_type)
    except ValueError:
        return None
    validated = _validated_payload(kind, envelope.payload)
    if validated is None:
        return None
    identifier, day, extras = validated
    shown = (extract_binding(row.get("r")), extract_binding(row.get("identifier")).strip())
    if shown != (statement_subject(kind, identifier, envelope.sequence), identifier):
        return None
    signers = manifest.curator_signers(envelope, statement_type=kind.value, graph=graph)
    needed = manifest.threshold if kind.needs_quorum else 1
    if len(signers) < needed and not _root_alone_reduction(envelope, kind, manifest, graph, root_keys, curators_silent):
        return None
    return CuratorRecord(kind=kind, identifier=identifier, sequence=envelope.sequence, day=day,
                         fields=tuple(sorted(extras.items())), signers=signers)


def _root_alone_reduction(envelope: signing.SignedEnvelope, kind: CuratorStatement, manifest: KeyManifest, graph: str,
                          root_keys: AbstractSet[str], curators_silent: bool) -> bool:
    """R7b asymmetric safety: when no curator key has heartbeated for 7 days, the
    offline root alone may sign a REDUCTION (revocation, rejection) — never anything else."""
    if not curators_silent or not kind.terminal or not root_keys:
        return False
    signers = signing.verified_signers(envelope, statement_type=kind.value, environment=manifest.environment, graph=graph,
                                       chain=manifest.chain, root_epoch=manifest.root_epoch)
    return bool(signers & {k.lower() for k in root_keys})


def curator_statements_sparql(after: str) -> str:
    """One page of curator statements after the subject cursor *after*."""
    cursor = f"FILTER(STR(?r) > {sparql_text.sparql_string_literal(after)})" if after else ""
    return f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?r ?identifier ?signedStatement WHERE {{
  ?r a g:CuratorStatement ;
     g:identifier ?identifier ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 5000
"""

