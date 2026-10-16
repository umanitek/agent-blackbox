"""Row builders — the quads a quorum-signed promotion is written as (§03.4; the curator-asset way).

Pattern: Strategy registry. One :class:`RowBuilder` per promotable threat
category (D3: every listable type is promotable), keyed by the identifier's
prefix as ``kernel/threat_ids`` names it — ``dep``, ``ioc``, ``skill``,
``injection``, ``fileaccess``. Each writes the corpus's EXISTING shape for its
type, so the verified reader needs no second vocabulary:

* ``dep`` — ``urn:defender:DependencySignal``, located by the live lookup
  through ``dp:package`` / ``dp:ecosystem`` / ``dp:version``;
* ``ioc`` — ``urn:defender:IocSignal`` with ``dp:iocType`` / ``dp:value``;
* ``skill`` / ``injection`` / ``fileaccess`` — a legacy ``g:identifier`` rule
  (skill name/version/shape; the pattern; tool name and category), the shape
  the reader's legacy lane compiles. Deliberately NOT typed ``SkillSignal`` /
  ``InjectionSignal``: for a typed row the reader also derives an identifier
  from the subject's last ``:`` segment, which for a ``threat_uri`` subject is
  a second, bogus rule (``injection:injection-<hash>``) a revocation by the
  real identifier would never reach.

Every row carries ``SIGNED_STATEMENT_PRED``: the ``blackbox.promotion``
envelope whose flat payload (:func:`promotion_payload`) names the rule —
identifier, severity, kind, ecosystem, package name/version — and its
provenance: the community report it was made from (subject, digest, reporter
key — ``kernel.signing.promotion_statement``), never a random id. The reader
builds a BLOCK-tier rule from that payload, never from the row, so a builder
refuses an envelope whose payload disagrees with the entry it is asked to
write. Rows written before the report was the provenance (random ids) are read
the same way: the reader never reads the provenance. No report carries an
injection's pattern (only its hash), so an injection is never promoted from a
report; its builder writes only an entry that holds the pattern. Evidence is
capped at :data:`EVIDENCE_MAX_BYTES` (F-017) and every literal stays under
``kernel/rdf_terms``' cap. A correction (P5) is not a category:
:func:`correction_payload` / :func:`correction_quads` write its
``CorrectionSignal`` rows (its shared-memory twin: ``publish.advisory_twin``).

Usage::

    payload = row_builders.promotion_payload(entry)                    # what the curators sign
    envelope = ctx.cosign(ctx.sign(PromotionDraft(payload, sequence=n), key_a), key_b)
    quads = row_builders.ROW_BUILDERS[entry.category].quads(entry, envelope)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from ...kernel import constants, rdf_terms, signing, threat_ids
from ...kernel.signing import promotion_statement as statement
from ...kernel.signing.statement_order import CuratorStatement
from ..context import CORRECTION_STATEMENT

#: The statement type every promoted row's envelope must carry.
PROMOTION_STATEMENT = CuratorStatement.PROMOTION.value
#: Evidence written per entry, in UTF-8 bytes (F-017: bounds batch size, so cost).
EVIDENCE_MAX_BYTES = 2048
_EVIDENCE_TRUNCATION_MARKER = " ...[truncated]"
#: The payload fields that NAME the rule; the row must agree with the signed ones.
SIGNED_RULE_FIELDS = ("identifier", "severity", "kind", "ecosystem", "packageName", "packageVersion")
#: The keys of a curator-asset promotion's payload (:func:`promotion_payload`).
PAYLOAD_KEYS = frozenset({*SIGNED_RULE_FIELDS, "advisoryId", "name", "report", "reportDigest", "reporterKey"})
_DEFENDER_PREDICATE = "urn:defender:p:"
_IOC_SIGNAL_TYPE = "urn:defender:IocSignal"


class RowBuildError(ValueError):
    """A promotion that must not be written: the message says why."""


@dataclass(frozen=True)
class ConfirmedEntry:
    """One quorum-confirmed threat ready to be written into the verified graph.

    ``identifier`` — the threat id (its prefix picks the builder, see
    :attr:`category`). ``severity`` — one of ``constants.SEVERITY_ORDER``.
    ``kind`` — e.g. ``malware`` (the only kind a dependency rule is promoted
    as: it blocks). ``report`` — the community report the rule was made from,
    its provenance (a reporter's own report of this identifier). ``evidence`` —
    why it is confirmed; written truncated to :data:`EVIDENCE_MAX_BYTES`.
    ``name`` — display name (default: the identifier). ``advisory_id`` — an
    advisory such as ``MAL-2026-1``. ``pattern`` — injection entries only: the
    regex the identifier hashes. Raises :class:`RowBuildError` when invalid.
    """

    identifier: str
    severity: str
    kind: str
    report: Optional[statement.ReportRef] = None
    evidence: str = ""
    name: str = ""
    advisory_id: str = ""
    pattern: str = ""

    def __post_init__(self) -> None:
        if self.category not in PROMOTABLE_CATEGORIES:
            raise RowBuildError(f"{self.identifier!r} is not of a promotable category {PROMOTABLE_CATEGORIES}")
        if self.severity not in constants.SEVERITY_ORDER:
            raise RowBuildError(f"severity must be one of {constants.SEVERITY_ORDER}")
        if not self.kind.strip():
            raise RowBuildError("a promoted entry needs a kind")
        if self.category == "dep" and self.kind != constants.KIND_MALWARE:
            raise RowBuildError("a dependency is promoted as malware only (a vulnerability never blocks)")
        if self.report is not None and (self.report.identifier != self.identifier
                                        or statement.reference(self.report.fields()) is None):
            raise RowBuildError("the report must be a reporter's own report of this identifier (subject, digest, key)")

    @property
    def category(self) -> str:
        """The identifier's prefix (``dep:npm:x@1`` → ``dep``) — the registry key."""
        return self.identifier.split(":", 1)[0].lower() if ":" in self.identifier else ""


def promotion_payload(entry: ConfirmedEntry) -> dict[str, str]:
    """The flat str→str payload the curators sign for *entry* — the same keys
    (:data:`PAYLOAD_KEYS`) for every category; fields that do not apply to a
    category are empty."""
    ecosystem, package, version = _package_fields(entry.identifier)
    report = entry.report.fields() if entry.report is not None else {}
    return {
        "identifier": entry.identifier,
        "severity": entry.severity,
        "kind": entry.kind,
        "ecosystem": ecosystem,
        "packageName": package,
        "packageVersion": version,
        "advisoryId": entry.advisory_id.strip(),
        "name": entry.name.strip() or entry.identifier,
        "report": report.get("report", ""),
        "reportDigest": report.get("reportDigest", ""),
        "reporterKey": report.get("reporterKey", ""),
    }


def _package_fields(identifier: str) -> tuple[str, str, str]:
    """``(ecosystem, package name, version)`` named by a dependency or a
    versioned skill identifier; empty strings for every other type."""
    dependency = threat_ids.parse_dependency_identifier(identifier)
    if dependency is not None:
        return dependency
    skill = _parse_skill(identifier)
    if skill is not None and skill.version:
        return "", skill.name, skill.version
    return "", "", ""


class RowBuilder(Protocol):
    """One promotable category's row shape. ``category`` — the registry key;
    ``quads(entry, envelope)`` — the verified-graph quads, always carrying the
    envelope under ``SIGNED_STATEMENT_PRED``; raises :class:`RowBuildError`."""

    category: str

    def quads(self, entry: ConfirmedEntry, envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
        ...


# ---------------------------------------------------------------- shared row parts


def _checked_payload(entry: ConfirmedEntry, envelope: signing.SignedEnvelope, category: str) -> Mapping[str, str]:
    """The envelope's signed payload, once it is a signed promotion of exactly
    *entry* (a row never shows a rule its signatures do not name)."""
    if entry.category != category:
        raise RowBuildError(f"the {category} builder cannot write {entry.identifier!r}")
    if envelope.statement_type != PROMOTION_STATEMENT or not envelope.signatures:
        raise RowBuildError(f"a promoted row needs a signed {PROMOTION_STATEMENT} envelope")
    expected = promotion_payload(entry)
    for field_name in SIGNED_RULE_FIELDS:
        if envelope.payload.get(field_name) != expected[field_name]:
            raise RowBuildError(f"the signed payload's {field_name} does not match the entry {entry.identifier!r}")
    return envelope.payload


def _capped_evidence(evidence: str) -> str:
    """*evidence* within :data:`EVIDENCE_MAX_BYTES` UTF-8 bytes, cut on a
    character boundary and marked when cut."""
    text = evidence.strip()
    if len(text.encode("utf-8")) <= EVIDENCE_MAX_BYTES:
        return text
    budget = EVIDENCE_MAX_BYTES - len(_EVIDENCE_TRUNCATION_MARKER.encode("utf-8"))
    return text.encode("utf-8")[:budget].decode("utf-8", errors="ignore") + _EVIDENCE_TRUNCATION_MARKER


def _signed_row(subject: str, rdf_type: Optional[str], payload: Mapping[str, str], envelope: signing.SignedEnvelope,
                literals: Sequence[tuple[str, str]], evidence: str = "") -> list[rdf_terms.Quad]:
    """One threat subject: its type, the signed rule fields, the type's own
    *literals*, the capped *evidence* and — always last — the envelope under
    ``SIGNED_STATEMENT_PRED``, checked against the store's literal cap. Empty
    values are skipped."""
    common = (
        (constants.IDENTIFIER_PRED, payload["identifier"]),
        (constants.SEVERITY_PRED, payload["severity"]),
        (constants.KIND_PRED, payload["kind"]),
        *literals,
        (constants.SCHEMA_NAME_PRED, payload.get("name", "")),
        (constants.SCHEMA_IDENTIFIER_PRED, payload.get("advisoryId", "")),
        (constants.SCHEMA_DESCRIPTION_PRED, _capped_evidence(evidence)),
        (constants.CURATED_PRED, "true"),
        (constants.SOURCE_OBSERVATION_PROVENANCE_JSON_PRED, _provenance_json(payload)),
        (constants.SIGNED_STATEMENT_PRED, envelope.to_text()),
    )
    quads = [rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(rdf_type))] if rdf_type else []
    quads += [rdf_terms.make_quad(subject, predicate, rdf_terms.literal(value)) for predicate, value in common if value]
    rdf_terms.assert_quads_literal_size(quads, label="promotion row")
    return quads


def _provenance_json(payload: Mapping[str, str]) -> str:
    """The rule's provenance as the corpus writes it: the report it was made from."""
    report = payload.get("report", "")
    return json.dumps([report] if report else [])


# ---------------------------------------------------------------- dependency


def _dependency_literals(payload: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    """The package fields, in the guardian vocabulary and as the ``dp:``
    triples the live lookup locates a ``DependencySignal`` by
    (``ruleset/live/lookup._dependency_sparql``)."""
    return (
        (constants.PACKAGE_ECOSYSTEM_PRED, payload["ecosystem"]),
        (constants.PACKAGE_NAME_PRED, payload["packageName"]),
        (constants.PACKAGE_VERSION_PRED, payload["packageVersion"]),
        (f"{_DEFENDER_PREDICATE}ecosystem", payload["ecosystem"]),
        (f"{_DEFENDER_PREDICATE}package", payload["packageName"]),
        (f"{_DEFENDER_PREDICATE}version", payload["packageVersion"]),
    )


class DependencyRowBuilder:
    """``dep:<ecosystem>:<name>@<version>`` → a ``DependencySignal`` with its evidence."""

    category = "dep"

    def quads(self, entry: ConfirmedEntry, envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
        payload = _checked_payload(entry, envelope, self.category)
        return _signed_row(threat_ids.threat_uri(entry.identifier), constants.DEFENDER_DEPENDENCY_TYPE_IRI,
                           payload, envelope, _dependency_literals(payload), entry.evidence)


# ---------------------------------------------------------------- the other categories


class IocRowBuilder:
    """``ioc:<type>:<value>`` → an ``IocSignal`` the live lookup finds by ``dp:value``."""

    category = "ioc"

    def quads(self, entry: ConfirmedEntry, envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
        payload = _checked_payload(entry, envelope, self.category)
        parts = entry.identifier.split(":", 2)
        ioc_type, value = (parts[1], parts[2]) if len(parts) == 3 else ("", "")
        if threat_ids.ioc_identifier(ioc_type, value) != entry.identifier or not threat_ids.ioc_value_is_well_formed(ioc_type, value):
            raise RowBuildError(f"{entry.identifier!r} is not a canonical, well-formed IOC identifier")
        literals = ((f"{_DEFENDER_PREDICATE}iocType", ioc_type), (f"{_DEFENDER_PREDICATE}value", value))
        return _signed_row(threat_ids.threat_uri(entry.identifier), _IOC_SIGNAL_TYPE, payload, envelope, literals, entry.evidence)


@dataclass(frozen=True)
class _Skill:
    name: str = ""
    version: str = ""
    danger_shape: str = ""
    artifact_hash: str = ""


def _parse_skill(identifier: str) -> Optional[_Skill]:
    """The parts of a ``skill:`` identifier in any of its three spellings
    (``threat_ids.skill_*_identifier``), else None."""
    if not identifier.startswith("skill:"):
        return None
    rest = identifier[len("skill:"):]
    if rest.startswith("artifact:"):
        artifact = rest[len("artifact:"):].split(":", 1)
        return _Skill(artifact_hash=artifact[0], danger_shape=artifact[1]) if len(artifact) == 2 and all(artifact) else None
    name, at_sign, version = rest.rpartition("@")
    # A version never holds ':'; an '@' before a ':' belongs to a shape id's name
    # (``skill:mail@helper:exec-remote``, ``skill:@acme/tool:exec-remote``).
    if at_sign and ":" not in version:
        return _Skill(name=name, version=version) if name and version else None
    name, _, shape = rest.rpartition(":")
    return _Skill(name=name, danger_shape=shape) if name and shape else None


class SkillRowBuilder:
    """``skill:…`` → a legacy ``g:identifier`` rule with the parts its identifier names."""

    category = "skill"

    def quads(self, entry: ConfirmedEntry, envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
        payload = _checked_payload(entry, envelope, self.category)
        skill = _parse_skill(entry.identifier)
        if skill is None:
            raise RowBuildError(f"{entry.identifier!r} is not a skill identifier")
        literals = ((constants.SKILL_NAME_PRED, skill.name), (constants.SKILL_VERSION_PRED, skill.version),
                    (constants.DANGER_SHAPE_PRED, skill.danger_shape), (constants.SKILL_ARTIFACT_HASH_PRED, skill.artifact_hash))
        return _signed_row(threat_ids.threat_uri(entry.identifier), None, payload, envelope, literals, entry.evidence)


class InjectionRowBuilder:
    """``injection:<hash>`` → a legacy ``g:identifier`` rule carrying the pattern the hash names."""

    category = "injection"

    def quads(self, entry: ConfirmedEntry, envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
        payload = _checked_payload(entry, envelope, self.category)
        if not entry.pattern or threat_ids.injection_identifier(entry.pattern) != entry.identifier:
            raise RowBuildError(f"{entry.identifier!r} needs the pattern its hash names")
        # The corpus stores regex escapes doubled; the reader collapses one layer
        # (row_adapters._normalize_injection_pattern), so write it the same way.
        literals = ((constants.PATTERN_PRED, entry.pattern.replace("\\", "\\\\")),)
        return _signed_row(threat_ids.threat_uri(entry.identifier), None, payload, envelope, literals, entry.evidence)


class FileAccessRowBuilder:
    """``fileaccess:{tool}:{category}`` → a legacy ``g:identifier`` rule (the
    corpus has no typed signal for it)."""

    category = "fileaccess"

    def quads(self, entry: ConfirmedEntry, envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
        payload = _checked_payload(entry, envelope, self.category)
        parts = entry.identifier.split(":", 2)
        if len(parts) != 3 or threat_ids.fileaccess_identifier(parts[1], parts[2]) != entry.identifier:
            raise RowBuildError(f"{entry.identifier!r} is not a canonical fileaccess identifier")
        literals = ((constants.TOOL_NAME_PRED, parts[1]), (constants.CATEGORY_PRED, parts[2]))
        return _signed_row(threat_ids.threat_uri(entry.identifier), None, payload, envelope, literals, entry.evidence)


#: Every category D3 calls promotable → its builder. Frozen: a category is
#: added here, in code review, never at run time.
ROW_BUILDERS: Mapping[str, RowBuilder] = MappingProxyType({
    builder.category: builder
    for builder in (DependencyRowBuilder(), IocRowBuilder(), SkillRowBuilder(), InjectionRowBuilder(), FileAccessRowBuilder())
})
PROMOTABLE_CATEGORIES: tuple[str, ...] = tuple(ROW_BUILDERS)


# ---------------------------------------------------------------- corrections and the advisory twin (P5)

#: How many subjects one correction may name, and its reason/source length (the envelope stays under 4 KB).
MAX_CORRECTION_TARGETS, _CORRECTION_TEXT_MAX = 20, 200
_IRI_UNSAFE = frozenset('<>"{}|^`\\ \r\n\t')


def correction_payload(identifier: str, subjects: Sequence[str], *, reason: str, source: str) -> dict[str, str]:
    """The flat payload the curators sign to suppress *subjects* — the subjects
    the verified graph holds for *identifier*, read first (F-031: a legacy row
    does not live at ``threat_uri(identifier)``). The reader honours only the
    targets inside this payload (``ruleset/live/corrections.py``)."""
    targets = sorted(set(subjects))
    if not 0 < len(targets) <= MAX_CORRECTION_TARGETS:
        raise RowBuildError(f"a correction names 1 to {MAX_CORRECTION_TARGETS} subjects, not {len(targets)}")
    if any(not target or len(target) > 512 or _IRI_UNSAFE & set(target) for target in targets):
        raise RowBuildError("a correction target must be a plain subject IRI")
    for label, text in (("reason", reason), ("source", source)):
        if not text.strip() or len(text) > _CORRECTION_TEXT_MAX or not text.isprintable():
            raise RowBuildError(f"a correction needs a one-line {label} of at most {_CORRECTION_TEXT_MAX} characters")
    return {"action": constants.DEFENDER_CORRECTION_SUPPRESS, "targetSubjects": " ".join(targets),
            "identifier": identifier, "reason": reason.strip(), "source": source.strip()}


def correction_quads(envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
    """One ``CorrectionSignal`` suppress row per signed target, each carrying the
    envelope — the shape the R3 reader honours. No ``g:identifier`` on purpose:
    the legacy identifier lane would compile such a row into a rule."""
    if envelope.statement_type != CORRECTION_STATEMENT or not envelope.signatures:
        raise RowBuildError(f"a correction row needs a signed {CORRECTION_STATEMENT} envelope")
    payload = envelope.payload
    if payload.get("action") != constants.DEFENDER_CORRECTION_SUPPRESS:
        raise RowBuildError("only a suppress correction is written")
    signed = rdf_terms.literal(envelope.to_text())
    prefix = f"urn:blackbox:correction:{threat_ids.stable_hash(payload.get('identifier', ''), 16)}:{envelope.sequence}"
    quads = []
    for target in str(payload.get("targetSubjects", "")).split():
        subject = f"{prefix}:{threat_ids.stable_hash(target, 12)}"
        quads += [
            rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.DEFENDER_CORRECTION_TYPE_IRI)),
            rdf_terms.make_quad(subject, constants.DEFENDER_CORRECTION_TARGET_PRED, rdf_terms.iri(target)),
            rdf_terms.make_quad(subject, constants.DEFENDER_CORRECTION_ACTION_PRED,
                                rdf_terms.literal(constants.DEFENDER_CORRECTION_SUPPRESS)),
            rdf_terms.make_quad(subject, f"{_DEFENDER_PREDICATE}reason", rdf_terms.literal(payload.get("reason", ""))),
            rdf_terms.make_quad(subject, f"{_DEFENDER_PREDICATE}source", rdf_terms.literal(payload.get("source", ""))),
            rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, signed),
        ]
    if not quads:
        raise RowBuildError("the signed correction names no target subject")
    rdf_terms.assert_quads_literal_size(quads, label="correction row")
    return quads

