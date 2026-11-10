"""Validated community report records — an unvalidated report cannot be built (Refine R1).

Every report and dispute leaves the machine through the report builder, and
the builder builds only from a :class:`ReportRecord` produced here. Validation
is closed-world: each field is checked against a vocabulary that ALREADY exists
in the code (detection's shapes and categories, the IOC types, the OWASP LLM
list, the injection contexts), the identifier must equal the one the fields
derive, and free text is refused. Rejects never leave the machine.

What a report may carry, per category (the evidence keys are the builder's
keyword names):

* ``injection`` — ``context`` (required, decision 24; :data:`INJECTION_CONTEXTS`,
  which adds ``in-tool-input`` — an injection found in a tool's input) + optional
  ``owasp_category``. Never the pattern text: the identifier is already its
  hash (KI-115/161).
* ``escalation`` — ``tool_name`` (a shell tool) + ``arg_shape`` (a known shape).
* ``dependency`` — ``ecosystem``, canonical ``package_name``,
  ``package_version``, ``kind`` = ``malware`` (a vulnerability report cannot
  be built — decision 22), ``reason`` (``DEPENDENCY_REASONS`` or
  ``advisory:<id>``, or ``verified-match`` when ``matched_by`` is ``verified``
  — the verified graph lists it, no advisory id needed; a whole-package ``*``
  version only with a ``WHOLE_PACKAGE_REASONS`` reason), optional ``advisory_id``.
* ``fileaccess`` — ``tool_name`` + ``file_category`` (a known category).
* ``skill`` — either a known-bad named version from a public registry
  (``registry`` + ``skill_name`` + ``skill_version``; the registry may be left
  out only when ``matched_by`` is ``verified`` — a name the verified graph
  already publishes reveals nothing about the reporter), or a local/unknown
  skill as ``artifact_hash`` (sha256 of its code) + ``danger_shape`` — never
  its name or version (KI-159).
* ``ioc`` — ``ioc_type`` (a known type) + ``ioc_context`` (where it was met)
  + optional ``reason`` (:data:`IOC_REASONS`); the canonical value is the identifier.

Every category may also carry two COMMON fields (trust-and-threat-lab §03.6),
in the same flat mapping as the evidence — exactly as they sit in a signed
payload, so a reader's re-check that feeds the payload's non-core keys back in
validates them too (LES-032): ``matched_by`` (:data:`MATCHED_BY`) and
``blackbox_version`` (a release number). Both are optional: reports signed
before they existed stay valid, and the record holds ``""`` for "not stated".

The vocabularies are plan §04's, kept in ``kernel.constants``.

Pattern: Factory (:func:`validate_report`) + a Strategy table of per-category
validators; the record is an immutable Value Object.

Usage::

    record = report_schema.validate_report(identifier=..., category="ioc",
        severity="high", framework="hermes", evidence={"ioc_type": "domain"})
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, UTC
from typing import Callable, Dict, Mapping, Optional, Tuple

from .. import detection
from ..kernel import constants, display_safety, threat_ids
from .sighting import vocab as sighting_vocab

#: Longest identifier / evidence value a report may carry.
MAX_IDENTIFIER_CHARS = 512
MAX_VALUE_CHARS = 128
#: A report dated further ahead than this is refused (sender clocks drift a little).
MAX_CLOCK_SKEW = timedelta(minutes=10)
#: The keys every signed report payload carries beside its evidence. Whatever
#: else a signed payload holds is evidence, and is checked against the schema.
REPORT_CORE_KEYS = frozenset({"subject", "identifier", "category", "severity", "reporter", "framework", "day"})

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._@:/+~-]+")       # package names/versions, tool names, advisory ids
#: A heuristic's id is its pattern hash; a verified-corpus id is the threat's
#: slug (``injection:seed-000``) — either way a lowercase slug, never free text.
_INJECTION_ID = re.compile(r"injection:[a-z0-9][a-z0-9._-]{0,63}")
#: A Blackbox release number (``1.1.0``, ``1.2.0rc1``, ``1.2.0+local``) — never free text.
_BLACKBOX_VERSION = re.compile(r"[0-9]{1,4}(\.[0-9]{1,4}){1,3}([a-z0-9.+-]{0,24})")

#: How the reporter's node matched the threat: the verified graph's rules, the
#: built-in detectors, or a public advisory (§03.6).
MATCHED_BY = frozenset({"verified", "built-in", "advisory"})
#: Why an indicator of compromise is reported (§03.6) — a closed code, never text.
IOC_REASONS = frozenset({"phishing", "malware-delivery", "command-and-control", "credential-harvest",
                         "exfil-endpoint", "scam", "injection-host"})   # injection-host: threat-profiles D8
#: Where an injection may be reported from: the R1 contexts plus a tool's input (§03.6).
INJECTION_CONTEXTS = (*constants.INJECTION_CONTEXTS, "in-tool-input")
#: The dependency reason of a package the verified graph lists (``matched_by=verified`` only).
VERIFIED_MATCH_REASON = "verified-match"
#: The common fields every category may carry beside its evidence.
COMMON_FIELD_KEYS = ("matched_by", "blackbox_version", *sighting_vocab.SIGHTING_KEYS)   # + threat-profiles §03.2
#: A verified skill rule's identifier (the corpus names skills by hash, not name@version).
_VERIFIED_SKILL_ID = re.compile(r"skill:[0-9a-f]{24}")


class ReportValidationError(ValueError):
    """A report that must not be built or shared; the message says why."""


@dataclass(frozen=True)
class ReportRecord:
    """One validated report: what the builder emits and the signer signs.

    ``evidence`` holds (builder keyword, value) pairs, sorted — only keys the
    category allows, every value checked. ``matched_by`` (one of
    :data:`MATCHED_BY`) and ``blackbox_version`` are the common fields;
    ``""`` means the report does not state it. ``sighting`` holds the
    threat-profile fields (:data:`.sighting.vocab.SIGHTING_KEYS`) it states, sorted.
    """

    identifier: str
    category: str
    severity: str
    framework: str
    evidence: tuple[tuple[str, str], ...]
    matched_by: str = ""
    blackbox_version: str = ""
    sighting: tuple[tuple[str, str], ...] = ()

    def common_fields(self) -> dict[str, str]:
        """The common fields this report states, keyed like the evidence."""
        stated = {"matched_by": self.matched_by, "blackbox_version": self.blackbox_version, **dict(self.sighting)}
        return {key: value for key, value in stated.items() if value}


def _fail(message: str) -> None:
    raise ReportValidationError(message)


def _token(name: str, value: Optional[str], *, required: bool = True) -> str:
    """A short safe token (no spaces, no control characters)."""
    text = str(value or "").strip()
    if not text:
        if required:
            _fail(f"{name} is required")
        return ""
    if len(text) > MAX_VALUE_CHARS or not _SAFE_TOKEN.fullmatch(text):
        _fail(f"{name} must be a short token without spaces or control characters")
    return text


def _one_of(name: str, value: Optional[str], allowed) -> str:
    text = str(value or "").strip().lower()
    if text not in allowed:
        _fail(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return text


# -- per-category validators (Strategy table): evidence in -> (derived id, evidence out)


def _injection(ev: Mapping[str, str]) -> tuple[Optional[str], dict[str, str]]:
    out = {"context": _one_of("context", ev.get("context"), INJECTION_CONTEXTS)}
    if ev.get("owasp_category"):
        out["owasp_category"] = _one_of("owasp_category", ev["owasp_category"],
                                        {c.lower() for c in constants.OWASP_LLM_CATEGORIES}).upper()
    return None, out   # the identifier is the pattern's hash, checked by shape


def _escalation(ev: Mapping[str, str]) -> tuple[Optional[str], dict[str, str]]:
    tool = _one_of("tool_name", ev.get("tool_name"), detection.SHELL_TOOLS)
    shape = _one_of("arg_shape", ev.get("arg_shape"), detection.ESCALATION_SHAPES)
    return threat_ids.escalation_identifier(tool, shape), {"tool_name": tool, "arg_shape": shape}


def _dependency(ev: Mapping[str, str]) -> tuple[Optional[str], dict[str, str]]:
    eco = _one_of("ecosystem", ev.get("ecosystem"), detection.DEPENDENCY_ECOSYSTEMS)
    raw_name = _token("package_name", ev.get("package_name"))
    name = threat_ids.canonical_package_name(eco, raw_name)
    if str(ev.get("kind") or "").lower() != constants.KIND_MALWARE:
        _fail("a dependency report must be kind=malware (vulnerabilities stay local — decision 22)")
    reason, advisory = _dependency_reason(ev, verified=ev.get("matched_by") == "verified")
    version = str(ev.get("package_version") or "").strip()
    if version == "*":   # a whole-package report: every version is malware
        if reason not in constants.WHOLE_PACKAGE_REASONS:
            _fail(f"a whole-package (*) report needs reason {' or '.join(constants.WHOLE_PACKAGE_REASONS)}")
    else:
        version = _token("package_version", version)
    out = {"ecosystem": eco, "package_name": name, "package_version": version, "kind": constants.KIND_MALWARE,
           "reason": reason}
    if advisory:
        out["advisory_id"] = advisory
    return threat_ids.dependency_identifier(eco, name, version), out


def _dependency_reason(ev: Mapping[str, str], *, verified: bool) -> tuple[str, str]:
    """(reason, advisory id): the closed reason, ``advisory:<id>`` — whose id
    must equal ``advisory_id`` when both are given — or, for a package the
    verified graph matched (*verified*), ``verified-match``."""
    reason = str(ev.get("reason") or "").strip()
    advisory = _token("advisory_id", ev.get("advisory_id"), required=False)
    if reason.lower().startswith(constants.ADVISORY_REASON_PREFIX):
        cited = _token("advisory id in reason", reason[len(constants.ADVISORY_REASON_PREFIX):])
        if advisory and advisory != cited:
            _fail("the reason's advisory and advisory_id differ")
        return constants.ADVISORY_REASON_PREFIX + cited, cited
    allowed = (*constants.DEPENDENCY_REASONS, constants.ADVISORY_REASON_PREFIX + "<id>",
               *((VERIFIED_MATCH_REASON,) if verified else ()))
    return _one_of("reason", reason, allowed), advisory


def _fileaccess(ev: Mapping[str, str]) -> tuple[Optional[str], dict[str, str]]:
    tool = _token("tool_name", ev.get("tool_name")).lower()
    category = _one_of("file_category", ev.get("file_category"), detection.SENSITIVE_PATH_CATEGORIES)
    return threat_ids.fileaccess_identifier(tool, category), {"tool_name": tool, "file_category": category}


def _skill(ev: Mapping[str, str]) -> tuple[Optional[str], dict[str, str]]:
    if ev.get("artifact_hash") or ev.get("danger_shape"):
        if ev.get("skill_name") or ev.get("skill_version") or ev.get("registry"):
            _fail("a local skill is reported by artifact hash + danger shape, never by name or version (KI-159)")
        digest = str(ev.get("artifact_hash") or "").strip().lower()
        if not threat_ids.is_hex64(digest):
            _fail("artifact_hash must be the sha256 hex of the skill's code")
        shape = _one_of("danger_shape", ev.get("danger_shape"), detection.SKILL_DANGER_SHAPES)
        return threat_ids.skill_artifact_identifier(digest, shape), {"artifact_hash": digest, "danger_shape": shape}
    name = _token("skill_name", ev.get("skill_name"))
    version = _token("skill_version", ev.get("skill_version"))
    out = {"skill_name": name, "skill_version": version}
    if ev.get("registry") or ev.get("matched_by") != "verified":   # a verified match is already public
        out["registry"] = _one_of("registry", ev.get("registry"), constants.SKILL_REGISTRIES)   # never local (KI-159)
        return threat_ids.skill_version_identifier(name, version), out
    # KI-353: a VERIFIED skill keeps the corpus's own identifier (checked by shape below).
    return None, out


def _ioc(ev: Mapping[str, str]) -> tuple[Optional[str], dict[str, str]]:
    out = {"ioc_type": _one_of("ioc_type", ev.get("ioc_type"), threat_ids.IOC_TYPES),
           "ioc_context": _one_of("ioc_context", ev.get("ioc_context"), constants.IOC_CONTEXTS)}
    if ev.get("reason"):
        out["reason"] = _one_of("reason", ev["reason"], IOC_REASONS)
    return None, out


def _common_fields(given: Mapping[str, str]) -> dict[str, str]:
    """The common fields *given* states (:data:`COMMON_FIELD_KEYS`), checked."""
    out: dict[str, str] = {}
    if given.get("matched_by"):
        out["matched_by"] = _one_of("matched_by", given["matched_by"], MATCHED_BY)
    if given.get("blackbox_version"):
        version = str(given["blackbox_version"]).strip()
        if not _BLACKBOX_VERSION.fullmatch(version):
            _fail("blackbox_version must be a release number such as 1.1.0")
        out["blackbox_version"] = version
    out.update(_sighting_fields(given, matched_by=out.get("matched_by", "")))
    return out


#: Each sighting field's allowed values: a closed set, or a strict shape.
_SIGHTING_SETS = {"agent_action": sighting_vocab.AGENT_ACTIONS, "outcome": sighting_vocab.OUTCOMES,
                  "threat_goal": sighting_vocab.THREAT_GOALS, "resource_at_risk": sighting_vocab.RESOURCES_AT_RISK}


def _sighting_fields(given: Mapping[str, str], *, matched_by: str) -> dict[str, str]:
    """The threat-profile fields *given* states (threat-profiles §03.2), checked:
    closed sets, the tool rule (host tool verbatim, else ``mcp-tool``/``other``),
    ATT&CK/ATLAS shape, and a verified-rule link only on a verified match."""
    out = {key: _one_of(key, given[key], allowed) for key, allowed in _SIGHTING_SETS.items() if given.get(key)}
    if given.get("agent_tool"):
        tool = str(given["agent_tool"]).strip().lower()
        if tool not in sighting_vocab.OTHER_TOOLS and not (tool in _HOST_TOOLS or sighting_vocab.TOOL_SHAPE.fullmatch(tool)):
            _fail("agent_tool must be a host tool name, mcp-tool or other")
        out["agent_tool"] = tool
    if given.get("attack_technique"):
        technique = str(given["attack_technique"]).strip()
        if not sighting_vocab.ATTACK_TECHNIQUE_SHAPE.fullmatch(technique):
            _fail("attack_technique must be a MITRE ATT&CK or ATLAS technique id")
        out["attack_technique"] = technique
    if given.get("verified_subject"):
        subject = str(given["verified_subject"]).strip()
        if matched_by != "verified" or not sighting_vocab.VERIFIED_SUBJECT_SHAPE.fullmatch(subject):
            _fail("verified_subject names a verified rule, and only on a verified match")
        out["verified_subject"] = subject
    return out


_HOST_TOOLS = frozenset({*detection.SHELL_TOOLS, *detection.HOST_FILE_AND_SKILL_TOOLS})

_VALIDATORS: dict[str, Callable[[Mapping[str, str]], tuple[Optional[str], dict[str, str]]]] = {
    "injection": _injection,
    "escalation": _escalation,
    "dependency": _dependency,
    "fileaccess": _fileaccess,
    "skill": _skill,
    "ioc": _ioc,
}


def _is_clean_token(identifier: str) -> bool:
    """A short single token: no spaces, and no control or FORMAT characters
    (bidi overrides, zero-width — §07: strip C0/C1, ESC, CR/LF, bidi and
    zero-width; ingest refuses, never repairs)."""
    return bool(identifier) and len(identifier) <= MAX_IDENTIFIER_CHARS and " " not in identifier \
        and display_safety.strip_controls(identifier) == identifier


def _check_identifier(category: str, identifier: str, derived: Optional[str], evidence: Mapping[str, str]) -> None:
    if not _is_clean_token(identifier):
        _fail("identifier must be a short single token without control or format characters")
    if derived is not None and identifier != derived:
        _fail(f"identifier does not match its fields (expected {derived})")
    if category == "skill" and derived is None and not (
            _VERIFIED_SKILL_ID.fullmatch(identifier)
            or identifier == threat_ids.skill_version_identifier(evidence["skill_name"], evidence["skill_version"])):
        _fail("a verified skill report names the skill (skill:<name>@<version>) or its verified rule (skill:<24 hex>)")
    if category == "injection" and not _INJECTION_ID.fullmatch(identifier):
        _fail("an injection identifier is a slug (injection:<pattern hash or corpus id>), never free text")
    if category == "ioc":
        prefix = f"ioc:{evidence['ioc_type']}:"
        value = identifier[len(prefix):] if identifier.startswith(prefix) else ""
        if not value or threat_ids.ioc_identifier(evidence["ioc_type"], value) != identifier:
            _fail("an ioc identifier must be the canonical ioc:<type>:<value>")
        if not threat_ids.ioc_value_is_well_formed(evidence["ioc_type"], value):
            _fail(f"the {evidence['ioc_type']} value does not have the shape that type allows")


def validate_report(*, identifier: str, category: str, severity: str, framework: str,
                    evidence: Mapping[str, Optional[str]], ts: Optional[datetime] = None) -> ReportRecord:
    """The validated record for one report, or :class:`ReportValidationError`.

    *evidence* is the flat field mapping: the category's evidence plus any
    :data:`COMMON_FIELD_KEYS` (a signed payload's non-core keys, as is)."""
    validator = _VALIDATORS.get(category)
    if validator is None:
        _fail(f"category must be one of: {', '.join(sorted(_VALIDATORS))}")
    if str(severity or "").strip().lower() not in constants.SEVERITY_ORDER:
        _fail(f"severity must be one of: {', '.join(constants.SEVERITY_ORDER)}")
    framework_name = _one_of("framework", framework, constants.REPORT_FRAMEWORKS)
    if ts is not None and _aware(ts) > datetime.now(UTC) + MAX_CLOCK_SKEW:
        _fail("a report cannot be dated in the future")
    given = {k: v for k, v in evidence.items() if v not in (None, "")}
    common = _common_fields(given)
    derived, out = validator({**given, **common})   # validators may read the checked common fields
    unknown = set(given) - set(out) - set(COMMON_FIELD_KEYS)
    if unknown:
        _fail(f"fields not allowed in a {category} report: {', '.join(sorted(unknown))}")
    _check_identifier(category, str(identifier or "").strip(), derived, out)
    return ReportRecord(identifier=identifier.strip(), category=category,
                        severity=constants.normalize_severity(severity), framework=framework_name,
                        evidence=tuple(sorted(out.items())), matched_by=common.get("matched_by", ""),
                        blackbox_version=common.get("blackbox_version", ""),
                        sighting=tuple(sorted((k, v) for k, v in common.items() if k in sighting_vocab.SIGHTING_KEYS)))


def validate_dispute(*, identifier: str, reason: str) -> tuple[str, str]:
    """(identifier, reason) for a false-positive dispute, or
    :class:`ReportValidationError`. The reason is REQUIRED and closed
    (``constants.FALSE_POSITIVE_REASONS``, plan §04); the disputed identifier is
    a single short token, never free text."""
    return validate_statement_identifier(identifier), _one_of("reason", reason, constants.FALSE_POSITIVE_REASONS)


def validate_statement_identifier(identifier: str) -> str:
    """The threat identifier a dispute or retraction names, stripped — a single
    short token, never free text — or :class:`ReportValidationError`."""
    identifier = str(identifier or "").strip()
    if not _is_clean_token(identifier):
        _fail("the identifier must be a short single token without control or format characters")
    return identifier


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)
