"""Row adapters: one verified-graph result row -> one rule / graph entry.

Pure functions (no I/O): severity, identity, provenance and the per-category
rule shape, plus the skill-name and injection-pattern normalizers. Called by
:mod:`.compiler`; :mod:`.disk_cache` reuses the injection normalizer on load.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional
from ..kernel import constants
from . import safe_regex
from ..kernel import threat_ids
from ..kernel.dkg_client import extract_binding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Build from query bindings
# ---------------------------------------------------------------------------


def _source_observation_provenance(row: dict[str, Any]) -> dict[str, Any]:
    raw = extract_binding(row.get("provenanceJson"))
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _row_severity(row: dict[str, Any]) -> str:
    severity = extract_binding(row.get("severity"))
    if not severity and extract_binding(row.get("rdfType")) == constants.SOURCE_OBSERVATION_TYPE_IRI:
        severity = _source_observation_provenance(row).get("severity")
    return constants.normalize_severity(severity, "high")


def _row_identity(row: dict[str, Any]) -> tuple:
    subject = extract_binding(row.get("threat"))
    rdf_type = extract_binding(row.get("rdfType"))
    identifier = extract_binding(row.get("identifier"))
    suffix = subject.rsplit(":", 1)[-1] if subject else ""
    if not identifier and rdf_type == "urn:defender:DependencySignal":
        eco = extract_binding(row.get("packageEcosystem")).lower()
        pkg = extract_binding(row.get("packageName")).lower()
        ver = extract_binding(row.get("packageVersion"))
        if eco and pkg and ver:
            identifier = f"dep:{eco}:{pkg}@{ver}"
    elif not identifier and rdf_type == "urn:defender:InjectionSignal" and suffix:
        identifier = f"injection:{suffix}"
    elif not identifier and rdf_type == "urn:defender:SkillSignal" and suffix:
        identifier = f"skill:{suffix}"
    elif not identifier and rdf_type == "urn:defender:IocSignal":
        ioc_type = extract_binding(row.get("category")).strip().lower()
        ioc_value = extract_binding(row.get("iocValue"))
        if ioc_type and ioc_value:
            # KI-387: the shared id (EVM addresses lower-case), as detection derives it.
            identifier = threat_ids.ioc_identifier(ioc_type, ioc_value)
    elif not identifier and rdf_type == constants.SOURCE_OBSERVATION_TYPE_IRI:
        lifecycle = extract_binding(row.get("lifecycleStatus")).strip().lower()
        ioc_type = extract_binding(row.get("canonicalType")).strip().lower()
        ioc_value = extract_binding(row.get("normalizedValue"))
        if lifecycle == "active" and ioc_type in threat_ids.IOC_TYPES and ioc_value:
            identifier = threat_ids.ioc_identifier(ioc_type, ioc_value)
    return subject, rdf_type, identifier


def _row_to_graph_entry(row: dict[str, Any], source: str) -> Optional[dict[str, Any]]:
    subject, _rdf_type, identifier = _row_identity(row)
    if not identifier:
        return None
    return {
        "identifier": identifier,
        "category": threat_ids.category_for(identifier),
        "severity": _row_severity(row),
        "name": (
            extract_binding(row.get("name"))
            or extract_binding(row.get("normalizedValue"))
            or identifier
        ),
        "subject": subject,
        "source": source,
    }


def _row_to_rule(row: dict[str, Any], source: str = "public") -> Optional[tuple]:
    """Map one SPARQL binding row to ``(category, key, rule)`` or ``None``.

    *source* tags the rule's trust tier: ``"public"`` (verifiable-memory, the
    curated source of truth) or ``"community"`` (shared-working-memory).
    """
    subject, rdf_type, identifier = _row_identity(row)
    if not identifier:
        return None
    severity = _row_severity(row)
    name = (
        extract_binding(row.get("name"))
        or extract_binding(row.get("normalizedValue"))
        or identifier
    )
    common = {
        "identifier": identifier,
        "subject": subject,
        "description": extract_binding(row.get("description")),
        "severity": severity,
        "name": name,
        "source": source,
    }
    if identifier.startswith("injection:"):
        pattern_src = _normalize_injection_pattern(extract_binding(row.get("pattern")))
        if not pattern_src:
            return None
        try:
            compiled = safe_regex.compile_bounded(pattern_src, re.IGNORECASE)   # G6: never a pattern that can hang the scan
        except safe_regex.UnsafePattern as exc:
            logger.warning("blackbox: skipping injection pattern %s: %s", identifier, exc)
            return None
        return ("injection", identifier, {
            **common,
            "pattern": compiled,
            "pattern_src": pattern_src,
        })
    if identifier.startswith("escalation:"):
        tool_name = extract_binding(row.get("toolName"))
        arg_shape = extract_binding(row.get("argShape"))
        if not tool_name or not arg_shape:
            return None
        return ("escalation", identifier, {
            **common,
            "toolName": tool_name,
            "argShape": arg_shape,
        })
    if identifier.startswith("dep:"):
        return _dependency_rule(row, identifier, common)
    if identifier.startswith("fileaccess:"):
        tool_name = extract_binding(row.get("toolName"))
        category = extract_binding(row.get("category"))
        if not (tool_name and category):
            # Fall back to parsing: fileaccess:{tool}:{category}
            try:
                _, tool_name, category = identifier.split(":", 2)
            except ValueError:
                return None
        return ("fileaccess", identifier, {
            **common,
            "toolName": tool_name.strip().lower(),
            "category": category.strip().lower(),
        })
    if identifier.startswith("skill:"):
        skill_name = extract_binding(row.get("skillName"))
        if not _SKILL_PACKAGE_NAME_RE.fullmatch(skill_name):
            skill_name = _skill_name_from_title(name)
        rule = {
            **common,
            "skillName": skill_name,
            "skillVersion": extract_binding(row.get("skillVersion")),
            "dangerShape": extract_binding(row.get("dangerShape")),
        }
        return ("skill", identifier, rule)
    if identifier.startswith("ioc:"):
        # ioc:{type}:{value} — type also carried in ?category; value is the rest.
        is_observation = rdf_type == constants.SOURCE_OBSERVATION_TYPE_IRI
        ioc_type = extract_binding(
            row.get("canonicalType") if is_observation else row.get("category")
        ).strip().lower()
        parts = identifier.split(":", 2)
        if not ioc_type and len(parts) == 3:
            ioc_type = parts[1].strip().lower()
        rule = {
            **common,
            "iocType": ioc_type,
            "value": (
                (parts[2] if is_observation and len(parts) == 3 else "")
                or extract_binding(row.get("iocValue"))
                or (parts[2] if len(parts) == 3 else "")
            ),
            "kind": extract_binding(
                row.get("observationCategory") if is_observation else row.get("kind")
            ) or None,
        }
        source_id = extract_binding(row.get("sourceId")) if is_observation else ""
        if source_id:
            rule["sourceId"] = source_id
        return ("ioc", identifier, rule)
    return None


#: The source and tier a verified rule is served under when it may not block — the one
#: non-blocking tier the detectors know. THE definition: ``live`` reads both from here
#: (``AssetTier.FLAG`` is :data:`FLAG_TIER`); this module imports nothing from ``live``.
FLAG_ONLY_SOURCE = "community"
FLAG_TIER = "flag"


def capped_at_flag(rule: dict[str, Any]) -> dict[str, Any]:
    """*rule* served flag-only (a copy): the FLAG tier's source and tier, never a block."""
    return {**rule, "source": FLAG_ONLY_SOURCE, "asset_tier": FLAG_TIER}


def _dependency_rule(row: dict[str, Any], identifier: str, common: dict[str, Any]) -> Optional[tuple]:
    """``("dependency", key, rule)`` for a ``dep:{eco}:{name}@{version}`` row, or None.

    A verified rule without a ``kind`` is served flag-only (trust-and-threat-lab
    R4, §03.4): the block gate stops every kind but ``vulnerability``, so an
    absent kind would block a package that may only be vulnerable. Promoted
    rows always carry ``kind`` (``row_builders`` refuses one without it)."""
    eco = extract_binding(row.get("packageEcosystem")).lower()
    pkg = extract_binding(row.get("packageName")).lower()
    ver = extract_binding(row.get("packageVersion"))
    if not (eco and pkg and ver):
        # Fall back to the identifier itself: dep:{eco}:{name}@{version}
        parsed = threat_ids.parse_dependency_identifier(identifier)
        if parsed is None:
            return None
        eco, pkg, ver = parsed[0].lower(), parsed[1].lower(), parsed[2]
    rule = {
        **common,
        "ecosystem": eco,
        "packageName": pkg,
        "packageVersion": ver,
        "advisoryId": extract_binding(row.get("advisoryId")),
        "kind": extract_binding(row.get("kind")) or None,
    }
    if rule["kind"] is None and rule["source"] == "public":
        rule = capped_at_flag(rule)
    return ("dependency", threat_ids.dependency_key(eco, pkg, ver), rule)


_QUOTED_SKILL_NAME_RE = re.compile(r"^[\"'`]([^\"'`]+)[\"'`]")
_SKILL_PACKAGE_NAME_RE = re.compile(
    r"@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?",
    re.IGNORECASE,
)
_TITLED_SKILL_NAME_RE = re.compile(
    r"^(@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?)\s+"
    r"(?:\(|bcc\b)",
    re.IGNORECASE,
)


def _skill_name_from_title(title: str) -> str:
    """Recover a concrete package name from older skill display titles.

    Early public SkillSignal records omitted ``skillName`` and embedded a name
    in titles such as ``'totally-safe-helper' (any version)``. Only explicit,
    package-shaped names are recovered. Generic research archetypes remain
    unmatched so they cannot turn into noisy package-name alerts.
    """
    value = (title or "").strip()
    quoted = _QUOTED_SKILL_NAME_RE.match(value)
    if quoted:
        return quoted.group(1).strip()
    titled = _TITLED_SKILL_NAME_RE.match(value)
    return titled.group(1).strip() if titled else ""


def _normalize_injection_pattern(pattern_src: str) -> str:
    """Undo the JSON/RDF escape layer applied to published regex literals.

    Public graph patterns arrive with regex escapes doubled (for example
    ``<\\\\|endoftext\\\\|>``). Compiling that value directly changes its
    meaning: the delimiter rule can match a bare ``>``. Collapse exactly one
    serialization layer before compiling so graph signatures retain their
    authored regex semantics.
    """
    return (pattern_src or "").replace("\\\\", "\\")
