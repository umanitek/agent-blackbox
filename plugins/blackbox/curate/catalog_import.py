"""Threat-catalog import helpers (curator side) — currently UNUSED.

Converts external threat catalogs (bumblebee format, backlogs) into threat
entries. Nothing in the plugin calls these today (only tests); they are kept
for the curator tooling (build item R6) to adopt — or delete.
"""

from __future__ import annotations

from typing import Any, Optional
from ..kernel import threat_ids
from ..kernel import constants

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_bumblebee_catalog(catalog: Any) -> bool:
    """Return whether *catalog* uses the bumblebee package-feed shape."""
    if not isinstance(catalog, dict):
        return False
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("package")
        and isinstance(entry.get("versions"), list)
        for entry in entries
    )


def _flatten_bumblebee(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """Fan out a bumblebee feed into one dependency per package version."""
    out: list[dict[str, Any]] = []
    comment = str(catalog.get("_comment") or "").strip()
    default_source = str(catalog.get("source") or "Socket").strip()
    contributor = str(catalog.get("contributor") or "").strip()
    for entry in catalog.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        ecosystem = str(entry.get("ecosystem") or "").strip()
        package = str(entry.get("package") or "").strip()
        versions = entry.get("versions")
        if not (ecosystem and package and isinstance(versions, list)):
            continue
        entry_name = str(entry.get("name") or package).strip()
        severity = entry.get("severity")
        advisory_id = entry.get("id")
        source = str(entry.get("source") or "").strip()
        description = entry_name
        if comment:
            snippet = comment if len(comment) <= 240 else comment[:237].rstrip() + "..."
            description = f"{entry_name} — {snippet}" if entry_name else snippet
        references = [source] if source else []
        for version_value in versions:
            version = str(version_value).strip()
            if not version:
                continue
            out.append(
                {
                    "type": "dependency",
                    "kind": "malware",
                    "ecosystem": ecosystem,
                    "package": package,
                    "version": version,
                    "title": f"{package}@{version}",
                    "description": description,
                    "severity": severity,
                    "advisoryId": advisory_id,
                    "references": references,
                    "source": default_source,
                    "contributor": contributor,
                }
            )
    return out


def _catalog_provenance_defaults(catalog: Any) -> dict[str, Any]:
    """Return catalog-level provenance inherited by individual entries."""
    if not isinstance(catalog, dict):
        return {}
    defaults: dict[str, Any] = {}
    source = catalog.get("sources") or catalog.get("source")
    if source:
        defaults["source"] = source
    if catalog.get("contributor"):
        defaults["contributor"] = catalog.get("contributor")
    return defaults


def _apply_provenance_defaults(entry: dict[str, Any], defaults: dict[str, Any]) -> None:
    """Fill missing per-entry provenance from catalog-level defaults."""
    if defaults.get("source") and not (entry.get("source") or entry.get("sources")):
        entry["source"] = defaults["source"]
    if defaults.get("contributor") and not entry.get("contributor"):
        entry["contributor"] = defaults["contributor"]


def _entry_provenance(entry: dict[str, Any]) -> dict[str, Any]:
    """Extract named sources, references, and contributor from an entry."""
    raw_sources = entry.get("sources")
    if raw_sources is None:
        raw_sources = entry.get("source")
    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    sources = [str(source).strip() for source in (raw_sources or []) if str(source).strip()]

    raw_references = entry.get("references")
    if isinstance(raw_references, str):
        raw_references = [raw_references]
    references = [
        str(reference).strip()
        for reference in (raw_references or [])
        if str(reference).strip()
    ]
    for source in sources:
        if source.startswith(("http://", "https://")) and source not in references:
            references.append(source)

    contributor = str(entry.get("contributor") or "").strip() or None
    return {"sources": sources, "references": references, "contributor": contributor}


def _flatten_catalog(catalog: Any, forced_type: Optional[str]) -> list[dict[str, Any]]:
    """Flatten supported threat-catalog shapes into individual entries."""
    if _is_bumblebee_catalog(catalog):
        return _flatten_bumblebee(catalog)
    out: list[dict[str, Any]] = []
    if isinstance(catalog, list):
        for item in catalog:
            if isinstance(item, dict):
                out.append({**item, **({"type": forced_type} if forced_type else {})})
    elif isinstance(catalog, dict):
        for item in catalog.get("threats", []) or []:
            if isinstance(item, dict):
                out.append({**item, **({"type": forced_type} if forced_type else {})})
        for key, category in (
            ("dependencies", "dependency"),
            ("injection", "injection"),
            ("escalation", "escalation"),
            ("fileaccess", "fileaccess"),
            ("skills", "skill"),
        ):
            for item in catalog.get(key, []) or []:
                if isinstance(item, dict):
                    out.append({"type": category, **item})
        for item in catalog.get("iocs", []) or []:
            if isinstance(item, dict):
                out.append({"type": "ioc", **item})
        out.extend(_flatten_backlog(catalog.get("backlog")))
    defaults = _catalog_provenance_defaults(catalog)
    if defaults:
        for entry in out:
            _apply_provenance_defaults(entry, defaults)
    return out


def _flatten_backlog(backlog: Any) -> list[dict[str, Any]]:
    """Flatten grouped backlog indicators into importable IOC entries."""
    if not isinstance(backlog, dict):
        return []
    out: list[dict[str, Any]] = []
    for group in backlog.values():
        if not isinstance(group, list):
            continue
        for item in group:
            if not isinstance(item, dict):
                continue
            rest = {key: value for key, value in item.items() if key != "type"}
            out.append(
                {
                    "type": "ioc",
                    "ioc_type": str(item.get("type") or "").lower(),
                    **rest,
                }
            )
    return out


def _entry_to_threat(entry: dict[str, Any]) -> tuple:
    """Return ``(category, identifier, fields)`` for a catalog entry."""
    category = str(entry.get("type") or "").lower()
    if category == "ioc":
        ioc_type = str(entry.get("ioc_type") or entry.get("iocType") or "").strip().lower()
        value = str(entry.get("value") or entry.get("indicator") or "").strip()
        if ioc_type in ("ipv4", "ipv6"):
            ioc_type = "ip"
        elif ioc_type in ("sha256", "sha1", "sha512", "md5"):
            if not value.lower().startswith(("sha256:", "sha1:", "sha512:", "md5:")):
                value = f"{ioc_type}:{value}"
            ioc_type = "hash"
        if ioc_type not in threat_ids.IOC_TYPES or not value:
            raise ValueError("ioc needs a supported ioc_type + value")
        identifier = threat_ids.ioc_identifier(ioc_type, value)
        threat = entry.get("threat") or entry.get("title") or entry.get("name")
        return "ioc", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": threat or f"{ioc_type}: {value[:80]}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ioc_type": ioc_type,
            "references": entry.get("references") or [],
        }
    if category == "injection":
        pattern = str(entry.get("pattern") or "").strip()
        if not pattern:
            raise ValueError("injection needs pattern")
        identifier = threat_ids.injection_identifier(pattern)
        return "injection", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"Injection {pattern[:40]}",
            "description": entry.get("summary") or entry.get("description") or "",
            "pattern": pattern,
            "owasp_category": entry.get("owaspCategory") or entry.get("owasp") or "LLM01",
        }
    if category == "escalation":
        tool = str(entry.get("toolName") or entry.get("tool") or "").strip()
        shape = str(entry.get("argShape") or entry.get("arg_shape") or "").strip()
        if not tool or not shape:
            raise ValueError("escalation needs toolName + argShape")
        identifier = threat_ids.escalation_identifier(tool, shape)
        return "escalation", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{tool} :: {shape}",
            "description": entry.get("summary") or entry.get("description") or "",
            "tool_name": tool,
            "arg_shape": shape,
        }
    if category == "dependency":
        ecosystem = str(entry.get("ecosystem") or "").strip()
        name = str(
            entry.get("name") or entry.get("package") or entry.get("package_name") or ""
        ).strip()
        version = str(entry.get("version") or entry.get("package_version") or "").strip()
        if not (ecosystem and name and version):
            raise ValueError("dependency needs ecosystem, name, version")
        if name.startswith("@"):
            name = "@" + name.lstrip("@")
        identifier = threat_ids.dependency_identifier(ecosystem, name, version)
        raw_kind = str(entry.get("kind") or "").strip().lower()
        kind = (
            raw_kind
            if raw_kind in (constants.KIND_MALWARE, constants.KIND_VULNERABILITY)
            else None
        )
        return "dependency", identifier, {
            "severity": constants.severity_for_kind(kind, entry.get("severity")),
            "name": entry.get("title") or entry.get("name") or f"{name}@{version}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ecosystem": ecosystem.lower(),
            "package_name": name,
            "package_version": version,
            "advisory_id": entry.get("advisoryId") or entry.get("advisory_id"),
            "references": entry.get("references") or [],
            "kind": kind,
        }
    if category == "fileaccess":
        tool = str(
            entry.get("toolName") or entry.get("tool") or entry.get("tool_name") or ""
        ).strip()
        file_category = str(entry.get("category") or entry.get("file_category") or "").strip()
        if not tool or not file_category:
            raise ValueError("fileaccess needs tool + category")
        identifier = threat_ids.fileaccess_identifier(tool, file_category)
        return "fileaccess", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{tool} :: {file_category}",
            "description": entry.get("summary") or entry.get("description") or "",
            "tool_name": tool.lower(),
            "file_category": file_category.lower(),
        }
    if category == "skill":
        skill_name = str(
            entry.get("skillName") or entry.get("skill_name") or entry.get("name") or ""
        ).strip()
        skill_version = str(
            entry.get("skillVersion") or entry.get("skill_version") or entry.get("version") or ""
        ).strip()
        danger_shape = str(entry.get("dangerShape") or entry.get("danger_shape") or "").strip()
        if not skill_name or not (skill_version or danger_shape):
            raise ValueError("skill needs name + (version or dangerShape)")
        if skill_version:
            identifier = threat_ids.skill_version_identifier(skill_name, skill_version)
        else:
            identifier = threat_ids.skill_shape_identifier(skill_name, danger_shape)
        return "skill", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or f"Skill {skill_name}",
            "description": entry.get("summary") or entry.get("description") or "",
            "skill_name": skill_name.lower(),
            "skill_version": skill_version or None,
            "danger_shape": danger_shape or None,
        }
    raise ValueError(f"unknown entry type: {category!r}")
