"""Graph-synced rule cache.

The :class:`Ruleset` is built only from the curated public
``verifiable-memory`` graph. Community Shared Working Memory is a future
feature and is neither queried nor matched by the current release.

It is cached to ``$BLACKBOX_HOME/ruleset.json`` and refreshed lazily:
:func:`get` returns the cached ruleset immediately and, if the cache is older
than ``sync_interval``, kicks off a single non-blocking background refresh.
Every refresh path shares a file lock so only one ruleset generation is built
across processes. Every path fails open to the last-good (or empty) ruleset.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import constants, quads
from .config import BlackboxConfig, load_blackbox_config
from .dkg_client import DkgClient, extract_binding

logger = logging.getLogger(__name__)

_SELECT_COLUMNS = """?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue ?targetSubject
       ?correctionAction ?canonicalType ?observationCategory
       ?lifecycleStatus ?normalizedValue ?provenanceJson ?sourceId"""

_DEFENDER_PREFIXES = """PREFIX defender: <urn:defender:>
PREFIX dp: <urn:defender:p:>
PREFIX blackbox: <urn:blackbox:>
PREFIX bp: <urn:blackbox:p:>
PREFIX schema: <http://schema.org/>
"""

# Rows fetched per page when syncing a tier. One SPARQL round-trip each.
_PAGE_SIZE = 5000
# Safety ceiling so a misbehaving node can never spin the pager forever.
_MAX_ROWS = 1_000_000
# Public VM snapshots are stored in bounded, confirmed named graphs. Querying
# five partitions at a time keeps Blazegraph responses comfortably below the
# client timeout while avoiding the expensive all-VM deduplication rewrite.
_VM_PARTITION_BATCH_SIZE = 5
_VM_PARTITION_QUERY_LIMIT = 50_000
_VM_PARTITION_QUERY_TIMEOUT = 120.0
_FORBIDDEN_IRI_CHARS = frozenset('<>"{}|^`\\\r\n\t')


def _threat_cursor_filter(after: str) -> str:
    if not after:
        return ""
    return f"FILTER(STR(?threat) > {json.dumps(after, ensure_ascii=True)})"


def _defender_page_sparql(
    signal_type: str,
    properties: str,
    limit: int,
    after: str,
    graph_uri: str = "",
) -> str:
    cursor_filter = _threat_cursor_filter(after)
    body = f"""    {{
        SELECT ?threat WHERE {{
            ?threat a defender:{signal_type} .
            {cursor_filter}
        }}
        ORDER BY STR(?threat)
        LIMIT {int(limit)}
    }}
    BIND(defender:{signal_type} AS ?rdfType)
{properties}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _source_observations_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> str:
    """Fetch compact IOC observations without pulling citation triples."""
    cursor_filter = _threat_cursor_filter(after)
    body = f"""    {{
        SELECT ?threat WHERE {{
            ?threat a blackbox:SourceObservation .
            {cursor_filter}
        }}
        ORDER BY STR(?threat)
        LIMIT {int(limit)}
    }}
    BIND(blackbox:SourceObservation AS ?rdfType)
    OPTIONAL {{ ?threat bp:canonicalType ?canonicalType . }}
    OPTIONAL {{ ?threat bp:category ?observationCategory . }}
    OPTIONAL {{ ?threat bp:lifecycleStatus ?lifecycleStatus . }}
    OPTIONAL {{ ?threat bp:normalizedValue ?normalizedValue . }}
    OPTIONAL {{ ?threat bp:provenanceJson ?provenanceJson . }}
    OPTIONAL {{ ?threat bp:sourceId ?sourceId . }}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _threats_sparql(limit: int, after: str = "", graph_uri: str = "") -> str:
    return _defender_page_sparql(
        "DependencySignal",
        """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:package ?packageName . }
    OPTIONAL { ?threat dp:version ?packageVersion . }
    OPTIONAL { ?threat dp:ecosystem ?packageEcosystem . }
    OPTIONAL { ?threat dp:advisoryId ?advisoryId . }""",
        limit,
        after,
        graph_uri,
    )


def _defender_threats_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> tuple:
    return (
        _threats_sparql(limit, after, graph_uri),
        _defender_page_sparql(
            "InjectionSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:pattern ?pattern . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "SkillSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "IocSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:iocType ?category . }
    OPTIONAL { ?threat dp:value ?iocValue . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "CorrectionSignal",
            """    OPTIONAL { ?threat dp:targetSubject ?targetSubject . }
    OPTIONAL { ?threat dp:action ?correctionAction . }""",
            limit,
            after,
            graph_uri,
        ),
        _source_observations_sparql(limit, after, graph_uri),
    )


def _legacy_threats_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> str:
    cursor_filter = _threat_cursor_filter(after)
    body = f"""  {{
    SELECT ?threat WHERE {{
      ?threat g:identifier ?cursorIdentifier .
      {cursor_filter}
    }}
    ORDER BY STR(?threat)
    LIMIT {int(limit)}
  }}
  ?threat g:identifier ?identifier .
  OPTIONAL {{ ?threat a ?rdfType . }}
  OPTIONAL {{ ?threat g:kind ?kind . }}
  OPTIONAL {{ ?threat g:severity ?severity . }}
  OPTIONAL {{ ?threat schema:name ?name . }}
  OPTIONAL {{ ?threat schema:description ?description . }}
  OPTIONAL {{ ?threat g:pattern ?pattern . }}
  OPTIONAL {{ ?threat g:toolName ?toolName . }}
  OPTIONAL {{ ?threat g:argShape ?argShape . }}
  OPTIONAL {{ ?threat g:packageName ?packageName . }}
  OPTIONAL {{ ?threat g:packageVersion ?packageVersion . }}
  OPTIONAL {{ ?threat g:packageEcosystem ?packageEcosystem . }}
  OPTIONAL {{ ?threat schema:identifier ?advisoryId . }}
  OPTIONAL {{ ?threat g:curated ?curated . }}
  OPTIONAL {{ ?threat g:category ?category . }}
  OPTIONAL {{ ?threat g:skillName ?skillName . }}
  OPTIONAL {{ ?threat g:skillVersion ?skillVersion . }}
  OPTIONAL {{ ?threat g:dangerShape ?dangerShape . }}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _context_graph_data_uri(cg_id: str) -> str:
    value = str(cg_id or "").strip()
    if not value or any(char in value for char in _FORBIDDEN_IRI_CHARS):
        return ""
    return f"did:dkg:context-graph:{value}"


def _verified_partitions_sparql(cg_id: str) -> str:
    data_graph = _context_graph_data_uri(cg_id)
    if not data_graph:
        return ""
    vm_prefix = f"{data_graph}/_verifiable_memory/"
    return f"""PREFIX dkg: <http://dkg.io/ontology/>
SELECT DISTINCT ?assertionGraph ?status WHERE {{
  GRAPH <{data_graph}/_meta> {{
    ?ka dkg:assertionGraph ?assertionGraph .
    OPTIONAL {{ ?ka dkg:status ?status . }}
  }}
  FILTER(STRSTARTS(STR(?assertionGraph), {json.dumps(vm_prefix)}))
}}
ORDER BY ?assertionGraph
"""


def _partition_threats_sparql(
    graph_uris: List[str],
    *,
    limit: int = _VM_PARTITION_QUERY_LIMIT,
    offset: int = 0,
) -> str:
    values = " ".join(f"<{uri}>" for uri in graph_uris)
    return f"""{_DEFENDER_PREFIXES}PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT DISTINCT ?sourceGraph {_SELECT_COLUMNS}
WHERE {{
  VALUES ?sourceGraph {{ {values} }}
  GRAPH ?sourceGraph {{
    {{
      ?threat a ?rdfType .
      VALUES ?rdfType {{
        defender:DependencySignal defender:InjectionSignal
        defender:SkillSignal defender:IocSignal defender:CorrectionSignal
        blackbox:SourceObservation
      }}
    }} UNION {{
      ?threat g:identifier ?identifier .
      OPTIONAL {{ ?threat a ?rdfType . }}
    }}
    OPTIONAL {{ ?threat dp:kind ?kind . }}
    OPTIONAL {{ ?threat g:kind ?kind . }}
    OPTIONAL {{ ?threat dp:severity ?severity . }}
    OPTIONAL {{ ?threat g:severity ?severity . }}
    OPTIONAL {{ ?threat schema:name ?name . }}
    OPTIONAL {{ ?threat schema:description ?description . }}
    OPTIONAL {{ ?threat dp:pattern ?pattern . }}
    OPTIONAL {{ ?threat g:pattern ?pattern . }}
    OPTIONAL {{ ?threat g:toolName ?toolName . }}
    OPTIONAL {{ ?threat g:argShape ?argShape . }}
    OPTIONAL {{ ?threat dp:package ?packageName . }}
    OPTIONAL {{ ?threat g:packageName ?packageName . }}
    OPTIONAL {{ ?threat dp:version ?packageVersion . }}
    OPTIONAL {{ ?threat g:packageVersion ?packageVersion . }}
    OPTIONAL {{ ?threat dp:ecosystem ?packageEcosystem . }}
    OPTIONAL {{ ?threat g:packageEcosystem ?packageEcosystem . }}
    OPTIONAL {{ ?threat dp:advisoryId ?advisoryId . }}
    OPTIONAL {{ ?threat schema:identifier ?advisoryId . }}
    OPTIONAL {{ ?threat g:curated ?curated . }}
    OPTIONAL {{ ?threat dp:iocType ?category . }}
    OPTIONAL {{ ?threat g:category ?category . }}
    OPTIONAL {{ ?threat g:skillName ?skillName . }}
    OPTIONAL {{ ?threat g:skillVersion ?skillVersion . }}
    OPTIONAL {{ ?threat g:dangerShape ?dangerShape . }}
    OPTIONAL {{ ?threat dp:value ?iocValue . }}
    OPTIONAL {{ ?threat dp:targetSubject ?targetSubject . }}
    OPTIONAL {{ ?threat dp:action ?correctionAction . }}
    OPTIONAL {{ ?threat bp:canonicalType ?canonicalType . }}
    OPTIONAL {{ ?threat bp:category ?observationCategory . }}
    OPTIONAL {{ ?threat bp:lifecycleStatus ?lifecycleStatus . }}
    OPTIONAL {{ ?threat bp:normalizedValue ?normalizedValue . }}
    OPTIONAL {{ ?threat bp:provenanceJson ?provenanceJson . }}
    OPTIONAL {{ ?threat bp:sourceId ?sourceId . }}
  }}
}}
ORDER BY ?sourceGraph ?threat
LIMIT {int(limit)}
OFFSET {int(offset)}
"""


def community_report_count(client: DkgClient, cfg: BlackboxConfig) -> int:
    """Count outbound sightings in the official SWM view."""
    sparql = (
        "SELECT (COUNT(DISTINCT ?r) AS ?n) WHERE { "
        "?r a <http://umanitek.ai/ontology/guardian/ThreatReport> }"
    )
    rows = client.query(
        sparql,
        cfg.context_graph_id,
        view=constants.VIEW_SHARED_WORKING_MEMORY,
        on_error=None,
    )
    if not rows:
        return 0
    try:
        return int(extract_binding(rows[0].get("n")) or 0)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Legacy proof verification (backward compatibility)
# ---------------------------------------------------------------------------

# This fallback keeps already-published proof-era rows effective.
_PROOFS_SPARQL = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?proof ?root ?member WHERE {
  ?proof a g:CurationProof .
  ?proof g:anchorRoot ?root .
  ?proof g:anchorMember ?member .
}"""


def _fetch_proofs(client: DkgClient, cg_id: str) -> Dict[str, Dict[str, Any]]:
    """Legacy proofs from the VM view: subject -> {root, members}. Fail-open
    to {} — no proofs simply means no community row can be promoted."""
    try:
        rows = client.query(_PROOFS_SPARQL, cg_id, view=constants.VIEW_VERIFIABLE_MEMORY, on_error=None)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: proof query failed: %s", exc)
        return {}
    proofs: Dict[str, Dict[str, Any]] = {}
    for row in rows or []:
        subj = extract_binding(row.get("proof"))
        root = extract_binding(row.get("root"))
        member = extract_binding(row.get("member"))
        if not (subj and root and member):
            continue
        entry = proofs.setdefault(subj, {"root": root, "members": set()})
        if entry["root"] == root:
            entry["members"].add(member)
    return proofs


def verified_identifiers(community_rows: List[Dict[str, Any]], proofs: Dict[str, Dict[str, Any]]) -> set:
    """Identifiers of SWM threat rows covered by a matching VM proof.

    A proof verifies only when EVERY member is present locally and the batch
    root recomputed over their anchor hashes equals the published root — a
    tampered or missing row invalidates its whole batch, never silently
    passes. Verified identifiers earn the blockable ``public`` tier.
    """
    candidates: List[Dict[str, str]] = []
    for row in community_rows:
        # Hash only threat-subject rows: reports (urn:guardian:report:*) share
        # the identifier and would shadow the threat row's hash.
        if not extract_binding(row.get("threat")).startswith("urn:guardian:threat:"):
            continue
        candidates.append({k: extract_binding(row.get(k)) for k in quads.ANCHOR_FIELDS})
    if not candidates or not proofs:
        return set()
    hashes = quads.anchor_hashes_from_rows(candidates)
    ok: set = set()
    for entry in proofs.values():
        members = entry["members"]
        if not members or not members.issubset(hashes.keys()):
            continue
        root = quads.anchor_root((ident, hashes[ident]) for ident in members)
        if root == entry["root"]:
            ok |= members
    return ok


@dataclass
class Ruleset:
    """Compiled detection rules. See :mod:`detection` for how each is used."""

    injection: List[Dict[str, Any]] = field(default_factory=list)
    escalation: List[Dict[str, Any]] = field(default_factory=list)
    dependency: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    fileaccess: List[Dict[str, Any]] = field(default_factory=list)
    skill: List[Dict[str, Any]] = field(default_factory=list)
    # IOC rules keyed by full identifier (``ioc:{type}:{value}``) for O(1) lookup.
    ioc: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    graph_threats: List[Dict[str, Any]] = field(default_factory=list)
    synced_at: float = 0.0
    context_graph_id: str = ""
    _graph_entries_cache: Dict[str, List[Dict[str, Any]]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def counts(self) -> Dict[str, int]:
        return {
            "injection": len(self.injection),
            "escalation": len(self.escalation),
            "dependency": len(self.dependency),
            "fileaccess": len(self.fileaccess),
            "skill": len(self.skill),
            "ioc": len(self.ioc),
        }

    def iter_rules(self):
        """Yield ``(category, rule)`` for every rule across all categories, so
        callers (e.g. the dashboard) can filter/count by ``rule["source"]``
        straight from the synced cache instead of re-querying the node."""
        for r in self.injection:
            yield "injection", r
        for r in self.escalation:
            yield "escalation", r
        for r in self.dependency.values():
            yield "dependency", r
        for r in self.fileaccess:
            yield "fileaccess", r
        for r in self.skill:
            yield "skill", r
        for r in self.ioc.values():
            yield "ioc", r

    def source_count(self, source: str) -> int:
        """How many rules are tagged with *source* (``public`` | ``community``)."""
        return sum(1 for _cat, r in self.iter_rules() if r.get("source") == source)

    def graph_entries(self, source: str) -> List[Dict[str, Any]]:
        cached = self._graph_entries_cache.get(source)
        if cached is not None:
            return cached
        entries = [item for item in self.graph_threats if item.get("source") == source]
        seen = {item.get("identifier") for item in entries}
        for category, rule in self.iter_rules():
            identifier = rule.get("identifier")
            if rule.get("source") != source or identifier in seen:
                continue
            seen.add(identifier)
            entries.append({
                "identifier": identifier,
                "category": category,
                "severity": str(rule.get("severity") or "info").lower(),
                "name": rule.get("name") or "",
                "subject": rule.get("subject") or "",
                "source": source,
            })
        self._graph_entries_cache[source] = entries
        return entries

    def graph_count(self, source: str) -> int:
        return len(self.graph_entries(source))


# ---------------------------------------------------------------------------
# Build from query bindings
# ---------------------------------------------------------------------------


def _source_observation_provenance(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = extract_binding(row.get("provenanceJson"))
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _row_severity(row: Dict[str, Any]) -> str:
    severity = extract_binding(row.get("severity"))
    if not severity and extract_binding(row.get("rdfType")) == constants.SOURCE_OBSERVATION_TYPE_IRI:
        severity = _source_observation_provenance(row).get("severity")
    return constants.normalize_severity(severity, "high")


def _row_identity(row: Dict[str, Any]) -> tuple:
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
            identifier = f"ioc:{ioc_type}:{ioc_value}"
    elif not identifier and rdf_type == constants.SOURCE_OBSERVATION_TYPE_IRI:
        lifecycle = extract_binding(row.get("lifecycleStatus")).strip().lower()
        ioc_type = extract_binding(row.get("canonicalType")).strip().lower()
        ioc_value = extract_binding(row.get("normalizedValue"))
        if lifecycle == "active" and ioc_type in quads.IOC_TYPES and ioc_value:
            identifier = quads.ioc_identifier(ioc_type, ioc_value)
    return subject, rdf_type, identifier


def _row_to_graph_entry(row: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
    subject, _rdf_type, identifier = _row_identity(row)
    if not identifier:
        return None
    prefix = identifier.split(":", 1)[0].lower()
    category = {
        "dep": "dependency",
        "injection": "injection",
        "escalation": "escalation",
        "fileaccess": "fileaccess",
        "skill": "skill",
        "ioc": "ioc",
    }.get(prefix, "other")
    return {
        "identifier": identifier,
        "category": category,
        "severity": _row_severity(row),
        "name": (
            extract_binding(row.get("name"))
            or extract_binding(row.get("normalizedValue"))
            or identifier
        ),
        "subject": subject,
        "source": source,
    }


def _row_to_rule(row: Dict[str, Any], source: str = "public") -> Optional[tuple]:
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
            compiled = re.compile(pattern_src, re.IGNORECASE)
        except re.error as exc:
            logger.debug("blackbox: skipping bad injection pattern %s: %s", identifier, exc)
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
        eco = extract_binding(row.get("packageEcosystem")).lower()
        pkg = extract_binding(row.get("packageName")).lower()
        ver = extract_binding(row.get("packageVersion"))
        if not (eco and pkg and ver):
            # Fall back to parsing the identifier: dep:{eco}:{name}@{version}
            try:
                _, rest = identifier.split(":", 1)
                eco2, tail = rest.split(":", 1)
                pkg2, ver2 = tail.rsplit("@", 1)
                eco, pkg, ver = eco2.lower(), pkg2.lower(), ver2
            except ValueError:
                return None
        key = quads.dependency_key(eco, pkg, ver)
        return ("dependency", key, {
            **common,
            "ecosystem": eco,
            "packageName": pkg,
            "packageVersion": ver,
            "advisoryId": extract_binding(row.get("advisoryId")),
            "kind": extract_binding(row.get("kind")) or None,
        })
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


def build_from_rows(rows: List[Dict[str, Any]], source: str = "public") -> Ruleset:
    """Build a :class:`Ruleset` from ``(rows, source)`` pairs or plain rows.

    *rows* may be a flat list of binding rows (all tagged *source*) or a list
    of ``(row, source)`` tuples as produced by :func:`refresh`. Precedence is
    identifier-first-wins with public beating community, so a community row can
    never shadow (or escalate/downgrade) a curated public rule.
    """
    rs = Ruleset(synced_at=time.time())
    inj_seen: set = set()
    esc_seen: set = set()
    fa_seen: set = set()
    skill_seen: set = set()
    graph_seen: set = set()
    tagged_rows = []
    suppressed_subjects: set = set()
    for item in rows:
        if isinstance(item, tuple):
            row, row_source = item
        else:
            row, row_source = item, source
        tagged_rows.append((row, row_source))
        if row_source != "public":
            continue
        if extract_binding(row.get("rdfType")) != constants.DEFENDER_CORRECTION_TYPE_IRI:
            continue
        action = extract_binding(row.get("correctionAction")).strip().lower()
        target = extract_binding(row.get("targetSubject")).strip()
        if action == constants.DEFENDER_CORRECTION_SUPPRESS and target:
            suppressed_subjects.add(target)

    for row, row_source in tagged_rows:
        if extract_binding(row.get("threat")) in suppressed_subjects:
            continue
        graph_entry = _row_to_graph_entry(row, row_source)
        if graph_entry:
            graph_key = (row_source, graph_entry["identifier"])
            if graph_key not in graph_seen:
                graph_seen.add(graph_key)
                rs.graph_threats.append(graph_entry)
        mapped = _row_to_rule(row, row_source)
        if not mapped:
            continue
        category, key, rule = mapped
        if category == "injection":
            if key not in inj_seen:
                inj_seen.add(key)
                rs.injection.append(rule)
        elif category == "escalation":
            if key not in esc_seen:
                esc_seen.add(key)
                rs.escalation.append(rule)
        elif category == "fileaccess":
            if key not in fa_seen:
                fa_seen.add(key)
                rs.fileaccess.append(rule)
        elif category == "skill":
            if key not in skill_seen:
                skill_seen.add(key)
                rs.skill.append(rule)
        elif category == "ioc":
            existing = rs.ioc.get(key)
            # Public (curated) rules always win over community rows.
            if existing is None or (
                existing.get("source") == "community" and rule.get("source") == "public"
            ):
                rs.ioc[key] = rule
        else:
            existing = rs.dependency.get(key)
            # Public (curated) rules always win over community rows.
            if existing is None or (
                existing.get("source") == "community" and rule.get("source") == "public"
            ):
                rs.dependency[key] = rule
    return rs


# ---------------------------------------------------------------------------
# Cache persistence
# ---------------------------------------------------------------------------


def _cache_path() -> Path:
    return constants.blackbox_home() / "ruleset.json"


def _lock_path() -> Path:
    return constants.blackbox_home() / "ruleset.lock"


def _serialize(rs: Ruleset) -> Dict[str, Any]:
    return {
        "synced_at": rs.synced_at,
        "context_graph_id": rs.context_graph_id,
        "injection": [
            {k: v for k, v in rule.items() if k != "pattern"} for rule in rs.injection
        ],
        "escalation": rs.escalation,
        "dependency": rs.dependency,
        "fileaccess": rs.fileaccess,
        "skill": rs.skill,
        "ioc": rs.ioc,
        "graph_threats": rs.graph_threats,
    }


def _deserialize(data: Dict[str, Any]) -> Ruleset:
    rs = Ruleset(
        synced_at=float(data.get("synced_at", 0.0)),
        context_graph_id=str(data.get("context_graph_id") or ""),
    )
    for rule in data.get("injection", []):
        src = _normalize_injection_pattern(str(rule.get("pattern_src") or ""))
        if not src:
            continue
        try:
            compiled = re.compile(src, re.IGNORECASE)
        except re.error:
            continue
        if rule.get("source", "public") == "public":
            rs.injection.append({**rule, "pattern_src": src, "pattern": compiled})
    rs.escalation = [r for r in data.get("escalation", []) if r.get("source", "public") == "public"]
    rs.dependency = {k: r for k, r in data.get("dependency", {}).items() if r.get("source", "public") == "public"}
    rs.fileaccess = [r for r in data.get("fileaccess", []) if r.get("source", "public") == "public"]
    rs.skill = [r for r in data.get("skill", []) if r.get("source", "public") == "public"]
    rs.ioc = {k: r for k, r in data.get("ioc", {}).items() if r.get("source", "public") == "public"}
    rs.graph_threats = [r for r in data.get("graph_threats", []) if r.get("source", "public") == "public"]
    return rs


def _write_cache(rs: Ruleset) -> None:
    try:
        home = constants.blackbox_home()
        home.mkdir(parents=True, exist_ok=True)
        tmp = _cache_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_serialize(rs)), encoding="utf-8")
        tmp.replace(_cache_path())
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: ruleset cache write failed: %s", exc)


def _read_cache() -> Optional[Ruleset]:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return _deserialize(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: ruleset cache read failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

_memory_lock = threading.Lock()
_refresh_lock = threading.Lock()
_memory_cache: Optional[Ruleset] = None
_memory_cache_stamp: Optional[int] = None
_refreshing = False


_QUERY_ERROR = object()  # sentinel: distinguishes a tier failure from an empty tier


def _cache_file_stamp() -> Optional[int]:
    try:
        return _cache_path().stat().st_mtime_ns
    except OSError:
        return None


def _matches_context_graph(rs: Optional[Ruleset], context_graph_id: str) -> bool:
    """Return whether a cache generation belongs to the requested graph.

    Cache files written before graph identity was persisted are accepted only
    for the built-in release graph. They cannot safely be attributed to an
    explicitly configured custom graph.
    """
    if rs is None:
        return False
    cached_graph = str(rs.context_graph_id or "")
    if cached_graph:
        return cached_graph == context_graph_id
    return context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID


def _latest_cached_ruleset(context_graph_id: str = "") -> Optional[Ruleset]:
    """Return the matching memory/disk generation, reloading replacements."""
    global _memory_cache, _memory_cache_stamp
    stamp = _cache_file_stamp()
    with _memory_lock:
        cached = _memory_cache
        known_stamp = _memory_cache_stamp
    if cached is not None and stamp == known_stamp:
        if context_graph_id and not _matches_context_graph(cached, context_graph_id):
            return None
        return cached
    disk = _read_cache()
    with _memory_lock:
        if disk is not None:
            _memory_cache = disk
            cached = disk
        _memory_cache_stamp = stamp
    if context_graph_id and not _matches_context_graph(cached, context_graph_id):
        return None
    return cached


def _fetch_tier(
    client: DkgClient,
    cg_id: str,
    view: str,
    agent_address: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Fully paginate one tier. Returns all rows, or ``None`` if the node errored.

    ``None`` (error) is distinct from ``[]`` (the tier is genuinely empty) so
    the caller can preserve a tier's last-good rules through a transient failure
    instead of wiping them.
    """
    if view == constants.VIEW_VERIFIABLE_MEMORY:
        partition_query = _verified_partitions_sparql(cg_id)
        if not partition_query:
            return None
        metadata = client.query(
            partition_query,
            cg_id,
            view=None,
            on_error=_QUERY_ERROR,
        )
        if metadata is _QUERY_ERROR:
            return None

        data_graph = _context_graph_data_uri(cg_id)
        vm_prefix = f"{data_graph}/_verifiable_memory/"
        partition_metadata = [
            (graph, extract_binding(row.get("status")))
            for row in metadata
            if (graph := extract_binding(row.get("assertionGraph"))).startswith(vm_prefix)
            and graph != vm_prefix
            and not any(char in graph for char in _FORBIDDEN_IRI_CHARS)
        ]
        partition_graphs = {graph for graph, _status in partition_metadata}
        partitions = sorted(
            {graph for graph, status in partition_metadata if status == "confirmed"}
        )
        # A broad VM query would union tentative assertion graphs and promote
        # them to public rules. Preserve the last-good tier until every graph
        # selected here is explicitly confirmed.
        if partition_graphs and not partitions:
            return None

        partition_rows: List[Dict[str, Any]] = []
        if partitions:
            for start in range(0, len(partitions), _VM_PARTITION_BATCH_SIZE):
                batch = partitions[start : start + _VM_PARTITION_BATCH_SIZE]
                offset = 0
                while len(partition_rows) < _MAX_ROWS:
                    page = client.query(
                        _partition_threats_sparql(batch, offset=offset),
                        cg_id,
                        view=None,
                        on_error=_QUERY_ERROR,
                        timeout=_VM_PARTITION_QUERY_TIMEOUT,
                    )
                    if page is _QUERY_ERROR:
                        return None
                    partition_rows.extend(page)
                    if len(page) < _VM_PARTITION_QUERY_LIMIT:
                        break
                    offset += _VM_PARTITION_QUERY_LIMIT
            if len(partition_rows) >= _MAX_ROWS:
                return None

        root_rows = _fetch_paged_lanes(
            client,
            cg_id,
            lambda limit, after: (
                _legacy_threats_sparql(limit, after, data_graph),
                *_defender_threats_sparql(limit, after, data_graph),
            ),
            view=None,
        )
        if root_rows is None:
            return None
        if len(partition_rows) + len(root_rows) >= _MAX_ROWS:
            return None
        return _dedupe_threat_rows([*partition_rows, *root_rows])

    return _fetch_paged_lanes(
        client,
        cg_id,
        lambda limit, after: (
            _legacy_threats_sparql(limit, after),
            *_defender_threats_sparql(limit, after),
        ),
        view=view,
        agent_address=agent_address,
    )


def _fetch_paged_lanes(
    client: DkgClient,
    cg_id: str,
    query_lanes: Callable[[int, str], tuple],
    *,
    view: Optional[str],
    agent_address: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    lane_count = len(query_lanes(1, ""))
    for lane_index in range(lane_count):
        after = ""
        fetched_subjects = 0
        while fetched_subjects < _MAX_ROWS:
            kwargs: Dict[str, Any] = {"view": view, "on_error": _QUERY_ERROR}
            if agent_address:
                kwargs["agent_address"] = agent_address
            query = query_lanes(_PAGE_SIZE, after)[lane_index]
            page = client.query(query, cg_id, **kwargs)
            if page is _QUERY_ERROR:
                return None
            rows.extend(page)
            page_subjects = list(
                dict.fromkeys(
                    subject
                    for row in page
                    if (subject := extract_binding(row.get("threat")))
                )
            )
            if not page_subjects:
                if page:
                    return None
                break
            next_cursor = page_subjects[-1]
            if next_cursor <= after:
                return None
            fetched_subjects += len(page_subjects)
            if len(page_subjects) < _PAGE_SIZE:
                break
            after = next_cursor
    return rows


def _dedupe_threat_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Prefer confirmed partition rows when a migrated root repeats a threat."""
    result: List[Dict[str, Any]] = []
    seen: set = set()
    for row in rows:
        threat = extract_binding(row.get("threat"))
        if threat and threat in seen:
            continue
        if threat:
            seen.add(threat)
        result.append(row)
    return result


_EMPTY_RULESET_RETRY_S = 30.0
_NONEMPTY_REFRESH_MIN_S = 15 * 60.0
_WINDOWS_FILE_LOCK_TIMEOUT_S = 30.0
_WINDOWS_FILE_LOCK_POLL_S = 0.05


class RulesetRefreshUnavailable(RuntimeError):
    """A required post-barrier refresh did not produce a fresh snapshot."""


class RulesetRefreshLockUnavailable(RulesetRefreshUnavailable):
    """A required post-barrier refresh could not acquire its process lock."""


class RulesetRefreshIncomplete(RulesetRefreshUnavailable):
    """A required post-barrier refresh could not read a complete VM snapshot."""


def _is_windows_platform() -> bool:
    return os.name == "nt"


@contextmanager
def _ruleset_refresh_lock(*, blocking: bool):
    """Serialize expensive VM reads across threads and Blackbox processes."""
    thread_acquired = _refresh_lock.acquire(blocking=blocking)
    if not thread_acquired:
        yield False
        return

    lock_fh = None
    file_acquired = False
    try:
        try:
            home = constants.blackbox_home()
            home.mkdir(parents=True, exist_ok=True)
            lock_fh = open(_lock_path(), "a+b")  # windows-footgun: ok - binary byte lock
            if _is_windows_platform():  # pragma: no cover - exercised via helper
                if _lock_path().stat().st_size == 0:
                    lock_fh.write(b"0")
                    lock_fh.flush()
                lock_fh.seek(0)
                if not _acquire_windows_file_lock(lock_fh, blocking=blocking):
                    lock_fh.close()
                    lock_fh = None
                    yield False
                    return
            else:
                import fcntl

                operation = fcntl.LOCK_EX
                if not blocking:
                    operation |= fcntl.LOCK_NB
                fcntl.flock(lock_fh.fileno(), operation)
            file_acquired = True
        except BlockingIOError:
            if lock_fh is not None:
                lock_fh.close()
                lock_fh = None
            yield False
            return
        except OSError:
            if _is_windows_platform():
                if lock_fh is not None:
                    lock_fh.close()
                    lock_fh = None
                yield False
                return
            if lock_fh is not None:
                lock_fh.close()
                lock_fh = None
        except Exception:
            if lock_fh is not None:
                lock_fh.close()
                lock_fh = None
            if _is_windows_platform():
                yield False
                return
            # Retain the in-process guard on platforms without a usable file
            # lock. Ruleset refreshes are fail-open by design.

        yield True
    finally:
        if lock_fh is not None:
            try:
                if file_acquired:
                    if _is_windows_platform():  # pragma: no cover - exercised on Windows
                        import msvcrt

                        lock_fh.seek(0)
                        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            finally:
                lock_fh.close()
        _refresh_lock.release()


def _acquire_windows_file_lock(
    lock_fh: Any,
    *,
    blocking: bool,
    msvcrt_module: Any = None,
    timeout_s: float = _WINDOWS_FILE_LOCK_TIMEOUT_S,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Acquire one Windows byte lock within a bounded contention window."""
    if msvcrt_module is None:  # pragma: no cover - imported only on Windows
        import msvcrt as msvcrt_module

    deadline = monotonic() + max(0.0, timeout_s)
    while True:
        lock_fh.seek(0)
        try:
            msvcrt_module.locking(
                lock_fh.fileno(),
                msvcrt_module.LK_NBLCK,
                1,
            )
            return True
        except OSError as exc:
            if not blocking:
                return False
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False
            sleep(min(_WINDOWS_FILE_LOCK_POLL_S, remaining))


def refresh(
    config: Optional[BlackboxConfig] = None,
    client: Optional[DkgClient] = None,
    *,
    wait_for_lock: bool = True,
    force_query: bool = False,
) -> Ruleset:
    """Query the node, rebuild the ruleset, and persist it. Fail-open.

    Reads only the verified public graph (VM), fully paginated (no cap). If its
    query fails, the last-good public rules are preserved. On total
    failure, returns the last-good cache or an empty ruleset. ``force_query``
    raises :class:`RulesetRefreshUnavailable` unless it can acquire the
    serialization lock and read a non-empty VM snapshot, allowing
    completion-barrier callers to fail closed. ``force_query`` is reserved for
    callers that have crossed a DKG completion barrier and must not adopt a
    generation started before that barrier.
    """
    config = config or load_blackbox_config()
    context_graph_id = config.context_graph_id
    initial_stamp = _cache_file_stamp()
    with _ruleset_refresh_lock(blocking=wait_for_lock) as acquired:
        if not acquired:
            if force_query:
                raise RulesetRefreshLockUnavailable(
                    "post-barrier ruleset refresh lock is unavailable"
                )
            return _latest_cached_ruleset(context_graph_id) or Ruleset(
                context_graph_id=context_graph_id
            )
        # If another process completed while this caller waited, its atomic
        # replacement is the requested fresh generation. Reuse it instead of
        # immediately issuing the same large query sequence again.
        if not force_query and _cache_file_stamp() != initial_stamp:
            latest = _latest_cached_ruleset(context_graph_id)
            if latest is not None:
                return latest
        return _refresh_unlocked(config, client, require_complete=force_query)


def _refresh_unlocked(
    config: Optional[BlackboxConfig] = None,
    client: Optional[DkgClient] = None,
    *,
    require_complete: bool = False,
) -> Ruleset:
    """Refresh while the caller holds :func:`_ruleset_refresh_lock`."""
    global _memory_cache, _memory_cache_stamp
    config = config or load_blackbox_config()
    context_graph_id = config.context_graph_id
    client = client or DkgClient(url=config.dkg_url, dkg_home=config.dkg_home)
    tiers = ((constants.VIEW_VERIFIABLE_MEMORY, "public"),)
    fetched = {tier: _fetch_tier(client, config.context_graph_id, view) for view, tier in tiers}

    # An entirely empty store gets an early cache-expiry below. Subscription,
    # admission, and catch-up are DKG daemon responsibilities; a cache read must
    # never restart network recovery.
    empty_success = all(rows == [] for rows in fetched.values())
    failed_tiers = [tier for tier, rows in fetched.items() if rows is None]

    if require_complete:
        if failed_tiers:
            raise RulesetRefreshIncomplete(
                "post-barrier VM query failed for "
                + ", ".join(sorted(failed_tiers))
            )
        if empty_success:
            raise RulesetRefreshIncomplete(
                "post-barrier VM query returned an empty snapshot"
            )

    if empty_success:
        # Snapshot replacement is atomic from the user's perspective. A
        # transient empty query (or a concurrent refresh racing catch-up)
        # must never erase an already verified, enforceable ruleset.
        disk_prior = _read_cache()
        candidates = [
            item
            for item in (_memory_cache, disk_prior)
            if _matches_context_graph(item, context_graph_id)
        ]
        prior = max(candidates, key=lambda item: item.source_count("public"), default=None)
        if prior is not None and prior.source_count("public") > 0:
            prior.context_graph_id = context_graph_id
            prior.synced_at = time.time()
            _write_cache(prior)
            with _memory_lock:
                _memory_cache = prior
                _memory_cache_stamp = _cache_file_stamp()
            return prior

    if all(rows is None for rows in fetched.values()):
        # Every tier failed — keep the last-good ruleset instead of emptying.
        existing = _latest_cached_ruleset(context_graph_id)
        if existing is not None:
            existing.context_graph_id = context_graph_id
            existing.synced_at = time.time()
            _write_cache(existing)
            with _memory_lock:
                _memory_cache = existing
                _memory_cache_stamp = _cache_file_stamp()
            return existing

    rows: List[Any] = []
    for tier, view_rows in fetched.items():
        if view_rows is None:  # a failed tier (fail-open handled below)
            continue
        rows.extend((row, tier) for row in view_rows)
    rs = build_from_rows(rows)
    rs.context_graph_id = context_graph_id
    if empty_success:
        # A fresh node's subscribe/catch-up is async. Do not cache "0 rules" as
        # fresh for the full sync interval; retry soon so the dashboard updates
        # shortly after VM lands locally.
        interval = max(1.0, float(config.sync_interval or 1))
        retry_after = min(_EMPTY_RULESET_RETRY_S, interval)
        rs.synced_at = time.time() - interval + retry_after

    errored = failed_tiers
    if errored:
        prior = _latest_cached_ruleset(context_graph_id)
        if prior is not None:
            _restore_tiers(rs, prior, errored)

    _write_cache(rs)
    with _memory_lock:
        _memory_cache = rs
        _memory_cache_stamp = _cache_file_stamp()
    return rs


def _restore_tiers(rs: Ruleset, prior: Ruleset, tiers: List[str]) -> None:
    """Re-add *prior* rules from the given (errored) *tiers* into *rs*.

    Only fills gaps: a rule already present from a freshly-fetched tier wins,
    and public still beats community for a shared dependency key — mirroring
    :func:`build_from_rows` precedence.
    """
    keep = set(tiers)
    graph_seen = {(item.get("source"), item.get("identifier")) for item in rs.graph_threats}
    for item in prior.graph_threats:
        key = (item.get("source"), item.get("identifier"))
        if item.get("source") in keep and key not in graph_seen:
            graph_seen.add(key)
            rs.graph_threats.append(item)
    for attr in ("injection", "escalation", "fileaccess", "skill"):
        seen = {r.get("identifier") for r in getattr(rs, attr)}
        for rule in getattr(prior, attr):
            if rule.get("source") in keep and rule.get("identifier") not in seen:
                getattr(rs, attr).append(rule)
    for attr in ("dependency", "ioc"):
        target = getattr(rs, attr)
        for key, rule in getattr(prior, attr).items():
            if rule.get("source") not in keep:
                continue
            existing = target.get(key)
            if existing is None or (existing.get("source") == "community" and rule.get("source") == "public"):
                target[key] = rule
    rs._graph_entries_cache.clear()


def _background_refresh(config: BlackboxConfig) -> None:
    global _refreshing
    try:
        refresh(config, wait_for_lock=False)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: background refresh failed: %s", exc)
    finally:
        _refreshing = False


def get(config: Optional[BlackboxConfig] = None) -> Ruleset:
    """Return the cached ruleset, lazily refreshing in the background if stale.

    Never blocks on the network: a stale cache is returned immediately while a
    single background thread refreshes it for the next call.
    """
    global _memory_cache, _memory_cache_stamp, _refreshing
    config = config or load_blackbox_config()
    cached = _latest_cached_ruleset(config.context_graph_id)
    if cached is None:
        disk = _read_cache()
        cached = (
            disk
            if _matches_context_graph(disk, config.context_graph_id)
            else Ruleset(context_graph_id=config.context_graph_id)
        )
        with _memory_lock:
            _memory_cache = cached
            _memory_cache_stamp = _cache_file_stamp()
    age = time.time() - cached.synced_at
    refresh_after = max(1.0, float(config.sync_interval or 1))
    if cached.source_count("public") > 0:
        refresh_after = max(refresh_after, _NONEMPTY_REFRESH_MIN_S)
    # Atomic check-and-set under the lock so two callers can't both spawn.
    should_spawn = False
    with _memory_lock:
        if age > refresh_after and not _refreshing:
            _refreshing = True
            should_spawn = True
    if should_spawn:
        try:
            threading.Thread(
                target=_background_refresh, args=(config,), name="blackbox-ruleset", daemon=True
            ).start()
        except Exception:  # pragma: no cover
            with _memory_lock:
                _refreshing = False
    return cached


def peek(config: Optional[BlackboxConfig] = None) -> Ruleset:
    """Return the last cached ruleset without starting a node refresh.

    The dashboard has one dedicated refresh worker. Request handlers and the
    dashboard's catch-up watcher use this read-only path so a large initial DKG
    transfer cannot accidentally fan out additional Blazegraph queries.
    """
    global _memory_cache, _memory_cache_stamp
    config = config or load_blackbox_config()
    cached = _latest_cached_ruleset(config.context_graph_id)
    if cached is None:
        disk = _read_cache()
        cached = (
            disk
            if _matches_context_graph(disk, config.context_graph_id)
            else Ruleset(context_graph_id=config.context_graph_id)
        )
        with _memory_lock:
            _memory_cache = cached
            _memory_cache_stamp = _cache_file_stamp()
    return cached
