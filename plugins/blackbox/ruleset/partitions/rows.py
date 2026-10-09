"""One verified partition's triples rebuilt into threat rows (Builder).

Reproduces exactly the rows the old joined partition query produced — same
columns, same SPARQL semantics (two branches, first-predicate-wins columns,
the product of multi-valued columns, DISTINCT) — so the compiler is unchanged.
Why the joined query was replaced: see the package docstring (KI-288/KI-289).

Usage: ``rows = rows_from_triples(partition_iri, [(subject, predicate, object), ...])``
"""

from __future__ import annotations

import itertools
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

Row = Dict[str, str]
Triple = Tuple[str, str, str]

_RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
_DP = "urn:defender:p:"
_G = "http://umanitek.ai/ontology/guardian/"
_BP = "urn:blackbox:p:"
_SCHEMA = "http://schema.org/"
_IDENTIFIER = f"{_G}identifier"

#: Types the joined query's first branch selected (``VALUES ?rdfType``).
THREAT_TYPES = frozenset({
    "urn:defender:DependencySignal", "urn:defender:InjectionSignal", "urn:defender:SkillSignal",
    "urn:defender:IocSignal", "urn:defender:CorrectionSignal", "urn:blackbox:SourceObservation",
})

#: Row column -> the predicates that fill it, in the order the joined query
#: tried them. Two OPTIONALs binding one variable do not union: the second only
#: matches values equal to the first, so a column takes the FIRST predicate's
#: values when it has any, otherwise the next one's.
COLUMN_PREDICATES: Dict[str, Tuple[str, ...]] = {
    "kind": (f"{_DP}kind", f"{_G}kind"),
    "severity": (f"{_DP}severity", f"{_G}severity"),
    "name": (f"{_SCHEMA}name",),
    "description": (f"{_SCHEMA}description",),
    "pattern": (f"{_DP}pattern", f"{_G}pattern"),
    "toolName": (f"{_G}toolName",),
    "argShape": (f"{_G}argShape",),
    "packageName": (f"{_DP}package", f"{_G}packageName"),
    "packageVersion": (f"{_DP}version", f"{_G}packageVersion"),
    "packageEcosystem": (f"{_DP}ecosystem", f"{_G}packageEcosystem"),
    "advisoryId": (f"{_DP}advisoryId", f"{_SCHEMA}identifier"),
    "curated": (f"{_G}curated",),
    "category": (f"{_DP}iocType", f"{_G}category"),
    "skillName": (f"{_G}skillName",),
    "skillVersion": (f"{_G}skillVersion",),
    "dangerShape": (f"{_G}dangerShape",),
    "iocValue": (f"{_DP}value",),
    "targetSubject": (f"{_DP}targetSubject",),
    "correctionAction": (f"{_DP}action",),
    "canonicalType": (f"{_BP}canonicalType",),
    "observationCategory": (f"{_BP}category",),
    "lifecycleStatus": (f"{_BP}lifecycleStatus",),
    "normalizedValue": (f"{_BP}normalizedValue",),
    "provenanceJson": (f"{_BP}provenanceJson",),
    "sourceId": (f"{_BP}sourceId",),
}


def rows_from_triples(source_graph: str, triples: Iterable[Triple], *, max_rows: Optional[int] = None) -> List[Row]:
    """Rebuild the joined query's rows for one partition from its triples.

    Branch 1 — a threat typed as one of :data:`THREAT_TYPES` — yields rows with
    that ``rdfType`` and no ``identifier``. Branch 2 — anything carrying
    ``g:identifier`` — yields rows with that identifier and each of its types
    (or none). Each other column multiplies rows by its values (the SPARQL
    product); rows are de-duplicated (DISTINCT) and ordered by threat.
    """
    facts: Dict[str, Dict[str, List[str]]] = {}
    for threat, predicate, value in triples:
        values = facts.setdefault(threat, {}).setdefault(predicate, [])
        if value not in values:
            values.append(value)
    rows: List[Row] = []
    seen = set()
    for threat in sorted(facts):
        for row in _threat_rows(source_graph, threat, facts[threat], max_rows=max_rows):
            key = tuple(sorted(row.items()))
            if key not in seen:
                seen.add(key)
                rows.append(row)
                if max_rows is not None and len(rows) > max_rows:
                    raise ValueError("selected rules exceed the decision bound")
    return rows


def _threat_rows(source_graph: str, threat: str, facts: Dict[str, List[str]], *, max_rows: Optional[int] = None) -> List[Row]:
    types = sorted(facts.get(_RDF_TYPE, []))
    bases: List[Dict[str, Optional[str]]] = [
        {"rdfType": rdf_type, "identifier": None} for rdf_type in types if rdf_type in THREAT_TYPES
    ]
    for identifier in sorted(facts.get(_IDENTIFIER, [])):
        bases.extend({"rdfType": rdf_type, "identifier": identifier} for rdf_type in (types or [None]))
    if not bases:
        return []
    columns = [(column, _column_values(facts, predicates)) for column, predicates in COLUMN_PREDICATES.items()]
    rows: List[Row] = []
    for base in bases:
        for combination in itertools.product(*(values for _column, values in columns)):
            row: Dict[str, Optional[str]] = {"sourceGraph": source_graph, "threat": threat, **base}
            row.update({column: value for (column, _values), value in zip(columns, combination)})
            rows.append({key: value for key, value in row.items() if value is not None})
            if max_rows is not None and len(rows) > max_rows:
                raise ValueError("multi-valued rule exceeds the decision bound")
    return rows


def _column_values(facts: Dict[str, List[str]], predicates: Sequence[str]) -> List[Optional[str]]:
    for predicate in predicates:
        values = facts.get(predicate)
        if values:
            return sorted(values)
    return [None]
