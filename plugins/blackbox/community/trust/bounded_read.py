"""Looking trust statements up in a graph anyone can write (Community Curation C3).

The shared memory is open: any node can publish rows beside a curator's,
under the same subject and the same asset name (bench 2026-10-03, KI-250), and
writing is free and fast. A read that SCANS every statement of a type and
orders it can therefore be made slow or truncated by anyone (an ordered scan
costs about 25 times an exact lookup, KI-264). So trust statements are never
scanned:

* statements are fetched by EXACT LOOKUP on identifiers the reader already
  knows — the reporters and threats it holds, plus the fixed ``curator``
  identifier — in batches, with no ordering;
* key manifests are fetched by type without ordering, and by the exact
  subjects the next manifests would have;
* whatever comes back is only a CANDIDATE: the caller verifies every row's
  signatures before it counts (``statements.curator_statements``), so junk
  rows that carry a genuine identifier cost a signature check and nothing else;
* a batch that fails, times out or reaches its row limit makes the lookup
  ``complete = False``: absence then proves nothing, and the reader keeps what
  its own trust store already holds (:mod:`.trust_store`).

Pattern: pure query builders + one function per lookup returning a frozen
:class:`Lookup` (a tagged result).

Usage::

    found = lookup_statements(client, graph, {"curator", "author:<key>", "ioc:ip:203.0.113.7"})
    rows = fold([*stored_rows, *found.rows])      # then verify each row
    if not found.complete: ...absence proves nothing...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from ...kernel import constants, signing, sparql_text
from ...kernel.dkg_client import extract_binding

#: The identifier every curator notice (pause, backlog, away, heartbeat) carries.
CURATOR_IDENTIFIER = "curator"
#: Identifiers per lookup query, and the most rows one query may return. A
#: genuine identifier has a handful of statements; a batch that reaches the
#: limit has been flooded and is reported as incomplete.
LOOKUP_BATCH = 100
LOOKUP_ROW_LIMIT = 2000
#: The most identifiers one read looks up (60 queries); a reader holds at most
#: 5,000 community rules, plus their authors.
MAX_IDENTIFIERS = 6000
#: Rows one manifest lookup may return, and how many versions ahead of the
#: known manifest (and into the next root epoch) are probed by exact subject.
MANIFEST_ROW_LIMIT = 500
MANIFEST_PROBE_AHEAD = 4

_PREFIX = f"PREFIX g: <{constants.BLACKBOX_ONTOLOGY}>"


@dataclass(frozen=True)
class Lookup:
    """What a lookup fetched. ``rows`` — candidate rows, duplicates folded
    (unverified: the caller checks signatures). ``complete`` — False when any
    batch failed, timed out or reached its row limit, so a statement that is
    missing from ``rows`` may still exist. ``limited`` / ``failed`` — how many
    batches reached the limit / could not be read."""

    rows: tuple[dict[str, str], ...] = ()
    complete: bool = True
    limited: int = 0
    failed: int = 0


def _plain(row: Mapping[str, Any]) -> dict[str, str]:
    """A node row as plain strings: subject, shown identifier, and the signed
    statement written the canonical way — so a copy of a statement that
    differs only in how it is written (spacing, key order, an ignored key,
    upper-case hex) IS that statement from here on (KI-266)."""
    text = extract_binding(row.get("signedStatement"))
    envelope = signing.from_text(text)
    return {"r": extract_binding(row.get("r")), "identifier": extract_binding(row.get("identifier")),
            "signedStatement": signing.canonical_text(envelope) if envelope is not None else text}


def fold(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """*rows* as plain rows with exact duplicates removed. A keep-alive copy of
    a statement is the same subject and the same signed text under a new asset
    name, and a rewritten copy has the same canonical text, so both fold to
    one (first occurrence wins the position)."""
    seen = set()
    out: list[dict[str, str]] = []
    for row in rows:
        plain = _plain(row)
        key = (plain["r"], plain["signedStatement"])
        if plain["signedStatement"] and key not in seen:
            seen.add(key)
            out.append(plain)
    return out


def statements_sparql(identifiers: Sequence[str]) -> str:
    """One batch: every curator statement whose identifier is one of *identifiers*."""
    values = " ".join(sparql_text.sparql_string_literal(identifier) for identifier in identifiers)
    return f"""{_PREFIX}
SELECT ?r ?identifier ?signedStatement WHERE {{
  VALUES ?identifier {{ {values} }}
  ?r g:identifier ?identifier ;
     a g:CuratorStatement ;
     g:signedStatement ?signedStatement .
}} LIMIT {LOOKUP_ROW_LIMIT}
"""


def lookup_statements(client: Any, graph: str, identifiers: Iterable[str], *,
                      view: str = constants.VIEW_SHARED_WORKING_MEMORY) -> Lookup:
    """Curator statements about *identifiers* in *graph* — exact lookups, no
    ordering. At most ``MAX_IDENTIFIERS`` identifiers are asked for (the
    caller passes the most important first)."""
    wanted = list(dict.fromkeys(i for i in identifiers if i))[:MAX_IDENTIFIERS]
    rows: list[Mapping[str, Any]] = []
    limited = failed = 0
    for start in range(0, len(wanted), LOOKUP_BATCH):
        page = sparql_text.query_rows(client, statements_sparql(wanted[start:start + LOOKUP_BATCH]), graph, view)
        if page is None:
            failed += 1
            continue
        if len(page) >= LOOKUP_ROW_LIMIT:
            limited += 1
        rows.extend(page)
    return Lookup(rows=tuple(fold(rows)), complete=not (limited or failed), limited=limited, failed=failed)


def manifest_subject(root_epoch: int, version: int) -> str:
    """The subject a key manifest of that order is published under."""
    return f"urn:guardian:key-manifest:{root_epoch}:{version}"


def _manifests_by_type_sparql() -> str:
    return f"""{_PREFIX}
SELECT ?r ?signedStatement WHERE {{
  ?r a g:KeyManifest ;
     g:signedStatement ?signedStatement .
}} LIMIT {MANIFEST_ROW_LIMIT}
"""


def _manifests_by_subject_sparql(subjects: Sequence[str]) -> str:
    values = " ".join(f"<{subject}>" for subject in subjects)
    return f"""{_PREFIX}
SELECT ?r ?signedStatement WHERE {{
  VALUES ?r {{ {values} }}
  ?r g:signedStatement ?signedStatement .
}} LIMIT {MANIFEST_ROW_LIMIT}
"""


def next_manifest_subjects(known: Iterable[tuple[int, int]]) -> list[str]:
    """The exact subjects worth probing: the next versions after the newest
    known ``(root_epoch, version)`` and the first versions of the next epoch;
    with nothing known, the first versions of epochs 0 and 1."""
    newest = max(known, default=None)
    if newest is None:
        orders = [(epoch, version) for epoch in (0, 1) for version in range(1, MANIFEST_PROBE_AHEAD + 1)]
    else:
        epoch, version = newest
        orders = [(epoch, version + step) for step in range(1, MANIFEST_PROBE_AHEAD + 1)]
        orders += [(epoch + 1, step) for step in range(1, MANIFEST_PROBE_AHEAD + 1)]
    return [manifest_subject(epoch, version) for epoch, version in orders]


def lookup_manifests(client: Any, graph: str, known: Iterable[tuple[int, int]] = (), *,
                     view: str = constants.VIEW_SHARED_WORKING_MEMORY) -> Lookup:
    """Key-manifest rows in *graph*: an unordered lookup by type, plus exact
    probes for the subjects the next manifests would have (so a flood of
    manifest-typed junk cannot hide a rotation behind the type lookup's limit)."""
    rows: list[Mapping[str, Any]] = []
    limited = failed = 0
    for sparql in (_manifests_by_type_sparql(), _manifests_by_subject_sparql(next_manifest_subjects(known))):
        page = sparql_text.query_rows(client, sparql, graph, view)
        if page is None:
            failed += 1
            continue
        if len(page) >= MANIFEST_ROW_LIMIT:
            limited += 1
        rows.extend(page)
    return Lookup(rows=tuple(fold(rows)), complete=not (limited or failed), limited=limited, failed=failed)
