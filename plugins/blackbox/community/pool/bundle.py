"""The export bundle — the confirmed pool as one file a stranger can check (Community Curation C8, plan §08).

The owner of the verified graph pulls from the confirmed pool without trusting
us. A bundle therefore holds only SIGNED statements that are already public in
the community graph: per threat the curators' confirmation, each reporter's own
report and the curators' listings of those reporters, plus the root-signed key
manifests that make the curator keys trustworthy. What an entry STATES in the
clear (the threat, the evidence reference) is re-derived from its signed
statements by the verifier and must match exactly.

:func:`verify_bundle` needs no node and no network: the file, the community
root key, and the network and graph the receiver expects. A bundle for another
network or graph, or without a manifest that root signed, fails AS A WHOLE; a
damaged entry fails alone, named, with the reason, and the others still pass.

What a bundle cannot prove: that a confirmation was not replaced AFTER the
export (a later rejection is a statement the file does not hold). It proves
what was confirmed, by whom, on what evidence; the live graph or a fresh
export answers "does it still stand".

Format (JSON, :data:`VERSION` 1)::

    {"format": "blackbox.confirmed-pool", "version": 1, "environment": "<network id>", "graph": "<graph id>",
     "manifests": ["<signed key manifest>", ...],
     "entries": [{"identifier": "...", "threat": {"category": "...", "severity": "...", "fields": {...}},
                  "evidence": "advisory:...", "confirmation": "<signed statement>",
                  "reports": ["<signed report>", ...], "listings": ["<signed listing>", ...]}]}

Pattern: Builder (:class:`Bundle` -> text) + a pure verifier returning a tagged result (:class:`BundleReport`).

Usage::

    text = Bundle(environment, graph, manifests, entries).to_text()
    report = verify_bundle(text, {root_key_hex}, environment=network_id, graph=community_graph)
    report.error                      # "" unless the bundle failed as a whole
    [(r.identifier, r.reason) for r in report.entries if not r.ok]
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import AbstractSet, Any, Mapping, Optional

from ...kernel import signing
from ...kernel.signing import KeyManifest
from ...kernel.signing import CuratorStatement
from ...kernel.signing import RootPins
from ..statements import curator_statements, curator_view
from ..trust import manifests as manifest_policy
from ..verification import ReportVerifier, VerifiedReport
from .confirmed import PoolEntry, confirmed_pool

FORMAT = "blackbox.confirmed-pool"
VERSION = 1
#: Limits on a bundle a verifier will read (a bundle is input from outside).
MAX_BUNDLE_CHARS = 64 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_STATEMENTS_PER_ENTRY = 500
MAX_MANIFESTS = 64
_ENTRY_KEYS = frozenset({"identifier", "threat", "evidence", "confirmation", "reports", "listings"})


def entry_document(entry: PoolEntry) -> dict[str, Any]:
    """One entry as it is written in a bundle: the signed statements, and in
    the clear what they say about the threat."""
    return {"identifier": entry.identifier,
            "threat": {"category": entry.category, "severity": entry.severity, "fields": dict(entry.fields)},
            "evidence": entry.evidence, "confirmation": entry.confirmation,
            "reports": list(entry.reports), "listings": list(entry.listings)}


@dataclass(frozen=True)
class Bundle:
    """A confirmed pool ready to hand on: the network (``environment``) and
    community ``graph`` it belongs to, the signed key ``manifests`` (the
    chain), and the ``entries``. ``to_text()`` is the file."""

    environment: str
    graph: str
    manifests: tuple[str, ...]
    entries: tuple[PoolEntry, ...]
    version: int = VERSION

    def to_text(self) -> str:
        document = {"format": FORMAT, "version": self.version, "environment": self.environment, "graph": self.graph,
                    "manifests": sorted(self.manifests),
                    "entries": [entry_document(entry) for entry in sorted(self.entries, key=lambda e: e.identifier)]}
        return json.dumps(document, sort_keys=True, indent=1, ensure_ascii=True) + "\n"


@dataclass(frozen=True)
class EntryResult:
    """One entry's check: ``ok``, else ``reason`` says exactly what failed.
    ``entry`` — the entry as derived from its signed statements (when ok)."""

    identifier: str
    ok: bool
    reason: str = ""
    entry: Optional[PoolEntry] = None


@dataclass(frozen=True)
class BundleReport:
    """What :func:`verify_bundle` found. ``error`` — non-empty when the bundle
    failed AS A WHOLE (nothing in it may be used). ``entries`` — one result per
    entry. ``manifest`` — the key manifest everything was checked against."""

    error: str = ""
    entries: tuple[EntryResult, ...] = ()
    manifest: Optional[KeyManifest] = None

    @property
    def ok(self) -> bool:
        return not self.error and all(result.ok for result in self.entries)

    @property
    def passed(self) -> tuple[PoolEntry, ...]:
        return tuple(result.entry for result in self.entries if result.ok and result.entry is not None)


def verify_bundle(text: str, roots: AbstractSet[str], *, environment: str, graph: str,
                  today: Optional[str] = None) -> BundleReport:
    """Check a whole bundle offline. *roots* — the community root key(s) the
    receiver trusts (hex); *environment* / *graph* — the network id and the
    community graph the receiver expects; *today* — the UTC day (default: now)."""
    document, error = _document(text, environment, graph)
    if document is None:
        return BundleReport(error=error)
    if not roots:
        return BundleReport(error="no root key was given: nothing in a bundle can be trusted without one")
    day = today or curator_view.today_utc()
    rows = [{"signedStatement": manifest} for manifest in document["manifests"]]
    trusted = manifest_policy.trusted_manifests(rows, environment, graph, RootPins.unbound(roots))
    if manifest_policy.manifests_conflict(trusted):
        return BundleReport(error="two root-signed key manifests of the same version disagree")
    manifest = manifest_policy.effective_manifest(trusted, day)
    if manifest is None:
        return BundleReport(error="no key manifest in the bundle is signed by the given root for this network and graph")
    results: list[EntryResult] = []
    seen = set()
    for raw in document["entries"]:
        result = _verify_entry(raw, manifest, environment, graph, day)
        if result.ok and result.identifier in seen:
            result = EntryResult(result.identifier, False, "a second entry for the same threat")
        seen.add(result.identifier)
        results.append(result)
    return BundleReport(entries=tuple(results), manifest=manifest)


def _document(text: str, environment: str, graph: str) -> tuple[Optional[dict[str, Any]], str]:
    """(the parsed bundle, "") or (None, why it fails as a whole)."""
    if not isinstance(text, str) or len(text) > MAX_BUNDLE_CHARS:
        return None, "the bundle is too large to read"
    try:
        document = json.loads(text)
    except ValueError:
        return None, "the bundle is not valid JSON"
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        return None, "this is not a confirmed-pool bundle"
    if type(document.get("version")) is not int or document["version"] != VERSION:
        return None, f"bundle version {document.get('version')!r} is not supported (this verifier reads version {VERSION})"
    if (document.get("environment"), document.get("graph")) != (environment, graph):
        return None, "the bundle is for another network or another graph"
    manifests, entries = document.get("manifests"), document.get("entries")
    if not _texts(manifests, MAX_MANIFESTS) or not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        return None, "the bundle's manifests or entries are malformed"
    return document, ""


def _texts(value: Any, limit: int) -> bool:
    return isinstance(value, list) and len(value) <= limit and all(isinstance(item, str) for item in value)


def _verify_entry(raw: Any, manifest: KeyManifest, environment: str, graph: str, today: str) -> EntryResult:
    """One entry, checked from its own signed statements only."""
    if not _entry_shaped(raw):
        shown = raw.get("identifier") if isinstance(raw, dict) else ""
        return EntryResult(shown if isinstance(shown, str) else "", False, "the entry is malformed")
    identifier = raw["identifier"]
    rows, reason = _statement_rows(raw, manifest, graph)
    reports, reason = (_reports(raw, identifier, environment, graph, today) if not reason else ([], reason))
    if reason:
        return EntryResult(identifier, False, reason)
    derived = [entry for entry in confirmed_pool(manifest, rows, reports, graph=graph, today=today)
               if entry.identifier == identifier]
    if not derived:
        return EntryResult(identifier, False, "the confirmation has expired (the threat's community lifetime has passed)")
    stated = entry_document(derived[0])
    differing = sorted(key for key in _ENTRY_KEYS if stated[key] != raw[key])
    if differing:
        return EntryResult(identifier, False, "what the entry states does not match its signed statements: " + ", ".join(differing))
    return EntryResult(identifier, True, entry=derived[0])


def _entry_shaped(raw: Any) -> bool:
    return (isinstance(raw, dict) and set(raw) == _ENTRY_KEYS and isinstance(raw["identifier"], str)
            and isinstance(raw["confirmation"], str) and isinstance(raw["threat"], dict)
            and _texts(raw["reports"], MAX_STATEMENTS_PER_ENTRY) and _texts(raw["listings"], MAX_STATEMENTS_PER_ENTRY))


def _statement_rows(raw: Mapping[str, Any], manifest: KeyManifest, graph: str) -> tuple[list[dict[str, str]], str]:
    """(the entry's curator statements as verified rows, "") or ([], why one fails)."""
    rows: list[dict[str, str]] = []
    for position, text in enumerate([raw["confirmation"], *raw["listings"]]):
        name = "the confirmation" if position == 0 else f"listing {position}"
        row = curator_statements.row_for_signed(text)
        record = curator_statements.parse_statement(row, manifest, graph=graph) if row is not None else None
        if record is None:
            return [], f"{name} does not verify (not signed by enough keys of the trusted manifest for this graph, or altered)"
        wanted = CuratorStatement.CONFIRMATION if position == 0 else CuratorStatement.COUNTED_AUTHORS
        if record.kind is not wanted:
            return [], f"{name} is another kind of statement"
        if position == 0 and record.identifier != raw["identifier"]:
            return [], "the confirmation is about another threat"
        if position == 0 and not record.field("evidence"):
            return [], "the confirmation carries no evidence reference"
        rows.append(row)
    return rows, ""


def _reports(raw: Mapping[str, Any], identifier: str, environment: str, graph: str,
             today: str) -> tuple[list[VerifiedReport], str]:
    """(the entry's verified reports, "") or ([], why one fails)."""
    verifier = ReportVerifier(environment, graph, today)
    reports: list[VerifiedReport] = []
    for position, text in enumerate(raw["reports"], start=1):
        report = verifier.verify_signed(text) if signing.is_canonical(text) else None
        if report is None:
            return [], f"report {position} does not verify (its reporter's signature, its network or graph, or its fields)"
        if report.identifier != identifier:
            return [], f"report {position} is about another threat"
        reports.append(report)
    return reports, ""
