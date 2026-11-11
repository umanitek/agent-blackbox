"""The confirmed pool — a VIEW over signed statements (Community Curation C8; plan §05, §08).

A threat is in the confirmed pool while a current confirmation from the
COMMUNITY curators stands for it: enough curator signatures, a signed
reference to the evidence they checked, no later verdict replacing it, and
not past the threat's community lifetime (counted from the confirmation's
signed day). It is a view: nothing new is written to the graph, so every
reader version keeps working.

:func:`confirmed_pool` derives the pool from three things anyone can hold —
the trusted key manifest, curator statement rows and verified reports — and
each :class:`PoolEntry` keeps the SIGNED TEXT of everything it rests on, so it
can be handed to someone who trusts none of us and checked again from the
root key down (:mod:`.bundle`).

Pattern: a pure function returning frozen Value Objects.

Usage::

    entries = confirmed_pool(manifest, statement_rows, verified_reports, graph=community_graph)
    for entry in entries:
        entry.identifier, entry.evidence, entry.trusted_voices, entry.confirmation
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ...kernel import constants, signing, threat_ids
from ...kernel.signing import Authority
from ...kernel.signing import KeyManifest
from ...kernel.signing import CuratorStatement
from .. import report_schema, stages
from ..statements import curator_statements, curator_view
from ..statements.curator_statements import CuratorRecord
from ..statements.lifetimes import lifetime_days
from ..verification import VerifiedReport

#: (statement kind, identifier) -> {signed content id: (the verified record, the smallest text that carries it)}.
#: One statement can be published as many texts (KI-266); the pool keeps one.
_Signed = dict[tuple[CuratorStatement, str], dict[str, tuple[CuratorRecord, str]]]


@dataclass(frozen=True)
class PoolEntry:
    """One confirmed threat and everything it rests on.

    The threat — ``identifier``, ``category``, ``severity`` (the highest any
    reporter signed; "" with no report) and ``fields`` (the closed evidence
    fields EVERY reporter signed identically, sorted).
    The confirmation — ``evidence`` (the signed reference to what the curators
    checked), ``confirmed_day``, ``sequence``, ``curators`` (the manifest keys
    that signed it) and ``confirmation`` (the signed statement, as text).
    The reports — ``reports`` (each reporter's own signed report, as text,
    sorted) and ``listings`` (the curators' signed trusted-reporter statements
    about those reporters, sorted).
    The context, derived from the above — ``reporters`` (distinct signers),
    ``partner_organisations`` and ``established`` (the trusted clusters among
    them on the day the pool was derived) and ``first_reported`` (the earliest
    signed report day).
    """

    identifier: str
    category: str
    severity: str
    fields: tuple[tuple[str, str], ...]
    evidence: str
    confirmed_day: str
    sequence: int
    curators: tuple[str, ...]
    confirmation: str
    reports: tuple[str, ...] = ()
    listings: tuple[str, ...] = ()
    reporters: int = 0
    partner_organisations: int = 0
    established: int = 0
    first_reported: str = ""

    @property
    def trusted_voices(self) -> int:
        """Trusted clusters behind the threat: one per partner organisation, one per established reporter."""
        return self.partner_organisations + self.established


def confirmed_pool(manifest: Optional[KeyManifest], statement_rows: Iterable[Mapping[str, str]],
                   reports: Iterable[VerifiedReport], *, graph: str, today: Optional[str] = None) -> list[PoolEntry]:
    """The confirmed pool, sorted by identifier.

    *manifest* — the COMMUNITY authority's trusted key manifest (None: an empty
    pool). *statement_rows* — candidate curator statement rows from the
    community graph (``r``, ``identifier``, ``signedStatement``); every one is
    verified here. *reports* — already VERIFIED reports; only those carrying
    their signed text can be handed on. *graph* — the community graph the
    statements must be signed for. *today* — the UTC day (default: now)."""
    if manifest is None:
        return []
    day = today or curator_view.today_utc()
    rows = _canonical_rows(statement_rows)
    view = curator_view.build_view(manifest, (), rows, verified_graph="", community_graph=graph, today=day,
                                   community_readable=True, authority=Authority.COMMUNITY)
    signed = _signed_statements(rows, manifest, graph)
    by_threat: dict[str, list[VerifiedReport]] = {}
    for report in reports:
        if report.signed:
            by_threat.setdefault(report.identifier, []).append(report)
    return [_entry(record, signed, by_threat.get(identifier, ()), view)
            for identifier, record in sorted(view.verdicts.items()) if _standing(record, day)]


def _standing(record: CuratorRecord, today: str) -> bool:
    """A confirmation with evidence, still inside the threat's community lifetime."""
    if record.kind is not CuratorStatement.CONFIRMATION or not record.field("evidence"):
        return False
    try:
        expires = date.fromisoformat(record.day) + timedelta(days=lifetime_days(record.identifier))
    except ValueError:
        return False
    return expires.isoformat() >= today


def _signed_statements(rows: Iterable[Mapping[str, str]], manifest: KeyManifest, graph: str) -> _Signed:
    """Every statement that verifies under *manifest*, by (kind, identifier),
    each ONCE: of its verified copies the one with the fewest signatures, then
    the smallest text. *rows* hold canonical texts (:func:`_canonical_rows`)."""
    found: _Signed = {}
    for row in rows:
        record = curator_statements.parse_statement(row, manifest, graph=graph)
        if record is None:
            continue
        text = row[curator_statements.SIGNED_STATEMENT_VAR]
        envelope = signing.from_text(text)
        slot = found.setdefault((record.kind, record.identifier), {})
        content = signing.content_id(envelope)
        if content not in slot or signing.copy_rank(text) < signing.copy_rank(slot[content][1]):
            slot[content] = (record, text)
    return found


def _canonical_rows(rows: Iterable[Mapping[str, str]]) -> list[dict[str, str]]:
    """*rows* with every statement written the canonical way (a pool entry is
    handed on in a file where every byte must matter); rows that are not
    statements are left out."""
    out = []
    for row in rows:
        envelope = signing.from_text(str(row.get(curator_statements.SIGNED_STATEMENT_VAR, "")))
        if envelope is not None:
            out.append({**{key: str(value) for key, value in row.items()},
                        curator_statements.SIGNED_STATEMENT_VAR: signing.canonical_text(envelope)})
    return out


def _confirmation(record: CuratorRecord, signed: _Signed) -> tuple[CuratorRecord, str]:
    """(the record, its text) of the statement the view chose as the current
    verdict: the same sequence, day and fields, whichever keys signed the copy
    that was read first."""
    same = [(held, text) for held, text in signed[(CuratorStatement.CONFIRMATION, record.identifier)].values()
            if (held.sequence, held.day, held.fields) == (record.sequence, record.day, record.fields)]
    return min(same, key=lambda pair: pair[1])


def _entry(record: CuratorRecord, signed: _Signed, reports: Sequence[VerifiedReport],
           view: curator_view.CuratorView) -> PoolEntry:
    identifier = record.identifier
    record, confirmation = _confirmation(record, signed)
    authors = sorted({report.author for report in reports})
    listings = {text for author in authors
                for _, text in signed.get((CuratorStatement.COUNTED_AUTHORS, f"author:{author}"), {}).values()}
    clusters = stages.clusters_for(authors, view)
    return PoolEntry(
        identifier=identifier, category=threat_ids.category_for(identifier), severity=_highest_severity(reports),
        fields=_agreed_fields(reports), evidence=record.field("evidence"), confirmed_day=record.day,
        sequence=record.sequence, curators=tuple(sorted(record.signers)), confirmation=confirmation,
        reports=tuple(sorted({report.signed for report in reports})), listings=tuple(sorted(listings)),
        reporters=len(authors), partner_organisations=clusters.partner, established=clusters.established,
        first_reported=min((report.day for report in reports if report.day), default=""))


def _highest_severity(reports: Iterable[VerifiedReport]) -> str:
    return max((report.severity for report in reports), key=lambda s: constants.SEVERITY_RANK.get(s, 0), default="")


def _agreed_fields(reports: Sequence[VerifiedReport]) -> tuple[tuple[str, str], ...]:
    """The evidence fields every report signed with the same value — what the
    reporters agree on, whatever order they were read in."""
    agreed: Optional[set] = None
    for report in reports:
        envelope = signing.from_text(report.signed)
        payload = envelope.payload if envelope is not None else {}
        evidence = {(key, value) for key, value in payload.items() if key not in report_schema.REPORT_CORE_KEYS}
        agreed = evidence if agreed is None else agreed & evidence
    return tuple(sorted(agreed or ()))
