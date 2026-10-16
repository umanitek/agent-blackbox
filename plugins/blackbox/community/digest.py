"""The seen-again counter — a weekly sighting digest per reporter (Refine R2b).

Repeat matches of VERIFIED threats are signal ("thousands of agents met this
site this week"), but a repeat can never be re-shared as a report: the
6-hour cooldown refuses it and the report's name is fixed (KI-170). So repeats
feed a LOCAL weekly tally instead, and once a week ONE signed digest leaves
the machine: the verified threats met during one ISO week, each as a coarse
bucket (1 / 2–9 / 10–99 / 100+). Exact counts and times are a fingerprint of
the user's activity, so none leave (decision 23). Only VERIFIED-tier matches
enter the tally (KI-158): a community-only match would tell whoever listed
the value who met it.

Named by (reporter, ISO week), every week is a NEW asset: no re-share, no
keep-alive, no same-version rejection. The digest for a week is published
once that week is over, so it is complete, and the tally remembers which
weeks it published.

Pattern: :class:`SightingTally` is a small stateful class (one lock, atomic
tmp+rename, bounded to recent weeks); :func:`bucket_for`,
:func:`iso_week`, :func:`build_digest` are pure; publishing is triggered from
the existing sync cycle (:func:`publish_due_digests`), never a new thread.

Usage::

    community.record_verified_sighting("dep:npm:evil@1.0.0")   # from the guard, per match
    community.publish_due_digests(client, cfg)                 # from the refresh cycle
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import date, datetime, timezone, UTC
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from .. import audit
from ..kernel import constants, rdf_terms, threat_ids
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient
from ..kernel import identity
from . import report_signer, sharing
from .report_signer import DIGEST_STATEMENT, ReportSigner

logger = logging.getLogger(__name__)

#: Most threats one digest names (the most-seen first). Bounds the envelope
#: (one graph literal) and what one week reveals about a reporter.
MAX_DIGEST_ENTRIES = 25
#: Completed weeks kept in the tally file (published or not).
_KEEP_WEEKS = 8
_TALLY_FILE = "sighting_tally.json"
#: How a digest's entries are carried inside the signed payload: one entry per
#: line, ``<identifier> <bucket>``.
_ENTRY_SEPARATOR = "\n"


class Bucket(Enum):
    """A coarse count: what a digest says instead of the exact number.
    ``midpoint`` is what readers add up for the network estimate."""

    ONE = "1"
    FEW = "2-9"
    MANY = "10-99"
    LOTS = "100+"

    @property
    def midpoint(self) -> int:
        return _MIDPOINTS[self]


#: The estimate a reader adds per bucket (plan §05: "sum of bucket midpoints";
#: the open bucket counts its floor — honest enough, never inflated).
_MIDPOINTS = {Bucket.ONE: 1, Bucket.FEW: 5, Bucket.MANY: 55, Bucket.LOTS: 100}


def bucket_for(count: int) -> Bucket:
    """The bucket a count falls in (1 → ONE, 2–9 → FEW, 10–99 → MANY, 100+ → LOTS)."""
    if count >= 100:
        return Bucket.LOTS
    if count >= 10:
        return Bucket.MANY
    if count >= 2:
        return Bucket.FEW
    return Bucket.ONE


def iso_week(when: date) -> str:
    """``YYYY-Www`` — the ISO week *when* falls in (``2026-W40``)."""
    year, week, _weekday = when.isocalendar()
    return f"{year}-W{week:02d}"


@dataclass(frozen=True)
class DigestEntry:
    """One verified threat met this week and how often, as a bucket."""

    identifier: str
    bucket: Bucket


def build_digest(counts: Mapping[str, int]) -> tuple[DigestEntry, ...]:
    """The entries for one week's ``{identifier: count}``: the most-seen
    :data:`MAX_DIGEST_ENTRIES` threats, bucketed; ties by identifier."""
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_DIGEST_ENTRIES]
    return tuple(DigestEntry(identifier, bucket_for(count)) for identifier, count in ranked if count > 0)


class SightingTally:
    """This node's per-week counts of verified-threat matches (``$BLACKBOX_HOME/sighting_tally.json``).

    ``{"weeks": {"2026-W40": {identifier: count}}, "published": ["2026-W39"]}``.
    One lock; atomic tmp+rename; weeks older than :data:`_KEEP_WEEKS` are
    pruned. Nothing per event is stored: only the week's counts.
    """

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._path = path or (constants.blackbox_home() / _TALLY_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    def record(self, identifier: str) -> None:
        """Count one match of *identifier* in the current ISO week."""
        if not identifier:
            return
        with self._lock:
            state = self._load()
            week = iso_week(self._clock().date())
            counts = state["weeks"].setdefault(week, {})
            counts[identifier] = int(counts.get(identifier, 0)) + 1
            self._save(state)

    def counts(self, week: str) -> dict[str, int]:
        with self._lock:
            return dict(self._load()["weeks"].get(week, {}))

    def due_weeks(self) -> list[str]:
        """Completed weeks with sightings that have not been published yet."""
        with self._lock:
            state = self._load()
            current = iso_week(self._clock().date())
            return sorted(week for week, counts in state["weeks"].items()
                          if week < current and counts and week not in state["published"])

    def mark_published(self, week: str) -> None:
        with self._lock:
            state = self._load()
            if week not in state["published"]:
                state["published"].append(week)
            self._save(state)

    def weeks(self) -> list[str]:
        """Every ISO week the tally currently holds counts for (export / inspection)."""
        with self._lock:
            return sorted(str(week) for week in (self._load().get("weeks") or {}))

    def forget(self) -> bool:
        """Erase the tally (KI-221): identity erasure must not let the next key republish the
        old key's exact weekly entry set. True when a file was removed."""
        with self._lock:
            try:
                self._path.unlink()
                return True
            except FileNotFoundError:
                return False

    def _load(self) -> dict[str, object]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
            weeks = {str(w): {str(k): int(v) for k, v in dict(c).items()} for w, c in dict(data["weeks"]).items()}
            return {"weeks": weeks, "published": [str(w) for w in data.get("published", [])]}
        except (OSError, ValueError, KeyError, TypeError):
            return {"weeks": {}, "published": []}

    def _save(self, state: dict[str, object]) -> None:
        weeks: dict[str, dict[str, int]] = state["weeks"]  # type: ignore[assignment]
        for week in sorted(weeks)[:-_KEEP_WEEKS]:
            weeks.pop(week, None)
        state["published"] = [w for w in state["published"] if w in weeks]  # type: ignore[index]
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
            tmp.write_text(json.dumps(state), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:   # fail-open: an unwritable home only loses this week's counts
            logger.warning("blackbox: could not save the sighting tally (%s)", exc)


def record_verified_sighting(identifier: str) -> None:
    """Count one VERIFIED-tier match (the guard calls this on every match,
    cooldown or not). Never raises."""
    try:
        SightingTally().record(identifier)
    except Exception as exc:  # pragma: no cover - the hook path stays fail-open
        logger.debug("blackbox: sighting tally skipped: %s", exc)


def digest_subject(reporter: str, week: str) -> str:
    """``urn:guardian:digest:{reporter}:{week}`` — one per reporter per week."""
    return f"urn:guardian:digest:{reporter.strip().lower()}:{week}"


def entries_text(entries: tuple[DigestEntry, ...]) -> str:
    """The entries as the signed payload carries them."""
    return _ENTRY_SEPARATOR.join(f"{e.identifier} {e.bucket.value}" for e in entries)


def parse_entries(text: str) -> Optional[tuple[DigestEntry, ...]]:
    """Entries from :func:`entries_text`; None for anything malformed."""
    entries = []
    for line in text.split(_ENTRY_SEPARATOR) if text else []:
        parts = line.split(" ")
        if len(parts) != 2 or not parts[0] or " " in parts[0]:
            return None
        try:
            entries.append(DigestEntry(parts[0], Bucket(parts[1])))
        except ValueError:
            return None
    return tuple(entries) if len(entries) <= MAX_DIGEST_ENTRIES else None


def build_digest_quads(*, reporter_address: str, week: str, entries: tuple[DigestEntry, ...],
                       signer: ReportSigner, framework: str = sharing.HOST_FRAMEWORK) -> list[rdf_terms.Quad]:
    """The signed digest as graph quads: type, reporter, ISO week, one
    ``g:reportsThreat`` per entry, and the envelope. The week is the only
    time it carries."""
    reporter = reporter_address.strip().lower()
    if not threat_ids.is_agent_address(reporter):
        raise ValueError("a digest needs its reporter's agent address (0x + 40 hex characters)")
    subject = digest_subject(reporter, week)
    out = [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.SIGHTING_DIGEST_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.REPORTER_PRED, rdf_terms.literal(reporter)),
        rdf_terms.make_quad(subject, constants.FRAMEWORK_PRED, rdf_terms.literal(framework)),
        rdf_terms.make_quad(subject, constants.ISO_WEEK_PRED, rdf_terms.literal(week)),
    ]
    out.extend(rdf_terms.make_quad(subject, constants.REPORTS_THREAT_PRED, rdf_terms.iri(threat_ids.threat_uri(e.identifier)))
               for e in entries)
    payload = {"subject": subject, "reporter": reporter, "framework": framework, "week": week,
               "entries": entries_text(entries)}
    out.append(rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED,
                                   rdf_terms.literal(signer.sign(DIGEST_STATEMENT, payload))))
    return out


def publish_due_digests(client: DkgClient, cfg: BlackboxConfig, tally: Optional[SightingTally] = None) -> int:
    """Publish one digest per completed, unpublished week; returns how many
    were sent. Needs sharing ON (a digest leaves the machine like a report),
    an identity and a signer. Every attempt is ledgered (category
    ``digest``). Fail-open."""
    from . import consent   # round 4: withdrawal must stop the weekly digest too
    if not consent.in_force():
        return 0
    if not cfg.community_enabled:
        return 0
    tally = tally or SightingTally()
    due = tally.due_weeks()
    if not due:
        return 0
    reporter = identity.reporter_address(client)
    signer = report_signer.resolve_report_signer(client, cfg.context_graph_id)
    if not reporter or signer is None:
        logger.debug("blackbox: sighting digest not published (no identity or signer)")
        return 0
    sent = 0
    for week in due:
        entries = build_digest(tally.counts(week))
        quads = build_digest_quads(reporter_address=reporter, week=week, entries=entries, signer=signer)
        name = f"digest-{threat_ids.stable_hash(reporter + week, 16)}"
        outcome, detail = sharing.send_report(client, cfg.context_graph_id, name, quads)
        audit.record_share_outcome(identifier=f"digest:{week}", category="digest", severity="info",
                                   subject=digest_subject(reporter, week), asset_name=name,
                                   ok=outcome is sharing.ShareOutcome.ACCEPTED, error=detail, outcome=outcome.value)
        if outcome is not sharing.ShareOutcome.FAILED:
            tally.mark_published(week)   # accepted, or already on the network: done either way
            sent += outcome is sharing.ShareOutcome.ACCEPTED
    return sent

