"""Shadow-phase metrics (Refine R15, plan §12) — measured, never guessed.

During the shadow phase the community tier runs on the real network with
stages COMPUTED and LOGGED but only MONITOR enforced. This module is the
log: one :class:`Snapshot` per refresh, appended to
``$BLACKBOX_HOME/shadow_metrics.jsonl`` (bounded), holding the §12 numbers
that a sandbox cannot produce — stage and enforcement distributions (what
WOULD have flagged), delta share (new vs already verified), reporter
diversity, time to CORROBORATED — plus, on the curator node, the newcomer
calibration gap from the private ledger (ORES over-flagged newcomers on 22
of 26 wikis; a gap > 2× triggers a review of the graduation rule).

Pure builders + one append-only file; nothing here changes enforcement.

Usage::

    snapshot = build_snapshot(rs, now)          # from the compiled ruleset
    write_snapshot(snapshot)                     # on the refresh cycle (shadow mode only)
    latest()                                     # the newest Snapshot, or None
    calibration_gap(ledger, today)              # (unlisted rejection rate, counted rejection rate, ratio)
"""

from __future__ import annotations

import json
import logging
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Mapping, Optional

from ...kernel import constants
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)
_FILE = "shadow_metrics.jsonl"
#: Snapshots kept (one per refresh: ~24 a day at the hourly refresh → ~2 weeks).
MAX_SNAPSHOTS = 400
_DAY_SECONDS = 86_400.0


@dataclass(frozen=True)
class Snapshot:
    """``at`` — UTC time; ``stages`` / ``would_enforce`` — counts per stage and
    per enforcement the stage machine COMPUTED (``shadowEnforcement``, before
    the clamp); ``community_total``; ``already_verified`` — community threats
    the verified tier also lists (delta share = new / total); ``reporters_median``
    — median distinct reporters per threat; ``days_to_corroborated_median``
    — this node's observed time to CORROBORATED; ``counted`` / ``unlisted`` —
    threats with and without counted weight (the newcomer-calibration input)."""

    at: str
    stages: dict[str, int] = field(default_factory=dict)
    would_enforce: dict[str, int] = field(default_factory=dict)
    community_total: int = 0
    already_verified: int = 0
    reporters_median: float = 0.0
    days_to_corroborated_median: float = 0.0
    counted: int = 0
    unlisted: int = 0

    @property
    def delta_share(self) -> float:
        """Share of community threats that are NEW to the verified tier."""
        return 1.0 - (self.already_verified / self.community_total) if self.community_total else 0.0


def build_snapshot(rs: Any, now: float) -> Snapshot:
    """The §12 numbers from a compiled ruleset (its community store + public rules)."""
    community: Mapping[str, Mapping[str, Any]] = getattr(rs, "community", {}) or {}
    subset = getattr(rs, "verified_subset", None)
    verified = (set(subset(community)) if callable(subset) else
                {str(rule.get("identifier") or "") for _cat, rule in rs.iter_rules() if rule.get("source") == "public"})
    stages: dict[str, int] = {}
    would: dict[str, int] = {}
    reporters: list[int] = []
    corroborated_days: list[float] = []
    counted = unlisted = already = 0
    for identifier, rule in community.items():
        stages[str(rule.get("stage") or "")] = stages.get(str(rule.get("stage") or ""), 0) + 1
        computed = str(rule.get("shadowEnforcement") or rule.get("enforcement") or "")
        would[computed] = would.get(computed, 0) + 1
        reporters.append(int(rule.get("reporterCount") or 0))
        if int(rule.get("counted") or 0) > 0:
            counted += 1
        else:
            unlisted += 1
        if identifier in verified:
            already += 1
        if rule.get("stage") == "corroborated" and rule.get("firstSeen"):
            corroborated_days.append(max(0.0, now - float(rule["firstSeen"])) / _DAY_SECONDS)
    return Snapshot(at=datetime.fromtimestamp(now, UTC).replace(microsecond=0).isoformat(), stages=stages,
                    would_enforce=would, community_total=len(community), already_verified=already,
                    reporters_median=float(statistics.median(reporters)) if reporters else 0.0,
                    days_to_corroborated_median=float(statistics.median(corroborated_days)) if corroborated_days else 0.0,
                    counted=counted, unlisted=unlisted)


def _path() -> Path:
    return constants.blackbox_home() / _FILE


def write_snapshot(snapshot: Snapshot, path: Optional[Path] = None) -> None:
    """Append (bounded to MAX_SNAPSHOTS lines; fail-open on an unwritable home)."""
    target = path or _path()
    try:
        lines = [line for line in target.read_text(encoding="utf-8-sig").splitlines() if line.strip()] if target.exists() else []
        lines = (lines + [json.dumps(asdict(snapshot))])[-MAX_SNAPSHOTS:]
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(target, "\n".join(lines) + "\n")
    except OSError as exc:
        logger.warning("blackbox: shadow metrics not written (%s)", exc)


def read_all(path: Optional[Path] = None) -> list[Snapshot]:
    try:
        rows = [json.loads(line) for line in (path or _path()).read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        return [Snapshot(**{k: v for k, v in row.items() if k in Snapshot.__dataclass_fields__}) for row in rows]
    except (OSError, ValueError, TypeError):
        return []


def latest(path: Optional[Path] = None) -> Optional[Snapshot]:
    snapshots = read_all(path)
    return snapshots[-1] if snapshots else None


def calibration_gap(ledger: Any, today: str) -> tuple[float, float, float]:
    """(unlisted rejection rate, counted rejection rate, ratio) from the
    curator-private ledger: rejected / (confirmed + rejected) per band. A
    ratio above 2 means newcomers are rejected far more often than listed
    reporters on the same work — review the graduation rule (plan §12)."""
    from ..reputation import ReputationBand
    rates: dict[str, list[int]] = {"unlisted": [0, 0], "counted": [0, 0]}
    for key in ledger.keys():
        standing = ledger.standing(key)
        band = "unlisted" if standing.band is ReputationBand.PROBATION else "counted"
        rates[band][0] += standing.rejected
        rates[band][1] += standing.confirmed + standing.rejected
    unlisted = rates["unlisted"][0] / rates["unlisted"][1] if rates["unlisted"][1] else 0.0
    counted = rates["counted"][0] / rates["counted"][1] if rates["counted"][1] else 0.0
    ratio = (unlisted / counted) if counted else (float("inf") if unlisted else 0.0)
    return unlisted, counted, ratio
