"""Lifecycle TRACK for a reporter: what happened to each report, and its standing (Refine R10).

:func:`outcome_line` renders one share-ledger row as "what happened to my
report": the share outcome, then the threat's current local stage and reason
from the compiled community store — the same stage every node computes (R3).
:func:`report_standing` / :func:`standing_lines` say whether this reporter is
COUNTED or on PROBATION (from the public counted-author list), how many of
its verified reports are on the graph, and a co-sighting estimate from this
week's digests (R2b). The curator-private standing pull is R13.
Called by :func:`.report_command.cmd_report` (``--status`` / ``--standing``).
"""

from __future__ import annotations

from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from ...kernel import display_safety, reporter_key
from ...kernel.dkg_client import DkgClient
from ...kernel.signing.statement_order import CuratorStatement
from .. import reader as graph_reader
from .. import reputation
from ..statements.curator_view import today_utc as curator_today

#: How a ledger outcome is shown (community.ShareOutcome values).
_OUTCOME_LABELS = {"accepted": "ok", "already-shared": "already shared", "failed": "FAILED",
                   "retrying": "retrying", "failed-after-retries": "FAILED after retries",   # R16
                   "kept-alive": "kept alive"}                                                # R5


def outcome_label(row: dict[str, Any]) -> str:
    """How one share-ledger row's outcome is shown — "ok", "already shared", "FAILED", … —
    the one mapping every view uses (`blackbox status` and `blackbox report --status`). A row
    from before outcomes were recorded falls back to its ``ok`` flag."""
    return _OUTCOME_LABELS.get(str(row.get("outcome") or ("accepted" if row.get("ok") else "failed")), "FAILED")


def outcome_line(row: dict[str, Any], compiled: dict[str, dict[str, Any]]) -> str:
    """R10 TRACK: one ledger row as "what happened to my report": the share
    outcome, then the threat's current local stage and reason from the
    compiled community store (what every node sees)."""
    outcome = outcome_label(row)
    identifier = str(row.get("identifier") or "")
    rule = compiled.get(identifier) or {}
    stage = f"{rule.get('stage')} ({rule.get('enforcement')}) — {rule.get('stageReason')}" if rule.get("stage")         else "not in the compiled community tier (not read yet, retracted, or below the compile cap)"
    return (f"{display_safety.term_safe(row.get('ts'), 24)}  [{outcome}]  {display_safety.term_safe(row.get('category'), 16)}  "
            f"{display_safety.term_safe(identifier, 90)}\n      stage: {display_safety.term_safe(stage, 160)}")


def report_standing(cfg) -> int:
    """R10: this reporter's standing — listed (counted) or on probation — and a
    co-sighting estimate, from the public counted-author list and this
    week's digests. Sightings of known threats protect peers but do not build
    reputation (plan §10). The curator-private standing pull is R13."""
    store = reporter_key.ReporterKeyStore()
    if not store.path.exists():
        print("This node has not signed a report yet; standing starts with the first report.")
        return 0
    own = store.public_key_hex()
    if not cfg.context_graph_id:
        print("No graph configured.")
        return 0
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    read = graph_reader.read_verified_reports(client, cfg)
    if not read.available:
        print(f"Community reports unavailable right now: {display_safety.term_safe(read.reason, 160)}")
        return 1
    for line in standing_lines(own, read):
        print(line)
    return 0


def graduation_progress(own_author: str, read: Any, today: str) -> tuple[int, int]:
    """(confirmed reports, days since the first report) of *own_author* on the
    PUBLIC record: how many of its reported threats a curator confirmation
    stands for, and how long it has been reporting (its earliest signed day)."""
    mine = [report for report in read.reports if report.author == own_author]
    confirmed = {report.identifier for report in mine if read.curator.verdict(report.identifier) is CuratorStatement.CONFIRMATION}
    first = min((report.day for report in mine if report.day), default="")
    try:
        days = (date.fromisoformat(today) - date.fromisoformat(first)).days if first else 0
    except ValueError:
        days = 0
    return len(confirmed), max(0, days)


def standing_lines(own_author: str, read: Any, today: Optional[str] = None) -> list[str]:
    entry = read.curator.counted.get(own_author)
    mine = {r.identifier for r in read.reports if r.author == own_author}
    co_sighted = sum(read.heat[i].agents for i in mine if i in read.heat)
    community_view = read.curator.community
    lines = []
    if entry is not None:
        lines.append(f"Standing: COUNTED ({entry.author_class}{', ' + entry.org if entry.org else ''}) until {entry.expires} — "
                     "your reports move stages.")
    elif read.curator.manifest is None and (community_view is None or community_view.manifest is None):
        lines.append("Standing: no curator key manifest is trusted on this network yet — every author counts 0 for now.")
    else:
        lines.append("Standing: PROBATION (not on the counted-author list) — your reports are stored and shown as "
                     "\"new reporter\" and weigh 0 until a curator lists you.")
        confirmed, days = graduation_progress(own_author, read, today or curator_today())
        need, wait = reputation.GRADUATION_MIN_NOVEL, reputation.GRADUATION_MIN_DAYS
        lines.append(f"Toward the trusted list: confirmed {min(confirmed, need)} of {need} · day {min(days, wait)} of {wait}"
                     + (" — both are met on the public record; the curators list you once they have checked that the confirmed reports were new."
                        if confirmed >= need and days >= wait else
                        " — each confirmed report must also be new (not already on a public feed) to count."))
    lines.append(f"Progress: {len(mine)} verified report(s) of yours are on the graph; "
                 f"co-sightings this week: ~{co_sighted} agent(s) met the threats you reported.")
    lines.append("Sightings of already-verified threats protect peers but do not build reputation.")
    return lines
