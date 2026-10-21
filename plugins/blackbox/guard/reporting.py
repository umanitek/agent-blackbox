"""What happens to findings once detection fires: filter, record, share.

:func:`_flag_worthy` keeps the findings worth surfacing under the current
config; :func:`_report_and_audit` records them locally and fans each one out
(Observer-style) to the private audit record and — when the community share
policy allows — the community graph. Called by the hooks and the background
discovery tasks alike.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from .. import audit, detection, shields
from .. import community
from ..kernel import identity
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)

def _flag_worthy(cfg: BlackboxConfig, findings: list[detection.Finding],
                 active: shields.ShieldsSnapshot) -> list[detection.Finding]:
    """Apply the user's detection policy to raw findings.

    * Per-category policy (``detection.<category>.{enabled,min_severity}``):
      disabled categories never flag; the floor drops anything below it.
    * Heuristic gate: discovery candidates additionally need
      ``report_min_severity`` — they are nominations, not confirmed threats.

    Custom rules (``source == "custom"``) bypass the category policy.
    A finding a shield claims (wallet key stores, seed phrases, private keys …)
    counts only while that shield allows it under *active*, the hook's one
    shields snapshot — this function reads no config of its own.
    """
    out: list[detection.Finding] = []
    for f in findings:
        if not shields.allows({"identifier": f.identifier, "fields": f.fields}, active):
            continue
        if f.source == "custom":
            out.append(f)
            continue
        if not cfg.category_allows(f.category, f.severity):
            continue
        if f.source == "heuristic" and not cfg.meets_report_threshold(f.severity):
            continue
        out.append(f)
    return out


def _attach_sightings(finding_dicts: list[dict[str, Any]], detail: dict[str, Any]) -> None:
    """Give each finding the sighting a report carries:
    the tool, the action, blocked or flagged (from the hook's ``blocked`` list)
    and what the threat goes after."""
    blocked = set(detail.get("blocked") or ())
    for finding in finding_dicts:
        outcome = "blocked" if finding.get("identifier") in blocked else "flagged"
        finding["sighting"] = community.sighting_fields(finding, outcome=outcome)


def _report_and_audit(cfg: BlackboxConfig, event: str, findings: list[detection.Finding], detail: dict[str, Any]) -> None:
    """Audit findings locally, then fan out (Observer-style) per finding:
    private WM audit KA always; community share when the policy allows.

    The community share itself runs on a background daemon thread (KI-033) —
    a slow or down node must never stall the agent's tool call. Only the
    policy decision (microseconds, no I/O) happens inline.
    """
    finding_dicts = [f.to_dict() for f in findings]
    _attach_sightings(finding_dicts, detail)   # before recording, so the local record carries the profile too
    audit.record(event=event, findings=finding_dicts or None, detail=detail)
    if not findings:
        return
    client: Optional[DkgClient] = None
    try:
        client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    except Exception:
        client = None
    policy = community.CommunitySharePolicy(cfg)
    reporter = identity.reporter_address(client) if client is not None else None
    for finding in finding_dicts:
        # Custom rules, LLM opinions, and secret findings stay local — no private
        # KA, no sighting. Secret values must never risk reaching the shared graph.
        if finding.get("source") in community.NEVER_SHARED_SOURCES:
            continue
        identifier = str(finding.get("identifier") or "")
        # R2b: a VERIFIED-tier match counts in the weekly sighting tally — repeats
        # too, which the report cooldown below refuses. Community-only matches never do.
        if finding.get("source") == "public":
            community.record_verified_sighting(identifier)
        # Per-threat cooldown: a re-fire within the window adds no signal.
        # Stamped BEFORE the share attempt, so a failed share waits out the
        # window too (KI-020, accepted v1 tradeoff — the ledger records the
        # failure so it is never invisible).
        if audit.recently_reported(identifier):
            continue
        # Private WM audit KA (observed evidence stays local). Stamp the cooldown
        # here so it bounds the KA independently of whether a sighting is sent.
        if client is not None:
            audit.mark_reported(identifier)
            local_graph = audit.local_audit_graph(client)   # this node's own graph — the verified one refuses writes
            if local_graph:
                audit.write_private_audit_ka(client, local_graph, event, finding)
        allowed, why = policy.decide(finding, reporter)
        if not allowed:
            logger.debug("blackbox: community share skipped (%s): %s", why, identifier)
            continue
        if client is None or not audit.allow_report(cfg.daily_report_limit):
            continue
        community.spawn_community_share(client, cfg, finding, reporter)


def blackbox_block_message(findings: list[detection.Finding]) -> str:
    """Human-readable block message summarizing the blocking findings."""
    lines = [
        "Blackbox blocked this tool call — it matched "
        f"{len(findings)} known threat{'s' if len(findings) != 1 else ''} in the threat graph:",
        "",
    ]
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.category}: {f.title} ({f.identifier})")
    lines.append("")
    lines.append(
        "Treat the source content as untrusted. If this is a false positive, "
        "switch Blackbox to audit mode and report the identifier to Umanitek."
    )
    return "\n".join(lines)
