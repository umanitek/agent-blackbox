"""What happens to findings once detection fires: filter, record, share.

:func:`_flag_worthy` keeps the findings worth surfacing under the current
config; :func:`_report_and_audit` records them locally and fans each one out
(Observer-style) to Hermes Desktop's live alert, the private audit record and —
when the community share policy allows — the community graph. Called by the hooks and the background
discovery tasks alike.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import logging
import threading
from typing import Any, Iterator, Optional
from .. import audit, desktop, detection, shields
from .. import community
from ..kernel import identity
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient
from . import report_queue

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

    Only the local record and the Desktop alert happen here. Everything that talks
    to the node — this node's identity, the private audit record, the share — is
    handed to :data:`report_queue.REPORTS` and runs after the hook has answered: a
    slow or down node must never stall the agent's tool call (KI-033).

    Sandbox mode (2026-10-21): the local finding is still recorded as real, but
    the share fan-out runs inside :func:`audit.sandbox_run` — its cooldowns and
    share ledger live in the sandbox folder, so a test never silences the real
    report of the same threat — and adds no verified sighting or private KA.
    """
    finding_dicts = [f.to_dict() for f in findings]
    _attach_sightings(finding_dicts, detail)   # before recording, so the local record carries the profile too
    audit.record(event=event, findings=finding_dicts or None, detail=detail)
    if not findings:
        return
    desktop.announce_findings(event, finding_dicts, detail)   # fail-open; title/severity/outcome only
    # copy_context: a follow-up queued inside audit.sandbox_run() ledgers into the sandbox too
    report_queue.REPORTS.submit(functools.partial(contextvars.copy_context().run, _follow_up, cfg, event, finding_dicts))


def _follow_up(cfg: BlackboxConfig, event: str, finding_dicts: list[dict[str, Any]]) -> None:
    """The node-facing part of reporting, in the sandbox lane when sandbox mode is on."""
    if cfg.community_sandbox:
        with audit.sandbox_run():
            _share_findings(cfg, event, finding_dicts)
    else:
        _share_findings(cfg, event, finding_dicts)


def _share_findings(cfg: BlackboxConfig, event: str, finding_dicts: list[dict[str, Any]]) -> None:
    """Per finding: cooldown, private audit KA, share-policy decision, background share."""
    client: Optional[DkgClient] = None
    try:
        client = DkgClient.for_config(cfg)
    except Exception:   # health: allow BLE001 -- the hook boundary is fail-open: a node client that cannot be built must never break the agent's tool call (KI-033)
        client = None
    policy = community.CommunitySharePolicy(cfg)
    reporter = identity.reporter_address(client) if client is not None else None
    real = not cfg.community_sandbox
    for finding in finding_dicts:
        # Custom rules, LLM opinions, and secret findings stay local — no private
        # KA, no sighting. Secret values must never risk reaching the shared graph.
        if finding.get("source") in community.NEVER_SHARED_SOURCES:
            continue
        identifier = str(finding.get("identifier") or "")
        # R2b: a VERIFIED-tier match counts in the weekly sighting tally — repeats
        # too, which the report cooldown below refuses. Community-only matches never do.
        if real and finding.get("source") == "public":
            community.record_verified_sighting(identifier)
        # Per-threat cooldown: a re-fire within the window adds no signal.
        # Stamped BEFORE the share attempt, so a failed share waits out the
        # window too (KI-020, accepted v1 tradeoff — the ledger records the
        # failure so it is never invisible).
        if audit.recently_reported(identifier):
            continue
        if client is not None:
            audit.mark_reported(identifier)
            local_graph = audit.local_audit_graph(client) if real else ""   # this node's own graph
            if local_graph:
                audit.write_private_audit_ka(client, local_graph, event, finding)
        allowed, why = policy.decide(finding, reporter)
        if not allowed:
            logger.debug("blackbox: community share skipped (%s): %s", why, identifier)
            continue
        if client is None or not audit.allow_report(cfg.daily_report_limit):
            continue
        worker = community.spawn_community_share(client, cfg, finding, reporter)
        collected = _COLLECTED_SHARES.get()
        if collected is not None:
            collected.append(worker)


#: The share threads started under :func:`collecting_shares` (None outside one).
_COLLECTED_SHARES: contextvars.ContextVar[Optional[list[threading.Thread]]] = contextvars.ContextVar(
    "blackbox_collected_shares", default=None)


@contextlib.contextmanager
def collecting_shares() -> Iterator[list[threading.Thread]]:
    """Collect every community share started inside the block — the report follow-up runs with
    the caller's context copied, so its shares land here too — so a caller waits for its OWN shares
    only (the Playground), never another agent's share running at the same time."""
    started: list[threading.Thread] = []
    token = _COLLECTED_SHARES.set(started)
    try:
        yield started
    finally:
        _COLLECTED_SHARES.reset(token)


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

def hook_failed(hook: str, exc: BaseException, *, tool_name: str = "", consequence: str) -> None:
    """A hook raised and the host carried on (fail-open): say so at WARNING and
    write an ``audit`` row (``event="guard_error"``) so the dashboard's activity
    trail and the operator can see that an action went through unchecked.

    Fail-open is never fail-silent: before this, a tool argument that tripped any
    parser bug disabled the guard for that call with one DEBUG line.
    *consequence* is the plain sentence for the log ("the action passed unchecked")."""
    logger.warning("blackbox: %s raised %s: %s — %s", hook, type(exc).__name__, exc, consequence)
    audit.record(event="guard_error", detail={"hook": hook, "tool_name": tool_name,
                                              "error": type(exc).__name__, "message": str(exc)[:300],
                                              "consequence": consequence})

