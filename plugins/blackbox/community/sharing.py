"""The share path: which findings may leave the machine, and sending them.

:class:`CommunitySharePolicy` is THE outbound gate (Strategy/Policy object;
pure ``decide()``); :func:`spawn_community_share` sends an allowed finding to
the community — the verified graph's shared memory, sub-graph
``constants.COMMUNITY_SUB_GRAPH`` — on a background thread and records the
outcome in the share ledger. The reporter identity comes from ``kernel.identity`` — the gate
refuses to share without one (KI-003).
"""

from __future__ import annotations

import contextvars
import logging
import threading
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from .. import audit, detection
from .. import community
from ..kernel import constants, threat_ids
from . import consent, keep_alive, membership, report_schema, report_signer, share_retry
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)

#: This runtime IS the Hermes host; the OpenClaw runtime has its own TS
#: pipeline and stamps its own framework when its share path ships (KI-014).
#: The framework every report from this runtime names (automatic and manual).
HOST_FRAMEWORK = "hermes"

#: Sources that must never leave the machine in any form. Secret findings
#: could carry the shape of a leak; custom rules and LLM opinions are the
#: operator's private judgment. Enforced BEFORE any graph write.
NEVER_SHARED_SOURCES = ("custom", "llm", "secret")


def is_vulnerability_finding(finding: dict[str, Any]) -> bool:
    """True for a finding that describes a VULNERABILITY (vs. malware).

    Either it says so (``kind == "vulnerability"``, any tier), or it is an OSV
    discovery candidate (an ``advisory_id`` in its fields, no kind) whose
    advisory is not a malicious-package (``MAL-``) advisory.
    """
    kind = str(finding.get("kind") or "").lower()
    if kind:
        return kind == "vulnerability"
    fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
    advisory = str(fields.get("advisory_id") or "")
    return bool(advisory) and detection.advisory_kind(advisory) == "vulnerability"


class CommunitySharePolicy:
    """Decides whether ONE finding may be shared to the community.

    Pattern: Policy object (Strategy) — the entire outbound gate chain lives
    in this single, dependency-injected, testable class instead of scattered
    conditionals. ``decide()`` is pure (no I/O); the one stateful gate (the
    daily cap) is consumed separately by the caller at spawn time so a denied
    decision never burns cap budget.

    Usage::

        policy = CommunitySharePolicy(cfg)
        ok, why = policy.decide(finding_dict, reporter_address)
        if ok and audit.allow_report(cfg.daily_report_limit):
            spawn_community_share(client, cfg, finding_dict, reporter_address)

    Gate order (first refusal wins, ``why`` names it for the debug log):
    ``community off`` → ``no consent`` (R13: the operator must have consented to the
    current reporter terms) → ``excluded source`` → ``vulnerability`` →
    ``community-only match`` → ``no identifier`` → ``no identity`` (KI-003:
    a fallback identity would merge distinct nodes into one ghost reporter —
    refuse instead) → ``not a valid report`` (Refine R1: a finding the report
    schema refuses — e.g. an injection seen in tool-call arguments, which has
    no reportable context — stays local instead of failing at send time).

    Decision 22 (Refine R0, LES-018) — what leaves AUTOMATICALLY is narrowed:

    * vulnerability findings never leave (KI-157): they reveal the reporter's
      unpatched software and add nothing OSV lacks. That covers a
      ``kind=vulnerability`` finding from any tier and an OSV candidate whose
      advisory is not a malicious-package advisory (``MAL-``);
    * a match against a COMMUNITY-only rule never auto-shares (KI-158):
      whoever listed the value would learn who met it. It still flags here and
      can leave only by an explicit operator ``blackbox report``.

    Self-discovered threats and VERIFIED-tier matches still share.
    """

    def __init__(self, cfg: BlackboxConfig) -> None:
        self._cfg = cfg

    def decide(self, finding: dict[str, Any], reporter: Optional[str]) -> tuple[bool, str]:
        if not self._cfg.community_enabled:
            return False, "community sharing disabled"
        if not consent.in_force():   # R13: opt-in (a recorded acceptance), withdrawable
            return False, consent.why_not()
        if finding.get("source") in NEVER_SHARED_SOURCES:
            return False, f"source {finding.get('source')} never leaves the machine"
        if is_vulnerability_finding(finding):
            return False, "vulnerability findings stay in the local audit (decision 22)"
        if finding.get("source") == "community":
            return False, "community-only match: flagged here, shared only by an explicit `blackbox report`"
        if not str(finding.get("identifier") or "").strip():
            return False, "no identifier"
        if not reporter:
            return False, "no resolved reporter identity"
        return _schema_decision(finding)


#: Finding fields that describe THIS machine's check, never the threat: they stay in the
#: local audit and are never put into a shared report (``answered_by`` says the local
#: fallback index answered because the graph store was down — DKG-lookup).
LOCAL_ONLY_FIELDS = frozenset({"answered_by"})


def shareable_fields(finding: dict[str, Any]) -> dict[str, Any]:
    """The fields a report may carry: the finding's evidence plus the sighting
    the guard attached (threat-profiles §03.2) — set, and not local-only."""
    fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
    sighting = finding.get("sighting") if isinstance(finding.get("sighting"), dict) else {}
    return {k: v for k, v in {**fields, **sighting}.items() if v is not None and k not in LOCAL_ONLY_FIELDS}


def _schema_decision(finding: dict[str, Any]) -> tuple[bool, str]:
    """Whether *finding* builds a valid report (the R1 schema), and why not."""
    fields = shareable_fields(finding)
    try:
        report_schema.validate_report(
            identifier=str(finding.get("identifier") or ""),
            category=str(finding.get("category") or ""),
            severity=str(finding.get("severity") or "info"),
            framework=HOST_FRAMEWORK,
            evidence=fields,
        )
    except report_schema.ReportValidationError as exc:
        return False, f"not a valid report, stays local: {exc}"
    return True, "ok"


class ShareOutcome(Enum):
    """What sending one report achieved — shown apart, never conflated (KI-104).

    ``ACCEPTED`` — a new report reached the network. ``REJECTED_SAME_VERSION``
    — this exact report was shared before; peers refuse a same-version
    re-share (KI-103), so it is not re-sent and is NOT counted as a new
    contribution. ``FAILED`` — the send failed. ``NOT_ALLOWED`` — nothing was sent:
    sharing is off or consent is not in force (the detail says which); the caller stops
    and keeps what it had, it is not a failure to retry.
    """

    ACCEPTED = "accepted"
    REJECTED_SAME_VERSION = "already-shared"
    FAILED = "failed"
    NOT_ALLOWED = "not-allowed"


#: The daemon's reply when a report with this name already exists sealed and it
#: refuses to rewrite it (DKG 10.0.20, captured on the R0P bench 2026-10-01).
#: Matched narrowly against that exact text (LES-015).
ALREADY_SEALED_REPLY = "is not an active working memory draft"


def send_report(client: DkgClient, graph: str, name: str, quads: list[dict[str, str]],
                lane: str = constants.COMMUNITY_SUB_GRAPH, *, cfg: Any,
                reduces: bool = False) -> tuple[ShareOutcome, str]:
    """Send one built report into *lane* (a shared-memory sub-graph) and say honestly
    what happened: (outcome, detail).

    THE outbound gate is here, where data leaves the machine: unless *reduces*, nothing
    is sent while ``consent.sharing_on(cfg)`` is false (``NOT_ALLOWED``, the reason in
    *detail*). Senders may check first to skip their work, but a sender that forgets
    still sends nothing. *reduces* — a dispute or a retraction: it only lowers
    enforcement, so it goes through whatever the switch says (LES-016). *cfg* has no
    default on purpose: every caller hands the gate its config.

    A report this node already got onto the network (its ledger says so) is
    not re-sent; neither is one the daemon reports as already sealed. Both
    come back as REJECTED_SAME_VERSION — before KI-180 the first was logged
    as a failure, before KI-104 the second as a success.
    """
    if not reduces and not consent.sharing_on(cfg):
        return ShareOutcome.NOT_ALLOWED, consent.why_not() or "community sharing is off"
    if audit.previously_accepted(name):
        return ShareOutcome.REJECTED_SAME_VERSION, "already shared earlier; a same-version re-share is refused by peers"
    try:
        membership.ensure_report_lane(client, graph)   # registers the lanes on the graph owner's node only
        result = client.share_knowledge_asset(graph, name, quads, sub_graph=lane)
    except Exception as exc:  # the outermost send boundary: any failure is FAILED, never raised
        if isinstance(exc, DkgError) and ALREADY_SEALED_REPLY in str(exc).lower():
            return ShareOutcome.REJECTED_SAME_VERSION, "the node already holds this report sealed (not re-sent)"
        logger.debug("blackbox: report share failed: %s", exc)
        return ShareOutcome.FAILED, str(exc)
    if isinstance(result, dict) and result.get("idempotent"):
        return ShareOutcome.REJECTED_SAME_VERSION, "the node reported this report as already shared"
    return ShareOutcome.ACCEPTED, ""


def spawn_community_share(
    client: DkgClient, cfg: BlackboxConfig, finding: dict[str, Any], reporter: str
) -> threading.Thread:
    """Run the share network lifecycle off the hook hot path (KI-033).

    Daemon thread, same pattern as the OSV and LLM workers in this file: the
    hook returns immediately; the share can take the node's full store/poll
    timeouts without ever freezing the protected agent.
    """
    # copy_context: a share started inside audit.sandbox_run() ledgers into the sandbox too
    worker = threading.Thread(
        target=contextvars.copy_context().run,
        args=(_share_sighting, client, cfg, finding, reporter),
        name="blackbox-community-share",
        daemon=True,
    )
    worker.start()
    return worker


def _share_sighting(
    client: DkgClient, cfg: BlackboxConfig, finding: dict[str, Any], reporter: str
) -> None:
    """Share one privacy-safe sighting with the community and ledger it.

    Targets the verified graph's SHARED memory, sub-graph
    ``constants.COMMUNITY_SUB_GRAPH`` (one graph, 2026-10-16) — never its
    Verified Memory: only the curator publishes there, and a report reaches it
    only when the curator promotes what it confirmed. Every attempt
    (success or failure) lands in the local reports ledger (KI-015) so the
    node keeps a durable record of its contributions. A node that cannot sign
    does not share (R0b): the refusal is ledgered like any failure. Fail-open.
    """
    identifier = str(finding.get("identifier") or "")
    subject = threat_ids.report_uri(identifier, reporter)
    name = report_asset_name(cfg, identifier, reporter)
    signer = report_signer.resolve_report_signer(client, cfg.context_graph_id)
    if signer is None:
        _ledger_share(finding, subject, name, ok=False, error="cannot sign reports (no network id or reporter key)")
        return
    try:
        # Reports contain signatures, never raw prompts, paths, or source files.
        fields = shareable_fields(finding)
        q = community.build_report_quads(
            identifier=identifier,
            category=str(finding.get("category") or ""),
            severity=str(finding.get("severity") or "info"),
            reporter_address=reporter,
            framework=HOST_FRAMEWORK,
            signer=signer,
            **fields,
        )
        outcome, detail = send_report(client, cfg.context_graph_id, name, q, lane=community_lane(cfg), cfg=cfg)
    except Exception as exc:  # pragma: no cover - fail open (building the report failed)
        logger.debug("blackbox: sighting share error: %s", exc)
        _ledger_share(finding, subject, name, ok=False, error=str(exc), outcome=ShareOutcome.FAILED.value)
        return
    _after_send(cfg, finding, name, subject, q, outcome, detail)


def report_asset_name(cfg: BlackboxConfig, identifier: str, reporter: str) -> str:
    """The asset name this node shares its report of *identifier* under: ``report-<hash>``, or
    ``sandbox-<hash>`` in sandbox mode, so a test never takes the name of the real report."""
    return f"{'sandbox' if cfg.community_sandbox else 'report'}-{threat_ids.stable_hash(identifier + reporter, 16)}"


def community_lane(cfg: BlackboxConfig) -> str:
    """The sub-graph this node's shares go to: ``sandbox`` in sandbox mode, else ``reports``."""
    return constants.SANDBOX_SUB_GRAPH if cfg.community_sandbox else constants.COMMUNITY_SUB_GRAPH


def _after_send(cfg: BlackboxConfig, finding: dict[str, Any], name: str, subject: str,
                q: list[dict[str, str]], outcome: ShareOutcome, detail: str) -> None:
    """Ledger one send; a refused real share is queued for retry, an accepted one kept alive.
    A sandbox test is only ledgered (in the sandbox folder): never retried, never kept alive."""
    identifier = str(finding.get("identifier") or "")
    if outcome is ShareOutcome.NOT_ALLOWED:   # nothing left the machine: nothing to ledger or retry
        logger.debug("blackbox: community share not sent: %s", detail)
        return
    if cfg.community_sandbox:
        _ledger_share(finding, subject, name, ok=outcome is ShareOutcome.ACCEPTED, error=detail, outcome=outcome.value)
        return
    if outcome is ShareOutcome.FAILED:
        # R16 (KI-202): a refused write is retried with backoff — a newly subscribed
        # node is refused for minutes on mainnet; its first catches must not be lost.
        share_retry.queue_failed_share(graph=cfg.context_graph_id, name=name, identifier=identifier,
                                       category=str(finding.get("category") or ""),
                                       severity=str(finding.get("severity") or "info"), subject=subject, quads=q,
                                       error=detail)
        return
    _ledger_share(finding, subject, name, ok=outcome is ShareOutcome.ACCEPTED, error=detail, outcome=outcome.value)
    if outcome is ShareOutcome.ACCEPTED:   # R5: this node keeps its own live reports on the network
        keep_alive.remember_accepted_share(cfg, name=name, identifier=identifier, subject=subject,
                                           severity=str(finding.get("severity") or "info"), quads=q)


def _ledger_share(finding: dict[str, Any], subject: str, name: str, *, ok: bool, error: str = "",
                  outcome: str = "") -> None:
    audit.record_share_outcome(
        identifier=str(finding.get("identifier") or ""),
        category=str(finding.get("category") or ""),
        severity=str(finding.get("severity") or ""),
        subject=subject,
        asset_name=name,
        ok=ok,
        error=error,
        outcome=outcome,
    )
