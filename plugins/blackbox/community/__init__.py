"""Community — what every protected agent shares and learns from.

Since 2026-10-16 the community lives in the verified graph itself: every node
shares its signed reports into that graph's shared memory (sub-graph
``kernel.constants.COMMUNITY_SUB_GRAPH``), and the curators promote what they
confirm into its Verified Memory. There is no second graph.
Every protected agent can report what it sees; every other agent reads it.
Community findings only ever FLAG — they never block — and community strings
are untrusted data that is clamped, typed and displayed, never interpreted.

Public surface:

* :class:`CommunityRule` — one corroborated community threat (the typed seam).
* :func:`fetch_community_report_rows` / :func:`aggregate_community_reports` —
  read reports, then fold them into rules (honest distinct-reporter counts).
* :func:`community_pause_active` / ``COMMUNITY_PAUSE_SUBJECT`` — the curator's
  fleet-wide ingest pause flag (read-only for us).
* :func:`community_report_count` — how many reports the graph holds.
* :class:`CommunitySharePolicy`, ``NEVER_SHARED_SOURCES`` — THE outbound gate;
  :func:`spawn_community_share` sends an allowed finding. This node's
  reporting identity is resolved by ``kernel.identity.reporter_address``.
* :func:`add_report_parser` + :func:`cmd_report` (``blackbox report``), :func:`print_community_status`
  (the status block), :func:`ensure_community_subscription` (the verified graph's
  subscription with the shared memory the community lives in),
  :func:`read_join_state` + :class:`JoinState` / ``JOIN_STATE_TEXT`` (is this node
  connected to that graph yet — the dashboard's community tile).
* :func:`build_report_quads` / :func:`build_false_positive_quads` /
  :func:`build_retraction_quads` — the
  privacy-safe statements a report or dispute shares (write side).
* :func:`read_verified_reports` — THE community read: fetch + verify (R0c/R0d).
* The curator's view and statements (Refine R2/R6): :func:`read_curator_view` ->
  :class:`CuratorView`; :func:`sign_curator_statement`, :func:`curator_statement_quads`,
  :func:`key_manifest_quads`, :data:`VERIFIED_GRAPH_KINDS` (which kinds live in the verified graph),
  :data:`EVIDENCE_REFERENCE` (the closed format of the evidence a confirmation cites).
* :func:`trust_panel` / :func:`trust_status_lines` — who curates, who is trusted, what is confirmed: one read
  model for the dashboard's trust panel and `blackbox status` (Community Curation C10).
* :func:`verified_manifest_history` / :func:`manifest_on_day` — the verified authority's root-signed
  manifests and which one was in force on a day: the verified scope tiers each new asset once against it
  (trust-and-threat-lab R2, F-050).
* :func:`stage_for` (+ :class:`Stage`, :class:`Enforcement`, :class:`StageResult`) —
  a community threat's local stage from the counted-author list (R3); :func:`clusters_for`
  (+ :class:`Clusters`) — the partner and established clusters behind it (the lab trigger reads them).
* :func:`record_verified_sighting` / :func:`publish_due_digests` — the
  seen-again counter: tally verified matches, publish one weekly digest (R2b).
* :mod:`shadow` — the shadow phase (R15): the MONITOR clamp and the §12 metrics log.
* :mod:`consent` — the sharing consent record (R13): opt-in, bound to the terms' content, withdrawable;
  the share gate refuses without it.
* :mod:`allowlist` — the allowlist / warninglist verdict and canaries (R9): byte-exact
  names hold, look-alikes support the report.
* :mod:`pool` — the confirmed pool (threats with a standing, evidenced community confirmation) and the
  export bundle its receiver checks offline from the community root (Community Curation C8).
* :mod:`reputation` — automated graduation, novelty, partners, collusion and the
  curator-private ledger (R4); readers see its decisions only through the counted-author list.
* :func:`publish_due_copies` — keep-alive (R5): this node re-publishes an
  epoch-named copy of each of its own live reports; :func:`lifetime_days` —
  how long a community statement lives, per threat type (plan §03).
* :func:`contributing_agent_count`, :func:`community_agents`,
  :func:`most_reported_threats`, :func:`reports_signed_by` — statistics over
  verified reports, counted by signer (unsanitized; the caller escapes).

Usage::

    from .. import community
    rows = community.fetch_community_report_rows(client, cfg)
    rules = community.aggregate_community_reports(rows or [], prior_first_seen)
"""

from __future__ import annotations

from .report_builder import build_false_positive_quads, build_report_quads, build_retraction_quads
from .sighting import injection_host_identifier, sighting_fields
from .membership import JOIN_STATE_TEXT, JoinState, ensure_community_subscription, ensure_report_lane, read_join_state
from .report_cli import add_report_parser, cmd_report, print_community_status
from .sharing import ALREADY_SEALED_REPLY, NEVER_SHARED_SOURCES, CommunitySharePolicy, spawn_community_share
from .graph_stats import community_agents, contributing_agent_count, most_reported_threats, reports_signed_by
from .verification import ReportVerifier, VerifiedReport, verify_report_rows
from .report_signer import network_environment
from .aggregation import CommunityRule, aggregate_community_reports
from .digest import publish_due_digests, record_verified_sighting
from . import keep_alive
from .keep_alive import publish_due_copies
from .statements.curator_view import COMMUNITY_LISTING_MAX_DAYS
from . import allowlist, consent, pool, reputation, shadow
from .pulse import PULSE
from .pulse import fingerprint as community_fingerprint
from .statements.lifetimes import lifetime_days
from .statements.author_budget import FirstSeenStore as _FirstSeenStore
from .share_retry import retry_due_shares, share_retry_stats
from .stages import Clusters, Enforcement, Stage, StageResult, clusters_for, stage_for
from .statements.curator_view import VERIFIED_GRAPH_KINDS, CuratorView, counted_dispute_weight
from .statements.curator_statements import EVIDENCE_REFERENCE
from .statements.curator_statements import manifest_quads as key_manifest_quads
from .statements.curator_statements import sign_statement as sign_curator_statement
from .statements.curator_statements import statement_quads as curator_statement_quads
from .reader import (
    COMMUNITY_PAUSE_SUBJECT,
    community_pause_active,
    community_report_count,
    fetch_community_report_rows,
    CommunityRead,
    ReadState,
    read_verified_reports,
)
from .trust import ActiveGraph, active_verified_graph, known_curator_statements, read_curator_view
from .trust import status_lines as trust_status_lines
from .trust import trust_panel
from .trust.manifest_history import manifest_on_day, verified_manifest_history
from ..kernel.sparql_text import page_rows
from ..kernel.signing.trust_anchors import trusted_roots as curator_trusted_roots
from .statements.curator_view import today_utc as curator_today


def first_seen_trail():
    """R10b: ({subject hash: first-seen epoch}, baseline) from the reader's budget trail — read-only."""
    return _FirstSeenStore().snapshot()


__all__ = [
    "ALREADY_SEALED_REPLY",
    "COMMUNITY_LISTING_MAX_DAYS",
    "COMMUNITY_PAUSE_SUBJECT",
    "EVIDENCE_REFERENCE",
    "JOIN_STATE_TEXT",
    "NEVER_SHARED_SOURCES",
    "PULSE",
    "VERIFIED_GRAPH_KINDS",
    "ActiveGraph",
    "Clusters",
    "CommunityRead",
    "CommunityRule",
    "CommunitySharePolicy",
    "CuratorView",
    "Enforcement",
    "JoinState",
    "ReadState",
    "ReportVerifier",
    "Stage",
    "StageResult",
    "VerifiedReport",
    "active_verified_graph",
    "add_report_parser",
    "aggregate_community_reports",
    "allowlist",
    "build_false_positive_quads",
    "build_report_quads",
    "build_retraction_quads",
    "clusters_for",
    "cmd_report",
    "community_agents",
    "community_fingerprint",
    "community_pause_active",
    "community_report_count",
    "consent",
    "contributing_agent_count",
    "counted_dispute_weight",
    "curator_statement_quads",
    "curator_today",
    "curator_trusted_roots",
    "ensure_community_subscription",
    "ensure_report_lane",
    "fetch_community_report_rows",
    "first_seen_trail",
    "injection_host_identifier",
    "keep_alive",
    "key_manifest_quads",
    "known_curator_statements",
    "lifetime_days",
    "manifest_on_day",
    "most_reported_threats",
    "network_environment",
    "page_rows",
    "pool",
    "print_community_status",
    "publish_due_copies",
    "publish_due_digests",
    "read_curator_view",
    "read_join_state",
    "read_verified_reports",
    "record_verified_sighting",
    "reports_signed_by",
    "reputation",
    "retry_due_shares",
    "shadow",
    "share_retry_stats",
    "sighting_fields",
    "sign_curator_statement",
    "spawn_community_share",
    "stage_for",
    "trust_panel",
    "trust_status_lines",
    "verified_manifest_history",
    "verify_report_rows",
]
