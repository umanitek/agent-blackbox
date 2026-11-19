"""Audit — the RECORD flow: what Blackbox saw, kept locally and redacted.

Everything here writes to or reads from ``$BLACKBOX_HOME`` (default
``~/.hermes/blackbox/``) on this machine only — size-capped JSONL logs, plus a
private working-memory record in the local node. Callers use this surface:

* Writing: :func:`record`, :func:`record_file_access`, :func:`record_dependency`,
  :func:`write_private_audit_ka` (into :func:`local_audit_graph`, this node's own private graph); redaction: :func:`sanitize_text`, :func:`redact`.
* Reading: :func:`read_findings`, :func:`count_findings`, :func:`read_audit`,
  :func:`count_audit`, :func:`read_local_activity`, :func:`read_file_access`,
  :func:`local_frameworks`, :func:`local_active_frameworks`.
* Outbound-report bookkeeping: :func:`record_share_outcome`,
  :func:`read_share_ledger`, :func:`erase_share_records`, :func:`recently_reported`, :func:`mark_reported`,
  :func:`allow_report`.

Usage::

    from .. import audit
    audit.record(event, finding, detail)
"""

from __future__ import annotations

from .activity import count_audit, read_audit, read_local_activity
from .findings import (
    count_findings,
    blocked_counts_by_identifier,
    local_active_frameworks,
    local_frameworks,
    read_file_access,
    read_findings,
    record,
    record_dependency,
    record_file_access,
)
from .private_ka import node_is_local, write_private_audit_ka
from .profile_logs import fold_profile_logs
from .local_graph import local_audit_graph
from .log_store import in_sandbox_run, sandbox_run
from .redaction import redact, sanitize_text
from .share_ledger import (
    allow_report,
    mark_reported,
    erase_share_records,
    read_share_ledger,
    recently_reported,
    previously_accepted,
    record_share_outcome,
)

__all__ = [
    "allow_report",
    "blocked_counts_by_identifier",
    "count_audit",
    "count_findings",
    "erase_share_records",
    "fold_profile_logs",
    "in_sandbox_run",
    "local_active_frameworks",
    "local_audit_graph",
    "local_frameworks",
    "mark_reported",
    "node_is_local",
    "previously_accepted",
    "read_audit",
    "read_file_access",
    "read_findings",
    "read_local_activity",
    "read_share_ledger",
    "recently_reported",
    "record",
    "record_dependency",
    "record_file_access",
    "record_share_outcome",
    "redact",
    "sandbox_run",
    "sanitize_text",
    "write_private_audit_ka",
]
