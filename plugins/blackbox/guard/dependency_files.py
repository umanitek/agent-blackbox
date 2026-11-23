"""The dependency-file checks in the hooks (KI-595): before a call, after it, and the session notes.

Before a call (:func:`before_call`, part of every judgement — the Hermes hook and
``tool_call_verdict`` alike): the files a manifest install installs from, and the packages a
write adds to a manifest or lockfile. After a call (:func:`after_call`, the Hermes post hook):
what an install added to its lockfile — a verified package that landed is a critical alert.

What could not be checked is recorded on the session as a ``dependency_check`` audit row
("dependencies not checked: package-lock.json is larger than 25 MB") — fail-open, never silent.
Only the Hermes hooks record (they pass a *session_id*); a verdict asked by another runtime
records nothing, as before.

Usage::

    findings = before_call(cfg, rules, tool_name, args, session_id)    # in the judgement
    after_call(load_config, tool_name, args, session_id, tool_call_id)  # in on_post_tool_call
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .. import audit, detection, shields
from ..kernel import action_context
from ..kernel.config import BlackboxConfig, reads_graph_directly
from . import graph_rules, host_process, reporting


#: The audit event a session's dependency notes are recorded under.
NOTE_EVENT = "dependency_check"
#: Why the per-call graph backend cannot judge a lockfile: it reads only the packages a command names.
DIRECT_BACKEND_NOTE = ("dependencies not checked: the per-call graph backend (detection_backend: dkg) reads only "
                       "the packages a command names, not a lockfile's")
_MAX_NOTES = 10


def record_notes(notes: list[str], tool_name: str, session_id: Optional[str]) -> None:
    """Record *notes* on the session (nothing when there are none or no Hermes session asked)."""
    if notes and session_id is not None:
        audit.record(event=NOTE_EVENT, detail={"session_id": session_id, "tool_name": tool_name,
                                               "notes": list(dict.fromkeys(notes))[:_MAX_NOTES]})


def before_call(cfg: BlackboxConfig, rules: Any, tool_name: str, args: Any,
                session_id: Optional[str] = None) -> list[detection.Finding]:
    """The dependency-file findings for one call before it runs (see the module doc)."""
    isolated = detection.run_isolated
    findings = isolated("check_dependency_write", lambda: detection.check_dependency_write(tool_name, args, rules))
    check = detection.DependencyCheck()
    try:
        check = detection.check_install_files(tool_name, args, rules)
    except Exception as exc:   # health: allow BLE001 -- fail-open, said on the session: a reader bug must not end the other checks
        check.notes.append(f"dependencies not checked: the check failed ({type(exc).__name__})")
    if reads_graph_directly(cfg) and check.files_read:
        check.notes.append(DIRECT_BACKEND_NOTE)
    record_notes(check.notes, tool_name, session_id)
    return findings + check.findings


def after_call(config: Callable[[], BlackboxConfig], tool_name: str, args: Any, session_id: str,
               tool_call_id: str) -> None:
    """Judge what an install added to its lockfile, raise a critical alert for a verified package
    that landed, and record what could not be read. *config* loads the settings (inside the
    fail-open boundary). Runs in this Hermes process's folder, as the judgement before it did."""
    try:
        cfg = config()
        with action_context.working_in(host_process.facts()["cwd"]):
            check = detection.check_landed(tool_name, args, lambda: graph_rules.detection_rules(cfg, tool_name, args)[0])
        findings = reporting._flag_worthy(cfg, check.findings, shields.snapshot()) if check.findings else []
        if findings:
            reporting._report_and_audit(cfg, "post_install_dependencies", findings, {
                "tool_name": tool_name, "session_id": session_id, "tool_call_id": tool_call_id,
                "decision": "flag", "after_install": True})
        record_notes(check.notes, tool_name, session_id)
    except Exception as exc:  # health: allow BLE001 -- the post hook's fail-open boundary; hook_failed records it (FIX-0160)
        reporting.hook_failed("post_tool_call", exc, tool_name=tool_name,
                              consequence="the packages the install added were not checked")
