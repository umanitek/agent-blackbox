"""Statements about reports — `blackbox report --false-positive` and
`--retract` — the report verb itself, and the send-and-record step they all share.

:func:`submit_report` sends one manual report. :func:`send_and_record` sends one built statement and writes the local share
ledger (KI-015: every attempt, success or failure). :func:`submit_statement`
dispatches to the DISPUTE verb (:func:`submit_false_positive`) or the RETRACT
verb (:func:`submit_retraction`, Refine R1). Called by
:func:`.report_command.cmd_report`.
"""

from __future__ import annotations

import argparse
from typing import Optional

from ... import audit
from ...kernel import display_safety, threat_ids
from ...kernel.dkg_client import DkgClient
from .. import keep_alive as keep_alive_mod
from .. import report_builder, report_schema, report_signer, sharing


def send_and_record(client: DkgClient, cfg, *, identifier: str, category: str, severity: str,
                     subject: str, name: str, quads: list[dict[str, str]],
                     reduces: bool = False) -> tuple[sharing.ShareOutcome, str]:
    """Send one built statement (a dispute or a retraction; reports go through
    :func:`.sharing.share_report`) and record the attempt in the local share ledger,
    success or failure (KI-015). Returns (outcome, detail) for the caller to report.
    Disputes and retractions are final: never kept alive, never queued."""
    outcome, detail = sharing.send_report(client, cfg.context_graph_id, name, quads, cfg=cfg, reduces=reduces)
    if outcome is sharing.ShareOutcome.NOT_ALLOWED:   # nothing left the machine: no ledger row
        return outcome, detail
    audit.record_share_outcome(
        identifier=identifier, category=category, severity=severity,
        subject=subject, asset_name=name, ok=outcome is sharing.ShareOutcome.ACCEPTED,
        error=detail, outcome=outcome.value,
    )
    return outcome, detail


def submit_report(client: DkgClient, cfg, finding: dict, reporter: str, signer: report_signer.ReportSigner) -> int:
    """Send one validated manual report (lifecycle: SUBMIT + ACKNOWLEDGE): cooldown and daily
    cap first, then :func:`.sharing.share_report` (the same path as automatic reports). *finding* is
    ``{"identifier", "category", "severity", "fields"}`` from the report command's factory.
    Prints the outcome and returns the exit code.

    In sandbox mode the report is a test, like an automatic one: it goes to the sandbox lane
    under a ``sandbox-`` name, uses the sandbox's own ledger, cooldown and cap, and is never
    kept alive or retried — so it cannot silence or mix with a real report of the same threat."""
    if cfg.community_sandbox:
        with audit.sandbox_run():
            return _send_report(client, cfg, finding, reporter, signer)
    return _send_report(client, cfg, finding, reporter, signer)


def _send_report(client: DkgClient, cfg, finding: dict, reporter: str, signer: report_signer.ReportSigner) -> int:
    sandbox = cfg.community_sandbox
    identifier = finding["identifier"]
    if audit.recently_reported(identifier):
        print(f"Already reported within the cooldown window: {display_safety.term_safe(identifier)}")
        return 0
    if not audit.allow_report(cfg.daily_report_limit):
        print(f"Daily report cap reached ({cfg.daily_report_limit}); try again tomorrow.")
        return 2
    outcome, detail, _name, subject = sharing.share_report(client, cfg, finding, reporter, signer)
    if outcome is sharing.ShareOutcome.NOT_ALLOWED:
        print(f"Not submitted: {display_safety.term_safe(detail, 160)}.")
        return 2
    if outcome is sharing.ShareOutcome.FAILED and sandbox:   # a test is never queued for retry
        print(f"Sandbox test share refused: {display_safety.term_safe(detail, 160)}")
        return 1
    if outcome is sharing.ShareOutcome.FAILED:   # the share path queued it for retry
        print(f"Share refused for now: {display_safety.term_safe(detail, 160)}")
        print("Queued for automatic retry (a newly subscribed node is refused for a few minutes). "
              "`blackbox report --status` shows it as 'retrying' until it lands.")
        return 1
    audit.mark_reported(identifier)
    if outcome is sharing.ShareOutcome.REJECTED_SAME_VERSION:
        print(f"Already shared with the community — not re-sent ({display_safety.term_safe(detail, 120)}).")
        return 0
    print("Sandbox mode: test report sent to the sandbox lane only; nothing reached the community's reports."
          if sandbox else "Report shared with the community.")
    print(f"  identifier: {display_safety.term_safe(identifier)}")
    print(f"  subject:    {display_safety.term_safe(subject)}")
    return 0


def submit_false_positive(client: DkgClient, cfg, identifier: str, reason: Optional[str], reporter: str,
                           signer: report_signer.ReportSigner) -> int:
    """Dispute a community threat (lifecycle: DISPUTE — the Q8 veto writer).
    A closed --reason is required (Refine R1); nothing is sent without one."""
    try:
        identifier, reason = report_schema.validate_dispute(identifier=identifier, reason=reason or "")
    except report_schema.ReportValidationError as exc:
        print(f"Invalid dispute: {exc}")
        print("Nothing was submitted.")
        return 2
    q = report_builder.build_false_positive_quads(identifier=identifier, reporter_address=reporter,
                                                  reason=reason, signer=signer)
    name = f"fp-{threat_ids.stable_hash(identifier + reporter, 16)}"
    subject = threat_ids.report_uri(identifier, reporter) + ":fp"
    outcome, detail = send_and_record(client, cfg, identifier=identifier, category="false-positive",
                                       severity="info", subject=subject, name=name, quads=q, reduces=True)
    if outcome is sharing.ShareOutcome.FAILED:
        print(f"Dispute FAILED: {display_safety.term_safe(detail, 160)}")
        print("The attempt is recorded in your local reports ledger.")
        return 1
    if outcome is sharing.ShareOutcome.REJECTED_SAME_VERSION:
        print(f"Dispute already shared with the community for: {display_safety.term_safe(identifier)} (not re-sent)")
        return 0
    print(f"False-positive signal shared for: {display_safety.term_safe(identifier)}")
    return 0


def submit_statement(client: DkgClient, cfg, args: argparse.Namespace, reporter: str,
                     signer: report_signer.ReportSigner) -> int:
    """A dispute (``--false-positive``) or a retraction (``--retract``)."""
    if args.false_positive:
        return submit_false_positive(client, cfg, args.false_positive, args.reason, reporter, signer)
    return submit_retraction(client, cfg, args.retract, reporter, signer)


def submit_retraction(client: DkgClient, cfg, identifier: str, reporter: str,
                      signer: report_signer.ReportSigner) -> int:
    """Withdraw this node's own report (lifecycle: RETRACT, Refine R1).

    Readers drop every report this node's key signed for the identifier
    (:mod:`.retractions`). Final: the same report cannot be re-sent.
    """
    try:
        identifier = report_schema.validate_statement_identifier(identifier)
    except report_schema.ReportValidationError as exc:
        print(f"Invalid retraction: {exc}")
        print("Nothing was submitted.")
        return 2
    quads = report_builder.build_retraction_quads(identifier=identifier, reporter_address=reporter,
                                                  framework=sharing.HOST_FRAMEWORK, signer=signer)
    name = f"retract-{threat_ids.stable_hash(identifier + reporter, 16)}"
    subject = threat_ids.report_uri(identifier, reporter) + ":retract"
    outcome, detail = send_and_record(client, cfg, identifier=identifier, category="retraction",
                                      severity="info", subject=subject, name=name, quads=quads, reduces=True)
    if outcome is sharing.ShareOutcome.FAILED:
        print(f"Retraction FAILED: {display_safety.term_safe(detail, 160)}")
        print("The attempt is recorded in your local reports ledger.")
        return 1
    keep_alive_mod.forget_retracted(identifier)   # R5: a retracted report is never kept alive again
    print(f"Retraction shared for: {display_safety.term_safe(identifier)}")
    print("Nodes running this version or later stop counting your report; older nodes count it until")
    print("they update. The report's record stays on the network — a shared graph cannot delete it.")
    return 0
