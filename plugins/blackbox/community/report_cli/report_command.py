"""``blackbox report`` — file, dispute and review this node's community reports.

Manual reports go through the same share path as automatic ones; also
``--status`` (this node's contributions, from the share ledger plus the
graph). Disputes and retractions are in :mod:`.statement_verbs`; export,
key restore and identity erasure in :mod:`.report_rights`.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from ... import audit
from ... import detection
from .. import consent, graph_stats, report_builder, report_schema, report_signer, sharing, share_retry
from . import report_rights, report_tracking, statement_verbs, submission_gate
from .. import reader as graph_reader
from ...kernel import constants, threat_ids

from ...kernel.config import load_blackbox_config
from ...kernel.dkg_client import DkgClient
from ...kernel import display_safety, identity, reporter_key

logger = logging.getLogger(__name__)

def print_community_status(cfg) -> None:
    """The truthful community lines for `blackbox status` (B4).

    Reads only local state (config + the reports ledger) so status stays
    instant and offline-safe; ledger identifiers are community-era data and
    render through :func:`_term_safe`.
    """
    if not cfg.context_graph_id:
        print("  community:         no graph configured (community sharing dormant)")
        return
    print(f"  community:         shared memory of {display_safety.term_safe(cfg.context_graph_id)}")
    # One answer for "is sharing on?" (consent.sharing_on): the switch AND an opt-in record.
    if consent.sharing_on(cfg):
        state = f"on (min severity {cfg.report_min_severity}, cap {cfg.daily_report_limit}/day)"
    elif not cfg.report:
        state = "off — opt-in; `blackbox report --enable-sharing` turns it on"
    else:
        state = f"off — {consent.why_not() or 'no graph is configured'}"
    print(f"  threat sharing:    {state}")
    ledger = audit.read_share_ledger(limit=1000)
    contributed = sum(1 for row in ledger if row.get("ok"))
    line = f"  reports shared:    {contributed}"
    if ledger:
        last = ledger[0]
        outcome = report_tracking.outcome_label(last)   # a refused re-share reads "already shared", not FAILED
        line += f" (last: {display_safety.term_safe(last.get('identifier'), 80)} · {outcome} · {display_safety.term_safe(last.get('ts'), 24)})"
    print(line)


#: Per-type required args (KI-025): a manual report with missing coordinates
#: would derive a malformed identifier (e.g. ``dep::pkg@``) that poisons
#: corroboration counting — reject loudly, submit nothing.
_REPORT_REQUIRED_ARGS: dict[str, tuple[str, ...]] = {
    "injection": ("pattern", "context"),
    "escalation": ("tool", "arg_shape"),
    "dependency": ("ecosystem", "name", "package_version", "kind", "reason"),
    "fileaccess": ("tool", "category"),
    "skill": (),   # either --registry/--skill-name/--skill-version or --artifact-hash/--danger-shape
    "ioc": ("ioc_type", "value", "context"),
}


#: Argument dest -> the flag an operator types (KI-066: the package version is
#: --package-version; Hermes's own top-level --version swallows `--version`).
#: The DEST must not be "version" either: Hermes prints its banner whenever the
#: parsed arguments carry a truthy ``version`` (KI-276).
_FLAG_NAMES = {"package_version": "package-version"}


#: (identifier, fields, error) for one report type's parsed args.
_ParsedReport = tuple[str, dict[str, Any], str]


def _injection_args(args: argparse.Namespace) -> _ParsedReport:
    # Never the pattern text: the identifier is its hash; where it was seen instead (R1).
    return threat_ids.injection_identifier(args.pattern), {"context": args.context, "owasp_category": args.owasp}, ""


def _escalation_args(args: argparse.Namespace) -> _ParsedReport:
    return (threat_ids.escalation_identifier(args.tool, args.arg_shape),
            {"tool_name": args.tool, "arg_shape": args.arg_shape}, "")


def _dependency_args(args: argparse.Namespace) -> _ParsedReport:
    fields = {
        "ecosystem": args.ecosystem.strip().lower(),
        "package_name": threat_ids.canonical_package_name(args.ecosystem, args.name),
        "package_version": args.package_version,
        "advisory_id": args.advisory_id,
        "kind": args.kind,
        "reason": args.reason,
    }
    return threat_ids.dependency_identifier(args.ecosystem, args.name, args.package_version), fields, ""


def _fileaccess_args(args: argparse.Namespace) -> _ParsedReport:
    return (threat_ids.fileaccess_identifier(args.tool, args.category),
            {"tool_name": args.tool, "file_category": args.category}, "")


def _skill_args(args: argparse.Namespace) -> _ParsedReport:
    """A local skill by --artifact-hash + --danger-shape (never its name,
    KI-159), or a known-bad registry skill by --registry/--skill-name/--skill-version."""
    if args.artifact_hash or args.danger_shape:
        if args.skill_name or args.skill_version or args.registry:
            return "", {}, "a local skill is reported by --artifact-hash + --danger-shape, never by name"
        if not (args.artifact_hash and args.danger_shape):
            return "", {}, "--type skill (local) requires --artifact-hash and --danger-shape"
        fields = {"artifact_hash": args.artifact_hash.strip().lower(), "danger_shape": args.danger_shape}
        return threat_ids.skill_artifact_identifier(args.artifact_hash, args.danger_shape), fields, ""
    if not (args.registry and args.skill_name and args.skill_version):
        return "", {}, ("--type skill requires --registry, --skill-name and --skill-version "
                        "(or, for a local skill, --artifact-hash and --danger-shape)")
    fields = {"registry": args.registry, "skill_name": args.skill_name, "skill_version": args.skill_version}
    return threat_ids.skill_version_identifier(args.skill_name, args.skill_version), fields, ""


def _ioc_args(args: argparse.Namespace) -> _ParsedReport:
    return (threat_ids.ioc_identifier(args.ioc_type, args.value),
            {"ioc_type": args.ioc_type, "ioc_context": args.context}, "")


#: Report type -> how its args become (identifier, fields). Strategy table: one
#: small function per type, each deriving the identifier with the SAME helpers
#: automatic detection uses.
_REPORT_FIELDS = {
    "injection": _injection_args,
    "escalation": _escalation_args,
    "dependency": _dependency_args,
    "fileaccess": _fileaccess_args,
    "skill": _skill_args,
    "ioc": _ioc_args,
}


def _queue_refused_share(cfg, finding, *, subject: str, name: str, quads, detail: str) -> int:
    """R16: a refused write is queued for automatic retry, and the operator is told so."""
    share_retry.queue_failed_share(graph=cfg.context_graph_id, name=name, identifier=finding["identifier"],
                                   category=finding["category"], severity=finding["severity"], subject=subject,
                                   quads=quads, error=detail)
    print(f"Share refused for now: {display_safety.term_safe(detail, 160)}")
    print("Queued for automatic retry (a newly subscribed node is refused for a few minutes). "
          "`blackbox report --status` shows it as 'retrying' until it lands.")
    return 1


def _report_finding_from_args(args: argparse.Namespace) -> tuple[Optional[dict], str]:
    """Factory: parsed report args → the finding dict the share path expects.

    Pattern: Factory function — the one creational seam of the manual path.
    Validates per-type required args (KI-025) and derives the deterministic
    identifier with the SAME quads helpers automatic detection uses, so a
    manual report and an automatic one about the same threat are
    byte-identical downstream. Returns (finding, "") or (None, error).
    """
    rtype = args.type or ""
    required = _REPORT_REQUIRED_ARGS.get(rtype)
    if required is None:
        return None, "a --type is required (or use --status / --false-positive)"
    missing = [f"--{_FLAG_NAMES.get(name, name.replace('_', '-'))}" for name in required if not getattr(args, name, None)]
    if missing:
        return None, f"--type {rtype} requires {', '.join(missing)}"
    identifier, fields, err = _REPORT_FIELDS[rtype](args)
    if err:
        return None, err
    fields = {k: v for k, v in fields.items() if v}
    try:   # the same schema the builder enforces — a bad report fails HERE, with its reason (R1)
        report_schema.validate_report(identifier=identifier, category=rtype, severity=args.severity,
                                      framework=sharing.HOST_FRAMEWORK, evidence=fields)
    except report_schema.ReportValidationError as exc:
        return None, str(exc)
    return {
        "identifier": identifier,
        "category": rtype,
        "severity": args.severity,
        "source": "custom-manual",  # never auto-shared; explicit path only
        "fields": fields,
    }, ""


def _choices(values) -> list[str]:
    return sorted(values)


#: Every `blackbox report` flag: (flags, argparse options). Data, not code, so
#: the closed vocabularies are visible in one place (Refine R1: no free text
#: leaves the machine; each choice list is the one the schema checks against).
_REPORT_FLAGS: tuple[tuple[tuple[str, ...], dict[str, Any]], ...] = (
    (("--type",), dict(choices=list(_REPORT_REQUIRED_ARGS))),
    (("--status",), dict(action="store_true", help="Show what this node has contributed, and what happened to each report")),
    (("--standing",), dict(action="store_true", help="Your standing as a reporter: counted or on probation, and co-sightings")),
    (("--false-positive",), dict(dest="false_positive", metavar="IDENTIFIER",
                                 help="Dispute a community threat (needs --reason)")),
    (("--retract",), dict(metavar="IDENTIFIER", help="Withdraw this node's own report of IDENTIFIER (final)")),
    (("--export",), dict(metavar="FILE", help="Write your statements + a reporter KEY BACKUP to FILE (JSON, 0600)")),
    (("--restore-key",), dict(dest="restore_key", metavar="FILE", help="Restore the reporter key from an export")),
    (("--erase-identity",), dict(dest="erase_identity", action="store_true",
                                 help="Destroy the reporter key and local share records (needs --confirm)")),
    (("--confirm",), dict(action="store_true", help="Confirm --erase-identity")),
    (("--ioc-type",), dict(dest="ioc_type", choices=list(threat_ids.IOC_TYPES), help="ioc: indicator type")),
    (("--value",), dict(help="ioc: the indicator value (domain/url/ip/hash/...)")),
    (("--pattern",), dict(help="injection: the pattern — hashed here, never sent")),
    (("--owasp",), dict(type=str.upper, choices=list(constants.OWASP_LLM_CATEGORIES),
                        help="injection: OWASP LLM category")),
    (("--tool",), dict(help="escalation/fileaccess: tool name")),
    (("--arg-shape",), dict(dest="arg_shape", choices=_choices(detection.ESCALATION_SHAPES),
                            help="escalation: argument shape")),
    (("--ecosystem",), dict(type=str.lower, choices=_choices(detection.DEPENDENCY_ECOSYSTEMS),
                            help="dependency: ecosystem")),
    (("--name",), dict(help="dependency: package name")),
    (("--package-version",), dict(dest="package_version", help="dependency: version, or * (KI-066/KI-276: Hermes owns --version and the name version)")),
    (("--advisory-id",), dict(dest="advisory_id", help="dependency: advisory id")),
    (("--kind",), dict(choices=[constants.KIND_MALWARE],
                       help="dependency: malware (vulnerabilities are never shared — decision 22)")),
    (("--reason",), dict(help="dependency: " + ", ".join(constants.DEPENDENCY_REASONS) + ", or advisory:<id>; "
                              "--false-positive: " + ", ".join(constants.FALSE_POSITIVE_REASONS))),
    (("--context",), dict(choices=_choices({*constants.INJECTION_CONTEXTS, *constants.IOC_CONTEXTS}),
                          help="injection/ioc: where it was seen")),
    (("--category",), dict(choices=_choices(detection.SENSITIVE_PATH_CATEGORIES),
                           help="fileaccess: sensitive-path category")),
    (("--registry",), dict(choices=list(constants.SKILL_REGISTRIES), help="skill: a named skill's public registry")),
    (("--skill-name",), dict(dest="skill_name", help="skill (from a registry): name")),
    (("--skill-version",), dict(dest="skill_version", help="skill (from a registry): known-bad version")),
    (("--artifact-hash",), dict(dest="artifact_hash", help="skill (local): sha256 of its code — never its name")),
    (("--danger-shape",), dict(dest="danger_shape", choices=_choices(detection.SKILL_DANGER_SHAPES),
                               help="skill (local): danger shape")),
    (("--severity",), dict(default="high", choices=list(constants.SEVERITY_ORDER))),
    (("--consent",), dict(action="store_true", help="read the reporter terms and record your agreement to share (R13; sharing is opt-in)")),
    (("--withdraw-consent",), dict(dest="withdraw_consent", action="store_true", help="withdraw consent: sharing stops")),
    (("--enable-sharing",), dict(dest="enable_sharing", action="store_true", help="turn community sharing on (opt-in: records your agreement to the reporter terms)")),
    (("--disable-sharing",), dict(dest="disable_sharing", action="store_true", help="turn community sharing off")),
)


#: cfg -> the compiled community store ({identifier: rule dict with stage fields}).
CompiledCommunity = Callable[[Any], dict[str, dict[str, Any]]]


def add_report_parser(sub: argparse._SubParsersAction, *, compiled_community: Optional[CompiledCommunity] = None) -> None:
    """Register ``blackbox report`` and its flags (:data:`_REPORT_FLAGS`) on
    the CLI's sub-parsers. Called once by ``cli.setup_cli``; the parsed
    namespace goes to :func:`cmd_report`. *compiled_community* is injected by
    the composition root (the ruleset depends on this package, not the other
    way round): ``--status`` prints each community threat's local stage from
    it (R3)."""
    report = sub.add_parser("report", help="Report a threat to the community / view your contributions")
    for flags, options in _REPORT_FLAGS:
        report.add_argument(*flags, **options)
    report.set_defaults(func=cmd_report, compiled_community=compiled_community)


def cmd_report(args: argparse.Namespace) -> int:
    """Manual community reporting: submit, dispute, or review contributions.

    Same gates as automatic sharing (community_enabled, identity, cooldown,
    daily cap) and the SAME share/ledger path — one implementation per
    concern. ACK is real: the command waits for the share job and prints the
    outcome + report subject (lifecycle: ACKNOWLEDGE).
    """
    cfg = load_blackbox_config()
    if args.status or getattr(args, "standing", False) or report_rights.wants_local_verb(args):   # local: nothing sent
        return _local_verb(cfg, args)
    reduction = submission_gate.is_reduction(args)
    refusal = submission_gate.refusal_for(cfg, reduction)
    if refusal is not None:
        return refusal
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    resolved = _reporting_identity(client, cfg.context_graph_id)
    if resolved is None:
        return 1
    reporter, signer = resolved
    if reduction:
        return statement_verbs.submit_statement(client, cfg, args, reporter, signer)
    finding, err = _report_finding_from_args(args)
    if finding is None:
        print(f"Invalid report: {err}")
        print("Nothing was submitted.")
        return 2
    identifier = finding["identifier"]
    if audit.recently_reported(identifier):
        print(f"Already reported within the cooldown window: {display_safety.term_safe(identifier)}")
        return 0
    if not audit.allow_report(cfg.daily_report_limit):
        print(f"Daily report cap reached ({cfg.daily_report_limit}); try again tomorrow.")
        return 2
    subject = threat_ids.report_uri(identifier, reporter)
    name = f"report-{threat_ids.stable_hash(identifier + reporter, 16)}"
    q = report_builder.build_report_quads(
        identifier=identifier,
        category=finding["category"],
        severity=finding["severity"],
        reporter_address=reporter,
        framework=sharing.HOST_FRAMEWORK,
        signer=signer,
        **finding["fields"],
    )
    outcome, detail = statement_verbs.send_and_record(client, cfg, identifier=identifier, category=finding["category"],
                                       severity=finding["severity"], subject=subject, name=name, quads=q, keep_alive=True)
    if outcome is sharing.ShareOutcome.FAILED:
        return _queue_refused_share(cfg, finding, subject=subject, name=name, quads=q, detail=detail)
    audit.mark_reported(identifier)
    if outcome is sharing.ShareOutcome.REJECTED_SAME_VERSION:
        print(f"Already shared with the community — not re-sent ({display_safety.term_safe(detail, 120)}).")
        return 0
    print("Report shared with the community.")
    print(f"  identifier: {display_safety.term_safe(identifier)}")
    print(f"  subject:    {display_safety.term_safe(subject)}")
    return 0


def _reporting_identity(client: DkgClient, graph: str) -> Optional[tuple[str, report_signer.ReportSigner]]:
    """(reporter address, signer) for a manual report, or None after telling
    the operator why nothing can be submitted (no identity, or cannot sign)."""
    reporter = identity.reporter_address(client)
    if not reporter or not reporter.startswith("0x"):
        print("No resolved node identity — refusing to report as a shared ghost identity.")
        print("Start the DKG node (or finish setup) and retry.")
        return None
    signer = report_signer.resolve_report_signer(client, graph)
    if signer is None:
        print("Cannot sign the report (the node reports no network id, or the reporter key is unusable).")
        print("Nothing was submitted — an unsigned report would not be counted by anyone.")
        return None
    return reporter, signer


#: Most community threats `report --status` lists with their stage.
_STATUS_STAGE_ROWS = 25


def _print_stages(community_rules: dict[str, dict[str, Any]]) -> None:
    """R3: every community threat's local stage and reason (counts per stage,
    then the first rows) — the compiled ruleset's view, so it is offline-safe."""
    staged = [(ident, rule) for ident, rule in community_rules.items() if rule.get("stage")]
    if not staged:
        return
    by_stage: dict[str, int] = {}
    for _ident, rule in staged:
        by_stage[str(rule["stage"])] = by_stage.get(str(rule["stage"]), 0) + 1
    print("Community threats by local stage: " + ", ".join(f"{s} {n}" for s, n in sorted(by_stage.items())))
    for ident, rule in staged[:_STATUS_STAGE_ROWS]:
        print(f"  [{display_safety.term_safe(rule['stage'], 12)} · {display_safety.term_safe(rule.get('enforcement'), 8)}]  "
              f"{display_safety.term_safe(ident, 80)}  — {display_safety.term_safe(rule.get('stageReason'), 110)}")
    if len(staged) > _STATUS_STAGE_ROWS:
        print(f"  … and {len(staged) - _STATUS_STAGE_ROWS} more (the dashboard lists them all).")


def _local_verb(cfg, args: argparse.Namespace) -> int:
    """``--status``, or one of the identity-rights verbs: no node, nothing sent."""
    if args.status:
        return _report_status(cfg, getattr(args, "compiled_community", None))
    if getattr(args, "standing", False):
        return report_tracking.report_standing(cfg)
    return report_rights.run_local_verb(args)


def _report_status(cfg, compiled_community: Optional[CompiledCommunity] = None) -> int:
    """Lifecycle TRACK: the ledger first (offline-safe), Q9 when reachable,
    then every community threat's local stage (R3) from the compiled store."""
    rows = audit.read_share_ledger(limit=50)
    compiled = compiled_community(cfg) if compiled_community is not None else {}
    if not rows:
        print("No community reports from this node yet.")
    else:
        print(f"Community contributions from this node (newest first, {len(rows)} shown):")
        for row in rows:
            print("  " + report_tracking.outcome_line(row, compiled))
    if cfg.context_graph_id:
        try:
            client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
            store = reporter_key.ReporterKeyStore()
            own_author = store.public_key_hex() if store.path.exists() else ""
            read = graph_reader.read_verified_reports(client, cfg)
            if not read.available:
                print(f"Community reports unavailable right now: {display_safety.term_safe(read.reason, 160)}")
            elif own_author:
                # R0d: count what THIS node's key signed and the graph verified —
                # never rows that merely claim our address.
                count = graph_stats.reports_signed_by(read.reports, own_author)
                print(f"In the community's shared memory: {count} verified report(s) signed by this node.")
            if compiled_community is not None:
                _print_stages(compiled_community(cfg))
        except Exception as exc:
            logger.debug("blackbox: report --status graph read failed: %s", exc)
    return 0
