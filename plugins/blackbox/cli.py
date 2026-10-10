"""The ``blackbox`` command — argument parsing and dispatch only.

:func:`setup_cli` builds the sub-commands and wires each to its feature
package's handler (``chat``, ``sync``, ``attach``, ``community``, ``dashboard``,
``detection``); ``status`` lives here because it summarizes all of them. No
feature logic belongs in this file.

Usage (Hermes registers it): ``ctx.register_cli_command("blackbox", ..., setup_cli)``.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any
import time
from . import attach, audit, community, ruleset
from .kernel import health
from .kernel import yaml_files
from .kernel.config import load_blackbox_config
from .kernel.dkg_client import DkgClient, DkgError
from .attach import cmd_attach, cmd_detach
from .chat import add_blackbox_chat_args, cmd_chat
from .community import add_report_parser, print_community_status
from .curate import add_curate_parser
from .dashboard import cmd_dashboard
from .detection import cmd_setup_llm
from .overrides import add_rules_parser
from .sync import cmd_sync

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Build the ``hermes blackbox`` subparser tree."""
    parser.set_defaults(func=cmd_chat)
    sub = parser.add_subparsers(dest="blackbox_command")

    chat = sub.add_parser(
        "chat",
        help="Start a Blackbox-named Hermes chat in the dedicated blackbox profile",
        description=(
            "Create/update the dedicated Blackbox profile, then launch normal "
            "Hermes chat through that profile. Extra args are passed to "
            "`hermes --profile blackbox chat`; bare text becomes `--query`."
        ),
    )
    add_blackbox_chat_args(chat)
    chat.set_defaults(func=cmd_chat)

    sub.add_parser("status", help="Show config, node reachability, ruleset + findings counts").set_defaults(func=_cmd_status)
    add_rules_parser(sub)   # R7b: local overrides (unblock / reblock / list)
    sync = sub.add_parser("sync", help="Force a ruleset refresh from the DKG node")
    sync.add_argument(
        "--wait",
        action="store_true",
        help="Wait for DKG catch-up before refreshing the Blackbox cache",
    )
    sync.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Seconds to wait for complete curator catch-up with --wait (default: 3600)",
    )
    sync.add_argument(
        "--require-rules",
        action="store_true",
        help="Return non-zero if the refreshed ruleset is empty (used by installers)",
    )
    sync.set_defaults(func=cmd_sync)

    attach_p = sub.add_parser(
        "attach", help="Auto-protect every local Hermes home + OpenClaw workspace"
    )
    attach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    attach_p.add_argument("--hermes-only", action="store_true", help="Only attach to Hermes homes")
    attach_p.add_argument("--openclaw-only", action="store_true", help="Only attach to OpenClaw workspaces")
    attach_p.set_defaults(func=cmd_attach)

    detach_p = sub.add_parser("detach", help="Disable Blackbox in every local agent")
    detach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    detach_p.add_argument("--remove-files", action="store_true", help="Also delete copied plugin files")
    detach_p.add_argument("--hermes-only", action="store_true", help="Only detach from Hermes homes")
    detach_p.add_argument("--openclaw-only", action="store_true", help="Only detach from OpenClaw workspaces")
    detach_p.set_defaults(func=cmd_detach)

    add_report_parser(sub, compiled_community=lambda cfg: ruleset.peek(cfg).community)
    add_curate_parser(sub, compiled_ruleset=lambda cfg: ruleset.peek(cfg))
    dash = sub.add_parser("dashboard", help="Start the local Blackbox dashboard")
    dash.add_argument("--port", type=int, help="Override dashboard port")
    dash.set_defaults(func=cmd_dashboard)

    setup_llm = sub.add_parser(
        "setup-llm", help="Configure the optional LLM prompt-injection reviewer (provider/model/key)"
    )
    setup_llm.add_argument("--provider", choices=["openai", "anthropic"], help="Skip the prompt: set provider")
    setup_llm.add_argument("--model", help="Skip the prompt: set model id (default: provider's recommended)")
    setup_llm.add_argument(
        "--key-source", choices=["hermes", "openclaw", "new"], help="Where to copy the API key from"
    )
    setup_llm.add_argument("--api-key", help="Skip the prompt: use this API key (with --key-source new)")
    setup_llm.add_argument(
        "--auto",
        action="store_true",
        help="Reuse existing Blackbox, Hermes, or OpenClaw model credentials without prompting",
    )
    setup_llm.add_argument(
        "--configure",
        action="store_true",
        help="Prompt for provider, API key, and model even when reusable config exists",
    )
    setup_llm.add_argument("--disable", action="store_true", help="Turn the LLM reviewer off and exit")
    setup_llm.set_defaults(func=cmd_setup_llm)


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    reachable = client.reachable()
    try:
        rs = ruleset.get(cfg)
        counts = rs.counts()
    except DkgError as exc:
        print(f"Graph protection unavailable: {exc}")
        return 2
    print("Agent Blackbox")
    if getattr(cfg, 'detection_backend', 'legacy-cache') == "dkg":
        print("  protection source: live local graph queries (no ruleset export)")
        print("  counts below:      confirmed graph entities; not a full-coverage proof")
    print(f"  mode:              {cfg.mode}")
    print(f"  block severity:    {cfg.block_severity}")
    print(f"  context graph:     {cfg.context_graph_id}")
    print(f"  DKG node:          {cfg.dkg_url}  [{'reachable' if reachable else 'unreachable'}]")
    print(f"  DKG home:          {cfg.dkg_home}")
    print(f"  DKG CLI:           {cfg.dkg_bin}")
    print_community_status(cfg)
    print(f"  sync interval:     {cfg.sync_interval}s")
    synced_at = getattr(rs, "synced_at", 0)
    print(f"  ruleset age:       {health.ruleset_age_text((time.time() - synced_at) if synced_at else None)}")
    if getattr(rs, "community_paused", False):
        print("  community ingest:  PAUSED by the curator")
    if getattr(rs, "curator_manifest_state", ""):
        print(f"  curator keys:      {rs.curator_manifest_state}")
    _print_health(cfg, rs, client, reachable)
    print(f"  ruleset:           {counts['injection']} injection, "
          f"{counts['escalation']} escalation, {counts['dependency']} dependency, "
          f"{counts['fileaccess']} fileaccess, {counts['skill']} skill, {counts['ioc']} ioc")
    if getattr(cfg, 'detection_backend', 'legacy-cache') != "dkg":
        _print_verified_progress(cfg)
    if not any(counts.values()):
        # KI-023: an empty ruleset is a LOUD state, never a quiet day.
        print("  !! UNPROTECTED:    threat ruleset is EMPTY — detection has no rules.")
        print("                     Run 'hermes blackbox sync --wait' to load the threat graph.")
    print(f"  findings logged:   {audit.count_findings()}")
    print(f"  dashboard:         http://127.0.0.1:{cfg.dashboard_port}")
    _print_attached_targets()
    return 0


def _print_verified_progress(cfg: Any) -> None:
    """KI-290: rules that cover only part of the verified graph must look partial."""
    done = ruleset.verified_progress(cfg.context_graph_id)
    if not done or not done.get("assets_total"):
        return
    line = f"  verified graph:    {done['assets_compiled']} of {done['assets_total']} assets compiled into rules"
    if done.get("stopped_early"):
        line += f" ({done['stopped_early']})"
    print(line)


def _print_health(cfg: Any, rs: Any, client: DkgClient, reachable: bool) -> None:
    """R10: the shared operator health items (the dashboard banner shows the same)."""
    read = None
    if reachable and cfg.community_graph_id:
        try:
            read = community.read_verified_reports(client, cfg)
        except Exception as exc:  # pragma: no cover - status must never crash on the node
            logger.debug("blackbox status: community read skipped: %s", exc)
    retries = community.share_retry_stats()
    items = health.operator_health(health.gather(cfg, rs, reachable, read, audit.blocked_counts_by_identifier(), time.time(),
                                                 pending_shares=retries.pending, shares_given_up=retries.given_up,
                                                 sharing_consent_problem=community.consent.why_not()))
    if cfg.community_graph_id:   # who curates, who is trusted, what is confirmed (the dashboard's trust panel shows the same)
        for line in community.trust_status_lines(community.trust_panel(read)):
            print(line)
    for line in health.render_lines(items):
        print(line)


def _print_attached_targets() -> None:
    """List which local Hermes homes / OpenClaw workspaces have Blackbox attached."""
    attached_hermes = []
    for home in attach.discover_hermes_homes():
        try:
            data = yaml_files.load_yaml(home / "config.yaml")
            if attach.enabled_list_has(data, "blackbox"):
                attached_hermes.append(str(home))
        except Exception:
            continue
    attached_openclaw = []
    for ws in attach.discover_openclaw_workspaces():
        try:
            import json as _json

            cfg_path = ws / "openclaw.json"
            data = _json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
            allow = ((data.get("plugins") or {}).get("allow")) if isinstance(data, dict) else None
            if isinstance(allow, list) and "blackbox" in allow:
                attached_openclaw.append(str(ws))
        except Exception:
            continue
    print(f"  attached (hermes): {len(attached_hermes)}")
    for path in attached_hermes:
        print(f"      - {path}")
    print(f"  attached (openclaw): {len(attached_openclaw)}")
    for path in attached_openclaw:
        print(f"      - {path}")
