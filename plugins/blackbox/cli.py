"""``hermes blackbox <sub>`` CLI.

Subcommands cover chat, status, sync, attachment, reporting, the dashboard,
and optional LLM review setup. Network reads fail open with a friendly message.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import logging
import os
import psutil
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from . import attach, audit, constants, llm, quads, ruleset, settings, sync_state
from .config import BlackboxConfig, load_blackbox_config
from .dkg_client import DkgClient, DkgError
from .dkg_progress import capture_durable_progress_cursor, read_durable_progress

logger = logging.getLogger(__name__)

_DKG_STEADY_SYNC_SETTINGS = {
    "DKG_SYNC_ON_CONNECT_ENABLED": "1",
    "DKG_SYNC_RECONCILER_ENABLED": "1",
    "DKG_DURABLE_SYNC_ENABLED": "1",
    "DKG_SYNC_GLOBAL_MAX_INFLIGHT": "1",
    "DKG_SYNC_GLOBAL_QUEUE_LIMIT": "0",
}

_BLACKBOX_CHAT_PROFILE = "agent-blackbox"
_BLACKBOX_SOUL_MARKER = "<!-- managed-by: hermes-blackbox-chat -->"
_LEGACY_MANAGED_SOUL_PREFIX = "<!-- managed-by: hermes-"
_BLACKBOX_SOURCE_ROOT_MARKER = ".blackbox-source-root"
_BLACKBOX_CONTEXT_FILE_MAX_CHARS = 100_000
_MAX_EMPTY_PUBLIC_PASSES = 3
_BLACKBOX_SOUL = f"""{_BLACKBOX_SOUL_MARKER}
# Agent Blackbox

You are Agent Blackbox. When asked who you are, answer as Agent Blackbox
rather than any inherited or legacy identity.

Your job is to help users work with Agent Blackbox: setup, local agent
attachment, audit/block mode, threat detection, dashboard behavior, and DKG
threat-graph workflows. Be direct, technical, and verify claims against real
Blackbox state before answering — NEVER answer threat-graph or detection
questions from general knowledge. If asked "what's in the public/community/local
graph", "what threats do we know", "recent activity", "connected agents", etc.,
you MUST fetch the real data from the sources below and answer from that.

## Graph scope
- **Public** (on-chain, verifiable memory): the Umanitek-curated threat graph.
  Confirmed threats that BLOCK in block mode. Field name in APIs: `curated`.
- **Community** (shared working memory / SWM): coming soon. It is not queried,
  matched, joined, or written in this release. Findings stay local.
- **Local** (this node's working memory + synced ruleset): what THIS node has
  pulled down and what it detects with offline. Field name: `ruleset`.

## Where to get each kind of data
Prefer the running dashboard API on http://127.0.0.1:9700 (all read-only, JSON):

- `GET /api/graph-status` — counts + config. Returns `mode`, `context_graph_id`,
  `dkg_url`, `node_reachable`, `last_sync`, `ruleset` (per-category local counts),
  `curated` (Public tier count), `community` (always 0 / coming soon),
  `sightings`, `findings_logged`.
- `GET /api/graph?tier=public|local` — the actual threat ENTRIES for a
  tier. Returns `{{tier, threats:[{{identifier, category, severity, name}}]}}`.
  Use this to list what's in the public/community/local graph.
- `GET /api/threat?tier=public&identifier=<id>` — full detail for one
  threat (description, references/advisories, reporters).
- `GET /api/findings?limit=&offset=` — threats Blackbox has flagged on this
  machine (newest first) with total.
- `GET /api/audit?limit=&offset=` — the full agent-activity feed (session
  lifecycle, API requests, tool calls with the real command, installs, flags).
- `GET /api/agents` — connected/protected local agents. Count the `agents` array
  EXACTLY; never estimate from generic Hermes status or sessions.
- `GET /api/reports` — returns the community-feature coming-soon state.

If the dashboard is NOT running (curl to :9700 fails), fall back to:
- `hermes blackbox status` — mode, node reachability, ruleset + findings counts.
- `hermes blackbox sync` — force a ruleset refresh from the DKG node first.
- Read the local state files directly under `$BLACKBOX_HOME` (usually
  `~/.hermes/blackbox/`): `ruleset.json` (synced threats by category, the local
  graph), `findings.jsonl` (every flag), `audit.jsonl` (activity),
  `dependencies.jsonl`, `file_access.jsonl`.

## Rules
- The endpoint is `/api/graph` (NOT `/api/threat-graph` — that does not exist).
- When the graph tiers read 0 but `ruleset` is non-zero, the DKG node/graph is
  unreachable for live queries while the local synced ruleset still works — say
  that explicitly rather than claiming the graph is empty.
- Quote real numbers and identifiers from the fetched JSON; don't paraphrase or
  invent entries.
- Before naming any threat, fetch it from an API or local state file in the
  current turn. If the lookup fails, say the data is unavailable; never fill
  the gap with remembered, illustrative, or example indicators.
"""


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Build the ``hermes blackbox`` subparser tree."""
    parser.set_defaults(func=_cmd_chat)
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
    _add_blackbox_chat_args(chat)
    chat.set_defaults(func=_cmd_chat)

    sub.add_parser("status", help="Show config, node reachability, ruleset + findings counts").set_defaults(
        func=_cmd_status
    )
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
    sync.set_defaults(func=_cmd_sync)

    attach_p = sub.add_parser(
        "attach", help="Auto-protect every local Hermes home + OpenClaw workspace"
    )
    attach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    attach_p.add_argument("--hermes-only", action="store_true", help="Only attach to Hermes homes")
    attach_p.add_argument("--openclaw-only", action="store_true", help="Only attach to OpenClaw workspaces")
    attach_p.set_defaults(func=_cmd_attach)

    detach_p = sub.add_parser("detach", help="Disable Blackbox in every local agent")
    detach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    detach_p.add_argument("--remove-files", action="store_true", help="Also delete copied plugin files")
    detach_p.add_argument("--hermes-only", action="store_true", help="Only detach from Hermes homes")
    detach_p.add_argument("--openclaw-only", action="store_true", help="Only detach from OpenClaw workspaces")
    detach_p.set_defaults(func=_cmd_detach)

    report = sub.add_parser("report", help="Community threat sharing (coming soon; submits nothing)")
    report.add_argument(
        "--type", required=True,
        choices=["injection", "escalation", "dependency", "fileaccess", "skill"],
    )
    report.add_argument("--pattern", help="injection: regex source")
    report.add_argument("--owasp", help="injection: OWASP category (e.g. LLM01)")
    report.add_argument("--tool", help="escalation/fileaccess: tool name")
    report.add_argument("--arg-shape", dest="arg_shape", help="escalation: arg shape slug")
    report.add_argument("--ecosystem", help="dependency: ecosystem (npm/pypi/...)")
    report.add_argument("--name", help="dependency: package name (or threat display name)")
    report.add_argument("--version", help="dependency: package version")
    report.add_argument("--advisory-id", dest="advisory_id", help="dependency: advisory id")
    report.add_argument(
        "--kind", choices=[constants.KIND_MALWARE, constants.KIND_VULNERABILITY],
        help="dependency: malware (blocks) or vulnerability (flags only)",
    )
    report.add_argument("--category", help="fileaccess: sensitive-path category (e.g. ssh-private-key)")
    report.add_argument("--skill-name", dest="skill_name", help="skill: skill name")
    report.add_argument("--skill-version", dest="skill_version", help="skill: known-bad version")
    report.add_argument("--danger-shape", dest="danger_shape", help="skill: danger shape slug (e.g. shell-exec)")
    report.add_argument("--severity", default="high", choices=list(constants.SEVERITY_ORDER))
    report.add_argument("--description", default="", help="Human-readable description")
    report.set_defaults(func=_cmd_report)

    dash = sub.add_parser("dashboard", help="Start the local Blackbox dashboard")
    dash.add_argument("--port", type=int, help="Override dashboard port")
    dash.set_defaults(func=_cmd_dashboard)

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
    setup_llm.set_defaults(func=_cmd_setup_llm)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _add_blackbox_chat_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("prompt", nargs="*", help='Bare prompt text, e.g. "who are you?"')
    parser.add_argument("-q", "--query", help="Single query (non-interactive mode)")
    parser.add_argument("--image", help="Optional local image path to attach to a single query")
    parser.add_argument("-m", "--model", help="Model to use")
    parser.add_argument("--provider", help="Inference provider")
    parser.add_argument("-t", "--toolsets", help="Comma-separated toolsets to enable")
    parser.add_argument("-s", "--skills", action="append", help="Preload one or more skills")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-Q", "--quiet", action="store_true", help="Suppress banner/spinner/tool previews")
    parser.add_argument("--resume", "-r", metavar="SESSION_ID", help="Resume a previous session by ID")
    parser.add_argument(
        "--continue",
        "-c",
        dest="continue_last",
        nargs="?",
        const=True,
        metavar="SESSION_NAME",
        help="Resume a session by name, or the most recent if no name given",
    )
    parser.add_argument("--worktree", "-w", action="store_true", help="Run in an isolated git worktree")
    parser.add_argument("--accept-hooks", action="store_true", help="Auto-approve unseen shell hooks")
    parser.add_argument("--checkpoints", action="store_true", help="Enable filesystem checkpoints")
    parser.add_argument("--max-turns", type=int, metavar="N", help="Maximum tool-calling iterations")
    parser.add_argument("--yolo", action="store_true", help="Bypass dangerous command approval prompts")
    parser.add_argument("--pass-session-id", action="store_true", help="Include session ID in the system prompt")
    parser.add_argument("--ignore-user-config", action="store_true", help="Ignore config.yaml")
    parser.add_argument("--ignore-rules", action="store_true", help="Skip AGENTS.md/SOUL.md/rules injection")
    parser.add_argument("--safe-mode", action="store_true", help="Disable all customizations")
    parser.add_argument("--tui", action="store_true", help="Launch the modern TUI")
    parser.add_argument("--cli", action="store_true", help="Force the classic prompt_toolkit REPL")
    parser.add_argument("--dev", dest="tui_dev", action="store_true", help="With --tui: run TypeScript sources")


def _cmd_chat(args: argparse.Namespace) -> int:
    profile = _ensure_blackbox_chat_profile()
    argv = _blackbox_chat_argv(_blackbox_chat_args(args), profile=profile)
    cwd = _blackbox_chat_cwd()
    if cwd is not None:
        os.chdir(cwd)
    env = dict(os.environ)
    env.pop("HERMES_HOME", None)
    env["HERMES_BLACKBOX_CHAT"] = "1"
    os.execvpe(argv[0], argv, env)
    return 1


def _ensure_blackbox_chat_profile(profile: str = _BLACKBOX_CHAT_PROFILE) -> str:
    from hermes_cli.profiles import create_profile, get_profile_dir, profile_exists

    if not profile_exists(profile):
        create_profile(
            profile,
            clone_config=True,
            no_alias=True,
            description="Agent Blackbox chat profile",
        )
    profile_dir = get_profile_dir(profile)
    _write_blackbox_soul(profile_dir)
    _ensure_blackbox_context_cap(profile_dir)
    attach.attach_hermes(profile_dir)
    return profile


def _blackbox_chat_args(args: argparse.Namespace) -> List[str]:
    out: List[str] = []
    for attr, flag in [
        ("query", "--query"),
        ("image", "--image"),
        ("model", "--model"),
        ("provider", "--provider"),
        ("toolsets", "--toolsets"),
        ("resume", "--resume"),
        ("max_turns", "--max-turns"),
    ]:
        value = getattr(args, attr, None)
        if value is not None:
            out.extend([flag, str(value)])
    for skill in getattr(args, "skills", None) or []:
        out.extend(["--skills", skill])
    continue_last = getattr(args, "continue_last", None)
    if continue_last is True:
        out.append("--continue")
    elif continue_last:
        out.extend(["--continue", str(continue_last)])
    for attr, flag in [
        ("verbose", "--verbose"),
        ("quiet", "--quiet"),
        ("worktree", "--worktree"),
        ("accept_hooks", "--accept-hooks"),
        ("checkpoints", "--checkpoints"),
        ("yolo", "--yolo"),
        ("pass_session_id", "--pass-session-id"),
        ("ignore_user_config", "--ignore-user-config"),
        ("ignore_rules", "--ignore-rules"),
        ("safe_mode", "--safe-mode"),
        ("tui", "--tui"),
        ("cli", "--cli"),
        ("tui_dev", "--dev"),
    ]:
        if getattr(args, attr, False):
            out.append(flag)
    prompt = getattr(args, "prompt", None) or []
    if prompt and not getattr(args, "query", None):
        out.extend(["--query", " ".join(prompt)])
    return out


def _blackbox_chat_cwd() -> Optional[Path]:
    candidates: List[Path] = []
    marker = Path(__file__).resolve().parent / _BLACKBOX_SOURCE_ROOT_MARKER
    try:
        if marker.exists():
            marked = Path(marker.read_text(encoding="utf-8").strip()).expanduser()
            candidates.append(marked)
    except Exception:
        pass
    try:
        candidates.append(attach._repo_root())
    except Exception:
        pass
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            continue
        if (resolved / "plugins" / "blackbox" / "cli.py").exists():
            return resolved
    return None


def _write_blackbox_soul(profile_dir: Path) -> None:
    soul_path = profile_dir / "SOUL.md"
    existing = ""
    if soul_path.exists():
        try:
            existing = soul_path.read_text(encoding="utf-8")
        except OSError:
            existing = ""
    if existing == _BLACKBOX_SOUL:
        return
    legacy_identity = (
        _LEGACY_MANAGED_SOUL_PREFIX in existing
        and _BLACKBOX_SOUL_MARKER not in existing
    )
    if existing and _BLACKBOX_SOUL_MARKER not in existing and not legacy_identity:
        backup = profile_dir / "SOUL.md.before-blackbox-chat"
        if not backup.exists():
            try:
                backup.write_text(existing, encoding="utf-8")
            except OSError:
                pass
    soul_path.write_text(_BLACKBOX_SOUL, encoding="utf-8")


def _ensure_blackbox_context_cap(profile_dir: Path) -> None:
    config_path = profile_dir / "config.yaml"
    if attach.yaml is None:
        if not config_path.exists():
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                f"context_file_max_chars: {_BLACKBOX_CONTEXT_FILE_MAX_CHARS}\n",
                encoding="utf-8",
            )
        return
    data = attach._load_yaml(config_path)
    current = data.get("context_file_max_chars")
    if isinstance(current, int) and current >= _BLACKBOX_CONTEXT_FILE_MAX_CHARS:
        return
    data["context_file_max_chars"] = _BLACKBOX_CONTEXT_FILE_MAX_CHARS
    attach._dump_yaml(config_path, data)


def _blackbox_chat_argv(chat_args: Optional[List[str]], profile: str = _BLACKBOX_CHAT_PROFILE) -> List[str]:
    args = [a for a in (chat_args or []) if a != "--"]
    argv = [sys.argv[0] or "hermes", "--profile", profile, "chat"]
    if args and not args[0].startswith("-"):
        argv.extend(["--query", " ".join(args)])
    else:
        argv.extend(args)
    return argv


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    reachable = client.reachable()
    rs = ruleset.get(cfg)
    counts = rs.counts()
    print("Agent Blackbox")
    print(f"  mode:              {cfg.mode}")
    print(f"  block severity:    {cfg.block_severity}")
    print(f"  context graph:     {cfg.context_graph_id}")
    print(f"  DKG node:          {cfg.dkg_url}  [{'reachable' if reachable else 'unreachable'}]")
    print(f"  DKG home:          {cfg.dkg_home}")
    print(f"  DKG CLI:           {cfg.dkg_bin}")
    print("  threat sharing:    off (Community graph coming soon)")
    print(f"  sync interval:     {cfg.sync_interval}s")
    print(f"  ruleset:           {counts['injection']} injection, "
          f"{counts['escalation']} escalation, {counts['dependency']} dependency, "
          f"{counts['fileaccess']} fileaccess, {counts['skill']} skill")
    print(f"  findings logged:   {audit.count_findings()}")
    print(f"  dashboard:         http://127.0.0.1:{cfg.dashboard_port}")
    _print_attached_targets()
    return 0


def _print_attached_targets() -> None:
    """List which local Hermes homes / OpenClaw workspaces have Blackbox attached."""
    attached_hermes = []
    for home in attach.discover_hermes_homes():
        try:
            data = attach._load_yaml(home / "config.yaml")
            if attach._enabled_list_has(data, "blackbox"):
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


def _cmd_sync(args: argparse.Namespace) -> int:
    """Run a ruleset sync, translating an interactive cancellation cleanly."""
    try:
        cfg = load_blackbox_config()
        if _uses_managed_dkg(cfg, args):
            return _cmd_sync_with_managed_dkg(cfg, args)
        if getattr(args, "wait", False):
            with _managed_sync_lock() as acquired:
                if not acquired:
                    print("Blackbox sync is already running; no second transfer was queued.")
                    return 2 if getattr(args, "require_rules", False) else 0
                return _cmd_sync_impl(args)
        return _cmd_sync_impl(args)
    except KeyboardInterrupt:
        try:
            current_transfer = sync_state.read()
            try:
                owns_transfer = int(current_transfer.get("pid") or 0) == os.getpid()
            except (TypeError, ValueError):
                owns_transfer = False
            if current_transfer.get("status") == "running" and owns_transfer:
                sync_state.write(
                    "cancelled",
                    context_graph_id=current_transfer.get("context_graph_id"),
                    graph_peer_id=current_transfer.get("graph_peer_id"),
                    phase=str(current_transfer.get("phase") or "cancelled"),
                    public_entries=int(current_transfer.get("public_entries") or 0),
                    expected_public_entries=int(
                        current_transfer.get("expected_public_entries") or 0
                    ),
                    community_entries=int(current_transfer.get("community_entries") or 0),
                    error="sync cancelled by user",
                )
        except Exception as exc:  # cancellation must never print a traceback
            logger.debug("blackbox: failed to record sync cancellation: %s", exc)
        print("Blackbox sync cancelled.", file=sys.stderr)
        return 130


def _uses_managed_dkg(cfg: BlackboxConfig, args: argparse.Namespace) -> bool:
    """Return whether this is a blocking sync for Blackbox's managed DKG."""
    return bool(
        getattr(args, "wait", False)
        and cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
        and cfg.graph_peer_id
        and Path(cfg.dkg_bin).is_file()
        and Path(cfg.dkg_home).is_dir()
    )


@contextmanager
def _managed_sync_lock():
    """Hold the one cross-process slot used by dashboard and manual syncs."""
    path = constants.blackbox_home() / "sync-window.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    acquired = False
    try:
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt

            if path.stat().st_size == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                pass
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                pass
        yield acquired
    finally:
        if acquired:
            if os.name == "nt":  # pragma: no cover - exercised on Windows
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _dkg_sync_environment(cfg: BlackboxConfig) -> Dict[str, str]:
    env = os.environ.copy()
    env.update(_DKG_STEADY_SYNC_SETTINGS)
    env["DKG_HOME"] = str(cfg.dkg_home)
    env.setdefault("DKG_CATCHUP_MAX_CONCURRENT_PEERS", "1")
    env.setdefault("DKG_STORE_QUEUE_WAIT_TIMEOUT_MS", "300000")
    env.setdefault("DKG_SYNC_TOTAL_TIMEOUT_MS", "1800000")
    env.setdefault("DKG_SWM_RECOVERY_TIMEOUT_MS", "3600000")
    # Native DKG dependencies are tied to the Node ABI used at installation.
    # A dashboard launched from another runtime can have a different ``node``
    # first on PATH, so preserve the executable of the currently managed node.
    node_executable = _managed_dkg_node_executable(cfg)
    if node_executable is not None:
        env["PATH"] = str(node_executable.parent) + os.pathsep + env.get("PATH", "")
    return env


def _managed_dkg_node_executable(cfg: BlackboxConfig) -> Optional[Path]:
    """Find the Node executable whose ABI matches the installed DKG runtime."""
    candidates: List[Path] = []

    def _candidate(value: object) -> None:
        if value:
            path = Path(str(value)).expanduser()
            if path not in candidates:
                candidates.append(path)

    try:
        pid = int((Path(cfg.dkg_home) / "daemon.pid").read_text(encoding="utf-8").strip())
        _candidate(psutil.Process(pid).exe())
    except (OSError, TypeError, ValueError, psutil.Error):
        pass

    # Recent DKG supervisors do not always retain daemon.pid. Locate only a
    # process running this exact installation, never an unrelated DKG node.
    try:
        dkg_cli = str(Path(cfg.dkg_bin).resolve())
        for process in psutil.process_iter(["exe", "cmdline"]):
            try:
                command = [str(item) for item in (process.info.get("cmdline") or [])]
                if dkg_cli not in command:
                    continue
                if not any(item in {"daemon-supervisor", "daemon-worker"} for item in command):
                    continue
                _candidate(process.info.get("exe") or process.exe())
            except (OSError, TypeError, ValueError, psutil.Error):
                continue
    except (OSError, psutil.Error):
        pass

    marker = Path(cfg.dkg_home) / ".blackbox-node-path"
    try:
        _candidate(marker.read_text(encoding="utf-8").strip())
    except OSError:
        pass
    nvm_bin = os.environ.get("NVM_BIN")
    if nvm_bin:
        _candidate(Path(nvm_bin) / ("node.exe" if os.name == "nt" else "node"))
    _candidate(shutil.which("node"))

    for executable in candidates:
        if not executable.is_file() or not _node_runtime_matches_dkg(executable, cfg):
            continue
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            tmp = marker.with_suffix(f".tmp-{os.getpid()}")
            tmp.write_text(str(executable.resolve()) + "\n", encoding="utf-8")
            os.replace(tmp, marker)
        except OSError:
            pass
        return executable
    return None


def _node_runtime_matches_dkg(executable: Path, cfg: BlackboxConfig) -> bool:
    """Load the installed native SQLite binding before trusting a Node path."""
    dkg_bin = Path(cfg.dkg_bin).expanduser()
    native_package = dkg_bin.parent.parent / "better-sqlite3"
    if not native_package.is_dir():
        return False
    probe = (
        "const DB=require(process.argv[1]);"
        "const db=new DB(':memory:');db.close();"
    )
    try:
        result = subprocess.run(
            [str(executable), "-e", probe, str(native_package)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _set_persisted_dkg_steady_state(cfg: BlackboxConfig) -> bool:
    """Persist bounded native reconciliation and report whether it changed."""
    path = Path(cfg.dkg_home) / "config.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    original = json.dumps(data, sort_keys=True)
    data.update(
        {
            "syncOnConnectEnabled": True,
            "syncReconcilerEnabled": True,
            "durableSyncEnabled": True,
            "syncGlobalMaxInflight": 1,
            "syncGlobalQueueLimit": 0,
            "syncSharedMemoryOnConnect": False,
        }
    )
    if original == json.dumps(data, sort_keys=True):
        return False
    tmp = path.with_suffix(f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return True


def _restart_managed_dkg(cfg: BlackboxConfig) -> None:
    """Restart the managed node with bounded native reconciliation enabled."""
    env = _dkg_sync_environment(cfg)
    command = str(cfg.dkg_bin)
    old_pid: Optional[int] = None
    try:
        old_pid = int(
            (Path(cfg.dkg_home) / "daemon.pid")
            .read_text(encoding="utf-8")
            .strip()
        )
    except (OSError, TypeError, ValueError):
        pass
    try:
        subprocess.run(
            [command, "stop"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        # ``dkg stop`` can return after its ten-second API wait while the
        # worker is still draining sync jobs. Starting immediately then sees
        # the old PID and refuses with "Daemon already running". Wait for the
        # exact managed worker and API listener to disappear first.
        stopped = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
        stop_deadline = time.monotonic() + 45
        while time.monotonic() < stop_deadline:
            pid_running = False
            if old_pid is not None:
                try:
                    process = psutil.Process(old_pid)
                    command_line = [str(item) for item in process.cmdline()]
                    pid_running = process.is_running() and any(
                        item in {"daemon-worker", "daemon-supervisor"}
                        for item in command_line
                    )
                except (OSError, psutil.Error):
                    pid_running = False
            if not pid_running and not stopped.reachable(timeout=0.5):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("managed DKG node did not finish stopping")

        # A forced worker exit can leave its PID file behind. Remove it only
        # after proving that exact managed process is no longer alive.
        if old_pid is not None:
            try:
                process = psutil.Process(old_pid)
                command_line = [str(item) for item in process.cmdline()]
                still_managed = process.is_running() and any(
                    item in {"daemon-worker", "daemon-supervisor"}
                    for item in command_line
                )
            except (OSError, psutil.Error):
                still_managed = False
            if not still_managed:
                try:
                    (Path(cfg.dkg_home) / "daemon.pid").unlink()
                except FileNotFoundError:
                    pass

        started = subprocess.run(
            [command, "start"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"could not restart the managed DKG node: {exc}") from exc

    if started.returncode != 0:
        detail = (started.stderr or started.stdout or "").strip()
        raise RuntimeError(
            "could not start the managed DKG node"
            + (f": {detail[-500:]}" if detail else "")
        )

    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            client.status(timeout=2)
            return
        except DkgError:
            time.sleep(1)
    detail = (started.stderr or started.stdout or "").strip()
    raise RuntimeError(
        "managed DKG node did not become ready"
        + (f": {detail[-500:]}" if detail else "")
    )


def _terminal_sync_details(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in state.items()
        if key not in {"status", "started_at", "updated_at", "pid"}
    }


def _last_sync_counts(context_graph_id: str = "") -> tuple[int, int]:
    previous = (
        sync_state.read_for_graph(context_graph_id)
        if context_graph_id
        else sync_state.read()
    )
    try:
        public = max(0, int(previous.get("public_entries") or 0))
    except (TypeError, ValueError):
        public = 0
    try:
        community = max(0, int(previous.get("community_entries") or 0))
    except (TypeError, ValueError):
        community = 0
    return public, community


def _complete_local_release_ruleset(
    cfg: BlackboxConfig,
    client: DkgClient,
) -> Optional[ruleset.Ruleset]:
    """Return a fully verified local release snapshot, if already present.

    The DKG source-pinned endpoint can lack an idempotent EOF marker after its
    checkpoint is cleaned up. Check the release's raw VM floor first, then
    rebuild from explicitly confirmed assertion graphs. Both conditions must
    hold, so tentative or legacy Defender-only data cannot bypass recovery.
    """
    try:
        verified_threats = client.threat_count(cfg.context_graph_id)
    except (DkgError, AttributeError, TypeError, ValueError):
        return None
    if verified_threats < constants.DEFAULT_GRAPH_RELEASE_THREAT_FLOOR:
        return None
    try:
        local_rules = ruleset.refresh(cfg, client, force_query=True)
    except ruleset.RulesetRefreshUnavailable:
        return None
    if (
        _ruleset_graph_count(local_rules, "public")
        < constants.DEFAULT_GRAPH_RELEASE_RULE_FLOOR
    ):
        return None
    return local_rules


def _cmd_sync_with_managed_dkg(cfg: BlackboxConfig, args: argparse.Namespace) -> int:
    """Run one foreground catch-up while DKG owns ongoing reconciliation."""
    with _managed_sync_lock() as acquired:
        if not acquired:
            print("Blackbox sync is already running; no second transfer was queued.")
            return 2 if getattr(args, "require_rules", False) else 0

        known_public, known_community = _last_sync_counts(cfg.context_graph_id)
        sync_state.write(
            "running",
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase="preparing-managed-sync",
            public_entries=known_public,
            community_entries=known_community,
        )
        terminal_state: Dict[str, Any] = {}
        result = 2
        failure: Optional[BaseException] = None
        try:
            # Upgrade installs that previously disabled the native reconciler.
            # Do not restart an already-correct node: preserving the pinned
            # curator connection lets DKG resume the same manifest after this
            # foreground command reaches its own deadline.
            if _set_persisted_dkg_steady_state(cfg):
                _restart_managed_dkg(cfg)
            result = _cmd_sync_impl(args)
            terminal_state = sync_state.read_for_graph(cfg.context_graph_id)
        except BaseException as exc:
            failure = exc
            terminal_state = sync_state.read_for_graph(cfg.context_graph_id)

        if failure is not None:
            raise failure
        status = str(terminal_state.get("status") or "")
        if status == "running" or not status:
            status = "done" if result == 0 else "failed"
        final_details = _terminal_sync_details(terminal_state)
        if status == "failed" and not final_details.get("error"):
            final_details["error"] = "required threat graph sync did not complete"
        sync_state.write(status, **final_details)
        return result


def _cmd_sync_impl(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    private_graph = _should_request_private_join(cfg)
    release_graph = cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
    managed_graph = private_graph or release_graph
    authoritative_available = bool(
        cfg.graph_peer_id and callable(getattr(client, "catchup_from_peer", None))
    )
    admitted = not private_graph
    pending_approval = private_graph
    # The pinned curator remains the preferred foreground source, but the DKG
    # subscription is still persisted below. That durable subscription is what
    # lets DKG continue reconciling after this command exits or the node restarts.
    subscribed = False
    catchup_restarted = False
    baseline_catchup_known = False
    baseline_catchup_job_id = ""
    fresh_catchup_seen = False
    fresh_catchup_job_id = ""
    refreshed_catchup_job_id = ""
    catchup_retry_attempts = 0
    next_catchup_retry_at = 0.0
    authoritative_attempted = False
    authoritative_recovered = False
    authoritative_cache_refreshed = False
    authoritative_complete = False
    authoritative_target = 0
    sync_complete = False
    last_join_attempt = float("-inf")
    deadline = time.monotonic() + max(1, int(getattr(args, "timeout", 180) or 180))
    track_sync = bool(getattr(args, "wait", False))

    if (
        release_graph
        and getattr(args, "wait", False)
        and getattr(args, "require_rules", False)
        and not authoritative_available
    ):
        print("  Required curator-pinned VM recovery is unavailable in this DKG build.")
        return 2

    if track_sync:
        known_public, known_community = _last_sync_counts(cfg.context_graph_id)
        sync_state.write(
            "running",
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase="joining" if private_graph else "network-catchup",
            public_entries=known_public,
            community_entries=known_community,
        )

    agent_address = ""
    try:
        identity = client.agent_identity()
        agent_address = str(identity.get("agentAddress") or "")
    except (DkgError, AttributeError):
        pass

    if getattr(args, "wait", False):
        try:
            baseline_catchup = client.catchup_status(cfg.context_graph_id)
            baseline_catchup_known = True
            baseline_catchup_job_id = _catchup_job_id(baseline_catchup)
        except (DkgError, AttributeError):
            pass

    if private_graph:
        status, admitted = _request_join(client, cfg.context_graph_id, cfg.graph_peer_id)
        pending_approval = not admitted
        last_join_attempt = time.monotonic()
        if status:
            print(status)

    rs = ruleset.Ruleset()
    public_count = 0
    community_count = 0
    initial_rules_ready = False
    attempt = 0
    last_subscribe_error = ""
    last_catchup: Dict[str, Any] = {}

    if release_graph and getattr(args, "wait", False):
        local_release = _complete_local_release_ruleset(cfg, client)
        if local_release is not None:
            rs = local_release
            counts = rs.counts()
            public_count = _ruleset_graph_count(rs, "public")
            initial_rules_ready = public_count > 0
            authoritative_attempted = True
            authoritative_recovered = True
            authoritative_cache_refreshed = True
            authoritative_complete = initial_rules_ready
            authoritative_target = public_count
            print(
                "Local confirmed VM already contains the complete "
                f"release ({public_count:,} enforceable threats)."
            )

    def _record_verified_pass(_inserted_triples: int) -> None:
        """Publish only locally committed threat counts between DKG passes."""
        nonlocal rs, public_count, authoritative_target, initial_rules_ready
        previous_public = public_count
        became_ready = False
        count_threats = getattr(client, "threat_count", None)
        if callable(count_threats):
            public_count = max(public_count, int(count_threats(cfg.context_graph_id) or 0))
        if public_count > 0 and not initial_rules_ready:
            # The DKG request has settled and its atomic store commit is now
            # queryable. Build one partial verified cache before announcing
            # readiness so an installer can safely open a useful dashboard
            # while the same single-flight transfer continues.
            try:
                partial_rules = ruleset.refresh(cfg, client)
            except Exception as exc:
                logger.debug("blackbox: initial verified rules cache is not ready: %s", exc)
            else:
                cached_public = _ruleset_graph_count(partial_rules, "public")
                if cached_public > 0:
                    rs = partial_rules
                    public_count = max(public_count, cached_public)
                    initial_rules_ready = True
                    became_ready = True
        authoritative_target = max(authoritative_target, public_count)
        sync_state.write(
            "running",
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase="recovering-verifiable-memory",
            public_entries=public_count,
            community_entries=community_count,
        )
        if initial_rules_ready and (public_count != previous_public or became_ready):
            print(f"  {public_count:,} verified threats ready")

    while True:
        now = time.monotonic()
        if (
            private_graph
            and not admitted
            and getattr(args, "wait", False)
            and now - last_join_attempt >= 10.0
        ):
            status, curator_confirmed = _request_join(
                client, cfg.context_graph_id, cfg.graph_peer_id
            )
            admitted = admitted or curator_confirmed
            if curator_confirmed:
                pending_approval = False
            last_join_attempt = time.monotonic()
            if status and attempt % 10 == 0:
                print(status)

        # The release graph has one known complete source peer. A fresh node
        # asks it first instead of downloading unrelated durable graphs from
        # every generic peer and only falling back minutes later.
        # If the direct path fails, the ordinary subscription/catch-up path
        # below remains available for compatibility and recovery.
        if (
            release_graph
            and getattr(args, "wait", False)
            and authoritative_available
            and not authoritative_attempted
        ):
            authoritative_attempted = True
            authoritative_recovered = _catchup_authoritative_vm(
                client,
                cfg.context_graph_id,
                cfg.graph_peer_id,
                deadline,
                on_progress=_record_verified_pass,
            )
            if not authoritative_recovered and getattr(args, "require_rules", False):
                print(
                    "  Foreground curator recovery did not complete; "
                    "persisting the DKG subscription for native reconciliation."
                )
            # Successful DKG passes already refreshed the verified cache via
            # ``_record_verified_pass``. If the pinned source failed before a
            # pass settled, do not launch a competing full-store query merely
            # to decide whether to persist the background subscription.
            if authoritative_recovered:
                try:
                    rs = ruleset.refresh(cfg, client, force_query=True)
                except ruleset.RulesetRefreshUnavailable:
                    rs = ruleset.peek(cfg)
                else:
                    authoritative_cache_refreshed = True
            else:
                rs = ruleset.peek(cfg)
            counts = rs.counts()
            cached_public = _ruleset_graph_count(rs, "public")
            public_count = (
                cached_public
                if authoritative_cache_refreshed
                else max(public_count, cached_public)
            )
            community_count = _ruleset_graph_count(rs, "community")
            authoritative_target = (
                public_count
                if authoritative_cache_refreshed
                else max(authoritative_target, public_count)
            )
            if authoritative_recovered:
                # The pinned pass established a complete foreground snapshot.
                # Still flow through the subscription call below so that DKG
                # owns future updates and restart-safe reconciliation.
                fresh_catchup_seen = True
                authoritative_complete = (
                    authoritative_cache_refreshed
                    and authoritative_target > 0
                    and public_count >= authoritative_target
                )

        may_probe_private = private_graph and not getattr(args, "wait", False)
        if not subscribed and (admitted or not private_graph or may_probe_private):
            try:
                subscription = client.subscribe_context_graph(cfg.context_graph_id)
                subscribed = True
                subscription_job_id = _catchup_job_id(subscription)
                if subscription_job_id and (
                    not baseline_catchup_known
                    or subscription_job_id != baseline_catchup_job_id
                ):
                    fresh_catchup_seen = True
                    fresh_catchup_job_id = subscription_job_id
                if not private_graph:
                    admitted = True
                    pending_approval = False
                if private_graph:
                    if track_sync:
                        sync_state.write(
                            "running",
                            context_graph_id=cfg.context_graph_id,
                            graph_peer_id=cfg.graph_peer_id,
                            phase="network-catchup",
                            public_entries=public_count,
                            community_entries=community_count,
                        )
                    print(
                        f"Requested subscription to {cfg.context_graph_id}; "
                        "verifying private-graph catch-up authorization."
                    )
                else:
                    print(f"Subscribed to {cfg.context_graph_id}; DKG catch-up started.")
            except DkgError as exc:
                last_subscribe_error = str(exc)
                if not private_graph:
                    print(f"warning: could not subscribe to {cfg.context_graph_id}: {exc}")

        catchup_state = ""
        catchup_includes_swm = False
        catchup_job_id = ""
        exact_job_status = False
        if getattr(args, "wait", False) and subscribed:
            try:
                catchup, exact_job_status = _catchup_status(
                    client,
                    cfg.context_graph_id,
                    fresh_catchup_job_id,
                )
                last_catchup = catchup
                catchup_state = str(catchup.get("status") or "").lower()
                catchup_includes_swm = catchup.get("includeSharedMemory") is True
                catchup_job_id = _catchup_job_id(catchup)
                if catchup_job_id and (
                    not baseline_catchup_known
                    or catchup_job_id != baseline_catchup_job_id
                ):
                    fresh_catchup_seen = True
                    if not fresh_catchup_job_id or not exact_job_status:
                        fresh_catchup_job_id = catchup_job_id
                if _catchup_denied(catchup):
                    pending_approval = True
                    admitted = False
            except DkgError:
                pass
        retryable_catchup = (
            not authoritative_recovered
            and getattr(args, "wait", False)
            and subscribed
            and (catchup_restarted or fresh_catchup_seen)
            and catchup_state in {"deferred", "unreachable"}
        )
        if retryable_catchup and now >= next_catchup_retry_at and now < deadline:
            catchup_retry_attempts += 1
            next_catchup_retry_at = now + min(
                10.0,
                float(2 ** min(catchup_retry_attempts - 1, 3)),
            )
            try:
                replacement = client.subscribe_context_graph(cfg.context_graph_id)
                replacement_job_id = _catchup_job_id(replacement)
                fresh_catchup_seen = True
                fresh_catchup_job_id = replacement_job_id
                last_catchup = replacement if isinstance(replacement, dict) else {}
                print(
                    "Retrying DKG catch-up after "
                    f"{catchup_state} state (attempt {catchup_retry_attempts})."
                )
                continue
            except DkgError as exc:
                last_subscribe_error = str(exc)
        fresh_job_complete = catchup_state == "done" and (
            exact_job_status
            or not fresh_catchup_job_id
            or catchup_job_id == fresh_catchup_job_id
        )
        barrier_job_id = catchup_job_id or fresh_catchup_job_id or "<unscoped>"
        catchup_pending = not authoritative_recovered and (
            catchup_state in {"queued", "running"}
            or (
                getattr(args, "wait", False)
                and (catchup_restarted or fresh_catchup_seen)
                and not fresh_job_complete
                and catchup_state not in {"failed", "cancelled", "denied"}
            )
        )
        catchup_failed = (
            not authoritative_recovered
            and (catchup_restarted or fresh_catchup_seen)
            and catchup_state in {"failed", "cancelled", "denied"}
        )
        if subscribed:
            if catchup_pending or catchup_failed:
                # DKG applies durable catch-up atomically. A full VM query here
                # cannot expose useful partial rules and competes with the
                # Blazegraph write that must finish first. Poll only the cheap
                # job status until the transfer reaches a terminal state.
                rs = ruleset.peek(cfg)
            else:
                force_catchup_query = (
                    fresh_job_complete
                    and barrier_job_id != refreshed_catchup_job_id
                )
                force_authoritative_query = (
                    authoritative_recovered
                    and not authoritative_cache_refreshed
                )
                force_query = force_catchup_query or force_authoritative_query
                try:
                    rs = ruleset.refresh(cfg, client, force_query=force_query)
                except ruleset.RulesetRefreshUnavailable:
                    rs = ruleset.peek(cfg)
                else:
                    if force_catchup_query:
                        refreshed_catchup_job_id = barrier_job_id
                    if force_authoritative_query:
                        authoritative_cache_refreshed = True
        counts = rs.counts()
        public_count = _ruleset_graph_count(rs, "public")
        community_count = _ruleset_graph_count(rs, "community")

        if (
            managed_graph
            and subscribed
            and not release_graph
            and not catchup_restarted
            and (
                catchup_includes_swm
                or (not fresh_catchup_seen and catchup_state == "done")
            )
            and not (
                authoritative_available
                and getattr(args, "wait", False)
                and public_count > 0
            )
        ):
            try:
                client.restart_context_graph_catchup(cfg.context_graph_id)
                catchup_restarted = True
                if catchup_includes_swm:
                    print("Replaced a legacy SWM catch-up with VM-only sync.")
                elif private_graph:
                    print("Restarted DKG catch-up after approval; waiting for threat rows.")
                else:
                    print("Restarted DKG catch-up; waiting for public threat rows.")
                if getattr(args, "wait", False):
                    continue
            except DkgError as exc:
                logger.debug("blackbox: catch-up restart failed: %s", exc)

        # A terminal generic catch-up is not success by itself.  A completed,
        # idempotent source-pinned recovery is: it has independently
        # verified the durable VM snapshot and may satisfy this gate on the
        # following loop iteration.
        authoritative_fallback_ready = (
            authoritative_recovered and authoritative_cache_refreshed
        )
        catchup_active = catchup_state in {"queued", "running"}
        catchup_cache_refreshed = (
            not fresh_job_complete
            or refreshed_catchup_job_id == barrier_job_id
        )
        fresh_catchup_complete = authoritative_fallback_ready or (
            not getattr(args, "wait", False)
            or (
                not catchup_active
                and catchup_cache_refreshed
                and (
                    not (catchup_restarted or fresh_catchup_seen)
                    or fresh_job_complete
                )
            )
        )
        base_sync_complete = public_count > 0 and fresh_catchup_complete
        # A clean local store has no public rows yet.  Waiting for
        # ``base_sync_complete`` before contacting the configured release
        # source deadlocks that exact first-sync case when generic peers do
        # not hold the graph.  Once the release graph is subscribed, pin the
        # authoritative source immediately; the recovery helper already
        # waits through DKG backpressure and verifies completion atomically.
        authoritative_recovery_ready = base_sync_complete or release_graph
        if (
            authoritative_recovery_ready
            and managed_graph
            and getattr(args, "wait", False)
            and authoritative_available
            and not authoritative_attempted
        ):
            authoritative_attempted = True
            authoritative_recovered = _catchup_authoritative_vm(
                client,
                cfg.context_graph_id,
                cfg.graph_peer_id,
                deadline,
                on_progress=_record_verified_pass,
            )
            if authoritative_recovered:
                try:
                    rs = ruleset.refresh(cfg, client, force_query=True)
                except ruleset.RulesetRefreshUnavailable:
                    rs = ruleset.peek(cfg)
                else:
                    authoritative_cache_refreshed = True
            else:
                rs = ruleset.refresh(cfg, client)
            counts = rs.counts()
            cached_public = _ruleset_graph_count(rs, "public")
            public_count = (
                cached_public
                if authoritative_cache_refreshed
                else max(public_count, cached_public)
            )
            community_count = _ruleset_graph_count(rs, "community")
            authoritative_target = (
                public_count
                if authoritative_cache_refreshed
                else max(authoritative_target, public_count)
            )
        if authoritative_recovered and public_count > authoritative_target:
            authoritative_target = public_count
        if authoritative_recovered:
            authoritative_complete = (
                authoritative_cache_refreshed
                and authoritative_target > 0
                and public_count >= authoritative_target
            )
            if authoritative_target <= 0:
                error = "authoritative VM returned no public threat entries"
                sync_state.write(
                    "failed",
                    context_graph_id=cfg.context_graph_id,
                    graph_peer_id=cfg.graph_peer_id,
                    phase="empty-verifiable-memory",
                    public_entries=0,
                    expected_public_entries=0,
                    community_entries=community_count,
                    error=error,
                )
                print(
                    "  authoritative VM returned zero public threat entries; "
                    "the required ruleset is unavailable."
                )
                break
        subscription_ready = subscribed
        sync_complete = (
            base_sync_complete
            and (not authoritative_attempted or authoritative_complete)
            and subscription_ready
        )
        if authoritative_recovered and not sync_complete:
            sync_state.write(
                "running",
                context_graph_id=cfg.context_graph_id,
                graph_peer_id=cfg.graph_peer_id,
                phase=(
                    "persisting-subscription"
                    if not subscription_ready
                    else (
                        "refreshing-verifiable-memory"
                        if not authoritative_complete
                        else "network-catchup"
                    )
                ),
                public_entries=public_count,
                expected_public_entries=authoritative_target,
                community_entries=community_count,
            )
        if sync_complete:
            break
        if (
            not authoritative_recovered
            and (catchup_restarted or fresh_catchup_seen)
            and catchup_state in {
                "failed", "cancelled", "denied"
            }
        ):
            break

        now = time.monotonic()
        if not getattr(args, "wait", False) or now >= deadline:
            if not subscribed:
                error = "required DKG subscription could not be persisted"
                if last_subscribe_error:
                    error = f"{error}: {last_subscribe_error}"
                sync_state.write(
                    "failed",
                    context_graph_id=cfg.context_graph_id,
                    graph_peer_id=cfg.graph_peer_id,
                    phase="persisting-subscription",
                    public_entries=public_count,
                    expected_public_entries=authoritative_target or public_count,
                    community_entries=community_count,
                    error=error,
                )
            elif authoritative_recovered and not authoritative_complete:
                sync_state.write(
                    "failed",
                    context_graph_id=cfg.context_graph_id,
                    graph_peer_id=cfg.graph_peer_id,
                    phase="refreshing-verifiable-memory",
                    public_entries=public_count,
                    expected_public_entries=authoritative_target,
                    community_entries=community_count,
                    error="public VM reconciliation deadline reached",
                )
            break
        attempt += 1
        if attempt == 1 or attempt % 10 == 0:
            if private_graph and pending_approval:
                suffix = f" for agent {agent_address}" if agent_address else ""
                print(f"Waiting for private graph membership confirmation{suffix}...")
            elif authoritative_recovered and not authoritative_complete:
                print(
                    "Waiting for public VM reconciliation "
                    f"({public_count:,}/{authoritative_target:,} entries)..."
                )
            else:
                state = catchup_state or "syncing"
                print(f"Waiting for DKG catch-up ({state})...")
        time.sleep(min(3.0, max(0.2, deadline - now)))

    if track_sync:
        current_transfer = sync_state.read_for_graph(cfg.context_graph_id)
        if sync_complete:
            sync_state.write(
                "done",
                context_graph_id=cfg.context_graph_id,
                graph_peer_id=cfg.graph_peer_id,
                phase="complete",
                public_entries=public_count,
                expected_public_entries=authoritative_target or public_count,
                community_entries=community_count,
            )
        elif current_transfer.get("status") == "running":
            sync_state.write(
                "failed",
                context_graph_id=cfg.context_graph_id,
                graph_peer_id=cfg.graph_peer_id,
                phase=str(current_transfer.get("phase") or "network-catchup"),
                public_entries=public_count,
                community_entries=community_count,
                error="required threat graph sync did not complete before the deadline",
            )

    print(f"Ruleset synced from {cfg.context_graph_id}:")
    print(f"  {counts['injection']} injection, {counts['escalation']} escalation, "
          f"{counts['dependency']} dependency")
    print(f"  {public_count:,} public VM (curated)")
    print("  Community graph (SWM): coming soon")
    if not sync_complete:
        if private_graph and (pending_approval or not subscribed):
            print("  This graph is not supported; Agent Blackbox only uses its public VM graph.")
            if agent_address:
                print(f"  Ask the curator to approve agent address: {agent_address}")
            if last_subscribe_error:
                logger.debug("blackbox: subscribe pending: %s", last_subscribe_error)
            if _catchup_denied(last_catchup):
                print("  DKG catch-up is denied until the curator confirms this node.")
        elif not subscribed:
            print("  Required public VM subscription could not be persisted.")
            if last_subscribe_error:
                print(f"  DKG subscription error: {last_subscribe_error}")
            print("  Retry with `hermes blackbox sync --wait`.")
        elif (catchup_restarted or fresh_catchup_seen) and str(
            last_catchup.get("status") or ""
        ).lower() in {
            "failed", "cancelled", "denied"
        }:
            detail = last_catchup.get("error") or (last_catchup.get("result") or {}).get("error")
            print(f"  Fresh DKG catch-up failed{f': {detail}' if detail else '.'}")
        elif authoritative_attempted and authoritative_target == 0:
            print("  The authoritative curator VM returned zero public threat entries.")
            print("  No rules are available to protect this node.")
        elif authoritative_attempted and not authoritative_complete:
            print("  Authoritative curator VM transfer is incomplete.")
            print("  Retry with `hermes blackbox sync --wait`.")
        else:
            print("  0 rules — DKG has not made curated VM threat rows queryable yet.")
            print("  Retry with `hermes blackbox sync --wait`.")
        if getattr(args, "require_rules", False):
            print("  Required ruleset sync is incomplete.")
            return 2
    return 0


def _ruleset_graph_count(rs: Any, source: str) -> int:
    for name in ("graph_count", "source_count"):
        counter = getattr(rs, name, None)
        if callable(counter):
            return int(counter(source) or 0)
    return sum(int(value or 0) for value in rs.counts().values())


def _catchup_authoritative_vm(
    client: DkgClient,
    context_graph_id: str,
    graph_peer_id: str,
    deadline: float,
    *,
    on_progress: Optional[Callable[[int], None]] = None,
) -> bool:
    """Recover and verify the public graph's durable VM snapshot."""
    catchup = getattr(client, "catchup_from_peer", None)
    if not callable(catchup) or not graph_peer_id:
        return False
    sync_state.write(
        "running",
        context_graph_id=context_graph_id,
        graph_peer_id=graph_peer_id,
        phase="recovering-verifiable-memory",
    )
    print("Syncing the complete verifiable VM snapshot...")
    backpressure_notice_printed = False
    backpressure_retries = 0
    empty_public_passes = 0
    incomplete_empty_passes = 0
    last_incomplete_safe_current: Optional[int] = None
    heartbeat_seconds = 10.0

    try:
        _connect_verifiable_source(
            client,
            context_graph_id,
            graph_peer_id,
            deadline,
        )
    except DkgError as exc:
        error = f"verifiable graph source is unreachable: {exc}"
        sync_state.write(
            "failed",
            context_graph_id=context_graph_id,
            graph_peer_id=graph_peer_id,
            error=error,
        )
        print(f"  {error}")
        return False

    # Legacy DKG builds report durable completion only in daemon.log. Bound
    # that compatibility signal to this recovery invocation so a completed
    # transfer from an earlier command cannot satisfy a new request.
    progress_cursor = capture_durable_progress_cursor(
        str(getattr(client, "dkg_home", "") or "")
    )

    # DKG authenticates the configured graph id against its on-chain name-hash
    # commitment. Request that graph directly instead of making VM availability
    # depend on a separately materialized ontology graph.
    public_progress_seen = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                error="authoritative sync deadline reached",
            )
            return False
        pass_budget_ms = (
            constants.DEFAULT_GRAPH_SYNC_PASS_BUDGET_MS
            if public_progress_seen
            else constants.INITIAL_GRAPH_SYNC_PASS_BUDGET_MS
        )
        budget_ms = max(
            1_000,
            min(
                pass_budget_ms,
                int(max(1.0, remaining - 10) * 1_000),
            ),
        )
        request_still_active = False
        try:
            # The DKG endpoint is synchronous and its final verification/store
            # phase can outlive a socket inactivity timeout. Run it behind a
            # daemon-thread wall-clock guard so a misbehaving daemon cannot pin
            # a fresh install forever. Polling also gives operators visible
            # proof of life while the request is legitimately busy.
            outcome: "queue.Queue[tuple[str, Any]]" = queue.Queue(maxsize=1)

            def _recover() -> None:
                try:
                    outcome.put(("ok", catchup(
                        context_graph_id,
                        graph_peer_id,
                        budget_ms=budget_ms,
                    )))
                except BaseException as exc:  # delivered back to the caller
                    outcome.put(("error", exc))

            worker = threading.Thread(
                target=_recover,
                name="blackbox-curator-vm-recovery",
                daemon=True,
            )
            worker.start()
            request_started = time.monotonic()
            request_deadline = min(
                deadline,
                request_started
                + max(
                    (budget_ms / 1_000) + 60.0,
                    constants.GRAPH_SYNC_SETTLEMENT_TIMEOUT_S
                    + constants.GRAPH_SYNC_WATCHDOG_HEADROOM_S,
                ),
            )
            request_timeout_seconds = max(
                1,
                int(request_deadline - request_started),
            )
            heartbeat = 0
            while True:
                wait_for = min(
                    heartbeat_seconds,
                    max(0.0, request_deadline - time.monotonic()),
                )
                if wait_for <= 0:
                    request_still_active = worker.is_alive()
                    raise DkgError(
                        "verifiable VM sync watchdog reached its "
                        f"{request_timeout_seconds}s settlement deadline"
                        + (
                            " while the DKG request remains active"
                            if request_still_active
                            else ""
                        )
                    )
                try:
                    outcome_kind, outcome_value = outcome.get(timeout=wait_for)
                    break
                except queue.Empty:
                    heartbeat += 1
                    elapsed = int(heartbeat * heartbeat_seconds)
                    print(
                        f"  verifiable VM sync is still active "
                        f"({elapsed}s elapsed)...",
                        flush=True,
                    )
                    sync_state.write(
                        "running",
                        context_graph_id=context_graph_id,
                        graph_peer_id=graph_peer_id,
                        phase="recovering-verifiable-memory",
                    )
            if outcome_kind == "error":
                raise outcome_value
            result = outcome_value
        except DkgError as exc:
            error = str(exc)
            retryable = not request_still_active and any(
                marker in error.lower()
                for marker in (
                    "backpressure",
                    '"retryable":true',
                    '"retryable": true',
                    "durable_catchup_all_peers_failed",
                    "store scheduler",
                    "queue wait timeout",
                    "timed out",
                    "exceeded its",
                )
            )
            if (
                retryable
                and backpressure_retries < 3
                and deadline - time.monotonic() > 4
            ):
                backpressure_retries += 1
                sync_state.write(
                    "running",
                    context_graph_id=context_graph_id,
                    graph_peer_id=graph_peer_id,
                    phase="waiting-for-dkg-capacity",
                )
                if not backpressure_notice_printed:
                    print("DKG graph sync is pausing briefly before a safe resume...")
                    backpressure_notice_printed = True
                time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))
                continue
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                error=error,
            )
            logger.debug("blackbox: verifiable graph recovery failed: %s", exc)
            return False
        results = result.get("results") if isinstance(result, dict) else None
        peer_result = next(
            (
                item
                for item in (results or [])
                if isinstance(item, dict)
                and str(item.get("peerId") or "") == graph_peer_id
            ),
            None,
        )
        peer_error = ""
        if isinstance(peer_result, dict):
            peer_error = str(
                peer_result.get("durableError")
                or peer_result.get("error")
                or peer_result.get("errors")
                or ""
            )
        explicit_incomplete = bool(
            isinstance(result, dict)
            and result.get("durableComplete") is False
            and result.get("retryable") is True
            and str(result.get("errorCode") or "")
            == "DURABLE_CATCHUP_INCOMPLETE"
        )
        attempted = bool(
            isinstance(result, dict)
            and (result.get("ok") is True or explicit_incomplete)
            and result.get("includeDurable") is True
            and result.get("includeSharedMemory") is False
            and int(result.get("peersAttempted") or 0) >= 1
            and isinstance(peer_result, dict)
            and not peer_error
        )
        if not attempted:
            error = str(
                (result or {}).get("error")
                or peer_error
                or "graph source did not accept durable VM recovery"
            )
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                error=error,
            )
            logger.debug("blackbox: graph source did not attempt VM recovery: %s", error)
            return False
        backpressure_retries = 0
        inserted = int(result.get("totalDurableInsertedTriples") or 0)
        durable_progress = read_durable_progress(
            str(getattr(client, "dkg_home", "") or ""),
            context_graph_id,
            after=progress_cursor,
        )
        # Newer DKG releases report the request's completion contract directly.
        # Retain daemon-log parsing as a compatibility fallback for 10.0.9.
        if result.get("durableComplete") is True:
            durable_progress["snapshot_complete"] = True
        elif result.get("durableComplete") is False:
            durable_progress["snapshot_complete"] = False
        sync_state.write(
            "running",
            context_graph_id=context_graph_id,
            graph_peer_id=graph_peer_id,
            phase=(
                "recovering-verifiable-memory"
                if inserted > 0
                else "refreshing-verifiable-memory"
            ),
            inserted_durable_triples=inserted,
            **durable_progress,
        )
        durable_progress = read_durable_progress(
            str(getattr(client, "dkg_home", "") or ""),
            context_graph_id,
        )
        if inserted <= 0:
            expected = int(durable_progress.get("expected_triples") or 0)
            safe_current = int(durable_progress.get("safe_current_triples") or 0)
            if expected > 0 and safe_current < expected:
                public_progress_seen = public_progress_seen or safe_current > 0
                if (
                    last_incomplete_safe_current is None
                    or safe_current > last_incomplete_safe_current
                ):
                    incomplete_empty_passes = 1
                else:
                    incomplete_empty_passes += 1
                last_incomplete_safe_current = safe_current
                if incomplete_empty_passes >= _MAX_EMPTY_PUBLIC_PASSES:
                    error = (
                        "public VM manifest made no durable progress after "
                        f"{incomplete_empty_passes} pinned passes "
                        f"({safe_current:,}/{expected:,})"
                    )
                    sync_state.write(
                        "failed",
                        context_graph_id=context_graph_id,
                        graph_peer_id=graph_peer_id,
                        phase="stalled-verifiable-memory",
                        inserted_durable_triples=0,
                        error=error,
                        **durable_progress,
                    )
                    print(f"  {error}")
                    return False
                sync_state.write(
                    "running",
                    context_graph_id=context_graph_id,
                    graph_peer_id=graph_peer_id,
                    phase="recovering-verifiable-memory",
                    inserted_durable_triples=0,
                    **durable_progress,
                )
                print(
                    "  verifiable VM pass settled without committed triples; "
                    f"snapshot remains incomplete ({safe_current:,}/{expected:,}); "
                    "retrying the pinned source"
                )
                time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))
                continue
            count_threats = getattr(client, "threat_count", None)
            local_threats: Optional[int] = None
            if callable(count_threats):
                try:
                    local_threats = int(count_threats(context_graph_id) or 0)
                except (DkgError, TypeError, ValueError):
                    local_threats = None
            if (
                context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
                and local_threats is not None
                and local_threats >= constants.DEFAULT_GRAPH_RELEASE_THREAT_FLOOR
            ):
                print(
                    "  verifiable VM release floor is complete "
                    f"({local_threats:,} threats verified and stored)"
                )
                return True
            if durable_progress.get("snapshot_complete") is True:
                expected = int(durable_progress.get("expected_triples") or 0)
                if expected > 0:
                    print(
                        f"  verifiable VM snapshot complete "
                        f"({expected:,} triples verified and stored)"
                    )
                else:
                    print("  verifiable VM snapshot complete")
                print("  verifiable VM sync settled (no new triples)")
                return True

            # A failed graph-scoped batch may have committed earlier KAs before
            # a later KA failed chain authentication.  Those rows are useful as
            # a partial ruleset, but their presence is not evidence that the
            # authoritative manifest settled.  Only the safe manifest boundary
            # above may turn a zero-insert response into success.
            empty_public_passes += 1
            safe_current = int(durable_progress.get("safe_current_triples") or 0)
            expected = int(durable_progress.get("expected_triples") or 0)
            if safe_current > 0:
                public_progress_seen = True
            if (
                empty_public_passes < _MAX_EMPTY_PUBLIC_PASSES
                and deadline - time.monotonic() > 4
            ):
                if expected > 0:
                    print(
                        "  public VM snapshot remains incomplete "
                        f"({safe_current:,}/{expected:,} safe triples"
                        + (
                            f", {local_threats:,} local threats"
                            if local_threats is not None and local_threats > 0
                            else ""
                        )
                        + "); retrying the pinned source"
                    )
                else:
                    print(
                        "  public VM returned no complete manifest boundary; "
                        "retrying the pinned source"
                    )
                time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))
                continue
            if expected > 0:
                error = (
                    "public VM snapshot remains incomplete after "
                    f"{empty_public_passes} pinned passes "
                    f"({safe_current}/{expected} safe triples)"
                )
                phase = "incomplete-verifiable-memory"
            else:
                error = (
                    "public VM returned no complete manifest boundary after "
                    f"{empty_public_passes} pinned passes"
                )
                phase = "empty-verifiable-memory"
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                phase=phase,
                error=error,
                **durable_progress,
            )
            print(f"  {error}")
            return False
        empty_public_passes = 0
        incomplete_empty_passes = 0
        last_incomplete_safe_current = int(
            durable_progress.get("safe_current_triples") or 0
        )
        print(f"  verifiable VM sync advanced ({inserted:,} triples inserted)")
        if on_progress is not None:
            on_progress(inserted)
        public_progress_seen = True
        if context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID:
            count_threats = getattr(client, "threat_count", None)
            if callable(count_threats):
                try:
                    local_threats = int(count_threats(context_graph_id) or 0)
                except (DkgError, TypeError, ValueError):
                    local_threats = 0
                if local_threats >= constants.DEFAULT_GRAPH_RELEASE_THREAT_FLOOR:
                    print(
                        "  verifiable VM release floor is complete "
                        f"({local_threats:,} threats verified and stored)"
                    )
                    return True
        # DKG's bounded rootless recovery deletes its transient page checkpoint
        # after the safe offset reaches the manifest total. Reissuing the full
        # snapshot request then starts a new scan at offset zero; it is not a
        # required idempotent EOF round. The HTTP response above is delivered
        # only after verification and store materialization settle, so combine
        # that successful response with the managed daemon's safe graph boundary
        # to recognize completion without downloading the snapshot again.
        if durable_progress.get("snapshot_complete") is True:
            expected = int(durable_progress.get("expected_triples") or 0)
            sync_state.write(
                "running",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                phase="refreshing-verifiable-memory",
                inserted_durable_triples=inserted,
                **durable_progress,
            )
            if expected > 0:
                print(
                    f"  verifiable VM snapshot complete "
                    f"({expected:,} triples verified and stored)"
                )
            else:
                print("  verifiable VM snapshot complete")
            return True
        # A transport interruption can yield a verified prefix and a successful
        # HTTP response. Repeat the pinned pass until the safe manifest boundary
        # is complete. The zero-insert path remains a compatibility fallback for
        # DKG builds that do not emit rootless durable progress.
        time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))


def _peer_discovery_pending(exc: DkgError) -> bool:
    detail = str(exc).lower()
    return any(
        marker in detail
        for marker in (
            "peer_not_found",
            "peerresolver returned no addresses",
            "no addresses for",
            "failed to find peer",
            "dial_failed",
            "all multiaddr dials failed",
            "transport error: timed out",
        )
    )


def _configured_publisher_circuits(client: DkgClient, peer_id: str) -> List[str]:
    """Build deterministic relay routes for a publisher on a cold peerstore."""
    try:
        config = json.loads(
            (Path(client.dkg_home) / "config.json").read_text(encoding="utf-8")
        )
    except (AttributeError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return []
    circuits: List[str] = []
    for relay in config.get("relayPeers") or []:
        address = str(relay or "").rstrip("/")
        if "/p2p/" not in address:
            continue
        circuits.append(f"{address}/p2p-circuit/p2p/{peer_id}")
    return circuits


def _connect_verifiable_source(
    client: DkgClient,
    context_graph_id: str,
    graph_peer_id: str,
    deadline: float,
) -> None:
    """Resolve a publisher reliably during a fresh node's DHT warm-up."""
    connect = getattr(client, "connect_peer", None)
    if not callable(connect):
        return
    discovery_deadline = min(deadline, time.monotonic() + 120.0)
    notice_printed = False
    last_error: Optional[DkgError] = None
    while time.monotonic() < discovery_deadline:
        try:
            connect(graph_peer_id)
            return
        except DkgError as exc:
            if not _peer_discovery_pending(exc):
                raise
            last_error = exc

        # DHT routing tables are intentionally empty on a brand-new node.
        # Try the configured core relays as circuit routes while discovery
        # warms up; the publisher may hold a reservation on any one of them.
        connect_multiaddr = getattr(client, "connect_multiaddr", None)
        if callable(connect_multiaddr):
            for circuit in _configured_publisher_circuits(client, graph_peer_id):
                try:
                    connect_multiaddr(circuit)
                    return
                except DkgError:
                    continue

        remaining = discovery_deadline - time.monotonic()
        if remaining <= 0:
            break
        sync_state.write(
            "running",
            context_graph_id=context_graph_id,
            graph_peer_id=graph_peer_id,
            phase="discovering-verifiable-source",
        )
        if not notice_printed:
            print("  discovering the verifiable graph publisher (fresh-node warm-up)...")
            notice_printed = True
        time.sleep(min(5.0, max(0.2, remaining)))
    if last_error is not None:
        raise last_error
    raise DkgError("publisher discovery deadline reached")


def _catchup_denied(catchup: Dict[str, Any]) -> bool:
    if not isinstance(catchup, dict):
        return False
    status = str(catchup.get("status") or "").lower()
    if status == "denied":
        return True
    result = catchup.get("result") if isinstance(catchup.get("result"), dict) else {}
    if result.get("denied") is True:
        return True
    error = str(catchup.get("error") or result.get("error") or "").lower()
    return any(term in error for term in ("denied", "unauthorized", "unconfirmed"))


def _catchup_job_id(catchup: Any) -> str:
    if not isinstance(catchup, dict):
        return ""
    nested = catchup.get("catchup")
    if isinstance(nested, dict):
        catchup = nested
    return str(catchup.get("jobId") or catchup.get("job_id") or catchup.get("id") or "")


def _catchup_status(
    client: DkgClient,
    context_graph_id: str,
    job_id: str = "",
) -> tuple[Dict[str, Any], bool]:
    """Read an exact catch-up job when supported, otherwise the graph latest."""
    if job_id:
        try:
            return client.catchup_status(context_graph_id, job_id=job_id), True
        except TypeError as exc:
            # Compatibility for older plugin clients and test doubles that do
            # not yet accept the keyword. Do not hide unrelated TypeErrors.
            if "job_id" not in str(exc):
                raise
        except DkgError as exc:
            # The daemon bounds its job history. If the exact job was evicted,
            # inspect the latest job and adopt it in the caller. Transport and
            # server failures must keep the caller pinned to this exact job.
            if exc.status_code not in {404, 410}:
                raise
    return client.catchup_status(context_graph_id), False


def _should_request_private_join(cfg: BlackboxConfig) -> bool:
    """Private graph membership is never part of Agent Blackbox."""
    return False


def _request_join(client: DkgClient, cg_id: str, graph_peer_id: str) -> tuple[Optional[str], bool]:
    """Submit one native private-graph join request.

    The boolean reports that the curator itself confirmed current membership
    and refreshed the signed peer-key delegation.  A local participant list
    can be stale after a store migration or curator restart, so it must not be
    used as the authorization signal for starting private catch-up.
    """
    if not graph_peer_id:
        return None, False
    try:
        result = client.request_join(cg_id, graph_peer_id)
    except DkgError as exc:
        return f"warning: could not request join for {cg_id}: {exc}", False
    if not isinstance(result, dict):
        return f"Join request submitted for {cg_id}; curator approval is still required.", False
    if result.get("alreadyMember") or result.get("already_member"):
        return (
            f"Join request: the curator confirmed membership for {cg_id} "
            "and refreshed this node's peer binding.",
            True,
        )
    delivered = result.get("delivered")
    if isinstance(delivered, list):
        delivered_count = len(delivered)
    elif isinstance(delivered, bool):
        delivered_count = 1 if delivered else 0
    elif isinstance(delivered, str) and delivered.lower() == "local":
        delivered_count = 1
    else:
        try:
            delivered_count = int(delivered or result.get("deliveredCount") or 0)
        except (TypeError, ValueError):
            delivered_count = 0
    if delivered_count:
        return (
            f"Join request sent for {cg_id}: delivered to {delivered_count} curator host(s); "
            "approval is pending.",
            False,
        )
    return f"Join request could not reach a graph host for {cg_id}; retrying.", False


def _cmd_attach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.attach_all(hermes=do_hermes, openclaw=do_openclaw, dry_run=args.dry_run)
    prefix = "Would protect" if args.dry_run else "Protected"
    for row in report.get("hermes", []):
        _print_hermes_attach_row(row, prefix)
    for row in report.get("openclaw", []):
        _print_openclaw_attach_row(row, prefix)
    count = report.get("count", 0)
    if args.dry_run:
        print(f"\nDry run: Blackbox would watch {count} agent(s). Nothing was written.")
    else:
        print(f"\nBlackbox is watching {count} agent(s). Restart any running agent to activate.")
    return 0


def _cmd_detach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.detach_all(
        hermes=do_hermes, openclaw=do_openclaw, remove_files=args.remove_files, dry_run=args.dry_run
    )
    prefix = "Would detach" if args.dry_run else "Detached"
    for row in report.get("hermes", []):
        if row.get("error"):
            print(f"  ! {row['target']} (hermes): {row['error']}")
        elif row.get("already") and not row.get("removed"):
            print(f"  - {row['target']} (hermes): already detached")
        else:
            extra = ", files removed" if row.get("removed") else ""
            print(f"  {prefix} {row['target']} (hermes){extra}")
    for row in report.get("openclaw", []):
        if row.get("error"):
            print(f"  ! {row['target']} (openclaw): {row['error']}")
        elif row.get("already"):
            print(f"  - {row['target']} (openclaw): already detached")
        else:
            print(f"  {prefix} {row['target']} (openclaw)")
    print("\nBlackbox detached. Restart any running agent to apply.")
    return 0


def _print_hermes_attach_row(row: Dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (hermes): {row['error']}")
        return
    if row.get("already") and not row.get("copied"):
        print(f"  - {row['target']} (hermes): already protected")
        return
    bits = []
    if row.get("copied"):
        bits.append("plugin copied")
    if row.get("enabled"):
        bits.append("enabled")
    elif row.get("already"):
        bits.append("already enabled")
    detail = f" ({', '.join(bits)})" if bits else ""
    print(f"  {prefix} {row['target']} (hermes){detail}")


def _print_openclaw_attach_row(row: Dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (openclaw): {row['error']}")
        return
    if row.get("already"):
        print(f"  - {row['target']} (openclaw): already protected")
        return
    note = f"  note: {row['note']}" if row.get("note") else ""
    print(f"  {prefix} {row['target']} (openclaw){note}")


def _cmd_report(args: argparse.Namespace) -> int:
    print("Community graph and threat sharing are coming soon.")
    print("Nothing was submitted; findings and threat reports stay local.")
    return 2


def _cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    port = args.port or cfg.dashboard_port
    try:
        from .dashboard.server import start_dashboard
    except Exception as exc:
        print(f"error: dashboard requires the [web] extra (fastapi/uvicorn): {exc}")
        return 1
    _replace_existing_dashboard(port)
    try:
        report = attach.attach_all(hermes=True, openclaw=True, dry_run=False)
        newly = [r for r in report.get("hermes", []) + report.get("openclaw", []) if not r.get("already") and not r.get("error")]
        if newly:
            for row in report.get("hermes", []):
                if not row.get("already") and not row.get("error"):
                    _print_hermes_attach_row(row, "Auto-attached")
            for row in report.get("openclaw", []):
                if not row.get("already") and not row.get("error"):
                    _print_openclaw_attach_row(row, "Auto-attached")
            print("  Restart any running agent to activate.")
    except Exception as exc:
        logger.debug("dashboard auto-attach skipped: %s", exc)
    print(f"Starting Blackbox dashboard on http://127.0.0.1:{port} (Ctrl-C to stop)")
    start_dashboard(port)
    return 0


def _replace_existing_dashboard(port: int) -> None:
    """Kill any dashboard already bound to ``port`` so re-running ``hermes
    blackbox dashboard`` seamlessly restarts it instead of colliding.

    Loopback-only, best-effort: probe the port, resolve owning PIDs via
    ``lsof``, and send SIGTERM (then SIGKILL after a short wait). Skips the
    current process — we never signal ourselves. Fail-open: any error just
    proceeds to the bind, which will surface the normal port-in-use error.
    """
    import shutil
    import signal
    import socket

    # Quick reachability probe — if nothing's listening, skip everything.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        if sock.connect_ex(("127.0.0.1", int(port))) != 0:
            return
    finally:
        sock.close()

    lsof = shutil.which("lsof")
    if not lsof:
        print(f"warning: port {port} in use but 'lsof' unavailable — cannot auto-restart.")
        return

    try:
        import subprocess
        out = subprocess.run(
            [lsof, "-tiTCP:" + str(int(port)), "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except Exception as exc:
        logger.debug("dashboard auto-restart: lsof failed: %s", exc)
        return

    my_pid = os.getpid()
    pids = {int(p) for p in out.split() if p.isdigit() and int(p) != my_pid}
    if not pids:
        return

    print(f"restarting: found existing dashboard on port {port} (pid {', '.join(str(p) for p in sorted(pids))}) — stopping it...")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            logger.debug("dashboard auto-restart: SIGTERM %s failed: %s", pid, exc)

    # Wait up to 3s for graceful exit, then SIGKILL stragglers.
    import psutil
    import time as _time
    for _ in range(30):
        alive = [pid for pid in pids if psutil.pid_exists(pid)]
        if not alive:
            return
        _time.sleep(0.1)
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    for pid in alive:
        try:
            os.kill(pid, kill_signal)
        except Exception as exc:
            logger.debug("dashboard auto-restart: SIGKILL %s failed: %s", pid, exc)


# ---------------------------------------------------------------------------
# setup-llm: interactive picker for the optional LLM reviewer
# ---------------------------------------------------------------------------

#: Standard env var names each provider's key lives in (mirrors hermes auth).
_LLM_KEY_ENV_VARS = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN"),
}

_PROVIDER_ALIASES = {
    "openai": "openai",
    "openai-api": "openai",
    "openai-responses": "openai",
    "openai-chat": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "anthropic-api": "anthropic",
}

_PROVIDER_KEYS = ("provider", "model_provider", "modelProvider", "llm_provider", "llmProvider")
_MODEL_KEYS = ("model", "default", "default_model", "defaultModel", "llm_model", "llmModel")
_API_KEY_KEYS = ("api_key", "apiKey", "key", "token")
_API_KEY_ENV_KEYS = ("key_env", "keyEnv", "api_key_env", "apiKeyEnv", "env", "env_var", "envVar")


def _tty():
    """Return an interactive /dev/tty handle, or None (piped / no terminal)."""
    try:
        return open("/dev/tty", "r+", encoding="utf-8")
    except Exception:
        return None


def _ask(prompt: str, tty) -> str:
    """Print *prompt* and read one trimmed line from the tty (or stdin)."""
    if tty is not None:
        tty.write(prompt)
        tty.flush()
        line = tty.readline()
        return line.strip() if line else ""
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _mask_key(key: str) -> str:
    """Show a key as ``sk-a…wxyz`` — enough to recognize, not enough to leak."""
    key = key or ""
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}…{key[-4:]}"


def _env_key(provider: str) -> str:
    """First non-empty value among *provider*'s standard key env vars."""
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):  # ordered, first wins
        val = os.environ.get(name)
        if val and val.strip():
            return val.strip()
    return ""


def _provider_alias(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    return _PROVIDER_ALIASES.get(raw, "")


def _env_lookup(name: str, env: Optional[Dict[str, str]] = None) -> str:
    if not name:
        return ""
    if env and env.get(name):
        return str(env[name]).strip()
    return str(os.environ.get(name, "") or "").strip()


def _env_key_from(provider: str, env: Optional[Dict[str, str]] = None) -> str:
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):
        val = _env_lookup(name, env)
        if val:
            return val
    return ""


def _value_from(mapping: Dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        val = mapping.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _key_from_mapping(mapping: Dict[str, Any], provider: str, env: Optional[Dict[str, str]] = None) -> str:
    direct = _value_from(mapping, _API_KEY_KEYS)
    if direct:
        return direct
    for key in _API_KEY_ENV_KEYS:
        env_name = mapping.get(key)
        if env_name is not None:
            found = _env_lookup(str(env_name).strip(), env)
            if found:
                return found
    return _env_key_from(provider, env)


def _iter_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


def _candidate_from_mapping(
    mapping: Dict[str, Any],
    source: str,
    env: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, str]]:
    provider = _provider_alias(_value_from(mapping, _PROVIDER_KEYS))
    if not provider:
        return None
    api_key = _key_from_mapping(mapping, provider, env)
    if not api_key:
        return None
    model = _value_from(mapping, _MODEL_KEYS) or llm.default_model(provider)
    return {"source": source, "provider": provider, "model": model, "api_key": api_key}


def _parse_env_value(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _load_env_file(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except Exception:
        return env
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            env[key] = _parse_env_value(value)
    return env


def _candidate_from_hermes_config(
    cfg: Dict[str, Any],
    env: Optional[Dict[str, str]],
    source: str,
) -> Optional[Dict[str, str]]:
    if not isinstance(cfg, dict):
        return None
    model_cfg = cfg.get("model") if isinstance(cfg.get("model"), dict) else {}
    candidates = [model_cfg, cfg]
    custom = cfg.get("custom_providers") or cfg.get("providers")
    if isinstance(custom, dict):
        candidates.extend(v for v in custom.values() if isinstance(v, dict))
    for candidate in candidates:
        resolved = _candidate_from_mapping(candidate, source, env)
        if resolved:
            return resolved
    return None


def _hermes_llm_candidate() -> Optional[Dict[str, str]]:
    try:
        from hermes_cli import config as hconfig

        cfg = hconfig.load_config()
        env = {**os.environ, **hconfig.load_env()}
    except Exception:
        cfg, env = {}, {}

    current = _candidate_from_hermes_config(cfg, env, "Hermes")
    if current:
        return current

    seen: set[Path] = set()
    for home in attach.discover_hermes_homes():
        try:
            resolved_home = home.expanduser().resolve()
        except Exception:
            continue
        if resolved_home in seen:
            continue
        seen.add(resolved_home)
        home_cfg = attach._load_yaml(resolved_home / "config.yaml")
        home_env = {**os.environ, **_load_env_file(resolved_home / ".env")}
        source = f"Hermes ({resolved_home})"
        candidate = _candidate_from_hermes_config(home_cfg, home_env, source)
        if candidate:
            return candidate
    return None


def _openclaw_llm_candidate() -> Optional[Dict[str, str]]:
    for workspace in attach.discover_openclaw_workspaces():
        path = workspace / "openclaw.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for mapping in _iter_dicts(data):
            resolved = _candidate_from_mapping(mapping, f"OpenClaw ({workspace})")
            if resolved:
                return resolved
    return None


def _auto_llm_candidate() -> tuple[str, Optional[Dict[str, str]]]:
    cfg = load_blackbox_config()
    if cfg.llm_ready:
        return "Blackbox", {
            "source": "Blackbox",
            "provider": cfg.llm_provider,
            "model": cfg.llm_model,
            "api_key": cfg.llm_api_key,
        }
    for resolver in (_hermes_llm_candidate, _openclaw_llm_candidate):
        candidate = resolver()
        if candidate:
            return candidate["source"], candidate
    return "", None


def _resolve_key(source: str, provider: str) -> str:
    """Resolve an API key for *provider* from the chosen *source*."""
    if source == "new":
        return ""
    if source == "openclaw":
        candidate = _openclaw_llm_candidate()
        if candidate and candidate["provider"] == provider:
            return candidate["api_key"]
    if source == "hermes":
        candidate = _hermes_llm_candidate()
        if candidate and candidate["provider"] == provider:
            return candidate["api_key"]
    return _env_key(provider)


def _cmd_setup_llm(args: argparse.Namespace) -> int:
    """Configure the opt-in LLM prompt-injection reviewer.

    Interactive by default (reads /dev/tty); fully scriptable via flags. Writes
    ``plugins.entries.blackbox.llm.*`` through the shared settings writer.
    """
    if args.disable:
        result = settings.write_settings({"llm": {"enabled": False}})
        print("LLM reviewer disabled." if result.get("ok") else f"error: {result.get('errors')}")
        return 0 if result.get("ok") else 1

    explicit = any(
        getattr(args, name, None)
        for name in ("provider", "model", "key_source", "api_key")
    )
    if not explicit and not getattr(args, "configure", False):
        source, candidate = _auto_llm_candidate()
        if candidate:
            if source == "Blackbox":
                print(
                    f"LLM reviewer already configured: "
                    f"provider={candidate['provider']}  model={candidate['model']}"
                )
                return 0
            result = settings.write_settings({
                "llm": {
                    "enabled": True,
                    "provider": candidate["provider"],
                    "model": candidate["model"],
                    "api_key": candidate["api_key"],
                }
            })
            if not result.get("ok"):
                print(f"error: could not save settings: {result.get('errors')}")
                return 1
            print(
                f"LLM reviewer enabled from {source}: "
                f"provider={candidate['provider']}  model={candidate['model']}"
            )
            return 0
        if args.auto:
            print("No reusable Hermes/OpenClaw LLM config found.")
            return 2

    tty = _tty()
    try:
        # --- provider -------------------------------------------------------
        provider = args.provider
        if not provider:
            if tty is None and not args.api_key:
                print("error: setup-llm needs a terminal, or pass --provider/--model/--api-key.")
                return 2
            ans = _ask("AI provider for the reviewer — [1] OpenAI (default)  [2] Anthropic: ", tty)
            provider = "anthropic" if ans in ("2", "anthropic") else "openai"

        # --- key source + resolution ---------------------------------------
        source = args.key_source
        api_key = args.api_key or ""
        if not api_key:
            if not source:
                ans = _ask(
                    "API key — [1] from Hermes env (default)  [2] from OpenClaw  [3] paste a new key: ",
                    tty,
                )
                source = {"2": "openclaw", "3": "new"}.get(ans, "hermes")
            api_key = _resolve_key(source, provider)
            if not api_key:
                env_hint = " / ".join(_LLM_KEY_ENV_VARS.get(provider, ()))
                if source != "new":
                    print(f"  No {provider} key found in the environment ({env_hint}).")
                api_key = _ask_secret("  Paste the API key: ", tty)

        if not api_key:
            print("error: no API key provided — nothing saved.")
            return 2

        # --- model ----------------------------------------------------------
        model = (args.model or "").strip()
        if not model:
            default_model = llm.default_model(provider)
            ans = _ask(f"Model id [{default_model}]: ", tty) if tty is not None else ""
            model = ans or default_model

        # --- persist --------------------------------------------------------
        result = settings.write_settings({
            "llm": {"enabled": True, "provider": provider, "model": model, "api_key": api_key},
        })
        if not result.get("ok"):
            print(f"error: could not save settings: {result.get('errors')}")
            return 1
        print(
            f"\nLLM reviewer enabled: provider={provider}  model={model}  key={_mask_key(api_key)}\n"
            "It gives a second opinion on prompt injection over the observer path (never blocks).\n"
            "Disable anytime with:  hermes blackbox setup-llm --disable"
        )
        return 0
    finally:
        if tty is not None:
            try:
                tty.close()
            except Exception:
                pass


def _ask_secret(prompt: str, tty) -> str:
    """Read a secret without echoing when possible; fall back to a plain read."""
    try:
        import getpass

        return getpass.getpass(prompt).strip()
    except Exception:
        return _ask(prompt, tty)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_bumblebee_catalog(catalog: Any) -> bool:
    """Return whether *catalog* uses the bumblebee package-feed shape."""
    if not isinstance(catalog, dict):
        return False
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        return False
    return any(
        isinstance(entry, dict)
        and entry.get("package")
        and isinstance(entry.get("versions"), list)
        for entry in entries
    )


def _flatten_bumblebee(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fan out a bumblebee feed into one dependency per package version."""
    out: List[Dict[str, Any]] = []
    comment = str(catalog.get("_comment") or "").strip()
    default_source = str(catalog.get("source") or "Socket").strip()
    contributor = str(catalog.get("contributor") or "").strip()
    for entry in catalog.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        ecosystem = str(entry.get("ecosystem") or "").strip()
        package = str(entry.get("package") or "").strip()
        versions = entry.get("versions")
        if not (ecosystem and package and isinstance(versions, list)):
            continue
        entry_name = str(entry.get("name") or package).strip()
        severity = entry.get("severity")
        advisory_id = entry.get("id")
        source = str(entry.get("source") or "").strip()
        description = entry_name
        if comment:
            snippet = comment if len(comment) <= 240 else comment[:237].rstrip() + "..."
            description = f"{entry_name} — {snippet}" if entry_name else snippet
        references = [source] if source else []
        for version_value in versions:
            version = str(version_value).strip()
            if not version:
                continue
            out.append(
                {
                    "type": "dependency",
                    "kind": "malware",
                    "ecosystem": ecosystem,
                    "package": package,
                    "version": version,
                    "title": f"{package}@{version}",
                    "description": description,
                    "severity": severity,
                    "advisoryId": advisory_id,
                    "references": references,
                    "source": default_source,
                    "contributor": contributor,
                }
            )
    return out


def _catalog_provenance_defaults(catalog: Any) -> Dict[str, Any]:
    """Return catalog-level provenance inherited by individual entries."""
    if not isinstance(catalog, dict):
        return {}
    defaults: Dict[str, Any] = {}
    source = catalog.get("sources") or catalog.get("source")
    if source:
        defaults["source"] = source
    if catalog.get("contributor"):
        defaults["contributor"] = catalog.get("contributor")
    return defaults


def _apply_provenance_defaults(entry: Dict[str, Any], defaults: Dict[str, Any]) -> None:
    """Fill missing per-entry provenance from catalog-level defaults."""
    if defaults.get("source") and not (entry.get("source") or entry.get("sources")):
        entry["source"] = defaults["source"]
    if defaults.get("contributor") and not entry.get("contributor"):
        entry["contributor"] = defaults["contributor"]


def _entry_provenance(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract named sources, references, and contributor from an entry."""
    raw_sources = entry.get("sources")
    if raw_sources is None:
        raw_sources = entry.get("source")
    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    sources = [str(source).strip() for source in (raw_sources or []) if str(source).strip()]

    raw_references = entry.get("references")
    if isinstance(raw_references, str):
        raw_references = [raw_references]
    references = [
        str(reference).strip()
        for reference in (raw_references or [])
        if str(reference).strip()
    ]
    for source in sources:
        if source.startswith(("http://", "https://")) and source not in references:
            references.append(source)

    contributor = str(entry.get("contributor") or "").strip() or None
    return {"sources": sources, "references": references, "contributor": contributor}


def _flatten_catalog(catalog: Any, forced_type: Optional[str]) -> List[Dict[str, Any]]:
    """Flatten supported threat-catalog shapes into individual entries."""
    if _is_bumblebee_catalog(catalog):
        return _flatten_bumblebee(catalog)
    out: List[Dict[str, Any]] = []
    if isinstance(catalog, list):
        for item in catalog:
            if isinstance(item, dict):
                out.append({**item, **({"type": forced_type} if forced_type else {})})
    elif isinstance(catalog, dict):
        for item in catalog.get("threats", []) or []:
            if isinstance(item, dict):
                out.append({**item, **({"type": forced_type} if forced_type else {})})
        for key, category in (
            ("dependencies", "dependency"),
            ("injection", "injection"),
            ("escalation", "escalation"),
            ("fileaccess", "fileaccess"),
            ("skills", "skill"),
        ):
            for item in catalog.get(key, []) or []:
                if isinstance(item, dict):
                    out.append({"type": category, **item})
        for item in catalog.get("iocs", []) or []:
            if isinstance(item, dict):
                out.append({"type": "ioc", **item})
        out.extend(_flatten_backlog(catalog.get("backlog")))
    defaults = _catalog_provenance_defaults(catalog)
    if defaults:
        for entry in out:
            _apply_provenance_defaults(entry, defaults)
    return out


def _flatten_backlog(backlog: Any) -> List[Dict[str, Any]]:
    """Flatten grouped backlog indicators into importable IOC entries."""
    if not isinstance(backlog, dict):
        return []
    out: List[Dict[str, Any]] = []
    for group in backlog.values():
        if not isinstance(group, list):
            continue
        for item in group:
            if not isinstance(item, dict):
                continue
            rest = {key: value for key, value in item.items() if key != "type"}
            out.append(
                {
                    "type": "ioc",
                    "ioc_type": str(item.get("type") or "").lower(),
                    **rest,
                }
            )
    return out


def _entry_to_threat(entry: Dict[str, Any]) -> tuple:
    """Return ``(category, identifier, fields)`` for a catalog entry."""
    category = str(entry.get("type") or "").lower()
    if category == "ioc":
        ioc_type = str(entry.get("ioc_type") or entry.get("iocType") or "").strip().lower()
        value = str(entry.get("value") or entry.get("indicator") or "").strip()
        if ioc_type in ("ipv4", "ipv6"):
            ioc_type = "ip"
        elif ioc_type in ("sha256", "sha1", "sha512", "md5"):
            if not value.lower().startswith(("sha256:", "sha1:", "sha512:", "md5:")):
                value = f"{ioc_type}:{value}"
            ioc_type = "hash"
        if ioc_type not in quads.IOC_TYPES or not value:
            raise ValueError("ioc needs a supported ioc_type + value")
        identifier = quads.ioc_identifier(ioc_type, value)
        threat = entry.get("threat") or entry.get("title") or entry.get("name")
        return "ioc", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": threat or f"{ioc_type}: {value[:80]}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ioc_type": ioc_type,
            "references": entry.get("references") or [],
        }
    if category == "injection":
        pattern = str(entry.get("pattern") or "").strip()
        if not pattern:
            raise ValueError("injection needs pattern")
        identifier = quads.injection_identifier(pattern)
        return "injection", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"Injection {pattern[:40]}",
            "description": entry.get("summary") or entry.get("description") or "",
            "pattern": pattern,
            "owasp_category": entry.get("owaspCategory") or entry.get("owasp") or "LLM01",
        }
    if category == "escalation":
        tool = str(entry.get("toolName") or entry.get("tool") or "").strip()
        shape = str(entry.get("argShape") or entry.get("arg_shape") or "").strip()
        if not tool or not shape:
            raise ValueError("escalation needs toolName + argShape")
        identifier = quads.escalation_identifier(tool, shape)
        return "escalation", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{tool} :: {shape}",
            "description": entry.get("summary") or entry.get("description") or "",
            "tool_name": tool,
            "arg_shape": shape,
        }
    if category == "dependency":
        ecosystem = str(entry.get("ecosystem") or "").strip()
        name = str(
            entry.get("name") or entry.get("package") or entry.get("package_name") or ""
        ).strip()
        version = str(entry.get("version") or entry.get("package_version") or "").strip()
        if not (ecosystem and name and version):
            raise ValueError("dependency needs ecosystem, name, version")
        if name.startswith("@"):
            name = "@" + name.lstrip("@")
        identifier = quads.dependency_identifier(ecosystem, name, version)
        raw_kind = str(entry.get("kind") or "").strip().lower()
        kind = (
            raw_kind
            if raw_kind in (constants.KIND_MALWARE, constants.KIND_VULNERABILITY)
            else None
        )
        return "dependency", identifier, {
            "severity": constants.severity_for_kind(kind, entry.get("severity")),
            "name": entry.get("title") or entry.get("name") or f"{name}@{version}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ecosystem": ecosystem.lower(),
            "package_name": name,
            "package_version": version,
            "advisory_id": entry.get("advisoryId") or entry.get("advisory_id"),
            "references": entry.get("references") or [],
            "kind": kind,
        }
    if category == "fileaccess":
        tool = str(
            entry.get("toolName") or entry.get("tool") or entry.get("tool_name") or ""
        ).strip()
        file_category = str(entry.get("category") or entry.get("file_category") or "").strip()
        if not tool or not file_category:
            raise ValueError("fileaccess needs tool + category")
        identifier = quads.fileaccess_identifier(tool, file_category)
        return "fileaccess", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{tool} :: {file_category}",
            "description": entry.get("summary") or entry.get("description") or "",
            "tool_name": tool.lower(),
            "file_category": file_category.lower(),
        }
    if category == "skill":
        skill_name = str(
            entry.get("skillName") or entry.get("skill_name") or entry.get("name") or ""
        ).strip()
        skill_version = str(
            entry.get("skillVersion") or entry.get("skill_version") or entry.get("version") or ""
        ).strip()
        danger_shape = str(entry.get("dangerShape") or entry.get("danger_shape") or "").strip()
        if not skill_name or not (skill_version or danger_shape):
            raise ValueError("skill needs name + (version or dangerShape)")
        if skill_version:
            identifier = quads.skill_version_identifier(skill_name, skill_version)
        else:
            identifier = quads.skill_shape_identifier(skill_name, danger_shape)
        return "skill", identifier, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or f"Skill {skill_name}",
            "description": entry.get("summary") or entry.get("description") or "",
            "skill_name": skill_name.lower(),
            "skill_version": skill_version or None,
            "danger_shape": danger_shape or None,
        }
    raise ValueError(f"unknown entry type: {category!r}")


def _resolve_reporter(client: DkgClient) -> str:
    # agent_identity is the definitive token→address resolution; status() is a
    # best-effort fallback for older daemons (same order as hooks._reporter_address).
    for resolver in (client.agent_identity, client.status):
        try:
            info = resolver()
        except Exception:
            continue
        if not isinstance(info, dict):
            continue
        for key in ("agentAddress", "defaultAgentAddress", "address"):
            val = info.get(key)
            if isinstance(val, str) and val:
                return val
    return "node"


def _build_candidate(args: argparse.Namespace) -> tuple:
    """Return ``(identifier, quad_kwargs)`` for ``report``; raise ValueError on bad input."""
    if args.type == "injection":
        if not args.pattern:
            raise ValueError("injection report requires --pattern")
        ident = quads.injection_identifier(args.pattern)
        return ident, {"pattern": args.pattern, "owasp_category": args.owasp}
    if args.type == "escalation":
        if not args.tool or not args.arg_shape:
            raise ValueError("escalation report requires --tool and --arg-shape")
        ident = quads.escalation_identifier(args.tool, args.arg_shape)
        return ident, {"tool_name": args.tool, "arg_shape": args.arg_shape}
    if args.type == "dependency":
        if not (args.ecosystem and args.name and args.version):
            raise ValueError("dependency report requires --ecosystem, --name, --version")
        ident = quads.dependency_identifier(args.ecosystem, args.name, args.version)
        return ident, {
            "ecosystem": args.ecosystem.lower(),
            "package_name": quads.canonical_package_name(args.ecosystem, args.name),
            "package_version": args.version,
            "advisory_id": args.advisory_id,
            "kind": getattr(args, "kind", None),
        }
    if args.type == "fileaccess":
        if not (args.tool and args.category):
            raise ValueError("fileaccess report requires --tool and --category")
        ident = quads.fileaccess_identifier(args.tool, args.category)
        return ident, {
            "tool_name": args.tool.strip().lower(),
            "file_category": args.category.strip().lower(),
        }
    if args.type == "skill":
        if not args.skill_name or not (args.skill_version or args.danger_shape):
            raise ValueError(
                "skill report requires --skill-name and one of --skill-version / --danger-shape"
            )
        if args.skill_version:
            ident = quads.skill_version_identifier(args.skill_name, args.skill_version)
        else:
            ident = quads.skill_shape_identifier(args.skill_name, args.danger_shape)
        return ident, {
            "skill_name": args.skill_name.strip().lower(),
            "skill_version": (args.skill_version or "").strip() or None,
            "danger_shape": (args.danger_shape or "").strip() or None,
        }
    raise ValueError(f"unknown type: {args.type}")
