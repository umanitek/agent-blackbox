"""``blackbox chat`` — a Hermes chat session preconfigured as the Blackbox assistant.

Creates/refreshes the managed ``agent-blackbox`` profile (its SOUL identity, the
pinned context-file cap) and launches Hermes in the source checkout so the
assistant can read the repo's own docs.
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import List, Optional
from .. import attach
from ..kernel import constants, yaml_files

logger = logging.getLogger(__name__)

_BLACKBOX_CHAT_PROFILE = constants.BLACKBOX_CHAT_PROFILE
_BLACKBOX_SOUL_MARKER = constants.BLACKBOX_CHAT_SOUL_MARKER
_LEGACY_MANAGED_SOUL_PREFIX = "<!-- managed-by: hermes-"
_BLACKBOX_SOURCE_ROOT_MARKER = ".blackbox-source-root"
_BLACKBOX_CONTEXT_FILE_MAX_CHARS = 100_000
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
- **Community** (shared working memory / SWM): the open community threat graph.
  Any Blackbox agent contributes privacy-safe threat reports and learns from
  other agents' reports. Community rules FLAG only — they can never block.
  Active only when a community graph is configured and sharing is on.
- **Local** (this node's working memory + synced ruleset): what THIS node has
  pulled down and what it detects with offline. Field name: `ruleset`.

## Where to get each kind of data
Prefer the running dashboard API on http://127.0.0.1:9700 (all read-only, JSON):

- `GET /api/graph-status` — counts + config. Returns `mode`, `context_graph_id`,
  `dkg_url`, `node_reachable`, `last_sync`, `ruleset` (per-category local counts),
  `curated` (Public tier count), `community` (community-tier rule count),
  `sightings`, `findings_logged`.
- `GET /api/graph?tier=public|local&q=<term>&limit=20` — look up threat ENTRIES
  in a tier. Returns `{{tier, threats:[{{identifier, category, severity, name}}], total}}`.
  Always pass `q` (a package, domain, identifier or word) and a small `limit`: a tier
  holds up to a million entries, and their names quote attack phrases. For "how many"
  use the counts in `/api/graph-status`; never fetch a whole tier.
- `GET /api/threat?tier=public&identifier=<id>` — full detail for one
  threat (description, references/advisories, reporters).
- `GET /api/findings?limit=&offset=` — threats Blackbox has flagged on this
  machine (newest first) with total.
- `GET /api/audit?limit=&offset=` — the full agent-activity feed (session
  lifecycle, API requests, tool calls with the real command, installs, flags).
- `GET /api/agents` — connected/protected local agents. Count the `agents` array
  EXACTLY; never estimate from generic Hermes status or sessions.
  `community_agents` (same response) lists OTHER nodes that reported into the
  community graph — never count them as agents connected to this Blackbox.
- `GET /api/reports` — this node's outbound community reports (the ledger).

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
# Commands
# ---------------------------------------------------------------------------


def add_blackbox_chat_args(parser: argparse.ArgumentParser) -> None:
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


def cmd_chat(args: argparse.Namespace) -> int:
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


def _blackbox_chat_args(args: argparse.Namespace) -> list[str]:
    out: list[str] = []
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
        if value is not None:   # "--flag=value": a value starting with "-" is never read as an option
            out.append(f"{flag}={value}")
    for skill in getattr(args, "skills", None) or []:
        out.append(f"--skills={skill}")
    continue_last = getattr(args, "continue_last", None)
    if continue_last is True:
        out.append("--continue")
    elif continue_last:
        out.append(f"--continue={continue_last}")
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
        out.append("--query=" + " ".join(prompt))
    return out


def _blackbox_chat_cwd() -> Optional[Path]:
    candidates: list[Path] = []
    # this file is plugins/blackbox/chat/command.py -> the plugin root is two up
    marker = Path(__file__).resolve().parents[1] / _BLACKBOX_SOURCE_ROOT_MARKER
    try:
        if marker.exists():
            marked = Path(marker.read_text(encoding="utf-8-sig").strip()).expanduser()
            candidates.append(marked)
    except Exception:
        pass
    try:
        candidates.append(attach.repo_root())
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
            existing = soul_path.read_text(encoding="utf-8-sig")
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
    if yaml_files.yaml is None:
        if not config_path.exists():
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                f"context_file_max_chars: {_BLACKBOX_CONTEXT_FILE_MAX_CHARS}\n",
                encoding="utf-8",
            )
        return
    try:
        data = yaml_files.load_for_edit(config_path)
    except yaml_files.UnreadableYaml as exc:
        logger.warning("blackbox chat: %s", exc)   # the profile's config is left as it is
        return
    current = data.get("context_file_max_chars")
    if isinstance(current, int) and current >= _BLACKBOX_CONTEXT_FILE_MAX_CHARS:
        return
    data["context_file_max_chars"] = _BLACKBOX_CONTEXT_FILE_MAX_CHARS
    yaml_files.dump_yaml(config_path, data)


def _blackbox_chat_argv(chat_args: Optional[list[str]], profile: str = _BLACKBOX_CHAT_PROFILE) -> list[str]:
    """The command that runs Hermes' own chat under Blackbox's profile.

    The program comes from Hermes' resolver (``build_relaunch_argv``), never from
    ``sys.argv[0]``: the published launcher runs ``python -I -c <script>``, so there
    ``sys.argv[0]`` is the string ``"-c"`` and exec failed with ``'/sbin/-c'`` (KI-459).
    The resolver gives the real ``hermes`` on PATH, or ``python -m hermes_cli.main``.
    """
    from hermes_cli.relaunch import build_relaunch_argv

    args = [a for a in (chat_args or []) if a != "--"]
    chat = ["--profile", profile, "chat"]
    if args and not args[0].startswith("-"):
        chat.append("--query=" + " ".join(args))
    else:
        chat.extend(args)
    return build_relaunch_argv(chat, preserve_inherited=False)
