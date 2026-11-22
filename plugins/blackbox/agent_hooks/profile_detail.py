"""What one agent profile is ACTUALLY operating under, read from the real files on this machine —
nothing here is assumed or made up; a file that does not exist is simply absent.

For a profile (an agent + one config home) and, optionally, a project folder one of its sessions
worked in: the instruction files in effect (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, rules
folders — user-level, project-level and every folder between the project and the home), the
settings per scope (permission mode, allowed and denied tools, the NAMES of environment
overrides, model), the hooks present (Blackbox's and others), the MCP servers configured, the
sub-agent and skill definitions, where sessions are stored (the path only — a transcript is never
opened) and the program with its version. ``risks`` are sentences derived only from those facts.

READ-ONLY and bounded: at most :data:`MAX_FILES` instruction files of :data:`MAX_TEXT_BYTES`
each, shown through ``kernel.redaction``. Only a home Blackbox already knows
(``profiles.homes``) and a project one of the agent's sessions ran in can be read — never a path
a caller chooses.

Usage::

    from . import profile_detail
    profile_detail.read("claude-code", home_folder, project="/Users/me/app")   # ProfileDetail | None
"""

from __future__ import annotations

import dataclasses
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from ..kernel import code_signing
from ..kernel.agent_hosts import BY_ID, Host
from ..kernel.bounded_files import read_small_text
from ..kernel.redaction import redact_secret_values
from . import permission_risks, profiles, versions
from .instances import store
from .instances.model import Running
from .protect import config_edit
from .protect.config_edit import MARK

__all__ = ["InstructionFile", "McpServer", "ProfileDetail", "ScopeSettings", "read"]

MAX_TEXT_BYTES = 64 * 1024
MAX_SETTINGS_BYTES = 2 * 1024 * 1024
MAX_FILES = 24
MAX_LIST = 60
MAX_ANCESTORS = 8
_SHELLS = ("sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh")

#: Per agent: instruction files in the config home, in a project folder (and each folder above
#: it), rules folders (home / project), settings files (home / project), MCP config files
#: (``~`` = the person's home), definition folders (home / project) and the sessions folder.
LAYOUT: dict[str, dict[str, tuple[str, ...]]] = {
    "claude-code": {"home_docs": ("CLAUDE.md",), "project_docs": ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md"),
                    "home_rules": ("rules",), "project_rules": (".claude/rules",),
                    "home_settings": ("settings.json", "settings.local.json"),
                    "project_settings": (".claude/settings.json", ".claude/settings.local.json"),
                    "mcp": ("~/.claude.json", "{project}/.mcp.json"), "home_defs": ("agents", "skills", "commands"),
                    "project_defs": (".claude/agents", ".claude/skills", ".claude/commands"), "sessions": ("projects",)},
    "codex": {"home_docs": ("AGENTS.md", "AGENTS.override.md"), "project_docs": ("AGENTS.md", "AGENTS.override.md"),
              "home_settings": ("config.toml",), "project_settings": (".codex/config.toml",), "mcp": ("{home}/config.toml",),
              "home_defs": ("prompts", "skills"), "sessions": ("sessions",)},
    "gemini-cli": {"home_docs": (".gemini/GEMINI.md",), "project_docs": ("GEMINI.md",),
                   "home_settings": (".gemini/settings.json",), "project_settings": (".gemini/settings.json",),
                   "mcp": ("{home}/.gemini/settings.json", "{project}/.gemini/settings.json"),
                   "home_defs": (".gemini/commands", ".gemini/extensions"), "sessions": (".gemini/tmp",)},
    "cursor": {"project_docs": (".cursorrules", "AGENTS.md"), "home_rules": ("rules",), "project_rules": (".cursor/rules",),
               "mcp": ("{home}/mcp.json", "{project}/.cursor/mcp.json"), "home_settings": ("cli-config.json",)},
    "copilot-cli": {"home_docs": ("copilot-instructions.md",), "project_docs": (".github/copilot-instructions.md", "AGENTS.md"),
                    "home_settings": ("settings.json",), "mcp": ("{home}/mcp-config.json",), "sessions": ("session-state",)},
    "devin": {"project_docs": ("AGENTS.md", "AGENTS.local.md", "AGENT.md"), "home_settings": ("config.json",),
              "project_settings": (".devin/config.json",), "home_defs": ("skills",), "project_defs": (".devin/skills",)},
    "windsurf": {"home_docs": ("memories/global_rules.md",), "project_docs": (".windsurfrules", "AGENTS.md"),
                 "project_rules": (".windsurf/rules",), "mcp": ("{home}/mcp_config.json",)},
    "cline": {"project_docs": (".clinerules", "AGENTS.md"), "project_rules": (".clinerules",)},
    "opencode": {"home_docs": ("AGENTS.md",), "project_docs": ("AGENTS.md",), "home_settings": ("opencode.json", "opencode.jsonc"),
                 "project_settings": ("opencode.json", ".opencode/opencode.jsonc"), "mcp": ("{home}/opencode.json", "{project}/opencode.json"),
                 "home_defs": ("agents", "plugins"), "project_defs": (".opencode/agents", ".opencode/plugins")},
}


@dataclass(frozen=True)
class InstructionFile:
    path: str
    scope: str            # "user" | "project" | "above the project" | "rules"
    size: int
    modified: float
    text: str             # redacted, at most MAX_TEXT_BYTES ("" when larger or unreadable)
    truncated: bool = False


@dataclass(frozen=True)
class ScopeSettings:
    path: str
    scope: str            # "user" | "project"
    permission_mode: str = ""
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    env_names: tuple[str, ...] = ()
    model: str = ""
    blackbox_hooks: int = 0
    other_hooks: int = 0
    hooks_off: bool = False
    skips_prompts: tuple[str, ...] = ()   # its settings that skip the person's permission prompts
    unloadable: tuple[str, ...] = ()      # why the agent would not run Blackbox's hooks as written (KI-570)


@dataclass(frozen=True)
class McpServer:
    name: str
    source: str           # the file that configures it
    launch: str           # its command line or URL, redacted


#: What the signature says when no program of the agent was found to check.
NO_PROGRAM = "No program of this agent was found on this Mac, so there is no signature to check."


@dataclass
class ProfileDetail:
    agent: str
    name: str
    home: str
    project: str
    program: str = ""
    version: str = ""
    signature: str = NO_PROGRAM         # the signer in a sentence (see ``signer`` for the fields)
    signer: Optional[code_signing.Signer] = None
    sessions_path: str = ""             # where this home keeps its sessions (the path only)
    sessions_exist: bool = False        # whether that folder exists yet (a new home has none)
    running_flags: list[str] = field(default_factory=list)   # flags of its running processes that skip prompts
    instructions: list[InstructionFile] = field(default_factory=list)
    settings: list[ScopeSettings] = field(default_factory=list)
    mcp_servers: list[McpServer] = field(default_factory=list)
    definitions: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


def _doc(path: Path, scope: str) -> Optional[InstructionFile]:
    try:
        info = path.stat()
    except OSError:
        return None
    if not path.is_file():
        return None
    text = read_small_text(str(path), MAX_TEXT_BYTES)
    return InstructionFile(str(path), scope, info.st_size, info.st_mtime, redact_secret_values(text or ""), truncated=text is None)


def _rules(folder: Path) -> list[InstructionFile]:
    try:
        files = sorted(item for item in folder.rglob("*") if item.is_file() and item.suffix in (".md", ".mdc", ".txt", ""))[:MAX_FILES]
    except OSError:
        return []
    return [doc for doc in (_doc(item, "rules") for item in files) if doc is not None]


def _instructions(layout: dict[str, tuple[str, ...]], home: Path, project: Optional[Path], user_home: Path) -> list[InstructionFile]:
    found = [_doc(home / name, "user") for name in layout.get("home_docs", ())]
    for name in layout.get("home_rules", ()):
        found += _rules(home / name)
    if project is not None:
        found += [_doc(project / name, "project") for name in layout.get("project_docs", ())]
        for name in layout.get("project_rules", ()):
            found += _rules(project / name)
        for parent in list(project.parents)[:MAX_ANCESTORS]:   # an instruction file above the project is in effect too
            if parent == user_home or user_home not in parent.parents:
                break
            found += [_doc(parent / name, "above the project") for name in layout.get("project_docs", ())]
    return [doc for doc in found if doc is not None][:MAX_FILES]


def _load(path: Path) -> Optional[dict[str, Any]]:
    text = read_small_text(str(path), MAX_SETTINGS_BYTES)
    if text is None:
        return None
    try:
        data = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text or "{}")
    except (ValueError, tomllib.TOMLDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _names(value: Any) -> tuple[str, ...]:
    return tuple(str(item)[:200] for item in value[:MAX_LIST]) if isinstance(value, list) else ()


def _hook_counts(data: dict[str, Any]) -> tuple[int, int]:
    ours = others = 0
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for entries in hooks.values():
        for entry in entries if isinstance(entries, list) else []:
            inner = entry.get("hooks") if isinstance(entry, dict) and isinstance(entry.get("hooks"), list) else [entry]
            for hook in inner:
                mine = isinstance(hook, dict) and MARK in str(hook.get("command") or "")
                ours, others = ours + mine, others + (not mine)
    return ours, others


def _settings(host: Host, path: Path, scope: str) -> Optional[ScopeSettings]:
    data = _load(path)
    if data is None:
        return None
    permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    mode = str(permissions.get("defaultMode") or data.get("approval_policy") or data.get("sandbox_mode") or "")[:60]
    model = data.get("model") if isinstance(data.get("model"), str) else ""
    ours, others = _hook_counts(data)
    off = any(profiles.lookup(data, key) == value for _name, key, value in host.switches)
    return ScopeSettings(str(path), scope, mode, _names(permissions.get("allow")), _names(permissions.get("deny")),
                         tuple(sorted(str(name)[:80] for name in env)[:MAX_LIST]), model[:80], ours, others, off,
                         tuple(permission_risks.from_settings(host.id, data)),
                         tuple(config_edit.invalid_entries(dataclasses.replace(host, config=str(path)), Path("/")))
                         if host.style == "nested" else ())


def _mcp(path: Path) -> list[McpServer]:
    data = _load(path) or {}
    servers = data.get("mcpServers") or data.get("mcp_servers") or data.get("mcp") or {}
    out = []
    for name, spec in list(servers.items())[:MAX_LIST] if isinstance(servers, dict) else []:
        spec = spec if isinstance(spec, dict) else {}
        command = spec.get("command")
        parts = command if isinstance(command, list) else [command] if command else []
        launch = " ".join(str(part) for part in parts + list(spec.get("args") or [])) or str(spec.get("url") or "")
        out.append(McpServer(str(name)[:120], str(path), redact_secret_values(launch)[:300]))
    return out


def _definitions(folders: list[Path]) -> list[str]:
    out = []
    for folder in folders:
        try:
            out += [str(item) for item in sorted(folder.iterdir())[:MAX_LIST] if not item.name.startswith(".")]
        except OSError:
            continue
    return out[:MAX_LIST * 2]


_SIGNER_KINDS = {"apple": "Apple", "app_store": "the Mac App Store", "developer_id": "Developer ID", "development": "a development certificate"}


def _signature_sentence(found: code_signing.Signer) -> str:
    """*found* as one plain sentence."""
    if found.kind == "script":
        return "A script run by an interpreter (not a signed program)."
    if found.kind == "unsigned":
        return "Not signed."
    if found.kind == "adhoc":
        return "Signed by no one (ad hoc)."
    if found.kind == "invalid":
        return f"Claims to be signed by {found.signer or 'a developer'}, but the signature does not verify."
    if found.verified:
        who = found.signer or _SIGNER_KINDS.get(found.kind, found.kind)
        team = f", team {found.team}" if found.team and found.team not in who else ""
        return f"Signed by {who} ({_SIGNER_KINDS.get(found.kind, found.kind)}{team}); verified" + (", notarised by Apple." if found.notarised else ".")
    return "Its signature could not be checked."


def _risks(detail: ProfileDetail) -> list[str]:
    """Sentences that follow from the facts above — nothing else."""
    risks = []
    if detail.signer is not None and detail.signer.kind == "invalid":
        risks.append(f"The program {detail.program} claims a signer that does not verify.")
    if detail.signer is not None and detail.signer.kind in ("unsigned", "adhoc"):
        risks.append(f"The program {detail.program} is not signed by a known developer.")
    for scope in detail.settings:
        for setting in scope.skips_prompts:
            risks.append(f"Runs with permission prompts skipped ({setting} in {scope.path}): it acts without asking you.")
        if scope.hooks_off:
            risks.append(f"Hooks are switched off in {scope.path}: Blackbox's hooks do not run there.")
        for reason in scope.unloadable:
            risks.append(f"Blackbox's hook in {scope.path} does not protect: {reason}.")
        if scope.scope == "user" and not scope.blackbox_hooks and BY_ID[detail.agent].style in ("nested", "flat"):
            risks.append(f"Blackbox's hooks are not in {scope.path}.")
    for server in detail.mcp_servers:
        words = server.launch.split()
        if words and Path(words[0]).name in _SHELLS:
            risks.append(f"The MCP server \"{server.name}\" starts a shell ({Path(words[0]).name}).")
    for flag in detail.running_flags:
        risks.append(f"A running {detail.name} was started with {flag}, which skips permission prompts: it acts without asking you.")
    if any(doc.truncated for doc in detail.instructions):
        risks.append("An instruction file is larger than Blackbox reads for display; its text is not shown.")
    return risks


def _allowed_project(agent: str, project: str) -> Optional[Path]:
    """*project* only when one of *agent*'s sessions worked in it (a caller cannot name a path)."""
    known = {item.cwd for item in store.all_instances() if item.agent == agent and item.cwd}
    return Path(project) if project and project in known else None


def _flags(agent: str, default: bool, folder: Path, running: Iterable[Running]) -> list[str]:
    """The prompt-skipping flags of *agent*'s processes running in this home (the default home:
    those that name no other)."""
    mine = [proc for proc in running if proc.agent == agent and (proc.profile == str(folder) or (default and not proc.profile))]
    return sorted({flag for proc in mine for flag in proc.skips_prompts})


def read(agent: str, home: str, project: str = "", user_home: Optional[Path] = None,
         running: Iterable[Running] = ()) -> Optional[ProfileDetail]:
    """The detail of *agent*'s profile in the config home *home* (one of ``profiles.homes``), with
    *project*'s own files when a session ran there; *running*: the agent processes now (the
    observer's), whose prompt-skipping flags become risk notes. None for an unknown agent or home."""
    host = BY_ID.get(agent)
    user_home = user_home or Path.home()
    found = next(((path, default) for path, default in profiles.homes(host, user_home) if str(path) == home), None) if host else None
    if host is None or found is None:
        return None
    folder, default = found
    layout = LAYOUT.get(agent, {})
    where = _allowed_project(agent, project)
    detail = ProfileDetail(agent, host.name, str(folder), str(where or ""))
    program = versions.installed(user_home).get(agent)
    if program:
        detail.program, detail.version = program.path, program.version
        detail.signer = code_signing.describe(program.path)
        detail.signature = _signature_sentence(detail.signer)
    # Read from THIS home (a moved one keeps its own), shown even before its first session.
    sessions = [folder / name for name in layout.get("sessions", ())]
    detail.sessions_path = str(sessions[0]) if sessions else ""
    detail.sessions_exist = bool(sessions) and sessions[0].is_dir()
    detail.running_flags = _flags(agent, default, folder, running)
    detail.instructions = _instructions(layout, folder, where, user_home)
    scopes = [(folder / name, "user") for name in layout.get("home_settings", ())]
    scopes += [(where / name, "project") for name in layout.get("project_settings", ())] if where else []
    detail.settings = [found for found in (_settings(host, path, scope) for path, scope in scopes) if found is not None]
    for template in layout.get("mcp", ()):
        if "{project}" in template and where is None:
            continue
        path = template.replace("{home}", str(folder)).replace("{project}", str(where or "")).replace("~", str(user_home), 1)
        detail.mcp_servers += _mcp(Path(path))
    detail.definitions = _definitions([folder / name for name in layout.get("home_defs", ())]
                                      + ([where / name for name in layout.get("project_defs", ())] if where else []))
    detail.risks = _risks(detail)
    return detail
