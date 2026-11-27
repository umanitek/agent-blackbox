"""Action parsing: what a tool call DOES, extracted from its arguments.

``parse_dependency_installs`` lives in :mod:`.command_line.dependency_installs` and is named here for its callers.

Which file a read touches (and its sensitive-path category), which skill is
being installed, which packages a shell command installs, which files it
reads, which URLs it downloads. Pure functions; consumed by the detectors and
by the hook's local activity log.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from typing import Any, Optional
from . import shell_shapes
from .command_line.dependency_installs import parse_dependency_installs   # the packages a command installs by name
from .paths import shell_files

# ---------------------------------------------------------------------------
# Sensitive file-access categories (discovery layer)
# ---------------------------------------------------------------------------

# (category, severity, compiled-path-regex). Matched against the accessed path
# only; the candidate carries ONLY the category + tool — never the exact path.
_SENSITIVE_PATH_RULES = (
    # A file under ~/.ssh that is a key (id_*, or any non-public file) — but NOT
    # the routine non-secret files (config, known_hosts, authorized_keys, *.pub).
    ("ssh-private-key", "critical", re.compile(
        r"(?:^|/)\.ssh/(?!(?:config|known_hosts|authorized_keys)$)(?!.*\.pub$).+"
        r"|(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)", re.IGNORECASE)),
    # A real .env — but NOT the committed, secret-free templates (.example etc.).
    ("env-file", "high", re.compile(
        r"(?:^|/)\.env(?:\.[\w.-]+)?$(?<!\.example)(?<!\.sample)(?<!\.template)(?<!\.dist)(?<!\.default)",
        re.IGNORECASE)),
    ("credentials", "critical", re.compile(
        r"(?:^|/)\.aws/credentials$|(?:^|/)\.netrc$|(?:^|/)\.npmrc$|(?:^|/)\.docker/config\.json$"
        r"|(?:^|/)\.kube/config$|(?:^|/)\.config/gcloud(?:/|$)", re.IGNORECASE)),
    ("password-store", "critical", re.compile(r"(?:^|/)\.password-store(?:/|$)|(?:^|/)\.pgpass$", re.IGNORECASE)),
    # Real browser credential stores only — anchored to a browser profile dir so
    # a project file literally named `Cookies` / `Login Data` isn't misflagged.
    ("browser-cookies", "high", re.compile(
        r"(?:Chrome|Chromium|Brave|Edge|Opera|Vivaldi|BraveSoftware)[\s\S]{0,120}/(?:Cookies|Login Data)$"
        r"|(?:^|/)cookies\.sqlite$|(?:^|/)Cookies\.binarycookies$"
        r"|(?:^|/)Library/Keychains(?:/|$)|(?:^|/)login\.keychain", re.IGNORECASE)),
    ("system-shadow", "critical", re.compile(r"^/etc/(?:shadow|passwd|sudoers)$", re.IGNORECASE)),
)

#: Every sensitive-path category detection can name — the closed vocabulary a
#: community file-access report is validated against (Refine R1).
SENSITIVE_PATH_CATEGORIES = frozenset(category for category, _sev, _rule in _SENSITIVE_PATH_RULES)

# Tools whose args reference a file/path. Value = tuple of candidate arg keys.
_FILE_ACCESS_TOOLS = {
    "read": "read",
    "write": "write",
    "read_file": "read",
    "write_file": "write",
    "edit_file": "write",
    "edit": "write",
    "patch": "write",
    "apply_patch": "write",
    "create_file": "write",
    "delete_file": "write",
    "open_file": "read",
    "cat": "read",
    "skill_manage": "write",
}
_PATH_KEYS = ("path", "file", "file_path", "filepath", "filename", "target", "target_file")


def _npmrc_has_token(args: Any) -> bool:
    """True when a .npmrc write/content carries an ``_authToken`` (credential)."""
    text = shell_shapes.command_from_args("", args) if not isinstance(args, dict) else ""
    if isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str):
                text += "\n" + v
    return "_authtoken" in text.lower()


def file_access_arg(tool_name: str, args: Any) -> Optional[dict[str, str]]:
    """Extract ``{tool, path, mode}`` for a file-access tool call, or ``None``.

    Recognises the file-touching tools in :data:`_FILE_ACCESS_TOOLS`. ``mode``
    is ``read`` or ``write``. Returns ``None`` for non-file tools or missing
    path — pure/deterministic, used for both visibility logging and detection.
    """
    tool = (tool_name or "").strip().lower()
    if tool not in _FILE_ACCESS_TOOLS or not isinstance(args, dict):
        return None
    path = ""
    for key in _PATH_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            path = val.strip()
            break
    if not path:
        return None
    return {"tool": tool, "path": path, "mode": _FILE_ACCESS_TOOLS[tool]}


def _canonical_path(path: str) -> str:
    """*path* in the one spelling the category rules read: ``\\`` as ``/`` (a Windows path), ``//``,
    ``/./`` and ``..`` folded, and macOS's ``/private`` taken off its system folders
    (``/private/etc/sudoers`` is ``/etc/sudoers``). Keyed on the canonical path, never the caller's
    spelling (LES-105)."""
    p = path.strip().replace("\\", "/")
    drive = re.match(r"^[A-Za-z]:(?=/)", p)
    p = (drive.group(0) if drive else "") + posixpath.normpath(p[len(drive.group(0)):] if drive else p)
    return re.sub(r"^/private(?=/(?:etc|var|tmp)(?:/|$))", "", p)


def sensitive_path_category(path: str, args: Any = None) -> Optional[dict[str, str]]:
    """Classify *path* into a sensitive category, or ``None``.

    Returns ``{category, severity}``. The ``.npmrc`` file is only sensitive
    when it carries an ``_authToken`` (checked via *args*) — a bare .npmrc is
    ignored. Deterministic; the caller carries ONLY the category off-box.
    """
    if not path:
        return None
    p = _canonical_path(path)
    if p.endswith(".npmrc"):
        # A token-bearing .npmrc is a credential store, so match the rest of the
        # `credentials` category at `critical` (not `high`).
        return {"category": "credentials", "severity": "critical"} if _npmrc_has_token(args) else None
    for category, severity, pattern in _SENSITIVE_PATH_RULES:
        try:
            if pattern.search(p):
                return {"category": category, "severity": severity}
        except re.error:  # pragma: no cover - static patterns
            continue
    return None

# Tools that install/modify a skill.
#: Tools whose output is a page fetched from the web (Hermes: web_extract,
#: web_search, browser_*): text they return is "in-fetched-page", an indicator
#: in their arguments is "fetched-by-tool" (Refine R1).
FETCH_TOOL_PREFIXES = ("web_", "browser_")

_SKILL_TOOLS = {"skill_manage", "skill_install", "install_skill", "plugin_install", "install_plugin"}
#: The host tool names above, public: a report may name these verbatim (threat-profiles D9).
HOST_FILE_AND_SKILL_TOOLS = frozenset({*_FILE_ACCESS_TOOLS, *_SKILL_TOOLS})
_SKILL_NAME_KEYS = ("name", "skill", "skill_name", "id", "plugin")
_SKILL_VERSION_KEYS = ("version", "skill_version", "ver")
_SKILL_CODE_KEYS = ("code", "content", "source", "body", "script")
_SKILL_PERM_KEYS = ("permissions", "capabilities", "scopes", "allow", "grants")

_MAX_SKILL_SCAN = 20_000


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k} {_stringify(v)}" for k, v in value.items())
    return str(value) if value is not None else ""


def skill_install_arg(tool_name: str, args: Any) -> Optional[dict[str, str]]:
    """Extract a skill install/modify descriptor, or ``None``.

    Returns ``{name, version, code, permissions, artifact_hash}`` (missing
    fields empty). ``code``/``permissions`` are the concatenated content to
    scan; they are NEVER carried off-box. ``artifact_hash`` is the sha256 of
    the FULL code + permissions (before the scan cap): a heuristic report
    names the skill by this hash, never by its name (Refine R1, KI-159), so
    the same skill code converges on one identifier on every node.
    """
    tool = (tool_name or "").strip().lower()
    if tool not in _SKILL_TOOLS or not isinstance(args, dict):
        return None
    name = ""
    for key in _SKILL_NAME_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            name = val.strip()
            break
    if not name:
        return None
    version = ""
    for key in _SKILL_VERSION_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            version = val.strip()
            break
    code = " ".join(_stringify(args.get(k)) for k in _SKILL_CODE_KEYS if args.get(k))
    perms = " ".join(_stringify(args.get(k)) for k in _SKILL_PERM_KEYS if args.get(k))
    # NUL separates the parts so moving text between code and permissions changes the hash.
    artifact_hash = hashlib.sha256(f"{code}\0{perms}".encode("utf-8", "surrogatepass")).hexdigest()
    return {"name": name, "version": version, "code": code[:_MAX_SKILL_SCAN],
            "permissions": perms[:_MAX_SKILL_SCAN], "artifact_hash": artifact_hash}



#: cat-family commands whose following path args are file reads.
def parse_shell_reads(command: str) -> list[str]:
    """Best-effort list of file paths the read, copy and archive commands in *command* touch.

    Completes the audit trail for the shell channel: ``cat ~/.ssh/id_rsa`` is a
    file read that the dedicated file tools would log, but a raw shell tool would
    otherwise miss. The parsing lives in :mod:`.paths.shell_files` (quotes and escapes
    respected); this keeps the paths only. Pure/deterministic.
    """
    return [arg.path for arg in shell_files.shell_file_args(command)]


def parse_downloads(command: str) -> list[str]:
    """URLs fetched by a curl/wget in *command* (for the download audit trail)."""
    if not command or not re.search(r"\b(?:curl|wget)\b", command, re.IGNORECASE):
        return []
    return list(dict.fromkeys(re.findall(r"https?://[^\s;'\"|&>]+", command)))
