"""Auto-protect every local agent — ``blackbox attach`` / ``blackbox detach``.

Discovers local Hermes, OpenClaw, Claude Code, and Codex installations and
enables Blackbox in each, so the user never has to enable it per-instance.

The trick for Hermes is that *a user plugin with the same name as a bundled
plugin replaces it* (``hermes_cli/plugins.py``): copying this plugin into a
home's ``plugins/blackbox/`` and adding ``blackbox`` to ``plugins.enabled`` in
that home's ``config.yaml`` activates it with no bundled-vs-user conflict.

Everything here is pure and testable: each function takes explicit paths, honours
``dry_run`` (no writes), and fails open per target (one bad home never aborts the
rest — the caller collects a per-target report). Only stdlib + PyYAML are used.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.11+ is required by Hermes
    tomllib = None  # type: ignore[assignment]

from . import constants

logger = logging.getLogger(__name__)
_BLACKBOX_CHAT_PROFILE = "blackbox"
_BLACKBOX_CHAT_SOUL_MARKER = "<!-- managed-by: hermes-blackbox-chat -->"
_SOURCE_ROOT_MARKER = ".blackbox-source-root"
_INSTALL_STAMP_MARKER = ".blackbox-install-stamp"

try:  # PyYAML ships with hermes; degrade gracefully if it is somehow absent.
    import yaml
except Exception:  # pragma: no cover - yaml is a hard dep in practice
    yaml = None  # type: ignore[assignment]


# Files/dirs never copied into a target home's plugins/blackbox/ — build
# artifacts and the plugin's own tests have no business in a runtime home.
_COPY_EXCLUDE_DIRS = {"__pycache__", "tests", ".pytest_cache", "node_modules"}
_COPY_EXCLUDE_SUFFIXES = (".pyc", ".pyo")

# The OpenClaw JS plugin is bundled inside an installed copy under this name so
# OpenClaw always has something to load, even when Blackbox was copied into a
# user home with no sibling ``integrations/`` (see ``_openclaw_plugin_source``).
_BUNDLED_OPENCLAW_DIRNAME = "_openclaw"
_BUNDLED_AGENT_HOOKS_DIRNAME = "_agent_hooks"
_OPENCLAW_MIN_VERSION = (2026, 6, 11)
_OPENCLAW_MIN_VERSION_TEXT = ".".join(str(part) for part in _OPENCLAW_MIN_VERSION)
_CODEX_MARKETPLACE_NAME = "agent-blackbox"
_EXTERNAL_HOOK_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _plugin_source_dir() -> Path:
    """Absolute path to this plugin's copy source.

    Installed copies carry ``.blackbox-source-root`` pointing back to the
    checkout that produced them. Prefer that checkout when it still exists so a
    re-run of ``hermes blackbox attach`` refreshes stale user-plugin files from
    the repo instead of copying the installed copy onto itself.
    """
    own = Path(__file__).resolve().parent
    marker = own / _SOURCE_ROOT_MARKER
    try:
        if marker.exists():
            root = Path(marker.read_text(encoding="utf-8").strip()).expanduser()
            candidate = (root / "plugins" / "blackbox").resolve()
            if candidate.is_dir() and candidate != own:
                return candidate
    except Exception:
        pass
    return own


def _repo_root() -> Path:
    """Best-effort repo root: ``<repo>/plugins/blackbox`` → ``<repo>``."""
    return _plugin_source_dir().parents[1]


def discover_hermes_homes() -> List[Path]:
    """Return every local Hermes home directory to protect.

    Includes the resolved default home, ``~/.hermes``, every existing
    ``~/.hermes/profiles/*/`` directory, and (on Windows) ``%LOCALAPPDATA%/hermes``.
    The canonical default is always included even if not yet created; results are
    de-duplicated preserving order.
    """
    homes: List[Path] = []

    def _add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            resolved = path.expanduser()
        except Exception:
            return
        if resolved not in homes:
            homes.append(resolved)

    # The canonical default (honours profile switching / $HERMES_HOME) — always
    # included even if the directory does not exist yet.
    try:
        _add(constants.hermes_home())
    except Exception:  # pragma: no cover - defensive
        pass

    default_dot = Path.home() / ".hermes"
    _add(default_dot)

    # Every existing profile directory under the default home.
    profiles_dir = default_dot / "profiles"
    try:
        if profiles_dir.is_dir():
            for child in sorted(profiles_dir.iterdir()):
                if child.is_dir() and not is_managed_blackbox_chat_profile(child):
                    _add(child)
    except Exception:
        pass

    # Windows: %LOCALAPPDATA%/hermes.
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            _add(Path(local_appdata) / "hermes")

    return homes


def is_managed_blackbox_chat_profile(path: Path) -> bool:
    """Return True for the internal Blackbox control chat profile.

    The dashboard's attach/connected-agent surfaces list protected workloads.
    The managed ``blackbox`` profile is the operator/control profile launched by
    ``hermes blackbox chat``; showing it as a defended agent is misleading.
    """
    try:
        resolved = path.expanduser()
        if resolved.name != _BLACKBOX_CHAT_PROFILE or resolved.parent.name != "profiles":
            return False
        soul = resolved / "SOUL.md"
        return soul.exists() and _BLACKBOX_CHAT_SOUL_MARKER in soul.read_text(encoding="utf-8")
    except Exception:
        return False


def _openclaw_config_path(target: Path) -> Path:
    """Return the config file represented by an OpenClaw attach *target*.

    Standard targets are state directories containing ``openclaw.json``.  An
    explicit ``$OPENCLAW_CONFIG_PATH`` may point at any filename, so discovery
    returns that file directly and this helper keeps both forms supported.
    """
    try:
        if target.is_file() or target.suffix.lower() in {".json", ".json5"}:
            return target
    except OSError:
        pass
    return target / "openclaw.json"


def discover_openclaw_workspaces() -> List[Path]:
    """Return existing local OpenClaw config targets.

    Candidate roots come from ``$OPENCLAW_CONFIG_PATH``,
    ``$OPENCLAW_STATE_DIR``, ``$OPENCLAW_HOME/.openclaw``, and any
    ``~/.openclaw*`` profile directory.  Standard configs are represented by
    their state directory for stable dashboard labels; a custom config filename
    is represented by the file itself.  Results are de-duplicated by config
    path, preserving order.
    """
    candidates: List[Path] = []

    def _add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            resolved = path.expanduser()
        except Exception:
            return
        if resolved not in candidates:
            candidates.append(resolved)

    def _add_config(path: Path) -> None:
        try:
            expanded = path.expanduser()
        except Exception:
            return
        # Keep the long-standing state-directory target shape for the normal
        # filename; only a true custom filename needs to travel as a file.
        _add(expanded.parent if expanded.name == "openclaw.json" else expanded)

    config_path = os.environ.get("OPENCLAW_CONFIG_PATH")
    if config_path and config_path.strip():
        _add_config(Path(config_path.strip()))

    state_dir = os.environ.get("OPENCLAW_STATE_DIR")
    if state_dir and state_dir.strip():
        _add(Path(state_dir.strip()))
    openclaw_home = os.environ.get("OPENCLAW_HOME")
    if openclaw_home and openclaw_home.strip():
        _add(Path(openclaw_home.strip()) / ".openclaw")

    # Glob every ``~/.openclaw*`` profile so any --profile/--dev workspace
    # created after the dashboard started still gets auto-attached.
    try:
        home = Path.home()
        for candidate in sorted(home.glob(".openclaw*")):
            if candidate.is_dir():
                _add(candidate)
    except Exception:  # pragma: no cover - defensive
        pass

    out: List[Path] = []
    seen_configs: set = set()
    for candidate in candidates:
        config = _openclaw_config_path(candidate)
        try:
            if not config.is_file():
                continue
            key = str(config.resolve())
        except OSError:
            continue
        if key in seen_configs:
            continue
        seen_configs.add(key)
        out.append(candidate)
    return out


def _claude_binary() -> Optional[str]:
    return shutil.which("claude")


def discover_claude_homes() -> List[Path]:
    """Return the local Claude Code user-config home when Claude is detected."""
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    candidates = (
        [Path(configured).expanduser()]
        if configured and configured.strip()
        else [Path.home() / ".claude"]
    )
    binary_available = _claude_binary() is not None
    out: List[Path] = []
    for candidate in candidates:
        try:
            if (candidate.is_dir() or binary_available) and candidate not in out:
                out.append(candidate)
        except OSError:
            continue
    return out


def discover_codex_homes() -> List[Path]:
    """Return the local Codex home when a config or Codex runtime is present."""
    configured = os.environ.get("CODEX_HOME")
    candidates = (
        [Path(configured).expanduser()]
        if configured and configured.strip()
        else [Path.home() / ".codex"]
    )
    binary_available = _codex_binary() is not None
    out: List[Path] = []
    for candidate in candidates:
        try:
            if (candidate.is_dir() or binary_available) and candidate not in out:
                out.append(candidate)
        except OSError:
            continue
    return out


def _json5_to_json(text: str) -> str:
    """Convert the JSON5 features commonly used by OpenClaw into strict JSON.

    OpenClaw officially accepts comments, trailing commas, unquoted object keys,
    and single-quoted strings.  Blackbox only needs those syntax features to
    merge one plugin entry; uncommon numeric JSON5 extensions fail safely rather
    than risking replacement of the user's config.
    """
    out: List[str] = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "/" and i + 1 < length and text[i + 1] == "/":
            i += 2
            while i < length and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < length and text[i + 1] == "*":
            i += 2
            while i + 1 < length and text[i : i + 2] != "*/":
                if text[i] in "\r\n":
                    out.append(text[i])
                i += 1
            if i + 1 >= length:
                raise ValueError("unterminated JSON5 block comment")
            i += 2
            continue
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < length:
                cur = text[i]
                i += 1
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    break
            else:
                raise ValueError("unterminated JSON5 string")
            out.append(text[start:i])
            continue
        if ch == "'":
            i += 1
            value: List[str] = []
            while i < length:
                cur = text[i]
                i += 1
                if cur == "'":
                    break
                if cur != "\\":
                    value.append(cur)
                    continue
                if i >= length:
                    raise ValueError("unterminated JSON5 escape")
                esc = text[i]
                i += 1
                if esc in "\r\n":
                    if esc == "\r" and i < length and text[i] == "\n":
                        i += 1
                    continue
                mapped = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0"}
                if esc in mapped:
                    value.append(mapped[esc])
                elif esc == "x" and i + 2 <= length:
                    value.append(chr(int(text[i : i + 2], 16)))
                    i += 2
                elif esc == "u" and i + 4 <= length:
                    value.append(chr(int(text[i : i + 4], 16)))
                    i += 4
                else:
                    value.append(esc)
            else:
                raise ValueError("unterminated JSON5 string")
            out.append(json.dumps("".join(value), ensure_ascii=False))
            continue
        out.append(ch)
        i += 1

    cleaned = "".join(out)

    # Quote unquoted object keys without touching string contents.
    keyed: List[str] = []
    i = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < len(cleaned):
                cur = cleaned[i]
                i += 1
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    break
            keyed.append(cleaned[start:i])
            continue
        if ch in "{,":
            keyed.append(ch)
            i += 1
            while i < len(cleaned) and cleaned[i].isspace():
                keyed.append(cleaned[i])
                i += 1
            match = re.match(r"[$A-Za-z_][$A-Za-z0-9_]*", cleaned[i:])
            if match:
                key = match.group(0)
                end = i + len(key)
                look = end
                while look < len(cleaned) and cleaned[look].isspace():
                    look += 1
                if look < len(cleaned) and cleaned[look] == ":":
                    keyed.append(json.dumps(key))
                    i = end
                    continue
            continue
        keyed.append(ch)
        i += 1

    # Remove trailing commas outside strings.
    strictish = "".join(keyed)
    final: List[str] = []
    i = 0
    while i < len(strictish):
        ch = strictish[i]
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < len(strictish):
                cur = strictish[i]
                i += 1
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    break
            final.append(strictish[start:i])
            continue
        if ch == ",":
            look = i + 1
            while look < len(strictish) and strictish[look].isspace():
                look += 1
            if look < len(strictish) and strictish[look] in "}]":
                i += 1
                continue
        final.append(ch)
        i += 1
    return "".join(final)


def _load_openclaw_config(path: Path) -> Dict[str, Any]:
    """Load an OpenClaw JSON/JSON5 config or raise without modifying it."""
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = json.loads(_json5_to_json(text))
    if not isinstance(data, dict):
        raise ValueError("OpenClaw config root must be an object")
    return data


def _calendar_version(value: Any) -> Optional[tuple]:
    match = re.search(r"(\d{4})\.(\d{1,2})\.(\d{1,2})", str(value or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _openclaw_version(data: Dict[str, Any]) -> Optional[tuple]:
    meta = data.get("meta")
    return _calendar_version(meta.get("lastTouchedVersion")) if isinstance(meta, dict) else None


# ---------------------------------------------------------------------------
# YAML helpers (idempotent, preserve unrelated keys)
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None or not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("blackbox.attach: could not parse %s (%s)", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _atomic_write(path: Path, text: str) -> None:
    """Write *text* via a temp file + rename so a reader never sees a torn file.

    A concurrent auto-attach sweep (or the dashboard reading a config) can race a
    write; ``os.replace`` is atomic on the same filesystem, so readers always see
    either the old or the new complete file, never a half-written one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _dump_yaml(path: Path, data: Dict[str, Any]) -> None:
    _atomic_write(path, yaml.safe_dump(data, default_flow_style=False, sort_keys=False))


def _enabled_list_has(data: Dict[str, Any], name: str) -> bool:
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return False
    enabled = plugins.get("enabled")
    return isinstance(enabled, list) and name in enabled


# ---------------------------------------------------------------------------
# Plugin file copy (dedup, version-aware)
# ---------------------------------------------------------------------------


def _installed_plugin_version(dest: Path) -> Optional[str]:
    """Read ``__version__`` from an installed copy's ``constants.py`` (cheap parse)."""
    const_path = dest / "constants.py"
    if not const_path.exists():
        return None
    try:
        for line in const_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("__version__"):
                _, _, rhs = stripped.partition("=")
                return rhs.strip().strip("'\"")
    except Exception:
        return None
    return None


def _needs_copy(dest: Path) -> bool:
    """True when the plugin should be (re)copied: missing, version bump, or a
    same-version in-place source edit (so dev iteration propagates without a
    manual version bump)."""
    init = dest / "__init__.py"
    if not init.exists():
        return True
    if _installed_plugin_version(dest) != constants.__version__:
        return True
    try:
        src_dir = _plugin_source_dir()
        if not _is_openclaw_plugin_dir(dest / _BUNDLED_OPENCLAW_DIRNAME):
            checkout = _source_checkout_root(src_dir)
            candidates = [src_dir / _BUNDLED_OPENCLAW_DIRNAME]
            if checkout is not None:
                candidates.append(checkout / "integrations" / "openclaw")
            if any(_is_openclaw_plugin_dir(candidate) for candidate in candidates):
                return True
        if not _is_agent_hooks_plugin_dir(dest / _BUNDLED_AGENT_HOOKS_DIRNAME):
            checkout = _source_checkout_root(src_dir)
            candidates = [src_dir / _BUNDLED_AGENT_HOOKS_DIRNAME]
            if checkout is not None:
                candidates.append(checkout / "integrations" / "agent-hooks")
            if any(_is_agent_hooks_plugin_dir(candidate) for candidate in candidates):
                return True
        stamp = dest / _INSTALL_STAMP_MARKER
        installed_at = stamp.stat().st_mtime if stamp.exists() else init.stat().st_mtime
        newest_src = max(
            p.stat().st_mtime for p in src_dir.rglob("*.py") if "__pycache__" not in p.parts
        )
        return newest_src > installed_at
    except Exception:  # pragma: no cover - best effort
        return False


def _copy_ignore(_dir: str, names: List[str]) -> List[str]:
    return [n for n in names if n in _COPY_EXCLUDE_DIRS or n.endswith(_COPY_EXCLUDE_SUFFIXES)]


def _copy_plugin_tree(src: Path, dest: Path) -> None:
    """Copy the plugin tree from *src* to *dest*, excluding pycache/tests.

    Replaces any existing copy so a version bump fully refreshes the files, and
    bundles the OpenClaw JS plugin so an installed copy can still point OpenClaw
    at it (an installed ``plugins/blackbox`` has no sibling ``integrations/``).
    """
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=_copy_ignore)
    _bundle_openclaw_plugin(src, dest)
    _bundle_agent_hooks_plugin(src, dest)
    (dest / _INSTALL_STAMP_MARKER).write_text(constants.__version__, encoding="utf-8")
    source_root = _source_checkout_root(src)
    if source_root is not None:
        try:
            (dest / _SOURCE_ROOT_MARKER).write_text(str(source_root), encoding="utf-8")
        except OSError:
            pass


def _source_checkout_root(src: Path) -> Optional[Path]:
    try:
        resolved = src.resolve()
        root = resolved.parents[1]
        if (root / ".git").exists() and (root / "plugins" / "blackbox").resolve() == resolved:
            return root
    except Exception:
        return None
    return None


def _bundle_openclaw_plugin(src: Path, dest: Path) -> None:
    """Ensure the OpenClaw JS plugin lives at ``dest/_openclaw``.

    Sourced from the source copy's own bundle (a re-copy from another installed
    copy) or the repo checkout (the first copy from ``integrations/openclaw``).
    Best-effort: bundling must never break the Hermes/Python attach, so any
    failure is logged and swallowed — OpenClaw attach then reports itself
    unprotected via ``_openclaw_load_paths_entry`` rather than crashing.
    """
    dest_bundle = dest / _BUNDLED_OPENCLAW_DIRNAME
    if _is_openclaw_plugin_dir(dest_bundle):
        return  # copytree already carried a valid bundle over from *src*
    checkout = _source_checkout_root(src)
    checkout_integration = checkout / "integrations" / "openclaw" if checkout is not None else None
    for candidate in (src / _BUNDLED_OPENCLAW_DIRNAME, checkout_integration, _repo_openclaw_dir()):
        if candidate is None:
            continue
        if not _is_openclaw_plugin_dir(candidate):
            continue
        try:
            if dest_bundle.exists():
                shutil.rmtree(dest_bundle)
            shutil.copytree(candidate, dest_bundle, ignore=_openclaw_ignore)
        except Exception as exc:  # pragma: no cover - best effort
            logger.debug("blackbox.attach: bundling OpenClaw plugin failed: %s", exc)
        return


def _openclaw_ignore(_dir: str, names: List[str]) -> List[str]:
    """Exclude deps/build/test dirs from the bundled OpenClaw plugin."""
    skip = {"node_modules", "dist", ".turbo", "test", "tests", "__pycache__"}
    return [n for n in names if n in skip or n.endswith((".pyc", ".log", ".tsbuildinfo"))]


def _repo_agent_hooks_dir() -> Path:
    return _repo_root() / "integrations" / "agent-hooks"


def _is_agent_hooks_plugin_dir(path: Path) -> bool:
    try:
        return (
            (path / ".codex-plugin" / "plugin.json").is_file()
            and (path / "hooks" / "hooks.json").is_file()
        )
    except OSError:
        return False


def _bundle_agent_hooks_plugin(src: Path, dest: Path) -> None:
    """Bundle the Claude/Codex hook package into installed Blackbox copies."""
    dest_bundle = dest / _BUNDLED_AGENT_HOOKS_DIRNAME
    if _is_agent_hooks_plugin_dir(dest_bundle):
        return
    checkout = _source_checkout_root(src)
    checkout_integration = checkout / "integrations" / "agent-hooks" if checkout else None
    for candidate in (
        src / _BUNDLED_AGENT_HOOKS_DIRNAME,
        checkout_integration,
        _repo_agent_hooks_dir(),
    ):
        if candidate is None or not _is_agent_hooks_plugin_dir(candidate):
            continue
        try:
            if dest_bundle.exists():
                shutil.rmtree(dest_bundle)
            shutil.copytree(candidate, dest_bundle, ignore=_copy_ignore)
        except Exception as exc:  # pragma: no cover - best effort
            logger.debug("blackbox.attach: bundling agent hooks failed: %s", exc)
        return


# ---------------------------------------------------------------------------
# Hermes attach / detach
# ---------------------------------------------------------------------------


def attach_hermes(home: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Enable Blackbox in a single Hermes *home*.

    Copies the plugin into ``<home>/plugins/blackbox/`` (only when missing or a
    version mismatch) and adds ``blackbox`` to ``plugins.enabled`` in
    ``<home>/config.yaml`` idempotently, preserving every other key. Returns a
    per-target report dict; fails open (``ok=False`` + ``error`` on failure).
    """
    home = home.expanduser()
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "hermes",
        "ok": False,
        "protected": False,
        "copied": False,
        "enabled": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        src = _plugin_source_dir()
        dest = home / "plugins" / "blackbox"
        # Don't copy a home onto itself (e.g. running from inside a home).
        same_tree = src == dest or src == dest.resolve() if dest.exists() else False
        needs = (not same_tree) and _needs_copy(dest)
        files_ready = same_tree or not needs
        if needs and not dry_run:
            _copy_plugin_tree(src, dest)
        report["copied"] = needs

        config_path = home / "config.yaml"
        data = _load_yaml(config_path)
        config_enabled = _enabled_list_has(data, "blackbox")
        if config_enabled and files_ready:
            report["already"] = True
        elif not config_enabled:
            if not dry_run:
                plugins = data.setdefault("plugins", {})
                if not isinstance(plugins, dict):
                    plugins = {}
                    data["plugins"] = plugins
                enabled = plugins.get("enabled")
                if not isinstance(enabled, list):
                    enabled = []
                    plugins["enabled"] = enabled
                if "blackbox" not in enabled:
                    enabled.append("blackbox")
                _dump_yaml(config_path, data)
            report["enabled"] = True
        # A dry-run reports the protection that exists now, not the state an
        # attach *could* create.  This keeps dashboard cards honest when config
        # says enabled but the plugin files are missing or stale.
        report["protected"] = (config_enabled and files_ready) if dry_run else True
        report["ok"] = True
    except Exception as exc:  # fail open per target
        logger.debug("blackbox.attach: attach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


def detach_hermes(home: Path, *, remove_files: bool = False, dry_run: bool = False) -> Dict[str, Any]:
    """Disable Blackbox in a single Hermes *home*.

    Removes ``blackbox`` from ``plugins.enabled`` (idempotent) and, when
    *remove_files* is set, deletes ``<home>/plugins/blackbox/``. Fails open.
    """
    home = home.expanduser()
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "hermes",
        "ok": False,
        "disabled": False,
        "removed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        config_path = home / "config.yaml"
        data = _load_yaml(config_path)
        if _enabled_list_has(data, "blackbox"):
            if not dry_run:
                data["plugins"]["enabled"] = [p for p in data["plugins"]["enabled"] if p != "blackbox"]
                _dump_yaml(config_path, data)
            report["disabled"] = True
        else:
            report["already"] = True

        dest = home / "plugins" / "blackbox"
        if remove_files and dest.exists():
            if not dry_run:
                shutil.rmtree(dest)
            report["removed"] = True
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# OpenClaw attach / detach
# ---------------------------------------------------------------------------


def _repo_openclaw_dir() -> Path:
    """The OpenClaw JS plugin in a repo checkout (sibling ``integrations/``)."""
    return _repo_root() / "integrations" / "openclaw"


def _bundled_openclaw_dir() -> Path:
    """The OpenClaw JS plugin bundled inside this (possibly installed) copy."""
    return _plugin_source_dir() / _BUNDLED_OPENCLAW_DIRNAME


def _is_openclaw_plugin_dir(path: Path) -> bool:
    """True when *path* is the OpenClaw plugin (identified by its manifest)."""
    try:
        return (path / "openclaw.plugin.json").is_file()
    except Exception:
        return False


def _openclaw_plugin_source() -> Optional[Path]:
    """Locate the OpenClaw JS plugin wherever this Blackbox copy runs from.

    An installed copy (``~/.hermes/plugins/blackbox``) has no sibling
    ``integrations/``, so the plugin is bundled into ``_openclaw`` at copy time
    and checked first; a repo checkout finds it via ``integrations/openclaw``.
    Returns ``None`` only when neither exists (e.g. a bare package with no repo),
    which the caller reports as an unprotected OpenClaw rather than a crash.
    """
    for candidate in (_bundled_openclaw_dir(), _repo_openclaw_dir()):
        if _is_openclaw_plugin_dir(candidate):
            return candidate
    return None


def _openclaw_load_paths_entry() -> Optional[str]:
    """Absolute path OpenClaw should load the Blackbox plugin from, or ``None``."""
    src = _openclaw_plugin_source()
    return str(src) if src is not None else None


def _same_openclaw_load_path(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return Path(left).expanduser().resolve() == Path(right).expanduser().resolve()
    except Exception:
        return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _is_blackbox_openclaw_load_path(value: Any) -> bool:
    """Recognize current or stale Blackbox OpenClaw plugin paths.

    Existing paths are identified by manifest id.  Known checkout/bundle path
    shapes cover stale directories that no longer exist, while deliberately not
    matching the pre-Blackbox ``plugins/guardian/_openclaw`` integration.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    path = Path(value).expanduser()
    try:
        manifest = path / "openclaw.plugin.json"
        if manifest.is_file():
            data = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("id") == "blackbox":
                return True
    except Exception:
        pass
    normalized = value.replace("\\", "/").rstrip("/").lower()
    if normalized.endswith("/plugins/blackbox/_openclaw"):
        return True
    if normalized.endswith("/integrations/openclaw"):
        return any(
            marker in normalized
            for marker in ("/agent-blackbox/", "/blackbox-", "/blackbox/")
        )
    return False


def _is_missing_pre_blackbox_load_path(value: Any) -> bool:
    """True for a vanished pre-Blackbox OpenClaw bundle path."""
    if not isinstance(value, str) or not value.strip():
        return False
    normalized = value.replace("\\", "/").rstrip("/").lower()
    if not normalized.endswith("/plugins/guardian/_openclaw"):
        return False
    try:
        return not Path(value).expanduser().exists()
    except OSError:
        return True


def attach_openclaw(workspace: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Enable Blackbox in a single OpenClaw *workspace*.

    Backs up ``openclaw.json``, then idempotently merges:

    * ``plugins.allow`` += ``"blackbox"``
    * ``plugins.load.paths`` += the absolute path to ``integrations/openclaw``
    * ``plugins.entries.blackbox`` = the Blackbox config + hook grants

    Preserves every other key. Fails open per target.
    """
    workspace = workspace.expanduser()
    config_path = _openclaw_config_path(workspace)
    report: Dict[str, Any] = {
        "target": str(workspace),
        "config_path": str(config_path),
        "kind": "openclaw",
        "ok": False,
        "protected": False,
        "changed": False,
        "already": False,
        "backed_up": False,
        "dry_run": dry_run,
    }
    try:
        if not config_path.is_file():
            raise FileNotFoundError(f"OpenClaw config not found: {config_path}")
        data = _load_openclaw_config(config_path)

        detected_version = _openclaw_version(data)
        if detected_version is not None:
            report["version"] = ".".join(str(part) for part in detected_version)
            if detected_version < _OPENCLAW_MIN_VERSION:
                report["unsupported"] = True
                report["error"] = (
                    f"OpenClaw {report['version']} is unsupported; "
                    f"Blackbox requires OpenClaw {_OPENCLAW_MIN_VERSION_TEXT}+"
                )
                return report

        cfg = load_blackbox_config_snapshot()
        load_path = _openclaw_load_paths_entry()
        if load_path is None:
            report["note"] = (
                "integrations/openclaw not found next to this Blackbox copy "
                "(likely copied into a user home); recording intent without a load path."
            )
            logger.info("blackbox.attach: %s", report["note"])

        changed = _merge_openclaw(data, cfg, load_path)
        report["changed"] = changed
        report["already"] = not changed
        report["protected"] = load_path is not None and not changed if dry_run else load_path is not None

        if changed and not dry_run:
            # Back up before writing.
            if config_path.exists():
                backup = config_path.with_name(config_path.name + ".blackbox.bak")
                shutil.copy2(config_path, backup)
                report["backed_up"] = True
            _atomic_write(config_path, json.dumps(data, indent=2) + "\n")
        # Honest status: without a load path the blackbox block is recorded but
        # OpenClaw won't actually load the hook, so this workspace isn't protected.
        report["ok"] = load_path is not None
    except Exception as exc:
        logger.debug("blackbox.attach: attach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


def _merge_openclaw(data: Dict[str, Any], cfg: Dict[str, Any], load_path: Optional[str]) -> bool:
    """Idempotently merge the Blackbox block into an ``openclaw.json`` dict.

    Returns ``True`` when anything changed. Pure (mutates *data* in place); the
    caller decides whether to persist.
    """
    changed = False
    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
        data["plugins"] = plugins

    allow = plugins.get("allow")
    if not isinstance(allow, list):
        allow = []
        plugins["allow"] = allow
    if "blackbox" not in allow:
        allow.append("blackbox")
        changed = True

    if load_path is not None:
        load = plugins.get("load")
        if not isinstance(load, dict):
            load = {}
            plugins["load"] = load
        paths = load.get("paths")
        if not isinstance(paths, list):
            paths = []
            load["paths"] = paths
        # One plugin id must resolve from one source.  Remove older Blackbox
        # checkout/bundle paths so OpenClaw cannot load a stale copy first.
        kept = [
            path
            for path in paths
            if not _is_missing_pre_blackbox_load_path(path)
            and (_same_openclaw_load_path(path, load_path) or not _is_blackbox_openclaw_load_path(path))
        ]
        if kept != paths:
            paths[:] = kept
            changed = True
        if not any(_same_openclaw_load_path(path, load_path) for path in paths):
            paths.append(load_path)
            changed = True

    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        entries = {}
        plugins["entries"] = entries
    desired_entry = {
        "enabled": True,
        "config": {
            "dkgUrl": cfg["dkg_url"],
            "dkgHome": cfg["dkg_home"],
            "contextGraphId": cfg["context_graph_id"],
            "mode": cfg["mode"],
            # Point OpenClaw's local findings log at THIS Hermes blackbox home so
            # the one dashboard surfaces OpenClaw detections too. OpenClaw writes
            # findings.openclaw.jsonl here; the dashboard merges all findings*.jsonl.
            "blackboxHome": cfg.get("blackbox_home") or str(constants.blackbox_home()),
        },
        "hooks": {"allowConversationAccess": True},
    }
    if entries.get("blackbox") != desired_entry:
        entries["blackbox"] = desired_entry
        changed = True
    return changed


def detach_openclaw(workspace: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Disable Blackbox in a single OpenClaw *workspace* (idempotent, fail-open)."""
    workspace = workspace.expanduser()
    config_path = _openclaw_config_path(workspace)
    report: Dict[str, Any] = {
        "target": str(workspace),
        "kind": "openclaw",
        "ok": False,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        if not config_path.exists():
            report["already"] = True
            report["ok"] = True
            return report
        data = _load_openclaw_config(config_path)
        plugins = data.get("plugins")
        changed = False
        if isinstance(plugins, dict):
            allow = plugins.get("allow")
            if isinstance(allow, list) and "blackbox" in allow:
                plugins["allow"] = [p for p in allow if p != "blackbox"]
                changed = True
            load = plugins.get("load")
            if isinstance(load, dict) and isinstance(load.get("paths"), list):
                # Remove ANY blackbox openclaw load path, not just the one that
                # resolves from this location — detaching an installed home would
                # otherwise orphan an entry pointing at a now-removed plugin.
                kept = [
                    p for p in load["paths"]
                    if not _is_blackbox_openclaw_load_path(p)
                ]
                if len(kept) != len(load["paths"]):
                    load["paths"] = kept
                    changed = True
            entries = plugins.get("entries")
            if isinstance(entries, dict) and "blackbox" in entries:
                del entries["blackbox"]
                changed = True
        report["changed"] = changed
        report["already"] = not changed
        if changed and not dry_run:
            _atomic_write(config_path, json.dumps(data, indent=2) + "\n")
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# Claude Code + Codex lifecycle-hook adapters
# ---------------------------------------------------------------------------


def _agent_hooks_plugin_source() -> Optional[Path]:
    for candidate in (
        _plugin_source_dir() / _BUNDLED_AGENT_HOOKS_DIRNAME,
        _repo_agent_hooks_dir(),
    ):
        if _is_agent_hooks_plugin_dir(candidate):
            return candidate
    return None


def _external_hook_source() -> Optional[Path]:
    candidate = _plugin_source_dir() / "external_hook.py"
    return candidate if candidate.is_file() else None


def _external_hook_runtime_fingerprint(source: Path) -> str:
    """Fingerprint the files copied into an immutable external-hook runtime."""
    digest = hashlib.sha256()
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        relative = path.relative_to(source)
        if any(part in _COPY_EXCLUDE_DIRS for part in relative.parts):
            continue
        if path.name.endswith(_COPY_EXCLUDE_SUFFIXES):
            continue
        digest.update(str(relative).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _prepare_external_hook_runtime(*, dry_run: bool = False) -> Path:
    """Return a stable, immutable runtime outside the active checkout.

    Claude Code and Codex retain hook commands across launches. Pointing those
    commands into the source checkout made a branch switch remove the target
    script and caused a visible hook error on every prompt. Content-addressed
    copies under ``BLACKBOX_HOME`` remain valid across branch switches and let
    an update publish a new runtime before either host's config is changed.
    """
    source = _plugin_source_dir()
    if _external_hook_source() is None:
        raise FileNotFoundError("Blackbox external-hook runtime is missing")
    fingerprint = _external_hook_runtime_fingerprint(source)
    runtimes = constants.blackbox_home() / "agent-hooks" / "runtimes"
    version_root = runtimes / fingerprint
    runtime_dir = version_root / "blackbox"
    runtime = runtime_dir / "external_hook.py"
    if dry_run or runtime.is_file():
        return runtime

    runtimes.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{fingerprint}.", dir=str(runtimes)))
    try:
        _copy_plugin_tree(source, temporary / "blackbox")
        # A managed hook runtime must remain self-contained. Installed Hermes
        # copies keep this marker so they can refresh from a checkout, but that
        # behavior would reintroduce branch dependence here.
        (temporary / "blackbox" / _SOURCE_ROOT_MARKER).unlink(missing_ok=True)
        if not (temporary / "blackbox" / "external_hook.py").is_file():
            raise FileNotFoundError("Prepared Blackbox external-hook runtime is incomplete")
        try:
            os.replace(temporary, version_root)
        except OSError:
            # Another concurrent attach may have published the same immutable
            # runtime first. Its validated destination is equivalent.
            if not runtime.is_file():
                raise
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    if not runtime.is_file():
        raise FileNotFoundError("Prepared Blackbox external-hook runtime is missing")
    return runtime


def _hook_commands(framework: str, runtime: Path) -> Dict[str, Any]:
    argv = [sys.executable, str(runtime), "--framework", framework]
    if framework == "claude-code":
        # Claude's documented exec form avoids shell parsing entirely, so
        # absolute paths containing spaces and shell metacharacters are safe.
        return {"command": sys.executable, "args": argv[1:]}
    windows = subprocess.list2cmdline(argv)
    return {
        "command": windows if os.name == "nt" else shlex.join(argv),
        "commandWindows": windows,
    }


def _hook_config(framework: str, runtime: Path) -> Dict[str, Any]:
    commands = _hook_commands(framework, runtime)

    def handler(status: str = "") -> Dict[str, Any]:
        item: Dict[str, Any] = {
            "type": "command",
            **commands,
            "timeout": 30,
        }
        if framework != "codex":
            item.pop("commandWindows", None)
        if status:
            item["statusMessage"] = status
        return item

    return {
        "description": "Agent Blackbox prompt and tool-call security hooks.",
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "*",
                    "hooks": [handler("Starting Agent Blackbox")],
                }
            ],
            "UserPromptSubmit": [
                {"hooks": [handler("Scanning prompt with Agent Blackbox")]}
            ],
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [handler("Checking tool call with Agent Blackbox")],
                }
            ],
            "PostToolUse": [{"matcher": "*", "hooks": [handler()]}],
            "Stop": [{"hooks": [handler()]}],
        },
    }


def _is_blackbox_command_hook(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    parts = [item.get("command"), item.get("commandWindows")]
    args = item.get("args")
    if isinstance(args, list):
        parts.extend(args)
    command = " ".join(str(part or "") for part in parts).lower()
    return (
        "external_hook.py" in command
        and "--framework" in command
        and ("claude-code" in command or "codex" in command)
    ) or "blackbox_hook.py" in command


def _merge_claude_hooks(data: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """Replace only Blackbox-owned Claude hook handlers, preserving all others."""
    before = json.dumps(data, sort_keys=True)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks
    desired_hooks = desired.get("hooks") or {}
    for event in _EXTERNAL_HOOK_EVENTS:
        kept_groups: List[Dict[str, Any]] = []
        groups = hooks.get(event)
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict):
                    continue
                handlers = group.get("hooks")
                if not isinstance(handlers, list):
                    kept_groups.append(group)
                    continue
                remaining = [item for item in handlers if not _is_blackbox_command_hook(item)]
                if remaining:
                    kept_groups.append({**group, "hooks": remaining})
        kept_groups.extend(desired_hooks.get(event) or [])
        hooks[event] = kept_groups
    return json.dumps(data, sort_keys=True) != before


def _remove_claude_hooks(data: Dict[str, Any]) -> bool:
    before = json.dumps(data, sort_keys=True)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    for event in list(_EXTERNAL_HOOK_EVENTS):
        groups = hooks.get(event)
        if not isinstance(groups, list):
            continue
        kept: List[Dict[str, Any]] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                kept.append(group)
                continue
            remaining = [item for item in handlers if not _is_blackbox_command_hook(item)]
            if remaining:
                kept.append({**group, "hooks": remaining})
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if not hooks:
        data.pop("hooks", None)
    return json.dumps(data, sort_keys=True) != before


def _claude_has_blackbox_hooks(data: Dict[str, Any]) -> bool:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    seen = set()
    for event in _EXTERNAL_HOOK_EVENTS:
        for group in hooks.get(event) or []:
            if not isinstance(group, dict):
                continue
            if any(
                _is_blackbox_command_hook(item) and _blackbox_command_hook_ready(item)
                for item in group.get("hooks") or []
            ):
                seen.add(event)
    return seen == set(_EXTERNAL_HOOK_EVENTS)


def _blackbox_command_hook_ready(item: Any) -> bool:
    """Return whether a Blackbox handler's executable and runtime still exist."""
    if not _is_blackbox_command_hook(item):
        return False
    command = str(item.get("command") or "")
    args = item.get("args")
    if isinstance(args, list):
        runtime = next(
            (
                Path(str(arg)).expanduser()
                for arg in args
                if str(arg).endswith("external_hook.py")
            ),
            None,
        )
        executable_ready = not os.path.isabs(command) or Path(command).is_file()
        return bool(
            executable_ready
            and runtime is not None
            and _managed_external_hook_runtime_ready(runtime)
        )

    shell_command = command or str(item.get("commandWindows") or "")
    try:
        tokens = shlex.split(shell_command, posix=os.name != "nt")
    except ValueError:
        return False
    runtime = next(
        (
            Path(token.strip("\"'")).expanduser()
            for token in tokens
            if token.strip("\"'").endswith("external_hook.py")
        ),
        None,
    )
    return bool(runtime is not None and _managed_external_hook_runtime_ready(runtime))


def _managed_external_hook_runtime_ready(runtime: Path) -> bool:
    """Require Claude hooks to use the branch-independent managed runtime."""
    try:
        root = (constants.blackbox_home() / "agent-hooks" / "runtimes").resolve()
        return runtime.is_file() and root in runtime.resolve().parents
    except OSError:
        return False


def attach_claude(home: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Install zero-configuration user hooks into Claude Code settings."""
    home = home.expanduser()
    settings = home / "settings.json"
    report: Dict[str, Any] = {
        "target": str(home),
        "config_path": str(settings),
        "kind": "claude-code",
        "ok": False,
        "available": home.is_dir() or _claude_binary() is not None,
        "protected": False,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        runtime = _prepare_external_hook_runtime(dry_run=dry_run)
        desired = _hook_config("claude-code", runtime)
        if settings.exists():
            data = json.loads(settings.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Claude settings root must be an object")
        else:
            data = {}
        protected_before = _claude_has_blackbox_hooks(data)
        changed = _merge_claude_hooks(data, desired)
        report["changed"] = changed
        report["already"] = protected_before and not changed
        report["protected"] = protected_before if dry_run else True
        if changed and not dry_run:
            if settings.exists():
                shutil.copy2(settings, settings.with_name("settings.json.blackbox.bak"))
                report["backed_up"] = True
            _atomic_write(settings, json.dumps(data, indent=2) + "\n")
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: attach_claude(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


def detach_claude(home: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    home = home.expanduser()
    settings = home / "settings.json"
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "claude-code",
        "ok": False,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        if not settings.exists():
            report.update(ok=True, already=True)
            return report
        data = json.loads(settings.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Claude settings root must be an object")
        changed = _remove_claude_hooks(data)
        report["changed"] = changed
        report["already"] = not changed
        if changed and not dry_run:
            _atomic_write(settings, json.dumps(data, indent=2) + "\n")
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_claude(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


def _codex_binary() -> Optional[str]:
    found = shutil.which("codex")
    if found:
        return found
    if sys.platform == "darwin":
        bundled = Path("/Applications/ChatGPT.app/Contents/Resources/codex")
        if bundled.is_file() and os.access(bundled, os.X_OK):
            return str(bundled)
    return None


def _codex_env(home: Path) -> Dict[str, str]:
    env = dict(os.environ)
    default = Path.home() / ".codex"
    try:
        if home.resolve() != default.resolve():
            env["CODEX_HOME"] = str(home)
    except OSError:
        env["CODEX_HOME"] = str(home)
    return env


def _run_codex_json(binary: str, home: Path, *args: str) -> Dict[str, Any]:
    completed = subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
        env=_codex_env(home),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Codex command failed").strip()
        raise RuntimeError(detail[-2000:])
    text = completed.stdout.strip()
    if not text:
        return {}
    data = json.loads(text)
    return data if isinstance(data, dict) else {"result": data}


def _plugin_fingerprint(source: Path, command: str) -> str:
    digest = hashlib.sha256(command.encode("utf-8"))
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(source)).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def _prepare_codex_marketplace(home: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    source = _agent_hooks_plugin_source()
    if source is None:
        raise FileNotFoundError("Blackbox Claude/Codex hook bundle is missing")
    runtime = _prepare_external_hook_runtime(dry_run=dry_run)
    config = _hook_config("codex", runtime)
    root = constants.blackbox_home() / "agent-hooks" / "codex-marketplace"
    plugin = root / "plugins" / "blackbox"
    command = str(config["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
    version = f"{constants.__version__}+codex.{_plugin_fingerprint(source, command)}"
    current_version = ""
    try:
        current_version = str(
            json.loads((plugin / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
            .get("version")
            or ""
        )
    except Exception:
        pass
    expected_hooks = json.dumps(config, indent=2) + "\n"
    try:
        installed_hooks = (plugin / "hooks" / "hooks.json").read_text(encoding="utf-8")
    except OSError:
        installed_hooks = ""
    changed = current_version != version or installed_hooks != expected_hooks
    marketplace = {
        "name": _CODEX_MARKETPLACE_NAME,
        "interface": {"displayName": "Agent Blackbox"},
        "plugins": [
            {
                "name": "blackbox",
                "source": {"source": "local", "path": "./plugins/blackbox"},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Engineering",
            }
        ],
    }
    if not dry_run:
        if changed:
            if plugin.exists():
                shutil.rmtree(plugin)
            shutil.copytree(source, plugin, ignore=_copy_ignore)
            manifest_path = plugin / ".codex-plugin" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = version
            _atomic_write(manifest_path, json.dumps(manifest, indent=2) + "\n")
            _atomic_write(plugin / "hooks" / "hooks.json", expected_hooks)
        marketplace_path = root / ".agents" / "plugins" / "marketplace.json"
        expected_marketplace = json.dumps(marketplace, indent=2) + "\n"
        if not marketplace_path.exists() or marketplace_path.read_text(encoding="utf-8") != expected_marketplace:
            _atomic_write(marketplace_path, expected_marketplace)
            changed = True
    return {"root": root, "plugin": plugin, "version": version, "changed": changed}


def _codex_config(home: Path) -> Dict[str, Any]:
    path = home / "config.toml"
    if tomllib is None or not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _codex_plugin_enabled(home: Path) -> bool:
    plugins = _codex_config(home).get("plugins")
    if not isinstance(plugins, dict):
        return False
    entry = plugins.get(f"blackbox@{_CODEX_MARKETPLACE_NAME}")
    return isinstance(entry, dict) and entry.get("enabled", True) is not False


def _codex_hooks_trusted(home: Path) -> bool:
    hooks = _codex_config(home).get("hooks")
    state = hooks.get("state") if isinstance(hooks, dict) else None
    if not isinstance(state, dict):
        return False
    required = {"session_start", "user_prompt_submit", "pre_tool_use", "post_tool_use", "stop"}
    trusted = set()
    for key, value in state.items():
        key_text = str(key).replace("\\", "/").lower()
        if "blackbox" not in key_text or "hooks.json:" not in key_text:
            continue
        if not isinstance(value, dict) or not str(value.get("trusted_hash") or "").startswith("sha256:"):
            continue
        event_part = key_text.split("hooks.json:", 1)[1].split(":", 1)[0]
        trusted.add(event_part)
    return required.issubset(trusted)


def attach_codex(home: Path, *, dry_run: bool = False, binary: Optional[str] = None) -> Dict[str, Any]:
    """Install the local Codex plugin without bypassing Codex hook trust."""
    home = home.expanduser()
    binary = binary or _codex_binary()
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "codex",
        "ok": False,
        "available": bool(binary),
        "installed": False,
        "protected": False,
        "trust_required": True,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        if not binary:
            raise FileNotFoundError("Codex CLI was not found; update or launch Codex, then run `blackbox attach`")
        prepared = _prepare_codex_marketplace(home, dry_run=dry_run)
        report["plugin_version"] = prepared["version"]
        report["marketplace"] = str(prepared["root"])
        report["changed"] = bool(prepared["changed"])
        if dry_run:
            enabled = _codex_plugin_enabled(home)
            trusted = enabled and _codex_hooks_trusted(home)
            report.update(
                ok=True,
                installed=enabled,
                protected=trusted,
                trust_required=not trusted,
                already=enabled and not prepared["changed"],
            )
            return report

        try:
            marketplaces = _run_codex_json(
                binary, home, "plugin", "marketplace", "list", "--json"
            )
        except RuntimeError as exc:
            # Codex validates configured marketplaces before returning the list.
            # A previous Blackbox install may point at a deleted temp/checkout
            # directory, which makes the list command fail before we can compare
            # and replace our own entry. Remove only our marketplace, then retry;
            # unrelated invalid marketplaces remain the user's responsibility.
            if _CODEX_MARKETPLACE_NAME not in str(exc):
                raise
            _run_codex_json(
                binary,
                home,
                "plugin",
                "marketplace",
                "remove",
                _CODEX_MARKETPLACE_NAME,
                "--json",
            )
            report["changed"] = True
            marketplaces = _run_codex_json(
                binary, home, "plugin", "marketplace", "list", "--json"
            )
        existing = next(
            (
                item
                for item in marketplaces.get("marketplaces", [])
                if isinstance(item, dict) and item.get("name") == _CODEX_MARKETPLACE_NAME
            ),
            None,
        )
        desired_root = str(Path(prepared["root"]).resolve())
        existing_root = str((existing or {}).get("root") or "")
        if existing is not None and existing_root:
            try:
                same_root = Path(existing_root).resolve() == Path(desired_root).resolve()
            except OSError:
                same_root = existing_root == desired_root
            if not same_root:
                _run_codex_json(
                    binary,
                    home,
                    "plugin",
                    "marketplace",
                    "remove",
                    _CODEX_MARKETPLACE_NAME,
                    "--json",
                )
                existing = None
        if existing is None:
            _run_codex_json(
                binary,
                home,
                "plugin",
                "marketplace",
                "add",
                desired_root,
                "--json",
            )
            report["changed"] = True

        plugins = _run_codex_json(binary, home, "plugin", "list", "--available", "--json")
        entries = list(plugins.get("installed") or []) + list(plugins.get("available") or [])
        current = next(
            (
                item
                for item in entries
                if isinstance(item, dict)
                and item.get("pluginId") == f"blackbox@{_CODEX_MARKETPLACE_NAME}"
            ),
            None,
        )
        current_ready = bool(
            current
            and current.get("installed")
            and current.get("enabled")
            and current.get("version") == prepared["version"]
        )
        if not current_ready:
            _run_codex_json(
                binary,
                home,
                "plugin",
                "add",
                f"blackbox@{_CODEX_MARKETPLACE_NAME}",
                "--json",
            )
            report["changed"] = True
        # Trust is over exact hook content. Existing state keys can describe the
        # previous plugin version, so any marketplace/plugin change must require
        # Codex to confirm the new hashes before we claim protection.
        trusted = not report["changed"] and _codex_hooks_trusted(home)
        report.update(
            ok=True,
            installed=True,
            protected=trusted,
            trust_required=not trusted,
            already=current_ready and not prepared["changed"],
        )
        if not trusted:
            report["note"] = "Plugin installed. In Codex, run /hooks once and trust the Agent Blackbox hooks."
    except Exception as exc:
        logger.debug("blackbox.attach: attach_codex(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


def detach_codex(
    home: Path,
    *,
    remove_files: bool = False,
    dry_run: bool = False,
    binary: Optional[str] = None,
) -> Dict[str, Any]:
    home = home.expanduser()
    binary = binary or _codex_binary()
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "codex",
        "ok": False,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        enabled = _codex_plugin_enabled(home)
        report["already"] = not enabled
        if enabled and not dry_run:
            if not binary:
                raise FileNotFoundError("Codex CLI was not found")
            _run_codex_json(
                binary,
                home,
                "plugin",
                "remove",
                f"blackbox@{_CODEX_MARKETPLACE_NAME}",
                "--json",
            )
            report["changed"] = True
        if remove_files:
            root = constants.blackbox_home() / "agent-hooks" / "codex-marketplace"
            if root.exists():
                if not dry_run:
                    shutil.rmtree(root)
                report["removed"] = True
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_codex(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# Config snapshot (for the OpenClaw entry) — decoupled from the running config
# ---------------------------------------------------------------------------


def load_blackbox_config_snapshot() -> Dict[str, Any]:
    """Resolve the Blackbox config values to write into an OpenClaw workspace.

    Uses :func:`config.load_blackbox_config` when available (honours env +
    config.yaml), else falls back to constants. Kept tiny so ``attach`` stays
    testable without a full hermes config.
    """
    try:
        from .config import load_blackbox_config

        cfg = load_blackbox_config()
        return {
            "dkg_url": cfg.dkg_url,
            "dkg_home": cfg.dkg_home,
            "context_graph_id": cfg.context_graph_id,
            "mode": cfg.mode,
            "blackbox_home": str(constants.blackbox_home()),
        }
    except Exception:
        return {
            "dkg_url": constants.DEFAULT_DKG_URL,
            "dkg_home": str(constants.blackbox_dkg_home()),
            "context_graph_id": constants.DEFAULT_CONTEXT_GRAPH_ID,
            "mode": "audit",
            "blackbox_home": str(constants.blackbox_home()),
        }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def attach_all(
    *,
    hermes: bool = True,
    openclaw: bool = True,
    claude: bool = True,
    codex: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Attach Blackbox to every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {
        "hermes": [],
        "openclaw": [],
        "claude-code": [],
        "codex": [],
        "dry_run": dry_run,
    }
    if hermes:
        for home in discover_hermes_homes():
            report["hermes"].append(attach_hermes(home, dry_run=dry_run))
    if openclaw:
        for ws in discover_openclaw_workspaces():
            report["openclaw"].append(attach_openclaw(ws, dry_run=dry_run))
    if claude:
        for home in discover_claude_homes():
            report["claude-code"].append(attach_claude(home, dry_run=dry_run))
    if codex:
        for home in discover_codex_homes():
            report["codex"].append(attach_codex(home, dry_run=dry_run))
    report["count"] = _protected_count(report)
    return report


def detach_all(
    *,
    hermes: bool = True,
    openclaw: bool = True,
    claude: bool = True,
    codex: bool = True,
    remove_files: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Detach Blackbox from every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {
        "hermes": [],
        "openclaw": [],
        "claude-code": [],
        "codex": [],
        "dry_run": dry_run,
    }
    if hermes:
        for home in discover_hermes_homes():
            report["hermes"].append(detach_hermes(home, remove_files=remove_files, dry_run=dry_run))
    if openclaw:
        for ws in discover_openclaw_workspaces():
            report["openclaw"].append(detach_openclaw(ws, dry_run=dry_run))
    if claude:
        for home in discover_claude_homes():
            report["claude-code"].append(detach_claude(home, dry_run=dry_run))
    if codex:
        for home in discover_codex_homes():
            report["codex"].append(
                detach_codex(home, remove_files=remove_files, dry_run=dry_run)
            )
    return report


def _protected_count(report: Dict[str, Any]) -> int:
    """Number of targets Blackbox is (now) protecting in an attach report."""
    total = 0
    for kind in ("hermes", "openclaw", "claude-code", "codex"):
        for row in report.get(kind, []):
            if row.get("protected", row.get("ok")):
                total += 1
    return total
