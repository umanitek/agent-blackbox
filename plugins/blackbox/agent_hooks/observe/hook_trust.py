"""Whether an agent will RUN Blackbox's hooks: its own trust record, read the way it reads it.

WHY (Linux round L7, BB-LINUX-PENDING-735ee6, Medium): Codex 0.172 runs a non-managed hook only
after the person has reviewed and trusted that exact hook definition (``/hooks`` in Codex). Until
then it skips it, silently: Blackbox's hooks were in ``~/.codex/hooks.json``, Blackbox showed Codex
as hooked, and a real ``codex exec`` ran 58 commands with nothing checked and nothing recorded.
"Hooks in its config" is not "hooks that run". This module reads the record Codex itself decides
by, so status, the agents API and the back-stop can say "NOT protected" and name the one step.

What Codex does (codex-rs, tag ``rust-v0.172.0``: ``hooks/src/engine/discovery.rs``,
``hooks/src/config_rules.rs``, ``config/src/fingerprint.rs``; learn.chatgpt.com/docs/hooks):

* each handler has a KEY — ``<hooks.json path>:<event label>:<group index>:<handler index>``;
* and a HASH — SHA-256 over the canonical JSON (sorted keys, no spaces) of the normalised
  identity ``{"event_name", "matcher"?, "hooks": [{"type": "command", "command", "timeout",
  "async", "statusMessage"?, "additionalContextLimit"?}]}`` (timeout defaulted and clamped as
  Codex does; a matcher kept only for the events that take one);
* the person's trust lives in the USER config ``$CODEX_HOME/config.toml`` as
  ``[hooks.state."<key>"] trusted_hash = "sha256:…"`` (``enabled = false`` switches one off);
  project, managed and plugin layers may not write it;
* a hook in the SYSTEM layer (``/etc/codex/hooks.json``) or from ``requirements.toml`` is
  *managed*: trusted by policy, no review;
* ``codex … --dangerously-bypass-hook-trust`` runs enabled hooks unreviewed for that one run.

The hash rule is checked against Codex's own test vectors and against the real Codex 0.172 on the
Linux test VM (``codex app-server`` → ``hooks/list`` gave the same ``currentHash`` for every one
of Blackbox's eight hooks; the tests carry both). If a later Codex hashed differently, every hook
would read as "changed since you trusted it": the protective answer, said with its reason, never
a quiet "protected" (LES-159: only the one value that proves it — every hook ``trusted`` — counts).

Blackbox never writes the trust itself: that would answer Codex's consent question on the
person's behalf. It tells the person, and they trust the hooks in Codex.

Usage::

    trust = hook_trust.read(host, home)          # HookTrust for the hooks file host.config names
    trust.runs                                   # True only when Codex will run every Blackbox hook
    trust.detail                                 # what is wrong and the one step that fixes it
    hook_trust.run_reason(host, argv, home)      # why ONE run skips Blackbox's hooks ("" = it runs them)
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from ...kernel.agent_hosts import Host
from ...kernel.bounded_files import read_small_text

#: The most of a hooks.json / config.toml read.
MAX_FILE_BYTES = 1024 * 1024
#: What every hook entry Blackbox writes runs (``protect.config_edit.MARK``; kept equal by a test).
MARK = "agent-hooks/runner.py"
#: Codex's system hooks file on macOS and Linux: a hook there is managed (trusted by policy).
CODEX_SYSTEM_HOOKS = Path("/etc/codex/hooks.json")
#: The run option that makes Codex run enabled hooks without their trust, for that run only.
CODEX_BYPASS_FLAG = "--dangerously-bypass-hook-trust"
CODEX_TRUST_STEP = ("run `codex`, type /hooks, and trust Blackbox's hooks (Codex asks once, "
                    "and again whenever they change)")

# The states, worst last. Only TRUSTED and MANAGED mean the agent runs the hook.
TRUSTED = "trusted"
MANAGED = "managed"
UNTRUSTED = "untrusted"
MODIFIED = "modified"
DISABLED = "disabled"
UNKNOWN = "unknown"
NOT_HOOKED = "not-hooked"
_RUNS = frozenset({TRUSTED, MANAGED})
_WORST_FIRST = (UNKNOWN, DISABLED, MODIFIED, UNTRUSTED)

#: hooks.json's event names → the label Codex keys and hashes them by (``hook_event_key_label``).
_CODEX_EVENTS = {"PreToolUse": "pre_tool_use", "PermissionRequest": "permission_request", "PostToolUse": "post_tool_use",
                 "PreCompact": "pre_compact", "PostCompact": "post_compact", "PreModelRequest": "pre_model_request",
                 "PostModelRequest": "post_model_request", "SessionStart": "session_start", "SessionEnd": "session_end",
                 "UserPromptSubmit": "user_prompt_submit", "SubagentStart": "subagent_start",
                 "SubagentStop": "subagent_stop", "Stop": "stop", "Interrupt": "interrupt"}
#: Events whose matcher Codex keeps (``matcher_pattern_for_event``); the rest ignore it.
_MATCHED = frozenset({"pre_tool_use", "permission_request", "post_tool_use", "session_start", "session_end",
                      "subagent_start", "subagent_stop", "pre_compact", "post_compact"})
#: Events whose additionalContextLimit Codex keeps, and the default it drops.
_CONTEXT_LIMITED = frozenset({"pre_tool_use", "post_tool_use", "session_start", "user_prompt_submit", "subagent_start"})
_DEFAULT_CONTEXT_LIMIT = 2500
#: SessionEnd / Interrupt time limits: default 1 s, at most 3 s; every other event 600 s.
_SHORT_EVENTS = frozenset({"session_end", "interrupt"})


@dataclass(frozen=True)
class HookTrust:
    """What the agent makes of Blackbox's hooks. ``state``: one of the module's states (the
    worst over all of Blackbox's hooks); ``detail``: said to the person, with the step that fixes
    it; ``keys``: the agent's own keys of the hooks it will not run."""

    state: str
    detail: str = ""
    keys: tuple[str, ...] = ()

    @property
    def runs(self) -> bool:
        """True only when the agent runs every one of Blackbox's hooks."""
        return self.state in _RUNS


def codex_hook_hash(event_label: str, matcher: Optional[str], handler: Mapping[str, Any]) -> str:
    """Codex's ``current_hash`` of one command handler (``discovery.rs`` ``hook_hash``)."""
    timeout = handler.get("timeout")
    timeout = timeout if isinstance(timeout, int) and not isinstance(timeout, bool) else None
    if event_label in _SHORT_EVENTS:
        timeout = min(max(timeout if timeout is not None else 1, 1), 3)
    else:
        timeout = max(timeout if timeout is not None else 600, 1)
    normalised: dict[str, Any] = {"type": "command", "command": str(handler.get("command") or ""),
                                  "timeout": timeout, "async": handler.get("async") is True}
    if isinstance(handler.get("statusMessage"), str):
        normalised["statusMessage"] = handler["statusMessage"]
    limit = handler.get("additionalContextLimit")
    if event_label in _CONTEXT_LIMITED and isinstance(limit, int) and limit != _DEFAULT_CONTEXT_LIMIT:
        normalised["additionalContextLimit"] = limit
    identity: dict[str, Any] = {"event_name": event_label, "hooks": [normalised]}
    if matcher is not None and event_label in _MATCHED:
        identity["matcher"] = matcher
    text = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _json_file(path: Path) -> Optional[dict[str, Any]]:
    text = read_small_text(str(path), MAX_FILE_BYTES)
    try:
        data = json.loads(text) if text is not None else None
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _our_handlers(hooks_file: Path, data: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(key, hash)`` of every Blackbox handler in a Codex hooks.json, keyed as Codex keys it."""
    out = []
    events = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, groups in events.items():
        label = _CODEX_EVENTS.get(event)
        if label is None or not isinstance(groups, list):
            continue
        for group_index, group in enumerate(groups):
            handlers = group.get("hooks") if isinstance(group, dict) else None
            matcher = group.get("matcher") if isinstance(group, dict) and isinstance(group.get("matcher"), str) else None
            for handler_index, handler in enumerate(handlers if isinstance(handlers, list) else []):
                if isinstance(handler, dict) and handler.get("type") == "command" and MARK in str(handler.get("command") or ""):
                    key = f"{hooks_file}:{label}:{group_index}:{handler_index}"
                    out.append((key, codex_hook_hash(label, matcher, handler)))
    return out


def _user_states(config_file: Path) -> Optional[dict[str, Any]]:
    """The ``[hooks.state]`` table of the user's config.toml ({} when there is no file or no
    table); None when the file is there but cannot be read as Codex reads it."""
    if not config_file.exists():
        return {}
    text = read_small_text(str(config_file), MAX_FILE_BYTES)
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    state = (data.get("hooks") or {}).get("state") if isinstance(data.get("hooks"), dict) else None
    return {str(key).strip(): value for key, value in state.items()} if isinstance(state, dict) else {}


def _one(state: Any, current: str) -> str:
    state = state if isinstance(state, dict) else {}
    if state.get("enabled") is False:
        return DISABLED
    trusted = state.get("trusted_hash")
    if trusted is None:
        return UNTRUSTED
    return TRUSTED if trusted == current else MODIFIED


_CODEX_DETAIL = {
    UNKNOWN: "Codex is NOT protected: Blackbox could not read Codex's trust record ({where}), so it cannot tell whether "
             "Codex runs its hooks. Check that file, then " + CODEX_TRUST_STEP + ".",
    DISABLED: "Codex is NOT protected: Blackbox's hooks are switched off in Codex (/hooks). To fix: run `codex`, "
              "type /hooks and switch Blackbox's hooks on.",
    MODIFIED: "Codex is NOT protected: Blackbox's hooks changed since you trusted them, and Codex skips a changed hook "
              "until it is trusted again. To fix: " + CODEX_TRUST_STEP + ".",
    UNTRUSTED: "Codex is NOT protected yet: Codex runs a new hook only after you trust it, so it skips Blackbox's "
               "hooks and none of what it does is checked. To fix: " + CODEX_TRUST_STEP + ".",
}


def codex_trust(hooks_file: Path, system_file: Optional[Path] = None) -> HookTrust:
    """What Codex makes of Blackbox's hooks in *hooks_file* (a ``$CODEX_HOME/hooks.json``): its
    trust record is the sibling ``config.toml``. A Blackbox hook in *system_file* is managed."""
    system_file = system_file or CODEX_SYSTEM_HOOKS
    system = _json_file(system_file) if system_file.exists() else None
    if system is not None and _our_handlers(system_file, system):
        return HookTrust(MANAGED, "Codex runs Blackbox's hooks from its system hooks file (managed: no review).")
    if not hooks_file.exists():
        return HookTrust(NOT_HOOKED)
    data = _json_file(hooks_file)
    states = _user_states(hooks_file.with_name("config.toml"))
    if data is None or states is None:
        where = hooks_file if data is None else hooks_file.with_name("config.toml")
        return HookTrust(UNKNOWN, _CODEX_DETAIL[UNKNOWN].format(where=where))
    ours = _our_handlers(hooks_file, data)
    if not ours:
        return HookTrust(NOT_HOOKED)
    verdicts = [(key, _one(states.get(key), current)) for key, current in ours]
    for worst in _WORST_FIRST:
        keys = tuple(key for key, verdict in verdicts if verdict == worst)
        if keys:
            return HookTrust(worst, _CODEX_DETAIL[worst], keys)
    return HookTrust(TRUSTED, "Codex trusts Blackbox's hooks.")


#: The agents whose own trust decides whether a hook in their config runs, and its reader.
READERS: dict[str, Callable[[Path], HookTrust]] = {"codex": codex_trust}


def read(host: Host, home: Path) -> Optional[HookTrust]:
    """*host*'s trust in Blackbox's hooks in the config *host* names under *home*; None for an
    agent that runs every hook in its config (no trust step)."""
    reader = READERS.get(host.id)
    return reader(host.config_path(home)) if reader else None


def run_reason(host: Host, argv: Sequence[str], home: Path) -> str:
    """Why ONE run of *host* (its argv words) skips Blackbox's hooks because the agent does not
    trust them ("" = it runs them, or the agent has no trust step). Codex's bypass option runs
    enabled hooks for that run; a hook switched off stays off."""
    trust = read(host, home)
    if trust is None or trust.runs or trust.state == NOT_HOOKED:
        return ""
    if host.id == "codex" and CODEX_BYPASS_FLAG in argv and trust.state != DISABLED:
        return ""
    return trust.detail
