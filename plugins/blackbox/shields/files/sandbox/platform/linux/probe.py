"""What this machine lets the agent sandbox do, from ``blackbox-sandbox probe`` (its JSON: the
launcher's ``probe.rs``), cached so the many status reads of one page cost one probe.

Usage::

    unavailable()     # None, or why agents can not be sandboxed here
    layers()          # [{"layer": "files", "enforced": "yes", "note": "…"}, …]
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Optional

from .profile import SANDBOX, runtime_dir

TIMEOUT_SECONDS = 5.0
#: How long one probe's answer is used (a kernel or AppArmor change shows within this).
CACHE_SECONDS = 300.0
NOT_INSTALLED = ("Blackbox's sandbox launcher is not installed yet (it comes with the system protection helper), so "
                 "agents can not be sandboxed here. Blackbox's hooks still protect your files.")
#: The launcher's marks, inside ``$XDG_RUNTIME_DIR``, for agent starts whose network rules the
#: helper did not apply in time (``helper/src/platform/linux/sandbox/scope.rs`` ``UNBOUND_FOLDER``).
UNBOUND_FOLDER = os.path.join("blackbox", "sandbox-unbound")
_cache: dict[str, tuple[float, dict[str, object]]] = {}


def unbound_starts(runtime: str = "") -> int:
    """How many agent starts since the last one with its rules ran WITHOUT the helper's network
    rules (0 when none, or no mark can be read). Read fresh on every call, never cached: a start
    without its rules must show on the next page view (security Critical
    2026-11-24-linux-sandbox-the-helper-never-finds-an-: the old status said "yes" while no rule
    had ever loaded)."""
    try:
        return len(os.listdir(os.path.join(runtime or runtime_dir(), UNBOUND_FOLDER)))
    except OSError:
        return 0


def probe(sandbox: str = SANDBOX, now: Optional[float] = None) -> dict[str, object]:
    """The launcher's probe (``{}`` when it is missing, fails or answers no JSON)."""
    now = time.monotonic() if now is None else now
    try:
        key = f"{sandbox}:{os.stat(sandbox).st_mtime_ns}"
    except OSError:
        return {}
    cached = _cache.get(key)
    if cached and now - cached[0] < CACHE_SECONDS:
        return cached[1]
    try:
        done = subprocess.run([sandbox, "probe"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, check=False)
        answer = json.loads(done.stdout) if done.returncode == 0 else {}
    except (OSError, subprocess.SubprocessError, ValueError):
        answer = {}
    answer = answer if isinstance(answer, dict) else {}
    _cache.clear()
    _cache[key] = (now, answer)
    return answer


def unavailable(sandbox: str = SANDBOX) -> Optional[str]:
    """Why agents can not be sandboxed here, or None."""
    if not os.access(sandbox, os.X_OK):
        return NOT_INSTALLED
    found = probe(sandbox)
    if found.get("userns") is True:
        return None
    why = str(found.get("why") or "the launcher's probe failed")
    return f"Agents can not be sandboxed here: {why}. Blackbox's hooks still protect your files."


def layers(sandbox: str = SANDBOX, runtime: str = "") -> list[dict[str, str]]:
    """Each layer of the sandbox, enforced here or why not (for the status page)."""
    found = probe(sandbox)
    if not found:
        return []
    signals = str(found.get("signals", "none"))
    unbound = unbound_starts(runtime)
    rules_note = "needs the system protection helper and a systemd user session"
    if unbound:
        rules_note = (f"the system protection helper did not apply its rules for {unbound} agent start(s): ssh back into "
                      "this computer and its local ports were NOT refused for them — restart those agents")
    rows = [
        ("files", found.get("userns") is True, "protected items hidden, Blackbox's and the startup places read-only",
         str(found.get("why") or "")),
        ("privileges", found.get("userns") is True, "no new privileges: sudo, su and setuid programs can not raise them", ""),
        ("terminal-and-keyrings", found.get("seccomp") is True, "typing into your terminal and the kernel keyrings refused",
         "this kernel has no seccomp"),
        ("signals", signals != "none", f"no signal, ptrace or /proc access to programs outside ({signals})",
         "kernel below 6.12: Landlock has no signal scope here"),
        ("abstract-sockets", found.get("abstract_sockets") == "landlock-scope", "abstract sockets outside refused (X11's among them)",
         "kernel below 6.12: an X11 display stays reachable through its abstract socket"),
        ("network-rules", found.get("helper_rules") is True and found.get("scope") is True and not unbound,
         "local ports, ssh to this machine and Docker's TCP port refused per agent", rules_note),
    ]
    return [{"layer": layer, "enforced": "yes" if on else "no", "note": yes if on else no} for layer, on, yes, no in rows]


__all__ = ["CACHE_SECONDS", "NOT_INSTALLED", "UNBOUND_FOLDER", "layers", "probe", "unavailable", "unbound_starts"]
