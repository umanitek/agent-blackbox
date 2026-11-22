"""Layer 2 on macOS: the agent sandbox is a Seatbelt profile, run with ``/usr/bin/sandbox-exec``.

Seatbelt is the kernel's own sandbox (the one App Store apps run in). A process started under a
profile keeps it for life, every process it starts inherits it, and nothing inside can lift it —
so a script, a compiled program or an interpreter an agent starts is refused the same as the
agent. Proven on this macOS (27.x, 2026-11-22): ``cat``, ``python3 open()``, grandchildren, a
symlink to a protected file, ``ln`` (hard link), ``mv``/``rm`` of a protected file and a rename of
a folder above one are all refused; a file next to it stays readable.

What it can not do, said plainly (proposal §04):

* driving ANOTHER app, which would do the work outside the sandbox: ``osascript`` (AppleScript
  and JavaScript), ``automator`` and ``shortcuts`` can not start inside (:data:`APP_DRIVERS`),
  and ``open`` / LaunchServices launches are refused (``lsopen``). Probed 2026-11-22: Seatbelt's
  ``appleevent-send`` rule does NOT stop a CLI's AppleEvents, and refusing the LaunchServices
  database lookup (``com.apple.lsd.mapdb``) stops them only by making every LaunchServices caller
  HANG (``open``, a browser login) — so it is not used. Left open: a program the agent compiles
  itself that sends AppleEvents through the system's own frameworks (``NSAppleScript``) — the
  OS's file checks (Layer 3) close that;
* setuid programs (``sudo``, ``su``) can not run inside any Seatbelt sandbox — so Layer 2 is a
  per-agent choice of the person (D7: agents keep ``sudo`` unless the person sandboxes them);
* ``sandbox-exec`` is marked deprecated by Apple but is what Apple's own tools still use; the
  long-term path is the OS's file checks (Endpoint Security, Layer 3).

Pattern: one **Strategy** of :mod:`.` (the platform facade).

Usage::

    text = render(places)                         # the profile
    launcher_script("claude", here, profile)      # the launcher Blackbox puts on PATH
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
from typing import Optional

from ..places import Places

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
PGREP = "/usr/bin/pgrep"
PROFILE_SUFFIX = ".sb"
#: GUI agents Blackbox can relaunch inside the sandbox (D10): id -> (name, app bundle).
APPS = {"cursor": ("Cursor", "/Applications/Cursor.app"), "windsurf": ("Windsurf", "/Applications/Windsurf.app")}
#: Programs that drive other apps (AppleScript / JavaScript for Automation, Automator workflows,
#: Shortcuts): refused inside — the app they drive would act outside the sandbox. A copy of one
#: does not run either (macOS kills a copied platform binary).
APP_DRIVERS = ("/usr/bin/osascript", "/usr/bin/automator", "/usr/bin/shortcuts")
#: The SSH port on this Mac: an agent may not log back into the Mac outside its sandbox.
LOCAL_SSH = ('"localhost:22"',)
TIMEOUT_SECONDS = 5.0


def unavailable() -> Optional[str]:
    """Why the sandbox can not run here, or None."""
    return None if os.access(SANDBOX_EXEC, os.X_OK) else "This Mac has no sandbox-exec, so agents can not be sandboxed."


def _quote(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _glob_regex(glob: str) -> str:
    """``/dir/*.pem`` as a Seatbelt regex matching files directly in that folder."""
    folder, name = os.path.split(glob)
    body = "".join("[^/]*" if char == "*" else "[^/]" if char == "?" else re.escape(char) for char in name)
    return "#\"^" + re.escape(folder).replace('"', '\\"') + "/" + body + "$\""


def render(places: Places, digest_line: str = "") -> str:
    """The Seatbelt profile for *places*. Everything not named stays allowed: the agent works as
    before, except on what the person (and Blackbox) protect."""
    refused = [f"(subpath {_quote(p)})" for p in places.denied_folders]
    refused += [f"(literal {_quote(p)})" for p in places.denied_files]
    refused += [f"(regex {_glob_regex(g)})" for g in places.denied_globs]
    lines = ["(version 1)", f"; Blackbox agent sandbox — generated, do not edit. {digest_line}".rstrip(), "(allow default)"]
    if refused:
        lines.append("(deny file-read* file-write* file-link\n  " + "\n  ".join(refused) + ")")
    if places.no_write:
        lines.append("(deny file-write*\n  " + "\n  ".join(f"(subpath {_quote(p)})" for p in places.no_write) + ")")
    if places.no_write_files:   # the shell startup files: the PATH block that keeps later agents inside (KI-535)
        lines.append("(deny file-write*\n  " + "\n  ".join(f"(literal {_quote(p)})" for p in places.no_write_files) + ")")
    if places.no_rename:
        lines.append("(deny file-write-unlink\n  " + "\n  ".join(f"(literal {_quote(p)})" for p in places.no_rename) + ")")
    lines.append("(deny lsopen)")   # `open -a OtherApp file`: another app would read it outside the sandbox
    lines.append("(deny process-exec " + " ".join(f"(literal {_quote(p)})" for p in APP_DRIVERS) + ")")
    lines.append(f"(deny network-outbound (remote ip {LOCAL_SSH[0]}))")   # ssh back into this Mac
    return "\n".join(lines) + "\n"


def launcher_script(command: str, here: str, profile: str) -> str:
    """The launcher put first on PATH for *command*: finds the real program further down PATH and
    runs it inside the profile. Already inside a sandbox (an agent starting another) it runs the
    program as it is — the sandbox it is in still applies. No profile: Blackbox's hooks only, said
    on stderr (fail-open: an agent always starts)."""
    return f"""#!/bin/sh
# Blackbox agent sandbox launcher for {command} — generated by Blackbox (File Shield), rewritten on change.
here={_shell(here)}
profile={_shell(profile)}
path_rest=$(printf '%s' "$PATH" | tr ':' '\\n' | grep -vxF "$here" | paste -sd: -)
real=$(PATH="$path_rest" command -v {_shell(command)}) || {{ echo "blackbox: {command} is not installed" >&2; exit 127; }}
if [ "${{BLACKBOX_AGENT_SANDBOX:-}}" = 1 ]; then exec "$real" "$@"; fi
if [ -r "$profile" ]; then
  BLACKBOX_AGENT_SANDBOX=1; export BLACKBOX_AGENT_SANDBOX
  exec {SANDBOX_EXEC} -f "$profile" "$real" "$@"
fi
echo "blackbox: no sandbox profile — {command} runs with Blackbox's hooks only" >&2
exec "$real" "$@"
"""


def _shell(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def _executable(bundle: str) -> Optional[str]:
    try:
        with open(os.path.join(bundle, "Contents", "Info.plist"), "rb") as handle:   # windows-footgun: ok (binary plist)
            name = plistlib.load(handle).get("CFBundleExecutable")
    except (OSError, ValueError):
        return None
    path = os.path.join(bundle, "Contents", "MacOS", str(name or ""))
    return path if name and os.access(path, os.X_OK) else None


def _running(executable: str) -> bool:
    try:
        done = subprocess.run([PGREP, "-f", executable], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return True   # cannot tell: refuse (a running copy would take the launch outside the sandbox)
    return done.returncode == 0


def open_app(app: str, profile: str) -> str:
    """Starts the GUI agent *app* (``cursor`` / ``windsurf``) inside the profile; answers what
    happened, for a person. Refused while it already runs: an editor hands a second launch to the
    copy already running — outside the sandbox."""
    if app not in APPS:
        raise ValueError(f"unknown app {app!r}")
    name, bundle = APPS[app]
    executable = _executable(bundle)
    if executable is None:
        raise LookupError(f"{name} is not installed in /Applications.")
    if _running(executable):
        raise RuntimeError(f"Quit {name} first: a copy already running would open outside the sandbox.")
    subprocess.Popen([SANDBOX_EXEC, "-f", profile, executable], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, env={**os.environ, "BLACKBOX_AGENT_SANDBOX": "1"})
    return f"{name} is starting inside Blackbox's sandbox."
