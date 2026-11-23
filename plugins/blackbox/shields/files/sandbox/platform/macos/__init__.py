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
* setuid programs (``sudo``, ``su``, ``top``, ``crontab``, ``/bin/ps``) can not run inside any Seatbelt
  sandbox (the kernel's ``forbidden-exec-sugid``; no profile rule lifts it) — so Layer 2 is a per-agent
  choice of the person. ``ps`` works from a copy without the setuid bit, which :func:`refresh_tools`
  keeps in ``<launchers>/sandbox-tools`` (made again when macOS changes) and every launcher puts
  first on the sandboxed PATH (KI-589; an absolute ``/bin/ps`` still fails). The others need root to
  work at all, so a stand-in there says why (:data:`SETUID_NOTE`) instead of a bare
  "operation not permitted";
* ``sandbox-exec`` is marked deprecated by Apple but is what Apple's own tools still use; the
  long-term path is the OS's file checks (Endpoint Security, Layer 3);
* a GUI editor built on Electron/Chromium (Cursor, Windsurf) sandboxes its own helper processes
  with Seatbelt, and a second Seatbelt sandbox can not be started inside one ("sandbox
  initialization failed: Operation not permitted" — every helper exits, so the editor never
  appears; KI-534, probed 2026-11-22 with a Chromium app). Inside Blackbox's sandbox the editor
  therefore runs with its OWN sandbox off (:data:`ELECTRON_FLAGS`): Blackbox's sandbox then covers
  the whole editor, but its web pages lose Chromium's extra isolation — the page says so before the
  person chooses it. An app from the App Store (Apple's App Sandbox) can not be started inside at all.

Pattern: one **Strategy** of :mod:`.` (the platform facade).

Usage::

    text = render(places)                         # the profile
    launcher_script("claude", here, profile)      # the launcher Blackbox puts on PATH
    refresh_tools(here)                           # the setuid-free ps + stand-ins, first on the sandboxed PATH
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path
from platform import mac_ver
from typing import Optional

from ......kernel.bounded_files import atomic_write, read_small_text
from ...places import Places
from .persistence_places import startup_places

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
#: An Electron/Chromium editor's own sandbox can not start inside Blackbox's (see the module doc).
ELECTRON_FLAGS = ("--no-sandbox",)
#: The folder beside the launchers whose programs come first on the SANDBOXED PATH only (never the
#: person's own PATH): the setuid-free ``ps`` and the stand-ins for setuid tools.
TOOLS_FOLDER = "sandbox-tools"
#: ``ps`` without its setuid bit runs inside the sandbox with the agent's own rights (KI-589). The
#: copy is signed ad hoc: macOS 27 kills a plain copy of a platform binary (probed 2026-11-22, exit
#: 137), macOS 26 ran one. A copy that still does not run is removed (the stand-in says why).
PS = "/bin/ps"
CODESIGN = "/usr/bin/codesign"
#: Setuid tools that need root to work at all (``top`` reads every process through a root-only
#: library, ``crontab`` the root-owned tables): each existing one gets a stand-in saying why.
SETUID_TOOLS = ("/usr/bin/top", "/usr/bin/crontab", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/at", "/usr/bin/atq",
                "/usr/bin/atrm", "/usr/bin/batch", "/usr/bin/login", "/usr/bin/newgrp", "/usr/bin/quota")
SETUID_NOTE = "macOS doesn't allow setuid programs inside the agent sandbox; run it in your own terminal"
_TOOLS_STAMP = ".macos"
#: How long an editor started inside the sandbox must stay up before it is called running.
STARTED_SECONDS = 4.0
STARTED_POLL_SECONDS = 0.2


def unavailable() -> Optional[str]:
    """Why the sandbox can not run here, or None."""
    return None if os.access(SANDBOX_EXEC, os.X_OK) else "This Mac has no sandbox-exec, so agents can not be sandboxed."


def _quote(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _glob_regex(glob: str) -> str:
    """``/dir/*.pem`` (or ``/plugins/*/blackbox-addon.json``: a wildcard in any part) as a Seatbelt
    regex; ``*`` and ``?`` never cross a ``/``."""
    body = "".join("[^/]*" if char == "*" else "[^/]" if char == "?" else re.escape(char) for char in glob)
    return "#\"^" + body.replace('"', '\\"') + "$\""


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
    if places.no_write_globs:   # every add-on's manifest, existing or not: no add-on is planted or removed
        lines.append("(deny file-write*\n  " + "\n  ".join(f"(regex {_glob_regex(g)})" for g in places.no_write_globs) + ")")
    if places.no_write_files:   # the shell startup files: the PATH block that keeps later agents inside (KI-535)
        lines.append("(deny file-write*\n  " + "\n  ".join(f"(literal {_quote(p)})" for p in places.no_write_files) + ")")
    startup = [f"(subpath {_quote(p)})" for p in places.startup_folders] + [f"(literal {_quote(p)})" for p in places.startup_files]
    startup += [f"(regex {_glob_regex(g)})" for g in places.startup_globs]
    if startup:   # launchd jobs, login items, cron, OpenSSH's login files, Homebrew's prefix (startup_places)
        lines.append("(deny file-write*\n  " + "\n  ".join(startup) + ")")
    if places.no_rename:
        lines.append("(deny file-write-unlink\n  " + "\n  ".join(f"(literal {_quote(p)})" for p in places.no_rename) + ")")
    lines.append("(deny lsopen)")   # `open -a OtherApp file`: another app would read it outside the sandbox
    lines.append("(deny process-exec " + " ".join(f"(literal {_quote(p)})" for p in APP_DRIVERS) + ")")
    lines.append(f"(deny network-outbound (remote ip {LOCAL_SSH[0]}))")   # ssh back into this Mac
    # No signal to a process outside this sandbox (Blackbox's dashboard, its helper, the person's
    # other programs): an agent could otherwise stop Blackbox from inside. Its own children share
    # the sandbox and stay signalable (a test runner stopping its workers); Ctrl-C comes from the
    # terminal, not from a sandboxed process. Probed on macOS 27 (2026-11-22): ``(target others)``
    # alone does NOT stop a signal; deny-all then allow ``same-sandbox`` does.
    lines.append("(deny signal)")
    lines.append("(allow signal (target same-sandbox))")
    return "\n".join(lines) + "\n"


def _tools_dir(launchers: str) -> str:
    return os.path.join(launchers, TOOLS_FOLDER)


def _stamp() -> str:
    """What the tool copies were made from: this macOS and the ``ps`` it ships."""
    try:
        found = os.stat(PS)
    except OSError:
        return ""
    return f"{mac_ver()[0]} {os.uname().version} {found.st_size} {found.st_mtime_ns}\n"


def refresh_tools(launchers: str, wanted: bool = True) -> bool:
    """Makes ``<launchers>/sandbox-tools`` hold a setuid-free copy of ``ps`` and a stand-in for each
    setuid tool here (:data:`SETUID_TOOLS`), again whenever macOS (or its ``ps``) changed; removes
    the folder when no agent is sandboxed (*wanted* False). Answers True when it wrote them.
    Fail-open: a Mac without ``/bin/ps`` or a read-only folder keeps none."""
    folder, stamp = _tools_dir(launchers), _stamp()
    if not wanted:
        shutil.rmtree(folder, ignore_errors=True)
        return False
    marker = os.path.join(folder, _TOOLS_STAMP)
    if stamp and read_small_text(marker, len(stamp) + 1) == stamp and os.access(os.path.join(folder, "ps"), os.X_OK):
        return False
    try:
        os.makedirs(folder, exist_ok=True)
        if stamp:
            _copy_ps(os.path.join(folder, "ps"))
        for tool in SETUID_TOOLS:
            standin = os.path.join(folder, os.path.basename(tool))
            if os.path.exists(tool) and os.stat(tool).st_mode & (stat.S_ISUID | stat.S_ISGID):
                atomic_write(Path(standin), _standin(os.path.basename(tool)), mode=0o755)
        atomic_write(Path(marker), stamp, mode=0o644)
    except OSError:
        return False
    return True


def _copy_ps(target: str) -> None:
    """A copy of ``ps`` at *target* without the setuid bit (copyfile copies bytes only), signed ad
    hoc, kept only when it runs."""
    shutil.copyfile(PS, target)
    os.chmod(target, 0o755)
    try:
        subprocess.run([CODESIGN, "--force", "--sign", "-", target], capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
        runs = subprocess.run([target, "-p", str(os.getpid()), "-o", "pid="], capture_output=True,
                              timeout=TIMEOUT_SECONDS, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        runs = False
    if not runs:
        atomic_write(Path(target), _standin("ps"), mode=0o755)


def _standin(name: str) -> str:
    return f"""#!/bin/sh
# Blackbox agent sandbox: {name} is setuid and can not run inside the sandbox — generated by Blackbox (File Shield).
echo "Blackbox's sandbox refused this ({name}): {SETUID_NOTE}." >&2
exit 126
"""


#: The Homebrew commands that only read, run as they are inside the sandbox; ``tap`` alone lists the taps.
BREW_READ_ONLY = ("list", "ls", "info", "abv", "search", "-S", "deps", "uses", "outdated", "config", "doctor", "dr", "--version",
                  "-v", "--prefix", "--cellar", "--repository", "--repo", "--cache", "--caskroom", "--env", "home", "homepage",
                  "desc", "leaves", "commands", "help", "-h", "--help", "log", "cat", "formulae", "casks", "options", "missing",
                  "shellenv", "tap-info", "which-formula", "")


def brew_shim(tools: str, python: str, dashboard_url: str) -> str:
    """The ``brew`` first on the sandboxed PATH (KI-593): a command that changes what is installed
    goes to Blackbox's broker through the client beside it (``packages/client.py``); a command that
    only reads (:data:`BREW_READ_ONLY`) runs the real Homebrew inside the sandbox; EVERY other
    command — ``tap`` / ``untap`` (a tap is code from anywhere), ``link``, ``unlink``, ``pin``,
    ``services``, ``update``, ``cleanup``… — writes Homebrew's prefix, which the sandbox keeps closed
    (security round 4: ``brew tap someone/evil-tap`` began cloning from inside), and is refused with
    the reason."""
    read_only = "|".join(f'"{verb}"' if verb else '""' for verb in BREW_READ_ONLY)
    return f"""#!/bin/sh
# Blackbox agent sandbox: brew — installs go through Blackbox (File Shield). Generated by Blackbox.
tools={_shell(tools)}
case "${{1:-}}" in
  install|upgrade|reinstall|uninstall|remove|rm)
    exec {_shell(python)} -I "$tools/brew-client.py" {_shell(dashboard_url)} "$@" ;;
  tap)
    if [ "$#" -gt 1 ]; then
      echo "Blackbox's sandbox refused this (brew tap): a tap adds formulae from outside Homebrew's official taps and changes Homebrew; run it in your own terminal if you trust it." >&2
      exit 126
    fi ;;
  {read_only}) ;;
  *)
    echo "Blackbox's sandbox refused this (brew ${{1}}): it changes Homebrew, which the agent sandbox keeps closed; Blackbox installs, upgrades and removes packages for you, run anything else in your own terminal." >&2
    exit 126 ;;
esac
path_rest=$(printf '%s' "$PATH" | tr ':' '\\n' | grep -vxF "$tools" | paste -sd: -)
real=$(PATH="$path_rest" command -v brew) || {{ echo "brew is not installed" >&2; exit 127; }}
exec "$real" "$@"
"""


def spawn_brew(command: list[str], env: dict[str, str], cwd: str) -> subprocess.Popen[str]:
    """Starts the brokered Homebrew run (``packages.jobs``): no stdin, output and errors as one text
    stream, its own process group (so :func:`stop_group` stops brew and every child it started)."""
    return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=cwd,
                            text=True, encoding="utf-8", errors="replace", start_new_session=True)


def stop_group(process: subprocess.Popen[str]) -> None:
    """Stops a run :func:`spawn_brew` started, with everything in its process group."""
    try:
        os.killpg(process.pid, signal.SIGTERM)   # windows-footgun: ok (macOS module)
    except OSError:
        pass


def _with_tools(tools: str) -> str:
    """The shell lines that put the sandbox's tools first on PATH, for the sandboxed program only."""
    return f"""tools={_shell(tools)}
if [ -d "$tools" ]; then PATH="$tools:$PATH"; export PATH; fi
"""


def launcher_script(command: str, here: str, profile: str) -> str:
    """The launcher put first on PATH for *command*: finds the real program further down PATH and
    runs it inside the profile, with the sandbox's tools (``<here>/sandbox-tools``) first on ITS
    PATH. Already inside a sandbox (an agent starting another) it runs the program as it is — the
    sandbox it is in still applies. No profile: Blackbox's hooks only, said on stderr (fail-open: an
    agent always starts)."""
    return f"""#!/bin/sh
# Blackbox agent sandbox launcher for {command} — generated by Blackbox (File Shield), rewritten on change.
here={_shell(here)}
profile={_shell(profile)}
path_rest=$(printf '%s' "$PATH" | tr ':' '\\n' | grep -vxF "$here" | paste -sd: -)
real=$(PATH="$path_rest" command -v {_shell(command)}) || {{ echo "blackbox: {command} is not installed" >&2; exit 127; }}
if [ "${{BLACKBOX_AGENT_SANDBOX:-}}" = 1 ]; then exec "$real" "$@"; fi
if [ -r "$profile" ]; then
  BLACKBOX_AGENT_SANDBOX=1; export BLACKBOX_AGENT_SANDBOX
  {_with_tools(_tools_dir(here)).strip().replace(chr(10), chr(10) + "  ")}
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


def open_app(app: str, profile: str, apps: Optional[dict[str, tuple[str, str]]] = None, log: Optional[str] = None,
             started_seconds: float = STARTED_SECONDS) -> str:
    """Starts the GUI agent *app* (``cursor`` / ``windsurf``) inside the profile and answers what
    happened, for a person — only once it is still running :data:`STARTED_SECONDS` later (KI-534:
    "is starting" was said for an editor that had already died). Refused while it already runs: an
    editor hands a second launch to the copy already running — outside the sandbox. *apps* and
    *log* (where its output goes) are for tests."""
    apps = APPS if apps is None else apps
    if app not in apps:
        raise ValueError(f"unknown app {app!r}")
    name, bundle = apps[app]
    executable = _executable(bundle)
    if executable is None:
        raise LookupError(f"{name} is not installed in {os.path.dirname(bundle)}.")
    if _running(executable):
        raise RuntimeError(f"Quit {name} first: a copy already running would open outside the sandbox.")
    output = open(log or os.devnull, "ab")   # windows-footgun: ok (binary log)
    try:
        process = subprocess.Popen([SANDBOX_EXEC, "-f", profile, executable, *ELECTRON_FLAGS], stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True,
                                   env={**os.environ, "BLACKBOX_AGENT_SANDBOX": "1"})
    finally:
        output.close()
    deadline = time.monotonic() + started_seconds
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{name} stopped right after starting inside the sandbox (exit {code}), so it is not "
                               "running. Open it normally if you need it now; its use stays covered by Blackbox's hooks.")
        time.sleep(STARTED_POLL_SECONDS)
    return f"{name} is running inside Blackbox's sandbox."


def shell_shim(shell: str, here: str, profile: str, launchers: str = "") -> str:
    """A ``bash`` / ``sh`` / ``zsh`` that runs the real shell inside the profile — put first on the
    Hermes agent's OWN PATH (never the person's), so every shell its terminal tool starts is inside
    the sandbox while the Hermes process itself (and Blackbox in it) stays outside. *launchers*:
    the folder whose ``sandbox-tools`` go first on the sandboxed shell's PATH."""
    return f"""#!/bin/sh
# Blackbox agent sandbox: {shell} for the Hermes agent's tools — generated by Blackbox (File Shield).
here={_shell(here)}
profile={_shell(profile)}
path_rest=$(printf '%s' "$PATH" | tr ':' '\\n' | grep -vxF "$here" | paste -sd: -)
real=$(PATH="$path_rest" command -v {_shell(shell)}) || real=/bin/{shell}
if [ "${{BLACKBOX_AGENT_SANDBOX:-}}" = 1 ] || [ ! -r "$profile" ]; then exec "$real" "$@"; fi
BLACKBOX_AGENT_SANDBOX=1; export BLACKBOX_AGENT_SANDBOX
{_with_tools(_tools_dir(launchers)) if launchers else ""}exec {SANDBOX_EXEC} -f "$profile" "$real" "$@"
"""


def command_shim(profile: str, launchers: str = "") -> str:
    """A wrapper that runs the command it is given inside the profile — the interpreter launcher
    Blackbox hands the Hermes agent for its ``execute_code`` Python (Hermes's
    ``HERMES_EXECUTE_CODE_LAUNCHER`` hook point). Already inside a sandbox, or no profile: the
    command runs as it is (fail-open: execute_code always starts; Blackbox reports the level)."""
    return f"""#!/bin/sh
# Blackbox agent sandbox: the Hermes agent's execute_code interpreter — generated by Blackbox (File Shield).
profile={_shell(profile)}
if [ "${{BLACKBOX_AGENT_SANDBOX:-}}" = 1 ] || [ ! -r "$profile" ]; then exec "$@"; fi
BLACKBOX_AGENT_SANDBOX=1; export BLACKBOX_AGENT_SANDBOX
{_with_tools(_tools_dir(launchers)) if launchers else ""}exec {SANDBOX_EXEC} -f "$profile" "$@"
"""
