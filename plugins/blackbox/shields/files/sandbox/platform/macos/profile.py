"""The Seatbelt profile text for one :class:`~..places.Places` policy (see the package doc for what
Seatbelt can and can not refuse).

Usage::

    text = render(places, "sha256:…")
"""

from __future__ import annotations

import os
import re

from ...permissions import Allowances
from ...places import Places

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
PROFILE_SUFFIX = ".sb"
#: Programs that drive other apps (AppleScript / JavaScript for Automation, Automator workflows,
#: Shortcuts): refused inside — the app they drive would act outside the sandbox. A copy of one
#: does not run either (macOS kills a copied platform binary).
APP_DRIVERS = ("/usr/bin/osascript", "/usr/bin/automator", "/usr/bin/shortcuts")
#: The SSH port on this Mac: an agent may not log back into the Mac outside its sandbox.
LOCAL_SSH = ('"localhost:22"',)


def _quote(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _glob_regex(glob: str) -> str:
    """``/dir/*.pem`` (or ``/plugins/*/blackbox-addon.json``: a wildcard in any part) as a Seatbelt
    regex; ``*`` and ``?`` never cross a ``/``."""
    body = "".join("[^/]*" if char == "*" else "[^/]" if char == "?" else re.escape(char) for char in glob)
    return "#\"^" + body.replace('"', '\\"') + "$\""


#: The container engines' sockets on macOS (Docker Desktop, colima, OrbStack, Rancher's socket in ~/.rd,
#: Lima, Podman machine): a container runs OUTSIDE the sandbox and can mount any folder, so a
#: sandboxed agent may reach these only when the ``docker`` permission allows it (KI-622). Both
#: spellings of /var/run (a link to /private/var/run). Probed on macOS 27.2 (2026-11-23):
#: ``(remote unix-socket (path-literal …))`` and ``(… (regex …))`` refuse a connect with EPERM.
DOCKER_SOCKETS = ("/var/run/docker.sock", "/private/var/run/docker.sock", "{home}/.docker/run/docker.sock",
                  "{home}/.docker/desktop/docker.sock", "{home}/.orbstack/run/docker.sock", "{home}/.rd/docker.sock")
DOCKER_SOCKET_GLOBS = ("{home}/.colima/*/docker.sock", "{home}/.lima/*/sock/docker.sock",
                       "{home}/Library/Containers/com.docker.docker/Data/*.sock",
                       "{home}/.local/share/containers/podman/machine/*/podman.sock",
                       "{home}/.local/share/containers/podman/machine/*/*/podman.sock")
#: The Docker engine's TCP ports on this Mac (plain and TLS).
DOCKER_PORTS = (2375, 2376)


#: The pasteboard server: refusing its lookup refuses reading and writing the clipboard.
PASTEBOARD = "com.apple.pasteboard.1"


#: Opens the reachable-ports block, the ONLY lines after the never-list. WHY there: probed on macOS
#: 27.2 (2026-11-23), an ``(allow network-outbound …)`` list followed by any later
#: ``(deny network-outbound …)`` (Docker's ports, the never-list's ssh rule) let the allowed ports
#: through only SOMETIMES — nondeterministically, run to run. With the allows last it held every
#: time. They never name a port the never-list or another refused permission closes (:func:`port_lines`).
PORTS_MARK = "; reachable ports while local-ports is blocked — after the never-list, never one it closes"
#: The ports the never-list closes on this Mac (ssh back into it).
NEVER_PORTS = (22,)


def _local_port_lines(allowances: Allowances) -> list[str]:
    """Every service on this Mac refused (the listed ports are reopened at the very end, :func:`port_lines`).
    Probed on macOS 27.2 (2026-11-23): ``localhost`` here also matches every address of this Mac
    (en0, link-local, Tailscale), so "this Mac" is covered whatever address an agent dials."""
    return ['(deny network-outbound (remote ip "localhost:*"))']


def port_lines(allowances: Allowances) -> list[str]:
    """The listed ports and Blackbox's dashboard port, reopened while local-ports is blocked — minus
    the never-list's ports and Docker's while Docker is refused."""
    if "local-ports" not in allowances.refused:
        return []
    closed = set(NEVER_PORTS) | (set(DOCKER_PORTS) if "docker" in allowances.refused else set())
    ports = sorted({*allowances.ports, *([allowances.dashboard_port] if allowances.dashboard_port else [])} - closed)
    if not ports:
        return []
    return [PORTS_MARK, "(allow network-outbound\n  " + "\n  ".join(f'(remote ip "localhost:{port}")' for port in ports) + ")"]


def _docker_lines(home: str) -> list[str]:
    sockets = [f"(remote unix-socket (path-literal {_quote(path.format(home=home))}))" for path in DOCKER_SOCKETS]
    sockets += [f"(remote unix-socket (regex {_glob_regex(glob.format(home=home))}))" for glob in DOCKER_SOCKET_GLOBS]
    sockets += [f'(remote ip "localhost:{port}")' for port in DOCKER_PORTS]
    return ["(deny network-outbound\n  " + "\n  ".join(sockets) + ")"]


#: The comment that opens the never-list: everything after it is rendered LAST in every profile,
#: so no permission rule above can lift it (Seatbelt: a later rule wins).
NEVER_MARK = "; never-list — rendered last: no permission above lifts it"
#: cfprefsd's two services. A ``defaults write`` (any CFPreferences write) is made BY cfprefsd, so
#: the file denies below do not hold for it, and Seatbelt's ``user-preference-write`` is accepted
#: but not enforced for a ``sandbox-exec`` process (both measured on macOS 27 with a throwaway
#: domain, tests/plugins/test_blackbox_sandbox_login_preferences.py). Denying BOTH lookups (never
#: one: without only the agent's, every preference write fails) makes CFPreferences read and write
#: the plist files itself, as the sandboxed process — every other domain keeps working, and the
#: file denies of the login window's and login items' preferences then hold.
CFPREFSD_SERVICES = ("com.apple.cfprefsd.agent", "com.apple.cfprefsd.daemon")
#: PREPARED, OFF: on once the VM probe of the real login-window domain shows the installed profile
#: lets a ``defaults write`` through (wave 9, item 4), and real agents ran in the VM with it (a
#: sandboxed program's preference writes then miss a running app's cfprefsd cache until it restarts).
CLOSE_PREFERENCES_THROUGH_CFPREFSD = False


def cfprefsd_lines() -> list[str]:
    """The rule that puts a sandboxed process's preferences in direct mode (:data:`CFPREFSD_SERVICES`)."""
    return ["(deny mach-lookup " + " ".join(f'(global-name "{name}")' for name in CFPREFSD_SERVICES) + ")"]


def render(places: Places, digest_line: str = "", allowances: Allowances = Allowances()) -> str:
    """The Seatbelt profile for *places* with the permissions *allowances* lets through. Everything
    not named stays allowed: the agent works as before, except on what the person (and Blackbox)
    protect. The permission lines come first, then the never-list (:data:`NEVER_MARK`); only the
    ports local-ports keeps reachable follow it (:data:`PORTS_MARK`), never one the never-list closes."""
    lines = ["(version 1)", f"; Blackbox agent sandbox — generated, do not edit. {digest_line}".rstrip(), "(allow default)"]
    lines += permission_lines(allowances)
    lines.append(NEVER_MARK)
    lines += _never(places)
    lines += port_lines(allowances)
    return "\n".join(lines) + "\n"


def permission_lines(allowances: Allowances, home: str = "") -> list[str]:
    """What the person's permissions refuse for one scope: each profile permission not lifted
    (Docker's sockets, the person's tool folders …) and the folder rules (kept out / read only)."""
    home = home or os.path.realpath(os.path.expanduser("~"))
    lines = _local_port_lines(allowances) if "local-ports" in allowances.refused else []
    lines += _docker_lines(home) if "docker" in allowances.refused else []
    if "clipboard" in allowances.refused:   # probed 2026-11-23: pbpaste fails at once, no hang
        lines.append(f'(deny mach-lookup (global-name "{PASTEBOARD}"))')
    tools = [f"(subpath {_quote(p)})" for p in allowances.tool_folders] + [f"(regex {_glob_regex(g)})" for g in allowances.tool_globs]
    if tools:   # tool-folders blocked: a program left there would run outside the sandbox later
        lines.append("(deny file-write*\n  " + "\n  ".join(tools) + ")")
    if allowances.hidden:
        lines.append("(deny file-read* file-write* file-link\n  " + "\n  ".join(f"(subpath {_quote(p)})" for p in allowances.hidden) + ")")
    if allowances.read_only:
        lines.append("(deny file-write*\n  " + "\n  ".join(f"(subpath {_quote(p)})" for p in allowances.read_only) + ")")
    return lines


def _never(places: Places) -> list[str]:
    """The never-list: the person's protected items, Blackbox's own places, the startup places, app
    drivers, ssh to this Mac and signals out of the sandbox."""
    refused = [f"(subpath {_quote(p)})" for p in places.denied_folders]
    refused += [f"(literal {_quote(p)})" for p in places.denied_files if p != places.canary]
    refused += [f"(regex {_glob_regex(g)})" for g in places.denied_globs]
    lines = []
    if refused:
        lines.append("(deny file-read* file-write* file-link\n  " + "\n  ".join(refused) + ")")
    if places.canary:
        # The canary is refused WITHOUT a report: every hook call probes it, and a log line per probe
        # buried the refusals the helper reads (KI-600: ~30 canary lines, then no line for a real read).
        lines.append(f"(deny file-read* file-write* file-link (literal {_quote(places.canary)}) (with no-report))")
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
    if CLOSE_PREFERENCES_THROUGH_CFPREFSD:
        lines += cfprefsd_lines()
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
    return lines



__all__ = ["APP_DRIVERS", "CFPREFSD_SERVICES", "CLOSE_PREFERENCES_THROUGH_CFPREFSD", "DOCKER_PORTS", "DOCKER_SOCKETS", "DOCKER_SOCKET_GLOBS", "LOCAL_SSH", "NEVER_MARK", "NEVER_PORTS", "PASTEBOARD", "PORTS_MARK", "PROFILE_SUFFIX", "SANDBOX_EXEC", "cfprefsd_lines", "permission_lines", "port_lines",
           "render"]
