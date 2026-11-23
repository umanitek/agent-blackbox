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


#: The container engines' sockets on macOS (Docker Desktop, colima, OrbStack, Rancher Desktop,
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


def _local_port_lines(allowances: Allowances) -> list[str]:
    """Every service on this Mac refused, then the listed ports and Blackbox's dashboard reopened.
    Probed on macOS 27.2 (2026-11-23): ``localhost`` here also matches every address of this Mac
    (en0, link-local, Tailscale), so "this Mac" is covered whatever address an agent dials."""
    ports = sorted({*allowances.ports, *([allowances.dashboard_port] if allowances.dashboard_port else [])})
    lines = ['(deny network-outbound (remote ip "localhost:*"))']
    if ports:
        lines.append("(allow network-outbound\n  " + "\n  ".join(f'(remote ip "localhost:{port}")' for port in ports) + ")")
    return lines


def _docker_lines(home: str) -> list[str]:
    sockets = [f"(remote unix-socket (path-literal {_quote(path.format(home=home))}))" for path in DOCKER_SOCKETS]
    sockets += [f"(remote unix-socket (regex {_glob_regex(glob.format(home=home))}))" for glob in DOCKER_SOCKET_GLOBS]
    sockets += [f'(remote ip "localhost:{port}")' for port in DOCKER_PORTS]
    return ["(deny network-outbound\n  " + "\n  ".join(sockets) + ")"]


#: The comment that opens the never-list: everything after it is rendered LAST in every profile,
#: so no permission rule above can lift it (Seatbelt: a later rule wins).
NEVER_MARK = "; never-list — rendered last: no permission above lifts it"


def render(places: Places, digest_line: str = "", allowances: Allowances = Allowances()) -> str:
    """The Seatbelt profile for *places* with the permissions *allowances* lets through. Everything
    not named stays allowed: the agent works as before, except on what the person (and Blackbox)
    protect. The permission lines come first, the never-list (:data:`NEVER_MARK`) last."""
    lines = ["(version 1)", f"; Blackbox agent sandbox — generated, do not edit. {digest_line}".rstrip(), "(allow default)"]
    lines += permission_lines(allowances)
    lines.append(NEVER_MARK)
    lines += _never(places)
    return "\n".join(lines) + "\n"


def permission_lines(allowances: Allowances, home: str = "") -> list[str]:
    """What the person's permissions refuse for one scope: each profile permission not lifted
    (Docker's sockets, the person's tool folders …) and the folder rules (kept out / read only)."""
    home = home or os.path.realpath(os.path.expanduser("~"))
    lines = _local_port_lines(allowances) if "local-ports" in allowances.refused else []
    lines += _docker_lines(home) if "docker" in allowances.refused else []   # after local-ports: a listed port never reopens Docker's
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



__all__ = ["APP_DRIVERS", "DOCKER_PORTS", "DOCKER_SOCKETS", "DOCKER_SOCKET_GLOBS", "LOCAL_SSH", "NEVER_MARK", "PASTEBOARD", "PROFILE_SUFFIX", "SANDBOX_EXEC", "permission_lines", "render"]
