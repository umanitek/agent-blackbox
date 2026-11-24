"""The Linux policy text for one :class:`~...places.Places` policy: the line-oriented file
``blackbox-sandbox run --policy`` reads STRICTLY (``helper/src/platform/linux/sandbox/policy.rs``
— its module doc is the format). Line 2 carries the digest the launcher exports, as on macOS.

How each place is enforced (see the package doc): a protected item or key → ``hide-*`` (a mode-0000
mask, EACCES); Blackbox's own places, the shell startup files, every hook config and the startup
places → ``ro`` / ``startup-ro`` (EROFS); the folders above an item → ``pin`` (EBUSY). A place that
does not exist when the agent starts is skipped there (a mount needs something to cover), which is
why the startup FOLDERS get an empty placeholder (:mod:`.placeholders`).

Unlike Seatbelt, no line here can lift another: the launcher keeps the STRONGEST action per path
(hide over read-only over pin), so the never-list holds whatever the permissions above it say. It is
still rendered last, after its mark, so the file reads like the macOS profile.

Usage::

    text = render(places, "sha256:…", allowances)
"""

from __future__ import annotations

import os

from ...permissions import Allowances
from ...places import Places

#: The launcher, installed root-owned beside the system protection helper (no agent can replace it).
SANDBOX = "/usr/local/libexec/blackbox/blackbox-sandbox"
PROFILE_SUFFIX = ".policy"
HEADER = "# blackbox-sandbox policy 1"
NEVER_MARK = "# never-list — rendered last: the launcher keeps the strongest rule per place, so nothing above lifts it"

#: The container engines' sockets on Linux (Docker, rootless Docker, Docker Desktop, Podman,
#: colima, Lima): a container runs OUTSIDE the sandbox and can mount any folder (KI-622).
#: ``{runtime}`` is ``$XDG_RUNTIME_DIR``. Docker's TCP ports are refused by the helper's
#: per-agent rules (``docker refuse``).
DOCKER_SOCKETS = ("/run/docker.sock", "/var/run/docker.sock", "{runtime}/docker.sock", "{home}/.docker/desktop/docker.sock",
                  "{home}/.docker/run/docker.sock", "/run/podman/podman.sock", "{runtime}/podman/podman.sock")
DOCKER_SOCKET_GLOBS = ("{home}/.colima/*/docker.sock", "{home}/.lima/*/sock/docker.sock")
#: The display servers' sockets: the clipboard, typing into other windows and screenshots all go
#: through them (X11 is a full escape: any client reads and drives every window).
DISPLAY_SOCKET_GLOBS = ("/tmp/.X11-unix/*", "{runtime}/wayland-*")   # no-tmp: ok — X11 fixes its sockets in /tmp
#: The camera and the microphone: the devices and the sound servers.
DEVICE_GLOBS = ("/dev/video*", "/dev/media*")
DEVICE_PLACES = ("/dev/snd", "{runtime}/pipewire-0", "{runtime}/pulse/native")
#: The D-Bus buses: the session bus starts jobs OUTSIDE the sandbox (``systemd-run --user``,
#: ``gio launch``, the desktop portal) and holds the keyring (F4: hidden in phase 1, so the
#: keychain is blocked in effect); the system bus asks polkit, whose dialog the person may accept.
BUS_SOCKETS = ("{runtime}/bus", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket")
#: The person's own systemd (the user manager) and the other session services that start or change
#: things OUTSIDE the sandbox, hidden whole. ``{runtime}/systemd`` holds the manager's control
#: sockets — ``private`` (what ``systemctl --user`` and ``systemd-run --user`` fall back to when the
#: bus is hidden), ``notify`` and, on newer systemd, its varlink endpoints. Linux round L2 (kernel
#: 7.0): through ``private`` a sandboxed agent ran ``systemd-run --user`` OUTSIDE and read a
#: protected file, made a timer and restarted Blackbox's dashboard (security Critical
#: 2026-11-24-linux-sandbox-escape-systemd-s-private-u). Also: the accessibility bus (a D-Bus bus that
#: reads and drives every window), snapd's session agent (starts snap user services) and
#: PackageKit's debconf socket. No agent's work needs any of them.
USER_MANAGER_FOLDERS = ("{runtime}/systemd", "{runtime}/at-spi")
SESSION_SERVICE_SOCKETS = ("{runtime}/snapd-session-agent.socket", "{runtime}/pk-debconf-socket")
#: The cgroup tree, read-only: every cgroup of the person's own systemd is theirs to write, so an
#: agent could move itself out of its scope (``echo $$ > …/app.slice/x.scope/cgroup.procs``, proven
#: on kernel 7.0 in fix wave L-W1) — out of reach of the helper's per-agent network rules, which
#: match the scope. Reading it (Node's memory limit, ``systemd-cgls``) still works.
CGROUP_TREE = "/sys/fs/cgroup"
#: The runtime folder's sockets that stay reachable ON PURPOSE, with why. The drift test fails on
#: any socket a real machine has that is neither hidden by the never-list, nor behind a permission
#: (Docker, the display, the camera and microphone), nor named here.
REACHABLE_ON_PURPOSE = {
    "{runtime}/gnupg": "gpg-agent: signs the agent's git commits and serves ssh keys for git pushes; the key files "
                       "themselves stay hidden, and ssh back into this machine is refused by the helper's rules",
}


def runtime_dir() -> str:
    """``$XDG_RUNTIME_DIR``, or systemd's usual ``/run/user/<uid>``."""
    return os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"   # windows-footgun: ok (Linux module)


def _escape(path: str) -> str:
    return path.replace("\\", "\\\\").replace("\n", "\\n")


def _line(directive: str, path: str) -> str:
    return f"{directive} {_escape(path)}"


def _wild(path: str) -> bool:
    return "*" in path or "?" in path


def _places(directive: str, paths: tuple[str, ...] | list[str], home: str, runtime: str) -> list[str]:
    """One line per path (``{home}`` / ``{runtime}`` filled); a glob gets ``<directive>-glob``."""
    lines = []
    for template in paths:
        path = template.replace("{home}", home).replace("{runtime}", runtime)
        lines.append(_line(f"{directive}-glob" if _wild(path) else directive, path))
    return lines


def permission_lines(allowances: Allowances, home: str = "", runtime: str = "") -> list[str]:
    """What the person's permissions refuse for one scope (each one not allowed) and the folder rules."""
    home = home or os.path.realpath(os.path.expanduser("~"))
    runtime = runtime or runtime_dir()
    refused = allowances.refused
    lines = []
    if "local-ports" in refused:
        lines.append("local-ports block")
        lines += [f"allow-port {port}" for port in sorted(set(allowances.ports))]
        if allowances.dashboard_port:
            lines.append(f"dashboard-port {allowances.dashboard_port}")
    if "docker" in refused:
        lines.append("docker refuse")
        lines += _places("hide-socket", DOCKER_SOCKETS + DOCKER_SOCKET_GLOBS, home, runtime)
    if "clipboard" in refused:   # on Linux the clipboard IS the display server
        lines.append("display refuse")
        lines += _places("hide-socket", DISPLAY_SOCKET_GLOBS, home, runtime)
    else:
        lines.append("display allow")
    if "camera-mic" in refused:
        lines.append("devices refuse")
        lines += _places("hide-socket", DEVICE_GLOBS + DEVICE_PLACES, home, runtime)
    lines += _places("ro", list(allowances.tool_folders) + list(allowances.tool_globs), home, runtime)
    lines += [_line("hide-dir", path) for path in allowances.hidden]
    lines += [_line("ro", path) for path in allowances.read_only]
    return lines


def _never(places: Places, home: str, runtime: str) -> list[str]:
    """The never-list: protected items and keys hidden, the canary hidden, Blackbox's own places,
    the startup files and places read-only, the folders above an item pinned, the buses, the user
    manager and the session services hidden, the cgroup tree read-only."""
    lines = [_line("hide-dir", path) for path in places.denied_folders]
    lines += [_line("hide-file", path) for path in places.denied_files if path != places.canary]
    lines += [_line("hide-glob", glob) for glob in places.denied_globs]
    if places.canary:
        lines.append(_line("canary", places.canary))
    lines += [_line("ro", path) for path in places.no_write]
    lines += [_line("ro-glob", glob) for glob in places.no_write_globs]
    lines += [_line("ro-file", path) for path in places.no_write_files]
    lines += [_line("startup-ro", path) for path in places.startup_folders + places.startup_files]
    lines += [_line("startup-ro-glob", glob) for glob in places.startup_globs]
    lines += [_line("pin", path) for path in places.no_rename]
    lines.append("bus refuse")
    lines += _places("hide-socket", BUS_SOCKETS + SESSION_SERVICE_SOCKETS, home, runtime)
    lines += _places("hide-dir", USER_MANAGER_FOLDERS, home, runtime)
    lines.append(_line("ro", CGROUP_TREE))
    return lines


def render(places: Places, digest_line: str = "", allowances: Allowances = Allowances(), home: str = "",
           runtime: str = "") -> str:
    """The policy for *places* with the permissions *allowances* lets through: the permission lines,
    then the never-list after its mark. *home* / *runtime* default to this person's."""
    home = home or os.path.realpath(os.path.expanduser("~"))
    runtime = runtime or runtime_dir()
    lines = [HEADER, f"# Blackbox agent sandbox — generated, do not edit. {digest_line}".rstrip()]
    lines += permission_lines(allowances, home, runtime)
    lines.append(NEVER_MARK)
    lines += _never(places, home, runtime)
    return "\n".join(dict.fromkeys(lines)) + "\n"


__all__ = ["BUS_SOCKETS", "CGROUP_TREE", "DEVICE_GLOBS", "DEVICE_PLACES", "DISPLAY_SOCKET_GLOBS", "DOCKER_SOCKETS", "DOCKER_SOCKET_GLOBS",
           "HEADER", "NEVER_MARK", "PROFILE_SUFFIX", "REACHABLE_ON_PURPOSE", "SANDBOX", "SESSION_SERVICE_SOCKETS",
           "USER_MANAGER_FOLDERS", "permission_lines", "render", "runtime_dir"]
