"""The Seatbelt profile text for one :class:`~..places.Places` policy (see the package doc for what
Seatbelt can and can not refuse).

Usage::

    text = render(places, "sha256:…")
"""

from __future__ import annotations

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


def permission_lines(allowances: Allowances) -> list[str]:
    """What the person's permissions refuse for one scope: folder rules (kept out / read only)."""
    lines = []
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



__all__ = ["APP_DRIVERS", "LOCAL_SSH", "NEVER_MARK", "PROFILE_SUFFIX", "SANDBOX_EXEC", "permission_lines", "render"]
