"""``open-app``: a sandboxed agent's ``open -a App file …`` or ``open <folder>`` (sandbox permission
``open-apps``, ask by default). The app must be installed and NOT one that runs commands or drives
other apps (Terminal, iTerm, Script Editor, Automator, Shortcuts … — ``platform.APP_DRIVER_APPS``:
``open -a Terminal x.command`` would run it outside the sandbox). Each file must exist, in its
canonical spelling, and be neither a protected item (nor inside one) nor one of Blackbox's own
places. A folder alone opens in Finder — never an app bundle (a ``.app`` folder, or any folder
holding ``Contents/MacOS``; nor as a file for an app): Finder would launch it, outside the sandbox. Then ``/usr/bin/open -a <app> -- <files>`` outside the sandbox.

**Security cost:** the app works on the file outside the sandbox, with the person's rights.

An app the PERSON installed (not root: ``platform.find_person_app``) is decided by ``user-apps``
too (block by default), so one switch says which apps, the other whether at all:

* ``open-apps`` blocked → refused, naming open-apps (whatever ``user-apps`` says);
* ``user-apps`` blocked → refused, naming user-apps ("Opening apps you installed"), so the person
  knows what to change;
* ``user-apps`` on ask → ONE request, for user-apps (its answer covers this opening: never two
  questions for one ``open``);
* ``user-apps`` allowed → ``open-apps`` decides as for any other app.

Usage::

    API_WRITES["open-app"](context, {"argv": ["-a", "Preview", "/Users/me/shop/a.pdf"], "pid": 4242})
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from ..... import audit
from .....kernel import constants
from ....shield_api import ShieldApiError, ShieldContext
from ... import mode as mode_module
from .....kernel.os_layout import machine_words
from .. import permissions, platform
from .asking import Asking, Planned, decide

PERMISSION = "open-apps"
#: The permission that widens which apps may be opened: the ones the person installed.
USER_APPS = "user-apps"
MAX_FILES = 20
FINDER = "Finder"
#: A folder Finder runs instead of showing: an app bundle, by name or by shape.
BUNDLE_SUFFIX = ".app"
BUNDLE_PROGRAMS = os.path.join("Contents", "MacOS")


def _inside(path: str, place: str) -> bool:
    return path == place or path.startswith(place.rstrip("/") + "/")


def _is_bundle(path: str) -> bool:
    return path.lower().endswith(BUNDLE_SUFFIX) or os.path.isdir(os.path.join(path, BUNDLE_PROGRAMS))


def _file(word: str, folder: str, protected: tuple[str, ...]) -> str:
    path = os.path.realpath(os.path.join(folder or "/", os.path.expanduser(word)))
    if not os.path.exists(path):
        raise ShieldApiError(400, f"{word} does not exist")
    own = [os.path.realpath(str(constants.blackbox_home())), os.path.realpath(str(constants.hermes_root()))]
    if any(_inside(path, os.path.realpath(os.path.expanduser(item))) for item in protected) or any(_inside(path, place) for place in own):
        raise ShieldApiError(403, f"{word} is kept from AI agents, so Blackbox will not open it for one")
    if _is_bundle(path):
        raise ShieldApiError(403, f"{word} is an app: Blackbox does not start an app an agent names by its folder")
    return path


def parse(argv: Any, folder: str) -> tuple[str, list[str], bool]:
    """``(app path, files, the person installed the app)`` for *argv*; raises ShieldApiError for
    anything Blackbox does not open."""
    words = argv if isinstance(argv, list) and all(isinstance(word, str) for word in argv) else []
    protected = mode_module.protected(mode_module.current())
    if len(words) == 1:   # open <folder>: Finder
        path = _file(words[0], folder, protected)
        if not os.path.isdir(path):
            raise ShieldApiError(400, "name the app: open -a App file")
        return platform.find_app(FINDER) or "/System/Library/CoreServices/Finder.app", [path], False
    if len(words) < 2 or words[0] != "-a":
        raise ShieldApiError(400, "Blackbox opens a file in a named app: open -a App file")
    app = platform.find_app(words[1])
    persons = not app
    if persons:
        app = platform.find_person_app(words[1])
    if not app or platform.is_driver(app):
        raise ShieldApiError(403, f"{words[1]} is not an installed app Blackbox opens for agents (never one that runs commands)")
    files = words[2:]
    if len(files) > MAX_FILES:
        raise ShieldApiError(400, f"at most {MAX_FILES} files at a time")
    return app, [_file(word, folder, protected) for word in files], persons


def blocked_words(name: str) -> str:
    """The refusal for an app the person installed while ``user-apps`` is blocked: names the
    permission, so the person knows what to change."""
    permission = permissions.BY_ID[USER_APPS].name
    return (f"{name} is an app you installed yourself, and \"{permission}\" ({USER_APPS}) is blocked for this AI agent in "
            "Blackbox's sandbox permissions; allow it on Blackbox's Security page, or open it yourself.")


def _decide_persons_app(name: str, asked: Asking, command: str) -> None:
    """The decision for an app the person installed (see the module doc); raises unless allowed now."""
    if permissions.decide(PERMISSION, asked.agent, asked.folder) is permissions.Mode.BLOCK:
        decide(PERMISSION, asked, command)   # refused, naming open-apps
    mode = permissions.decide(USER_APPS, asked.agent, asked.folder)
    if mode is permissions.Mode.BLOCK:
        raise ShieldApiError(403, blocked_words(name))
    decide(USER_APPS if mode is permissions.Mode.ASK else PERMISSION, asked, command)


def open_app(context: ShieldContext, body: Mapping[str, Any]) -> Planned:
    """The door: the app and files checked, the asker found and the permission decided (raises when
    not allowed); the opening runs in the job (``brokered``)."""
    if set(body) - {"argv", "pid", "cwd"}:
        raise ShieldApiError(400, "a request carries the app and the files only")
    asked = Asking.of(context, body)
    app, files, persons = parse(body.get("argv"), asked.folder)
    name = os.path.splitext(os.path.basename(app))[0]   # "Preview" (.app), "org.gnome.Evince" (.desktop)
    command = f"open -a {name} " + " ".join(files)
    if persons:
        _decide_persons_app(name, asked, command)
    else:
        decide(PERMISSION, asked, command)

    def work() -> tuple[int, str]:
        code = platform.open_with(app, files)
        audit.record_for(audit.SANDBOX_RECORDER, event="brokered_open", workspace=asked.folder,
                         detail={"what": "app", "app": name, "files": len(files), "agent": asked.agent, "exit": code})
        return code, f"Opened in {name}." if code == 0 else f"{machine_words().capitalize()} could not open it."
    return Planned("open-app", command, asked, work)


__all__ = ["FINDER", "MAX_FILES", "PERMISSION", "USER_APPS", "blocked_words", "open_app", "parse"]
