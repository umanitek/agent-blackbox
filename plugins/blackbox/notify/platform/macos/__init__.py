"""macOS: Blackbox's own notifier app, and the system's script notifier as the fallback.

``Blackbox.app`` (``notifier.swift`` in this folder, built by ``build.sh``) is a tiny app whose
only job is to hand one notification to macOS, so it appears under Blackbox's own name and the
person can allow, silence or style it in System Settings → Notifications like any app. It lives
in ``$BLACKBOX_HOME/notifier/`` and is put there from a verified archive (:func:`install`): the
release's ``blackbox-notify-darwin.zip`` checked against the SHA-256 committed in this checkout,
or a locally built one a test or a developer names. macOS asks the person's permission ONCE, and
only a person who is there (:mod:`.session`, KI-PENDING-411cdb): :func:`request` opens the app
through LaunchServices in their desktop session — from the installer only when it runs there,
otherwise from the dashboard's "Allow Blackbox to notify you" card or Blackbox Desktop's first
run. When the answer is off, :func:`status` says so with a one-click way to System Settings, and
:func:`send` says what became of each notification (:class:`..model.Delivery`).

Without the app (not installed, or it cannot run) :func:`send` falls back to ``osascript``'s
``display notification``: it works with no install and no permission of Blackbox's own, but macOS
shows it under "Script Editor" — so the text says "Blackbox" itself, and :func:`status` says
which of the two is in use.

The dashboard process (the person's own user) runs this; the root helper never shows UI.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Optional

from ....kernel import constants
from ...model import Delivery, NotifierStatus
from . import session

APP_NAME = "Blackbox.app"
BUNDLE_ID = "ai.umanitek.blackbox.notifier"
OPEN = "/usr/bin/open"
EXECUTABLE = "Contents/MacOS/blackbox-notify"
OSASCRIPT = "/usr/bin/osascript"
TIMEOUT_SECONDS = 8.0
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
_SOUND = {"critical": "1", "warning": "0", "info": "0"}


def home() -> Path:
    return constants.blackbox_home() / "notifier"


def app() -> Path:
    return home() / APP_NAME


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return done.returncode, (done.stdout or "").strip()[:200]


def _app_ready() -> bool:
    binary = app() / EXECUTABLE
    return binary.is_file() and not binary.is_symlink()


#: The system's notification settings, opened at Blackbox's own entry (macOS 13 and later; an
#: older macOS opens the Notifications pane itself).
SETTINGS_URL = "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=" + BUNDLE_ID
SETTINGS_LABEL = "Open Notification settings for Blackbox"
#: The notifier's exit codes (notifier.swift).
_SENT, _DENIED, _NOT_DETERMINED = 0, 3, 5
_SCREEN_NOTE = " The screen is shared or mirrored now, and macOS hides banners then: it waits in Notification Center."
_FALLBACK_NOTE = " Meanwhile, security notices still reach you through macOS's script notifier, labelled Blackbox."


def _permission() -> str:
    """The notifier app's answer: ``authorized`` | ``denied`` | ``not-determined``, "" without one."""
    if not _app_ready():
        return ""
    code, answer = _run([str(app() / EXECUTABLE), "status"])
    return answer if code == 0 and answer in ("authorized", "denied", "not-determined") else ""


def _screen_hidden() -> bool:
    """True while banners are hidden: a Screen Sharing viewer is connected, or the display is
    mirrored (the notifier's ``display`` answer; an older notifier does not know the word)."""
    if session.screen_shared():
        return True
    if not _app_ready():
        return False
    code, answer = _run([str(app() / EXECUTABLE), "display"])
    return code == 0 and answer == "mirrored"


def status() -> NotifierStatus:
    """What shows Blackbox's notifications here and whether the person allowed it, in words —
    with the way to change it (*settings*) while it is off or not asked yet."""
    permission = _permission()
    hidden = _screen_hidden()
    if permission == "authorized":
        return NotifierStatus("app", True, permission, "Notifications appear under Blackbox's own name." + (_SCREEN_NOTE if hidden else ""),
                              screen_hidden=hidden)
    if permission == "denied":
        return NotifierStatus("app", True, permission,
                              "Notifications are switched off for Blackbox in System Settings → Notifications." + _FALLBACK_NOTE,
                              SETTINGS_URL, SETTINGS_LABEL, screen_hidden=hidden)
    if permission == "not-determined":
        can_ask = session.console_is_ours()
        ask = ("Choose \"Allow Blackbox to notify you\" on the dashboard and macOS asks once."
               if can_ask else "macOS asks when you are logged in to this Mac's desktop and open the Blackbox dashboard.")
        return NotifierStatus("app", True, permission, "macOS has not asked yet whether Blackbox may notify you. " + ask + _FALLBACK_NOTE,
                              SETTINGS_URL, SETTINGS_LABEL, can_ask=can_ask, screen_hidden=hidden)
    if Path(OSASCRIPT).is_file():
        return NotifierStatus("fallback", True, "unknown",
                              "Blackbox's own notifier is not installed; notifications appear through macOS's script notifier.",
                              screen_hidden=hidden)
    return NotifierStatus("none", False, "unknown", "No way to show a notification on this Mac; the dashboard shows every one.")


def _quoted(text: str) -> str:
    """*text* as an AppleScript string literal (a quote or backslash can never end it early)."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ") + '"'


def _send_fallback(title: str, body: str) -> bool:
    if not Path(OSASCRIPT).is_file():
        return False
    script = f"display notification {_quoted(body[:600])} with title \"Blackbox\" subtitle {_quoted(title[:200])}"
    code, _ = _run([OSASCRIPT, "-e", script])
    return code == 0


def _through_fallback(title: str, body: str, why: str) -> Delivery:
    if _send_fallback(title, body):
        return Delivery("fallback", why + " It went through macOS's script notifier instead, labelled Blackbox.")
    return Delivery("not-shown", why + " macOS's script notifier could not show it either.")


def send(title: str, body: str, level: str, ident: str) -> Delivery:
    """Hand one notification to macOS and say honestly what became of it (:class:`Delivery`).

    Through Blackbox's app when the person allowed it. While its permission is off or not asked
    yet, a SECURITY notice (``warning`` / ``critical``) still reaches the person through the
    system's script notifier, labelled Blackbox — nothing about a threat is silently lost; an
    ``info`` notice (an agent started, a summary) is not pushed round their choice. The app never
    asks for permission while sending: that question waits for the person (:func:`request`)."""
    if _app_ready():
        code, _ = _run([str(app() / EXECUTABLE), "send", title[:200], body[:600], ident[:120], _SOUND.get(level, "0")])
        if code == _SENT:
            hidden = _screen_hidden()
            return Delivery("delivered", "Delivered to Notification Center." + (_SCREEN_NOTE if hidden else ""))
        if code in (_DENIED, _NOT_DETERMINED):
            why = ("macOS did not show it: notifications are off for Blackbox." if code == _DENIED
                   else "macOS did not show it: you have not allowed Blackbox's notifications yet.")
            return _through_fallback(title, body, why) if level in ("warning", "critical") else Delivery("not-shown", why)
        return _through_fallback(title, body, "Blackbox's notifier could not hand it to macOS.")
    return _through_fallback(title, body, "Blackbox's own notifier is not installed.")


def request() -> NotifierStatus:
    """Ask the person — now, while they are at this Mac — whether Blackbox may notify them.

    The notifier app is opened through LaunchServices (``open``), so macOS shows its question in
    the person's desktop session (an app run directly from a background process is answered
    "denied" with no question). Only when this user is at the desktop and macOS has not asked yet;
    otherwise nothing is asked and the status says why. Called from a click (the dashboard's
    card, Blackbox Desktop's first run) or an installer running in the person's own session."""
    current = status()
    if current.permission != "not-determined" or not session.console_is_ours():
        return current
    _run([OPEN, "-n", "-g", str(app()), "--args", "request"])
    return replace(current, can_ask=False,
                   detail="macOS is asking now whether Blackbox may notify you — look at the top right of your screen and choose Allow.")


def open_settings() -> bool:
    """Open System Settings at Blackbox's notifications (the person's click). False when nobody
    is at this Mac's desktop to see it."""
    if not session.console_is_ours():
        return False
    code, _ = _run([OPEN, SETTINGS_URL])
    return code == 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def install(source: Optional[Path] = None, sha256: str = "") -> NotifierStatus:
    """Put ``Blackbox.app`` in place from the archive *source*, checked against *sha256* first
    (anything else installs nothing and raises ValueError), then ask the person's permission
    once. With no *source*, only the status is answered (the fallback stays in use)."""
    if source is None:
        return status()
    source = Path(source)
    if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"not a notifier archive: {source}")
    if len(sha256) != 64 or _sha256(source) != sha256.lower():
        raise ValueError("the notifier archive's checksum does not match: nothing was installed")
    staging = home() / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            if any(name.startswith(("/", "..")) or "/../" in name or not name.startswith(APP_NAME + "/") for name in names):
                raise ValueError("the notifier archive holds something other than Blackbox.app")
        # ditto keeps the bundle's signature and executable bits; zipfile.extractall keeps neither.
        code, _ = _run(["/usr/bin/ditto", "-x", "-k", str(source), str(staging)])
        if code != 0 or not (staging / APP_NAME / EXECUTABLE).is_file():
            raise ValueError("the notifier archive could not be unpacked")
        (staging / APP_NAME / EXECUTABLE).chmod(0o755)
        shutil.rmtree(app(), ignore_errors=True)
        (staging / APP_NAME).rename(app())
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    # macOS asks only a person who is there to answer (session.py): from an installer in their own
    # desktop session, now; otherwise the dashboard's card or Blackbox Desktop asks later.
    return request() if session.in_desktop_session() else status()


def remove() -> None:
    shutil.rmtree(home(), ignore_errors=True)
