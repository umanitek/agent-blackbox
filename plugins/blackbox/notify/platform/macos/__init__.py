"""macOS: Blackbox's own notifier app, and the system's script notifier as the fallback.

``Blackbox.app`` (``notifier.swift`` in this folder, built by ``build.sh``) is a tiny app whose
only job is to hand one notification to macOS, so it appears under Blackbox's own name and the
person can allow, silence or style it in System Settings → Notifications like any app. It lives
in ``$BLACKBOX_HOME/notifier/`` and is put there from a verified archive (:func:`install`): the
release's ``blackbox-notify-darwin.zip`` checked against the SHA-256 committed in this checkout,
or a locally built one a test or a developer names. macOS asks the person's permission the first
time (``request``); :func:`install` triggers that once, with the installer's plain explanation.

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
from pathlib import Path
from typing import Optional

from ....kernel import constants
from ...model import NotifierStatus

APP_NAME = "Blackbox.app"
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


def status() -> NotifierStatus:
    if _app_ready():
        code, answer = _run([str(app() / EXECUTABLE), "status"])
        if code == 0 and answer in ("authorized", "denied", "not-determined"):
            detail = {"authorized": "Notifications appear under Blackbox's own name.",
                      "denied": "Notifications are switched off for Blackbox in System Settings → Notifications.",
                      "not-determined": "macOS will ask once whether Blackbox may show notifications."}[answer]
            return NotifierStatus("app", answer != "denied", answer, detail)
    if Path(OSASCRIPT).is_file():
        return NotifierStatus("fallback", True, "unknown",
                              "Blackbox's own notifier is not installed; notifications appear through macOS's script notifier.")
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


def send(title: str, body: str, level: str, ident: str) -> bool:
    """Show one notification: through Blackbox's app when it is installed and allowed, else
    through the system's script notifier. False when neither could show it."""
    if _app_ready():
        code, _ = _run([str(app() / EXECUTABLE), "send", title[:200], body[:600], ident[:120], _SOUND.get(level, "0")])
        if code == 0:
            return True
        if code == 3:
            return False   # the person said no to Blackbox's notifications: do not go round that
    return _send_fallback(title, body)


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
    _run([str(app() / EXECUTABLE), "request"])   # macOS asks the person once; either answer is theirs
    return status()


def remove() -> None:
    shutil.rmtree(home(), ignore_errors=True)
