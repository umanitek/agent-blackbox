"""macOS: is the person at this Mac — and can they see a banner right now?

macOS asks "may Blackbox show notifications?" ONCE, as a banner in the person's desktop session.
Asked from anywhere else (an installer run over SSH, a login service with no desktop, a process
not launched through LaunchServices) the system answers "denied" at once with no banner, and a
banner nobody is there to answer goes away and is recorded as Off — for good (KI-PENDING-411cdb,
VM pass 3, 2026-11-22). So the question is asked only when the person is present:

* :func:`console_is_ours` — the Mac's desktop (``/dev/console``) belongs to this user: someone
  is logged in to it as us, so an app opened through LaunchServices appears in front of them.
* :func:`in_desktop_session` — and THIS process runs inside that desktop session (launchd's
  ``Aqua`` manager), not over SSH or in a background service. The installer asks only then;
  otherwise the question waits for the dashboard's "Allow Blackbox to notify you" card or
  Blackbox Desktop's first run, both of which the person clicks.
* :func:`screen_shared` — Screen Sharing or a mirrored display is in use: macOS hides banners
  then by default ("Allow notifications when mirroring or sharing the display" is off), so a
  notification is in Notification Center but not on the screen.

Read-only; nothing here asks the person anything.
"""

from __future__ import annotations

import os
import subprocess

LAUNCHCTL = "/bin/launchctl"
PGREP = "/usr/bin/pgrep"
TIMEOUT_SECONDS = 3.0
#: The process macOS runs while a Screen Sharing (VNC) viewer is connected.
SCREEN_SHARING_PROCESS = "screensharingd"


def _out(argv: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return done.returncode, (done.stdout or "").strip()


def console_is_ours() -> bool:
    """True when this user owns the Mac's desktop (is logged in at the screen)."""
    try:
        return os.stat("/dev/console").st_uid == os.getuid()   # windows-footgun: ok (macOS-only module)
    except OSError:
        return False


def in_desktop_session() -> bool:
    """True when this process runs in this user's desktop session (``launchctl managername`` is
    ``Aqua``) and that desktop is on the screen — never over SSH or in a background service."""
    code, manager = _out([LAUNCHCTL, "managername"])
    return code == 0 and manager == "Aqua" and console_is_ours()


def screen_shared() -> bool:
    """True while a Screen Sharing viewer is connected (banners are hidden then by default)."""
    code, _ = _out([PGREP, "-x", SCREEN_SHARING_PROCESS])
    return code == 0
