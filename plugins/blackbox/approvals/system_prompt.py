"""Confirming a held change WITHOUT Blackbox Desktop: the operating system asks for the user's
password.

The dashboard is a web page, and whoever holds its token can script that page. A "Confirm"
button inside it would prove nothing. What a program cannot do on its own is answer the
system's authentication prompt, which macOS (SecurityAgent) or polkit draws, asking for the
password. So the page's "Confirm" asks the core to show that prompt, naming the change. The
change is approved only when the person types the password.

* macOS: ``osascript -e 'do shell script "/usr/bin/true" with prompt "…" with administrator privileges'``
* Linux: ``pkexec /bin/true`` (the desktop's polkit agent asks)
* anywhere else: unavailable. The change then waits for Blackbox Desktop.

Nothing privileged runs: the authenticated command is ``true``. One prompt at a time, and each
held request is asked at most once. Limits (UI automation through Accessibility) are those of
Desktop's dialog. Blackbox Desktop's docs/security/approvals.md has the threat model.

Pattern: **Strategy**. :data:`PROMPTERS` holds one per platform, and tests replace it.

Usage::

    if system_prompt.available() and system_prompt.confirm(["Switch Blackbox to Audit mode"]):
        store.approve_confirmed(held.id)
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import threading
from typing import Callable, Sequence

#: How long the person has to answer the prompt.
PROMPT_TIMEOUT_SECONDS = 120
#: At most this much of each reason is shown (a reason can quote a value from the request).
MAX_REASON_CHARS = 120
_UNSAFE = re.compile(r"[\x00-\x1f\x7f\"\\]")
_one_at_a_time = threading.Lock()

Prompter = Callable[[str], bool]


def prompt_text(reasons: Sequence[str]) -> str:
    """What the prompt says: a fixed header and each reason, cleaned (no quotes or control characters)."""
    lines = [_UNSAFE.sub("", str(reason))[:MAX_REASON_CHARS] for reason in list(reasons)[:6]]
    return "Blackbox: allow turning protection DOWN? " + "; ".join(lines) + ". Only if YOU asked for it."


def _mac(text: str) -> bool:
    script = f'do shell script "/usr/bin/true" with prompt "{text}" with administrator privileges'
    done = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, timeout=PROMPT_TIMEOUT_SECONDS, check=False)
    return done.returncode == 0


def _linux(_text: str) -> bool:
    done = subprocess.run(["pkexec", "/bin/true"], capture_output=True, timeout=PROMPT_TIMEOUT_SECONDS, check=False)
    return done.returncode == 0


PROMPTERS: dict[str, Prompter] = {"Darwin": _mac, "Linux": _linux}


def _prompter() -> Prompter | None:
    system = platform.system()
    if system == "Darwin" and shutil.which("osascript"):
        return PROMPTERS["Darwin"]
    if system == "Linux" and shutil.which("pkexec"):
        return PROMPTERS["Linux"]
    return None


def available() -> bool:
    return _prompter() is not None


def confirm(reasons: Sequence[str]) -> bool:
    """True only when the person passed the system's prompt. A second prompt while one is open,
    a timeout or a missing prompter answers False."""
    prompter = _prompter()
    if prompter is None or not _one_at_a_time.acquire(blocking=False):
        return False
    try:
        return prompter(prompt_text(reasons))
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        _one_at_a_time.release()
