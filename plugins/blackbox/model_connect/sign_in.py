"""The free Nous account sign-in, run by Hermes itself in a child process (2026-11-19).

Hermes' own ``hermes auth add nous --no-browser`` does the whole device sign-in: it asks the Nous
Portal for a link and a short code, prints them, waits while the person approves in their
browser, and stores the result in the agent's own Hermes files. This class starts that command,
reads the link and the code from its output so the dashboard can show them, and on success runs
*after_sign_in* (the package makes Nous the agent's provider on the model Hermes recommends for
the account — a free account lands on a free model). Blackbox never sees or stores a token.

Pattern: a small State machine owned by one object with one lock — idle → waiting (link + code
shown) → connected | failed | cancelled. Only one sign-in runs at a time; a second start returns
the one already running. The child is Blackbox's own and is stopped on cancel or after
:data:`SIGN_IN_LIMIT_SECONDS`.

Usage::

    sign_in = NousSignIn()
    view = sign_in.start()   # {"status": "starting" | "waiting", "link": ..., "code": ...}
    sign_in.view()           # poll until "connected" or "failed"
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from ..kernel.host_command import hermes_argv
from ..kernel.redaction import redact_secret_values

#: Hermes' own device sign-in lasts 15 minutes at the portal; a little more covers slow polling.
SIGN_IN_LIMIT_SECONDS = 17 * 60
_LINK = re.compile(r"Open:\s*(https://\S+)")
_CODE = re.compile(r"enter code:\s*([A-Za-z0-9-]{4,32})")
#: The last line of the child's output kept for a failure message (redacted, shortened).
_REASON_CHARS = 240

Popen = Callable[..., "subprocess.Popen[str]"]


def _safe_link(raw: str) -> str:
    """The sign-in link if it is an https address on a Nous host, else "" (never a link elsewhere)."""
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and (host == "nousresearch.com" or host.endswith(".nousresearch.com")):
        return raw
    return ""


class NousSignIn:
    """One Hermes Nous sign-in at a time; see the module doc."""

    def __init__(self, after_sign_in: Callable[[], bool], *, popen: Popen = subprocess.Popen,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._after_sign_in, self._popen, self._clock = after_sign_in, popen, clock
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen[str]] = None
        self._state: dict[str, Any] = {"status": "idle"}
        self._started = 0.0

    def view(self) -> dict[str, Any]:
        """What the dashboard shows: status, and the link and code while waiting."""
        with self._lock:
            if self._state.get("status") in ("starting", "waiting") and \
                    self._clock() - self._started > SIGN_IN_LIMIT_SECONDS:
                self._stop_locked("failed", "The sign-in was not approved in time. Start it again.")
            return dict(self._state)

    def start(self) -> dict[str, Any]:
        """Start the sign-in (or return the one already running)."""
        with self._lock:
            if self._state.get("status") in ("starting", "waiting"):
                return dict(self._state)
            try:
                proc = self._popen(hermes_argv("auth", "add", "nous", "--no-browser"),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, bufsize=1)
            except (OSError, ValueError):
                self._state = {"status": "failed", "reason": "Blackbox could not start Hermes' sign-in."}
                return dict(self._state)
            self._proc, self._started = proc, self._clock()
            self._state = {"status": "starting"}
        threading.Thread(target=self._follow, args=(proc,), name="blackbox-nous-sign-in", daemon=True).start()
        return self.view()

    def cancel(self) -> dict[str, Any]:
        """Stop a running sign-in; nothing is saved."""
        with self._lock:
            if self._state.get("status") in ("starting", "waiting"):
                self._stop_locked("cancelled", "")
            return dict(self._state)

    # ------------------------------------------------------------------ internals
    def _stop_locked(self, status: str, reason: str) -> None:
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()   # Blackbox's own child: Hermes saves nothing before the approval
        self._state = {"status": status, "reason": reason} if reason else {"status": status}

    def _follow(self, proc: subprocess.Popen[str]) -> None:
        """Read the child's output for the link and code, then settle on its exit."""
        last_line = ""
        for line in proc.stdout or ():
            text = line.strip()
            if text:
                last_line = text
            link, code = _LINK.search(text), _CODE.search(text)
            with self._lock:
                if self._proc is not proc:
                    return   # cancelled or timed out: this child no longer speaks for the panel
                if link and _safe_link(link.group(1)):
                    self._state["link"] = link.group(1)
                if code:
                    self._state["code"] = code.group(1)
                if self._state.get("link") and self._state.get("code"):
                    self._state["status"] = "waiting"
        code = proc.wait()
        provider_set = code == 0 and self._after_sign_in()
        with self._lock:
            if self._proc is not proc:
                return
            self._proc = None
            if provider_set:
                self._state = {"status": "connected"}
            else:
                reason = redact_secret_values(last_line)[:_REASON_CHARS] if code != 0 else \
                    "Signed in, but Blackbox could not select Nous as the agent's provider."
                self._state = {"status": "failed", "reason": reason or "Hermes' sign-in did not finish."}
