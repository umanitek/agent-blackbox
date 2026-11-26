"""What a running process IS: its program, who signed it (verified) and whether it runs sandboxed
(KI-588 f) — read from the program and the kernel, never from what the process says of itself.

* *path*: the kernel's executable for the pid (``observe.platform.process_path``);
* *signer*: ``kernel.code_signing.describe`` — ``codesign`` held to what it claims (intact, chain
  to Apple, notarisation), kept per program version (path + modification time + size), so a view
  asking every second runs ``codesign`` once per program;
* *sandboxed*: the kernel's own answer for the RUNNING process (``sandbox_check``) — App Sandbox,
  Blackbox's agent sandbox or any ``sandbox-exec`` profile;
* *app_sandbox*: whether the program is signed with ``com.apple.security.app-sandbox`` — what it
  asks for, not proof that it runs so (*sandboxed* is that); kept per program version too.

Each is None / ``unknown`` when it cannot be read — never a guess. Read-only.

Usage::

    found = facts(4242)     # ProcessFacts(pid, path, signer, sandboxed, app_sandbox)
    asdict(found)
"""

from __future__ import annotations

import os
import plistlib
import threading
from dataclasses import dataclass, field
from typing import Optional

from ..kernel import code_signing
from .observe import platform

APP_SANDBOX = "com.apple.security.app-sandbox"
MAX_CACHED = 2000

_lock = threading.Lock()
_entitled: dict[tuple[str, float, int], Optional[bool]] = {}


@dataclass(frozen=True)
class ProcessFacts:
    """One process: *path* ("" when gone or not readable — *found* False), its verified *signer*
    (``code_signing.Signer``), *sandboxed* (the kernel runs it in a sandbox; None: could not ask)
    and *app_sandbox* (its program asks for App Sandbox; None: could not read its entitlements)."""

    pid: int
    path: str
    found: bool
    signer: code_signing.Signer = field(default_factory=lambda: code_signing.Signer(kind="unknown"))
    sandboxed: Optional[bool] = None
    app_sandbox: Optional[bool] = None


def _app_sandbox(path: str) -> Optional[bool]:
    """Whether *path* is signed with the App Sandbox entitlement, kept per program version."""
    try:
        status = os.stat(path)
    except OSError:
        return None
    key = (path, status.st_mtime, status.st_size)
    with _lock:
        if key in _entitled:
            return _entitled[key]
    text = code_signing.entitlements(path)
    if text is None:
        return None   # not kept: a timeout is asked again next time
    try:
        declared = plistlib.loads(text.encode("utf-8")) if text.strip() else {}
    except (ValueError, plistlib.InvalidFileException):
        declared = None
    found = (declared.get(APP_SANDBOX) is True) if isinstance(declared, dict) else None
    with _lock:
        if len(_entitled) >= MAX_CACHED:
            _entitled.pop(next(iter(_entitled)))
        _entitled[key] = found
    return found


def facts(pid: int) -> ProcessFacts:
    """Everything above for *pid* (a gone process: *path* "" and the rest unknown)."""
    path = platform.process_path(pid)
    if not path:
        return ProcessFacts(pid=pid, path="", found=False)
    return ProcessFacts(pid=pid, path=path, found=True, signer=code_signing.describe(path),
                        sandboxed=platform.process_sandboxed(pid), app_sandbox=_app_sandbox(path))


def forget() -> None:
    """Drops the kept entitlement answers (tests)."""
    with _lock:
        _entitled.clear()


__all__ = ["APP_SANDBOX", "ProcessFacts", "facts", "forget"]
