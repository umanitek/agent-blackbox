"""Blackbox's start inside Hermes: the hooks are Hermes's in microseconds, the guard loads beside them.

Private security finding ``2026-11-26-linux-hermes-plugin-load-past-hermes-s-1`` (Linux round L7,
High; BB-LINUX-PENDING-cc89c4): Hermes gives each plugin's import + ``register()``
``plugins.load_timeout_seconds`` (10 s by default) and DROPS a plugin that overruns it
("Failed to load plugin 'blackbox': load timed out after 10s"). Blackbox's ``register()`` used to
import the whole guard first — about 700 modules: 0.6 s on a fast Mac, 10-15 s on a 4-CPU VM
during the first graph sync — so on a busy machine Hermes ran with NO Blackbox: no hook, nothing
recorded, no ``blackbox`` command.

Now ``register()`` hands Hermes the five gates below and returns. This module imports only the
standard library at load time. The guard itself (:mod:`.hooks`) is imported on Blackbox's own
thread (``blackbox-start``), started by the FIRST hook call — never during Hermes's plugin
discovery, where a second thread adding modules to ``sys.modules`` would race Hermes's own walks
over it (the L7 logs show other plugins failing with "dictionary changed size during iteration").

Pattern: **State** — ``STARTING`` → ``READY`` (or ``FAILED``), one :class:`threading.Event`.

What a hook does while the guard is still loading (the security argument):

* ``pre_tool_call`` — the only hook that can refuse — WAITS for the guard (up to
  :func:`wait_seconds`, kept below Hermes's own hook timeout) and is then judged by the full
  guard, exactly as before. Still loading after that wait, the call is REFUSED with
  :data:`NOT_CHECKED_MESSAGE` ("not checked yet, try again"): an action Blackbox has not judged
  never passes because Blackbox was slow (Hermes itself fails a timed-out ``pre_tool_call``
  closed). Only genuine breakage — the guard failed to import, or did not come up within
  :data:`GIVE_UP_SECONDS` — lets calls pass (the fail-open invariant), and never silently: it is
  logged as :data:`BROKEN_LINE` in Hermes's own log, which Blackbox's watcher
  (``agent_hooks.hermes_load``) turns into a HIGH "running without Blackbox" finding.
* The observer hooks (session start and end, the model request, the tool result) never wait:
  the call is queued with its context and run on the start thread IN ORDER before the guard is
  called ready — so a session's start (which puts its shells in the sandbox) is applied before
  that session's first tool call is judged, and no prompt goes unscanned.

Usage (the plugin's composition root only)::

    from .guard import startup
    for name, gate in startup.HERMES_HOOKS.items():
        ctx.register_hook(name, gate)
    with startup.loading():   # the CLI's import never runs beside the start thread's
        from . import cli
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Iterator, Optional

logger = logging.getLogger(__name__)

STARTING, READY, FAILED = "starting", "ready", "failed"
#: The longest a ``pre_tool_call`` waits for the guard. WHY 20 s: Hermes's own hook timeout is
#: 30 s by default (``plugins.hook_callback_timeout``) and a callback that overruns it is skipped
#: for 60 s; answering first keeps the refusal ours, with our words.
WAIT_CAP_SECONDS = 20.0
#: Kept between our wait and Hermes's hook timeout when the person set a shorter one.
HOOK_TIMEOUT_MARGIN_SECONDS = 3.0
#: The least a ``pre_tool_call`` waits, whatever Hermes's timeout says.
WAIT_FLOOR_SECONDS = 1.0
#: A guard that is not up this long after its start began is broken, not slow: calls pass
#: (fail-open), said in Hermes's log. Even the L7 VM's worst load took 15 s.
GIVE_UP_SECONDS = 300.0
#: Observer calls held while the guard loads; past it the oldest are kept and the rest counted.
MAX_QUEUED = 512
#: The words Blackbox's watcher looks for in Hermes's log (``agent_hooks.hermes_load``).
BROKEN_LINE = "Blackbox could not start in this Hermes"
NOT_CHECKED_MESSAGE = ("Blackbox is still starting on this busy computer and has not checked this action yet, "
                       "so it was not run. Try it again in a moment.")
_GATED = ("pre_tool_call", "post_tool_call", "pre_api_request", "on_session_start", "on_session_end")
#: Hermes's hook name → the guard's function (:mod:`.hooks`).
_GUARD_NAMES = {"pre_tool_call": "on_pre_tool_call", "post_tool_call": "on_post_tool_call",
                "pre_api_request": "on_pre_api_request", "on_session_start": "on_session_start",
                "on_session_end": "on_session_end"}

_LOADING = threading.RLock()


@contextlib.contextmanager
def loading() -> Iterator[None]:
    """Hold while importing the plugin's heavy modules outside the start thread (the CLI): one
    importer at a time, so two threads never import the same module graph side by side."""
    with _LOADING:
        yield


class _Start:
    """The guard's start in this process (one instance, :data:`START`)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.settled = threading.Event()   # set once READY or FAILED
        self.state = STARTING
        self.began = 0.0
        self.thread: Optional[threading.Thread] = None
        self.hooks: Any = None
        self.reason = ""
        self.queue: deque[tuple[str, tuple, dict, contextvars.Context]] = deque()
        self.dropped = 0

    def begin(self) -> None:
        """Start loading the guard on its own thread (once; later calls do nothing)."""
        with self.lock:
            if self.thread is not None:
                return
            self.began = time.monotonic()
            # The caller's context travels along: Hermes keeps the profile's home in a ContextVar.
            self.thread = threading.Thread(target=contextvars.copy_context().run, args=(self._run,),
                                           name="blackbox-start", daemon=True)
            self.thread.start()

    def _run(self) -> None:
        try:
            with _LOADING:
                from . import hooks   # the whole guard: detection, audit, shields, watch…
        except BaseException as exc:   # health: allow BLE001 -- any import failure is breakage, said out loud
            self._fail(f"the guard did not load ({type(exc).__name__}: {str(exc)[:300]})")
            return
        _warm(hooks)
        self._drain(hooks)

    def _drain(self, hooks: Any) -> None:
        """Run the queued observer calls in order, then call the guard ready — under the lock
        only when nothing is left, so a call queued meanwhile is never skipped or reordered."""
        while True:
            with self.lock:
                if not self.queue:
                    self.hooks, self.state = hooks, READY
                    self.settled.set()
                    if self.dropped:
                        logger.warning("blackbox: %d early hook call(s) were not replayed (queue full)", self.dropped)
                    return
                name, args, kwargs, context = self.queue.popleft()
            try:
                context.run(getattr(hooks, _GUARD_NAMES[name]), *args, **kwargs)
            except Exception:   # health: allow BLE001 -- the guard's hooks fail open themselves; this is a backstop
                logger.debug("blackbox: replayed %s failed", name, exc_info=True)

    def _fail(self, reason: str) -> None:
        with self.lock:
            if self.state != STARTING:
                return
            self.state, self.reason = FAILED, reason
            self.queue.clear()
        # Said before any waiting call is let go, so the log line is never later than the first pass.
        logger.error("%s: %s. Its tool calls pass UNCHECKED until Hermes is restarted.", BROKEN_LINE, reason)
        self.settled.set()

    def ready_hooks(self, wait: float) -> Any:
        """The guard once it is READY (waiting up to *wait* seconds), else None."""
        self.begin()
        if not self.settled.wait(max(0.0, wait)) and time.monotonic() - self.began > GIVE_UP_SECONDS:
            self._fail(f"the guard was not up {GIVE_UP_SECONDS:.0f} s after its start began")
        return self.hooks if self.state == READY else None

    def hooks_or_queue(self, name: str, args: tuple, kwargs: dict) -> Any:
        """The guard when READY; otherwise queue the observer call *name* (run before READY)."""
        self.begin()
        with self.lock:
            if self.state == READY:
                return self.hooks
            if self.state == STARTING:
                if len(self.queue) < MAX_QUEUED:
                    self.queue.append((name, args, kwargs, contextvars.copy_context()))
                else:
                    self.dropped += 1
            return None


def _warm(hooks: Any) -> None:
    """Read the settings and the compiled rules once, so the first judged call is as fast as
    every later one. Best effort: a failure here is the hook's own to handle when it runs."""
    try:
        cfg = hooks._config()
        hooks.graph_rules.detection_rules(cfg, "", {})
    except Exception:   # health: allow BLE001 -- warming only; the hook reads them again itself
        logger.debug("blackbox: warming the guard failed", exc_info=True)


START = _Start()


def wait_seconds() -> float:
    """How long a ``pre_tool_call`` may wait for the guard: :data:`WAIT_CAP_SECONDS`, or less
    when Hermes's own hook timeout (``plugins.hook_callback_timeout``) is shorter."""
    try:
        from hermes_cli.config import load_config_readonly   # Hermes's own reader, already loaded in Hermes
        plugins = (load_config_readonly() or {}).get("plugins")
        timeout = float(plugins.get("hook_callback_timeout")) if isinstance(plugins, dict) else 0.0
    except Exception:   # health: allow BLE001 -- not inside Hermes, or no such setting: the cap
        timeout = 0.0
    if timeout <= 0:
        return WAIT_CAP_SECONDS
    return max(WAIT_FLOOR_SECONDS, min(WAIT_CAP_SECONDS, timeout - HOOK_TIMEOUT_MARGIN_SECONDS))


def pre_tool_call(*args: Any, **kwargs: Any) -> Optional[dict[str, str]]:
    """Hermes's ``pre_tool_call``: the guard's verdict, waiting for the guard while it loads;
    refused when it is still loading after :func:`wait_seconds`; passed when it is broken."""
    hooks = START.hooks if START.state == READY else START.ready_hooks(wait_seconds())
    if hooks is not None:
        return hooks.on_pre_tool_call(*args, **kwargs)
    if START.state == FAILED:
        return None   # fail-open: the reason is in Hermes's log, and the watcher's HIGH finding
    return {"action": "block", "message": NOT_CHECKED_MESSAGE}


def _observer(name: str) -> Callable[..., None]:
    def gate(*args: Any, **kwargs: Any) -> None:
        hooks = START.hooks_or_queue(name, args, kwargs)
        if hooks is not None:
            getattr(hooks, _GUARD_NAMES[name])(*args, **kwargs)
    gate.__name__ = gate.__qualname__ = name
    gate.__doc__ = f"Hermes's ``{name}``: the guard's, or queued while the guard loads."
    return gate


#: Hermes's hook name → the gate Blackbox registers for it.
HERMES_HOOKS: dict[str, Callable[..., Any]] = {name: pre_tool_call if name == "pre_tool_call" else _observer(name)
                                               for name in _GATED}

__all__ = ["BROKEN_LINE", "FAILED", "HERMES_HOOKS", "NOT_CHECKED_MESSAGE", "READY", "START", "STARTING", "loading",
           "wait_seconds"]
