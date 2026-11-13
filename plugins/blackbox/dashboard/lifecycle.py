"""Startup and shutdown hooks for the dashboard app, without FastAPI's deprecated ``on_event``.

``@app.on_event("startup")`` is deprecated in FastAPI (it raises a
DeprecationWarning per registration, ~140 extra warnings per suite run) in
favour of a *lifespan*. These decorators chain each hook onto the app's
existing lifespan, so any module that is handed an app (``server.create_app``,
``community_routes``) can add hooks, in any order, with no shared registry.

Pattern: Decorator (each registration wraps the previous lifespan — a chain
of async context managers). Startup hooks run in registration order; shutdown
hooks run in reverse, like nested ``with`` blocks.

Usage::

    @on_startup(app)
    def _start_worker() -> None: ...

    @on_shutdown(app)
    def _stop_worker() -> None: ...

    run_in_background(app, [check_node, warm_graph, warm_reports], name="blackbox-warm", passes=2, pause_s=2.5)
"""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, Sequence, TypeVar

logger = logging.getLogger(__name__)

Hook = TypeVar("Hook", bound=Callable[[], Any])


def _chain(app: Any, startup: Callable[[], Any] | None, shutdown: Callable[[], Any] | None) -> None:
    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(the_app: Any) -> AsyncIterator[Any]:
        async with inner(the_app) as state:
            if startup is not None:
                startup()
            try:
                yield state
            finally:
                if shutdown is not None:
                    shutdown()

    app.router.lifespan_context = lifespan


def on_startup(app: Any) -> Callable[[Hook], Hook]:
    """Decorator: run the (synchronous) function when *app* starts."""
    def register(hook: Hook) -> Hook:
        _chain(app, hook, None)
        return hook
    return register


def on_shutdown(app: Any) -> Callable[[Hook], Hook]:
    """Decorator: run the (synchronous) function when *app* shuts down."""
    def register(hook: Hook) -> Hook:
        _chain(app, None, hook)
        return hook
    return register


def run_in_background(app: Any, calls: Sequence[Callable[[], Any]], *, name: str, passes: int = 1,
                      pause_s: float = 0.0, join_s: float = 2.0) -> None:
    """Run *calls*, in order, on a daemon thread once *app* starts — and end the work with the app.

    The calls run *passes* times, *pause_s* apart. When the app shuts down nothing further is
    called and the pause ends at once; shutdown then waits up to *join_s* for the call in
    flight, so the thread does not go on reading after its app is gone (a warm-up that
    outlived its app ran into whatever used the process next). Best-effort: a call that
    raises ends the work with a WARNING naming *name*.
    """
    running: list[tuple[threading.Thread, threading.Event]] = []   # one entry per start of the app

    def work(stopping: threading.Event) -> None:
        try:
            for index in range(passes):
                if index and stopping.wait(pause_s):
                    return
                for call in calls:
                    if stopping.is_set():
                        return
                    call()
        except Exception as exc:   # health: allow BLE001 -- best-effort background work; only the class is logged
            logger.warning("blackbox dashboard: %s failed: %s", name, type(exc).__name__)

    def start() -> None:
        # A fresh thread and stop flag each time: an app can start, stop and start again.
        stopping = threading.Event()
        thread = threading.Thread(target=work, args=(stopping,), name=name, daemon=True)
        running.append((thread, stopping))
        thread.start()

    def stop() -> None:
        while running:
            thread, stopping = running.pop()
            stopping.set()
            thread.join(timeout=join_s)

    _chain(app, start, stop)
