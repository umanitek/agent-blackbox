"""The coding agents Blackbox protects through their own hooks (``agent_hooks``), over HTTP.

* ``GET  /api/agent-hooks`` → ``{"agents": [AgentRow…], "kinds": [...]}`` — every coding agent
  found here or hooked, with its honest state and its recent sessions (hashed ids only).
* ``POST /api/agent-hooks/event`` — one event from the hook runner: a ``pre_tool`` answered with
  the guard's verdict ``{"decision": "allow" | "block", "message"}`` first, on its own threads
  (:data:`HOOK_THREADS`), and recorded right after on the recorder thread (KI-552). 400 for a
  malformed event; 503 when it could not be judged (the runner then lets the agent continue).
* ``POST /api/agent-hooks/protection`` ``{"kind": <agent id>, "enabled": bool}`` — install or
  remove an agent's hooks (Protect / Stop protecting, on the dashboard or in a companion app).

Both POSTs pass the app-wide browser boundary (the session token from ``GET /api/session``), so a
web page cannot reach them. While "Protect new agents automatically" is on, a background sweep
hooks a newly installed agent — or a config home a running agent uses — within
:data:`OBSERVE_SECONDS` and repairs every hook every :data:`SWEEP_SECONDS` (``agent_hooks.sweep``). Whatever that
setting says, the hook watch (``agent_hooks.keep_hooks``) puts back a hook of Blackbox's removed or
changed outside Blackbox, and records it as a HIGH finding, every :data:`OBSERVE_SECONDS`. The instance views (live tree, history, one
instance, profiles) are in :mod:`.instances`.
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' ``Request``
# annotation as the class itself.
import asyncio
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any, Callable

logger = logging.getLogger(__name__)

NO_CACHE = {"Cache-Control": "no-store"}
#: The largest event read (a write tool's whole file can be in its arguments).
MAX_BODY_BYTES = 1024 * 1024
#: A full sweep (hooks repaired, every agent re-checked) at least this often.
SWEEP_SECONDS = 300.0
#: How often the cheap look runs: the process observer (``agent_hooks.tracking.observe_now`` — a
#: running agent that names a config home Blackbox has not hooked) and which agents are on this
#: machine (a few file checks and PATH lookups). Either is hooked at once, not at the next full
#: sweep.
OBSERVE_SECONDS = 5.0
_FIRST_LOOK_SECONDS = 20.0

#: The threads that answer hook events — the agents' hot path — kept apart from the shared pool
#: that serves pages, long-polls (the live view, the notifications feed hold a thread for up to
#: 25 s each) and reads. WHY (KI-552): under 40 events a second the shared pool was full, and a
#: hook waited for a free thread longer than for its verdict.
HOOK_THREADS = 8
_verdicts = ThreadPoolExecutor(max_workers=HOOK_THREADS, thread_name_prefix="blackbox-hook-verdict")

Cache = Callable[..., Any]
_sweeper: dict[str, Any] = {"thread": None}


def should_sweep(present: frozenset[str], seen: frozenset[str] | None, since_last: float) -> bool:
    """True when the agents on this machine changed since the last sweep (one was installed or
    removed), or the last sweep is :data:`SWEEP_SECONDS` old. WHY (E2E 2026-11-21): a coding agent
    installed after Blackbox stayed unhooked — unprotected — for up to five minutes."""
    return present != seen or since_last >= SWEEP_SECONDS


class _Sweeper:
    """The background look, one :meth:`step` every :data:`OBSERVE_SECONDS`: the process observer
    looks (a running agent's moved config home is learned), then the agents are hooked when a
    home was learned, the agents on this machine changed, or the last full sweep is
    :data:`SWEEP_SECONDS` old. Pattern: a small **State** holder for the loop, so one step can be
    run and checked on its own."""

    def __init__(self) -> None:
        self.seen: frozenset[str] | None = None
        self.last = float("-inf")

    def step(self) -> bool:
        """One look; True when it swept."""
        import time

        from ... import agent_hooks
        agent_hooks.tracking.observe_now()
        present = agent_hooks.present()
        # A config home learned since the last look (a hook event or a running agent named it)
        # is hooked now, not at the next full sweep.
        swept = False
        if agent_hooks.tracking.new_profiles() or should_sweep(present, self.seen, time.monotonic() - self.last):
            agent_hooks.sweep()
            self.seen, self.last = present, time.monotonic()
            swept = True
        # Every look, whatever "Protect new agents automatically" says: a hook of Blackbox's that was
        # removed or changed outside Blackbox is said (HIGH) and put back within OBSERVE_SECONDS
        # (security finding 2026-11-24, Linux round L4: 90 s later nothing had been put back).
        agent_hooks.keep_hooks()
        return swept


def _sweep_forever() -> None:
    stop = threading.Event()
    sweeper = _Sweeper()
    wait = _FIRST_LOOK_SECONDS
    while not stop.wait(wait):
        wait = OBSERVE_SECONDS
        try:
            sweeper.step()
        except Exception:   # health: allow BLE001 -- a sweep that fails tries again next round
            logger.warning("blackbox dashboard: the agent hooks sweep failed", exc_info=True)


def _also(app: Any) -> None:
    """The instance views' routes, and the sweep (once per process)."""
    from .instances import register as register_instances
    register_instances(app)
    if _sweeper["thread"] is None:
        _sweeper["thread"] = threading.Thread(target=_sweep_forever, name="blackbox-agent-hooks-sweep", daemon=True)
        _sweeper["thread"].start()


def register(app: Any, swr: Cache) -> None:
    """Add the agent-hooks routes to *app* and start the sweep (once per process)."""
    from fastapi import Request
    from fastapi.concurrency import run_in_threadpool
    from fastapi.responses import JSONResponse

    from ... import agent_hooks

    @app.get("/api/agent-hooks")
    def agent_hooks_list() -> Any:
        return JSONResponse({"agents": [asdict(row) for row in agent_hooks.rows()], "kinds": list(agent_hooks.KINDS)},
                            headers=NO_CACHE)

    async def _body(request: Request) -> Any:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError("request too large")
        return json.loads(raw.decode("utf-8-sig") or "{}")

    @app.post("/api/agent-hooks/event")
    async def agent_hooks_event(request: Request) -> Any:
        body: Any = None
        try:
            body = await _body(request)
            # The verdict on the hook threads (off the event loop and the shared pool); the
            # bookkeeping follows on the recorder thread after the agent has its answer.
            answer = await asyncio.get_running_loop().run_in_executor(_verdicts, agent_hooks.answer_event, body)
            return JSONResponse(answer, headers=NO_CACHE)
        except (ValueError, RecursionError) as exc:
            return JSONResponse({"error": str(exc)[:200]}, status_code=400, headers=NO_CACHE)
        except Exception:   # health: allow BLE001 -- "could not judge": 503, the runner lets the agent continue
            agent = body.get("agent") if isinstance(body, dict) else ""
            if agent in agent_hooks.KINDS:
                agent_hooks.note_error(agent)
            logger.warning("blackbox dashboard: an agent hook event could not be checked", exc_info=True)
            return JSONResponse({"error": "could not check the event"}, status_code=503, headers=NO_CACHE)

    @app.post("/api/agent-hooks/protection")
    async def agent_hooks_protection(request: Request) -> Any:
        try:
            body = await _body(request)
        except (ValueError, RecursionError) as exc:
            return JSONResponse({"error": str(exc)[:200]}, status_code=400, headers=NO_CACHE)
        kind, enabled = body.get("kind") if isinstance(body, dict) else None, body.get("enabled") if isinstance(body, dict) else None
        if kind not in agent_hooks.KINDS or not isinstance(enabled, bool):
            return JSONResponse({"error": "kind must be a known agent and enabled true or false"}, status_code=400, headers=NO_CACHE)
        result = await run_in_threadpool(agent_hooks.set_protection, kind, enabled)
        return JSONResponse(result, status_code=200 if result["ok"] else 400, headers=NO_CACHE)

    _also(app)
