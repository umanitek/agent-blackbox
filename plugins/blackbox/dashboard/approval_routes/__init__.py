"""The gate in front of every route that can turn protection down, and the app's approval routes.

:class:`Gate` is ASGI middleware placed INNERMOST — after the dashboard's browser boundary, so
only a request that already carries the dashboard's token can be held (an unauthenticated one is
refused by the boundary and raises no dialog). For a gated route (``approvals.gated``):

* not weakening → applied at once (strengthening is never delayed);
* weakening, approved before with this exact body → applied, once;
* weakening otherwise → held, answered **428** ``{"ok": false, "approval": {...}, "errors": [why]}``.
  The Desktop app sees it, asks the person in a native dialog and answers with its key.

Routes (the POSTs behind the boundary's token):
``GET  /api/desktop/approvals``           ``{"paired": bool, "confirm_here": bool, "waiting": [held …]}``
``POST /api/desktop/approvals/pair``      ``{"key": hex, "proof": hex?}`` — Blackbox Desktop's key
``POST /api/desktop/approvals/answer``    ``{"id", "approve": bool, "proof": hex}`` — Desktop's native dialog
``POST /api/approvals/confirm``           ``{"id"}`` — the dashboard page's path: the system's password
                                          prompt (``approvals.system_prompt``), at most once per request
``GET  /approvals.js``                    the page script: a held answer shows "Confirm with your
                                          password", then the same request is sent again

Pattern: **Proxy** (protection proxy) around the dashboard's own routes.

WHY no ``from __future__ import annotations`` here: FastAPI reads the route functions'
annotations at runtime, and ``Request`` is imported inside :func:`register`.
"""


import json
from pathlib import Path
from typing import Any, Awaitable, Callable

from ... import approvals
from ...approvals import Approvals

#: The most of a gated request's body read (the dashboard's settings bodies are small).
MAX_BODY_BYTES = 256 * 1024
#: The answer to a change that waits for the person's approval.
HELD_STATUS = 428
NOT_PAIRED = "Turning protection down needs your confirmation: confirm it with your password, or in Blackbox Desktop."
ASK = "Waiting for your confirmation in Blackbox Desktop (or confirm it with your password)."
#: The page script (served at ``/approvals.js``; it lives with the dashboard's other static files).
SCRIPT = Path(__file__).resolve().parents[1] / "static" / "approvals.js"

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class Gate:
    """``app.add_middleware``-style ASGI middleware (``Gate(app, store=…, current=…)``)."""

    def __init__(self, app: Any, store: Approvals, current: Callable[[], approvals.Current] = approvals.Current.read) -> None:
        self.app, self.store, self.current = app, store, current

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        route = scope.get("path", "")
        if scope.get("type") != "http" or scope.get("method") != "POST" or not approvals.gated(route):
            await self.app(scope, receive, send)
            return
        body, more = await _read(receive)
        if more:   # too large for a settings body: let the route refuse it
            await self.app(scope, _replay(body, True, receive), send)
            return
        try:
            payload = json.loads(body.decode("utf-8-sig") or "{}")
        except (UnicodeDecodeError, ValueError, RecursionError):
            payload = None   # malformed: the route answers 400
        from starlette.concurrency import run_in_threadpool
        reasons = await run_in_threadpool(lambda: approvals.reasons(route, payload, self.current())) if payload is not None else []
        if not reasons or self.store.consume(route, body):
            await self.app(scope, _replay(body, False), send)
            return
        held = self.store.hold(route, body, reasons)
        message = ASK if self.store.paired() else NOT_PAIRED
        await _json(send, HELD_STATUS, {"ok": False, "approval": held.as_json(), "errors": [message, *reasons]})


async def _read(receive: Receive) -> tuple[bytes, bool]:
    chunks, size = [], 0
    while True:
        message = await receive()
        chunk = message.get("body", b"")
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return b"".join(chunks), True
        if not message.get("more_body"):
            return b"".join(chunks), False


def _replay(body: bytes, more: bool, receive: Receive | None = None) -> Receive:
    sent = {"done": False}

    async def replay() -> dict[str, Any]:
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": more}
        # The rest of a body too large to judge comes from the client as it arrives.
        return await receive() if receive is not None else {"type": "http.disconnect"}
    return replay


async def _json(send: Send, status: int, content: dict[str, Any]) -> None:
    raw = json.dumps(content).encode("utf-8")
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store"),
                            (b"content-length", str(len(raw)).encode())]})
    await send({"type": "http.response.body", "body": raw})


def register(app: Any, _swr: Any = None, store: Approvals | None = None) -> None:
    """Add the approval routes and place :class:`Gate` innermost on *app* (before it starts).
    *store* defaults to ``approvals.STORE`` (the dashboard's one store; tests pass their own)."""
    from fastapi import Request
    from fastapi.responses import FileResponse, JSONResponse
    from starlette.concurrency import run_in_threadpool

    store = store if store is not None else approvals.STORE
    from starlette.middleware import Middleware

    # WHY append to user_middleware instead of add_middleware: add_middleware puts a layer
    # OUTSIDE the ones already there, i.e. before the browser boundary's token check — then an
    # unauthenticated request could raise dialogs. Starlette builds the stack from this list,
    # first = outermost, when the app starts.
    app.user_middleware.append(Middleware(Gate, store=store))

    @app.get("/api/desktop/approvals")
    def approvals_waiting() -> Any:
        return JSONResponse({"paired": store.paired(), "confirm_here": approvals.system_prompt.available(),
                             "waiting": [held.as_json() for held in store.waiting()]}, headers={"Cache-Control": "no-store"})

    @app.get("/approvals.js")
    def approvals_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers={"Cache-Control": "no-store"})

    @app.post("/api/approvals/confirm")
    async def approvals_confirm(request: Request) -> Any:
        """The page's "Confirm with your password": the system prompt, once per held request."""
        body = await _small_json(request)
        held = next((item for item in store.waiting() if item.id == str(body.get("id") or "")), None)
        if held is None or not store.mark_prompted(held.id):
            return JSONResponse({"ok": False, "error": "nothing to confirm (unknown, expired or already asked)"}, status_code=409)
        if not await run_in_threadpool(approvals.system_prompt.confirm, held.reasons):
            return JSONResponse({"ok": False, "error": "not confirmed: protection stays on"}, status_code=403)
        return JSONResponse({"ok": store.approve_confirmed(held.id)})

    @app.post("/api/desktop/approvals/pair")
    async def approvals_pair(request: Request) -> Any:
        body = await _small_json(request)
        ok = store.pair(str(body.get("key") or ""), str(body.get("proof") or ""))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 403)

    @app.post("/api/desktop/approvals/answer")
    async def approvals_answer(request: Request) -> Any:
        body = await _small_json(request)
        ok = store.answer(str(body.get("id") or ""), body.get("approve") is True, str(body.get("proof") or ""))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 403)


async def _small_json(request: Any) -> dict[str, Any]:
    raw = await request.body()
    try:
        value = json.loads(raw[:4096].decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
