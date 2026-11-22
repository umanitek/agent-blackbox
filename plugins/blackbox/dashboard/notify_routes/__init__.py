"""Native notifications over HTTP (``notify``): the ONE feed both deliverers read, the policy,
and the lease by which Blackbox Desktop says "I am showing them".

* ``GET /api/notifications/feed[?since=N&limit=&wait=S]`` → ``{top, delivered, holder, notices:
  [Notice]}`` — the feed after ``since`` (default: after the DELIVERED cursor, i.e. what nobody
  has shown yet), oldest first. With ``wait`` (≤ :data:`MAX_WAIT_SECONDS`) the answer is held
  until the feed moves (a long-poll). A Notice: ``{id, seq, ts, category, kind, level, title,
  body, detail, agent, agent_name, instance, project, deliver, held}``; ``title`` and ``body``
  are lock-screen safe, ``detail`` is for inside an app (or when the person turned
  ``details`` on); ``deliver`` is False when the policy holds it back from the screen.
* ``GET /api/notifications/history[?limit=&before=]`` → ``{notices}`` newest first.
* ``GET /api/notifications/policy`` → ``{policy, notifier, holder, categories}``.
* ``POST /api/notifications/lease`` ``{"holder": "desktop", "seconds": 30}`` → the caller shows
  the feed for that long (renew before it runs out; 0 gives it up); the plugin's own notifier is
  silent meanwhile.
* ``POST /api/notifications/delivered`` ``{"seq": N}`` → the feed is shown up to ``N``.
* ``POST /api/notifications/test`` → ``{sent, delivery: {outcome, detail}, notifier}`` — hands one
  harmless notification to the system now; ``sent`` is true only when the system took it
  (``outcome``: ``delivered`` | ``fallback`` | ``not-shown``).
* ``POST /api/notifications/allow`` → ``{notifier}`` — the person asks to be notified: macOS asks
  them once, in their desktop session (the dashboard's "Allow Blackbox to notify you" card and
  Blackbox Desktop's first run; KI-PENDING-411cdb). Nothing is asked when it was asked before.
* ``POST /api/notifications/settings`` → ``{opened}`` — opens the system's notification settings
  at Blackbox (``notifier.settings`` / ``notifier.settings_label`` name the same action).
* ``GET /notifications`` — the dashboard's page: settings and the history.
* ``GET /notify-allow.js`` — the dashboard's "Allow Blackbox to notify you" card (or, while they
  are off, the way to System Settings), drawn into ``#notify-allow-root``.

The policy is SAVED through ``POST /api/settings`` ``{"notifications": {...}}`` — so turning
security notices off, or muting an agent, is held by the approval gate like any change that makes
Blackbox tell the person less. POSTs pass the browser boundary (the session token).

The pump (``notify.PUMP``) starts and stops with the app.
"""

# No ``from __future__ import annotations`` here: FastAPI must see the handlers' annotations.
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

NO_CACHE = {"Cache-Control": "no-store"}
MAX_WAIT_SECONDS = 25.0
PAGE = Path(__file__).resolve().parent.parent / "static" / "notifications.html"
SCRIPT = Path(__file__).resolve().parent.parent / "static" / "notifications.js"
ALLOW_SCRIPT = Path(__file__).resolve().parent.parent / "static" / "notify_allow.js"

Cache = Callable[..., Any]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def register(app: Any, swr: Cache) -> None:
    """Add the notification routes to *app* and run the pump for the app's lifetime."""
    from fastapi.responses import JSONResponse

    from ... import approvals, notify
    from .. import lifecycle

    # A change of the notifications section that tells the person less waits for their approval.
    approvals.SECTION_JUDGES[notify.policy.SECTION] = notify.policy_weakening

    @lifecycle.on_startup(app)
    def _start_notifications() -> None:
        notify.PUMP.start()

    @lifecycle.on_shutdown(app)
    def _stop_notifications() -> None:
        notify.PUMP.stop()

    @app.get("/api/notifications/feed")
    def notifications_feed(since: str = "", limit: str = "100", wait: str = "") -> Any:   # sync: a long-poll waits in the thread pool
        after = _int(since, -1) if since else notify.delivered()
        seconds = min(max(float(_int(wait)), 0.0), MAX_WAIT_SECONDS)
        if seconds and after >= notify.top():
            notify.wait(after, seconds)
        return JSONResponse({"top": notify.top(), "delivered": notify.delivered(), "holder": notify.holder(),
                             "notices": notify.rows(max(after, 0), _int(limit, 100))}, headers=NO_CACHE)

    @app.get("/api/notifications/history")
    def notifications_history(limit: str = "100", before: str = "0") -> Any:
        return JSONResponse({"notices": notify.history(_int(limit, 100), _int(before))}, headers=NO_CACHE)

    @app.get("/api/notifications/policy")
    def notifications_policy() -> Any:
        return JSONResponse({"policy": notify.read_policy().as_json(), "notifier": asdict(notify.notifier_status()),
                             "holder": notify.holder(), "categories": list(notify.CATEGORIES)}, headers=NO_CACHE)

    _register_writes(app, notify)


def _register_writes(app: Any, notify: Any) -> None:
    """The lease, the delivered cursor, the test notification — and the page itself."""
    from fastapi.responses import FileResponse, JSONResponse

    @app.post("/api/notifications/lease")
    def notifications_lease(body: dict[str, Any]) -> Any:
        holder = str(body.get("holder") or "")[:40]
        if not holder:
            return JSONResponse({"error": "holder is required"}, status_code=400, headers=NO_CACHE)
        try:
            seconds = float(body.get("seconds") or 0)
        except (TypeError, ValueError):
            return JSONResponse({"error": "seconds must be a number"}, status_code=400, headers=NO_CACHE)
        return JSONResponse({"seconds": notify.claim(holder, seconds), "delivered": notify.delivered()}, headers=NO_CACHE)

    @app.post("/api/notifications/delivered")
    def notifications_delivered(body: dict[str, Any]) -> Any:
        return JSONResponse({"delivered": notify.mark_delivered(_int(body.get("seq")))}, headers=NO_CACHE)

    @app.post("/api/notifications/test")
    def notifications_test() -> Any:
        delivery = notify.send_test()
        return JSONResponse({"sent": delivery.reached_system, "delivery": asdict(delivery), "notifier": asdict(notify.notifier_status())},
                            headers=NO_CACHE)

    @app.post("/api/notifications/allow")
    def notifications_allow() -> Any:
        return JSONResponse({"notifier": asdict(notify.request_permission())}, headers=NO_CACHE)

    @app.post("/api/notifications/settings")
    def notifications_settings() -> Any:
        return JSONResponse({"opened": notify.open_notification_settings()}, headers=NO_CACHE)

    @app.get("/notifications")
    def notifications_page() -> Any:
        return FileResponse(str(PAGE), media_type="text/html", headers=NO_CACHE)

    @app.get("/notifications.js")
    def notifications_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/notify-allow.js")
    def notifications_allow_script() -> Any:
        return FileResponse(str(ALLOW_SCRIPT), media_type="application/javascript", headers=NO_CACHE)
