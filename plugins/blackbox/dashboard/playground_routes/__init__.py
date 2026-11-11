"""The dashboard's Playground: sandbox mode's panel and its two API routes (2026-10-21).

* ``GET /playground.js`` — the panel script (draws ``#playground-root``, sets the
  page's sandbox colour);
* ``GET /api/playground`` — sandbox mode on/off, sharing on/off, this node's own
  sandbox tests and the graph's sandbox lane (what every member shared there);
* ``GET /api/playground/graph`` and ``GET /api/playground/threat`` — the sandbox lane in
  the Community graph's own response shapes; in sandbox mode the dashboard's Community
  tab reads these instead of ``/api/graph`` / ``/api/threat`` (display only);
* ``GET /api/playground/local`` — this node's sandbox tests as findings rows, as local
  activity and as Agent activity entries; in sandbox mode the dashboard lists them beside
  the real findings, in the Local tab and in Agent activity, tagged SANDBOX, and alerts on
  new ones the way it alerts on real findings (Amos, 2026-10-27) — counts stay the real ones;
* ``POST /api/playground/run`` ``{"kind": "domain"}`` — run one sandbox test
  (:func:`playground.run_test`); 409 with a plain reason when it cannot run;
* ``GET /api/playground/wallets`` — the shields' wallet tests for this machine (every
  wallet found here, generated seed phrases and keys; never a generated secret);
* ``POST /api/playground/wallets/run`` ``{"id": "vault:metamask:…"}`` — run one through the
  real check, local only (:func:`playground.run_wallet_test`); 409 with the reason.

The POST is a state change, so the app-wide browser boundary already demands
the session token on it (KI-028 / LES-006); nothing here bypasses that.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "playground.js"
NO_CACHE = {"Cache-Control": "no-store"}

Cache = Callable[..., Any]


def state_payload() -> dict[str, Any]:
    """Everything the panel draws, in one read."""
    from ... import playground
    from ...kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    view = playground.read_lane(cfg) if cfg.community_sandbox else None
    return {
        "sandbox": cfg.community_sandbox,
        "sharing": cfg.community_enabled,
        "graph": cfg.context_graph_id,
        "kinds": list(playground.KINDS),
        "tests": playground.recent_tests(limit=20) if cfg.community_sandbox else [],
        "lane": _safe_lane(view.to_dict()) if view is not None else {"graph": cfg.context_graph_id, "readable": False,
                                                                     "agents": 0, "entries": []},
    }


# The lane is what OTHER members wrote: every string in it is sanitized like the community tier's
# (safe_payloads — stripped, clamped, defanged; identifiers verbatim but stripped), never served raw.

def _safe_lane(lane: dict[str, Any]) -> dict[str, Any]:
    from ..safe_payloads import safe_identifier, safe_text
    lane["entries"] = [{**entry, "identifier": safe_identifier(entry["identifier"]),
                        "reporter": safe_text(entry["reporter"], 64), "severity": safe_text(entry["severity"], 16),
                        "fields": [(safe_text(key, 64), safe_text(value, 300)) for key, value in entry["fields"]]}
                       for entry in lane["entries"]]
    return lane


def _safe_detail(detail: dict[str, Any]) -> dict[str, Any]:
    from ..safe_payloads import safe_identifier, safe_text
    out = {safe_text(key, 64): (safe_text(value, 300) if isinstance(value, str) else value) for key, value in detail.items()}
    out["identifier"] = safe_identifier(detail["identifier"])
    if "sandboxReporters" in detail:
        out["sandboxReporters"] = [safe_text(reporter, 64) for reporter in detail["sandboxReporters"]]
    return out


def _sandbox_view() -> Any:
    """The sandbox lane when sandbox mode is on, else an empty unreadable view."""
    from ... import playground
    from ...kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    return playground.read_lane(cfg) if cfg.community_sandbox else playground.LaneView(cfg.context_graph_id, False, ())


def graph_payload(q: str, category: str, ecosystem: str, offset: int, limit: int) -> dict[str, Any]:
    """The sandbox lane as a Community graph page."""
    from ... import playground

    from ..safe_payloads import safe_identifier, safe_text

    page = playground.graph.graph_page(_sandbox_view(), q=q, category=category, ecosystem=ecosystem,
                                       offset=offset, limit=limit)
    page["threats"] = [{**threat, "identifier": safe_identifier(threat["identifier"]), "name": safe_text(threat["name"]),
                        "severity": safe_text(threat["severity"], 16)} for threat in page["threats"]]
    return page


def threat_payload(identifier: str) -> dict[str, Any]:
    """One sandbox threat as a Community threat detail."""
    from ... import playground

    return _safe_detail(playground.graph.threat_detail(_sandbox_view(), identifier))


def local_payload() -> dict[str, Any]:
    """This node's sandbox tests for the findings table and the Local tab (empty outside sandbox mode)."""
    from ... import playground
    from ...kernel.config import load_blackbox_config

    if not load_blackbox_config().community_sandbox:
        return {"sandbox": False, "findings": [], "audit": [],
                "local": {"sessions": [], "sessionCount": 0, "threatCount": 0}}
    return {"sandbox": True, "findings": playground.recent_tests(limit=100), "audit": playground.sandbox_audit(),
            "local": playground.sandbox_activity()}


def run_payload(body: Any) -> tuple[int, dict[str, Any]]:
    """(status, body) for one POST: 200 with the result, 409 with the reason it cannot run."""
    from ... import playground

    kind = str(body.get("kind") or "") if isinstance(body, dict) else ""
    try:
        return 200, {"ok": True, "result": playground.run_test(kind).to_dict()}
    except playground.PlaygroundRefused as exc:
        return 409, {"ok": False, "error": str(exc)}


def wallet_list_payload() -> dict[str, Any]:
    """The wallet tests the panel lists (empty outside sandbox mode)."""
    from ... import playground
    from ...kernel.config import load_blackbox_config

    return {"tests": playground.wallet_tests() if load_blackbox_config().community_sandbox else []}


def wallet_run_payload(body: Any) -> tuple[int, dict[str, Any]]:
    """(status, body) for one wallet test: 200 with the result, 409 with the reason it cannot run."""
    from ... import playground

    test_id = str(body.get("id") or "") if isinstance(body, dict) else ""
    try:
        return 200, {"ok": True, "result": playground.run_wallet_test(test_id).to_dict()}
    except playground.PlaygroundRefused as exc:
        return 409, {"ok": False, "error": str(exc)}


def register(app: Any, swr: Cache) -> None:
    """Add the panel script and the two Playground routes to *app* (*swr* is unused: never cached)."""
    from fastapi import Body, Query
    from fastapi.responses import FileResponse, JSONResponse

    @app.get("/playground.js")
    def playground_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/api/playground")
    def playground_state() -> Any:
        return JSONResponse(state_payload(), headers=NO_CACHE)

    @app.get("/api/playground/graph")
    def playground_graph(q: str = Query(""), category: str = Query(""), ecosystem: str = Query(""),
                         offset: int = Query(0), limit: int = Query(200)) -> Any:
        return JSONResponse(graph_payload(q, category, ecosystem, offset, limit), headers=NO_CACHE)

    @app.get("/api/playground/local")
    def playground_local() -> Any:
        return JSONResponse(local_payload(), headers=NO_CACHE)

    @app.get("/api/playground/threat")
    def playground_threat(identifier: str = Query(..., min_length=1)) -> Any:
        return JSONResponse(threat_payload(identifier), headers=NO_CACHE)

    # A plain (sync) handler: FastAPI runs it in its thread pool, so a test that waits
    # up to ~90 s for its share never blocks the dashboard. The body is a plain dict
    # (this module uses postponed annotations; a Request annotation would not resolve).
    @app.post("/api/playground/run")
    def playground_run(body: dict[str, Any] = Body(default={})) -> Any:
        status, payload = run_payload(body)
        return JSONResponse(payload, status_code=status, headers=NO_CACHE)

    @app.get("/api/playground/wallets")
    def playground_wallets() -> Any:
        return JSONResponse(wallet_list_payload(), headers=NO_CACHE)

    @app.post("/api/playground/wallets/run")
    def playground_wallet_run(body: dict[str, Any] = Body(default={})) -> Any:
        status, payload = wallet_run_payload(body)
        return JSONResponse(payload, status_code=status, headers=NO_CACHE)
