"""The dashboard's side of shields: the settings each shield adds, and ``GET /api/shields``.

The kernel's settings stay shield-free (it never imports a shield); the dashboard composes
each shield's Settings view onto what the kernel answers, on GET and POST alike, so
the page re-renders from one shape. A sub-package because ``dashboard/`` is at its file
limit. The page draws every shield from these routes alone (``static/shields.js``); no
shield is named in the dashboard's own markup or script.

``GET /api/shields`` answers every registered shield's card (``shields.statuses()``) with
what the page needs to draw it — the shield's ``name``, ``tagline``, ``beta``, its ``page``
address and ``claims`` (the finding identifier patterns it owns, so the page can tell its
findings apart) — sanitised ONCE here, at the serving boundary (a shield clamps its own text but never
imports the dashboard), and served through the server's stale-while-revalidate cache for
:data:`STATUS_TTL_SECONDS`, so N shields cost one read per 2 s however many tabs poll.

``GET /api/shields/{id}/events`` answers that shield's full local events report
(``[ShieldEvent.as_json()]``, newest first; 404 for an id no shield is registered as),
sanitised once here too. Its text is the operator's OWN logs (redacted when logged), so it
is cleaned and clamped but not defanged — ``backup.tgz`` stays ``backup.tgz`` — and the
``identifier`` goes through ``safe_identifier``, the token the page hands back.

``GET /shields/{id}`` is the shield's explainer page, which reads everything else by
RELATIVE address: its prose (``/shields/{id}/content.json``), its tested attack
table (``/attacks.json``: the hand-written rows, ``systems`` and ``tested_with`` composed by
the registry, plus one generated row per browser folder rule, :func:`attacks_payload`), its figures (``/graph.json``, 404 for a shield that ships none) and its packs'
logos (``/packs/{pack}/logo.svg``). Every file is found through the registry from ``id`` and
``pack`` — a value no shield or pack is registered as is 404 before the filesystem is
touched — and a logo is served as an image, never a document: ``image/svg+xml``,
``nosniff`` and a sandboxing CSP, so an SVG opened directly runs nothing. The
campaign addresses ``/trader-shield``, ``/trader-shield/attacks.json`` and
``/trader-shield/graph.json`` are permanent 307 aliases with FIXED Locations, never
built from the request. All of it sits behind the app-wide browser boundary.

``GET /shields.js`` is the dashboard's shield code (``static/shields.js``, one fixed file).

Usage::

    return shields_routes.with_shields(settings.read_settings())   # GET /api/settings
    return shields_routes.with_shields(settings.write_settings(payload, validators=...))   # POST
    shields_routes.register(app, _swr)   # from dashboard.server.create_app
    shields_routes.events_payload("trader")   # -> [ShieldEvent.as_json()], or None for an unknown id
    shields_routes.attacks_payload("trader")  # -> the page's table with its browser-folder rows
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional

from ... import audit, shields
from ...kernel.config import load_blackbox_config
from ...kernel.display_safety import strip_controls
from ..safe_payloads import safe_identifier, safe_text

logger = logging.getLogger(__name__)

#: How long one answer of ``GET /api/shields`` is reused (the page polls every 4 s).
STATUS_TTL_SECONDS = 2.0
#: The longest text a card carries (a section's help sentence is the longest today).
MAX_CARD_TEXT = 1000
#: The longest text an event carries (its story: the asked request, escaped, plus the prose).
MAX_EVENT_TEXT = 8000
#: A card's ``logo`` and ``page``: a path on this dashboard (``/shields/trader/packs/metamask/logo.svg``),
#: served as is or not at all.
LOCAL_PATHS = ("logo", "page")
LOCAL_URL = re.compile(r"/[A-Za-z0-9_-]+(?:[./][A-Za-z0-9_-]+)*")
#: A pack logo is an image, never a document: opened directly, its script cannot run.
LOGO_HEADERS = {"X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                "Cache-Control": "public, max-age=86400"}
NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate"}
#: The page's shield code (``GET /shields.js``): it ships with the page, so it is never cached either.
SHIELDS_SCRIPT = Path(__file__).resolve().parents[1] / "static" / "shields.js"
#: The campaign addresses of Trader Shield's page: permanent, each to a FIXED Location.
ALIASES = {"/trader-shield": "/shields/trader",
           "/trader-shield/attacks.json": "/shields/trader/attacks.json",
           "/trader-shield/graph.json": "/shields/trader/graph.json"}
#: The folded group the generated browser-folder rows are shown in: one row per rule.
BROWSER_FOLDER_GROUP = {"id": "browser-folders", "title": "Every browser folder", "fold": True,
                        "intro": "A stealer often takes a whole browser folder instead of one file. Every place a "
                                 "browser keeps its profiles is archived in the tests with a wallet inside, and "
                                 "every one is blocked. Open to see each browser, system and install."}
#: A browser folder rule whose ``source`` contains this was checked on a real install (``real-software``).
REAL_INSTALL = "installed on"
OS_NAMES = {"linux": "Linux", "macos": "macOS", "windows": "Windows"}
#: ``create_app``'s cache: ``swr(key, producer, default, ttl)`` answers the cached value.
Cache = Callable[..., Any]
#: ``create_app``'s cache writer: ``store(key, producer)`` recomputes and caches now.
CacheStore = Callable[[str, Callable[[], Any]], None]
#: The cache key of ``GET /api/shields``.
CACHE_KEY = "shields"


def refresh_after_save(store: CacheStore) -> None:
    """Rebuild every shield's card now, after a Settings save changed a mode, so the page's
    refresh right after Save shows the new mode instead of the card cached before it.
    Fail-open: the save already succeeded; a card that cannot be built is logged and the
    cache keeps its last card until the next refresh."""
    try:
        store(CACHE_KEY, statuses_payload)
    except Exception:
        logger.warning("blackbox dashboard: shield cards not rebuilt after a settings save", exc_info=True)


def with_shields(result: dict[str, Any]) -> dict[str, Any]:
    """*result* with ``shields`` (``{id: {mode, fields}}``) added to its settings view.

    A ``write_settings`` result carries the view under ``settings``; a ``read_settings``
    result is the view. Fail-open: when a shield's view cannot be built, the settings are
    answered without ``shields`` and the page leaves the shield groups as they were.
    """
    view = result.get("settings") if isinstance(result.get("settings"), dict) else result
    try:
        view["shields"] = shields.settings_view()
    except Exception as exc:   # one broken shield must never take the settings page down
        logger.warning("blackbox dashboard: shield settings view failed (%s)", type(exc).__name__)
    return result


def _card_text(value: str) -> str:
    return safe_text(value, MAX_CARD_TEXT)


def _local_text(value: str) -> str:
    """The operator's own logged text: controls stripped and clamped, never defanged."""
    return strip_controls(value)[:MAX_EVENT_TEXT]


def sanitised(value: Any, text: Callable[[str], str] = _card_text) -> Any:
    """*value* (plain JSON) with every string passed through *text* (by default
    ``safe_payloads.safe_text`` — the dashboard's one sanitiser), except a ``logo`` or a
    ``page``, each a local path kept only when it is one (defanging would break it), and an ``identifier``,
    which goes through ``safe_identifier``; keys are the record's own field names."""
    if isinstance(value, str):
        return text(value)
    if isinstance(value, dict):
        return {key: _local_url(item) if key in LOCAL_PATHS else safe_identifier(item) if key == "identifier"
                else sanitised(item, text) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitised(item, text) for item in value]
    return value


def card(status: shields.ShieldStatus) -> dict[str, Any]:
    """*status* as the page draws it: the card, plus its shield's descriptive fields."""
    shield = shields.get(status.shield_id)
    described = {} if shield is None else {
        "name": shield.name, "tagline": shield.tagline, "beta": shield.beta, "page": f"/shields/{shield.id}",
        "claims": [kind.identifier for kind in shield.finding_kinds if kind.identifier]}
    return {**status.as_json(), **described}


def statuses_payload() -> list[Any]:
    """Every shield's card as served: ``[card(ShieldStatus)]``, sanitised once."""
    return [sanitised(card(status)) for status in shields.statuses()]


def events_payload(shield_id: str) -> list[Any] | None:
    """*shield_id*'s events report as served, sanitised once; None when no shield has that id.

    In sandbox mode the Playground's tests are events too (Amos, 2026-10-27): the same report
    read from the sandbox's own logs, each marked ``"sandbox": true``, merged newest first —
    the real logs are never mixed with them anywhere but on this page."""
    shield = shields.get(shield_id)
    if shield is None:
        return None
    rows = [sanitised(event.as_json(), _local_text) for event in shield.events()]
    if load_blackbox_config().community_sandbox:
        with audit.sandbox_run():
            tests = [{**sanitised(event.as_json(), _local_text), "sandbox": True} for event in shield.events()]
        rows = sorted(rows + tests, key=lambda row: float(row.get("ts") or 0), reverse=True)
    return rows


def browser_folder_rows(shield_id: str) -> list[dict[str, Any]]:
    """One attack row per browser folder rule of *shield_id* (``browsers.json``), in file order.

    Row ``vault-root-<browser>-<os>-<install>`` (``-2``, ``-3`` … when rules share all three)
    claims what the suite proves for that rule: the folder holding the root, with a store of
    the first supported browser-extension pack that keeps one for the root's engine, archived
    with ``tar czf`` through the real hook, is blocked. ``proof: test``, ``evidence: [tests]``,
    plus ``real-software`` when the rule's ``source`` records a real install. What the row
    DOES lives in the test, never here (a shipped table carries no scenario fields).
    """
    packs = [pack for pack in shields.loaded_packs(shield_id)
             if pack.status == "supported" and pack.kind == "browser-extension"]
    rows: list[dict[str, Any]] = []
    seen: Counter[str] = Counter()
    for root in shields.browser_roots(shield_id):
        pack = next((pack for pack in packs if (pack.data.get("stores") or {}).get(root.engine)), None)
        if pack is None:
            continue   # no supported pack keeps a store there: no row, and the suite says so
        key = f"vault-root-{root.browser}-{root.os}-{root.install}"
        seen[key] += 1
        place = OS_NAMES.get(root.os, root.os) + ("" if root.install == "native" else ", " + root.install)
        place += "" if seen[key] == 1 else f", layout {seen[key]}"
        rows.append({"id": key if seen[key] == 1 else f"{key}-{seen[key]}", "group": BROWSER_FOLDER_GROUP["id"],
                     "proof": "test", "outcome": "blocked", "targets": [pack.id],
                     "evidence": ["tests"] + (["real-software"] if REAL_INSTALL in root.source else []),
                     "title": f"{root.browser.capitalize()} folder archived ({place})",
                     "how": f"The agent archives the folder holding {root.path} with tar, {pack.name}'s vault inside."})
    return rows


def attacks_payload(shield_id: str) -> Optional[dict[str, Any]]:
    """*shield_id*'s attack table as its page reads it: the registry's table with the
    generated browser-folder rows and their folded group (placed after ``vault``); None for
    an unknown id. Raises what ``shields.attack_table`` raises for a broken file."""
    table = shields.attack_table(shield_id)
    rows = browser_folder_rows(shield_id) if table is not None else []
    if not rows:
        return table
    groups = list(table["groups"])
    after = next((index + 1 for index, group in enumerate(groups) if group.get("id") == "vault"), len(groups))
    return {**table, "groups": groups[:after] + [BROWSER_FOLDER_GROUP] + groups[after:],
            "attacks": table["attacks"] + rows}


def shield_file(shield_id: str, name: str) -> Optional[Path]:
    """The page-side file *name* (``page``, ``content.json`` or ``graph.json``) of the shield
    registered as *shield_id*, when it ships one; None otherwise (the id is never a path)."""
    shield = shields.get(shield_id)
    if shield is None:
        return None
    path = {"page": shield.page, "content.json": shield.page.with_name("content.json"),
            "graph.json": shield.folder / "graph.json"}[name]
    return path if path.is_file() else None


def register(app: Any, swr: Cache) -> None:
    """Add ``GET /api/shields`` (cached through *swr*), ``GET /api/shields/{id}/events``, the
    page's ``GET /shields.js`` and every shield's page and its files (:func:`register_pages`)
    to *app*."""
    from fastapi.responses import FileResponse, JSONResponse

    register_pages(app)
    from . import api_routes
    api_routes.register(app)   # each shield's own endpoints: /api/shields/{id}/api/{name}
    for register_routes in shields.addon_routes():   # an installed add-on's own routes (shields.extensions)
        try:
            register_routes(app)
        except Exception:   # an add-on never takes the dashboard down: its routes are left out
            logger.warning("blackbox: add-on routes could not be added", exc_info=True)

    @app.get("/shields.js")
    def shields_script() -> Any:
        return FileResponse(str(SHIELDS_SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/api/shields")
    def shield_statuses() -> Any:
        return swr(CACHE_KEY, statuses_payload, [], STATUS_TTL_SECONDS)

    @app.get("/api/shields/{shield_id}/events")
    def shield_events(shield_id: str) -> Any:
        payload = events_payload(shield_id)
        if payload is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return payload


def _local_url(value: Any) -> str:
    """*value* when it is a plain path on this dashboard, else "" (no scheme, host or ``..``)."""
    return value if isinstance(value, str) and LOCAL_URL.fullmatch(value) else ""


def register_pages(app: Any) -> None:
    """Add ``GET /shields/{id}`` and its relative files, and the three permanent aliases."""
    from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

    def not_found() -> Any:
        return JSONResponse({"error": "not found"}, status_code=404)

    def served(shield_id: str, name: str, media_type: str) -> Any:
        path = shield_file(shield_id, name)
        return FileResponse(str(path), media_type=media_type, headers=NO_CACHE) if path else not_found()

    @app.get("/shields/{shield_id}")
    def shield_page(shield_id: str) -> Any:
        return served(shield_id, "page", "text/html")

    @app.get("/shields/{shield_id}/content.json")
    def shield_content(shield_id: str) -> Any:
        return served(shield_id, "content.json", "application/json")

    @app.get("/shields/{shield_id}/graph.json")
    def shield_graph(shield_id: str) -> Any:
        return served(shield_id, "graph.json", "application/json")

    @app.get("/shields/{shield_id}/attacks.json")
    def shield_attacks(shield_id: str) -> Any:
        try:
            table = attacks_payload(shield_id)
        except ValueError as exc:   # the file broke the shield-file rules: say so, never a 500
            logger.warning("blackbox dashboard: %s attack table unavailable (%s)", shield_id, exc)
            table = None
        return JSONResponse(table, headers=NO_CACHE) if table is not None else not_found()

    @app.get("/shields/{shield_id}/packs/{pack_id}/logo.svg")
    def pack_logo(shield_id: str, pack_id: str) -> Any:
        logo = shields.pack_logo(shield_id, pack_id)   # the registry's own record, never a free path
        if logo is None:
            return not_found()
        return FileResponse(str(logo), media_type="image/svg+xml", headers=LOGO_HEADERS)

    for alias, location in ALIASES.items():
        app.add_api_route(alias, _redirect_to(location, RedirectResponse), methods=["GET"],
                          include_in_schema=False)


def _redirect_to(location: str, response: Any) -> Callable[[], Any]:
    """A handler answering 307 to the fixed *location* (bound here, never read from the request)."""
    def redirect() -> Any:
        return response(location, status_code=307)
    return redirect
