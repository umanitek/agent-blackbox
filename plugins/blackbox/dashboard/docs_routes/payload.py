"""What the dashboard's Docs page shows that comes from the product itself.

The Docs page explains Blackbox in prose it ships with (``docs.html``), and reads everything that
changes with the product from ``GET /api/docs`` — built here, live, from the shields registry:
the security settings (every agent permission explained, what is refused in every mode, what no
setting relaxes — :func:`settings_doc`), each shield, its page prose (what it does today, what it cannot yet, what comes next), its packs
(with each pack's stores, browsers and sources), the browser folders it knows, its tested attack
table and the real-machine runs that exercised it. Nothing here is a hand-kept copy of product data, so the docs
cannot drift from what the product does. The one hand-written record is ``field_tests.json``: the
real-machine test runs, which are past events, not product state.

Shields are read generically (the dashboard never names a shield's parts — see
tests/plugins/test_blackbox_shields_boundaries.py).

Usage::

    payload = build_payload()        # DocsPayload, JSON-ready
    payload["shields"][0]["packs"]   # every pack of the first shield
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional, TypedDict

from ... import detection, shields
from ...kernel.constants import __version__

logger = logging.getLogger(__name__)

FIELD_TESTS_FILE = Path(__file__).with_name("field_tests.json")
#: The attack-table row fields the page may show: never a row's test command (those live with the
#: tests, never in plugin files — the Hermes catalog gate scans what ships).
ATTACK_FIELDS = ("id", "group", "title", "how", "outcome", "targets", "evidence")


class AvailabilityDoc(TypedDict, total=False):
    """One store a wallet ships in: ``store``, ``browsers``, ``state`` (protected / not-covered /
    not-offered / not-found) and, when known, ``url``, ``source`` and ``note``."""

    store: str
    browsers: list[str]
    state: str
    url: str
    source: str
    note: str


class PackDoc(TypedDict):
    """One pack of a shield (a wallet, for Trader Shield) as the Docs page lists it."""

    id: str
    name: str
    kind: str
    status: str
    verified: str
    source: str
    stores: dict[str, list[str]]
    places: list[str]
    label: str
    availability: list[AvailabilityDoc]
    logo: Optional[str]


class BrowserDoc(TypedDict):
    """One browser folder the shield knows: which browser, on which system, installed how."""

    browser: str
    engine: str
    os: str
    install: str


class ContentDoc(TypedDict):
    """A shield page's prose (its ``content.json``): ``can`` and ``cannot`` are ``[title, detail]``
    pairs, ``coming`` is a list of names. Empty lists when the shield ships no prose."""

    can: list[list[str]]
    cannot: list[list[str]]
    coming: list[str]


class ShieldDoc(TypedDict):
    """One shield: who it is, what it can do, what it guards, where it looks, what was tested
    and the real-machine runs that exercised it (``field_tests``, runs naming this shield)."""

    id: str
    name: str
    tagline: str
    beta: bool
    page: str
    capabilities: list[dict[str, str]]
    packs: list[PackDoc]
    browsers: list[BrowserDoc]
    attacks: dict[str, Any]
    content: ContentDoc
    field_tests: list[dict[str, Any]]


class PermissionDoc(TypedDict):
    """One agent permission as the person reads it: what it ``unlocks``, what the agent meets
    ``when_blocked``, its ``cost`` if relaxed, its strict ``default`` and the ``modes`` on offer."""

    id: str
    name: str
    unlocks: str
    when_blocked: str
    cost: str
    default: str
    modes: list[str]
    route: str


class RuleDoc(TypedDict):
    """A rule shown with its reason: one refused in every mode, or one no setting relaxes."""

    name: str
    why: str
    permission: str


class SettingsDoc(TypedDict):
    """The security settings: every agent permission, what is refused in every mode (and which
    permission may relax it), and the self-protection rules no setting relaxes."""

    permissions: list[PermissionDoc]
    always_blocked: list[RuleDoc]
    always_on: list[RuleDoc]


class DocsPayload(TypedDict):
    """``GET /api/docs``: the product version, every shield, the security settings, and the
    real-machine runs that name no shield (a run naming one is listed under that shield)."""

    version: str
    shields: list[ShieldDoc]
    settings: SettingsDoc
    field_tests: list[dict[str, Any]]


def _pack_doc(shield_id: str, pack: Any) -> PackDoc:
    data = pack.data
    has_logo = shields.pack_logo(shield_id, pack.id) is not None
    return PackDoc(
        id=pack.id, name=pack.name, kind=pack.kind, status=pack.status, verified=pack.verified,
        source=pack.source, stores={engine: list(ids) for engine, ids in (data.get("stores") or {}).items()},
        places=list(data.get("places") or []), label=str(data.get("label") or ""),
        availability=[AvailabilityDoc(**entry) for entry in data.get("availability") or []],
        logo=f"/shields/{shield_id}/packs/{pack.id}/logo.svg" if has_logo else None)


def _attacks_doc(shield_id: str) -> dict[str, Any]:
    from ..shields_routes import attacks_payload   # the page's table, browser-folder rows included

    try:
        table = attacks_payload(shield_id)
    except (OSError, ValueError) as exc:
        logger.warning("blackbox docs: the %s attack table could not be read: %s", shield_id, exc)
        table = None
    if not table:
        return {"groups": [], "rows": [], "evidence_levels": {}, "tested_with": ""}
    return {"groups": table.get("groups", []), "evidence_levels": table.get("evidence_levels", {}),
            "tested_with": table.get("tested_with", ""),
            "rows": [{field: row[field] for field in ATTACK_FIELDS if field in row} for row in table.get("attacks", [])]}


def _pairs(value: Any) -> list[list[str]]:
    """``[[title, detail], …]`` from a content list; anything else in it is dropped."""
    return [[str(item[0]), str(item[1])] for item in value or []
            if isinstance(item, list) and len(item) == 2 and all(isinstance(part, str) for part in item)]


def _content_doc(shield_id: str) -> ContentDoc:
    from ..shields_routes import shield_file   # the one place that knows where a shield keeps its prose

    path = shield_file(shield_id, "content.json")
    data: Any = {}
    if path is not None:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            logger.warning("blackbox docs: the %s page prose could not be read: %s", shield_id, exc)
    if not isinstance(data, dict):
        data = {}
    return ContentDoc(can=_pairs(data.get("can")), cannot=_pairs(data.get("cannot")),
                      coming=[str(name) for name in data.get("coming") or [] if isinstance(name, str)])


def _shield_doc(shield: Any, runs: list[dict[str, Any]]) -> ShieldDoc:
    return ShieldDoc(
        id=shield.id, name=shield.name, tagline=shield.tagline, beta=shield.beta, page=f"/shields/{shield.id}",
        capabilities=[{"id": cap.id, "name": cap.name, "note": cap.note} for cap in shield.capabilities],
        packs=[_pack_doc(shield.id, pack) for pack in shields.loaded_packs(shield.id)],
        browsers=[BrowserDoc(browser=root.browser, engine=root.engine, os=root.os, install=root.install)
                  for root in shields.browser_roots(shield.id)],
        attacks=_attacks_doc(shield.id), content=_content_doc(shield.id),
        field_tests=[run for run in runs if run.get("shield") == shield.id])


def _field_tests() -> list[dict[str, Any]]:
    try:
        runs = json.loads(FIELD_TESTS_FILE.read_text(encoding="utf-8-sig")).get("runs", [])
    except (OSError, ValueError) as exc:
        logger.warning("blackbox docs: field tests could not be read: %s", exc)
        return []
    return [run for run in runs if isinstance(run, dict)] if isinstance(runs, list) else []


def settings_doc() -> SettingsDoc:
    """The security settings, read from the one catalogue the guard and the Security page use."""
    permissions = [PermissionDoc(id=each.id, name=each.name, unlocks=each.unlocks, when_blocked=each.when_blocked,
                                 cost=each.cost, default=each.default.value, modes=[mode.value for mode in each.modes],
                                 route=each.route.value)
                   for each in shields.AGENT_PERMISSIONS if each.controllable]
    return SettingsDoc(permissions=permissions,
                       always_blocked=[RuleDoc(name=rule.name, why=rule.why, permission=rule.permission)
                                       for rule in detection.ALWAYS_BLOCKED],
                       always_on=[RuleDoc(name=rule.name, why=rule.why, permission="") for rule in shields.ALWAYS_ON])


def build_payload() -> DocsPayload:
    """The Docs page's live data (see :class:`DocsPayload`)."""
    runs = _field_tests()
    registered = {shield.id for shield in shields.all_shields()}
    return DocsPayload(version=__version__, shields=[_shield_doc(shield, runs) for shield in shields.all_shields()],
                       settings=settings_doc(), field_tests=[run for run in runs if run.get("shield") not in registered])
