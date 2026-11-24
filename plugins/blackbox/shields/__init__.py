"""Shields — named, opt-in protection packs; this is the registry and the only public entry.

**Registry over Strategies.** Each registered :class:`~.contract.Shield` is a record of
plain callables (composition, no base class); the functions here fan a call out to
every shield and apply the rules no shield may opt out of:

* ``snapshot()`` reads every shield's mode ONCE; the hooks take one snapshot per call and hand it
  to ``check`` and ``allows``. A mode is read only by the shield's own ``mode()``.
* ``check()`` runs every ENABLED shield's ``detect`` and marks each finding
  ``source="secret"`` (local only: the community gate refuses that source); a finding
  whose ``fields["pack"]`` names no pack of its shield is dropped, and a shield whose
  ``detect`` raises contributes nothing (fail-open, WARNING each).
* ``allows()`` is the gate: a finding no shield claims is always allowed; a claimed
  one only while that shield is enabled and its ``allows`` agrees. A shield whose
  ``claims`` or ``allows`` raises is read as "claims and refuses" — opt-in
  protection fails toward OFF.

Packs and browser roots are loaded once — the plugin's own shields' at import, an add-on's
changes on the registry's first use — never on the hot path, and loading never raises: a broken pack is ``unavailable`` with its reason, the rest
load. That first use also finds any add-on installed beside the plugin (:mod:`.extensions`, the
extension point every add-on registers through): its own shields join the registry
and its extensions are applied to the shields they extend.

Usage::

    active = shields.snapshot()
    findings = detection.detect_all(...) + shields.check(tool, args, active)
    kept = [f for f in findings if shields.allows(f.to_dict(), active)]
"""

from __future__ import annotations

import dataclasses
import logging
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from ..detection import Finding
from ..kernel.config import one_entry_read
from ..kernel.settings import SettingsValidator
from . import extensions, files, network, trader
from .change_words import describe_change, shield_name
from .contract import (
    BrowserRoot,
    Capability,
    Pack,
    Shield, ShieldAlert,
    ShieldEvent,
    ShieldMode,
    ShieldsSnapshot,
    ShieldStatus,
)
from .extensions import Registrar, ShieldExtension
from .alerting import alerts
from .json_records import JsonValue
from .local_only import LOCAL_ONLY_SOURCE, LOCAL_ONLY_SOURCES
from .local_only import local_only as _local_only
from .network.lockdown import hosts_in   # the hosts a call names, as Network Shield reads them (watch rules)
from .packs import TABLE_MAX_BYTES, ShieldData, load_shield_data, read_json_file
from .self_test import SELF_TESTS, SelfTest
from .shield_api import MAX_WRITE_BYTES as API_MAX_WRITE_BYTES
from .shield_api import NAME_PATTERN as API_NAME_PATTERN
from .shield_api import (
    AssistantAnswer,
    InstanceRef,
    RawAnswer,
    RunningAgent,
    ShieldApi,
    ShieldApiError,
    ShieldContext,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AGENT_SANDBOX", "API_MAX_WRITE_BYTES", "API_NAME_PATTERN", "PACKAGE_INSTALLS", "AssistantAnswer",
    "BrowserRoot", "Capability", "InstanceRef", "Pack", "RawAnswer", "Registrar", "RunningAgent", "SelfTest", "Shield",
    "ShieldAlert", "ShieldApi", "ShieldApiError", "ShieldContext", "ShieldEvent", "ShieldExtension",
    "ShieldMode", "ShieldStatus", "ShieldsSnapshot", "addon_routes", "agent_sandbox_weakening",
    "alerts", "all_shields", "allow_lists", "allows", "apply_sandbox_default", "attack_table",
    "browser_roots", "call_api", "check", "describe_change", "enter_hermes_process", "events", "get", "hosts_in",
    "loaded_packs", "pack_logo", "package_installs_weakening", "permission_refused", "prompt_findings", "reload_registry",
    "remove_sandbox_placeholders", "run_hides_socket",
    "self_tests", "settings_validators", "settings_view", "shield_name", "snapshot", "statuses",
    "unlocked", "write_weakening",
]

#: File Shield's sandbox for the Hermes agent's own shells, at each Hermes session start (fail-open).
enter_hermes_process = files.sandbox.enter_hermes_session
#: Uninstall: the agent sandbox's still-empty startup placeholders taken back (Linux; KI-677).
remove_sandbox_placeholders = files.sandbox.remove_placeholders
#: File Shield's agent sandbox by default, on install, upgrade and attach (gated: ``sandbox.defaults``).
apply_sandbox_default = files.sandbox.defaults.apply
#: ``agent_packages``: Homebrew installs Blackbox makes for sandboxed agents; loosening it waits (approvals).
PACKAGE_INSTALLS, package_installs_weakening = files.sandbox.packages.SECTION, files.sandbox.packages.setting_weakening
#: ``agent_sandbox``: the sandbox permissions per agent and project; loosening them waits (approvals).
AGENT_SANDBOX, agent_sandbox_weakening = files.sandbox.permissions.SECTION, files.sandbox.permissions.section_weakening
#: A sandbox refusal an agent's hook saw: asks the person when the permission it means is on "ask"
#: (a refused signal: the stop broker, with the process it named).
permission_refused = files.sandbox.on_refusal
#: Whether the profile a sandboxed run started with hides an engine's socket (``<file>#<digest>``,
#: the socket path): how a refused Docker connect is recognised from outside the sandbox (KI-685).
run_hides_socket = files.sandbox.run_hides_socket

#: The plugin's own shields, in registration order. Registering one is one line here; an add-on's
#: shields and extensions join them on first use (:func:`_registry`).
_BASE: tuple[Shield, ...] = (trader.TRADER, network.NETWORK, files.FILES)
#: The plugin's own folder and package: where add-ons are looked for, and under which parent.
_PLUGIN_DIR = Path(__file__).resolve().parent.parent
_PLUGIN_PACKAGE = __name__.rpartition(".")[0]

#: The block threshold an attack table is tested at when it names none (Blackbox's default).
DEFAULT_TESTED_SEVERITY = "critical"


def _load_all(shields: Iterable[Shield]) -> dict[str, ShieldData]:
    """Each shield's packs and roots; a shield whose loading fails has none, with the reason."""
    loaded: dict[str, ShieldData] = {}
    for shield in shields:
        try:
            loaded[shield.id] = data = load_shield_data(shield)
            if shield.use_data is not None:   # the shield's own copy comes from this one read
                shield.use_data(data.packs, data.roots)
        except Exception as exc:   # loading never takes the registry (and with it the guard) down
            logger.warning("blackbox: shield %s data could not be loaded: %s", shield.id, exc)
            loaded[shield.id] = ShieldData(health=(f"shield data unavailable — {type(exc).__name__}",))
    return loaded


#: The plugin's own shields' data, loaded at import as always (their code relies on it from then
#: on: a shield's ``use_data`` hands it its packs); an add-on's changes load on first use.
_BASE_DATA: dict[str, ShieldData] = _load_all(_BASE)
_registry_lock = threading.Lock()
#: The assembled registry: shields, each one's data, and each one's pack ids (built once).
_built: dict[str, Any] = {}


def _registry() -> dict[str, Any]:
    """The registry, built on first use: add-ons found, shields assembled, their data loaded."""
    if _built:
        return _built
    with _registry_lock:
        if not _built:
            extensions.load(_PLUGIN_PACKAGE, _PLUGIN_DIR)
            shields = extensions.assemble(_BASE)
            unchanged = {id(shield) for shield in _BASE}
            data = {**{shield.id: _BASE_DATA[shield.id] for shield in shields if id(shield) in unchanged},
                    **_load_all(shield for shield in shields if id(shield) not in unchanged)}
            _built.update(shields=shields, data=data,
                          pack_ids={shield_id: frozenset(pack.id for pack in item.packs) for shield_id, item in data.items()})
    return _built


def reload_registry() -> None:
    """Forgets the assembled registry and the add-ons (tests; a changed add-on)."""
    with _registry_lock:
        _built.clear()
        extensions.reset()
        _BASE_DATA.update(_load_all(_BASE))   # each base shield's own data handed back to it


def all_shields() -> tuple[Shield, ...]:
    """Every registered shield, in registration order (the plugin's, then each add-on's)."""
    return _registry()["shields"]


def get(shield_id: str) -> Optional[Shield]:
    """The shield registered as *shield_id*, or None."""
    return next((shield for shield in all_shields() if shield.id == shield_id), None)


def addon_routes() -> list[Any]:
    """Each add-on's route registrar (``register_routes(app)``), for the dashboard."""
    _registry()
    return extensions.route_registrars()


def unlocked(shield_id: str) -> frozenset[str]:
    """The options of *shield_id* an installed add-on makes available."""
    _registry()
    return extensions.unlocked(shield_id)


def _mode_of(shield: Shield) -> ShieldMode:
    try:
        return shield.mode()
    except Exception as exc:   # a mode that cannot be read is off (fails toward OFF)
        logger.warning("blackbox: shield %s mode could not be read: %s", shield.id, exc)
        return ShieldMode(enabled=False)


def snapshot() -> ShieldsSnapshot:
    """Every shield paired with its mode, each read once — take one per hook call. The config is
    read once for all of them (``kernel.config.one_entry_read``), however many shields there are."""
    with one_entry_read():
        return ShieldsSnapshot(entries=tuple((shield, _mode_of(shield)) for shield in all_shields()))


def check(tool_name: str, args: Any, active: ShieldsSnapshot) -> list[Finding]:
    """Every enabled shield's own findings for this call, each marked local-only; a finding
    naming a pack its shield does not have is a detector fault and is dropped."""
    findings: list[Finding] = []
    for shield, mode in active.entries:
        if not mode.enabled:
            continue
        try:
            raised = shield.detect(tool_name, args, mode)
        except Exception as exc:   # a broken detector contributes nothing (fail-open)
            logger.warning("blackbox: shield %s detect failed: %s", shield.id, exc)
            continue
        for finding in raised:
            pack = finding.fields.get("pack")
            if pack is not None and pack not in _registry()["pack_ids"].get(shield.id, frozenset()):
                logger.warning("blackbox: shield %s finding %s names unknown pack %r; dropped",
                               shield.id, finding.identifier, pack)
                continue
            findings.append(_local_only(shield.id, finding))
    return findings


def prompt_findings(texts: Iterable[str], active: ShieldsSnapshot) -> list[Finding]:
    """Every enabled shield's flags for the prompts *texts* (``Shield.prompt_check``), each marked
    local-only; a check that raises contributes nothing (fail-open)."""
    findings: list[Finding] = []
    for shield, mode in active.entries:
        if not mode.enabled or shield.prompt_check is None:
            continue
        for text in texts:
            try:
                raised = shield.prompt_check(text, mode)
            except Exception:   # a broken check contributes nothing (fail-open); the traceback says why
                logger.warning("blackbox: shield %s prompt check failed", shield.id, exc_info=True)
                continue
            findings.extend(_local_only(shield.id, finding) for finding in raised)
    return findings


def allows(finding: Mapping[str, Any], active: ShieldsSnapshot) -> bool:
    """False when a shield claims *finding* and is off or refuses it; True otherwise."""
    for shield, mode in active.entries:
        try:
            if shield.claims(finding) and not (mode.enabled and shield.allows(finding, mode)):
                return False
        except Exception as exc:   # claims-and-refuses: opt-in protection fails toward OFF
            logger.warning("blackbox: shield %s gate failed: %s", shield.id, exc)
            return False
    return True


def self_tests() -> list[tuple[Shield, SelfTest]]:
    """Every shield's sandbox self-tests for this machine under its current mode, each with its
    shield (for the Playground); a builder that fails contributes nothing (fail-open)."""
    tests: list[tuple[Shield, SelfTest]] = []
    for shield, mode in snapshot().entries:
        builder = SELF_TESTS.builder(shield.id)
        try:
            tests.extend((shield, test) for test in (builder(mode) if builder else ()))
        except Exception:   # a broken builder lists nothing; the traceback says why
            logger.warning("blackbox: shield %s self-tests could not be built", shield.id, exc_info=True)
    return tests


def settings_validators() -> tuple[SettingsValidator, ...]:
    """One settings validator per shield, for ``kernel.settings.write_settings(validators=...)``."""
    return tuple(shield.validate for shield in all_shields())


def allow_lists() -> dict[str, frozenset[str]]:
    """``{shield id: its allow-list options}`` — adding to one of these turns protection down;
    on every other list option, removing an entry does (``approvals`` judges by this)."""
    return {shield.id: shield.allow_lists for shield in all_shields()}


def write_weakening(shield_id: str, name: str, body: Mapping[str, Any]) -> Optional[list[str]]:
    """Why ``POST /api/shields/<shield_id>/api/<name>`` with *body* would turn protection down
    (empty: it would not). None when that write has no judge — it never weakens anything. A
    judge that fails answers that the change could not be checked: it asks rather than applies."""
    shield = get(shield_id)
    judge = shield.api.weakening.get(name) if shield is not None and shield.api is not None else None
    if judge is None:
        return None
    try:
        return list(judge(body))
    except Exception:   # health: allow BLE001 -- an unreadable current state asks the person
        logger.warning("blackbox shields: weakening judge %s/%s failed", shield_id, name, exc_info=True)
        return [f"Change {shield.name} (Blackbox could not check whether it turns protection down)"]


def settings_view() -> dict[str, Any]:
    """``{shield id: {mode, fields}}`` for the Settings page (the one view that shows personal options)."""
    return {shield.id: {"mode": _mode_of(shield).as_json(include_personal=True),
                        "fields": [item.as_json() for item in shield.settings_fields()]}
            for shield in all_shields()}


def statuses() -> list[ShieldStatus]:
    """Every shield's card, built from one snapshot."""
    return [shield.status(mode) for shield, mode in snapshot().entries]


def events(shield_id: str) -> list[ShieldEvent]:
    """The local events report of *shield_id* (empty for an unknown id)."""
    shield = get(shield_id)
    return shield.events() if shield is not None else []


def pack_logo(shield_id: str, pack_id: str) -> Optional[Path]:
    """The logo file of a usable pack, resolved through the registry only; None when it has none."""
    data = _registry()["data"].get(shield_id)
    pack = next((item for item in data.packs if item.id == pack_id), None) if data else None
    if pack is None or pack.status == "unavailable" or pack.logo is None:
        return None
    return pack.folder / pack.logo.file


def loaded_packs(shield_id: str) -> tuple[Pack, ...]:
    """Every pack *shield_id* loaded, in display order (unavailable ones included, with their
    reason); empty for an unknown id."""
    data = _registry()["data"].get(shield_id)
    return data.packs if data else ()


def browser_roots(shield_id: str) -> tuple[BrowserRoot, ...]:
    """Every browser folder rule *shield_id* loaded from its ``browsers.json``, in file order
    (a bad entry was dropped with a health reason); empty for an unknown id or a shield with none."""
    data = _registry()["data"].get(shield_id)
    return data.roots if data else ()


def attack_table(shield_id: str) -> Optional[dict[str, Any]]:
    """*shield_id*'s tested attack table as its page reads it; None for an unknown id.

    The rows, groups and evidence levels are the hand-written ``attacks.json``; what the
    table is tested ON is composed here from the registry, never typed:
    ``systems`` — every supported pack (``logo``: whether it ships one) then every
    capability — and ``tested_with``, the setup sentence the test suite runs under
    (every supported pack chosen, block mode at the table's ``tested_severity``).
    Raises :class:`~.packs.PackError` when the file breaks the shield-file rules.
    """
    shield = get(shield_id)
    if shield is None:
        return None
    table = read_json_file(shield.attacks, inside=shield.folder, max_bytes=TABLE_MAX_BYTES)
    supported = [pack for pack in loaded_packs(shield_id) if pack.status == "supported"]
    systems = [{"id": pack.id, "name": pack.name, "logo": pack.logo is not None} for pack in supported]
    systems += [{"id": item.id, "name": item.name, "note": item.note, "logo": False} for item in shield.capabilities]
    severity = table.get("tested_severity", DEFAULT_TESTED_SEVERITY)
    tested_with = f"{shield.name} on for {_spoken_list([pack.name for pack in supported])}, block mode, block at {severity}"
    return {**table, "systems": systems, "tested_with": tested_with}


def _spoken_list(names: list[str]) -> str:
    """*names* as a sentence lists them: "A", "A and B", "A, B and C" ("no pack" when empty)."""
    if len(names) < 2:
        return "".join(names) or "no pack"
    return ", ".join(names[:-1]) + " and " + names[-1]


def call_api(shield_id: str, method: str, name: str, context: ShieldContext, data: Any) -> JsonValue:
    """Runs endpoint *name* of shield *shield_id*'s own API (:mod:`.shield_api`): a ``GET``
    read with *data* as its query parameters, or a ``POST`` write with *data* as its body.

    Raises :class:`ShieldApiError` 404 for an unknown shield or endpoint (or the wrong method),
    and passes on the refusals the endpoint raises itself. Anything else an endpoint raises is
    a 500 here: a shield never takes the dashboard down.
    """
    shield = get(shield_id)
    api = shield.api if shield else None
    handlers = (api.reads if method == "GET" else api.writes if method == "POST" else {}) if api else {}
    handler = handlers.get(name)
    if handler is None:
        raise ShieldApiError(404, "unknown shield endpoint")
    try:
        return handler(context, data)
    except ShieldApiError:
        raise
    except Exception:   # health: allow BLE001 -- a broken shield endpoint answers 500, never breaks the dashboard
        logger.warning("blackbox shields: %s %s/%s failed", method, shield_id, name, exc_info=True)
        raise ShieldApiError(500, "the shield could not answer") from None
