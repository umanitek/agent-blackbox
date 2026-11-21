"""Add-ons: how an installed add-on extends the shields — the **Extension point** (Plugin) pattern.

The public plugin carries only what works on its own. An add-on installed beside it — Blackbox
Desktop's, which brings a native helper with deeper system access — adds what needs more:
whole shields of its own, and more of an existing shield (its endpoints, detectors, events, the
options it makes available, a fuller page). The plugin never names the add-on's code; it finds an
add-on by FOLDER and the add-on registers itself through this module.

**Discovery.** For each name in :data:`ADDON_PACKAGES`, a folder of that name next to the
plugin's own folder (``<plugins dir>/blackbox_desktop/__init__.py``) is loaded as a sibling
package of the plugin (``hermes_plugins.blackbox_desktop`` beside ``hermes_plugins.blackbox``),
so its relative imports (``from ..blackbox import shields``) reach the plugin through its package
entries. Its ``register(registrar)`` is called once with a :class:`Registrar`. Discovery runs once,
on the registry's first use, never on import and never again on the hot path.

**Fail-open.** An add-on that cannot be loaded, or whose ``register`` raises, contributes NOTHING
(what it registered before failing is dropped) and the plugin works as if it were absent; the
reason is kept (:func:`problems`) and logged. A detector, status or events callable an extension
adds that raises later contributes nothing for that call.

Usage, inside an add-on::

    def register(registrar):
        registrar.register_shield(FILE_SHIELD)
        registrar.extend(ShieldExtension(shield_id="network-shield", provider="Blackbox Desktop",
                                         unlocks=frozenset({"dns", "firewall"}), api=MY_API))
        registrar.add_routes(lambda app: ...)
"""

from __future__ import annotations

import dataclasses
import fnmatch
import importlib.util
import logging
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from ..detection import Finding
from .contract import Capability, FindingKind, Shield, ShieldEvent, ShieldMode, ShieldStatus
from .shield_api import ShieldApi

logger = logging.getLogger(__name__)

#: The add-on folders looked for next to the plugin's own folder, in load order.
ADDON_PACKAGES = ("blackbox_desktop",)

Detector = Callable[[str, Any, ShieldMode], list[Finding]]


@dataclass(frozen=True)
class ShieldExtension:
    """More of an existing shield, from an add-on (*provider*, the product name people see).

    * ``unlocks`` — option ids (e.g. protections) the add-on makes available; without it the
      shield shows them as needing the add-on;
    * ``api`` — more endpoints, merged into the shield's own (``/api/shields/<id>/api/<name>``);
    * ``detect`` — more findings for a tool call (each identifier inside ``claims``);
    * ``claims`` — identifier patterns (fnmatch) of the findings ``detect`` raises;
    * ``events`` — more events for the shield's report (merged newest first);
    * ``status`` — the card, decorated: ``status(mode, card) -> card``;
    * ``finding_kinds`` / ``capabilities`` — more rows for the sighting layer and the attack table;
    * ``packs`` + ``page`` + ``attacks`` (all three, in one folder) — the add-on's own pack folder,
      page and tested attack table replace the shield's; ``detectors`` / ``use_data`` with them.
    """

    shield_id: str
    provider: str
    unlocks: frozenset[str] = frozenset()
    api: Optional[ShieldApi] = None
    detect: Optional[Detector] = None
    claims: tuple[str, ...] = ()
    events: Optional[Callable[[], list[ShieldEvent]]] = None
    status: Optional[Callable[[ShieldMode, ShieldStatus], ShieldStatus]] = None
    finding_kinds: tuple[FindingKind, ...] = ()
    capabilities: tuple[Capability, ...] = ()
    packs: Optional[Path] = None
    page: Optional[Path] = None
    attacks: Optional[Path] = None
    detectors: tuple[Any, ...] = ()
    use_data: Optional[Callable[..., None]] = None


@dataclass
class Registrar:
    """What an add-on's ``register`` is handed; everything it adds is kept only if it succeeds."""

    provider_package: str
    shields: list[Shield] = field(default_factory=list)
    extensions: list[ShieldExtension] = field(default_factory=list)
    routes: list[Callable[[Any], None]] = field(default_factory=list)

    def register_shield(self, shield: Shield) -> None:
        """A whole shield of the add-on's own (registered after the plugin's)."""
        self.shields.append(shield)

    def extend(self, extension: ShieldExtension) -> None:
        """More of an existing shield (see :class:`ShieldExtension`)."""
        if extension.packs is not None and (extension.page is None or extension.attacks is None):
            raise ValueError("an extension that brings packs brings its page and attack table too")
        self.extensions.append(extension)

    def add_routes(self, register_routes: Callable[[Any], None]) -> None:
        """A function the dashboard calls with its FastAPI app to add the add-on's routes."""
        self.routes.append(register_routes)


_lock = threading.Lock()
_state: dict[str, Any] = {"loaded": False, "registrars": [], "problems": []}


def _load_one(parent: str, plugins_dir: Path, name: str) -> Optional[Registrar]:
    init = plugins_dir / name / "__init__.py"
    if not init.is_file():
        return None
    module_name = f"{parent}.{name}" if parent else name
    for loaded in [key for key in sys.modules if key == module_name or key.startswith(module_name + ".")]:
        del sys.modules[loaded]   # a reloaded plugin gets a fresh add-on bound to it, never a stale one
    spec = importlib.util.spec_from_file_location(module_name, init, submodule_search_locations=[str(init.parent)])
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {init}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    registrar = Registrar(provider_package=name)
    module.register(registrar)
    return registrar


def load(plugin_package: str, plugin_dir: Path, names: Iterable[str] = ADDON_PACKAGES) -> None:
    """Finds and registers every add-on next to *plugin_dir* (once; later calls do nothing).
    *plugin_package* is the plugin's own package name (``hermes_plugins.blackbox``)."""
    with _lock:
        if _state["loaded"]:
            return
        _state["loaded"] = True
        parent = plugin_package.rpartition(".")[0]
        for name in names:
            try:
                registrar = _load_one(parent, plugin_dir.parent, name)
            except Exception as exc:   # an add-on never takes the plugin down: it contributes nothing
                logger.warning("blackbox: add-on %s could not be loaded: %s", name, exc, exc_info=True)
                _state["problems"].append(f"{name}: {type(exc).__name__}: {exc}")
                continue
            if registrar is not None:
                _state["registrars"].append(registrar)


def reset() -> None:
    """Forgets every add-on (tests; a reloaded plugin starts from nothing)."""
    with _lock:
        _state.update(loaded=False, registrars=[], problems=[])


def use(registrar: Registrar) -> None:
    """Registers an add-on's registrar directly (tests stand an add-on in without a folder)."""
    with _lock:
        _state["loaded"] = True
        _state["registrars"].append(registrar)


def problems() -> list[str]:
    """Why an add-on found next to the plugin is not in use (empty when none failed)."""
    return list(_state["problems"])


def providers() -> list[str]:
    """The add-on packages in use."""
    return [registrar.provider_package for registrar in _state["registrars"]]


def added_shields() -> list[Shield]:
    return [shield for registrar in _state["registrars"] for shield in registrar.shields]


def extensions_of(shield_id: str) -> list[ShieldExtension]:
    return [ext for registrar in _state["registrars"] for ext in registrar.extensions if ext.shield_id == shield_id]


def unlocked(shield_id: str) -> frozenset[str]:
    """Every option id an add-on makes available for *shield_id*."""
    return frozenset().union(*(ext.unlocks for ext in extensions_of(shield_id)))


def route_registrars() -> list[Callable[[Any], None]]:
    return [routes for registrar in _state["registrars"] for routes in registrar.routes]


def _merged_api(base: Optional[ShieldApi], extensions: list[ShieldExtension]) -> Optional[ShieldApi]:
    apis = [api for api in [base, *(ext.api for ext in extensions)] if api is not None]
    if not apis:
        return None
    reads: dict[str, Any] = {}
    writes: dict[str, Any] = {}
    for api in apis:
        reads.update(api.reads)
        writes.update(api.writes)
    return ShieldApi(reads=reads, writes=writes)


def _safe(call: Callable[..., Any], fallback: Any, what: str) -> Callable[..., Any]:
    def guarded(*args: Any) -> Any:
        try:
            return call(*args)
        except Exception:   # an add-on's callable never breaks the shield: it adds nothing
            logger.warning("blackbox: add-on %s failed", what, exc_info=True)
            return fallback(*args) if callable(fallback) else fallback
    return guarded


def apply(shield: Shield) -> Shield:
    """*shield* with every add-on extension of it applied (the shield itself when none)."""
    extensions = extensions_of(shield.id)
    if not extensions:
        return shield
    detectors = [shield.detect, *(_safe(ext.detect, [], f"{ext.provider} detect") for ext in extensions if ext.detect)]
    patterns = tuple(pattern for ext in extensions for pattern in ext.claims)
    base_claims, base_status, base_events = shield.claims, shield.status, shield.events
    statuses = [_safe(ext.status, lambda _mode, card: card, f"{ext.provider} status") for ext in extensions if ext.status]
    more_events = [_safe(ext.events, [], f"{ext.provider} events") for ext in extensions if ext.events]

    def detect(tool_name: str, args: Any, mode: ShieldMode) -> list[Finding]:
        return [finding for detector in detectors for finding in detector(tool_name, args, mode)]

    def claims(finding: Mapping[str, Any]) -> bool:
        identifier = str(finding.get("identifier") or "")
        return base_claims(finding) or any(fnmatch.fnmatchcase(identifier, pattern) for pattern in patterns)

    def status(mode: ShieldMode) -> ShieldStatus:
        card = base_status(mode)
        for decorate in statuses:
            card = decorate(mode, card)
        return card

    def events() -> list[ShieldEvent]:
        merged = base_events() + [event for more in more_events for event in more()]
        return sorted(merged, key=lambda event: -event.ts)

    changes: dict[str, Any] = dict(
        detect=detect, claims=claims, status=status, events=events, api=_merged_api(shield.api, extensions),
        finding_kinds=shield.finding_kinds + tuple(kind for ext in extensions for kind in ext.finding_kinds),
        capabilities=shield.capabilities + tuple(item for ext in extensions for item in ext.capabilities),
    )
    presenting = next((ext for ext in reversed(extensions) if ext.packs is not None), None)
    if presenting is not None:
        changes.update(packs=presenting.packs, page=presenting.page, attacks=presenting.attacks,
                       detectors=presenting.detectors or shield.detectors, use_data=presenting.use_data or shield.use_data)
    return dataclasses.replace(shield, **changes)


def assemble(base: Iterable[Shield]) -> tuple[Shield, ...]:
    """The plugin's shields with their extensions applied, then each add-on's own shields."""
    shields = [apply(shield) for shield in base]
    taken = {shield.id for shield in shields}
    for shield in added_shields():
        if shield.id in taken:
            logger.warning("blackbox: add-on shield %s ignored: the id is taken", shield.id)
            continue
        taken.add(shield.id)
        shields.append(shield)
    return tuple(shields)


__all__ = ["ADDON_PACKAGES", "Registrar", "ShieldExtension"]
