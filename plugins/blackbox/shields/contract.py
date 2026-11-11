"""What every shield provides, and the typed records it answers with.

A **shield** is a named, opt-in protection pack for one kind of user (Trader Shield
for people who hold crypto). The design is **Strategy + Registry, by composition**:
a :class:`Shield` is a frozen record of metadata and plain callables (its mode, its
validator, its detectors, its gate, its status and events), so a shield is assembled
from functions and there is no base class to inherit from. The registry
(``shields/__init__.py``) holds the shields and is the only public entry.

Every other record here is a frozen dataclass with ``as_json()``: they are the only
shapes that cross to the dashboard, so a field is added here or nowhere.

Usage::

    TRADER = Shield(id="trader", name="Trader Shield", tagline="…", beta=True,
                    mode=mode.current, validate=mode.validate, detect=detectors.detect,
                    claims=gate.claims, allows=gate.allows, status=status.build,
                    events=events.report, settings_fields=mode.fields,
                    finding_kinds=KINDS, capabilities=CAPABILITIES,
                    packs=HERE / "wallets", page=HERE / "page" / "trader.html",
                    attacks=HERE / "attacks.json", detectors=(browser_extension, app_folder),
                    browser_roots=HERE / "browsers.json")
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol

from ..detection import Finding
from ..kernel.settings import ShieldSettings

#: The JSON values a record's ``as_json()`` answers with.
JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def _plain(value: Any) -> JsonValue:
    """*value* as plain JSON: records by their ``as_json()``, paths as text, tuples as lists."""
    if hasattr(value, "as_json"):
        return value.as_json()
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, frozenset, set)):
        return [_plain(item) for item in value]
    return value


def _record_json(record: Any) -> dict[str, JsonValue]:
    """Every field of the dataclass *record*, as plain JSON."""
    return {item.name: _plain(getattr(record, item.name)) for item in fields(record)}


class PackDetector(Protocol):
    """One detector of a shield, as the pack loader sees it (a module satisfies this).

    ``KINDS`` names the pack kinds it serves (``("desktop-app", "cli-key-file")``);
    ``validate_pack(manifest)`` checks that kind's own block of a ``supported`` pack's
    manifest and answers the first problem as one sentence, or None when it is valid.
    """

    KINDS: tuple[str, ...]

    def validate_pack(self, manifest: Mapping[str, Any]) -> Optional[str]: ...


@dataclass(frozen=True)
class ShieldMode:
    """The setting in force for one shield: on or off, plus its options.

    *options* maps an option to its chosen values (``{"wallets": ("metamask",)}``).
    A chosen pack that is not supported right now stays here (reported, never
    dropped). *personal* names the options that hold personal data (the operator's
    own wallet addresses); ``as_json()`` leaves them out unless asked.
    """

    enabled: bool
    options: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    personal: frozenset[str] = frozenset()

    def as_json(self, include_personal: bool = False) -> dict[str, JsonValue]:
        options: dict[str, JsonValue] = {key: list(values) for key, values in self.options.items()
                   if include_personal or key not in self.personal}
        return {"enabled": self.enabled, **options}


@dataclass(frozen=True)
class StatusRow:
    """One line of a status section: an icon, its state, the text and a smaller line under it."""

    icon: str
    state: str
    text: str
    sub: str = ""
    logo: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class StatusSection:
    """A titled group of rows on a shield's card ("Found on this machine", "Always watching")."""

    title: str
    help: str
    rows: tuple[StatusRow, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class ShieldStatus:
    """What a shield's dashboard card shows; *blocking* is Blackbox's audit/block mode."""

    shield_id: str
    mode: ShieldMode
    blocking: bool
    sections: tuple[StatusSection, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)   # mode.as_json() without personal options


@dataclass(frozen=True)
class TimelineStep:
    """One step of the session around an event (model call, tool call, file read …)."""

    type: str
    ts: float
    tool: str
    label: str
    result: str = ""
    threats: tuple[str, ...] = ()
    threat_titles: tuple[str, ...] = ()
    this: bool = False

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class SessionSummary:
    """The agent session an event happened in."""

    id: str
    agent: str
    model: str
    start: str
    end: str
    status: str
    steps: int

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class EventFact:
    """One labelled fact of an event; *mono* shows the value in a fixed-width font."""

    label: str
    value: str
    mono: bool = False

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class ShieldEvent:
    """One event of a shield's local report: the story, what to do, the facts and the timeline.

    *story* is HTML-safe text with a few bold spans; the shield writes it, the page
    renders it as given (no shield prose in JavaScript).
    """

    ts: float
    identifier: str
    title: str
    severity: str
    outcome: str
    tool: str
    command: str
    asked: str
    logo: str
    story: str
    session: SessionSummary
    what_to_do: tuple[str, ...] = ()
    facts: tuple[EventFact, ...] = ()
    timeline: tuple[TimelineStep, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class AttackRow:
    """One row of a shield's tested attack table; *targets* are pack or capability ids."""

    id: str
    group: str
    targets: tuple[str, ...]
    proof: str          # test | bench
    outcome: str        # blocked | flagged | missed | allowed
    title: str
    how: str
    tool: str
    args: Mapping[str, JsonValue] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class Capability:
    """Something a shield protects that is not a pack (``exchanges``, ``keychain`` …).

    *claims* are identifier patterns its gate claims; empty = display-only (shown on
    the page and in the table, never gated by the shield).
    """

    id: str
    name: str
    note: str
    claims: tuple[str, ...] = ()

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class FindingKind:
    """What a shield's detectors emit or claim, with the sighting layer's classification.

    One of *identifier* (a pattern such as ``"secret:seed-phrase"`` or
    ``"*:crypto-wallet"``) or *category* (a file category) names the kind; *goal*,
    *resource* and *attack* are its row in ``community/sighting/classification.py``.
    """

    goal: str
    resource: str
    attack: str
    identifier: str = ""
    category: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class SettingOption:
    """One choice of a multi-pick setting: a pack id, its name, status and logo URL."""

    id: str
    name: str
    status: str
    logo: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class SettingField:
    """How Settings draws one field of a shield's group.

    *kind* is ``toggle`` (a boolean), ``multi-pick`` (ids from *options*) or ``lines``
    (a list of strings typed one per line); a ``lines`` field may carry *pattern*, a
    regular expression each line must match in full — the page leaves out (never sends)
    a line that does not, and the shield's validator is still the authority.
    """

    key: str
    kind: str
    label: str
    help: str = ""
    options: tuple[SettingOption, ...] = ()
    pattern: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class PackLogo:
    """A pack's logo: the SVG file, the terms that allow showing it, where it came from."""

    file: str
    terms: str
    source: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class Pack:
    """One protected thing inside a shield (a wallet), described by data in its folder.

    *status* is ``supported`` / ``planned`` from the manifest, or ``unavailable`` when
    the manifest failed validation — then *reason* says why, and the pack is never
    used to build a matcher. *data* is the kind's own block (validated by its detector).
    """

    id: str
    name: str
    kind: str
    status: str
    order: int
    folder: Path
    data: Mapping[str, JsonValue] = field(default_factory=dict)
    logo: Optional[PackLogo] = None
    verified: str = ""
    source: str = ""
    reason: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class BrowserRoot:
    """Where one browser keeps its profiles, as a path template (``~/.mozilla/firefox/*``).

    *profiles* is ``children`` (the root holds profile folders) or ``self`` (the root
    is a profile, or holds no profile folder).
    """

    browser: str
    engine: str         # chromium | firefox
    os: str             # linux | macos | windows
    path: str
    profiles: str       # children | self
    install: str        # native | snap | flatpak
    verified: str
    source: str

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class Shield:
    """One shield: metadata plus the callables that make it work (Strategy; no base class).

    *packs* is the folder of pack folders; the shield's own folder is its parent, and
    every file the loader reads must lie inside it. *detectors* are the pack kinds'
    validators (see :class:`PackDetector`); *browser_roots* is its ``browsers.json``,
    when it ships one. *use_data* receives the packs and roots the registry loaded (read once).
    """

    id: str
    name: str
    tagline: str
    beta: bool
    mode: Callable[[], ShieldMode]
    validate: Callable[[dict[str, Any]], ShieldSettings]
    detect: Callable[[str, Any, ShieldMode], list[Finding]]
    claims: Callable[[Mapping[str, Any]], bool]
    allows: Callable[[Mapping[str, Any], ShieldMode], bool]
    status: Callable[[ShieldMode], ShieldStatus]
    events: Callable[[], list[ShieldEvent]]
    settings_fields: Callable[[], list[SettingField]]
    finding_kinds: tuple[FindingKind, ...]
    capabilities: tuple[Capability, ...]
    packs: Path
    page: Path
    attacks: Path
    detectors: tuple[PackDetector, ...] = ()
    browser_roots: Optional[Path] = None
    use_data: Optional[Callable[[tuple[Pack, ...], tuple[BrowserRoot, ...]], None]] = None

    @property
    def folder(self) -> Path:
        """The shield's own folder: everything it ships lives inside it."""
        return self.packs.parent

    def as_json(self) -> dict[str, JsonValue]:
        """The shield's descriptive fields (its callables do not serialise)."""
        return {"id": self.id, "name": self.name, "tagline": self.tagline, "beta": self.beta,
                "finding_kinds": _plain(self.finding_kinds), "capabilities": _plain(self.capabilities)}


@dataclass(frozen=True)
class ShieldsSnapshot:
    """Every registered shield paired with its mode, read once (one config read per hook call)."""

    entries: tuple[tuple[Shield, ShieldMode], ...] = ()

    def mode(self, shield_id: str) -> Optional[ShieldMode]:
        """The mode *shield_id* had when the snapshot was taken (None for an unknown id)."""
        return next((mode for shield, mode in self.entries if shield.id == shield_id), None)

    def as_json(self) -> dict[str, JsonValue]:
        return {shield.id: mode.as_json() for shield, mode in self.entries}
