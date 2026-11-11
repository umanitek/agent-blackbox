"""Read/write the user-tunable Blackbox detection policy.

The dashboard settings page (gear icon) is the primary consumer. Settings live
under ``plugins.entries.blackbox.*`` in the hermes ``config.yaml`` — the same
place :mod:`config` reads from — so a change here is picked up by every hook on
the next :func:`config.load_blackbox_config`.

Everything is best-effort and validated: :func:`read_settings` always returns a
complete, defaulted view (even with no config file), and :func:`write_settings`
only ever persists known keys with validated values, preserving every unrelated
config key. A save is all-or-nothing (KI-389): one invalid value and NOTHING is
persisted — a half-applied save once turned wallet protection off while reporting
an error about an unrelated field. Writing prefers the hermes config writer (comment/format-preserving)
and falls back to a plain YAML read-modify-write for standalone installs.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable, NamedTuple

from . import constants
from . import yaml_files
from .config import load_blackbox_config
from .config_values import schema
from .config_values.schema import DETECTION_CATEGORIES, MAX_PROTECTED_PATHS

logger = logging.getLogger(__name__)

_GEAR_KEYS = yaml_files.BLACKBOX_ENTRY_PATH


class ShieldSettings(NamedTuple):
    """What one shield's settings validator answers for a settings payload.

    *section* is the shield's validated fields (empty = the payload does not touch
    this shield); the kernel stores it at ``shields.<shield_id>``, merged field by
    field. *supersedes* names top-level entry keys the section replaces; they are
    deleted in the same write, and only when the section is written. A validator may
    return a plain ``(shield_id, section, errors)`` tuple instead.
    """

    shield_id: str
    section: dict[str, Any]
    errors: list[str]
    supersedes: tuple[str, ...] = ()


#: A shield's settings validator: ``validator(payload) -> ShieldSettings``. The caller
#: hands these in (dependency injection) so the kernel never imports a shield.
SettingsValidator = Callable[[dict[str, Any]], tuple[Any, ...]]

#: Marks a superseded key in the updates for :func:`_apply` to delete.
_SUPERSEDED = object()


def read_settings() -> dict[str, Any]:
    """Return the current settings as a JSON-friendly, fully-defaulted dict."""
    cfg = load_blackbox_config()
    categories = {
        cat: cfg.category_setting(cat) for cat in DETECTION_CATEGORIES
    }
    return {
        "mode": cfg.mode,
        "block_severity": cfg.block_severity,
        "report": cfg.report,
        "community_sandbox": cfg.community_sandbox,
        "report_min_severity": cfg.report_min_severity,
        "discover": cfg.discover,
        "osv_lookup": cfg.osv_lookup,
        "categories": categories,
        "protected_paths": list(cfg.protected_paths),
        "llm": {
            "enabled": cfg.llm_enabled,
            "provider": cfg.llm_provider,
            "model": cfg.llm_model,
            # Never expose the raw key; report only whether one is set.
            "has_key": bool(cfg.llm_api_key),
        },
        "severity_order": list(constants.SEVERITY_ORDER),
        "category_labels": {
            "injection": "Prompt injection",
            "escalation": "Dangerous commands",
            "dependency": "Vulnerable dependencies",
            "fileaccess": "Sensitive file access",
            "skill": "Suspicious skills",
            "secret": "Secret exposure",
            "ioc": "Malicious indicators",
        },
    }


def _validate(payload: dict[str, Any], *, sharing_consent: bool = False) -> tuple[dict[str, Any], list[str]]:
    """Coerce a settings *payload* into a validated ``blackbox`` config subtree.

    Returns ``(entry_updates, errors)``. Unknown keys are ignored; an invalid value
    is an error (and :func:`write_settings` then persists nothing), so a malformed
    request can never corrupt the config. *sharing_consent* (R13, injected by the caller —
    the kernel never asks a feature): without it ``report: true`` is refused.
    """
    errors: list[str] = []
    updates: dict[str, Any] = {}
    if not isinstance(payload, dict):
        return {}, ["payload must be an object"]

    if "mode" in payload:
        mode = schema.choice(schema.Mode, payload["mode"])
        (updates.__setitem__("mode", mode) if mode else errors.append(f"invalid mode: {payload['mode']!r}"))

    for key in ("block_severity", "report_min_severity"):
        if key in payload:
            val = schema.severity(payload[key])
            if val:
                updates[key] = val
            else:
                errors.append(f"invalid {key}: {payload[key]!r}")

    for key in ("discover", "osv_lookup", "report", "community_sandbox"):
        # `report` (KI-005): the community-sharing switch is a real settings
        # key now — validate-then-persist like every other boolean.
        if key in payload:
            if not isinstance(payload[key], bool):
                errors.append(f"{key} must be a boolean")
            elif key == "report" and payload[key] and not sharing_consent:
                errors.append("report: could not record turning community sharing on — check that the Blackbox home is writable")
            else:
                updates[key] = payload[key]

    if "categories" in payload:
        if not isinstance(payload["categories"], dict):
            errors.append("categories must be an object")
        updates["detection"] = schema.category_settings(payload["categories"], errors)

    if "protected_paths" in payload:
        raw = payload["protected_paths"]
        if isinstance(raw, list) and len(raw) <= MAX_PROTECTED_PATHS:
            updates["protected_paths"] = schema.path_list(raw)
        else:
            errors.append(f"protected_paths must be a list of up to {MAX_PROTECTED_PATHS} paths")

    if "llm" in payload:
        llm = _validate_llm(payload["llm"], errors)
        if llm:
            updates["llm"] = llm

    return updates, errors


def _validate_llm(raw: Any, errors: list[str]) -> dict[str, Any]:
    """The valid ``llm`` reviewer fields of *raw*; each problem is appended to *errors*.

    The key is stored ONE way (KI-371): ``api_key_env`` (the name of the variable that
    holds it, e.g. ``OPENAI_API_KEY`` from ~/.hermes/.env) or ``api_key`` (a key typed
    in). Saving one clears the other — ``None`` here means "remove it" (see :func:`_apply`).
    """
    llm: dict[str, Any] = {}
    if not isinstance(raw, dict):
        errors.append("llm must be an object")
        return llm
    if "enabled" in raw:
        if isinstance(raw["enabled"], bool):
            llm["enabled"] = raw["enabled"]
        else:
            errors.append("llm.enabled must be a boolean")
    if "provider" in raw:
        prov = str(raw["provider"]).strip().lower()
        if prov == "" or schema.choice(schema.Provider, prov):
            llm["provider"] = prov
        else:
            errors.append(f"invalid llm.provider: {raw['provider']!r}")
    if "model" in raw:
        llm["model"] = str(raw["model"]).strip()
    if "api_key" in raw:
        llm["api_key"] = str(raw["api_key"]).strip()
        llm["api_key_env"] = None
    if raw.get("api_key_env"):
        name = str(raw["api_key_env"]).strip()
        if name.isascii() and name.isidentifier():
            llm["api_key_env"] = name
            llm["api_key"] = None
        else:
            errors.append(f"invalid llm.api_key_env: {raw['api_key_env']!r}")
    return llm


def write_settings(payload: dict[str, Any], *, sharing_consent: bool = False,
                   validators: Iterable[SettingsValidator] = ()) -> dict[str, Any]:
    """Validate *payload* and persist it under ``plugins.entries.blackbox``.

    Returns ``{"ok": bool, "errors": [...], "settings": <new read_settings>}``.
    All-or-nothing: with any error nothing is persisted and ``ok`` is False (the
    dashboard answers 400). Never raises — a write failure is reported in the result.
    Each of *validators* (see :class:`ShieldSettings`) checks its own shield's section;
    without one, a ``shields`` key in *payload* is dropped, never written (fail-closed).
    """
    updates, errors = _validate(payload, sharing_consent=sharing_consent)
    shield_updates, shield_errors = _shield_updates(payload, validators)
    updates.update(shield_updates)
    errors.extend(shield_errors)
    if errors:
        return {"ok": False, "errors": errors, "settings": read_settings()}
    if not updates:
        return {"ok": False, "errors": errors or ["nothing to update"], "settings": read_settings()}

    persisted = _persist(updates)
    if not persisted:
        errors.append("could not persist settings (config not writable)")
    return {"ok": persisted, "errors": errors, "settings": read_settings()}


def _shield_updates(payload: dict[str, Any],
                    validators: Iterable[SettingsValidator]) -> tuple[dict[str, Any], list[str]]:
    """``(updates, errors)`` from running each handed-in shield validator on *payload*.

    The kernel composes ``{"shields": {shield_id: section}}`` itself, so validators can
    never overwrite each other, and marks each superseded key for deletion. A validator
    that raises or answers malformed is an error (the save then writes nothing).
    """
    updates: dict[str, Any] = {}
    sections: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for validator in validators:
        try:
            result = ShieldSettings(*validator(payload))
        except Exception as exc:   # a broken shield must fail the save, never the dashboard
            logger.warning("blackbox.settings: a shield settings validator failed (%s)", type(exc).__name__)
            errors.append("shield settings could not be checked")
            continue
        if not _is_error_list(result.errors):   # never extend by None, nor a str letter by letter
            errors.append(f"invalid shield settings from {result.shield_id!r}")
            continue
        errors.extend(result.errors)
        if not result.section:
            continue
        if not _well_formed(result) or result.shield_id in sections:
            errors.append(f"invalid shield settings from {result.shield_id!r}")
            continue
        sections[result.shield_id] = dict(result.section)
        updates.update(dict.fromkeys(result.supersedes, _SUPERSEDED))
    if sections:
        updates["shields"] = sections
    return updates, errors


def _well_formed(result: ShieldSettings) -> bool:
    """True when *result* has a named shield, a dict section and string superseded keys."""
    return (isinstance(result.shield_id, str) and bool(result.shield_id)
            and isinstance(result.section, dict) and isinstance(result.supersedes, (tuple, list))
            and all(isinstance(key, str) and key != "shields" for key in result.supersedes))


def _is_error_list(errors: Any) -> bool:
    """True when *errors* is a list or tuple of strings (what the dashboard shows)."""
    return isinstance(errors, (list, tuple)) and all(isinstance(error, str) for error in errors)


@yaml_files.edits_config
def _persist(updates: dict[str, Any]) -> bool:
    """Merge *updates* into the blackbox config entry. Prefer hermes' writer.

    Held under the kernel's one config-edit lock (``yaml_files.edits_config``) so
    concurrent saves, and a save beside an attach, can never lose updates (KI-030);
    both writers end in atomic tmp+rename inside their respective helpers.
    """
    return _persist_locked(updates)


@yaml_files.edits_config   # also for a direct caller; the lock is re-entrant
def _persist_locked(updates: dict[str, Any]) -> bool:
    try:
        from hermes_cli import config as hconfig

        raw = hconfig.read_raw_config()
        if not isinstance(raw, dict):
            raw = {}
        entry = _dig(raw, _GEAR_KEYS)
        _apply(entry, updates)
        hconfig.save_config(raw, strip_defaults=False, preserve_keys={_GEAR_KEYS})
        return True
    except Exception as exc:
        logger.debug("blackbox.settings: hermes config write failed (%s); trying YAML", exc)

    # Standalone fallback: plain YAML read-modify-write of the active home.
    try:
        path = constants.hermes_home() / "config.yaml"
        data = yaml_files.load_for_edit(path)   # unreadable: the save fails, the file stays
        entry = _dig(data, _GEAR_KEYS)
        _apply(entry, updates)
        yaml_files.dump_yaml(path, data)
        return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox.settings: YAML config write failed: %s", exc)
        return False


def _dig(root: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Return the nested dict at *keys*, creating empty dicts along the way."""
    node = root
    for key in keys:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    return node


def _apply(entry: dict[str, Any], updates: dict[str, Any]) -> None:
    """Apply validated *updates* onto the blackbox config *entry* in place.

    ``detection``, ``shields`` and ``llm`` are deep-merged (so setting the model never
    drops the key, tuning one category never drops another, and saving one shield never
    touches another's section); a key marked superseded is deleted; every other key is
    a straight overwrite.
    """
    for key, value in updates.items():
        if value is _SUPERSEDED:
            entry.pop(key, None)
        elif key in ("detection", "shields") and isinstance(value, dict):
            _merge_per_id(entry, key, value)
        elif key == "llm" and isinstance(value, dict):
            existing = entry.get("llm")
            if not isinstance(existing, dict):
                existing = {}
                entry["llm"] = existing
            existing.update(value)
            for cleared in [name for name, setting in value.items() if setting is None]:
                existing.pop(cleared, None)   # KI-371: a replaced key copy is removed, not left behind
        else:
            entry[key] = value


def _merge_per_id(entry: dict[str, Any], key: str, sections: dict[str, dict[str, Any]]) -> None:
    """Merge each ``{id: section}`` of *sections* into ``entry[key][id]`` field by field.

    Never wholesale: an id absent from *sections* keeps its stored section untouched,
    and a field absent from a section keeps its stored value.
    """
    existing = entry.get(key)
    if not isinstance(existing, dict):
        existing = {}
        entry[key] = existing
    for section_id, section in sections.items():
        current = existing.get(section_id)
        if not isinstance(current, dict):
            current = {}
            existing[section_id] = current
        current.update(section)
