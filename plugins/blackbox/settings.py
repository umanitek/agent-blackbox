"""Read/write the user-tunable Blackbox detection policy.

The dashboard settings page (gear icon) is the primary consumer. Settings live
under ``plugins.entries.blackbox.*`` in the hermes ``config.yaml`` — the same
place :mod:`config` reads from — so a change here is picked up by every hook on
the next :func:`config.load_blackbox_config`.

Everything is best-effort and validated: :func:`read_settings` always returns a
complete, defaulted view (even with no config file), and :func:`write_settings`
only ever persists known keys with validated values, preserving every unrelated
config key. Writing prefers the hermes config writer (comment/format-preserving)
and falls back to a plain YAML read-modify-write for standalone installs.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from . import constants
from .config import DETECTION_CATEGORIES, load_blackbox_config

logger = logging.getLogger(__name__)

_GEAR_KEYS = ("plugins", "entries", "blackbox")


def read_settings() -> Dict[str, Any]:
    """Return the current settings as a JSON-friendly, fully-defaulted dict."""
    cfg = load_blackbox_config()
    categories = {
        cat: cfg.category_setting(cat) for cat in DETECTION_CATEGORIES
    }
    return {
        "mode": cfg.mode,
        "block_severity": cfg.block_severity,
        "report": cfg.report,
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


def _validate(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Coerce a settings *payload* into a validated ``blackbox`` config subtree.

    Returns ``(entry_updates, errors)``. Unknown keys and invalid values are
    dropped (with an error note) rather than persisted, so a malformed request
    can never corrupt the config.
    """
    errors: List[str] = []
    updates: Dict[str, Any] = {}
    if not isinstance(payload, dict):
        return {}, ["payload must be an object"]

    if "mode" in payload:
        mode = str(payload["mode"]).lower()
        if mode in ("audit", "block"):
            updates["mode"] = mode
        else:
            errors.append(f"invalid mode: {payload['mode']!r}")

    for key in ("block_severity", "report_min_severity"):
        if key in payload:
            val = str(payload[key]).lower()
            if val in constants.SEVERITY_RANK:
                updates[key] = val
            else:
                errors.append(f"invalid {key}: {payload[key]!r}")

    for key in ("discover", "osv_lookup"):
        if key in payload:
            if isinstance(payload[key], bool):
                updates[key] = payload[key]
            else:
                errors.append(f"{key} must be a boolean")

    if "categories" in payload:
        cats = payload["categories"]
        detection: Dict[str, Any] = {}
        if isinstance(cats, dict):
            for cat in DETECTION_CATEGORIES:
                item = cats.get(cat)
                if not isinstance(item, dict):
                    continue
                setting: Dict[str, Any] = {}
                if "enabled" in item:
                    if isinstance(item["enabled"], bool):
                        setting["enabled"] = item["enabled"]
                    else:
                        errors.append(f"{cat}.enabled must be a boolean")
                if "min_severity" in item:
                    ms = str(item["min_severity"]).lower()
                    if ms in constants.SEVERITY_RANK:
                        setting["min_severity"] = ms
                    else:
                        errors.append(f"invalid {cat}.min_severity: {item['min_severity']!r}")
                if setting:
                    detection[cat] = setting
        else:
            errors.append("categories must be an object")
        updates["detection"] = detection

    if "protected_paths" in payload:
        raw = payload["protected_paths"]
        if isinstance(raw, list):
            paths: List[str] = []
            for item in raw:
                text = str(item or "").strip()
                if text and text not in paths:
                    paths.append(text)
            updates["protected_paths"] = paths[:100]
        else:
            errors.append("protected_paths must be a list")

    if "llm" in payload:
        raw = payload["llm"]
        llm: Dict[str, Any] = {}
        if isinstance(raw, dict):
            if "enabled" in raw:
                if isinstance(raw["enabled"], bool):
                    llm["enabled"] = raw["enabled"]
                else:
                    errors.append("llm.enabled must be a boolean")
            if "provider" in raw:
                prov = str(raw["provider"]).strip().lower()
                if prov in ("openai", "anthropic", ""):
                    llm["provider"] = prov
                else:
                    errors.append(f"invalid llm.provider: {raw['provider']!r}")
            if "model" in raw:
                llm["model"] = str(raw["model"]).strip()
            if "api_key" in raw:
                llm["api_key"] = str(raw["api_key"]).strip()
            if llm:
                updates["llm"] = llm
        else:
            errors.append("llm must be an object")

    return updates, errors


def write_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate *payload* and persist it under ``plugins.entries.blackbox``.

    Returns ``{"ok": bool, "errors": [...], "settings": <new read_settings>}``.
    Never raises — a write failure is reported in the result.
    """
    updates, errors = _validate(payload)
    if not updates:
        return {"ok": False, "errors": errors or ["nothing to update"], "settings": read_settings()}

    persisted = _persist(updates)
    if not persisted:
        errors.append("could not persist settings (config not writable)")
    return {"ok": persisted, "errors": errors, "settings": read_settings()}


def _persist(updates: Dict[str, Any]) -> bool:
    """Merge *updates* into the blackbox config entry. Prefer hermes' writer."""
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
        from . import attach

        path = constants.hermes_home() / "config.yaml"
        data = attach._load_yaml(path)
        if not isinstance(data, dict):
            data = {}
        entry = _dig(data, _GEAR_KEYS)
        _apply(entry, updates)
        attach._dump_yaml(path, data)
        return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox.settings: YAML config write failed: %s", exc)
        return False


def _dig(root: Dict[str, Any], keys: Tuple[str, ...]) -> Dict[str, Any]:
    """Return the nested dict at *keys*, creating empty dicts along the way."""
    node = root
    for key in keys:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    return node


def _apply(entry: Dict[str, Any], updates: Dict[str, Any]) -> None:
    """Apply validated *updates* onto the blackbox config *entry* in place.

    ``detection`` and ``llm`` are deep-merged (so setting the model never drops
    the key, and tuning one category never drops another); every other key is a
    straight overwrite.
    """
    for key, value in updates.items():
        if key == "detection" and isinstance(value, dict):
            existing = entry.get("detection")
            if not isinstance(existing, dict):
                existing = {}
                entry["detection"] = existing
            for cat, setting in value.items():
                cur = existing.get(cat)
                if not isinstance(cur, dict):
                    cur = {}
                    existing[cat] = cur
                cur.update(setting)
        elif key == "llm" and isinstance(value, dict):
            existing = entry.get("llm")
            if not isinstance(existing, dict):
                existing = {}
                entry["llm"] = existing
            existing.update(value)
        else:
            entry[key] = value
