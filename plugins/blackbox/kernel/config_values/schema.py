"""What a Blackbox setting may hold — one schema, used when config is READ and when it is SAVED.

WHY one place: reading config.yaml (``kernel.config``) and saving a dashboard edit
(``kernel.settings``) each carried their own lists of valid modes, providers,
categories and path rules; a value added to one side was silently dropped by the
other. Both now ask this module. The difference between them stays where it
belongs: reading falls back to a default for a bad value, saving refuses it.

Usage::

    mode = choice(Mode, raw) or Mode.AUDIT.value            # reading: default
    if (mode := choice(Mode, raw)) is None: errors.append(…)   # saving: refuse
    detection = category_settings(raw)                      # reading: bad fields skipped
    detection = category_settings(raw, errors)              # saving: bad fields reported
    paths = path_list(items)                                # trimmed, no repeats, order kept

Values are plain lowercase text everywhere else in the plugin (``cfg.mode == "block"``);
the enums are ``StrEnum`` so a member compares equal to its text.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Iterable, Optional

from .. import constants


class Mode(StrEnum):
    """What a finding does: record it (audit) or stop the call (block)."""

    AUDIT = "audit"
    BLOCK = "block"


class Provider(StrEnum):
    """Who answers the optional second-opinion reviewer."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class DetectionBackend(StrEnum):
    """Where graph rules are read from: the compiled local file, or the node's store per call."""

    LEGACY_CACHE = "legacy-cache"
    DKG = "dkg"


#: The detection categories a user can tune individually.
DETECTION_CATEGORIES = ("injection", "escalation", "dependency", "fileaccess", "skill", "secret", "ioc")
#: Most protected paths a config may list (each is matched on every file-access call).
MAX_PROTECTED_PATHS = 100


def choice(kind: type[StrEnum], raw: Any) -> Optional[str]:
    """*raw* as one of *kind*'s values (trimmed, lowercased), or None when it is not one."""
    text = str(raw).strip().lower()
    return text if text in kind._value2member_map_ else None


def severity(raw: Any) -> Optional[str]:
    """*raw* as a severity name from the kernel's ladder, or None."""
    text = str(raw).strip().lower()
    return text if text in constants.SEVERITY_RANK else None


def category_settings(raw: Any, errors: Optional[list[str]] = None) -> dict[str, dict[str, Any]]:
    """The valid per-category policy in *raw*: ``{category: {"enabled": bool, "min_severity": name}}``.

    Unknown categories and non-mapping items are skipped. A known field with a bad
    value is skipped too, and named in *errors* when a list is given (saving)."""
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    for category in DETECTION_CATEGORIES:
        item = raw.get(category)
        if not isinstance(item, dict):
            continue
        setting: dict[str, Any] = {}
        if isinstance(item.get("enabled"), bool):
            setting["enabled"] = item["enabled"]
        elif "enabled" in item and errors is not None:
            errors.append(f"{category}.enabled must be a boolean")
        minimum = severity(item.get("min_severity"))
        if minimum:
            setting["min_severity"] = minimum
        elif "min_severity" in item and errors is not None:
            errors.append(f"invalid {category}.min_severity: {item['min_severity']!r}")
        if setting:
            out[category] = setting
    return out


def path_list(raw: Iterable[Any]) -> list[str]:
    """*raw* as trimmed, non-empty path patterns without repeats, in the order given."""
    out: list[str] = []
    for item in raw:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return out
