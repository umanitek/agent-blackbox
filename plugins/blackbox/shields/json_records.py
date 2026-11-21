"""How every shield record becomes plain JSON (moved out of ``contract.py`` unchanged).

Every record of the shields contract answers ``as_json()`` through :func:`_record_json`, so the
dashboard only ever receives plain JSON values (:data:`JsonValue`).
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from typing import Any, Mapping

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
