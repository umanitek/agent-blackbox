"""Configuration value coercion and local path defaults."""
import os
from pathlib import Path
from typing import Any, Dict
from .. import constants
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    raw = str(value).strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _env_or(entry: Dict[str, Any], *, env: str, key: str, default: Any) -> Any:
    """Resolve a single config value: env var wins, then config entry, then default."""
    env_val = os.environ.get(env)
    if env_val is not None and env_val.strip() != "":
        return env_val.strip()
    if key in entry and entry[key] is not None:
        return entry[key]
    return default


def _first_env(*names: str) -> str:
    """Return the first non-empty environment variable from *names*."""
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return ""


def _default_dkg_url() -> str:
    port = _as_int(os.environ.get("BLACKBOX_DKG_PORT"), constants.DEFAULT_DKG_PORT)
    return f"http://127.0.0.1:{port}"


def _is_default_dkg_home(value: object) -> bool:
    """True when a config entry points at the DKG CLI's shared default home."""
    raw = str(value or "").strip()
    if not raw:
        return False
    try:
        return Path(raw).expanduser().resolve() == (Path.home() / ".dkg").resolve()
    except Exception:
        return Path(raw).expanduser() == Path.home() / ".dkg"

