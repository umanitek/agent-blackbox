"""Find an LLM reviewer key the operator already gave Hermes: its model config + a key variable.

The provider and model come from the active Hermes home's config (``hermes_cli.config``).
The key comes ONLY from a variable, read through Hermes (:func:`read_host_secret`): a
variable the config names (``key_env`` …) or the provider's standard one
(``OPENAI_API_KEY``, ``ANTHROPIC_API_KEY`` …). Blackbox never reads a ``.env`` file,
another profile's home, another program's config (OpenClaw), or a key written into
Hermes's config itself — credentials reach a plugin only through Hermes (plugin
catalog rule 11). A key Blackbox cannot find this way is pasted by the operator.

A candidate is ``{"source", "provider", "model", "api_key", "api_key_env"}``;
``api_key_env`` names the variable the key was read from, so ``setup-llm`` saves the
name instead of a copy (KI-371). Used by :mod:`.` (``blackbox setup-llm``).
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from ...kernel import constants, yaml_files
from ...kernel.host_secrets import read_host_secret
from .. import reviewer as llm

#: Standard env var names each provider's key lives in (mirrors hermes auth).
_LLM_KEY_ENV_VARS = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN"),
}

_PROVIDER_ALIASES = {
    "openai": "openai",
    "openai-api": "openai",
    "openai-responses": "openai",
    "openai-chat": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "anthropic-api": "anthropic",
}

_PROVIDER_KEYS = ("provider", "model_provider", "modelProvider", "llm_provider", "llmProvider")
_MODEL_KEYS = ("model", "default", "default_model", "defaultModel", "llm_model", "llmModel")
_API_KEY_ENV_KEYS = ("key_env", "keyEnv", "api_key_env", "apiKeyEnv", "env", "env_var", "envVar")


def _env_key(provider: str) -> tuple[str, str]:
    """(key, variable name): the first of *provider*'s standard key variables Hermes has, or ("", "")."""
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):  # ordered, first wins
        value = read_host_secret(name)
        if value:
            return value, name
    return "", ""


def reachable_key_env(candidate: dict[str, str]) -> str:
    """*candidate*'s variable name when Hermes gives that variable the same key, else "".

    Saving only the name is safe only when the reviewer will find the same key under it
    at run time; otherwise the key was pasted and is saved as itself.
    """
    name = candidate.get("api_key_env", "")
    return name if name and read_host_secret(name) == candidate.get("api_key") else ""


def _provider_alias(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    return _PROVIDER_ALIASES.get(raw, "")


def _value_from(mapping: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        val = mapping.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _key_from_mapping(mapping: dict[str, Any], provider: str) -> tuple[str, str]:
    """(key, variable name) from a variable *mapping* names, else from *provider*'s standard ones."""
    for field_name in _API_KEY_ENV_KEYS:
        name = str(mapping.get(field_name) or "").strip()
        value = read_host_secret(name)
        if value:
            return value, name
    return _env_key(provider)


def _candidate_from_mapping(mapping: dict[str, Any], source: str) -> Optional[dict[str, str]]:
    provider = _provider_alias(_value_from(mapping, _PROVIDER_KEYS))
    if not provider:
        return None
    api_key, api_key_env = _key_from_mapping(mapping, provider)
    if not api_key:
        return None
    model = _value_from(mapping, _MODEL_KEYS) or llm.default_model(provider)
    return {"source": source, "provider": provider, "model": model, "api_key": api_key, "api_key_env": api_key_env}


def _hermes_llm_candidate() -> Optional[dict[str, str]]:
    """The provider/model the active Hermes home uses, with a key Hermes holds for it — or None."""
    try:
        from hermes_cli import config as hconfig

        cfg = hconfig.load_config()
    except Exception:   # Hermes not importable (standalone run): nothing to reuse
        return None
    if not isinstance(cfg, dict):
        return None
    model_cfg = cfg.get("model") if isinstance(cfg.get("model"), dict) else {}
    candidates = [model_cfg, cfg]
    custom = cfg.get("custom_providers") or cfg.get("providers")
    if isinstance(custom, dict):
        candidates.extend(v for v in custom.values() if isinstance(v, dict))
    for mapping in candidates:
        resolved = _candidate_from_mapping(mapping, "Hermes")
        if resolved:
            return resolved
    return None


def stored_llm_entry() -> dict[str, Any]:
    """The ``plugins.entries.blackbox.llm`` mapping as saved in the active Hermes home's config.yaml."""
    llm = yaml_files.blackbox_entry(yaml_files.load_yaml(constants.hermes_home() / "config.yaml")).get("llm")
    return llm if isinstance(llm, dict) else {}


def copied_key_env(provider: str, api_key: str) -> str:
    """The standard variable Hermes holds *api_key* under, or "" (KI-371 clean-up)."""
    names = _LLM_KEY_ENV_VARS.get(provider, ())
    return next((name for name in names if api_key and read_host_secret(name) == api_key), "")
