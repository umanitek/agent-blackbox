"""Blackbox configuration loading.

Config lives under ``plugins.entries.blackbox.*`` in the hermes ``config.yaml``
and is read via :func:`hermes_cli.config.load_config`. Every key has an
environment-variable override that wins over the file (see the table in the
plugin README). Loading always fails open — a missing/broken config file
yields :class:`BlackboxConfig` defaults rather than raising.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from . import constants

#: The detection categories a user can tune individually.
DETECTION_CATEGORIES = ("injection", "escalation", "dependency", "fileaccess", "skill", "secret", "ioc")

logger = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

#: Sensible out-of-the-box protected paths — high-signal credential stores an
#: agent rarely has a legitimate reason to read. Applied only when the config
#: key is absent; an explicit (even empty) ``protected_paths`` list wins.
DEFAULT_PROTECTED_PATHS: Tuple[str, ...] = (
    "~/.ssh/*",          # SSH private keys
    ".env",              # environment files (any directory)
    ".env.*",            # env variants (.env.local, .env.production, ...)
    "*.pem",             # PEM-encoded keys / certificates
    "*.key",             # private key files
    "*.p12",             # PKCS#12 / PFX keystores
    "~/.aws/credentials",  # cloud credential store
)


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


@dataclass(frozen=True)
class BlackboxConfig:
    """Resolved Blackbox settings for the current process."""

    mode: str = "audit"
    context_graph_id: str = constants.DEFAULT_CONTEXT_GRAPH_ID
    graph_peer_id: str = constants.DEFAULT_GRAPH_PEER_ID
    dkg_url: str = constants.DEFAULT_DKG_URL
    dkg_home: str = field(default_factory=lambda: str(constants.blackbox_dkg_home()))
    dkg_bin: str = field(default_factory=lambda: str(constants.blackbox_dkg_bin()))
    sync_interval: int = 3600
    report: bool = False
    daily_report_limit: int = 0
    report_min_severity: str = "high"
    block_severity: str = "critical"
    dashboard_port: int = 9700
    discover: bool = True
    osv_lookup: bool = True
    auto_attach: bool = True
    #: Optional LLM reviewer (opt-in, off by default). When enabled with a key
    #: present, an LLM gives a second opinion on prompt injection over the
    #: observer path. Provider is ``openai`` or ``anthropic``. Config keys:
    #: ``plugins.entries.blackbox.llm.{enabled,provider,model,api_key}``.
    llm_enabled: bool = False
    llm_provider: str = ""
    llm_model: str = ""
    llm_api_key: str = ""
    #: Per-category user policy: ``{category: {"enabled": bool, "min_severity": str}}``.
    #: Missing categories default to enabled at ``info`` (flag everything the
    #: graph knows). Config key: ``plugins.entries.blackbox.detection.*``.
    categories: Mapping[str, Any] = field(default_factory=dict)
    #: User-defined protected path patterns (globs / prefixes). Access to a
    #: matching path is flagged locally (source="custom", never shared to SWM)
    #: and blocks in block mode. Config key: ``protected_paths``. Defaults to
    #: :data:`DEFAULT_PROTECTED_PATHS` when the key is absent.
    protected_paths: Tuple[str, ...] = DEFAULT_PROTECTED_PATHS

    @property
    def block_enabled(self) -> bool:
        """True when the plugin is allowed to block tool calls."""
        return self.mode.lower() == "block"

    @property
    def llm_ready(self) -> bool:
        """True when the optional LLM reviewer is enabled and fully configured."""
        return bool(
            self.llm_enabled
            and self.llm_provider in ("openai", "anthropic")
            and self.llm_model
            and self.llm_api_key
        )

    def meets_block_threshold(self, severity: str) -> bool:
        """True when *severity* is at or above the configured block threshold."""
        rank = constants.SEVERITY_RANK
        floor = rank.get(self.block_severity.lower(), rank["critical"])
        return rank.get((severity or "").lower(), -1) >= floor

    def meets_report_threshold(self, severity: str) -> bool:
        """True when a heuristic candidate at *severity* is worth flagging.

        Graph-backed findings (public or community) are always flagged; this
        threshold only gates the built-in discovery heuristics so low-signal
        candidates don't drown the findings feed and the community graph.
        """
        rank = constants.SEVERITY_RANK
        floor = rank.get(self.report_min_severity.lower(), rank["high"])
        return rank.get((severity or "").lower(), -1) >= floor

    def category_setting(self, category: str) -> Dict[str, Any]:
        """Resolved user policy for one category: ``{"enabled", "min_severity"}``.

        Defaults: enabled at ``info`` — flag everything Blackbox can detect for
        that category. A user who only cares about e.g. critical dependency
        vulns sets ``detection.dependency.min_severity: critical``.
        """
        raw = self.categories.get(category) if isinstance(self.categories, Mapping) else None
        raw = raw if isinstance(raw, Mapping) else {}
        min_sev = str(raw.get("min_severity") or "info").lower()
        if min_sev not in constants.SEVERITY_RANK:
            min_sev = "info"
        enabled = raw.get("enabled")
        return {
            "enabled": bool(enabled) if isinstance(enabled, bool) else True,
            "min_severity": min_sev,
        }

    def category_allows(self, category: str, severity: str) -> bool:
        """True when the user's policy lets a *category* finding at *severity* flag."""
        setting = self.category_setting(category)
        if not setting["enabled"]:
            return False
        rank = constants.SEVERITY_RANK
        floor = rank[setting["min_severity"]]
        return rank.get((severity or "").lower(), -1) >= floor


def _blackbox_entry() -> Dict[str, Any]:
    """Return the ``plugins.entries.blackbox`` mapping, or ``{}`` on any error."""
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("blackbox: config load failed (%s); using defaults", exc)
        return {}
    entries = ((cfg.get("plugins") or {}).get("entries") or {})
    entry = entries.get("blackbox") or {}
    return entry if isinstance(entry, dict) else {}


def load_blackbox_config() -> BlackboxConfig:
    """Build a :class:`BlackboxConfig` from config file + environment overrides."""
    entry = _blackbox_entry()
    mode = str(_env_or(entry, env="BLACKBOX_MODE", key="mode", default="audit")).lower()
    if mode not in {"audit", "block"}:
        mode = "audit"
    block_severity = str(
        _env_or(entry, env="BLACKBOX_BLOCK_SEVERITY", key="block_severity", default="critical")
    ).lower()
    if block_severity not in constants.SEVERITY_RANK:
        block_severity = "critical"
    report_min_severity = str(
        _env_or(
            entry,
            env="BLACKBOX_REPORT_MIN_SEVERITY",
            key="report_min_severity",
            default="high",
        )
    ).lower()
    if report_min_severity not in constants.SEVERITY_RANK:
        report_min_severity = "high"
    categories = _normalize_categories(entry.get("detection"))
    protected_paths = _normalize_protected_paths(entry.get("protected_paths"))
    llm_entry = entry.get("llm") if isinstance(entry.get("llm"), dict) else {}
    llm_provider = str(
        _env_or(llm_entry, env="BLACKBOX_LLM_PROVIDER", key="provider", default="")
    ).strip().lower()
    if llm_provider not in ("openai", "anthropic", ""):
        llm_provider = ""
    llm_model = str(_env_or(llm_entry, env="BLACKBOX_LLM_MODEL", key="model", default="")).strip()
    llm_api_key = str(_env_or(llm_entry, env="BLACKBOX_LLM_API_KEY", key="api_key", default="")).strip()
    llm_enabled = _as_bool(
        _env_or(llm_entry, env="BLACKBOX_LLM_ENABLED", key="enabled", default=False), False
    )
    context_graph_id = str(
        _env_or(
            entry,
            env="BLACKBOX_CONTEXT_GRAPH_ID",
            key="context_graph_id",
            default=constants.DEFAULT_CONTEXT_GRAPH_ID,
        )
    )
    # Auto-switch an install still pointed at a legacy (pre-Blackbox) graph to the
    # current default, so an existing DKG user syncs the correct CG with no manual
    # step. A genuinely custom graph id is not in the legacy set and is untouched.
    if context_graph_id in constants.LEGACY_CONTEXT_GRAPH_IDS:
        logger.info(
            "blackbox: switching legacy context_graph_id %s -> %s",
            context_graph_id,
            constants.DEFAULT_CONTEXT_GRAPH_ID,
        )
        context_graph_id = constants.DEFAULT_CONTEXT_GRAPH_ID
    default_dkg_home = str(constants.blackbox_dkg_home())
    dkg_home_env = _first_env("BLACKBOX_DKG_HOME")
    configured_dkg_home = entry.get("dkg_home") or entry.get("dkgHome")
    configured_dkg_url = entry.get("dkg_url") or entry.get("dkgUrl")
    if _is_default_dkg_home(configured_dkg_home):
        logger.info(
            "blackbox: switching shared default dkg_home %s -> %s",
            configured_dkg_home,
            default_dkg_home,
        )
        configured_dkg_home = ""
    dkg_home = str(
        configured_dkg_home
        or dkg_home_env
        or default_dkg_home
    ).strip()
    dkg_bin = str(
        entry.get("dkg_bin")
        or entry.get("dkgBin")
        or _first_env("BLACKBOX_DKG_BIN")
        or constants.blackbox_dkg_bin()
    ).strip()
    dkg_url_env = _first_env("BLACKBOX_DKG_DAEMON_URL", "BLACKBOX_DKG_URL")
    dkg_url = str(
        configured_dkg_url
        or dkg_url_env
        or _default_dkg_url()
    ).rstrip("/")
    legacy_dkg_urls = {"http://127.0.0.1:9200", "http://localhost:9200"}
    has_configured_dkg_home = bool(configured_dkg_home)
    if not has_configured_dkg_home and dkg_url in legacy_dkg_urls:
        dkg_url = _default_dkg_url()
    graph_peer_id = str(
        _env_or(
            entry,
            env="BLACKBOX_GRAPH_PEER_ID",
            key="graph_peer_id",
            default=constants.DEFAULT_GRAPH_PEER_ID,
        )
    ).strip()
    # Replace bootstrap peers from previous releases; custom peers are untouched.
    if graph_peer_id in constants.LEGACY_GRAPH_PEER_IDS:
        logger.info(
            "blackbox: switching stale graph_peer_id %s -> %s",
            graph_peer_id,
            constants.DEFAULT_GRAPH_PEER_ID,
        )
        graph_peer_id = constants.DEFAULT_GRAPH_PEER_ID
    return BlackboxConfig(
        mode=mode,
        context_graph_id=context_graph_id,
        graph_peer_id=graph_peer_id,
        dkg_url=dkg_url,
        dkg_home=dkg_home,
        dkg_bin=dkg_bin,
        sync_interval=max(
            3600,
            _as_int(
                _env_or(
                    entry,
                    env="BLACKBOX_SYNC_INTERVAL",
                    key="sync_interval",
                    default=3600,
                ),
                3600,
            ),
        ),
        # Threat sharing ships with the future community graph. This is not a
        # user-toggleable path in the VM-only release.
        report=False,
        daily_report_limit=0,
        report_min_severity=report_min_severity,
        block_severity=block_severity,
        dashboard_port=_as_int(
            _env_or(entry, env="BLACKBOX_DASHBOARD_PORT", key="dashboard_port", default=9700), 9700
        ),
        discover=_as_bool(_env_or(entry, env="BLACKBOX_DISCOVER", key="discover", default=True), True),
        osv_lookup=_as_bool(
            _env_or(entry, env="BLACKBOX_OSV_LOOKUP", key="osv_lookup", default=True), True
        ),
        auto_attach=_as_bool(
            _env_or(entry, env="BLACKBOX_AUTO_ATTACH", key="auto_attach", default=True), True
        ),
        categories=categories,
        protected_paths=protected_paths,
        llm_enabled=llm_enabled,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
    )


def _normalize_categories(raw: Any) -> Dict[str, Dict[str, Any]]:
    """Validate the ``detection`` config mapping into per-category policy dicts."""
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    for category in DETECTION_CATEGORIES:
        item = raw.get(category)
        if not isinstance(item, dict):
            continue
        setting: Dict[str, Any] = {}
        if isinstance(item.get("enabled"), bool):
            setting["enabled"] = item["enabled"]
        min_sev = str(item.get("min_severity") or "").lower()
        if min_sev in constants.SEVERITY_RANK:
            setting["min_severity"] = min_sev
        if setting:
            out[category] = setting
    return out


def _normalize_protected_paths(raw: Any) -> Tuple[str, ...]:
    """Validate ``protected_paths`` into a tuple of non-empty pattern strings.

    A missing key (``None``) falls back to :data:`DEFAULT_PROTECTED_PATHS`; an
    explicit list — including an empty one — is honoured verbatim so a user who
    clears the list keeps it cleared.
    """
    if raw is None:
        return DEFAULT_PROTECTED_PATHS
    if not isinstance(raw, (list, tuple)):
        return ()
    out = []
    for item in raw:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return tuple(out[:100])
