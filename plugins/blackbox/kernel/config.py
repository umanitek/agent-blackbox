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
from pathlib import Path
from contextlib import contextmanager
from contextvars import ContextVar
from .snapshot_config import SnapshotSyncConfig, snapshot_fields

from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Optional

from . import constants, yaml_files
from .config_values import saved_entry, schema
from .config_values.semantic import SemanticConfig, semantic_config
from .host_secrets import read_host_secret

#: Re-exported: callers read the category list from here.
DETECTION_CATEGORIES = schema.DETECTION_CATEGORIES

logger = logging.getLogger(__name__)

_DASHBOARD_PORT = constants.DEFAULT_DASHBOARD_PORT

#: Sensible out-of-the-box protected paths — high-signal credential stores an agent rarely has a
#: legitimate reason to read. Applied only when the config key is absent; an explicit (even empty) list wins.
DEFAULT_PROTECTED_PATHS: tuple[str, ...] = (
    "~/.ssh/*",          # SSH private keys
    ".env",              # environment files (any directory)
    ".env.*",            # env variants (.env.local, .env.production, ...)
    "*.pem",             # PEM-encoded keys / certificates
    "*.key",             # private key files
    "*.p12",             # PKCS#12 / PFX keystores
    "~/.aws/credentials",  # cloud credential store
    "~/.hermes/blackbox/*",   # Blackbox's own state: overrides, allowlist, consent, ledgers (review round 4)
    "~/.hermes/plugins/blackbox/*",   # the plugin code itself
)


from .config_values import (_as_bool, _as_int, _as_float, _env_or, _first_env,
                            _default_dkg_url, _is_default_dkg_home, _fallback_mode)

@dataclass(frozen=True)
class BlackboxConfig:
    """Resolved Blackbox settings for the current process."""

    mode: str = schema.Mode.AUDIT.value
    #: Opt in to "dkg" after upgrading the local query capability.
    #: Existing and older-daemon installs retain their explicitly named legacy mode.
    detection_backend: str = schema.DetectionBackend.LEGACY_CACHE.value
    snapshot_sync: SnapshotSyncConfig | None = None
    snapshot_sync_error: str = ""   # why the saved block was set aside; sync refuses while set (KI-490)
    semantic: SemanticConfig = field(default_factory=SemanticConfig)
    context_graph_id: str = constants.DEFAULT_CONTEXT_GRAPH_ID
    graph_peer_id: str = constants.DEFAULT_GRAPH_PEER_ID
    dkg_url: str = constants.DEFAULT_DKG_URL
    dkg_home: str = field(default_factory=lambda: str(constants.blackbox_dkg_home()))
    dkg_bin: str = field(default_factory=lambda: str(constants.blackbox_dkg_bin()))
    sync_interval: int = 3600
    report: bool = False   # community sharing is opt-in (2026-10-16); a consent record is also needed
    daily_report_limit: int = constants.DEFAULT_DAILY_REPORT_LIMIT
    report_min_severity: str = "high"
    #: Seconds between community-pulse probes (R16); 0 disables the pulse.
    community_poll_interval: int = 20
    #: Days per keep-alive epoch (R5): this node re-publishes a copy of each of
    #: its live reports once per epoch (TTL/3 of the default 30-day expiry); 0 = off.
    community_keepalive_epoch_days: float = 10.0
    #: R15 shadow phase: community stages are computed and logged, but every
    #: community rule is clamped to MONITOR — nothing community-derived reaches an agent.
    community_shadow: bool = False
    #: Sandbox mode (2026-10-21): shares go to the ``sandbox`` lane, which nothing that builds rules or flags reads.
    community_sandbox: bool = False
    #: Owner node only: approve every pending join request on the pulse (sync allowlist, never publish).
    community_auto_approve: bool = False
    #: DKG-lookup B9: ``off`` (default: a failed lookup is could-not-tell + an alarm) | ``index`` (opt-in on-disk SQLite last resort).
    verified_lookup_fallback: str = "off"
    block_severity: str = "critical"
    dashboard_port: int = _DASHBOARD_PORT
    discover: bool = True
    osv_lookup: bool = True
    auto_attach: bool = False   # opt-in: each Hermes profile is its own trust boundary (attach.automatic_targets)
    #: Optional LLM reviewer (opt-in, off by default): an LLM gives a second opinion on prompt
    #: injection over the observer path. Provider ``openai`` or ``anthropic``. Config keys:
    #: ``plugins.entries.blackbox.llm.{enabled,provider,model,api_key_env|api_key}`` — ``api_key_env``
    #: names the variable holding the key (KI-371: Hermes loads ~/.hermes/.env), so no copy is kept.
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
    protected_paths: tuple[str, ...] = DEFAULT_PROTECTED_PATHS

    @property
    def block_enabled(self) -> bool:
        """True when the plugin is allowed to block tool calls."""
        return self.mode.lower() == schema.Mode.BLOCK

    @property
    def community_enabled(self) -> bool:
        """True when outbound community sharing may run — THE single gate.

        Every community write path checks this one expression (no scattered
        gate logic): the build must ship the capability
        (:data:`constants.COMMUNITY_GRAPH_ENABLED`), the operator must have
        sharing on (``report``), and a graph address must exist (empty keeps
        the feature dormant by construction, KI-035).
        """
        return bool(
            constants.COMMUNITY_GRAPH_ENABLED
            and self.report
            and self.context_graph_id.strip()
        )

    @property
    def llm_ready(self) -> bool:
        """True when the optional LLM reviewer is enabled and fully configured."""
        return bool(
            self.llm_enabled
            and schema.choice(schema.Provider, self.llm_provider) is not None
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

    def category_setting(self, category: str) -> dict[str, Any]:
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


def _blackbox_entry() -> dict[str, Any]:
    """Return the ``plugins.entries.blackbox`` mapping (:mod:`.config_values.saved_entry`: the last
    good one while the file cannot be read; empty before any good read)."""
    return saved_entry.read()


#: What a status route says for the mode before the saved settings were ever read in this process.
MODE_STARTING = "starting"


def mode_answer(cfg: BlackboxConfig) -> str:
    """*cfg*'s mode for a status answer — or :data:`MODE_STARTING` while the saved settings could
    not be read yet (never the default presented as the person's choice, KI-PENDING-b28f8f)."""
    return cfg.mode if saved_entry.known(_blackbox_entry()) else MODE_STARTING


#: The separate community graph's settings (2026-10-12 to 2026-10-16), config keys and environment
#: variables: ignored since there is one graph, and said so once per process.
_RETIRED_COMMUNITY_SETTINGS = frozenset({"community_graph_id", "community_graph_peer_id",
                                         "BLACKBOX_COMMUNITY_GRAPH_ID", "BLACKBOX_COMMUNITY_GRAPH_PEER_ID"})
_retired_settings_noted: set[str] = set()


def _note_retired_community_settings(entry: Mapping[str, Any]) -> None:
    for name in _RETIRED_COMMUNITY_SETTINGS - _retired_settings_noted:
        if str(entry.get(name) or os.environ.get(name) or "").strip():
            _retired_settings_noted.add(name)
            logger.info("blackbox: %s is ignored: community reports live in the verified graph now", name)


def reads_graph_directly(cfg: Any) -> bool:
    """True when *cfg* selects the per-call graph backend (``detection_backend: dkg``): rules are
    read from the node's store for each call instead of the compiled local file. Accepts any
    object; one without the field (a partial config in a test) means the compiled file."""
    return getattr(cfg, "detection_backend", schema.DetectionBackend.LEGACY_CACHE) == schema.DetectionBackend.DKG


def _configured_dkg_home(entry: Mapping[str, Any]) -> str:
    """The ``dkg_home`` the person's config names, or "" (a legacy shared default counts as none)."""
    configured = str(entry.get("dkg_home") or entry.get("dkgHome") or "").strip()
    if _is_default_dkg_home(configured):
        logger.info("blackbox: switching shared default dkg_home %s -> %s", configured, constants.blackbox_dkg_home())
        return ""
    return configured


def _resolve_dkg_home(entry: Mapping[str, Any]) -> str:
    """Blackbox's DKG node home: the config's ``dkg_home``, else ``BLACKBOX_DKG_HOME``, else the default."""
    return str(_configured_dkg_home(entry) or _first_env("BLACKBOX_DKG_HOME") or constants.blackbox_dkg_home()).strip()


def dkg_home() -> Path:
    """Where THIS install's DKG node keeps its state (``daemon.pid``, ``config.json``, the store).

    Cheap — reads only the Blackbox config entry, never credentials — so a page can ask on every
    read. Use this, not :func:`constants.blackbox_dkg_home`: the installer puts the node beside the
    install (``<install root>/.dkg``) and records it as ``dkg_home``; the constant is only the
    fallback when nothing was recorded (E2E recheck 2026-11-21: the node's own port was rated high
    because its pid file was looked for in the fallback folder).
    """
    return Path(_resolve_dkg_home(_blackbox_entry())).expanduser()


def raw_section(name: str) -> dict[str, Any]:
    """The saved Blackbox config section *name* as written ({} when absent or not a mapping), for
    a package that owns and parses its own section (``notify.policy``)."""
    section = _blackbox_entry().get(name)
    return dict(section) if isinstance(section, dict) else {}


#: The longest quiet limit an agent instance may be given (a day).
QUIET_MINUTES_MAX = 1440


@dataclass(frozen=True)
class AgentActivity:
    """The agent history's settings (``agent_activity.*`` in config.yaml): how many days an
    ended agent instance stays in the history, whether the TEXT of prompts is kept in it (off by
    default — a privacy choice the person confirms), and after how many quiet minutes an
    instance with no process to follow counts as ended."""

    history_days: int = 30
    record_prompt_text: bool = False
    quiet_minutes: int = 30


def agent_activity(entry: Mapping[str, Any] | None = None) -> AgentActivity:
    """The saved (or a proposed *entry*'s) agent-activity settings. Cheap, like :func:`dkg_home`:
    it reads only the Blackbox config entry."""
    section = (_blackbox_entry() if entry is None else entry).get("agent_activity")
    section = section if isinstance(section, dict) else {}
    return AgentActivity(history_days=min(365, max(1, _as_int(section.get("history_days", 30), 30))),
                         record_prompt_text=_as_bool(section.get("record_prompt_text", False), False),
                         quiet_minutes=min(QUIET_MINUTES_MAX, max(1, _as_int(section.get("quiet_minutes", 30), 30))))


def load_blackbox_config(*, entry: dict[str, Any] | None = None) -> BlackboxConfig:
    """Resolve the saved or proposed entry with the same environment precedence."""
    entry = _blackbox_entry() if entry is None else entry
    _note_retired_community_settings(entry)
    mode = schema.choice(schema.Mode, _env_or(entry, env="BLACKBOX_MODE", key="mode", default="")) or schema.Mode.AUDIT.value
    block_severity = schema.severity(_env_or(entry, env="BLACKBOX_BLOCK_SEVERITY", key="block_severity", default="")) or "critical"
    report_min_severity = schema.severity(_env_or(entry, env="BLACKBOX_REPORT_MIN_SEVERITY", key="report_min_severity",
                                                  default="")) or "high"
    categories = schema.category_settings(entry.get("detection"))
    protected_paths = _normalize_protected_paths(entry.get("protected_paths"))
    llm_entry = entry.get("llm") if isinstance(entry.get("llm"), dict) else {}
    llm_provider = schema.choice(schema.Provider, _env_or(llm_entry, env="BLACKBOX_LLM_PROVIDER", key="provider", default="")) or ""
    llm_model = str(_env_or(llm_entry, env="BLACKBOX_LLM_MODEL", key="model", default="")).strip()
    referenced_key = read_host_secret(str(llm_entry.get("api_key_env") or "").strip())   # KI-371: a variable's name
    llm_api_key = (read_host_secret("BLACKBOX_LLM_API_KEY") or str(llm_entry.get("api_key") or "").strip() or referenced_key)
    llm_enabled = _as_bool(_env_or(llm_entry, env="BLACKBOX_LLM_ENABLED", key="enabled", default=False), False)
    context_graph_id = str(_env_or(entry, env="BLACKBOX_CONTEXT_GRAPH_ID", key="context_graph_id",
                                   default=constants.DEFAULT_CONTEXT_GRAPH_ID))
    # Auto-switch an install still pointed at a legacy (pre-Blackbox) graph to the
    # current default, so an existing DKG user syncs the correct CG with no manual
    # step. A genuinely custom graph id is not in the legacy set and is untouched.
    if context_graph_id in constants.LEGACY_CONTEXT_GRAPH_IDS:
        logger.info("blackbox: switching legacy context_graph_id %s -> %s", context_graph_id, constants.DEFAULT_CONTEXT_GRAPH_ID)
        context_graph_id = constants.DEFAULT_CONTEXT_GRAPH_ID
    configured_dkg_home = _configured_dkg_home(entry)
    configured_dkg_url = entry.get("dkg_url") or entry.get("dkgUrl")
    dkg_home = str(configured_dkg_home or _first_env("BLACKBOX_DKG_HOME") or constants.blackbox_dkg_home()).strip()
    dkg_bin = str(entry.get("dkg_bin") or entry.get("dkgBin") or _first_env("BLACKBOX_DKG_BIN")
                  or constants.blackbox_dkg_bin()).strip()
    dkg_url_env = _first_env("BLACKBOX_DKG_DAEMON_URL", "BLACKBOX_DKG_URL")
    dkg_url = str(configured_dkg_url or dkg_url_env or _default_dkg_url()).rstrip("/")
    if not configured_dkg_home and dkg_url in {"http://127.0.0.1:9200", "http://localhost:9200"}:
        dkg_url = _default_dkg_url()
    graph_peer_id = str(_env_or(entry, env="BLACKBOX_GRAPH_PEER_ID", key="graph_peer_id",
                                default=constants.DEFAULT_GRAPH_PEER_ID)).strip()
    # Replace old bootstrap peers (custom ones untouched); the default is in that set too (KI-335).
    if graph_peer_id in constants.LEGACY_GRAPH_PEER_IDS and graph_peer_id != constants.DEFAULT_GRAPH_PEER_ID:
        logger.info("blackbox: switching stale graph_peer_id %s -> %s", graph_peer_id, constants.DEFAULT_GRAPH_PEER_ID)
        graph_peer_id = constants.DEFAULT_GRAPH_PEER_ID
    return BlackboxConfig(
        mode=mode, semantic=semantic_config(entry), **snapshot_fields(entry),
        detection_backend=str(entry.get("detection_backend", schema.DetectionBackend.LEGACY_CACHE.value)).strip().lower(),
        context_graph_id=context_graph_id,
        graph_peer_id=graph_peer_id,
        dkg_url=dkg_url,
        dkg_home=dkg_home,
        dkg_bin=dkg_bin,
        sync_interval=max(3600, _as_int(_env_or(entry, env="BLACKBOX_SYNC_INTERVAL", key="sync_interval", default=3600), 3600)),
        # Community sharing switches (README: `report` / `report_min_severity`): `report` defaults OFF
        # (opt-in, 2026-10-16); the daily cap is a real bound from the first report (KI-002).
        report=_as_bool(_env_or(entry, env="BLACKBOX_REPORT", key="report", default=False), False),
        daily_report_limit=constants.effective_daily_report_limit(_as_int(_env_or(entry, env="BLACKBOX_DAILY_REPORT_LIMIT", key="daily_report_limit", default=constants.DEFAULT_DAILY_REPORT_LIMIT), constants.DEFAULT_DAILY_REPORT_LIMIT)),
        community_shadow=_as_bool(_env_or(entry, env="BLACKBOX_COMMUNITY_SHADOW", key="community_shadow", default=False), False),
        community_sandbox=_as_bool(_env_or(entry, env="BLACKBOX_COMMUNITY_SANDBOX", key="community_sandbox", default=False), False),
        community_auto_approve=_as_bool(_env_or(entry, env="BLACKBOX_COMMUNITY_AUTO_APPROVE", key="community_auto_approve", default=False), False),
        verified_lookup_fallback=_fallback_mode(_env_or(entry, env="BLACKBOX_VERIFIED_LOOKUP_FALLBACK", key="verified_lookup_fallback", default="off")),
        community_poll_interval=_as_int(_env_or(entry, env="BLACKBOX_COMMUNITY_POLL_INTERVAL", key="community_poll_interval", default=20), 20),
        community_keepalive_epoch_days=_as_float(_env_or(entry, env="BLACKBOX_COMMUNITY_KEEPALIVE_EPOCH_DAYS", key="community_keepalive_epoch_days", default=10.0), 10.0),
        report_min_severity=report_min_severity,
        block_severity=block_severity,
        dashboard_port=_as_int(_env_or(entry, env="BLACKBOX_DASHBOARD_PORT", key="dashboard_port", default=_DASHBOARD_PORT), _DASHBOARD_PORT),
        discover=_as_bool(_env_or(entry, env="BLACKBOX_DISCOVER", key="discover", default=True), True),
        osv_lookup=_as_bool(_env_or(entry, env="BLACKBOX_OSV_LOOKUP", key="osv_lookup", default=True), True),
        auto_attach=_as_bool(_env_or(entry, env="BLACKBOX_AUTO_ATTACH", key="auto_attach", default=False), False),
        categories=categories,
        protected_paths=protected_paths,
        llm_enabled=llm_enabled,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_api_key=llm_api_key,
    )


def _normalize_protected_paths(raw: Any) -> tuple[str, ...]:
    """Validate ``protected_paths`` into a tuple of non-empty pattern strings.

    A missing key (``None``) falls back to :data:`DEFAULT_PROTECTED_PATHS`; an
    explicit list — including an empty one — is honoured verbatim so a user who
    clears the list keeps it cleared.
    """
    if raw is None:
        return DEFAULT_PROTECTED_PATHS
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(schema.path_list(raw)[:schema.MAX_PROTECTED_PATHS])


#: The ``blackbox`` entry read once for the duration of :func:`one_entry_read` (None outside it).
_ENTRY_MEMO: ContextVar[Optional[dict[str, Any]]] = ContextVar("blackbox_entry_memo", default=None)


@contextmanager
def one_entry_read() -> Iterator[None]:
    """Within this block, :func:`shield_entry` reads the config ONCE and reuses it — the shields
    snapshot every tool call takes reads it once for all shields, however many there are."""
    token = _ENTRY_MEMO.set({})
    try:
        yield
    finally:
        _ENTRY_MEMO.reset(token)


def shield_entry() -> dict[str, Any]:
    """The ``plugins.entries.blackbox`` mapping a shield's mode reads (:func:`_blackbox_entry`,
    looked up at call time); one read per :func:`one_entry_read` block."""
    memo = _ENTRY_MEMO.get()
    if memo is None:
        return _blackbox_entry()
    if "entry" not in memo:
        memo["entry"] = _blackbox_entry()
    return memo["entry"]
