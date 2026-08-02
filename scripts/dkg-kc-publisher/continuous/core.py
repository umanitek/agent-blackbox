"""Configuration, canonicalization, state, and audit primitives.

This module deliberately uses SQLite and the Python standard library for all
durable behavior.  PyYAML is the only runtime dependency and is already a
Hermes dependency.  Raw source values are stored for provenance, but callers
must never send them to logs or model prompts without an explicit safe view.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence

import yaml


UTC = dt.timezone.utc
SCHEMA_VERSION = 2
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEX_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_SECRET_KEY = re.compile(r"(?:token|secret|password|authorization|api[_-]?key|webhook)", re.I)


def utcnow() -> str:
    return dt.datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_day(value: Optional[str] = None) -> str:
    parsed = parse_time(value) if value else dt.datetime.now(UTC)
    return parsed.astimezone(UTC).date().isoformat()


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes | str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    payload = data.encode("utf-8") if isinstance(data, str) else data
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def safe_summary(value: str, *, prefix: int = 18) -> str:
    """Return an inert identifier for hostile source text."""
    text = str(value)
    return f"sha256:{sha256(text)[:16]} chars:{len(text)} prefix:{json.dumps(text[:prefix])}"


def _merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge(dict(result[key]), value)
        else:
            result[key] = value
    return result


DEFAULTS: Dict[str, Any] = {
    "paths": {"state_dir": "./continuous-state", "publisher_dir": ".."},
    "limits": {
        "asset_records": 1000,
        "approval_bundle_records": 10000,
        "minimum_bundle_records": 10000,
        "daily_publish_records": 100000,
        "max_new_records_per_source_run": 50000,
        "max_pending_records": 500000,
        "max_source_bytes": 2_000_000_000,
        "max_source_files": 10000,
        "max_line_bytes": 16384,
        "approval_ttl_hours": 24,
        "approval_preflight_ttl_minutes": 30,
    },
    "publisher": {
        "enabled": False,
        "auto_approve": False,
        "epochs": 12,
        "publish_mode": "sync",
        "swm_restore_mode": "skip",
        "network": "mainnet-base",
        "pipeline_width": 1,
        "access_policy": 1,
        "require_swm_verification": False,
        "verified_incremental_support": False,
        "approved_publish_script_sha256": "",
    },
    "graph_dedupe": {
        "enabled": False,
        "required_for_publishing": True,
        "max_age_hours": 6,
        "query_batch_size": 1000,
        "query_timeout_seconds": 60,
        "query_attempts": 3,
        "query_retry_delay_seconds": 5,
    },
    "slack": {
        "enabled": False,
        "allow_any_channel_member": False,
        "approver_user_ids": [],
        "progress_interval_seconds": 60,
    },
    "downloads": {"host": "127.0.0.1", "port": 8791},
    "ai_discovery": {
        "enabled": False,
        "max_calls_per_run": 1,
        "max_calls_per_day": 2,
        "max_output_tokens": 1200,
        "max_total_tokens_per_day": 20000,
        "max_estimated_cost_usd_per_day": 2.0,
    },
    "sources": [],
}


def load_config(path: Path) -> Dict[str, Any]:
    path = path.expanduser().resolve()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("configuration root must be a mapping")
    config = _merge(DEFAULTS, raw)
    config["_config_path"] = str(path)
    base = path.parent
    for key in ("state_dir", "publisher_dir"):
        candidate = Path(str(config["paths"][key])).expanduser()
        config["paths"][key] = str(candidate if candidate.is_absolute() else (base / candidate).resolve())
    _validate_config(config)
    return config


def _positive_int(section: Mapping[str, Any], name: str, *, allow_zero: bool = False) -> int:
    value = section.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < (0 if allow_zero else 1):
        raise ValueError(f"{name} must be {'a non-negative' if allow_zero else 'a positive'} integer")
    return value


def _positive_number(section: Mapping[str, Any], name: str) -> float:
    value = section.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return float(value)


def _validate_config(config: Mapping[str, Any]) -> None:
    limits = config["limits"]
    asset = _positive_int(limits, "asset_records")
    bundle = _positive_int(limits, "approval_bundle_records")
    minimum = _positive_int(limits, "minimum_bundle_records")
    daily = _positive_int(limits, "daily_publish_records")
    if bundle < asset or bundle % asset:
        raise ValueError("approval_bundle_records must be an exact multiple of asset_records")
    if minimum > bundle:
        raise ValueError("minimum_bundle_records cannot exceed approval_bundle_records")
    if minimum % asset:
        raise ValueError("minimum_bundle_records must be an exact multiple of asset_records")
    if daily < bundle:
        raise ValueError("daily_publish_records must allow at least one full approval bundle")
    for name in (
        "max_new_records_per_source_run", "max_pending_records", "max_source_bytes",
        "max_source_files", "max_line_bytes", "approval_ttl_hours", "approval_preflight_ttl_minutes",
    ):
        _positive_int(limits, name)
    publisher = config["publisher"]
    if not isinstance(publisher.get("auto_approve", False), bool):
        raise ValueError("publisher.auto_approve must be true or false")
    if publisher.get("auto_approve", False) and not publisher.get("enabled", False):
        raise ValueError("publisher.auto_approve requires publisher.enabled: true")
    if publisher.get("auto_approve", False) and not config["slack"].get("enabled", False):
        raise ValueError("publisher.auto_approve requires slack.enabled: true")
    if int(publisher.get("epochs", 0)) != 12:
        raise ValueError("publisher.epochs must remain 12")
    if publisher.get("publish_mode") not in {"sync", "async"}:
        raise ValueError("publisher.publish_mode must be sync or async")
    if int(publisher.get("pipeline_width", 0)) != 1:
        raise ValueError("continuous publishing requires publisher.pipeline_width: 1")
    if str(publisher.get("access_policy")) not in {"0", "1"}:
        raise ValueError("publisher.access_policy must be 0 (public) or 1 (private)")
    swm_restore_mode = str(publisher.get("swm_restore_mode", "skip"))
    if swm_restore_mode not in {"restore", "skip"}:
        raise ValueError("publisher.swm_restore_mode must be restore or skip")
    require_swm_verification = publisher.get("require_swm_verification") is True
    if swm_restore_mode == "restore" and not require_swm_verification:
        raise ValueError("SWM restoration mode requires require_swm_verification: true")
    if swm_restore_mode == "skip" and require_swm_verification:
        raise ValueError("VM-only mode requires require_swm_verification: false")
    if publisher.get("enabled", False):
        if publisher.get("verified_incremental_support") is not True:
            raise ValueError("paid publishing requires verified_incremental_support: true")
        script_hash = str(publisher.get("approved_publish_script_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", script_hash):
            raise ValueError("paid publishing requires an approved publish.mjs SHA-256")
        required = (
            "context_graph_id", "context_graph_onchain_id", "dkg_version",
            "ledger_dkg_version", "network",
        )
        missing = [name for name in required if not publisher.get(name)]
        if missing:
            raise ValueError(f"publisher configuration missing: {', '.join(missing)}")
        if not any(publisher.get(name) for name in (
            "dkg_auth_token_credential", "dkg_auth_token_file", "dkg_auth_token_env", "dkg_auth_token_path",
        )):
            raise ValueError("paid publishing requires a protected DKG auth-token reference")

    graph = config["graph_dedupe"]
    _positive_int(graph, "max_age_hours")
    query_batch_size = _positive_int(graph, "query_batch_size")
    _positive_int(graph, "query_timeout_seconds")
    query_attempts = _positive_int(graph, "query_attempts")
    retry_delay = _positive_int(graph, "query_retry_delay_seconds")
    if query_batch_size > 2000:
        raise ValueError("graph_dedupe.query_batch_size must be at most 2000")
    if query_attempts > 5:
        raise ValueError("graph_dedupe.query_attempts must be at most 5")
    if retry_delay > 60:
        raise ValueError("graph_dedupe.query_retry_delay_seconds must be at most 60")
    if publisher.get("enabled", False) and graph.get("required_for_publishing", True) and not graph.get("enabled", False):
        raise ValueError("paid publishing requires graph_dedupe.enabled: true")

    slack = config["slack"]
    if slack.get("enabled", False):
        _positive_int(slack, "progress_interval_seconds")
        for name in ("workspace_id", "channel_id"):
            if not slack.get(name):
                raise ValueError(f"slack.{name} is required when Slack is enabled")
        if not slack.get("allow_any_channel_member", False) and not slack.get("approver_user_ids"):
            raise ValueError("slack.approver_user_ids must not be empty when Slack is enabled")
        for secret in ("bot_token", "app_token"):
            if not any(slack.get(f"{secret}_{kind}") for kind in ("credential", "file", "env")):
                raise ValueError(f"Slack requires a protected {secret} reference")
        download_base = str(slack.get("download_base_url") or "")
        if download_base:
            parsed_download = urllib.parse.urlsplit(download_base)
            if parsed_download.scheme != "https" or not (parsed_download.hostname or "").endswith(".ts.net"):
                raise ValueError("slack.download_base_url must be a tailnet-only https://*.ts.net URL")

    downloads = config["downloads"]
    if downloads.get("host") != "127.0.0.1":
        raise ValueError("downloads.host must remain loopback-only")
    port = _positive_int(downloads, "port")
    if port > 65535:
        raise ValueError("downloads.port must be at most 65535")

    ai = config["ai_discovery"]
    if ai.get("enabled", False):
        if not ai.get("model"):
            raise ValueError("ai_discovery.model is required when discovery is enabled")
        for name in ("max_calls_per_run", "max_calls_per_day", "max_output_tokens", "max_total_tokens_per_day"):
            _positive_int(ai, name)
        _positive_number(ai, "max_estimated_cost_usd_per_day")
        if int(ai["max_calls_per_run"]) > int(ai["max_calls_per_day"]):
            raise ValueError("max_calls_per_run cannot exceed max_calls_per_day")
        pricing = ai.get("estimated_pricing") or {}
        for name in ("input_usd_per_million", "output_usd_per_million", "web_search_call_usd"):
            _positive_number(pricing, name)
        if not any(ai.get(f"api_key_{kind}") for kind in ("credential", "file", "env")):
            raise ValueError("AI discovery requires a protected API-key reference")
    ids: set[str] = set()
    for source in config.get("sources") or []:
        if not isinstance(source, dict) or not source.get("id"):
            raise ValueError("each source must be a mapping with an id")
        source_id = str(source["id"])
        if source_id in ids:
            raise ValueError(f"duplicate source id: {source_id}")
        ids.add(source_id)
        if source.get("enabled", False) and source.get("adapter") != "git_lines":
            raise ValueError(f"{source_id}: only the reviewed git_lines adapter may be enabled")
        if source.get("enabled", False) and source.get("line_parser", "indicator") not in {"indicator", "maltrail"}:
            raise ValueError(f"{source_id}: line_parser has not been reviewed")
        if source.get("enabled", False) and not source.get("license", {}).get("redistribution_approved", False):
            raise ValueError(f"{source_id}: enabled source is not approved for redistribution")


def read_secret(config: Mapping[str, Any], name: str) -> str:
    """Read a secret through a systemd credential, protected file, or env var.

    The configuration contains only a credential/file/env *reference*, never
    the value.  Values are returned without logging and never cached globally.
    """
    credential = config.get(f"{name}_credential")
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    candidates: list[Path] = []
    if credential and credential_dir:
        candidates.append(Path(credential_dir) / str(credential))
    if config.get(f"{name}_file"):
        candidates.append(Path(str(config[f"{name}_file"])).expanduser())
    for candidate in candidates:
        try:
            value = candidate.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            continue
        if value:
            return value
    env_name = config.get(f"{name}_env")
    if env_name and os.environ.get(str(env_name)):
        return os.environ[str(env_name)].strip()
    raise RuntimeError(f"secret {name!r} is not installed through its configured reference")


def _redact(value: Any, key: str = "") -> Any:
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class AuditLog:
    def __init__(self, state_dir: Path, run_id: str):
        self.run_id = run_id
        self.path = state_dir / "logs" / f"run-{run_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, **fields: Any) -> None:
        record = _redact({"at": utcnow(), "run_id": self.run_id, "event": event, **fields})
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        human = fields.get("message") or event
        print(f"[{record['at']}] {human}", file=sys.stderr)


@dataclasses.dataclass(frozen=True)
class CanonicalIndicator:
    kind: str
    value: str

    @property
    def entity_id(self) -> str:
        return f"urn:blackbox:entity:{self.kind}:{sha256(self.kind + chr(0) + self.value)}"


def _domain(value: str) -> str:
    value = value.rstrip(".").lower()
    encoded = value.encode("idna").decode("ascii")
    if len(encoded) > 253 or "." not in encoded:
        raise ValueError("not a registrable domain")
    labels = encoded.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid domain label")
    return encoded


def canonicalize_indicator(raw: str) -> CanonicalIndicator:
    value = str(raw).strip()
    if not value or len(value.encode("utf-8")) > 16384:
        raise ValueError("indicator is empty or oversized")

    lower = value.lower()
    if lower.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not publishable")
        if not parsed.hostname:
            raise ValueError("URL has no host")
        host = _domain(parsed.hostname) if not _is_ip(parsed.hostname) else str(ipaddress.ip_address(parsed.hostname))
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port is not None else "")
        normalized = urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment))
        return CanonicalIndicator("url", normalized)

    hash_value = lower.removeprefix("0x")
    algorithm = _HEX_HASH_LENGTHS.get(len(hash_value))
    if algorithm and re.fullmatch(r"[0-9a-f]+", hash_value):
        return CanonicalIndicator("hash", f"{algorithm}:{hash_value}")

    endpoint = _parse_endpoint(value)
    if endpoint:
        return endpoint
    try:
        return CanonicalIndicator("ip", str(ipaddress.ip_address(value)))
    except ValueError:
        pass
    return CanonicalIndicator("domain", _domain(value))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_endpoint(value: str) -> Optional[CanonicalIndicator]:
    host = ""
    port_text = ""
    if value.startswith("[") and "]:" in value:
        host, port_text = value[1:].split("]:", 1)
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
    if not host or not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port is outside 1..65535")
    try:
        address = str(ipaddress.ip_address(host))
        display = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    except ValueError:
        display = f"{_domain(host)}:{port}"
    return CanonicalIndicator("endpoint", display)


@dataclasses.dataclass(frozen=True)
class Observation:
    observation_id: str
    source_id: str
    upstream_id: str
    source_revision: str
    canonical_type: str
    canonical_value: str
    canonical_id: str
    original_value: str
    category: str
    lifecycle_status: str
    confidence: int
    severity: str
    license_id: str
    license_url: str
    attribution: str
    references: Sequence[str]
    evidence: str
    parser_version: str
    fetched_at: str
    content_sha256: str

    @classmethod
    def build(
        cls,
        *,
        source_id: str,
        upstream_id: str,
        source_revision: str,
        original_value: str,
        category: str,
        lifecycle_status: str,
        confidence: int,
        severity: str,
        license_id: str,
        license_url: str,
        attribution: str,
        references: Sequence[str],
        evidence: str,
        parser_version: str,
        fetched_at: Optional[str] = None,
    ) -> "Observation":
        canonical = canonicalize_indicator(original_value)
        event = {
            "source": source_id,
            "upstream": upstream_id,
            "value": original_value,
            "status": lifecycle_status,
            "evidence": evidence,
        }
        content_hash = sha256(canonical_json(event))
        observation_id = f"urn:blackbox:observation:{sha256(source_id + chr(0) + upstream_id + chr(0) + content_hash)}"
        return cls(
            observation_id=observation_id,
            source_id=source_id,
            upstream_id=upstream_id,
            source_revision=source_revision,
            canonical_type=canonical.kind,
            canonical_value=canonical.value,
            canonical_id=canonical.entity_id,
            original_value=original_value,
            category=category,
            lifecycle_status=lifecycle_status,
            confidence=max(0, min(100, int(confidence))),
            severity=severity,
            license_id=license_id,
            license_url=license_url,
            attribution=attribution,
            references=tuple(references),
            evidence=evidence,
            parser_version=parser_version,
            fetched_at=fetched_at or utcnow(),
            content_sha256=content_hash,
        )

    def publisher_record(self) -> Dict[str, Any]:
        return {
            "type": "source_observation",
            "observationId": self.observation_id,
            "canonicalId": self.canonical_id,
            "canonicalType": self.canonical_type,
            "normalizedValue": self.canonical_value,
            "originalValue": self.original_value,
            "sourceId": self.source_id,
            "upstreamId": self.upstream_id,
            "sourceRevision": self.source_revision,
            "category": self.category,
            "lifecycleStatus": self.lifecycle_status,
            "confidence": self.confidence,
            "severity": self.severity,
            "licenseId": self.license_id,
            "licenseUrl": self.license_url,
            "attribution": self.attribution,
            "references": list(self.references),
            "evidence": self.evidence,
            "parserVersion": self.parser_version,
            "fetchedAt": self.fetched_at,
            "contentSha256": self.content_sha256,
        }


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self._migrate()

    def close(self) -> None:
        self.db.close()

    def _migrate(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS runs(
              run_id TEXT PRIMARY KEY, kind TEXT NOT NULL, started_at TEXT NOT NULL,
              ended_at TEXT, status TEXT NOT NULL, metrics_json TEXT NOT NULL DEFAULT '{}', error TEXT
            );
            CREATE TABLE IF NOT EXISTS source_state(
              source_id TEXT PRIMARY KEY, revision TEXT, cursor_json TEXT NOT NULL DEFAULT '{}',
              last_attempt_at TEXT, last_success_at TEXT, status TEXT, error TEXT,
              fetched INTEGER NOT NULL DEFAULT 0, parsed INTEGER NOT NULL DEFAULT 0,
              invalid INTEGER NOT NULL DEFAULT 0, inserted INTEGER NOT NULL DEFAULT 0,
              duplicate INTEGER NOT NULL DEFAULT 0, canonical_match INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS observations(
              observation_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, upstream_id TEXT NOT NULL,
              source_revision TEXT NOT NULL, canonical_type TEXT NOT NULL,
              canonical_value TEXT NOT NULL, canonical_id TEXT NOT NULL,
              original_value TEXT NOT NULL, category TEXT NOT NULL,
              lifecycle_status TEXT NOT NULL, confidence INTEGER NOT NULL, severity TEXT NOT NULL,
              license_id TEXT NOT NULL, license_url TEXT NOT NULL, attribution TEXT NOT NULL,
              references_json TEXT NOT NULL, evidence TEXT NOT NULL, parser_version TEXT NOT NULL,
              fetched_at TEXT NOT NULL, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
              content_sha256 TEXT NOT NULL, state TEXT NOT NULL,
              bundle_id TEXT, published_at TEXT,
              UNIQUE(source_id, upstream_id, content_sha256)
            );
            CREATE INDEX IF NOT EXISTS observations_state_idx ON observations(state, fetched_at, observation_id);
            CREATE INDEX IF NOT EXISTS observations_canonical_idx ON observations(canonical_id);
            CREATE TABLE IF NOT EXISTS source_members(
              source_id TEXT NOT NULL, upstream_id TEXT NOT NULL, canonical_type TEXT NOT NULL,
              canonical_value TEXT NOT NULL, original_value TEXT NOT NULL, last_revision TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(source_id, upstream_id)
            );
            CREATE TABLE IF NOT EXISTS bundles(
              bundle_id TEXT PRIMARY KEY, manifest_sha256 TEXT NOT NULL UNIQUE,
              batch_manifest_sha256 TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
              record_count INTEGER NOT NULL, asset_count INTEGER NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
              decision_at TEXT, decided_by TEXT, decision_reason TEXT,
              approval_nonce_hash TEXT, nonce_used_at TEXT,
              approval_preflight_sha256 TEXT, approval_preflight_at TEXT,
              approval_preflight_json TEXT,
              slack_workspace TEXT, slack_channel TEXT, slack_ts TEXT,
              published_at TEXT, last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS bundle_observations(
              bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
              position INTEGER NOT NULL, observation_id TEXT NOT NULL REFERENCES observations(observation_id),
              PRIMARY KEY(bundle_id, position), UNIQUE(bundle_id,observation_id)
            );
            CREATE TABLE IF NOT EXISTS assets(
              bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id), ordinal INTEGER NOT NULL,
              batch_name TEXT NOT NULL, record_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
              finalized_at TEXT, tx_hash TEXT UNIQUE, ual TEXT UNIQUE,
              PRIMARY KEY(bundle_id, ordinal)
            );
            CREATE TABLE IF NOT EXISTS decisions(
              decision_id INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
              action TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL,
              manifest_sha256 TEXT NOT NULL, workspace TEXT, channel TEXT, decided_at TEXT NOT NULL,
              reason TEXT
            );
            CREATE TABLE IF NOT EXISTS ai_usage(
              day TEXT PRIMARY KEY, calls INTEGER NOT NULL DEFAULT 0,
              input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0,
              estimated_cost_usd REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS source_proposals(
              proposal_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, model TEXT NOT NULL,
              proposal_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'proposed'
            );
            CREATE TABLE IF NOT EXISTS graph_entities(
              canonical_id TEXT PRIMARY KEY, canonical_type TEXT NOT NULL,
              canonical_value TEXT NOT NULL, views_json TEXT NOT NULL,
              first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS graph_sync(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), synced_at TEXT NOT NULL,
              context_graph_id TEXT NOT NULL, rows_seen INTEGER NOT NULL,
              entities_seen INTEGER NOT NULL, views_json TEXT NOT NULL
            );
            """
        )
        row = self.db.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
        if row is None:
            self.db.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
        elif row["version"] == 1 and SCHEMA_VERSION == 2:
            self.db.executescript(
                """
                BEGIN IMMEDIATE;
                ALTER TABLE bundle_observations RENAME TO bundle_observations_v1;
                CREATE TABLE bundle_observations(
                  bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
                  position INTEGER NOT NULL,
                  observation_id TEXT NOT NULL REFERENCES observations(observation_id),
                  PRIMARY KEY(bundle_id,position), UNIQUE(bundle_id,observation_id)
                );
                INSERT INTO bundle_observations(bundle_id,position,observation_id)
                  SELECT bundle_id,position,observation_id FROM bundle_observations_v1;
                DROP TABLE bundle_observations_v1;
                UPDATE schema_meta SET version=2;
                COMMIT;
                """
            )
        elif row["version"] != SCHEMA_VERSION:
            raise RuntimeError(f"unsupported state schema {row['version']}, expected {SCHEMA_VERSION}")

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def begin_run(self, run_id: str, kind: str) -> None:
        self.db.execute(
            "INSERT INTO runs(run_id,kind,started_at,status) VALUES (?,?,?,'running')",
            (run_id, kind, utcnow()),
        )

    def finish_run(self, run_id: str, status: str, metrics: Mapping[str, Any], error: Optional[str] = None) -> None:
        self.db.execute(
            "UPDATE runs SET ended_at=?,status=?,metrics_json=?,error=? WHERE run_id=?",
            (utcnow(), status, canonical_json(metrics).decode(), error, run_id),
        )

    def insert_observation(self, observation: Observation, *, candidate: bool = True) -> str:
        canonical_match = self.db.execute(
            "SELECT 1 FROM observations WHERE canonical_id=? LIMIT 1", (observation.canonical_id,)
        ).fetchone() is not None
        try:
            self.db.execute(
                """INSERT INTO observations(
                  observation_id,source_id,upstream_id,source_revision,canonical_type,canonical_value,
                  canonical_id,original_value,category,lifecycle_status,confidence,severity,license_id,
                  license_url,attribution,references_json,evidence,parser_version,fetched_at,first_seen_at,
                  last_seen_at,content_sha256,state
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    observation.observation_id, observation.source_id, observation.upstream_id,
                    observation.source_revision, observation.canonical_type, observation.canonical_value,
                    observation.canonical_id, observation.original_value, observation.category,
                    observation.lifecycle_status, observation.confidence, observation.severity,
                    observation.license_id, observation.license_url, observation.attribution,
                    canonical_json(list(observation.references)).decode(), observation.evidence,
                    observation.parser_version, observation.fetched_at, observation.fetched_at,
                    observation.fetched_at, observation.content_sha256,
                    "candidate" if candidate else "quarantined",
                ),
            )
        except sqlite3.IntegrityError:
            self.db.execute(
                "UPDATE observations SET last_seen_at=? WHERE source_id=? AND upstream_id=? AND content_sha256=?",
                (observation.fetched_at, observation.source_id, observation.upstream_id, observation.content_sha256),
            )
            return "duplicate"
        return "canonical_match" if canonical_match else "inserted"

    def pending_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) AS n FROM observations WHERE state='candidate'").fetchone()["n"])

    def get_observations(self, ids: Sequence[str]) -> list[Observation]:
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        rows = self.db.execute(
            f"SELECT * FROM observations WHERE observation_id IN ({placeholders})", tuple(ids)
        ).fetchall()
        by_id = {row["observation_id"]: self._observation(row) for row in rows}
        return [by_id[value] for value in ids]

    @staticmethod
    def _observation(row: sqlite3.Row) -> Observation:
        return Observation(
            observation_id=row["observation_id"], source_id=row["source_id"], upstream_id=row["upstream_id"],
            source_revision=row["source_revision"], canonical_type=row["canonical_type"],
            canonical_value=row["canonical_value"], canonical_id=row["canonical_id"],
            original_value=row["original_value"], category=row["category"],
            lifecycle_status=row["lifecycle_status"], confidence=row["confidence"], severity=row["severity"],
            license_id=row["license_id"], license_url=row["license_url"], attribution=row["attribution"],
            references=json.loads(row["references_json"]), evidence=row["evidence"],
            parser_version=row["parser_version"], fetched_at=row["fetched_at"],
            content_sha256=row["content_sha256"],
        )

    def bundle_candidates(self, limit: int) -> list[Observation]:
        rows = self.db.execute(
            """WITH eligible AS (
                 SELECT o.*,
                        ROW_NUMBER() OVER (
                          PARTITION BY o.canonical_id ORDER BY o.fetched_at,o.observation_id
                        ) AS canonical_rank
                 FROM observations o
                 WHERE o.state='candidate'
                   AND NOT EXISTS (
                     SELECT 1 FROM graph_entities g WHERE g.canonical_id=o.canonical_id
                   )
                   AND NOT EXISTS (
                     SELECT 1
                     FROM bundle_observations bo
                     JOIN observations bundled ON bundled.observation_id=bo.observation_id
                     JOIN bundles b ON b.bundle_id=bo.bundle_id
                     WHERE bundled.canonical_id=o.canonical_id
                       AND b.state NOT IN ('declined','expired','superseded')
                   )
               )
               SELECT * FROM eligible WHERE canonical_rank=1
               ORDER BY fetched_at,observation_id LIMIT ?""",
            (limit,),
        ).fetchall()
        return [self._observation(row) for row in rows]

    def graph_sync_row(self) -> Optional[sqlite3.Row]:
        return self.db.execute("SELECT * FROM graph_sync WHERE singleton=1").fetchone()

    def bundle_row(self, bundle_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown bundle {bundle_id}")
        return row

    def list_bundles(self, states: Sequence[str] = ()) -> list[sqlite3.Row]:
        if states:
            marks = ",".join("?" for _ in states)
            return self.db.execute(
                f"SELECT * FROM bundles WHERE state IN ({marks}) ORDER BY created_at", tuple(states)
            ).fetchall()
        return self.db.execute("SELECT * FROM bundles ORDER BY created_at").fetchall()

    def published_today(self, day: Optional[str] = None) -> int:
        day = day or utc_day()
        row = self.db.execute(
            "SELECT COALESCE(SUM(record_count),0) AS n FROM assets WHERE status='finalized' AND substr(finalized_at,1,10)=?",
            (day,),
        ).fetchone()
        return int(row["n"])

    def expire_bundles(self) -> int:
        now = utcnow()
        cursor = self.db.execute(
            "UPDATE bundles SET state='expired' WHERE state IN ('bundled','approved') AND expires_at < ?",
            (now,),
        )
        return cursor.rowcount

    def requeue_expired_observations(self) -> int:
        """Return never-published rows from expired manifests to candidate state.

        Historical bundle membership is retained for auditability. Ambiguous,
        publishing, declined, and superseded bundles are deliberately excluded.
        """
        cursor = self.db.execute(
            """UPDATE observations
               SET state='candidate',bundle_id=NULL
               WHERE state='bundled'
                 AND bundle_id IN (
                   SELECT bundle_id FROM bundles WHERE state='expired'
                 )"""
        )
        return cursor.rowcount

    def stats(self) -> Dict[str, Any]:
        observations = {
            row["state"]: row["n"]
            for row in self.db.execute("SELECT state,COUNT(*) AS n FROM observations GROUP BY state")
        }
        bundles = {
            row["state"]: row["n"]
            for row in self.db.execute("SELECT state,COUNT(*) AS n FROM bundles GROUP BY state")
        }
        sources = [dict(row) for row in self.db.execute("SELECT * FROM source_state ORDER BY source_id")]
        graph_sync = self.graph_sync_row()
        known_graph_entities = int(self.db.execute("SELECT COUNT(*) AS n FROM graph_entities").fetchone()["n"])
        return {
            "observations": observations,
            "bundles": bundles,
            "sources": sources,
            "graph_sync": dict(graph_sync) if graph_sync else None,
            "known_graph_entities": known_graph_entities,
            "published_today": self.published_today(),
        }
