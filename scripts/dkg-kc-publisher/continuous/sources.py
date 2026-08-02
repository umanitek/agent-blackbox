"""Allowlisted, non-executing source acquisition adapters."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Tuple

from .core import AuditLog, Observation, State, canonical_json, sha256, utcnow


PARSER_VERSION = "git-lines-v2"


class SourceError(RuntimeError):
    pass


def _run_git(args: list[str], *, cwd: Optional[Path] = None, timeout: int = 600) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "git failed").strip()
        raise SourceError(detail[-2000:])
    return completed.stdout.strip()


def _validate_repository(source: Mapping[str, Any]) -> str:
    repository = str(source.get("repository") or "")
    parsed = urllib.parse.urlsplit(repository)
    allowed_hosts = set(source.get("allowed_hosts") or ["github.com", "gitlab.com"])
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname not in allowed_hosts:
        raise SourceError(f"{source.get('id')}: repository must use HTTPS on an allowlisted host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SourceError(f"{source.get('id')}: repository URL may not contain credentials/query/fragment")
    return repository


def _snapshot_checkout(source: Mapping[str, Any], state_dir: Path, cursor: Mapping[str, Any]) -> Tuple[Path, str, bool]:
    """Return (checkout, revision, is_new_revision)."""
    source_id = str(source["id"])
    checkout = state_dir / "sources" / f"{source_id}-{sha256(str(source.get('repository')))[:10]}"
    repository = _validate_repository(source)
    ref = str(source.get("ref") or "HEAD")
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", "--filter=blob:none", "--no-checkout", repository, str(checkout)], timeout=1200)
    if not (checkout / ".git").is_dir():
        raise SourceError(f"{source_id}: source cache is not a Git checkout")
    actual_remote = _run_git(["remote", "get-url", "origin"], cwd=checkout)
    if actual_remote.rstrip("/") != repository.rstrip("/"):
        raise SourceError(f"{source_id}: cached remote differs from reviewed repository")

    active_revision = str(cursor.get("revision") or "") if not cursor.get("complete", True) else ""
    if active_revision:
        try:
            _run_git(["cat-file", "-e", f"{active_revision}^{{commit}}"], cwd=checkout)
        except SourceError:
            _run_git(["fetch", "--depth", "1", "origin", active_revision], cwd=checkout, timeout=1200)
        revision = active_revision
        is_new = False
    else:
        _run_git(["fetch", "--depth", "1", "origin", ref], cwd=checkout, timeout=1200)
        revision = _run_git(["rev-parse", "FETCH_HEAD"], cwd=checkout)
        is_new = revision != str(cursor.get("last_complete_revision") or "")
    _run_git(["checkout", "--detach", "--force", revision], cwd=checkout, timeout=1200)
    return checkout, revision, is_new


def _files(checkout: Path, source: Mapping[str, Any], limits: Mapping[str, Any]) -> list[Path]:
    patterns = [str(value) for value in (source.get("paths") or [])]
    excludes = [str(value) for value in (source.get("exclude_paths") or [])]
    if not patterns:
        raise SourceError(f"{source.get('id')}: no reviewed source paths configured")
    found: list[Path] = []
    total_bytes = 0
    root = checkout.resolve()
    for candidate in checkout.rglob("*"):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        resolved = candidate.resolve()
        if root not in resolved.parents:
            raise SourceError(f"{source.get('id')}: source path escaped checkout")
        relative = candidate.relative_to(checkout).as_posix()
        if not any(fnmatch.fnmatch(relative, pattern) for pattern in patterns):
            continue
        if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
            continue
        total_bytes += candidate.stat().st_size
        if total_bytes > int(limits["max_source_bytes"]):
            raise SourceError(f"{source.get('id')}: reviewed files exceed max_source_bytes")
        found.append(candidate)
        if len(found) > int(limits["max_source_files"]):
            raise SourceError(f"{source.get('id')}: reviewed files exceed max_source_files")
    if not found:
        raise SourceError(f"{source.get('id')}: reviewed path patterns matched no files")
    return sorted(found, key=lambda path: path.relative_to(checkout).as_posix())


def _line_records(
    checkout: Path,
    files: list[Path],
    *,
    start_file: int,
    start_line: int,
    max_line_bytes: int,
) -> Iterator[Tuple[int, int, Path, str]]:
    for file_index in range(start_file, len(files)):
        path = files[file_index]
        with path.open("rb") as handle:
            for line_index, raw in enumerate(handle):
                if file_index == start_file and line_index < start_line:
                    continue
                if len(raw) > max_line_bytes:
                    yield file_index, line_index, path, ""
                    continue
                try:
                    value = raw.decode("utf-8").strip()
                except UnicodeDecodeError:
                    yield file_index, line_index, path, ""
                    continue
                yield file_index, line_index, path, value


def _source_state(state: State, source_id: str) -> Dict[str, Any]:
    row = state.db.execute("SELECT * FROM source_state WHERE source_id=?", (source_id,)).fetchone()
    if row is None:
        return {"source_id": source_id, "cursor_json": "{}"}
    return dict(row)


def _save_source_state(
    state: State,
    source_id: str,
    *,
    revision: str,
    cursor: Mapping[str, Any],
    status: str,
    metrics: Mapping[str, int],
    error: Optional[str] = None,
    success: bool = False,
) -> None:
    now = utcnow()
    state.db.execute(
        """INSERT INTO source_state(
          source_id,revision,cursor_json,last_attempt_at,last_success_at,status,error,
          fetched,parsed,invalid,inserted,duplicate,canonical_match
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(source_id) DO UPDATE SET
          revision=excluded.revision,cursor_json=excluded.cursor_json,last_attempt_at=excluded.last_attempt_at,
          last_success_at=CASE WHEN ? THEN excluded.last_success_at ELSE source_state.last_success_at END,
          status=excluded.status,error=excluded.error,fetched=excluded.fetched,parsed=excluded.parsed,
          invalid=excluded.invalid,inserted=excluded.inserted,duplicate=excluded.duplicate,
          canonical_match=excluded.canonical_match""",
        (
            source_id, revision, canonical_json(cursor).decode(), now, now if success else None,
            status, error, metrics.get("fetched", 0), metrics.get("parsed", 0), metrics.get("invalid", 0),
            metrics.get("inserted", 0), metrics.get("duplicate", 0), metrics.get("canonical_match", 0), success,
        ),
    )


def _observation_from_line(
    source: Mapping[str, Any], revision: str, relative: str, value: str, fetched_at: str,
) -> Observation:
    upstream_id = f"{relative}:{sha256(value)}"
    license_info = source["license"]
    repository = str(source["repository"])

    return Observation.build(
        source_id=str(source["id"]),
        upstream_id=upstream_id,
        source_revision=revision,
        original_value=value,
        category=str(_path_setting(source, relative, "category", source.get("category") or "uncategorized")),
        lifecycle_status="active",
        confidence=int(_path_setting(source, relative, "confidence", source.get("confidence", 50))),
        severity=str(_path_setting(source, relative, "severity", source.get("severity") or "unknown")),
        license_id=str(license_info["id"]),
        license_url=str(license_info["url"]),
        attribution=str(license_info.get("attribution") or source["id"]),
        references=[repository, f"{repository.removesuffix('.git')}/blob/{revision}/{relative}"],
        evidence=f"listed in {relative}",
        parser_version=PARSER_VERSION,
        fetched_at=fetched_at,
    )


def _parse_indicator_line(source: Mapping[str, Any], value: str) -> str:
    """Apply only the parser explicitly reviewed for this source contract."""
    parser = str(source.get("line_parser") or "indicator")
    stripped = value.strip()
    if parser == "indicator":
        return stripped
    if parser == "maltrail":
        # Maltrail permits an IOC followed by a human comment (`IP # owner`).
        # Split only a whitespace-delimited comment marker so URL fragments
        # remain intact. Multi-token residues are rejected by canonicalization.
        return re.split(r"\s+#", stripped, maxsplit=1)[0].strip()
    raise SourceError(f"{source.get('id')}: unsupported reviewed line parser {parser!r}")


def _path_setting(source: Mapping[str, Any], relative: str, name: str, fallback: Any) -> Any:
    for pattern, selected in (source.get(f"{name}_by_path") or {}).items():
        if fnmatch.fnmatch(relative, str(pattern)):
            return selected
    return fallback


def ingest_source(
    source: Mapping[str, Any], config: Mapping[str, Any], state: State, log: AuditLog,
) -> Dict[str, Any]:
    source_id = str(source["id"])
    metrics = {"fetched": 0, "parsed": 0, "invalid": 0, "inserted": 0, "duplicate": 0, "canonical_match": 0, "removed": 0}
    prior = _source_state(state, source_id)
    cursor = json.loads(prior.get("cursor_json") or "{}")
    fetched_at = utcnow()
    revision = ""
    try:
        checkout, revision, is_new = _snapshot_checkout(source, Path(config["paths"]["state_dir"]), cursor)
        if cursor.get("complete", True) and not is_new:
            _save_source_state(
                state, source_id, revision=revision, cursor=cursor, status="unchanged",
                metrics=metrics, success=True,
            )
            log.emit("source_unchanged", source_id=source_id, revision=revision)
            return metrics

        files = _files(checkout, source, config["limits"])
        start_file = int(cursor.get("file_index", 0)) if cursor.get("revision") == revision else 0
        start_line = int(cursor.get("line_index", 0)) if cursor.get("revision") == revision else 0
        cap = min(
            int(source.get("max_records_per_run") or config["limits"]["max_new_records_per_source_run"]),
            max(0, int(config["limits"]["max_pending_records"]) - state.pending_count()),
        )
        if cap <= 0:
            raise SourceError("max_pending_records reached")
        completed = True
        next_file = start_file
        next_line = start_line
        auto_candidate = bool(source.get("auto_candidate", True))

        for file_index, line_index, path, value in _line_records(
            checkout, files, start_file=start_file, start_line=start_line,
            max_line_bytes=int(config["limits"]["max_line_bytes"]),
        ):
            next_file, next_line = file_index, line_index + 1
            raw_value = value.strip()
            if not raw_value or raw_value.startswith("#") or raw_value.startswith("//"):
                if not raw_value:
                    metrics["invalid"] += 1
                continue
            metrics["fetched"] += 1
            relative = path.relative_to(checkout).as_posix()
            try:
                indicator = _parse_indicator_line(source, raw_value)
                observation = _observation_from_line(source, revision, relative, indicator, fetched_at)
            except (ValueError, KeyError):
                metrics["invalid"] += 1
                if metrics["fetched"] >= cap:
                    completed = False
                    break
                continue
            metrics["parsed"] += 1
            outcome = state.insert_observation(observation, candidate=auto_candidate)
            metrics[outcome] += 1
            state.db.execute(
                """INSERT INTO source_members(
                  source_id,upstream_id,canonical_type,canonical_value,original_value,last_revision,active
                ) VALUES (?,?,?,?,?,?,1)
                ON CONFLICT(source_id,upstream_id) DO UPDATE SET
                  canonical_type=excluded.canonical_type,canonical_value=excluded.canonical_value,
                  original_value=excluded.original_value,last_revision=excluded.last_revision,active=1""",
                (
                    source_id, observation.upstream_id, observation.canonical_type,
                    observation.canonical_value, observation.original_value, revision,
                ),
            )
            if metrics["fetched"] >= cap:
                completed = False
                break

        if completed:
            removed = state.db.execute(
                "SELECT * FROM source_members WHERE source_id=? AND active=1 AND last_revision<>?",
                (source_id, revision),
            ).fetchall()
            if source.get("publish_removals", True):
                license_info = source["license"]
                for member in removed:
                    relative = str(member["upstream_id"]).split(":", 1)[0]
                    removal = Observation.build(
                        source_id=source_id,
                        upstream_id=str(member["upstream_id"]),
                        source_revision=revision,
                        original_value=str(member["original_value"]),
                        category=str(_path_setting(
                            source, relative, "category", source.get("category") or "uncategorized",
                        )),
                        lifecycle_status="inactive",
                        confidence=int(_path_setting(
                            source, relative, "confidence", source.get("confidence", 50),
                        )),
                        severity="informational",
                        license_id=str(license_info["id"]),
                        license_url=str(license_info["url"]),
                        attribution=str(license_info.get("attribution") or source_id),
                        references=[str(source["repository"])],
                        evidence="absent from completed source snapshot",
                        parser_version=PARSER_VERSION,
                        fetched_at=fetched_at,
                    )
                    state.insert_observation(removal, candidate=auto_candidate)
            state.db.execute(
                "UPDATE source_members SET active=0 WHERE source_id=? AND active=1 AND last_revision<>?",
                (source_id, revision),
            )
            metrics["removed"] = len(removed)
            cursor = {"complete": True, "last_complete_revision": revision}
            status = "complete"
        else:
            cursor = {
                "complete": False,
                "revision": revision,
                "file_index": next_file,
                "line_index": next_line,
                "last_complete_revision": cursor.get("last_complete_revision"),
            }
            status = "partial"
        _save_source_state(
            state, source_id, revision=revision, cursor=cursor, status=status,
            metrics=metrics, success=completed,
        )
        log.emit("source_ingested", source_id=source_id, revision=revision, status=status, metrics=metrics)
        return metrics
    except Exception as exc:
        _save_source_state(
            state, source_id, revision=revision, cursor=cursor, status="error",
            metrics=metrics, error=str(exc), success=False,
        )
        log.emit("source_error", source_id=source_id, error_type=type(exc).__name__, message=f"{source_id}: acquisition failed")
        raise


def ingest_all(config: Mapping[str, Any], state: State, log: AuditLog) -> Dict[str, Any]:
    aggregate: Dict[str, Any] = {"sources": {}, "errors": 0}
    for source in config.get("sources") or []:
        if not source.get("enabled", False):
            continue
        try:
            aggregate["sources"][source["id"]] = ingest_source(source, config, state, log)
        except Exception:
            aggregate["errors"] += 1
    return aggregate
