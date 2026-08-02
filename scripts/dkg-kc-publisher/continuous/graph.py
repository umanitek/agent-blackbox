"""Read-only, candidate-bound DKG checks used to prevent duplicate publishing."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, Mapping, Sequence

from .core import AuditLog, State, canonical_json, canonicalize_indicator, read_secret, utcnow


_PREDICATES = ("urn:defender:p:value", "urn:blackbox:p:normalizedValue")
_SYNC_STRATEGY = "confirmed-context-partition"
_UNSAFE_IRI = re.compile(r'[\x00-\x20<>"{}|\\^`]')


def _token(config: Mapping[str, Any]) -> str:
    value = read_secret(config["publisher"], "dkg_auth_token")
    for line in value.splitlines():
        candidate = line.strip()
        if candidate and not candidate.startswith("#"):
            return candidate
    raise RuntimeError("the protected DKG auth-token source contains no token")


def _endpoint(config: Mapping[str, Any]) -> str:
    publisher = config["publisher"]
    host = str(publisher.get("dkg_endpoint", "http://127.0.0.1")).rstrip("/")
    port = int(publisher.get("dkg_port", 8900))
    return f"{host}:{port}" if urllib.parse.urlsplit(host).port is None else host


def _confirmed_graph(config: Mapping[str, Any]) -> str:
    publisher = config["publisher"]
    context_graph_id = str(publisher.get("context_graph_id") or "")
    onchain_id = str(publisher.get("context_graph_onchain_id") or "")
    if not context_graph_id or not onchain_id:
        raise RuntimeError("graph deduplication requires the context graph and its on-chain ID")
    iri = f"did:dkg:context-graph:{context_graph_id}/context/{onchain_id}"
    if _UNSAFE_IRI.search(iri):
        raise RuntimeError("the configured context graph cannot be represented as a safe graph IRI")
    return iri


def _binding_value(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("value") or "")
    text = str(value or "")
    if text.startswith('"'):
        escaped = False
        chars: list[str] = []
        for character in text[1:]:
            if character == '"' and not escaped:
                break
            chars.append(character)
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
        try:
            return json.loads('"' + "".join(chars) + '"')
        except json.JSONDecodeError:
            return "".join(chars)
    return text


def _rows(response: Any) -> Iterable[Mapping[str, Any]]:
    if not isinstance(response, dict):
        return ()
    candidates = response.get("bindings")
    if candidates is None and isinstance(response.get("results"), dict):
        candidates = response["results"].get("bindings")
    if candidates is None and isinstance(response.get("result"), dict):
        candidates = response["result"].get("bindings")
    if not isinstance(candidates, list):
        raise RuntimeError("DKG query returned an unrecognized binding shape")
    return (row for row in candidates if isinstance(row, dict))


def _query(config: Mapping[str, Any], token: str, sparql: str) -> Dict[str, Any]:
    request = urllib.request.Request(
        f"{_endpoint(config)}/api/query",
        data=canonical_json({"sparql": sparql}),
        headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
        method="POST",
    )
    timeout = int(config["graph_dedupe"]["query_timeout_seconds"])
    attempts = int(config["graph_dedupe"].get("query_attempts", 3))
    retry_delay = int(config["graph_dedupe"].get("query_retry_delay_seconds", 5))
    body: Any = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read())
            break
        except urllib.error.HTTPError as exc:
            raw_detail = exc.read().decode("utf-8", errors="replace")[:1000]
            try:
                parsed_detail = json.loads(raw_detail)
                detail = str(parsed_detail.get("error") or parsed_detail.get("message") or "")
            except json.JSONDecodeError:
                detail = raw_detail
            suffix = f": {detail[:500]}" if detail else ""
            if exc.code not in {429, 500, 502, 503, 504} or attempt == attempts:
                raise RuntimeError(f"DKG graph query returned HTTP {exc.code}{suffix}") from exc
        except (TimeoutError, urllib.error.URLError) as exc:
            if attempt == attempts:
                raise RuntimeError(
                    f"DKG graph query transport failed after {attempts} attempts"
                ) from exc
        time.sleep(min(retry_delay * attempt, 60))
    if not isinstance(body, dict):
        raise RuntimeError("DKG graph query returned a non-object response")
    return body


def _probe_confirmed_graph(config: Mapping[str, Any], token: str) -> None:
    graph = _confirmed_graph(config)
    sparql = f"SELECT ?subject WHERE {{ GRAPH <{graph}> {{ ?subject ?predicate ?object }} }} LIMIT 1"
    if not list(_rows(_query(config, token, sparql))):
        raise RuntimeError("the confirmed context-graph partition is empty or unavailable")


def _query_values(config: Mapping[str, Any], token: str, values: Sequence[str]) -> set[str]:
    if not values:
        return set()
    graph = _confirmed_graph(config)
    literals = " ".join(json.dumps(value, ensure_ascii=False) for value in values)
    predicates = " ".join(f"<{value}>" for value in _PREDICATES)
    sparql = f"""SELECT DISTINCT ?indicator WHERE {{
  GRAPH <{graph}> {{
    VALUES ?indicator {{ {literals} }}
    VALUES ?predicate {{ {predicates} }}
    ?entity ?predicate ?indicator .
  }}
}}"""
    requested = set(values)
    result: set[str] = set()
    for row in _rows(_query(config, token, sparql)):
        value = _binding_value(row.get("indicator"))
        if value not in requested:
            raise RuntimeError("DKG candidate query returned a value outside its bounded input set")
        result.add(value)
    return result


def _candidate_records(state: State) -> list[Mapping[str, Any]]:
    return list(state.db.execute(
        """SELECT canonical_id,canonical_type,canonical_value
           FROM observations o
           WHERE state='candidate'
             AND NOT EXISTS (
               SELECT 1 FROM graph_entities g WHERE g.canonical_id=o.canonical_id
             )
           GROUP BY canonical_id,canonical_type,canonical_value
           ORDER BY MIN(fetched_at),canonical_id"""
    ).fetchall())


def _bundle_records(state: State, bundle_id: str) -> list[Mapping[str, Any]]:
    return list(state.db.execute(
        """SELECT o.canonical_id,o.canonical_type,o.canonical_value
           FROM bundle_observations bo
           JOIN observations o ON o.observation_id=bo.observation_id
           WHERE bo.bundle_id=?
           GROUP BY o.canonical_id,o.canonical_type,o.canonical_value
           ORDER BY MIN(bo.position),o.canonical_id""",
        (bundle_id,),
    ).fetchall())


def _check_records(
    config: Mapping[str, Any], token: str, records: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    by_value = {str(row["canonical_value"]): row for row in records}
    values = list(by_value)
    batch_size = int(config["graph_dedupe"]["query_batch_size"])
    existing_values: set[str] = set()
    for offset in range(0, len(values), batch_size):
        existing_values.update(_query_values(config, token, values[offset:offset + batch_size]))

    existing: Dict[str, Mapping[str, Any]] = {}
    for value in existing_values:
        canonical = canonicalize_indicator(value)
        row = by_value.get(canonical.value)
        if row is None or canonical.entity_id != row["canonical_id"]:
            raise RuntimeError("DKG candidate canonicalization did not match durable state")
        existing[canonical.entity_id] = row
    return {"checked": len(records), "existing": existing}


def _store_existing(state: State, existing: Mapping[str, Mapping[str, Any]], observed_at: str) -> None:
    with state.transaction() as db:
        for canonical_id, record in existing.items():
            db.execute(
                """INSERT INTO graph_entities(
                     canonical_id,canonical_type,canonical_value,views_json,first_seen_at,last_seen_at
                   ) VALUES (?,?,?,?,?,?)
                   ON CONFLICT(canonical_id) DO UPDATE SET
                     canonical_type=excluded.canonical_type,
                     canonical_value=excluded.canonical_value,
                     views_json=excluded.views_json,
                     last_seen_at=excluded.last_seen_at""",
                (
                    canonical_id, record["canonical_type"], record["canonical_value"],
                    canonical_json([_SYNC_STRATEGY]).decode(), observed_at, observed_at,
                ),
            )


def _supersede_bundle(
    state: State, bundle_id: str, existing: Mapping[str, Mapping[str, Any]],
) -> None:
    """Cancel a not-yet-published manifest and safely requeue its clean rows."""
    canonical_ids = sorted(existing)
    placeholders = ",".join("?" for _ in canonical_ids)
    reason = f"graph recheck found {len(canonical_ids)} already-published canonical indicators"
    with state.transaction() as db:
        row = db.execute("SELECT state FROM bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown bundle {bundle_id}")
        if row["state"] not in {"bundled", "approved"}:
            raise RuntimeError(f"bundle {bundle_id} is {row['state']}, not safely supersedable")
        db.execute(
            "UPDATE bundles SET state='superseded',last_error=? WHERE bundle_id=?",
            (reason, bundle_id),
        )
        db.execute(
            f"""UPDATE observations SET state='graph_duplicate'
                WHERE bundle_id=? AND canonical_id IN ({placeholders})""",
            (bundle_id, *canonical_ids),
        )
        db.execute(
            f"""UPDATE observations SET state='candidate',bundle_id=NULL
                WHERE bundle_id=? AND state='bundled'
                  AND canonical_id NOT IN ({placeholders})""",
            (bundle_id, *canonical_ids),
        )


def sync_graph_entities(config: Mapping[str, Any], state: State, log: AuditLog) -> Dict[str, Any]:
    """Check only pending canonical values against the confirmed graph partition.

    DKG view-wide joins over hundreds of per-KA partitions are both expensive and
    unreliable for this inventory shape. A bounded VALUES query against the
    confirmed per-context-graph partition uses exact object lookups and proves
    each candidate immediately before it can enter an approval bundle.
    """
    graph = config["graph_dedupe"]
    if not graph.get("enabled", False):
        return {"status": "disabled"}
    token = _token(config)
    _probe_confirmed_graph(config, token)
    records = _candidate_records(state)
    result = _check_records(config, token, records)
    synced_at = utcnow()
    _store_existing(state, result["existing"], synced_at)
    with state.transaction() as db:
        db.execute(
            """INSERT INTO graph_sync(
                 singleton,synced_at,context_graph_id,rows_seen,entities_seen,views_json
               ) VALUES (1,?,?,?,?,?)
               ON CONFLICT(singleton) DO UPDATE SET
                 synced_at=excluded.synced_at,context_graph_id=excluded.context_graph_id,
                 rows_seen=excluded.rows_seen,entities_seen=excluded.entities_seen,
                 views_json=excluded.views_json""",
            (
                synced_at, str(config["publisher"]["context_graph_id"]), result["checked"],
                len(result["existing"]), canonical_json([_SYNC_STRATEGY]).decode(),
            ),
        )
    log.emit(
        "graph_sync_complete", candidates_checked=result["checked"],
        existing_entities=len(result["existing"]), strategy=_SYNC_STRATEGY,
        message=(
            f"graph check tested {result['checked']} pending indicators; "
            f"excluded {len(result['existing'])} already published"
        ),
    )
    return {
        "status": "complete", "candidates_checked": result["checked"],
        "existing_entities": len(result["existing"]), "synced_at": synced_at,
        "strategy": _SYNC_STRATEGY,
    }


def assert_bundle_absent_from_graph(
    config: Mapping[str, Any], state: State, bundle_id: str,
) -> Dict[str, Any]:
    """Recheck an immutable bundle immediately before approval or publication."""
    if not config["graph_dedupe"].get("enabled", False):
        raise RuntimeError("graph deduplication is disabled")
    token = _token(config)
    records = _bundle_records(state, bundle_id)
    result = _check_records(config, token, records)
    observed_at = utcnow()
    _store_existing(state, result["existing"], observed_at)
    if result["existing"]:
        _supersede_bundle(state, bundle_id, result["existing"])
        raise RuntimeError(
            f"bundle was superseded because {len(result['existing'])} canonical indicators are already in the graph"
        )
    return {
        "status": "absent", "checked": result["checked"],
        "checked_at": observed_at, "strategy": _SYNC_STRATEGY,
    }


def required_sync_strategy() -> str:
    return _SYNC_STRATEGY
