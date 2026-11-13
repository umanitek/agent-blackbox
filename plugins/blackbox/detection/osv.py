"""Client-side OSV vulnerability lookup for dependency auto-discovery.

A tiny, dependency-free helper around ``https://api.osv.dev/v1/query``. It is
the DISCOVERY nomination layer for dependencies: when an install is detected
whose package is NOT already in the graph ruleset, :func:`lookup` asks OSV
whether that exact ``package@version`` is known-vulnerable. If so, the caller
auto-submits a *candidate* dependency threat.

Design constraints (all enforced here):

* **stdlib only** — ``urllib``; no new third-party dependency.
* **fail-open** — any transport/parse error returns ``None`` (no finding).
* **short timeout** — never delays the agent loop meaningfully.
* **privacy** — only OSV-*vulnerable* installs are ever surfaced; a clean
  package returns ``None`` and is never reported.
* **cached** — an in-memory dedupe cache keyed by ``eco:name@version`` so a
  repeated install in the same process makes at most one network call.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any, Optional

from ..kernel import constants

logger = logging.getLogger(__name__)

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 3.0

#: Blackbox ecosystem slug → OSV ecosystem name. ``homebrew`` has no OSV
#: ecosystem, so it is intentionally absent (skipped, never looked up).
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
}
#: The package ecosystems Blackbox names dependencies in (Refine R1 vocabulary).
DEPENDENCY_ECOSYSTEMS = frozenset(_ECOSYSTEM_MAP)
#: OSV's malicious-package database uses MAL- advisory ids; every other OSV
#: advisory describes a vulnerability.
MALWARE_ADVISORY_PREFIX = "MAL-"


def advisory_kind(advisory_id: Optional[str]) -> str:
    """``"malware"`` for an OSV malicious-package advisory, else ``"vulnerability"``."""
    return "malware" if str(advisory_id or "").upper().startswith(MALWARE_ADVISORY_PREFIX) else "vulnerability"


def advisory_reason(advisory_id: Optional[str]) -> Optional[str]:
    """``advisory:<id>`` — the report reason an advisory gives (plan §04) — or None."""
    return f"{constants.ADVISORY_REASON_PREFIX}{advisory_id}" if advisory_id else None

# In-memory result cache. Value is the finding dict or None (clean/skip).
_cache: dict[str, Optional[dict[str, str]]] = {}
_cache_lock = threading.Lock()


def osv_ecosystem(ecosystem: str) -> Optional[str]:
    """Map a Blackbox ecosystem slug to its OSV name, or ``None`` to skip."""
    return _ECOSYSTEM_MAP.get((ecosystem or "").strip().lower())


def _severity_of(vuln: dict[str, Any]) -> str:
    """Severity of an OSV record as a level on Blackbox's ladder: OSV's own label, with its
    ``moderate`` read as ``medium``; ``high`` when it gives none or one the ladder lacks (a
    label outside the ladder ranks below every threshold, so the finding would vanish)."""
    return constants.normalize_severity(_severity_label(vuln), fallback="high")


def _severity_label(vuln: dict[str, Any]) -> str:
    """The severity label an OSV record carries, as written (lower-case); "" when none."""
    # OSV database_specific.severity is the most common human label.
    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        raw = str(dbs.get("severity") or "").strip().lower()
        if raw:
            return raw
    # Fall back to ecosystem-specific severity blocks when present.
    for aff in vuln.get("affected") or []:
        if isinstance(aff, dict):
            aff_dbs = aff.get("database_specific")
            if isinstance(aff_dbs, dict):
                raw = str(aff_dbs.get("severity") or "").strip().lower()
                if raw:
                    return raw
    return ""


def _query(osv_eco: str, name: str, version: str) -> Optional[dict[str, Any]]:
    body = json.dumps({"package": {"ecosystem": osv_eco, "name": name}, "version": version}).encode("utf-8")
    req = urllib.request.Request(
        _OSV_URL, data=body, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
        logger.debug("blackbox: OSV query failed for %s@%s: %s", name, version, exc)
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:  # pragma: no cover - defensive
        return None


def lookup(ecosystem: str, name: str, version: str) -> Optional[dict[str, str]]:
    """Return ``{advisory_id, severity, kind}`` if OSV knows *name@version* bad.

    ``kind`` is ``malware`` when any advisory is a malicious-package (MAL-)
    one — that advisory is the one returned — else ``vulnerability``.
    Returns ``None`` when the package is clean, the ecosystem is unsupported,
    the version is missing, or anything fails (fail-open). An ANSWER is cached per
    process; a query that failed is not, so the package is asked about again.
    """
    eco = (ecosystem or "").strip().lower()
    name = (name or "").strip()
    version = (version or "").strip()
    if not name or not version:
        return None
    osv_eco = osv_ecosystem(eco)
    if not osv_eco:
        return None
    key = f"{eco}:{name.lower()}@{version}"
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    answer = _query(osv_eco, name, version)
    if not isinstance(answer, dict):
        return None   # could not ask: not "clean", and not remembered
    result = _finding(answer)
    with _cache_lock:
        _cache[key] = result
    return result


def advisory_status(ecosystem: str, name: str, version: str) -> tuple[str, Optional[dict[str, str]]]:
    """Like :func:`lookup`, but "nothing found" and "could not ask" are told
    apart: ``("found", {advisory_id, severity, kind})``, ``("clean", None)``
    when OSV answered and names no advisory, ``("unavailable", None)`` when the
    query failed or the package cannot be asked about (no version, an
    ecosystem OSV does not cover). Never cached: unavailable is transient. The
    curator service decides on this — a failed query must not read as clean."""
    eco, name, version = (ecosystem or "").strip().lower(), (name or "").strip(), (version or "").strip()
    osv_eco = osv_ecosystem(eco)
    if not name or not version or not osv_eco:
        return "unavailable", None
    data = _query(osv_eco, name, version)
    if not isinstance(data, dict):
        return "unavailable", None
    finding = _finding(data)
    return ("found", finding) if finding is not None else ("clean", None)


def _finding(data: Optional[dict[str, Any]]) -> Optional[dict[str, str]]:
    """``{advisory_id, severity, kind}`` from one OSV answer, or None when it
    names no advisory (or is no answer at all)."""
    if not isinstance(data, dict):
        return None
    vulns = data.get("vulns")
    if not isinstance(vulns, list) or not vulns:
        return None
    records = [v for v in vulns if isinstance(v, dict)] or [{}]
    # A malicious-package advisory outranks any vulnerability advisory.
    first = next((v for v in records if advisory_kind(v.get("id")) == "malware"), records[0])
    advisory_id = str(first.get("id") or "OSV")
    return {"advisory_id": advisory_id, "severity": _severity_of(first), "kind": advisory_kind(advisory_id)}
