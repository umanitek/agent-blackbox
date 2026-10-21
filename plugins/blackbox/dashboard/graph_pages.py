"""The dashboard's graph pages: how a tier's threats become one page.

Lifted out of ``server.py`` (at its size alarm) as pure functions, so the
``/api/graph`` and ``/api/threat`` handlers stay thin:

* :func:`_graph_entries` — a ruleset's threats of one source, in graph-entry shape.
* :func:`_balanced_graph_entries` — the front page shows a sample of every category.
* :func:`tier_response` — the page dict (totals describe the whole filtered result).
* :func:`public_tier_response` — the public page: compiled small-tier entries first,
  then the live dependency / IOC tiers from the node's store (DKG-lookup B7).
* :func:`compiled_rule` / :func:`rule_for` — the rule behind one identifier (live
  lookup for a public ``dep:`` / ``ioc:`` identifier).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..kernel import threat_ids
from .safe_payloads import graph_tier_item, safe_identifier, safe_text


def _graph_entries(rs: Any, source: str) -> list[dict[str, Any]]:
    getter = getattr(rs, "graph_entries", None)
    if callable(getter):
        entries = getter(source) or []
        return entries if isinstance(entries, list) else list(entries)
    return [
        {
            "identifier": rule.get("identifier"),
            "category": category,
            "severity": str(rule.get("severity") or "info").lower(),
            "name": rule.get("name") or "",
            "subject": rule.get("subject") or "",
            "source": source,
        }
        for category, rule in rs.iter_rules()
        if rule.get("source") == source
    ]


def _balanced_graph_entries(
    entries: list[dict[str, Any]], minimum_per_category: int = 24
) -> list[dict[str, Any]]:
    """Front-load a small sample of every populated threat category."""
    category_order = (
        "dependency", "injection", "escalation", "fileaccess",
        "skill", "secret", "ioc", "other",
    )
    buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in category_order}
    for entry in entries:
        key = str(entry.get("category") or "other").lower()
        buckets.setdefault(key, []).append(entry)

    front: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    ordered_keys = category_order + tuple(k for k in buckets if k not in category_order)
    for key in ordered_keys:
        skipped[key] = min(len(buckets.get(key, [])), minimum_per_category)
    for index in range(minimum_per_category):
        for key in ordered_keys:
            bucket = buckets.get(key, [])
            if index < len(bucket):
                front.append(bucket[index])

    rest: list[dict[str, Any]] = []
    consumed: dict[str, int] = {}
    for entry in entries:
        key = str(entry.get("category") or "other").lower()
        used = consumed.get(key, 0)
        if used < skipped.get(key, 0):
            consumed[key] = used + 1
            continue
        rest.append(entry)
    return front + rest


def tier_response(tier: str, all_threats: list[dict[str, Any]], offset: int, limit: int) -> dict[str, Any]:
    """One page of *all_threats* (already filtered) with totals for the WHOLE result.

    Counts describe the complete filtered result, never the rendered page, so the
    dashboard can show the real threat magnitude on category / ecosystem hubs
    while progressively loading leaves.
    """
    category_totals: dict[str, int] = {}
    ecosystem_totals: dict[str, int] = {}
    for item in all_threats:
        item_category = str(item.get("category") or "other").lower()
        category_totals[item_category] = category_totals.get(item_category, 0) + 1
        if item_category == "dependency":
            parts = str(item.get("identifier") or "").split(":")
            ecosystem_name = (parts[1] if len(parts) > 1 else "other").lower()
            ecosystem_totals[ecosystem_name] = ecosystem_totals.get(ecosystem_name, 0) + 1
    return {
        "tier": tier,
        "threats": all_threats[offset:offset + limit],
        "total": len(all_threats),
        "category_totals": category_totals,
        "ecosystem_totals": ecosystem_totals,
        "offset": offset,
        "limit": limit,
        "partial": offset + limit < len(all_threats),
    }


def compiled_rule(rs: Any, tier: str, identifier: str) -> dict[str, Any]:
    """The compiled rule of *tier* with this *identifier*, else its graph entry, else {}."""
    try:
        for _cat, rule in rs.iter_rules():
            if rule.get("source") == tier and rule.get("identifier") == identifier:
                return rule
    except Exception:
        pass
    try:
        return next(item for item in _graph_entries(rs, tier) if item.get("identifier") == identifier)
    except Exception:
        return {}


def public_tier_response(rs: Any, compiled: list[dict[str, Any]], *, needle: str, category: str, ecosystem: str,
                         offset: int, limit: int) -> dict[str, Any]:
    """The public page: *compiled* entries (small tiers, already filtered and
    shaped) occupy the first positions, the live tiers follow — one window from
    the store for the part of ``[offset, offset+limit)`` past the compiled ones.
    Totals cover both; when the store could not answer, the page says so
    (``live_unavailable``) and the live totals fall back to the scope's counts.
    A ruleset without a live scope answers exactly as before."""
    page = compiled[offset:offset + limit]
    browse = getattr(rs, "live_browse", None)
    live = browse(category=category, ecosystem=ecosystem, needle=needle, offset=max(0, offset - len(compiled)),
                  limit=limit - len(page)) if callable(browse) else None
    if live is None:
        return tier_response("public", compiled, offset, limit)
    response = tier_response("public", compiled, 0, len(compiled))
    response["threats"] = page + [graph_tier_item(entry, community=False) for entry in live.entries]
    for kind, count in live.kind_totals.items():
        response["category_totals"][kind] = response["category_totals"].get(kind, 0) + count
    for name, count in live.ecosystem_totals.items():
        response["ecosystem_totals"][name] = response["ecosystem_totals"].get(name, 0) + count
    response["total"] = len(compiled) + live.total
    response.update(offset=offset, limit=limit, partial=offset + limit < len(compiled) + live.total)
    if not live.known:
        response["live_unavailable"] = live.reason or "the node's store did not answer"
    if live.capped:
        response["total_capped"] = True   # a search stopped counting at the cap: "N or more"
    return response


def rule_for(rs: Any, tier: str, identifier: str) -> dict[str, Any]:
    """:func:`compiled_rule`, then — for a public ``dep:`` / ``ioc:`` identifier —
    the live lookup, which carries the rule's subject for the detail read."""
    found = compiled_rule(rs, tier, identifier)
    if found or tier != "public":
        return found
    return _live_rule(rs, identifier) or {}


def verified_profile(rs: Any, identifier: str) -> dict[str, Any]:
    """What this node's OWN verified copy says a community threat is (threat profiles):
    its name, description, kind and — for an injection — the pattern text. A community
    report only names the threat; the reader supplies the rest from data it already
    trusts, so nothing describing it ever has to travel. Empty when the verified graph
    does not list the identifier."""
    try:
        rule = rule_for(rs, "public", identifier)
    except Exception:   # fail open: a down store means "no verified description", never an error
        rule = {}
    if not rule:
        return {}
    out = {"verified": True}
    for key in ("name", "description", "kind"):
        if rule.get(key):
            out[key] = str(rule[key])
    if rule.get("pattern_src"):
        out["pattern"] = str(rule["pattern_src"])
    return out


def _live_rule(rs: Any, identifier: str) -> Optional[dict[str, Any]]:
    parsed = threat_ids.parse_dependency_identifier(identifier)
    if parsed is not None and callable(getattr(rs, "dependency_rules", None)):
        return next((rule for rule in rs.dependency_rules([parsed]).rules.values()
                     if rule.get("identifier") == identifier), None)
    if identifier.startswith("ioc:") and callable(getattr(rs, "ioc_rules", None)):
        return rs.ioc_rules([identifier]).rules.get(identifier)
    return None


def page_response(rs: Any, tier: str, threats: list[dict[str, Any]], *, needle: str, category: str, ecosystem: str,
                  offset: int, limit: int) -> dict[str, Any]:
    """The page for *tier*: the public tier gets the live dependency / IOC tiers
    after its compiled entries; the community tier is its filtered list alone."""
    if tier == "public":
        return public_tier_response(rs, threats, needle=needle, category=category, ecosystem=ecosystem,
                                    offset=offset, limit=limit)
    return tier_response(tier, threats, offset, limit)


def community_threat(rs: Any, identifier: str) -> dict[str, Any]:
    """Shape a sanitized threat detail from the aggregated community store."""
    rule = (getattr(rs, "community", {}) or {}).get(identifier)
    if not rule:
        return {"identifier": safe_identifier(identifier), "tier": "community", "found": False}
    detail = {safe_text(k, 64): (safe_text(v) if isinstance(v, str) else v) for k, v in rule.items()}
    detail.update({
        "identifier": safe_identifier(identifier), "tier": "community", "found": True,
        "reporters": int(rule.get("reporterCount") or 0), **verified_profile(rs, identifier),
    })
    return detail
