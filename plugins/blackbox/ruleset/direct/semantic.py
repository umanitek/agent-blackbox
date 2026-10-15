"""Vector candidates followed by authoritative, owner-pinned VM hydration."""
import math
from collections import defaultdict

from ...kernel.dkg_client import extract_binding
from .client import LocalGraphClient, GraphReadUnavailable
from .reader import compile_reply, validate_config
from .view import _selected_triples
from .. import curator_tier


# Descriptions and names carry behavioral meaning; do not embed the bulk IOC list.
INDEX_SPEC = {"view": "verifiable-memory", "types": ["urn:defender:InjectionSignal", "urn:defender:SkillSignal"],
              "textPredicates": ["http://schema.org/name", "http://schema.org/description"]}


def semantic_candidates(cfg, text, *, client=None):
    validate_config(cfg)
    client = client or LocalGraphClient(cfg, budget_s=min(5.0, cfg.semantic.budget_s))
    reply = client.request("POST", "/api/entities/search", {
        "contextGraphId": cfg.context_graph_id, "indexId": cfg.semantic.index_id,
        "query": text, "limit": cfg.semantic.max_candidates, "timeoutMs": 2000})
    if (reply.get("version") != 1 or reply.get("contextGraphId") != cfg.context_graph_id
            or reply.get("view") != "verifiable-memory" or reply.get("indexId") != cfg.semantic.index_id
            or reply.get("coverage") != "local-indexed-subset" or reply.get("freshness") != "candidates-revalidated"):
        raise GraphReadUnavailable("SEMANTIC_RESPONSE_INVALID")
    entities = reply.get("entities")
    if not isinstance(entities, list) or len(entities) > cfg.semantic.max_candidates:
        raise GraphReadUnavailable("SEMANTIC_RESPONSE_INVALID")
    pairs = []
    for row in entities:
        if not isinstance(row, dict) or not isinstance(row.get("score"), (int, float)) or not math.isfinite(row["score"]):
            raise GraphReadUnavailable("SEMANTIC_RESPONSE_INVALID")
        pairs.append({"sourceGraph": row.get("sourceGraph"), "threat": row.get("entityUri")})
    if not pairs:
        return [], {"coverage": reply["coverage"], "scan_complete": reply.get("scanComplete"), "candidates": 0}
    hydrated = _selected_triples(cfg, client, pairs)
    rs = compile_reply(cfg, hydrated)  # applies correction/suppress records, including description-only threats
    curator_tier.apply_curator_tier(rs, client, cfg)
    if getattr(rs, "curator_read_unavailable", False) or getattr(client, "failure_code", ""):
        raise GraphReadUnavailable("QUERY_AUTHORITY_UNAVAILABLE")
    allowed = {r["subject"]: r for r in rs.graph_entries("public") if r["category"] in {"injection", "skill"}}
    evidence = _evidence(hydrated, entities, allowed)
    return evidence, {"coverage": reply["coverage"], "scan_complete": reply.get("scanComplete"),
                      "candidates": len(evidence), "stale_candidates": reply.get("staleCandidates", 0),
                      "observed_at": hydrated["observedAt"]}


def _evidence(reply, entities, allowed):
    props = defaultdict(lambda: defaultdict(set))
    assets = defaultdict(set)
    for row in reply["result"]["bindings"]:
        key = (extract_binding(row["sourceGraph"]), extract_binding(row["threat"]))
        props[key][extract_binding(row["p"])].add(extract_binding(row["o"]))
        assets[key].add(extract_binding(row["ka"]))
    results = []
    for candidate in entities:
        subject, graph = candidate["entityUri"], candidate["sourceGraph"]
        key = (graph, subject)
        if subject not in allowed or key not in props:
            continue
        facts = props[key]
        text = "\n".join(sorted(facts.get("http://schema.org/name", set()) | facts.get("http://schema.org/description", set())))
        if not text or len(text) > 6000:
            continue
        results.append({"entity_uri": subject, "source_graph": graph, "assets": sorted(assets[key]),
                        "identifier": allowed[subject]["identifier"], "category": allowed[subject]["category"],
                        "text": text, "score": candidate["score"]})
    return results
