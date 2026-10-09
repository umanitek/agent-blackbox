"""Action-scoped detection reads from local DKG; no exported graph cache."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..ruleset.compiler import Ruleset, build_from_rows
from ..ruleset.partitions.rows import rows_from_triples
from ..ruleset import curator_tier
from ..kernel.dkg_client import extract_binding, DkgError
from .client import GraphReadUnavailable, LocalGraphClient, local_url
from .queries import candidate_query, candidates


@dataclass
class DetectionRead:
    rules: Ruleset
    state: str = "unavailable"
    code: str = "QUERY_UNAVAILABLE"
    query_id: str = ""
    observed_at: str = ""

    def evidence(self):
        return {"backend": "dkg", "state": self.state, "code": self.code,
                "coverage": "local-confirmed-subset", "graph_complete": None, "query_id": self.query_id,
                "observed_at": self.observed_at}


def read_for_action(cfg, tool: str, args, *, client=None) -> DetectionRead:
    result = DetectionRead(Ruleset(context_graph_id=cfg.context_graph_id))
    try:
        validate_config(cfg)
        client = client or LocalGraphClient(cfg)
        identifiers, packages = candidates(tool, args)
        reply = client.bounded(candidate_query(cfg.context_graph_id, identifiers, packages), cfg.context_graph_id)
        result.rules = compile_reply(cfg, reply)
        curator_tier.apply_curator_tier(result.rules, client, cfg)
        if getattr(result.rules, "curator_read_unavailable", False):
            raise GraphReadUnavailable("QUERY_AUTHORITY_UNAVAILABLE")
        if getattr(client, "failure_code", ""):
            raise GraphReadUnavailable(client.failure_code)
        result.state, result.code = "available", ""
        result.query_id, result.observed_at = reply["queryId"], reply["observedAt"]
    except GraphReadUnavailable as exc:
        result.code = exc.code
    except ValueError:
        result.code = "QUERY_RULE_LIMIT"
    except DkgError:
        result.code = "QUERY_UNAVAILABLE"
    except Exception:
        # A malformed rule/adapter must never bypass independent local checks.
        result.code = "QUERY_MALFORMED_RESPONSE"
    return result


def validate_config(cfg):
    """Reject unsupported combinations, never silently omit a protection tier.

    Community's persisted reader-day budgets and 90-day retention require a
    separate migration. Its existing backend remains available unchanged.
    """
    if cfg.community_graph_id:
        raise GraphReadUnavailable("DIRECT_COMMUNITY_MIGRATION_REQUIRED")
    local_url(cfg.dkg_url)  # validate locality even when a test injects a reader


def compile_reply(cfg, reply):
    """Compile only a bounded query result. It is never stored or shared across profiles."""
    partitions = defaultdict(list)
    provenance = defaultdict(set)
    for row in reply["result"]["bindings"]:
        if any(not extract_binding(row.get(key)) for key in ("sourceGraph", "ka", "threat", "p")) or "o" not in row:
            raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE")
        provenance[extract_binding(row["threat"])].add((extract_binding(row["sourceGraph"]), extract_binding(row["ka"])))
        partitions[extract_binding(row["sourceGraph"])].append(tuple(extract_binding(row[key]) for key in ("threat", "p", "o")))
    rows = []
    for graph, triples in sorted(partitions.items()):
        rows.extend(rows_from_triples(graph, triples, max_rows=2048 - len(rows)))
    rules = build_from_rows(rows)
    rules.context_graph_id = cfg.context_graph_id
    for _, rule in rules.iter_rules():
        rule["graph_provenance"] = [{"assertion_graph": graph, "asset": ka}
                                    for graph, ka in sorted(provenance.get(rule.get("subject"), ()))]
    return rules
