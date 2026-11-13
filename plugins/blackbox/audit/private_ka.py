"""The private working-memory audit record kept in the local DKG node.

Redacted-but-local evidence stays in the node's PRIVATE working memory — never
shared to SWM — in a graph this node owns (:mod:`.local_graph`). Best-effort; a
failed write is logged as a warning, never swallowed silently.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlsplit
from typing import Any
from ..kernel import constants, local_http
from . import redaction

logger = logging.getLogger(__name__)

def node_is_local(url: str) -> bool:
    """Whether a DKG node URL points at THIS machine (KI-223). The private audit record
    carries redacted command/prompt text; it may only ever be written to a node on the
    same host — a remote ``dkg_url`` (a shared bench node, a cloud node) is not "local".
    An empty URL counts as local (the default is loopback); one that cannot be read does
    not — this is a privacy gate, and it answers "no" when it cannot tell."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    return not host or local_http.is_loopback_host(host)


def write_private_audit_ka(client: Any, cg_id: str, event: str, finding: dict[str, Any]) -> None:
    """Write a private WM audit KA carrying the observed command/prompt.

    Privacy split: the redacted-but-local evidence lives in the node's private
    working memory, never shared to SWM, and ONLY when the node is on this
    machine (KI-223: with a remote ``dkg_url`` the text would leave the host).
    Best-effort — failures are swallowed.
    """
    from ..kernel import rdf_terms, threat_ids

    if not node_is_local(str(getattr(client, "url", "") or "")):
        logger.debug("blackbox: private audit record skipped — the DKG node is not on this machine")
        return
    try:
        ident = str(finding.get("identifier") or "unknown")
        ts = rdf_terms.datetime_literal()
        subj = f"urn:guardian:audit:{threat_ids.stable_hash(ident + str(time.time()), 24)}"
        q = [
            {"subject": subj, "predicate": constants.RDF_TYPE, "object": f"{constants.BLACKBOX_ONTOLOGY}AuditRecord"},
            {"subject": subj, "predicate": constants.IDENTIFIER_PRED, "object": rdf_terms.literal(ident)},
            {"subject": subj, "predicate": constants.SEVERITY_PRED, "object": rdf_terms.literal(str(finding.get("severity") or "info"))},
            {"subject": subj, "predicate": constants.SCHEMA_DESCRIPTION_PRED, "object": rdf_terms.literal(redaction.sanitize_text(str(finding.get("evidence") or ""), 1200))},
            {"subject": subj, "predicate": constants.SCHEMA_DATE_MODIFIED_PRED, "object": ts},
        ]
        # Private: create+write+seal in WM, do NOT share to SWM.
        client.write_private_knowledge_asset(cg_id, subj.rsplit(":", 1)[-1], q)
    except Exception as exc:  # pragma: no cover - fail open, but never silently (the Local tab depends on it)
        logger.warning("blackbox: private audit record not written to %s: %s", cg_id, exc)
