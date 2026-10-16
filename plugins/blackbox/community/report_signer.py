"""Signing community statements — proof of who sent a report or dispute (R0b).

Every report and dispute this node shares carries a signed envelope
(:mod:`..kernel.signing`) made with this node's reporter key
(:mod:`..kernel.reporter_key`). The signature is bound to:

* the statement type — ``blackbox.report``, ``blackbox.dispute`` or
  ``blackbox.retract``;
* the environment — the DKG network id the node runs on, so a statement
  signed on a test network can never be replayed on mainnet;
* the graph it is shared to — the verified graph, whose shared memory the
  community lives in (one graph, 2026-10-16).

A node that cannot sign does not share (fail closed): an unsigned report would
be indistinguishable from a forged one to every reader (LES-014).

Usage::

    signer = report_signer.resolve_report_signer(client, cfg.context_graph_id)
    if signer is None:
        ...refuse to share...
    quads = build_report_quads(..., signer=signer)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..kernel import reporter_key, signing
from ..kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)

REPORT_STATEMENT = "blackbox.report"
DISPUTE_STATEMENT = "blackbox.dispute"
RETRACT_STATEMENT = "blackbox.retract"   # Refine R1: a reporter withdrawing its own report
DIGEST_STATEMENT = "blackbox.digest"     # Refine R2b: a reporter's weekly sighting digest
#: Bump when the signed payload's fields change meaning (readers check it).
#: 2 (threat profiles, 2026-10-12): a report may carry the sighting fields.
#: A reader sets aside fields it does not know ONLY from a statement of a
#: newer schema than its own (``verification``); at its own version they are refused.
STATEMENT_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class ReportSigner:
    """Everything needed to sign this node's community statements.

    ``private_key`` — the reporter key; ``environment`` — the DKG network id;
    ``graph`` — the graph the statements are shared to (the verified graph). Build with :func:`resolve_report_signer`.
    """

    private_key: Ed25519PrivateKey  # gitleaks:allow — a type annotation, not a secret
    environment: str
    graph: str

    def sign(self, statement_type: str, payload: Mapping[str, str]) -> str:
        """The serialized envelope for *payload* (one graph literal)."""
        return signing.sign(
            self.private_key,
            statement_type=statement_type,
            environment=self.environment,
            graph=self.graph,
            payload=payload,
            schema_version=STATEMENT_SCHEMA_VERSION,
        ).to_text()


def network_environment(status: Optional[Mapping[str, object]]) -> str:
    """The signing environment for a node status: its DKG network id ("" when
    unknown). THE one definition — writers sign with it, readers verify with
    it, so the two can never disagree."""
    return str((status or {}).get("networkId") or "")


def resolve_report_signer(client: DkgClient, graph: str) -> Optional[ReportSigner]:
    """This node's signer for *graph*, or None when it cannot sign.

    None when no graph is given, the node does not report its network id, or
    the reporter key file is unusable — the caller must then refuse to share.
    """
    if not graph:
        return None
    try:
        network = network_environment(client.status())
    except Exception as exc:  # any node failure means "cannot sign now"
        logger.warning("blackbox: cannot sign reports — node status unavailable: %s", exc)
        return None
    if not network:
        logger.warning("blackbox: cannot sign reports — the node reports no network id")
        return None
    try:
        key = reporter_key.ReporterKeyStore().load_or_create()
    except (reporter_key.ReporterKeyError, OSError) as exc:
        logger.warning("blackbox: cannot sign reports — reporter key unusable: %s", exc)
        return None
    return ReportSigner(private_key=key, environment=network, graph=graph)
