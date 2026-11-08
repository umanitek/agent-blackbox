"""The detection result type, shared by every detector.

:class:`Finding` is what each detector returns and what the guard reports,
audits and (through ``fields``) shares; :func:`_rule_source` reads a graph
rule's trust tier. Kept apart from the detectors so a detector can live in its
own file without an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

#: ``Finding.kind`` of a finding that may flag but must never block, whatever its
#: ``source`` and severity and whatever ``block_severity`` the operator chose — e.g.
#: a token approval to an address only community reports list, or an unlimited
#: approval a trading bot sends every day (KI-385). The hook's blocking rule reads it.
KIND_FLAG_ONLY = "flag-only"

#: ``Finding.fields`` key set on a wallet secret (seed phrase, private key) that a call SENDS
#: off the machine. A wallet secret has no right destination, so this one is a built-in rule:
#: it counts whether or not Trader Shield is on (KI-488) — the shield claims every other
#: wallet-secret finding (one merely written or read locally) and gates it by its mode.
FIELD_WALLET_SECRET_SENT = "walletSecretSent"


@dataclass
class Finding:
    """One detected threat. ``evidence`` is expected to already be redacted.

    ``source`` says which trust tier raised the finding:

    * ``"public"`` — matched the verified public threat graph (the source of
      truth). ``confirmed`` is True; blockable in block mode.
    * ``"community"`` — matched a rule seen only in the shared community pool.
      Flagged (and re-reported to strengthen the consensus signal) but NEVER
      blocks: anyone can write to the community pool.
    * ``"heuristic"`` — raised only by a built-in discovery heuristic; a
      *candidate* nominated to the community graph.
    * ``"custom"`` — matched a user-configured local rule (e.g. a protected
      path). Always flags, blocks in block mode, never shared to SWM.

    ``confirmed`` is kept as the strict "public graph says so" bit — only
    confirmed findings can block. ``fields`` carries the privacy-safe threat
    attributes (pattern/toolName/category/skillName/...) that the auto-submit
    path forwards to ``build_report_quads``. It NEVER contains raw prompts,
    paths, or file/skill source. ``rule_subject`` is the subject of the graph
    rule that matched (``""`` for a built-in finding): a report links it so a
    reader finds the threat's name and description in its OWN verified copy.
    """

    identifier: str
    category: str  # injection | escalation | dependency | fileaccess | skill
    severity: str
    title: str
    tool_name: str = ""
    matched: str = ""
    evidence: str = ""
    confirmed: bool = True
    source: str = "public"  # public | community | heuristic | custom
    # malware | vulnerability | historical | flag-only; only malware/None may block
    kind: Optional[str] = None
    fields: dict[str, Any] = field(default_factory=dict)
    rule_subject: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "tool_name": self.tool_name,
            "matched": self.matched,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
            "candidate": not self.confirmed,
            "source": self.source,
            "kind": self.kind,
            "fields": dict(self.fields),
            "rule_subject": self.rule_subject,
        }


def rule_subject(rule: Optional[dict[str, Any]]) -> str:
    """The matched graph rule's subject IRI (``""`` when there is no rule)."""
    return str((rule or {}).get("subject") or "")


def _rule_source(rule: dict[str, Any]) -> str:
    """Trust tier of a graph rule. Untagged rules default to ``public`` —
    rules built before tier tagging (or handed in directly by tests) were
    always treated as verified."""
    src = str(rule.get("source") or "public").lower()
    return src if src in ("public", "community") else "public"


#: What a lookup answer says about itself when the graph store could not answer and
#: the operator's opt-in local index did (the finding then carries ``answered_by``).
FALLBACK_REASON = "fallback index"
ANSWERED_BY_FALLBACK = "local index (graph store down)"


def mark_answered_by(answer: Any) -> dict[str, dict[str, Any]]:
    """The answer's rules; when the graph store was down and the local index answered,
    each rule is copied with ``answered_by`` set so the finding and the audit row say so."""
    rules = getattr(answer, "rules", {}) or {}
    if getattr(answer, "reason", "") != FALLBACK_REASON:
        return rules
    return {key: {**rule, "answered_by": ANSWERED_BY_FALLBACK} for key, rule in rules.items()}
