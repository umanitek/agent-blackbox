"""The kill list on the wire — build, sign, parse (Refine R14, plan §06 KILL LIST).

A kill list is ONE signed statement (``blackbox.kill-list``) in the verified
graph, versioned by its sequence, carrying every entry the curators want
readers to act on: installed skills and MCP servers to DISABLE at the hook
(the tool call is refused; files and config untouched; never uninstall) or
to WARN about. Entries are keyed on registry + identifier + version +
artifact hash; an empty version or hash means "any".

Signing (plan §06 blast-radius gates, enforced by :mod:`.gates` on the
reader): 2-of-3 curator keys always; a name- or publisher-WIDE kill (no
version AND no hash, or a publisher entry) needs the root as a third
signature; a kill on a popular or allowlisted artifact needs the root AND a
24-hour hold from the signed day; at most 20 NEW disables per version. Any
signature, key-expiry or clock failure keeps the LAST-GOOD list — never
"disable all", never "enable all" (Mozilla, 2019).

Pattern: Value Objects (:class:`KillEntry`, :class:`KillList`) with paired
build / parse functions — the same shape as the curator statements.

Usage::

    envelope = sign_kill_list(KillList(version=3, day="2026-10-02", entries=(...)), key_a, manifest, graph)
    quads = kill_list_quads(envelope)                      # one asset per version
    parsed = parse_kill_list(row, manifest, graph=graph)   # (envelope, KillList) or None
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..kernel import constants, rdf_terms, signing, sparql_text, threat_ids
from ..kernel.dkg_client import extract_binding
from ..kernel.signing import KeyManifest

KILL_LIST_STATEMENT = "blackbox.kill-list"
#: The graph type of a kill-list asset (a curator statement vocabulary term).
KILL_LIST_TYPE_IRI = f"{constants.BLACKBOX_ONTOLOGY}KillList"
#: Registries a kill may name.
REGISTRIES = ("skill", "mcp")
#: Entries per list. The signed envelope is capped at 4096 characters (an
#: oversized literal would break peers' graph sync), and a compact entry is
#: ~90 characters, so one version holds a few dozen entries — enough for the
#: ≤20 new disables a version may add (plan §06). Wider needs are versions.
MAX_ENTRIES = 40
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@/:-]{0,127}")


class KillAction(Enum):
    DISABLE = "disable"   # the hook refuses the call; nothing on disk changes
    WARN = "warn"         # the hook flags the call and lets it through


@dataclass(frozen=True)
class KillEntry:
    """One target. ``registry`` ∈ skill | mcp; ``identifier`` — the skill or
    MCP server name (``*`` with a ``publisher`` = publisher-wide);
    ``version`` / ``artifact_hash`` — exact pins ("" = any); ``action``;
    ``reason`` — a closed-vocabulary word for the operator; ``publisher`` —
    set only for publisher-wide kills; ``tool_prefix`` — for MCP servers,
    the tool-name prefix the host gives that server's tools."""

    registry: str
    identifier: str
    action: KillAction
    reason: str = "malware"
    version: str = ""
    artifact_hash: str = ""
    publisher: str = ""
    tool_prefix: str = ""

    @property
    def wide(self) -> bool:
        """A name- or publisher-wide kill: no version AND no hash, a publisher entry — or ANY
        MCP-server kill (review round 4: a tool-name prefix matches a whole server, and a short
        prefix matches most tools; the root signs every one)."""
        return (self.registry == "mcp" or bool(self.publisher) or self.identifier == "*"
                or (not self.version and not self.artifact_hash))

    @property
    def key(self) -> str:
        return f"{self.registry}:{self.publisher or self.identifier}:{self.version or '*'}:{self.artifact_hash or '*'}"

    def as_json(self) -> dict[str, str]:
        """Compact: empty optional fields are omitted (the envelope is size-capped)."""
        data = {"registry": self.registry, "identifier": self.identifier, "action": self.action.value, "reason": self.reason}
        for name, value in (("version", self.version), ("artifact_hash", self.artifact_hash),
                            ("publisher", self.publisher), ("tool_prefix", self.tool_prefix)):
            if value:
                data[name] = value
        return data

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Optional[KillEntry]:
        try:
            entry = cls(registry=str(data["registry"]), identifier=str(data["identifier"]),
                        action=KillAction(str(data["action"])), reason=str(data.get("reason") or "malware"),
                        version=str(data.get("version") or ""), artifact_hash=str(data.get("artifact_hash") or "").lower(),
                        publisher=str(data.get("publisher") or ""), tool_prefix=str(data.get("tool_prefix") or "").lower())
        except (KeyError, ValueError, TypeError):
            return None
        return entry if entry.valid() else None

    def valid(self) -> bool:
        return (self.registry in REGISTRIES and bool(_NAME.fullmatch(self.identifier) or self.identifier == "*")
                and (not self.artifact_hash or threat_ids.is_hex64(self.artifact_hash))
                and self.reason in constants.REVOCATION_REASONS + ("malware", "compromised", "impersonation")
                and (not self.publisher or bool(_NAME.fullmatch(self.publisher)))
                and (not self.tool_prefix or (len(self.tool_prefix) >= 3 and bool(_NAME.fullmatch(self.tool_prefix))))
                and (self.registry != "mcp" or bool(self.tool_prefix))
                and (self.identifier != "*" or bool(self.publisher)))


@dataclass(frozen=True)
class KillList:
    """``version`` (the signed sequence — latest wins), ``day`` (signed UTC
    day the list was made; the 24 h hold counts from it), ``entries``."""

    version: int
    day: str
    entries: tuple[KillEntry, ...]

    def to_payload(self) -> dict[str, str]:
        return {"version": str(self.version), "day": self.day,
                "entries": signing.canonical_json([e.as_json() for e in self.entries])}

    @classmethod
    def from_payload(cls, payload: Mapping[str, str], sequence: int) -> Optional[KillList]:
        try:
            version, day = int(payload["version"]), str(payload["day"])
            raw = json.loads(payload["entries"])
        except (KeyError, ValueError, TypeError):
            return None
        if version != sequence or not _DAY.fullmatch(day) or not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
            return None
        entries = [KillEntry.from_json(item) for item in raw if isinstance(item, dict)]
        if any(e is None for e in entries) or len(entries) != len(raw):
            return None
        return cls(version=version, day=day, entries=tuple(e for e in entries if e is not None))

    def as_cache(self) -> dict[str, Any]:
        """The plain dict the compiled ruleset carries (disk cache + memory)."""
        return {"version": self.version, "day": self.day, "entries": [e.as_json() for e in self.entries]}

    @classmethod
    def from_cache(cls, data: Any) -> Optional[KillList]:
        """The list from a ruleset's cached dict; None for an empty or malformed one."""
        if not isinstance(data, dict) or not data.get("entries"):
            return None
        entries = [KillEntry.from_json(item) for item in data.get("entries", []) if isinstance(item, dict)]
        if any(e is None for e in entries):
            return None
        try:
            return cls(version=int(data.get("version", 0)), day=str(data.get("day") or ""),
                       entries=tuple(e for e in entries if e is not None))
        except (TypeError, ValueError):
            return None

    @property
    def disables(self) -> tuple[KillEntry, ...]:
        return tuple(e for e in self.entries if e.action is KillAction.DISABLE)


def sign_kill_list(kill_list: KillList, key: Ed25519PrivateKey, manifest: KeyManifest, graph: str) -> signing.SignedEnvelope:
    """The first signature (co-sign with ``signing.cosign``; the root co-signs
    wide and popular kills). Raises ValueError for an invalid list."""
    if KillList.from_payload(kill_list.to_payload(), kill_list.version) is None:
        raise ValueError("not a valid kill list")
    return signing.sign(key, statement_type=KILL_LIST_STATEMENT, environment=manifest.environment, graph=graph,
                        payload=kill_list.to_payload(), chain=manifest.chain, root_epoch=manifest.root_epoch,
                        sequence=kill_list.version)


def kill_list_subject(version: int) -> str:
    return f"urn:guardian:curator:kill-list:{version}"


def kill_list_quads(envelope: signing.SignedEnvelope) -> list[rdf_terms.Quad]:
    subject = kill_list_subject(envelope.sequence)
    return [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(KILL_LIST_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]


def parse_kill_list(row: Mapping[str, Any], manifest: Optional[KeyManifest], *, graph: str
                    ) -> Optional[tuple[signing.SignedEnvelope, KillList]]:
    """The (envelope, list) in *row* when its envelope parses, its subject is
    its own, and at least the manifest's threshold of curator keys signed
    it; otherwise None (the blast-radius gates run afterwards, per entry)."""
    if manifest is None:
        return None
    envelope = signing.from_text(extract_binding(row.get("signedStatement")))
    if envelope is None or envelope.statement_type != KILL_LIST_STATEMENT:
        return None
    if extract_binding(row.get("r")) != kill_list_subject(envelope.sequence):
        return None
    if not manifest.has_quorum(envelope, statement_type=KILL_LIST_STATEMENT, graph=graph):
        return None
    kill_list = KillList.from_payload(envelope.payload, envelope.sequence)
    return (envelope, kill_list) if kill_list is not None else None


def kill_list_sparql(after: str) -> str:
    """One page of kill-list rows after the subject cursor *after*."""
    cursor = sparql_text.cursor_filter(after)
    return f"""
PREFIX g: <{constants.BLACKBOX_ONTOLOGY}>
SELECT ?r ?signedStatement WHERE {{
  ?r a g:KillList ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 200
"""
