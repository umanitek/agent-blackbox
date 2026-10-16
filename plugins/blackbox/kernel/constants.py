"""Static constants for the Agent Blackbox plugin.

Everything here is a compile-time constant: the plugin version, the Blackbox
ontology IRIs (shared by :mod:`quads`, :mod:`ruleset` and :mod:`cli` so the
whole plugin speaks one vocabulary), the default public context-graph id, and
the resolution of ``$BLACKBOX_HOME``.

The ontology IRIs are kept byte-for-byte identical to the original TypeScript
node-ui builders so independent Blackbox nodes converge on the same threat
KAs and SPARQL filters keep matching across the Python and TS implementations.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, Tuple

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Ontology
# ---------------------------------------------------------------------------

#: Base IRI for the Blackbox ontology (``g:`` prefix in SPARQL). The legacy
#: ``/guardian/`` path remains byte-stable because the published corpus already
#: uses these predicate/type IRIs. The ``urn:guardian:`` subject schemes in
#: kernel/threat_ids.py remain stable for the same reason.
BLACKBOX_ONTOLOGY = "http://umanitek.ai/ontology/guardian/"

# rdf:type IRIs -------------------------------------------------------------
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime"

REPORT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}ThreatReport"
FALSE_POSITIVE_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}FalsePositive"
#: A signed curator statement (Refine R2): verdicts, the counted-author list,
#: backlog and away notices. Its meaning lives in the signed envelope.
CURATOR_STATEMENT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}CuratorStatement"
#: A root-signed curator key manifest (Refine R7a/R2), in the verified graph.
KEY_MANIFEST_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}KeyManifest"

#: The curator ROOT keys each DKG network trusts, bound to the root epoch each
#: may sign: ``{network id: {root_epoch: (Ed25519 public keys, hex)}}`` — e.g.
#: ``{mainnet: {1: (root_a,), 2: (root_b,)}}``. Readers trust only key
#: manifests signed by these; a pinned root signing another epoch can only
#: freeze readers (``trust_anchors.RootPins``). Empty until the root ceremony
#: (Refine R7b/R13): with no root, no curator statement counts anywhere. A
#: network listed here can NOT be overridden at runtime; only unlisted (sandbox)
#: networks accept roots from the BLACKBOX_CURATOR_ROOT_KEYS environment variable.
CURATOR_ROOT_KEYS: Mapping[str, Mapping[int, tuple[str, ...]]] = {}
#: A reporter withdrawing its own report (Refine R1, lifecycle RETRACT).
RETRACTION_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}Retraction"
#: One reporter's weekly sighting digest (Refine R2b): verified threats met
#: that ISO week, as count buckets. The week it covers is ``g:isoWeek``.
SIGHTING_DIGEST_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}SightingDigest"
ISO_WEEK_PRED = f"{BLACKBOX_ONTOLOGY}isoWeek"

# Blackbox predicates -------------------------------------------------------
IDENTIFIER_PRED = f"{BLACKBOX_ONTOLOGY}identifier"
CURATED_PRED = f"{BLACKBOX_ONTOLOGY}curated"
SEVERITY_PRED = f"{BLACKBOX_ONTOLOGY}severity"
PATTERN_PRED = f"{BLACKBOX_ONTOLOGY}pattern"
TOOL_NAME_PRED = f"{BLACKBOX_ONTOLOGY}toolName"
ARG_SHAPE_PRED = f"{BLACKBOX_ONTOLOGY}argShape"
OWASP_CATEGORY_PRED = f"{BLACKBOX_ONTOLOGY}owaspCategory"
PACKAGE_NAME_PRED = f"{BLACKBOX_ONTOLOGY}packageName"
PACKAGE_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}packageVersion"
PACKAGE_ECOSYSTEM_PRED = f"{BLACKBOX_ONTOLOGY}packageEcosystem"
FIXED_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}fixedVersion"
REFERENCE_PRED = f"{BLACKBOX_ONTOLOGY}reference"
# Named provenance (feed/dataset), e.g. "OSV.dev" — distinct from g:reference
# (a URL). Multi-valued.
SOURCE_PRED = f"{BLACKBOX_ONTOLOGY}source"
REPORTS_THREAT_PRED = f"{BLACKBOX_ONTOLOGY}reportsThreat"
REPORTER_PRED = f"{BLACKBOX_ONTOLOGY}reporter"
FRAMEWORK_PRED = f"{BLACKBOX_ONTOLOGY}framework"
#: The signed envelope (kernel.signing) a community report or dispute carries;
#: readers believe its author only after verifying it (Refine R0b, 2026-10).
SIGNED_STATEMENT_PRED = f"{BLACKBOX_ONTOLOGY}signedStatement"
#: Refine R1: where an injection was seen (INJECTION_CONTEXTS) and a skill's
#: artifact hash (sha256 of its code — local skills are never named, KI-159).
INJECTION_CONTEXT_PRED = f"{BLACKBOX_ONTOLOGY}injectionContext"
SKILL_ARTIFACT_HASH_PRED = f"{BLACKBOX_ONTOLOGY}skillArtifactHash"
#: Refine R1 (plan §04): where an indicator was met (IOC_CONTEXTS); why a
#: dependency is malware (DEPENDENCY_REASONS) or why a dispute says a threat is
#: wrong (FALSE_POSITIVE_REASONS); which registry a named skill comes from.
IOC_CONTEXT_PRED = f"{BLACKBOX_ONTOLOGY}iocContext"
REPORT_REASON_PRED = f"{BLACKBOX_ONTOLOGY}reportReason"
SKILL_REGISTRY_PRED = f"{BLACKBOX_ONTOLOGY}skillRegistry"
#: Trust-and-threat-lab §03.6 (REP1): how the reporter's node matched the threat
#: (``report_schema.MATCHED_BY``) and which Blackbox release built the report.
MATCHED_BY_PRED = f"{BLACKBOX_ONTOLOGY}matchedBy"
BLACKBOX_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}blackboxVersion"

# threat kind: distinguishes active malware from a mere vulnerability. Only
# ``malware`` blocks (at/above block_severity); ``vulnerability`` always flags
# but never auto-blocks, so a legit-but-vulnerable package isn't stopped.
KIND_PRED = f"{BLACKBOX_ONTOLOGY}kind"
KIND_MALWARE = "malware"
KIND_VULNERABILITY = "vulnerability"

# file-access predicates (g:toolName reused; category is new) ----------------
CATEGORY_PRED = f"{BLACKBOX_ONTOLOGY}category"
# suspicious-skill predicates -----------------------------------------------
IOC_TYPE_PRED = f"{BLACKBOX_ONTOLOGY}iocType"
SKILL_NAME_PRED = f"{BLACKBOX_ONTOLOGY}skillName"
SKILL_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}skillVersion"
DANGER_SHAPE_PRED = f"{BLACKBOX_ONTOLOGY}dangerShape"

# Append-only public corrections. Published threat assets remain immutable;
# a VM-verified CorrectionSignal can monotonically suppress one exact RDF
# subject without deleting or rewriting the original knowledge asset.
#: The verified graph's rdf:type for a dependency threat (the row adapter keys on it).
DEFENDER_DEPENDENCY_TYPE_IRI = "urn:defender:DependencySignal"
DEFENDER_CORRECTION_TYPE_IRI = "urn:defender:CorrectionSignal"
DEFENDER_CORRECTION_TARGET_PRED = "urn:defender:p:targetSubject"
DEFENDER_CORRECTION_ACTION_PRED = "urn:defender:p:action"
DEFENDER_CORRECTION_SUPPRESS = "suppress"

# VM-native source observations. Newer publisher batches use this compact
# ontology for feed IOCs instead of Defender ``IocSignal`` entities. These
# records are still VM-confirmed; Agent Blackbox must recognize them or a
# healthy node appears permanently stuck at the older Defender-only count.
SOURCE_OBSERVATION_TYPE_IRI = "urn:blackbox:SourceObservation"
SOURCE_OBSERVATION_CANONICAL_TYPE_PRED = "urn:blackbox:p:canonicalType"
SOURCE_OBSERVATION_CATEGORY_PRED = "urn:blackbox:p:category"
SOURCE_OBSERVATION_LIFECYCLE_STATUS_PRED = "urn:blackbox:p:lifecycleStatus"
SOURCE_OBSERVATION_NORMALIZED_VALUE_PRED = "urn:blackbox:p:normalizedValue"
SOURCE_OBSERVATION_PROVENANCE_JSON_PRED = "urn:blackbox:p:provenanceJson"
SOURCE_OBSERVATION_SOURCE_ID_PRED = "urn:blackbox:p:sourceId"

# schema.org predicates -----------------------------------------------------
SCHEMA_NAME_PRED = "http://schema.org/name"
SCHEMA_DESCRIPTION_PRED = "http://schema.org/description"
SCHEMA_IDENTIFIER_PRED = "http://schema.org/identifier"
SCHEMA_DATE_MODIFIED_PRED = "http://schema.org/dateModified"
# Optional attribution — who contributed the asset (org, handle, or wallet).
SCHEMA_CONTRIBUTOR_PRED = "http://schema.org/contributor"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Default public Verifiable Memory graph (config key ``context_graph_id``).
DEFAULT_CONTEXT_GRAPH_ID = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"

#: Legacy graph ids from earlier defaults. A node still pointed at one of these
#: is transparently switched to ``DEFAULT_CONTEXT_GRAPH_ID`` at config-load
#: time, so an existing install moves to the current graph with zero manual
#: steps. A genuinely custom ``context_graph_id`` (anything not in this set)
#: is always left untouched.
LEGACY_CONTEXT_GRAPH_IDS = frozenset({
    "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox",
    "umanitek/blackbox-threats-staging",
    "umanitek/guardian-threats-staging",
    "umanitek/guardian-threats",
})

#: Default Blackbox-managed local DKG node HTTP endpoint.
DEFAULT_DKG_PORT = 9320
DEFAULT_DKG_URL = f"http://127.0.0.1:{DEFAULT_DKG_PORT}"

#: Source peer used for verified catch-up of the default threat graph.
DEFAULT_GRAPH_PEER_ID = "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM"

# The minimum complete release generation bundled with this Agent Blackbox
# build. DKG reconciliation remains subscribed for later append-only updates;
# these floors only let the foreground command recognize that the known
# release is already present instead of starting a redundant source transfer.
DEFAULT_GRAPH_RELEASE_THREAT_FLOOR = 550_000
DEFAULT_GRAPH_RELEASE_RULE_FLOOR = 500_000

#: DKG divides this caller boundary across three router attempts and its remote
#: responder may spend ten seconds waiting for capacity before it starts serving
#: a page.  A 30-second caller budget therefore gave each attempt less than the
#: responder's own queue window and deterministically aborted congested fresh
#: installs at offset zero.  Use the route's bounded maximum so each page retains
#: DKG's full transport timeout.  Durable checkpoints still split a large VM into
#: safe, resumable passes; this only gives each pass enough time to make progress.
INITIAL_GRAPH_SYNC_PASS_BUDGET_MS = 300_000

#: Follow-up passes use the same complete transport window.  This remains below
#: DKG's ten-minute responder-session lifetime and preserves its checkpointed
#: exact-graph boundaries across retries and process restarts.
DEFAULT_GRAPH_SYNC_PASS_BUDGET_MS = 300_000

#: Publisher pressure is explicitly retryable. Keep trying until the command's
#: overall deadline, with a bounded delay so many fresh clients cannot create a
#: tight retry loop against the same responder.
GRAPH_SYNC_RETRY_BACKOFF_INITIAL_S = 2.0
GRAPH_SYNC_RETRY_BACKOFF_MAX_S = 30.0

#: Durable network fetching is bounded by the pass budget above, but DKG must
#: still verify complete graphs and atomically materialize them afterward. A
#: large fresh-node pass can spend many minutes in that correctness-critical
#: settlement phase, so the HTTP caller and its watchdog must wait longer than
#: the fetch budget.
GRAPH_SYNC_SETTLEMENT_TIMEOUT_S = 3_600.0

#: Let the HTTP client report its own timeout before the outer CLI watchdog
#: fires. This prevents a retry from overlapping a request that is still
#: blocked inside urllib at the settlement boundary.
GRAPH_SYNC_WATCHDOG_HEADROOM_S = 15.0

#: Previous bootstrap peers transparently replaced during config loading.
LEGACY_GRAPH_PEER_IDS = frozenset({
    "12D3KooWAuEHYTWbD3R3yPTcECCYZnrjHNpJmrUw5b4D5T3m5Kr3",
    "12D3KooWBY9jmNATMPv1DZcKbFas5RtjpkhT69pPwvkUBY2MMnDX",
    "12D3KooWQHQd1SNecrRxwceqPJkXSKEYn8vrV4QyJ2AfqeYwXz1E",
    "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM",
})

#: Severity ladder, lowest → highest. ``info`` < ... < ``critical``.
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}

#: OWASP Top 10 for LLM applications — the closed set an injection report's
#: class is validated against (Refine R1).
OWASP_LLM_CATEGORIES = tuple(f"LLM{n:02d}" for n in range(1, 11))

#: Where a prompt injection was seen (decision 24, KI-161): a closed context,
#: never the source domain or any text.
INJECTION_CONTEXTS = ("in-fetched-page", "in-tool-output", "in-user-prompt", "in-skill")

#: Where an indicator of compromise was met (plan §04).
IOC_CONTEXTS = ("fetched-by-tool", "in-prompt", "in-tool-output", "in-dependency", "in-skill")

#: Why a dependency is reported as malware (plan §04), besides ``advisory:<id>``.
DEPENDENCY_REASONS = ("typosquat", "install-hook", "exfil", "internal-mirror-collision")
#: The only reasons a whole-package (``@*``) dependency report may give.
WHOLE_PACKAGE_REASONS = ("typosquat", "internal-mirror-collision")
#: The prefix of an advisory-backed reason (``advisory:MAL-2026-1``).
ADVISORY_REASON_PREFIX = "advisory:"

#: Registries a skill may be NAMED from. A local or unknown skill is never named:
#: it is reported by artifact hash only (KI-159).
SKILL_REGISTRIES = ("mcp-registry", "clawhub", "npm", "pypi", "oci", "mcpb")

#: Why a dispute (``g:FalsePositive``) says a threat is wrong (plan §04).
FALSE_POSITIVE_REASONS = ("internal-mirror", "unreachable", "tolerable", "fixed", "wrong")

#: Why a curator REJECTS a community report (Refine R2). The plan requires a
#: closed reason but never listed one; these are drawn from its own concepts:
#: benign (checked, not malicious), duplicate (already verified), allowlisted
#: (a byte-exact allowlisted name), scope-exceeds-evidence (rule scope must not
#: exceed evidence scope), unverifiable (no independent evidence could exist),
#: bad-faith (a strike). Missing-but-obtainable evidence is DEFERRED, not rejected.
REJECTION_REASONS = ("benign", "duplicate", "allowlisted", "scope-exceeds-evidence", "unverifiable", "bad-faith")
#: Why a curator REVOKES a verified rule (Refine R2), from the plan's revocation
#: paths: a false positive, upstream evidence withdrawn, fixed upstream, a rule
#: broader than its evidence, superseded by another rule, a dispute upheld.
REVOCATION_REASONS = ("false-positive", "evidence-withdrawn", "fixed-upstream", "scope-too-broad",
                      "superseded", "dispute-upheld")
#: Counted-author classes in the Phase 1 list (plan §05).
COUNTED_AUTHOR_CLASSES = ("partner", "established")

#: Frameworks a report may name.
REPORT_FRAMEWORKS = ("hermes", "openclaw")

#: SPARQL views exposed by the DKG node ``/api/query`` route.
VIEW_WORKING_MEMORY = "working-memory"
VIEW_SHARED_WORKING_MEMORY = "shared-working-memory"
VIEW_VERIFIABLE_MEMORY = "verifiable-memory"

# The community: what every Blackbox agent shares and learns from. Since
# 2026-10-16 it lives in the verified graph itself (``context_graph_id``) — its
# shared memory, sub-graph ``COMMUNITY_SUB_GRAPH`` — and there is no second
# graph. Edges share there; the curator promotes what it confirms to the
# graph's Verified Memory. The runtime gate lives in config
# (BlackboxConfig.community_enabled = report AND a graph); this constant only
# records that the capability ships in this build.
COMMUNITY_GRAPH_ENABLED = True

#: The named sub-graph of the verified graph every community statement is
#: written to and read from. Never the graph's ROOT: the DKG keeps one author
#: catalog per writer of a root and allows 64 per graph, and every node is a
#: writer — a named sub-graph has no per-author catalog. (DKG 10.0.23 also
#: refuses members' direct shares into a catalog-mode root.)
COMMUNITY_SUB_GRAPH = "reports"

#: Default daily cap on outbound community reports per node. Bounds a runaway
#: or compromised agent's graph footprint even before the per-threat 6-hour
#: cooldown is considered. Refine R1 (plan §07): 100/day (20 until 2026-10-12), client-side hygiene
#: only — readers enforce the real per-author budget — and it can no longer be
#: switched off: a limit of 0 or below means this default, never "no cap".
DEFAULT_DAILY_REPORT_LIMIT = 100


def effective_daily_report_limit(configured: int) -> int:
    """The daily report cap to enforce: *configured* when positive, else the
    default — never "no cap" (Refine R1). THE one rule; config and the share
    ledger both apply it."""
    return configured if configured > 0 else DEFAULT_DAILY_REPORT_LIMIT


def normalize_severity(value: object, fallback: str = "info") -> str:
    """Coerce an arbitrary value to a known severity string.

    ``moderate`` (OSV/CVSS spelling) maps to ``medium``; anything unknown
    falls back to *fallback*.
    """
    raw = str(value or "").strip().lower()
    if raw == "moderate":
        return "medium"
    return raw if raw in SEVERITY_RANK else fallback


def severity_for_kind(kind: object, severity: object, fallback: str = "high") -> str:
    """Normalized severity, forcing ``malware`` to at least ``critical``.

    Malware must block under the default policy (``block_severity=critical``),
    so a malware entry that omits or under-states its severity is floored to
    ``critical``. A ``vulnerability`` (or unknown kind) keeps its normalized
    severity — a legit-but-vulnerable package should flag, not block.
    """
    sev = normalize_severity(severity, fallback)
    if str(kind or "").strip().lower() == KIND_MALWARE:
        return "critical"
    return sev


def hermes_home() -> Path:
    """Return the active ``HERMES_HOME`` directory.

    Prefers the hermes runtime helper (which honours profile switching); falls
    back to ``$HERMES_HOME`` and then ``~/.hermes`` so the plugin's CLI works
    even outside a running agent.
    """
    try:
        from hermes_constants import get_hermes_home

        return get_hermes_home()
    except Exception:
        env = os.environ.get("HERMES_HOME")
        return Path(env).expanduser() if env else Path.home() / ".hermes"


def blackbox_home() -> Path:
    """Return ``$BLACKBOX_HOME`` — defaults to ``$HERMES_HOME/blackbox``.

    Created on demand by the callers that write into it (ruleset cache, audit
    logs). An explicit ``BLACKBOX_HOME`` env var overrides the default.
    """
    env = os.environ.get("BLACKBOX_HOME")
    if env and env.strip():
        return Path(env).expanduser()
    return hermes_home() / "blackbox"


def blackbox_dkg_home() -> Path:
    """Return the Blackbox-managed DKG home.

    This is separate from the DKG CLI default ``~/.dkg`` so install/bootstrap,
    auth token reads, daemon pid/api-port files, and graph/cache storage do not
    touch a user's existing DKG node.
    """
    env = os.environ.get("BLACKBOX_DKG_HOME")
    if env and env.strip():
        return Path(env).expanduser()
    return blackbox_home() / "dkg"


def blackbox_dkg_cli_dir() -> Path:
    """Return the Blackbox-owned DKG CLI package directory.

    The installer keeps its managed DKG source checkout here. Keeping the
    checkout beside the Blackbox DKG home prevents a Blackbox install from
    upgrading or depending on a user's unrelated DKG CLI.
    """
    env = os.environ.get("BLACKBOX_DKG_CLI_DIR")
    if env and env.strip():
        return Path(env).expanduser()
    return blackbox_home() / "dkg-cli"


def blackbox_dkg_bin() -> Path:
    """Return the Blackbox-owned ``dkg`` executable path."""
    env = os.environ.get("BLACKBOX_DKG_BIN")
    if env and env.strip():
        return Path(env).expanduser()
    bin_name = "dkg.cmd" if os.name == "nt" else "dkg"
    return blackbox_dkg_cli_dir() / "node_modules" / ".bin" / bin_name
