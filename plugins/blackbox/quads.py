"""Deterministic identifier, URI, and quad builders for the threat graph.

This is the single source of truth for:

* **threat identifiers** — ``dep:``/``injection:``/``escalation:`` strings that
  two independent nodes compute identically so they converge on the same
  Threat knowledge asset.
* **arg-shape normalization** — the deterministic ``normalize_arg_shape``
  heuristic that turns a tool call into an escalation signature.
* **N-Triples term escaping** and the report quad builder.

The identifier scheme and ontology are kept byte-for-byte compatible with the
original TypeScript ``node-ui`` builders.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from . import constants


# A quad is a ``{subject, predicate, object}`` dict. ``object`` is a ready N-Triples
# term (IRIs bare, literals quoted). No per-quad ``graph`` — the daemon pins it.
Quad = Dict[str, str]


# ---------------------------------------------------------------------------
# Hashing / slugs / URIs
# ---------------------------------------------------------------------------


def stable_hash(value: str, length: int = 24) -> str:
    """SHA-256 hex digest of *value*, truncated to *length* chars."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_SLUG_TRIM_RE = re.compile(r"^-+|-+$")


def slug(value: str) -> str:
    """Lowercase, replace runs of non ``[a-z0-9._-]`` with ``-``, cap at 96 chars."""
    lowered = _SLUG_RE.sub("-", str(value).lower())
    trimmed = _SLUG_TRIM_RE.sub("", lowered)[:96]
    return trimmed or "unknown"


# The legacy ``urn:guardian:`` subject schemes (and ontology IRI in
# constants.py) remain byte-stable so the already-published threat corpus stays
# addressable and queryable.
def threat_uri(identifier: str) -> str:
    """Stable curated-threat subject URI for a threat *identifier*."""
    return f"urn:guardian:threat:{slug(identifier)}"


def report_uri(identifier: str, agent_address: str) -> str:
    """Per-submitter namespaced report subject URI.

    SWM root entities are first-writer-wins, so each submitter's sighting of a
    threat gets its own subject: ``urn:guardian:report:{addrLower}:{h}`` where
    ``h`` is ``sha256(identifier)[:16]``. Counting distinct reporters of a
    threat therefore counts distinct namespaces.
    """
    addr = (agent_address or "anonymous").lower()
    return f"urn:guardian:report:{addr}:{stable_hash(identifier, 16)}"


# ---------------------------------------------------------------------------
# Identifier builders
# ---------------------------------------------------------------------------


def canonical_package_name(ecosystem: str, name: str) -> str:
    """Canonicalize a package name so the same package always maps to one key.

    PyPI treats names case- AND separator-insensitively (PEP 503): ``Foo.Bar``,
    ``foo-bar`` and ``foo_bar`` are the same project, so runs of ``-_.`` collapse
    to a single ``-``. Every other ecosystem is only lowercased (npm is
    case-insensitive; RubyGems/cargo/go names are separator-*sensitive*, so
    collapsing there would wrongly merge distinct packages).
    """
    canon = name.strip().lower()
    if ecosystem.strip().lower() == "pypi":
        canon = re.sub(r"[-_.]+", "-", canon)
    return canon


def dependency_key(ecosystem: str, name: str, version: str) -> str:
    """The ruleset lookup key ``{ecosystem}:{canonical-name}@{version}``.

    Shared by the detector and the ruleset builder so a graph id and a live
    lookup are byte-identical for any spelling of the same package.
    """
    return f"{ecosystem.strip().lower()}:{canonical_package_name(ecosystem, name)}@{version.strip()}"


def dependency_identifier(ecosystem: str, name: str, version: str) -> str:
    """``dep:{ecosystem}:{canonical-name}@{version}`` (see :func:`dependency_key`)."""
    return f"dep:{dependency_key(ecosystem, name, version)}"


def injection_identifier(pattern: str) -> str:
    """``injection:{sha256(pattern)[:24]}``."""
    return f"injection:{stable_hash(pattern, 24)}"


def escalation_identifier(tool_name: str, arg_shape: str) -> str:
    """``escalation:{tool}:{argShape}`` — the human-readable escalation id.

    The shape is kept literal (not hashed) so the id is legible, e.g.
    ``escalation:shell:remote-script-pipe``. The detector emits lowercase
    hyphenated slugs, so both tool and shape are lowercased here — a
    graph rule that differs only in case still matches.
    """
    return f"escalation:{tool_name.strip().lower()}:{arg_shape.strip().lower()}"


def fileaccess_identifier(tool_name: str, category: str) -> str:
    """``fileaccess:{tool}:{category}`` — e.g. ``fileaccess:read_file:ssh-private-key``.

    Both parts are kept literal (lowercased) so the id is legible and two nodes
    that touch the same sensitive-path category converge on one threat KA.
    """
    return f"fileaccess:{tool_name.strip().lower()}:{category.strip().lower()}"


def skill_version_identifier(name: str, version: str) -> str:
    """``skill:{name}@{version}`` — the known-bad (graph-matched) skill id."""
    return f"skill:{name.strip().lower()}@{version.strip()}"


def skill_shape_identifier(name: str, danger_shape: str) -> str:
    """``skill:{name}:{dangerShape}`` — a heuristic dangerous-code/permission id."""
    return f"skill:{name.strip().lower()}:{danger_shape.strip()}"


# ---------------------------------------------------------------------------
# IOC identifiers (network + crypto indicators)
# ---------------------------------------------------------------------------

#: The indicator types a published ``ioc:`` threat can carry. ``domain``/``url``/
#: ``ip`` are network indicators; ``hash`` is a file digest; ``wallet``/
#: ``contract`` are crypto addresses. All match against agent tool-call text.
IOC_TYPES = ("domain", "url", "ip", "hash", "wallet", "contract")

_EVM_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    """Canonicalize an IOC value so a graph id and a live match are identical.

    Domains/URLs/IPs/EVM-addresses/hashes lower-case (the network + EVM name
    spaces are case-insensitive); base58 crypto addresses (BTC/Solana) are
    case-*sensitive* and kept verbatim. URLs drop a trailing slash and lower
    only scheme+host so the path stays exact; IPs drop any ``:port``.
    """
    t = (ioc_type or "").strip().lower()
    raw = str(value or "").strip()
    if not raw:
        return ""
    if t == "domain":
        return raw.rstrip(".").lower()
    if t == "url":
        parts = raw.split("://", 1)
        if len(parts) == 2:
            host_path = parts[1].split("/", 1)
            host = host_path[0].lower()
            rest = ("/" + host_path[1]) if len(host_path) == 2 else ""
            raw = f"{parts[0].lower()}://{host}{rest}"
        return raw.rstrip("/")
    if t == "ip":
        return raw.split(":", 1)[0]
    if t == "hash":
        return raw.lower()
    if t in ("wallet", "contract"):
        return raw.lower() if _EVM_ADDR_RE.fullmatch(raw) else raw
    return raw


def ioc_identifier(ioc_type: str, value: str) -> str:
    """``ioc:{type}:{normalized-value}`` — the shared IOC id (see :func:`normalize_ioc_value`)."""
    return f"ioc:{(ioc_type or '').strip().lower()}:{normalize_ioc_value(ioc_type, value)}"


# ---------------------------------------------------------------------------
# Arg-shape normalization
# ---------------------------------------------------------------------------

# A remote-download-piped-to-interpreter shape: `curl ... | sh`, `wget ... | bash`.
REMOTE_SCRIPT_RE = re.compile(
    r"\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b",
    re.IGNORECASE,
)
# `rm -rf` against DANGEROUS roots only. Matches the short combined/split forms
# (`-rf`, `-fr`, `-r -f`) and the long forms (`--recursive --force`). The target
# arm is deliberately narrow: whole-system roots, a bare `/`, a whole-home wipe
# (`~`, `~/`, `$HOME`), or a security-sensitive home dir (`~/.ssh` etc.). Routine
# cleanup — `rm -rf node_modules`, `~/.cache`, `~/build`, `/var/tmp/...` — does
# NOT match, so ordinary dev work stays quiet.
RM_RF_SYSTEM_RE = re.compile(
    r"\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r|"
    r"--recursive\s+--force|--force\s+--recursive|-r\s+--force|--recursive\s+-f)\b[\s\S]{0,200}"
    r"(?:"
    r"\s/(?:etc|usr|bin|sbin|opt|private|System|Library)\b"          # system roots
    r"|\s/var(?!/(?:tmp|folders))\b"                                 # /var but not temp
    r"|\s/\s*(?=[;&|]|$)"                                            # bare / (root)
    r"|\s(?:~|\$HOME)/?(?=\s|[;&|]|$)"                               # whole home wipe
    r"|\s(?:~|\$HOME)/\.(?:ssh|aws|gnupg|gpg|kube|docker|password-store)\b"  # sensitive home dirs
    r")",
    re.IGNORECASE,
)
# `chmod 777` against a SENSITIVE target (system root or security dir). World-
# writable perms on a scratch/build/public dir are common and harmless, so a
# bare `chmod 777 ./public` no longer fires.
CHMOD_WORLD_RE = re.compile(
    r"\bchmod\s+(?:-R\s+)?0?777\b[\s\S]{0,200}"
    r"(?:\s/(?:etc|usr|bin|sbin|var|opt|private|System|Library)\b|\s/\s*(?=[;&|]|$)"
    r"|\s(?:~|\$HOME)/?\.?(?:ssh|aws|gnupg))",
    re.IGNORECASE,
)
# Piping a fetched payload straight into eval.
CURL_EVAL_RE = re.compile(r"\b(?:curl|wget)\b[\s\S]{0,300}\|\s*eval\b", re.IGNORECASE)
# Disabling TLS verification on a network fetch. `-k`/`--insecure` mean "skip
# cert check" for curl only; for wget `-k` is `--convert-links` (benign), whose
# insecure flag is `--no-check-certificate`. Keep them ecosystem-specific so a
# routine `wget -k` mirror isn't misflagged.
INSECURE_FETCH_RE = re.compile(
    # curl: --insecure, --no-check-certificate, or a short-flag group containing
    # `k` (`-k`, `-sk`, `-ks`, `-fsSLk`). Kept as a plain char class (no inline
    # case flags) so the TS port stays byte-identical for parity.
    r"\bcurl\b[\s\S]{0,200}(?:--insecure|--no-check-certificate|\s-[a-z]*k[a-z]*\b)"
    r"|\bwget\b[\s\S]{0,200}--no-check-certificate",
    re.IGNORECASE,
)
# A local/private/dev host — an insecure TLS fetch against one of these is
# routine (self-signed dev servers, internal endpoints), not a threat.
_LOCAL_HOST_RE = re.compile(
    r"(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0|\[::1\]|\b10\.\d+\.\d+\.\d+"
    r"|\b192\.168\.\d+\.\d+|\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\.local\b|\.internal\b)",
    re.IGNORECASE,
)

# Ordered so the most specific / most dangerous shape wins for a given command.
_SHELL_SHAPE_RULES = (
    ("remote-script-pipe", REMOTE_SCRIPT_RE),
    ("remote-eval-pipe", CURL_EVAL_RE),
    ("rm-rf-system-paths", RM_RF_SYSTEM_RE),
    ("chmod-world-writable", CHMOD_WORLD_RE),
    ("insecure-tls-fetch", INSECURE_FETCH_RE),
)

# Shapes that Blackbox still MATCHES against curated graph rules but never
# auto-nominates as heuristic candidates. `remote-script-pipe` (`curl … | bash`)
# is the canonical install idiom for rustup, nvm, Homebrew, oh-my-zsh, etc., so
# firing + reporting on the shape alone would flag routine agent behaviour and
# flood the community graph. A known-bad
# `curl|bash` into the graph and Blackbox will match it.
NO_AUTO_NOMINATE_SHAPES = frozenset({"remote-script-pipe"})

# Tool names whose payload is treated as a shell command string.
_SHELL_TOOLS = {"terminal", "shell", "bash", "run_command", "exec", "command"}
_COMMAND_KEYS = ("command", "cmd", "shell", "script", "input")

_MAX_SHAPE_SCAN = 8000


def _command_from_args(tool_name: str, args: Any) -> str:
    """Best-effort extraction of a shell command string from tool args."""
    if isinstance(args, str):
        return args[:_MAX_SHAPE_SCAN]
    if not isinstance(args, dict):
        return ""
    for key in _COMMAND_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val:
            return val[:_MAX_SHAPE_SCAN]
    # Fall back to concatenating string values for shell-like tools only.
    if (tool_name or "").lower() in _SHELL_TOOLS:
        parts = [v for v in args.values() if isinstance(v, str)]
        return " ".join(parts)[:_MAX_SHAPE_SCAN]
    return ""


def normalize_arg_shape(tool_name: str, args: Any) -> Optional[str]:
    """Derive a deterministic escalation ``argShape`` for a tool call.

    Returns a stable slug (e.g. ``remote-script-pipe``) or ``None`` when the
    call does not match any known dangerous shape. Deterministic and pure so
    independent clients agree on identifiers.
    """
    command = _command_from_args(tool_name, args)
    if not command:
        return None
    for shape, pattern in _SHELL_SHAPE_RULES:
        try:
            if pattern.search(command):
                # Insecure TLS against a localhost / private / .local host is
                # routine dev work, not a threat — skip it (other shapes still win).
                if shape == "insecure-tls-fetch" and _LOCAL_HOST_RE.search(command):
                    continue
                return shape
        except re.error:  # pragma: no cover - static patterns
            continue
    return None


# ---------------------------------------------------------------------------
# Built-in injection heuristics (discovery layer — OWASP LLM01/LLM06)
# ---------------------------------------------------------------------------

# Each entry is (severity, owasp, compiled-regex). These are the DISCOVERY
# nomination layer: a prompt matching one that is NOT already in the graph is
# auto-submitted as a *candidate* injection. Privacy: only the matched
# substring (truncated) is ever carried off-box — never the surrounding prompt.
# Anchored on the injection *structure* (override-verb + previous/your +
# instruction-noun, or an exfil verb near a secret) so common real-world
# phrasings match without firing on ordinary prose.
_INJECTION_HEURISTICS = (
    # OpenClaw's external-content sanitizer emits this marker after removing a
    # model-control delimiter; treat the marker itself as a high-signal event.
    ("high", "LLM01", re.compile(r"\[REMOVED_SPECIAL_TOKEN\]")),
    # "ignore all previous instructions" and its many close variants:
    # ignore/disregard/forget/skip/override + (all|any|the)? +
    # previous/prior/above/earlier + instructions/messages/prompts/rules/context/...
    ("high", "LLM01", re.compile(
        r"(?:ignore|disregard|forget|skip|override)\s+(?:all\s+|any\s+|the\s+|these\s+)?"
        r"(?:previous|prior|above|earlier|preceding|prior\s+)\s*"
        r"(?:instruction|message|prompt|rule|context|direction|directive|command|guideline)s?",
        re.IGNORECASE)),
    # Disclose the system prompt / instructions (prompt-extraction recon).
    ("high", "LLM06", re.compile(
        r"(?:reveal|show|print|repeat|disclose|give|tell|share|send|output|expose|leak|"
        r"what(?:'s|\s+is|\s+are)?|display)\b[\s\S]{0,40}\b"
        r"(?:system\s+prompt|system\s+message|initial\s+(?:instruction|prompt)s?|"
        r"your\s+(?:instructions|prompt|system\s+prompt|guidelines))",
        re.IGNORECASE)),
    ("high", "LLM01", re.compile(r"you\s+are\s+now\b[\s\S]{0,40}\b(?:DAN|developer\s+mode|jailbroken|unrestricted)", re.IGNORECASE)),
    ("high", "LLM01", re.compile(r"(?:pretend|act\s+as|roleplay|imagine)\s+(?:to\s+be\s+|you(?:'re|\s+are)\s+|as\s+)?[\s\S]{0,40}\b(?:no\s+restrictions|unrestricted|without\s+rules|no\s+rules|jailbroken|DAN\b)", re.IGNORECASE)),
    # Exfiltrate a secret. Two shapes so precision stays high:
    #   (a) unambiguous verbs (exfiltrate/exfil/smuggle) within 40 chars of a secret;
    #   (b) ambiguous verbs (leak/upload/steal/send/post) only when they DIRECTLY
    #       govern the secret — so "leak-proof the token" and "memory leak … token
    #       bucket" don't fire, but "leak the api key" does.
    ("high", "LLM06", re.compile(r"(?:exfiltrate|exfil|smuggle)\b[\s\S]{0,40}\b(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables?|\.env)", re.IGNORECASE)),
    ("high", "LLM06", re.compile(r"\b(?:leak|upload|steal|send|post)(?:s|ing|ed)?\s+(?:the\s+|my\s+|our\s+|your\s+|all\s+(?:the\s+)?)?(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables?|\.env)", re.IGNORECASE)),
)

#: Truncation cap for the matched dangerous phrase kept as local evidence.
_INJECTION_PHRASE_CAP = 120
_MAX_INJECTION_SCAN = 50_000


def scan_injection_heuristics(text: str) -> List[Dict[str, str]]:
    """Return built-in injection matches as ``[{pattern, phrase, severity, owasp}]``.

    ``pattern`` is the built-in heuristic's own regex *source* — a fixed,
    non-sensitive signature safe to share to the community graph and stable
    across users (so identical attacks dedupe to one identifier). ``phrase`` is
    the matched substring of the observed text (truncated to ~120 chars); it is
    kept for LOCAL evidence only and must never leave the machine. Deterministic
    and pure; used by detection to nominate candidate injection threats.
    """
    if not text:
        return []
    scan = text[:_MAX_INJECTION_SCAN]
    out: List[Dict[str, str]] = []
    seen: set = set()
    for severity, owasp, pattern in _INJECTION_HEURISTICS:
        try:
            m = pattern.search(scan)
        except re.error:  # pragma: no cover - static patterns
            continue
        if not m:
            continue
        if pattern.pattern in seen:
            continue
        seen.add(pattern.pattern)
        out.append({
            "pattern": pattern.pattern,                      # shareable signature
            "phrase": m.group(0)[:_INJECTION_PHRASE_CAP],    # local evidence only
            "severity": severity,
            "owasp": owasp,
        })
    return out


# ---------------------------------------------------------------------------
# Sensitive file-access categories (discovery layer)
# ---------------------------------------------------------------------------

# (category, severity, compiled-path-regex). Matched against the accessed path
# only; the candidate carries ONLY the category + tool — never the exact path.
_SENSITIVE_PATH_RULES = (
    # A file under ~/.ssh that is a key (id_*, or any non-public file) — but NOT
    # the routine non-secret files (config, known_hosts, authorized_keys, *.pub).
    ("ssh-private-key", "critical", re.compile(
        r"(?:^|/)\.ssh/(?!(?:config|known_hosts|authorized_keys)$)(?!.*\.pub$).+"
        r"|(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)", re.IGNORECASE)),
    # A real .env — but NOT the committed, secret-free templates (.example etc.).
    ("env-file", "high", re.compile(
        r"(?:^|/)\.env(?:\.[\w.-]+)?$(?<!\.example)(?<!\.sample)(?<!\.template)(?<!\.dist)(?<!\.default)",
        re.IGNORECASE)),
    ("credentials", "critical", re.compile(
        r"(?:^|/)\.aws/credentials$|(?:^|/)\.netrc$|(?:^|/)\.npmrc$|(?:^|/)\.docker/config\.json$"
        r"|(?:^|/)\.kube/config$|(?:^|/)\.config/gcloud(?:/|$)", re.IGNORECASE)),
    ("password-store", "critical", re.compile(r"(?:^|/)\.password-store(?:/|$)|(?:^|/)\.pgpass$", re.IGNORECASE)),
    # Real browser credential stores only — anchored to a browser profile dir so
    # a project file literally named `Cookies` / `Login Data` isn't misflagged.
    ("browser-cookies", "high", re.compile(
        r"(?:Chrome|Chromium|Brave|Edge|Opera|Vivaldi|BraveSoftware)[\s\S]{0,120}/(?:Cookies|Login Data)$"
        r"|(?:^|/)cookies\.sqlite$|(?:^|/)Cookies\.binarycookies$"
        r"|(?:^|/)Library/Keychains(?:/|$)|(?:^|/)login\.keychain", re.IGNORECASE)),
    ("system-shadow", "critical", re.compile(r"^/etc/(?:shadow|passwd|sudoers)$", re.IGNORECASE)),
)

# Tools whose args reference a file/path. Value = tuple of candidate arg keys.
_FILE_ACCESS_TOOLS = {
    "read": "read",
    "write": "write",
    "read_file": "read",
    "write_file": "write",
    "edit_file": "write",
    "edit": "write",
    "patch": "write",
    "apply_patch": "write",
    "create_file": "write",
    "delete_file": "write",
    "open_file": "read",
    "cat": "read",
    "skill_manage": "write",
}
_PATH_KEYS = ("path", "file", "file_path", "filepath", "filename", "target", "target_file")


def _npmrc_has_token(args: Any) -> bool:
    """True when a .npmrc write/content carries an ``_authToken`` (credential)."""
    text = _command_from_args("", args) if not isinstance(args, dict) else ""
    if isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str):
                text += "\n" + v
    return "_authtoken" in text.lower()


def file_access_arg(tool_name: str, args: Any) -> Optional[Dict[str, str]]:
    """Extract ``{tool, path, mode}`` for a file-access tool call, or ``None``.

    Recognises the file-touching tools in :data:`_FILE_ACCESS_TOOLS`. ``mode``
    is ``read`` or ``write``. Returns ``None`` for non-file tools or missing
    path — pure/deterministic, used for both visibility logging and detection.
    """
    tool = (tool_name or "").strip().lower()
    if tool not in _FILE_ACCESS_TOOLS or not isinstance(args, dict):
        return None
    path = ""
    for key in _PATH_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            path = val.strip()
            break
    if not path:
        return None
    return {"tool": tool, "path": path, "mode": _FILE_ACCESS_TOOLS[tool]}


def sensitive_path_category(path: str, args: Any = None) -> Optional[Dict[str, str]]:
    """Classify *path* into a sensitive category, or ``None``.

    Returns ``{category, severity}``. The ``.npmrc`` file is only sensitive
    when it carries an ``_authToken`` (checked via *args*) — a bare .npmrc is
    ignored. Deterministic; the caller carries ONLY the category off-box.
    """
    if not path:
        return None
    p = path.strip()
    if p.endswith(".npmrc"):
        # A token-bearing .npmrc is a credential store, so match the rest of the
        # `credentials` category at `critical` (not `high`).
        return {"category": "credentials", "severity": "critical"} if _npmrc_has_token(args) else None
    for category, severity, pattern in _SENSITIVE_PATH_RULES:
        try:
            if pattern.search(p):
                return {"category": category, "severity": severity}
        except re.error:  # pragma: no cover - static patterns
            continue
    return None


# ---------------------------------------------------------------------------
# Secret VALUE detection — an actual key/token/private-key present in tool args.
# This is the "the agent is handling/leaking a real secret" signal, distinct
# from touching a secret FILE. Format-anchored so only unambiguous secret shapes
# match (a legit `Authorization: Bearer <opaque>` API call is NOT flagged, but a
# recognizable provider key or a private-key block is).
# ---------------------------------------------------------------------------

_SECRET_VALUE_RULES = (
    ("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("anthropic-api-key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-api-key", "high", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("github-token", "high", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}")),
    ("slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", "high", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("gcp-service-account-key", "high", re.compile(r'"type"\s*:\s*"service_account"')),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)

# Commands that SEND data off-box — a secret value alongside one of these is
# exfiltration (critical/block), not routine handling.
_EGRESS_RE = re.compile(
    r"\b(?:nc|ncat|netcat|telnet|sendmail)\b"
    r"|\b(?:curl|wget)\b[\s\S]{0,300}(?:\s-d\b|--data|--data-binary|--data-raw|\s-F\b|--form|\s-T\b|--upload-file)"
    r"|\|\s*(?:nc|ncat|curl|wget)\b",
    re.IGNORECASE,
)


def scan_secret_values(text: str) -> List[Dict[str, str]]:
    """Return recognizable secret VALUES present in *text* as ``[{type, severity}]``.

    Deterministic; the caller carries only the secret TYPE off-box, NEVER the
    value (see :func:`redact_secret_values`).
    """
    if not text:
        return []
    scan = text[:_MAX_INJECTION_SCAN]
    out: List[Dict[str, str]] = []
    seen: set = set()
    for typ, severity, pattern in _SECRET_VALUE_RULES:
        if typ in seen:
            continue
        try:
            if pattern.search(scan):
                seen.add(typ)
                out.append({"type": typ, "severity": severity})
        except re.error:  # pragma: no cover - static patterns
            continue
    return out


def looks_like_egress(text: str) -> bool:
    """True when *text* contains a command that sends data off the machine."""
    return bool(text and _EGRESS_RE.search(text))


def redact_secret_values(text: str) -> str:
    """Replace every recognizable secret value in *text* with a typed marker."""
    out = str(text)
    for typ, _severity, pattern in _SECRET_VALUE_RULES:
        out = pattern.sub(f"[REDACTED_{typ.upper().replace('-', '_')}]", out)
    return out


# ---------------------------------------------------------------------------
# Suspicious-skill danger-shape scanning (discovery layer)
# ---------------------------------------------------------------------------

# (dangerShape, severity, compiled-regex) over the skill's declared code/content.
_SKILL_CODE_RULES = (
    # Bare shell-out is normal for legit skills (formatters, test runners, build
    # tools), so it is only a LOW informational signal — it stays in the local
    # audit but is below the default report floor, so it doesn't nominate to the
    # community graph. The genuinely dangerous shapes below keep their severity.
    ("shell-exec", "low", re.compile(
        r"\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|child_process|exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\()", re.IGNORECASE)),
    ("remote-script-pipe", "critical", REMOTE_SCRIPT_RE),
    ("credential-exfil", "critical", re.compile(
        r"(?:os\.environ|process\.env|getenv)\b[\s\S]{0,120}\b(?:requests\.(?:post|get)|fetch\s*\(|urlopen|http[s]?://)", re.IGNORECASE)),
    ("obfuscation", "high", re.compile(
        r"\b(?:eval|exec)\s*\(\s*(?:base64|atob|Buffer\.from|codecs\.decode)|\bbase64\.b64decode\b[\s\S]{0,40}\b(?:eval|exec)", re.IGNORECASE)),
)

# (dangerShape, severity, compiled-regex) over declared permissions/capabilities.
# No trailing \b — several of these end in ``*`` (a non-word char).
_SKILL_PERMISSION_RULES = (
    ("over-broad-filesystem", "high", re.compile(r"\b(?:filesystem[:_-]?\*|fs[:_-]?full|read[_-]?write[_-]?all|allowallpaths)", re.IGNORECASE)),
    ("over-broad-shell", "high", re.compile(r"\b(?:arbitrary[_-]?shell|shell[:_-]?\*|exec[:_-]?any|allowshell)", re.IGNORECASE)),
    ("over-broad-network", "medium", re.compile(r"\b(?:network[:_-]?\*|raw[_-]?socket|allowallhosts|net[:_-]?any)", re.IGNORECASE)),
)

# Tools that install/modify a skill.
_SKILL_TOOLS = {"skill_manage", "skill_install", "install_skill", "plugin_install", "install_plugin"}
_SKILL_NAME_KEYS = ("name", "skill", "skill_name", "id", "plugin")
_SKILL_VERSION_KEYS = ("version", "skill_version", "ver")
_SKILL_CODE_KEYS = ("code", "content", "source", "body", "script")
_SKILL_PERM_KEYS = ("permissions", "capabilities", "scopes", "allow", "grants")

_MAX_SKILL_SCAN = 20_000


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k} {_stringify(v)}" for k, v in value.items())
    return str(value) if value is not None else ""


def skill_install_arg(tool_name: str, args: Any) -> Optional[Dict[str, str]]:
    """Extract a skill install/modify descriptor, or ``None``.

    Returns ``{name, version, code, permissions}`` (missing fields empty).
    ``code``/``permissions`` are the concatenated content to scan; they are
    NEVER carried off-box — only matched danger-shape names are submitted.
    """
    tool = (tool_name or "").strip().lower()
    if tool not in _SKILL_TOOLS or not isinstance(args, dict):
        return None
    name = ""
    for key in _SKILL_NAME_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            name = val.strip()
            break
    if not name:
        return None
    version = ""
    for key in _SKILL_VERSION_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            version = val.strip()
            break
    code = " ".join(_stringify(args.get(k)) for k in _SKILL_CODE_KEYS if args.get(k))
    perms = " ".join(_stringify(args.get(k)) for k in _SKILL_PERM_KEYS if args.get(k))
    return {"name": name, "version": version, "code": code[:_MAX_SKILL_SCAN], "permissions": perms[:_MAX_SKILL_SCAN]}


def scan_skill_dangers(code: str, permissions: str) -> List[Dict[str, str]]:
    """Return built-in skill danger matches as ``[{dangerShape, severity}]``.

    Scans *code* for dangerous-code shapes and *permissions* for over-broad
    capability grants. Deterministic; the caller carries only the shape name.
    """
    out: List[Dict[str, str]] = []
    seen: set = set()
    for text, rules in ((code or "", _SKILL_CODE_RULES), (permissions or "", _SKILL_PERMISSION_RULES)):
        if not text:
            continue
        for shape, severity, pattern in rules:
            if shape in seen:
                continue
            try:
                if pattern.search(text):
                    seen.add(shape)
                    out.append({"dangerShape": shape, "severity": severity})
            except re.error:  # pragma: no cover - static patterns
                continue
    return out


# ---------------------------------------------------------------------------
# Dependency install parsing
# ---------------------------------------------------------------------------

_SHELL_INSTALL_PATTERNS = (
    re.compile(r"\b(?:python(?:3)?\s+-m\s+)?pip3?\s+install\b", re.IGNORECASE),
    re.compile(r"\buv\s+pip\s+install\b", re.IGNORECASE),
    re.compile(r"\buv\s+add\b", re.IGNORECASE),
    re.compile(r"\buvx\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(?:install|i|add)\b", re.IGNORECASE),
    re.compile(r"\bpnpm\s+add\b", re.IGNORECASE),
    re.compile(r"\byarn\s+add\b", re.IGNORECASE),
    re.compile(r"\bbun\s+add\b", re.IGNORECASE),
    re.compile(r"\bcargo\s+add\b", re.IGNORECASE),
    re.compile(r"\bgem\s+install\b", re.IGNORECASE),
    re.compile(r"\bbrew\s+install\b", re.IGNORECASE),
)

_TOKEN_RE = re.compile(r"""\"([^\"]*)\"|'([^']*)'|(\S+)""")


def _tokenize_shell(command: str) -> List[str]:
    out: List[str] = []
    for m in _TOKEN_RE.finditer(command):
        out.append(m.group(1) or m.group(2) or m.group(3) or "")
    return out


def _parse_package_token(raw: str, ecosystem: str) -> Optional[Dict[str, str]]:
    """Parse a single install token into ``{name, version}`` for *ecosystem*."""
    token = raw.replace(",", "").replace(";", "").strip()
    if not token or token.startswith(("http://", "https://", "/", ".", "@git")):
        return None
    if ecosystem in ("pypi", "rubygems"):
        exact = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)", token)
        if exact:
            return {"name": exact.group(1), "version": exact.group(2)}
        loose = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?", token)
        if loose:
            return {"name": loose.group(1), "version": ""}
        return None
    if ecosystem == "npm":
        idx = token.rfind("@")
        if idx > 0:  # scoped names start with @, so require idx > 0
            return {"name": token[:idx], "version": token[idx + 1 :]}
        if re.fullmatch(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+", token):
            return {"name": token, "version": ""}
        return None
    # cargo / homebrew / other: name[@version]
    idx = token.rfind("@")
    if idx > 0:
        return {"name": token[:idx], "version": token[idx + 1 :]}
    if re.fullmatch(r"[A-Za-z0-9._+/-]+", token):
        return {"name": token, "version": ""}
    return None


# manager token -> (ecosystem, number of leading subcommand tokens to skip)
_MANAGER_SPECS = {
    ("pip", "install"): ("pypi", 2),
    ("pip3", "install"): ("pypi", 2),
    ("uv", "pip"): ("pypi", 3),  # `uv pip install <pkg>`
    ("uv", "add"): ("pypi", 2),
    ("uvx",): ("pypi", 1),
    ("npm", None): ("npm", 2),  # npm install|i|add
    ("pnpm", "add"): ("npm", 2),
    ("yarn", "add"): ("npm", 2),
    ("bun", "add"): ("npm", 2),
    ("cargo", "add"): ("cargo", 2),
    ("gem", "install"): ("rubygems", 2),
    ("brew", "install"): ("homebrew", 2),
}


#: cat-family commands whose following path args are file reads.
_SHELL_READ_CMDS = {"cat", "less", "more", "head", "tail", "bat", "xxd", "hexdump", "strings", "od", "nl"}


def _looks_like_path(token: str) -> bool:
    return "/" in token or token.startswith("~") or token.startswith(".") or "." in token


def parse_shell_reads(command: str) -> List[str]:
    """Best-effort list of file paths a cat-family command in *command* reads.

    Completes the audit trail for the shell channel: ``cat ~/.ssh/id_rsa`` is a
    file read that the dedicated file tools would log, but a raw shell tool would
    otherwise miss. Pure/deterministic; used for visibility logging only.
    """
    if not command or not any(f" {c} " in f" {command} " for c in _SHELL_READ_CMDS):
        return []
    tokens = _tokenize_shell(command)
    out: List[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i].lower() in _SHELL_READ_CMDS:
            j = i + 1
            while j < len(tokens) and tokens[j] not in (";", "&&", "||", "|", ">", ">>", "<"):
                tok = tokens[j]
                if not tok.startswith("-") and _looks_like_path(tok):
                    out.append(tok)
                j += 1
            i = j
        else:
            i += 1
    return list(dict.fromkeys(out))


def parse_downloads(command: str) -> List[str]:
    """URLs fetched by a curl/wget in *command* (for the download audit trail)."""
    if not command or not re.search(r"\b(?:curl|wget)\b", command, re.IGNORECASE):
        return []
    return list(dict.fromkeys(re.findall(r"https?://[^\s;'\"|&>]+", command)))


# IOC extraction — pull indicators out of arbitrary tool-call text so a match
# against a synced ``ioc:`` rule can fire. Only KNOWN-BAD values (already in the
# ruleset) ever match, so broad extraction is safe: a token that isn't a known
# threat is a cheap dict miss, not a false positive.
_URL_RE = re.compile(r"https?://[^\s'\"<>|\\)}\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_BTC_RE = re.compile(r"\b(?:bc1[023-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b")
_SOL_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
_MAX_IOC_TEXT = 50_000
_MAX_IOC_CANDIDATES = 4000


def _host_suffixes(host: str) -> List[str]:
    """A host plus the parent domains a ``domain:`` rule might use.

    ``login.evil.co.uk`` yields ``login.evil.co.uk``, ``evil.co.uk``, ``co.uk``
    and a ``www.``-stripped variant, so a rule on the registrable domain
    still fires on a subdomain. No public-suffix list (kept dependency-free):
    the parent walk stops at two labels and every candidate is an O(1) lookup.
    """
    host = host.strip(".").lower()
    if not host:
        return []
    out = [host]
    if host.startswith("www."):
        out.append(host[4:])
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        out.append(".".join(labels[i:]))
    return list(dict.fromkeys(out))


def iter_ioc_candidates(text: str) -> List[str]:
    """Candidate ``ioc:`` identifiers to look up for *text* (deduped, capped).

    Extracts URLs (+ their hosts), bare domains, IPv4s, sha256/md5 hashes, and
    EVM/BTC/Solana crypto addresses. An EVM/base58 address is emitted as BOTH a
    ``wallet:`` and a ``contract:`` candidate (the address alone doesn't say
    which), so either representation matches.
    """
    if not text:
        return []
    if len(text) > _MAX_IOC_TEXT:
        text = text[:_MAX_IOC_TEXT]
    out: List[str] = []
    seen: set = set()

    def add(ioc_type: str, value: str) -> None:
        if len(out) >= _MAX_IOC_CANDIDATES:
            return
        ident = ioc_identifier(ioc_type, value)
        if ident not in seen:
            seen.add(ident)
            out.append(ident)

    for url in _URL_RE.findall(text):
        clean = url.rstrip(".,);'\"")
        add("url", clean)
        host = clean.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":", 1)[0]
        for suffix in _host_suffixes(host):
            add("domain", suffix)
    for host in _DOMAIN_RE.findall(text):
        for suffix in _host_suffixes(host):
            add("domain", suffix)
    for ip in _IPV4_RE.findall(text):
        add("ip", ip)
    for h in _SHA256_RE.findall(text):
        add("hash", f"sha256:{h}")
    for h in _SHA1_RE.findall(text):
        add("hash", f"sha1:{h}")
    for h in _MD5_RE.findall(text):
        add("hash", f"md5:{h}")
    for addr in _EVM_ADDR_RE.findall(text) + _BTC_RE.findall(text) + _SOL_RE.findall(text):
        add("wallet", addr)
        add("contract", addr)
    return out


def parse_dependency_installs(command: str) -> List[Dict[str, str]]:
    """Parse install commands into ``[{ecosystem, name, version}, ...]``.

    Supports pip/uv/uvx/npm/pnpm/yarn/bun/cargo/gem/brew. Returns an empty list
    when the command is not an install (cheap gate first). Deduplicates.
    """
    if not command or not any(p.search(command) for p in _SHELL_INSTALL_PATTERNS):
        return []
    tokens = _tokenize_shell(command)
    out: List[Dict[str, str]] = []
    seen: set = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()
        nxt = tokens[i + 1].lower() if i + 1 < len(tokens) else None
        ecosystem = ""
        start = -1
        if (tok, "pip") in _MANAGER_SPECS and nxt == "pip":
            ecosystem, skip = _MANAGER_SPECS[(tok, "pip")]
            start = i + skip
        elif (tok, nxt) in _MANAGER_SPECS:
            ecosystem, skip = _MANAGER_SPECS[(tok, nxt)]
            start = i + skip
        elif (tok,) in _MANAGER_SPECS:
            ecosystem, skip = _MANAGER_SPECS[(tok,)]
            start = i + skip
        elif tok == "npm" and nxt in ("install", "i", "add"):
            ecosystem, start = "npm", i + 2
        if start < 0 or not ecosystem:
            i += 1
            continue
        j = start
        while j < len(tokens):
            raw = tokens[j]
            if raw in (";", "&&", "||", "|"):
                break
            if raw.startswith("-") or raw in ("install", "add", "i"):
                j += 1
                continue
            parsed = _parse_package_token(raw, ecosystem)
            if parsed and parsed["name"]:
                key = f"{ecosystem}:{parsed['name'].lower()}:{parsed['version']}"
                if key not in seen:
                    seen.add(key)
                    out.append({"ecosystem": ecosystem, **parsed})
            j += 1
        i = j
    return out


# ---------------------------------------------------------------------------
# N-Triples term escaping
# ---------------------------------------------------------------------------


def iri(value: str) -> str:
    """Render an IRI term (bare, per the daemon's quad object convention)."""
    return value


# DKG v10 validates writable RDF literals with dkg-core's
# DKG_RDF_LITERAL_SAFE_MUTF8_BYTES (60,000 Java Modified UTF-8 bytes for the
# full quoted RDF literal term). That is below Java's writeUTF 65,535-byte
# ceiling and is enforced across Oxigraph/Blazegraph-compatible paths. Keep
# Blackbox below it so one oversized threat field cannot abort a peer's sync
# insert for the whole graph.
_DKG_RDF_LITERAL_SAFE_MUTF8_BYTES = 60000
_MAX_LITERAL_BYTES = 50000
_TRUNCATION_MARKER = " ...[truncated]"


def java_modified_utf8_byte_length(value: str) -> int:
    """Java Modified UTF-8 byte length, matching DKG's literal validator."""
    raw = str(value).encode("utf-16-be", "surrogatepass")
    total = 0
    for i in range(0, len(raw), 2):
        code = (raw[i] << 8) | raw[i + 1]
        if code == 0:
            total += 2
        elif code <= 0x7F:
            total += 1
        elif code <= 0x07FF:
            total += 2
        else:
            total += 3
    return total


def _escape_literal_text(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def literal_term_mutf8_byte_length(term: str) -> Optional[int]:
    """Java MUTF-8 byte length for a quoted RDF literal term, or ``None`` for IRIs."""
    if not str(term).startswith('"'):
        return None
    return java_modified_utf8_byte_length(str(term))


def _literal_term_for_value(value: str) -> str:
    return f'"{_escape_literal_text(value)}"'


def _literal_value_term_mutf8_bytes(value: str) -> int:
    return java_modified_utf8_byte_length(_literal_term_for_value(value))


def _cap_literal_value(value: str) -> str:
    text = str(value)
    if _literal_value_term_mutf8_bytes(text) <= _MAX_LITERAL_BYTES:
        return text

    marker = _TRUNCATION_MARKER
    chars = list(text)
    lo, hi = 0, len(chars)
    best = marker
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = "".join(chars[:mid]) + marker
        if _literal_value_term_mutf8_bytes(candidate) <= _MAX_LITERAL_BYTES:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def assert_quads_literal_size(
    quads: Iterable[Quad],
    *,
    max_bytes: int = _MAX_LITERAL_BYTES,
    label: str = "quads",
) -> None:
    """Raise when any outgoing RDF literal term exceeds Blackbox's DKG budget."""
    for i, q in enumerate(quads):
        obj = q.get("object", "") if isinstance(q, dict) else ""
        actual = literal_term_mutf8_byte_length(obj)
        if actual is not None and actual > max_bytes:
            raise ValueError(
                f"RDF literal {label}[{i}].object is {actual} Java MUTF-8 bytes, "
                f"exceeds Blackbox cap {max_bytes}; subject={q.get('subject')!r} "
                f"predicate={q.get('predicate')!r}"
            )


def literal(value: str) -> str:
    """Render a plain-string literal term with N-Triples escaping.

    Oversized values are truncated to keep every literal below the DKG store's
    per-literal byte cap (:data:`_MAX_LITERAL_BYTES`); an over-limit literal
    aborts a peer's graph sync and hides the whole community graph from them.
    """
    return _literal_term_for_value(_cap_literal_value(str(value)))


def datetime_literal(ts: Optional[datetime] = None) -> str:
    """Render an ``xsd:dateTime`` typed literal (UTC ISO-8601)."""
    when = ts or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    iso = when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return f'{literal(iso)}^^{constants.XSD_DATETIME}'


def _q(subject: str, predicate: str, obj: str) -> Quad:
    return {"subject": subject, "predicate": predicate, "object": obj}


# ---------------------------------------------------------------------------
# Legacy proof anchors (read compatibility only)
# ---------------------------------------------------------------------------

#: Detection-relevant fields covered by a threat's anchor hash, in canonical
#: order. Producers and consumers hash the same SPARQL binding values, so
#: tampering with any field the detector consumes breaks the batch root.
ANCHOR_FIELDS = ("identifier", "kind", "severity", "name", "pattern", "toolName", "argShape")


def threat_anchor_hash(fields: Dict[str, Any]) -> str:
    """Canonical sha256 over a threat row's detection-relevant fields."""
    lines = [f"{k}={fields.get(k) or ''}" for k in ANCHOR_FIELDS]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def anchor_hashes_from_rows(rows: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """Map identifier -> anchor hash from plain-string binding rows.

    A re-published threat can yield several rows per identifier; keeping the
    lexicographically greatest hash makes independent clients converge on
    the same value without coordinating row order.
    """
    out: Dict[str, str] = {}
    for row in rows:
        ident = str(row.get("identifier") or "").strip()
        if not ident:
            continue
        h = threat_anchor_hash(row)
        if ident not in out or h > out[ident]:
            out[ident] = h
    return out


def anchor_root(pairs: Iterable[tuple]) -> str:
    """Batch root: sha256 over the sorted ``identifier\\x00hash`` lines."""
    lines = sorted(f"{ident}\x00{h}" for ident, h in pairs)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Threat / report quad builders
# ---------------------------------------------------------------------------


def build_report_quads(
    *,
    identifier: str,
    category: str,
    severity: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    # optional full threat fields for NEW candidate threats
    pattern: Optional[str] = None,
    owasp_category: Optional[str] = None,
    tool_name: Optional[str] = None,
    arg_shape: Optional[str] = None,
    ecosystem: Optional[str] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    advisory_id: Optional[str] = None,
    file_category: Optional[str] = None,
    skill_name: Optional[str] = None,
    skill_version: Optional[str] = None,
    danger_shape: Optional[str] = None,
    kind: Optional[str] = None,
) -> List[Quad]:
    """Build a sighting/report for SWM.

    The subject is per-submitter namespaced (:func:`report_uri`). A report
    NEVER carries observed prompt/command text (privacy split — that stays in
    the private WM audit). For a NEW candidate threat, the caller may pass the
    threat fields needed for independent review.
    """
    subj = report_uri(identifier, reporter_address)
    threat = threat_uri(identifier)
    out: List[Quad] = [
        _q(subj, constants.RDF_TYPE, iri(constants.REPORT_TYPE_IRI)),
        _q(subj, constants.REPORTS_THREAT_PRED, iri(threat)),
        _q(subj, constants.IDENTIFIER_PRED, literal(identifier)),
        _q(subj, constants.REPORTER_PRED, literal((reporter_address or "anonymous").lower())),
        _q(subj, constants.FRAMEWORK_PRED, literal(framework)),
        _q(subj, constants.SEVERITY_PRED, literal(constants.normalize_severity(severity))),
        _q(subj, constants.SCHEMA_DATE_MODIFIED_PRED, datetime_literal(ts)),
    ]
    if category == "injection" and pattern:
        out.append(_q(subj, constants.PATTERN_PRED, literal(pattern)))
        if owasp_category:
            out.append(_q(subj, constants.OWASP_CATEGORY_PRED, literal(owasp_category)))
    elif category == "escalation":
        if tool_name:
            out.append(_q(subj, constants.TOOL_NAME_PRED, literal(tool_name)))
        if arg_shape:
            out.append(_q(subj, constants.ARG_SHAPE_PRED, literal(arg_shape)))
    elif category == "dependency":
        if package_name:
            out.append(_q(subj, constants.PACKAGE_NAME_PRED, literal(package_name)))
        if package_version:
            out.append(_q(subj, constants.PACKAGE_VERSION_PRED, literal(package_version)))
        if ecosystem:
            out.append(_q(subj, constants.PACKAGE_ECOSYSTEM_PRED, literal(ecosystem)))
        if advisory_id:
            out.append(_q(subj, constants.SCHEMA_IDENTIFIER_PRED, literal(advisory_id)))
        # Keep the dependency kind intact in the community report.
        if kind:
            out.append(_q(subj, constants.KIND_PRED, literal(kind)))
    elif category == "fileaccess":
        if tool_name:
            out.append(_q(subj, constants.TOOL_NAME_PRED, literal(tool_name)))
        if file_category:
            out.append(_q(subj, constants.CATEGORY_PRED, literal(file_category)))
    elif category == "skill":
        if skill_name:
            out.append(_q(subj, constants.SKILL_NAME_PRED, literal(skill_name)))
        if skill_version:
            out.append(_q(subj, constants.SKILL_VERSION_PRED, literal(skill_version)))
        if danger_shape:
            out.append(_q(subj, constants.DANGER_SHAPE_PRED, literal(danger_shape)))
    return out
