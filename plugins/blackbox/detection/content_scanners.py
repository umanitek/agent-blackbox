"""Content scanners: what is IN the text an agent is about to act on.

Bounded, pure scans over untrusted text — injection heuristics (OWASP LLM01 /
LLM06), secret-shaped values (and their redaction), danger shapes in skill
code/permissions, and IOC candidates (URLs, domains, IPs, hashes, wallets)
checked against the ruleset by identifier.
"""

from __future__ import annotations

import re
from . import shell_shapes
from ..kernel import crypto_secrets, redaction, threat_ids

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


def scan_injection_heuristics(text: str) -> list[dict[str, str]]:
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
    out: list[dict[str, str]] = []
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


#: Secret values are looked for in the first AND the last this-many characters of a text
#: (the whole text when it is shorter than both): a secret padded past the head is still
#: seen, and the cost stays bounded on any input (KI-376). A secret placed in the middle
#: of a text longer than twice this is a known gap.
SECRET_SCAN_WINDOW = 50_000
_SEVERITY_RANK = {"": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


def secret_scan_windows(text: str) -> tuple[str, ...]:
    """The parts of *text* a secret scan reads: all of it, or its head and its tail."""
    if len(text) <= 2 * SECRET_SCAN_WINDOW:
        return (text,)
    return (text[:SECRET_SCAN_WINDOW], text[-SECRET_SCAN_WINDOW:])


def scan_secret_values(text: str, *more: str) -> list[dict[str, str]]:
    """Return recognizable secret VALUES present in *text* (and in each of *more*, read
    independently — e.g. the decoded URLs of the same call) as ``[{type, severity}]``,
    each type once at the worst severity any window gave it (see
    :data:`SECRET_SCAN_WINDOW`).

    Deterministic; the caller carries only the secret TYPE off-box, NEVER the
    value (see ``kernel.redaction.redact_secret_values``).
    """
    worst: dict[str, str] = {}
    for window in (window for part in (text, *more) if part for window in secret_scan_windows(part)):
        for hit in _scan_window(window):
            if _SEVERITY_RANK[hit["severity"]] > _SEVERITY_RANK[worst.get(hit["type"], "")]:
                worst[hit["type"]] = hit["severity"]
    return [{"type": secret_type, "severity": severity} for secret_type, severity in worst.items()]


def _scan_window(scan: str) -> list[dict[str, str]]:
    """The secret values in one window of text."""
    out: list[dict[str, str]] = []
    seen: set = set()
    for typ, severity, pattern in redaction.SECRET_VALUE_RULES:
        if typ in seen:
            continue
        try:
            if pattern.search(scan):
                seen.add(typ)
                out.append({"type": typ, "severity": severity})
        except re.error:  # pragma: no cover - static patterns
            continue
    seed = _seed_phrase_severity(scan)
    if seed:
        out.append({"type": "seed-phrase", "severity": seed})
    # A Solana secret key (Phantom's export, the CLI's id.json) proves itself, but an
    # agent's own trading setup may hold one: handling it flags, sending it is critical.
    if crypto_secrets.find_solana_secret_keys(scan):
        out.append({"type": "solana-private-key", "severity": "high"})
    # A Bitcoin WIF key or an extended private key (xprv…) proves itself by its checksum.
    if crypto_secrets.find_bitcoin_private_keys(scan):
        out.append({"type": "bitcoin-private-key", "severity": "high"})
    return out


def _seed_phrase_severity(text: str) -> str:
    """How serious the worst seed phrase in *text* is, or ``""`` for none.

    critical (blocks): a checksum-valid phrase of 18+ words, or of 12/15 words
    with a cue ("seed", "recovery", numbered words) — MetaMask's Secret
    Recovery Phrase is 12 words. high: a valid 12/15-word phrase without a cue
    (1 in 16 random list-word runs passes the checksum). medium: a published
    test phrase, or a 12+ run of list words whose checksum fails (a mistyped
    phrase is still a secret). Sending any of them off the machine is raised to
    critical by the caller.
    """
    rank = {"": 0, "medium": 1, "high": 2, "critical": 3}
    worst = ""
    for run in crypto_secrets.find_seed_phrase_runs(text):
        if run.valid_words and not run.test_phrase and (run.valid_words >= 18 or run.has_cue):
            severity = "critical"
        elif run.valid_words and not run.test_phrase:
            severity = "high"
        else:
            severity = "medium"
        worst = max(worst, severity, key=rank.__getitem__)
    return worst


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
    ("remote-script-pipe", "critical", shell_shapes.REMOTE_SCRIPT_RE),
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


#: Every skill danger shape detection can name (code + permission rules) — the
#: closed vocabulary a community skill report is validated against (Refine R1).
SKILL_DANGER_SHAPES = frozenset(shape for shape, _sev, _rule in _SKILL_CODE_RULES + _SKILL_PERMISSION_RULES)


def scan_skill_dangers(code: str, permissions: str) -> list[dict[str, str]]:
    """Return built-in skill danger matches as ``[{dangerShape, severity}]``.

    Scans *code* for dangerous-code shapes and *permissions* for over-broad
    capability grants. Deterministic; the caller carries only the shape name.
    """
    out: list[dict[str, str]] = []
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


# IOC extraction — pull indicators out of arbitrary tool-call text so a match
# against a synced ``ioc:`` rule can fire. Only KNOWN-BAD values (already in the
# ruleset) ever match, so broad extraction is safe: a token that isn't a known
# threat is a cheap dict miss, not a false positive.
_URL_RE = re.compile(r"https?://[^\s'\"<>|\\)}\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# G6: at most 10 labels per candidate (a real IOC domain has a handful; an
# unbounded label chain made this scan quadratic — FIX-0025) and RFC hostname
# length limits in _host_suffixes.
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,10}[a-z]{2,24}\b", re.IGNORECASE)
_MAX_HOST_CHARS = 253
_MAX_HOST_LABELS = 16
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_BTC_RE = re.compile(r"\b(?:bc1[023-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b")
_SOL_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
_MAX_IOC_TEXT = 50_000
_MAX_IOC_CANDIDATES = 4000


def _host_suffixes(host: str) -> list[str]:
    """A host plus the parent domains a ``domain:`` rule might use.

    ``login.evil.co.uk`` yields ``login.evil.co.uk``, ``evil.co.uk``, ``co.uk``
    and a ``www.``-stripped variant, so a rule on the registrable domain
    still fires on a subdomain. No public-suffix list (kept dependency-free):
    the parent walk stops at two labels and every candidate is an O(1) lookup.
    """
    host = host.strip(".").lower()
    if not host or len(host) > _MAX_HOST_CHARS or host.count(".") >= _MAX_HOST_LABELS:
        return []   # not a hostname anyone resolves; never build its suffix chain (FIX-0025)
    out = [host]
    if host.startswith("www."):
        out.append(host[4:])
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        out.append(".".join(labels[i:]))
    return list(dict.fromkeys(out))


def iter_ioc_candidates(text: str) -> list[str]:
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
    out: list[str] = []
    seen: set = set()

    def add(ioc_type: str, value: str) -> None:
        if len(out) >= _MAX_IOC_CANDIDATES:
            return
        ident = threat_ids.ioc_identifier(ioc_type, value)
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
    for addr in threat_ids.EVM_ADDRESS_RE.findall(text) + _BTC_RE.findall(text) + _SOL_RE.findall(text):
        add("wallet", addr)
        add("contract", addr)
    return out
