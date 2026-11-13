"""Redaction — THE one implementation that scrubs secret values out of text.

Every place that writes or sends text that might hold a secret (the local
audit logs, the private audit record, the opt-in LLM reviewer) goes through
this module, so a secret shape learned once is scrubbed everywhere (quality
item G1). The same rule table is detection's source for "the agent is
handling a real secret" findings.

Usage::

    from ..kernel import redaction
    safe = redaction.redact_secret_values(text)
    for secret_type, severity, pattern in redaction.SECRET_VALUE_RULES: ...
"""

from __future__ import annotations

import re

from .crypto_secrets import redact_bitcoin_keys, redact_own_keys, redact_seed_phrases, redact_solana_keys, text_view

# ---------------------------------------------------------------------------
# Secret VALUE detection — an actual key/token/private-key present in tool args.
# This is the "the agent is handling/leaking a real secret" signal, distinct
# from touching a secret FILE. Format-anchored so only unambiguous secret shapes
# match (a legit `Authorization: Bearer <opaque>` API call is NOT flagged, but a
# recognizable provider key or a private-key block is).
# ---------------------------------------------------------------------------

SECRET_VALUE_RULES = (
    # The WHOLE block — through its END line, or to the end of the text when the
    # block was cut off — so redaction removes the key material, not just the
    # header line (KI-178). Detection matches on the same header as before.
    ("private-key", "critical", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("aws-access-key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("anthropic-api-key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-api-key", "high", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("github-token", "high", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}")),
    ("slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", "high", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("gcp-service-account-key", "high", re.compile(r'"type"\s*:\s*"service_account"')),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    # A raw wallet key (MetaMask "Export private key": 64 hex) is shaped exactly
    # like a transaction hash, so it counts only right after a key LABEL —
    # PRIVATE_KEY=, "privateKey": "…", private key: …, PK= (Polymarket's env
    # name), wallet_key / eth_key / key= — or inside a key-taking call
    # (eth_account's Account.from_key(…), viem's privateKeyToAccount(…), ethers'
    # new Wallet(…)). "public key" is never a label. The value is 64+ hex (0x / 0X,
    # anything after it — a key followed by a letter or more hex is still a key).
    # The label goes with the value when redacted.
    # Handling one flags (an agent's own trading config holds one); sending it out
    # is critical (KI-380).
    # Linear time: the name around the keyword is at most 64 characters each side;
    # the unbounded `[A-Za-z0-9_]*` before it backtracked quadratically ("privatekey"
    # x 1000 took 0.2 s on every redaction, KI-382).
    ("wallet-private-key", "high", re.compile(
        r"(?:\b(?:[A-Za-z0-9_]{0,64}?(?:private[ _-]?key|priv[_-]?key|secret[ _-]?key|signer[ _-]?key|signing[ _-]?key"
        r"|wallet[ _-]?key|eth[_-]?key|evm[_-]?key|account[_-]?key)[A-Za-z0-9_]{0,64}|pk|(?<!public )(?<!public_)(?<!public-)key)"
        r"[\"']?[ \t]*(?:[:=]|\bis\b)[ \t]*[\"']?"
        r"|\b(?:from_key|from_private_key|fromPrivateKey|privateKeyToAccount|Wallet|Account)[ \t]*\([ \t]*[\"'`]?)"
        r"(?:0x)?[0-9a-f]{64}[0-9a-f]*",
        re.IGNORECASE)),
    # A Solana seed half (32 bytes, 43-44 base58 characters) has no self-check and reads
    # like an address, so it counts only after a Solana key label (SOLANA_PRIVATE_KEY=,
    # solanaSecretKey: …). A bare one stays a gap (KI-380).
    ("wallet-private-key", "high", re.compile(
        r"\b[A-Za-z0-9_]{0,32}?(?:sol(?:ana)?|phantom|keypair)[_ -]?(?:private|secret)?[_ -]?(?:key|seed)[A-Za-z0-9_]{0,32}"
        r"[\"']?[ \t]*[:=][ \t]*[\"']?[1-9A-HJ-NP-Za-km-z]{43,44}(?![1-9A-HJ-NP-Za-km-z])",
        re.IGNORECASE)),
)


# Redaction-only shapes: scrubbed from anything written or sent, but too broad
# to be detection signals (they would raise findings on ordinary text).
_REDACTION_ONLY_RULES = (
    # Shorter/older provider keys than the detection rules above require.
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}")),
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
#: THE words that mark a name as holding a secret, as regex fragments matched without regard
#: to case anywhere inside a longer name (``AWS_SECRET_ACCESS_KEY``, ``refresh_token``,
#: ``clientSecret``). One list for both places a name is judged: a ``name=value`` in text
#: (below) and a key of a structure being logged (:data:`SECRET_NAME_RE`, used by
#: ``audit.redaction``). They were two lists and had drifted: one lacked ``access_key``,
#: the other ``authorization``.
SECRET_NAME_WORDS = ("api[_-]?key", "token", "secret", "password", "passwd", "credential",
                     "authorization", "private[_-]?key", "access[_-]?key")
_SECRET_NAME_PATTERN = "|".join(SECRET_NAME_WORDS)
#: Matches a name that holds a secret (search it in the name).
SECRET_NAME_RE = re.compile(_SECRET_NAME_PATTERN, re.IGNORECASE)

# A secret-named key followed by `:` or `=` and a value: `DB_PASSWORD=...`,
# `"api_key": "..."`. The key name stays (it explains the log line); the value
# goes. A value already replaced by a typed marker (`[REDACTED_...]`) is kept.
# Linear time on hostile text: a bounded look-ahead finds the keyword inside the
# name, then at most 64 name characters are taken possessively (`{1,64}+`, no
# backtracking); a longer run cannot be one name, so it is not rescanned per position.
# The earlier `\b[...]*(?:keyword)[...]*` re-split every long word run and took
# seconds per KB on text like "tokens-tokens-..." — on every tool call (KI-373).
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<key>\b(?=[A-Za-z0-9_-]{0,64}?(?:" + _SECRET_NAME_PATTERN + r"))[A-Za-z0-9_-]{1,64}+[\"']?)"
    r"(?P<sep>\s*[:=]\s*[\"']?)"
    r"(?P<value>[^\s\"'\[\],;]{8,})",
    re.IGNORECASE,
)


def redact_secret_values(text: str) -> str:
    """Replace every recognizable secret value in *text* with a marker.

    Percent escapes are decoded first (a URL is read as its receiver reads it). Wallet
    seed phrases become ``[REDACTED_SEED_PHRASE]`` and verified Solana
    secret keys ``[REDACTED_SOLANA_KEY]``; Bitcoin WIF and extended keys
    ``[REDACTED_BITCOIN_PRIVATE_KEY]`` / ``[REDACTED_EXTENDED_PRIVATE_KEY]``; a raw
    64-hex key that opens one of the operator's listed addresses (Trader Shield settings)
    ``[REDACTED_WALLET_PRIVATE_KEY]``; known secret
    shapes become typed markers (``[REDACTED_PRIVATE_KEY]``);
    bearer tokens become ``Bearer [REDACTED]``; secret-named assignments keep
    their key and lose their value (``DB_PASSWORD=[REDACTED]``). Truncate
    AFTER calling this, never before — a secret cut in half no longer matches.
    """
    # A URL is read the way its receiver reads it: %2C, %3D, %20 and double-encoded escapes
    # decoded first, so no rule is dodged by encoding (KI-377).
    out = text_view.percent_decoded(str(text))
    out = redact_seed_phrases(out)          # wallet seed phrases first: words no shape rule recognises
    out = redact_solana_keys(out)           # then Solana keys: proven by their own Ed25519 self-check
    out = redact_bitcoin_keys(out)          # then Bitcoin WIF / xprv keys: proven by their Base58Check checksum
    for typ, _severity, pattern in SECRET_VALUE_RULES:
        out = pattern.sub(f"[REDACTED_{typ.upper().replace('-', '_')}]", out)
    out = redact_own_keys(out)              # then UNLABELLED raw keys of the operator's listed addresses (KI-377)
    for typ, pattern in _REDACTION_ONLY_RULES:
        out = pattern.sub(f"[REDACTED_{typ.upper().replace('-', '_')}]", out)
    out = _BEARER_RE.sub("Bearer [REDACTED]", out)
    return _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group('key')}{m.group('sep')}[REDACTED]", out)
