"""Is a key-shaped value a real secret, or a placeholder that only looks like one? (BB-005)

The secret-value rules (``kernel.redaction.SECRET_VALUE_RULES``) match by SHAPE: ``sk-`` and
20 characters is an OpenAI key, a ``-----BEGIN PRIVATE KEY-----`` header is a private key.
Shape alone blocked the files every project writes on purpose: ``.env.example`` with
``OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx`` or ``sk-ant-your-key-here``, and unit tests of a
redaction filter holding ``ghp_abcdef…0123456789`` or a mock PEM block (field report,
2026-11-27, Windows coding workflow).

The judgement is on the VALUE, never on the file's path or name. WHY: a path rule
("anything under ``__tests__/`` only flags") would let an agent stage a REAL key by writing
it into a test file. A real key is random, so it cannot be made to look like a placeholder
without changing it (and then it is no longer the key). A value is a placeholder only when
it carries almost no randomness:

* a token's body, after its provider prefix, has at most :data:`_MAX_FILLER_DISTINCT`
  distinct characters (``xxxx…``, ``0000…``, ``XXXX…``), or
* what is left once placeholder words (``your``, ``key``, ``here``, ``test``, ``fake`` …) and
  counting runs (``abcd…``, ``1234…``) are taken out is shorter than :data:`_MIN_RANDOM_CHARS`, or
* it is a value a provider publishes in its own docs (:data:`_PUBLISHED_EXAMPLES`).

A private-key header is a placeholder only when NOTHING after it in the scanned text is a
line of key material (:data:`_MIN_PEM_MATERIAL` base64 characters in one stretch: PEM lines
are 64 wide, and the smallest real key, Ed25519 PKCS#8, is exactly 64). The whole rest of the
text is read, not only up to the END line, so splitting a header from its body
(``printf '%s' '-----BEGIN…' 'MIIE…'``) still counts. A header in a scan window that was CUT
(the head of a long call) and has no END line is still a key: its body may lie past the cut,
and "could not tell" is never "no key" (LES-011).

Usage::

    is_placeholder("openai-api-key", "sk-xxxxxxxxxxxxxxxxxxxxxxxx")          # True
    is_placeholder("openai-api-key", "sk-proj-9fK2…(a real random key)")      # False
    pem = "-----BEGIN PRIVATE KEY-----\\nMOCK\\n-----END PRIVATE KEY-----"
    is_placeholder("private-key", pem, 0, len(pem))                          # True
"""

from __future__ import annotations

import re

#: A token body with this many distinct characters or fewer is filler (``xxxx``, ``0000``).
_MAX_FILLER_DISTINCT = 4
#: Fewer random characters than this, once words and counting runs are out: a placeholder.
#: A real provider token keeps 20+ (every rule asks for 16–35+ characters of body).
_MIN_RANDOM_CHARS = 8
#: Base64 characters of key material a real private key always has in one stretch
#: (Ed25519 PKCS#8, the smallest, is exactly 64; PEM lines are 64 wide).
_MIN_PEM_MATERIAL = 64
#: A counting run this long or longer is taken out (``abc`` alone could be random).
_MIN_COUNTING_RUN = 4

#: Values providers print in their own documentation, used verbatim in examples everywhere.
_PUBLISHED_EXAMPLES = frozenset({
    # AWS's documented example access key id, built from pieces so no key-shaped literal sits in the
    # plugin (the catalog's own secret scan reads every file).
    "AKIA" + "IOSFODNN7EXAMPLE",
})

#: Provider prefixes, taken off before the body is judged (longest first).
_PREFIX = re.compile(r"^(?:sk-ant-(?:api\d+-)?|sk-proj-|sk-|github_pat_|gh[pousr]_|xox[baprs]-|AIza|AKIA"
                     r"|(?:sk|rk)_live_|0x)", re.IGNORECASE)
#: Words a person writes where a key will go. Matched inside the lowercased body.
_PLACEHOLDER_WORDS = re.compile(
    r"your|my|insert|enter|put|replace|change|me|goes|here|placeholder|example|sample|dummy|fake|mock"
    r"|test(?:ing)?|redacted|todo|not|real|valid|api|keys?|tokens?|secret|value|openai|anthropic|claude"
    r"|github|google|gemini|slack|stripe|aws|proj(?:ect)?|live|personal|access|bot|user|app|pat")
#: Separators and filler marks inside a placeholder (``your-key-here``, ``<key>``, ``sk-...``).
_NOT_ALNUM = re.compile(r"[^0-9a-z]")
_COUNTING_ORDERS = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "1234567890")

_PEM_HEADER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_FOOTER = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
#: Legacy encrypted-PEM header lines (``Proc-Type: 4,ENCRYPTED``, ``DEK-Info: …``): not material.
_PEM_FIELD_LINE = re.compile(r"(?m)^[ \t]*[A-Za-z-]+:[^\n]*$")
#: Line breaks as written inside code or JSON strings (``"…\\n…"``): a real key in a string has them.
_ESCAPED_BREAK = re.compile(r"\\[nr]")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]+")


def is_placeholder(secret_type: str, text: str, start: int = 0, end: int = -1, *, cut: bool = False) -> bool:
    """True when the value one secret-value rule matched — ``text[start:end]`` (all of *text*
    by default) — is a placeholder, not a secret (see the module doc). ``private-key`` reads
    everything after the header in *text*; *cut*: *text* was cut short at its end (the head
    window of a long call). Every other type reads the token's value. Pure, linear in *text*."""
    end = len(text) if end < 0 else end
    if secret_type == "private-key":
        return _pem_is_placeholder(text[start:], cut)
    return _token_is_placeholder(text[start:end])


def _token_is_placeholder(matched: str) -> bool:
    # The value is the last word of the match: a labelled rule ("PRIVATE_KEY=0x…") matches the label too.
    value = re.split(r"[\s:=\"'`(]+", matched.strip())[-1]
    if value in _PUBLISHED_EXAMPLES:
        return True
    body = _NOT_ALNUM.sub("", _PREFIX.sub("", value).lower())
    if not body:
        return True
    if len(set(body)) <= _MAX_FILLER_DISTINCT:
        return True
    return len(_without_counting_runs(_PLACEHOLDER_WORDS.sub("", body))) < _MIN_RANDOM_CHARS


def _without_counting_runs(text: str) -> str:
    """*text* with every run of :data:`_MIN_COUNTING_RUN`+ characters in counting order taken out."""
    kept: list[str] = []
    start = 0
    while start < len(text):
        end = start + 1
        while end < len(text) and _follows(text[end - 1], text[end]):
            end += 1
        if end - start < _MIN_COUNTING_RUN:
            kept.append(text[start:end])
        start = end
    return "".join(kept)


def _follows(before: str, after: str) -> bool:
    return any(before + after in order for order in _COUNTING_ORDERS)


def _pem_is_placeholder(from_header: str, cut: bool) -> bool:
    header = _PEM_HEADER.match(from_header)
    if header is None:
        return False
    rest = from_header[header.end():]
    if cut and not _PEM_FOOTER.search(rest):
        return False   # the body may be past the cut: still a key (LES-011)
    material = _ESCAPED_BREAK.sub("\n", _PEM_FIELD_LINE.sub("", rest))
    return not any(len(run) >= _MIN_PEM_MATERIAL and len(set(run)) > _MAX_FILLER_DISTINCT
                   for run in _BASE64_RUN.findall(material))


__all__ = ["is_placeholder"]
