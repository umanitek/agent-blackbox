"""BIP-39 seed phrases (a wallet's Secret Recovery Phrase) found in text.

A seed phrase IS the wallet: anyone holding the 12–24 words owns every
account behind it. MetaMask calls it the Secret Recovery Phrase (12 words);
most wallets accept 12, 15, 18, 21 or 24.

How a phrase is recognised (BIP-39, github.com/bitcoin/bips bip-0039):

* every word is on the 2048-word English list, which ships next to this file
  and is pinned by its SHA-256 (:data:`WORDLIST_SHA256`) — a changed or
  truncated list disables detection loudly instead of silently;
* the words stand together: anything that is not a letter may stand between
  them (spaces of any kind and length, commas, ``|``, ``&``, line breaks, list
  numbering, a web address's ``+``). Ordinary English breaks such a run within a
  few words ("the", "of", "is" are not on the list). The text is read through
  :func:`.text_view.normalised` first, so percent-encoding (``%2C``, ``%61``),
  invisible characters, fullwidth letters, HTML entities and CamelCase joins
  (``AbandonAbility…``) do not hide a phrase (KI-378); a word may also be written
  as its first four letters (BIP-39 makes them unique — the steel-backup form);
* a phrase may also be base64-encoded: a base64 run that decodes to text holding a
  phrase counts as that phrase. Other encodings (hex, rot13, reversed words) and an
  all-lower-case join with no separator ("abandonability…") are a known gap;
* the last word carries a checksum: of the n×11 bits the words encode, the
  final n/3 bits must equal the first bits of SHA-256 of the rest. A random
  run passes with probability 1/16 (12 words) down to 1/256 (24 words), so
  the checksum confirms a phrase rather than finding one.

What callers get, per run of 12+ list words (:class:`SeedPhraseRun`): where
it is, how many words, whether a checksum-valid phrase of a standard length is
inside it, whether a cue word is near ("seed", "recovery", "phrase", …) and
whether it is one of the published test phrases (uniform entropy, e.g.
"abandon … about"). Policy (block / flag) is the caller's.

Usage::

    for run in find_seed_phrase_runs(text):
        run.valid_words      # 12/15/18/21/24 when a checksum-valid phrase is inside, else 0
    redact_seed_phrases(text)  # every phrase-shaped run → [REDACTED_SEED_PHRASE]
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .text_view import TextView, readings

logger = logging.getLogger(__name__)

WORDLIST_FILE = Path(__file__).with_name("bip39_english.txt")
#: SHA-256 of the official list (bitcoin/bips bip-0039/english.txt), checked at load.
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
#: Fewest words a phrase can have.
MIN_WORDS = 12
#: Phrase lengths BIP-39 defines, longest first (the longest valid one wins).
PHRASE_LENGTHS = (24, 21, 18, 15, 12)
MARKER = "[REDACTED_SEED_PHRASE]"

_WORD = re.compile(r"[A-Za-z]+")
#: A base64 run long enough to hold a 12-word phrase; at most _MAX_ENCODED of them per text are decoded.
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{64,4096}={0,2}(?![A-Za-z0-9+/=_-])")
_MAX_ENCODED = 16
_CUE = re.compile(r"\b(?:seed|mnemonic|recovery|phrase|secret|backup|srp|words?|wallet)\b", re.IGNORECASE)
_CUE_WINDOW = 80


@dataclass(frozen=True)
class SeedPhraseRun:
    """A run of 12+ consecutive wordlist words in a text.

    ``start``/``end`` — character offsets of the run; ``word_count`` — its
    length; ``valid_words`` — the length of the longest checksum-valid
    standard phrase inside it (0 when none); ``has_cue`` — a cue word within
    80 characters or numbered words; ``test_phrase`` — the valid phrase is a
    published example (uniform entropy), not a real wallet.
    """

    start: int
    end: int
    word_count: int
    valid_words: int
    has_cue: bool
    test_phrase: bool


@lru_cache(maxsize=1)
def _wordlist() -> Optional[dict[str, int]]:
    """``{word: index}`` from the pinned list, or ``None`` when the file is
    missing or not the pinned list (logged once at WARNING)."""
    try:
        data = WORDLIST_FILE.read_bytes()
    except OSError as exc:
        logger.warning("blackbox: BIP-39 wordlist unreadable (%s); seed-phrase detection is OFF", exc)
        return None
    if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
        logger.warning("blackbox: BIP-39 wordlist does not match its pinned SHA-256; seed-phrase detection is OFF")
        return None
    words = data.decode("ascii").split()
    return {word: index for index, word in enumerate(words)}


def wordlist_ready() -> bool:
    """True when the pinned BIP-39 wordlist loaded, i.e. seed-phrase detection is ON."""
    return _wordlist() is not None


def phrase_from_entropy(entropy: bytes) -> Optional[str]:
    """The BIP-39 phrase for *entropy* (16–32 bytes, a multiple of 4), checksum included,
    from the pinned list — e.g. a fresh ``secrets.token_bytes(16)`` for a 12-word test
    phrase that opens nothing. ``None`` when the wordlist is off or the length is not standard."""
    words = _wordlist()
    if words is None or len(entropy) not in (16, 20, 24, 28, 32):
        return None
    by_index = list(words)
    checksum_bits = len(entropy) * 8 // 32
    value = int.from_bytes(entropy, "big") << checksum_bits | hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    count = (len(entropy) * 8 + checksum_bits) // 11
    return " ".join(by_index[(value >> (11 * (count - 1 - position))) & 0x7FF] for position in range(count))


def checksum_entropy(indices: list[int]) -> Optional[bytes]:
    """The entropy behind word *indices* when their BIP-39 checksum holds,
    else ``None``. ``len(indices)`` must be a standard phrase length."""
    total_bits = len(indices) * 11
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits
    value = 0
    for index in indices:
        value = (value << 11) | index
    entropy = (value >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    return entropy if (value & ((1 << checksum_bits) - 1)) == expected else None


@lru_cache(maxsize=1)
def _prefixes() -> dict[str, int]:
    """``{first four letters: index}`` for every list word longer than four letters
    (BIP-39 makes the first four letters unique, so a steel backup writes only those)."""
    words = _wordlist() or {}
    return {word[:4]: index for word, index in words.items() if len(word) > 4}


def _runs(text: str, words: dict[str, int]) -> list[list[tuple[int, int, int]]]:
    """Runs of consecutive list words in *text* as ``[(start, end, index), ...]``. Every
    non-letter between two words joins them; any other word ends the run."""
    prefixes = _prefixes()
    runs: list[list[tuple[int, int, int]]] = []
    current: list[tuple[int, int, int]] = []
    for match in _WORD.finditer(text):
        token = match.group(0).lower()
        index = words.get(token)
        if index is None and len(token) == 4:
            index = prefixes.get(token)
        if index is None:
            if len(current) >= MIN_WORDS:
                runs.append(current)
            current = []
        else:
            current.append((match.start(), match.end(), index))
    if len(current) >= MIN_WORDS:
        runs.append(current)
    return runs


#: Repeated words a real phrase may hold, per word of its length (12 and 15 words: 2; 18 and
#: 21: 3; 24: 4). WHY (KI-556): ordinary commands can be made of list words — ``echo loop-1 ;
#: echo loop-2 …`` is 24 of them — and with sliding windows some window of such a run passes the
#: 4-bit checksum about one time in sixteen. A phrase drawn from 128+ random bits almost never
#: repeats words this often (more than 2 repeats in 12 words: about 6 in a million); a command
#: that reuses its few words always does. Used for the checksum (detection: a looping command is
#: not a "valid phrase") and for redaction (:func:`_random_looking`). The published test
#: phrases, whose entropy is one repeated byte, are recognised as such by detection.
REPEATS_PER_WORD = 1 / 6


def _real_shape(indices: list[int], entropy: bytes) -> bool:
    """True when a checksum-valid window looks like a phrase drawn from random bits."""
    return len(set(entropy)) == 1 or len(indices) - len(set(indices)) <= int(len(indices) * REPEATS_PER_WORD)


def _longest_valid(run: list[tuple[int, int, int]]) -> tuple[int, list[int], Optional[bytes]]:
    """``(length, offsets, entropy)`` for the longest standard length at which
    *run* holds a checksum-valid phrase: EVERY offset that is valid at that
    length (a label word such as "seed" joins the run, and the window that
    includes it passes the checksum by chance 1 time in 16), and the first
    one's entropy. ``(0, [], None)`` when there is none."""
    indices = [index for _start, _end, index in run]
    for length in PHRASE_LENGTHS:
        found = [(offset, checksum_entropy(indices[offset:offset + length]))
                 for offset in range(len(indices) - length + 1)]
        valid = [(offset, entropy) for offset, entropy in found
                 if entropy is not None and _real_shape(indices[offset:offset + length], entropy)]
        if valid:
            return length, [offset for offset, _entropy in valid], valid[0][1]
    return 0, [], None


def _has_cue(text: str, span_start: int, span_end: int) -> bool:
    """A cue word near the phrase, or numbered words. Looked for OUTSIDE the
    phrase itself: "seed", "phrase", "wallet" are list words, so a label like
    "seed:" joins the run, and a phrase may contain them by chance."""
    nearby = text[max(0, span_start - _CUE_WINDOW):span_start] + " " + text[span_end:span_end + _CUE_WINDOW]
    numbered = bool(re.search(r"\b\d{1,2}[.)]\s*[A-Za-z]", text[max(0, span_start - 4):span_end]))
    return bool(_CUE.search(nearby)) or numbered


def _plain_runs(text: str, words: dict[str, int]) -> list[SeedPhraseRun]:
    """The runs in *text*'s normalised readings, with their ORIGINAL offsets (a run found
    in both readings is reported once)."""
    out: list[SeedPhraseRun] = []
    for view in readings(text):
        out += [run for run in _view_runs(view, words) if (run.start, run.end) not in {(r.start, r.end) for r in out}]
    return out


def _view_runs(view: TextView, words: dict[str, int]) -> list[SeedPhraseRun]:
    out: list[SeedPhraseRun] = []
    for run in _runs(view.text, words):
        valid_words, offsets, entropy = _longest_valid(run)
        windows = [run[offset:offset + valid_words] for offset in offsets] or [run]
        start, end = view.original_span(run[0][0], run[-1][1])
        out.append(SeedPhraseRun(
            start=start, end=end, word_count=len(run), valid_words=valid_words,
            has_cue=any(_has_cue(view.text, window[0][0], window[-1][1]) for window in windows),
            test_phrase=entropy is not None and len(set(entropy)) == 1,
        ))
    return out


def _decoded_text(blob: str) -> Optional[str]:
    """*blob* base64-decoded, when that gives printable ASCII text; else None."""
    core = blob.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(core + "=" * (-len(core) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    printable = all(32 <= byte < 127 or byte in (9, 10, 13) for byte in raw)
    return raw.decode("ascii") if printable else None


def _encoded_runs(text: str, words: dict[str, int]) -> list[SeedPhraseRun]:
    """Phrases hidden in base64: each decoded run is reported over the WHOLE blob."""
    out: list[SeedPhraseRun] = []
    for match in list(_BASE64.finditer(text))[:_MAX_ENCODED]:
        decoded = _decoded_text(match.group(0))
        for run in _plain_runs(decoded, words) if decoded else []:
            out.append(SeedPhraseRun(
                start=match.start(), end=match.end(), word_count=run.word_count, valid_words=run.valid_words,
                has_cue=run.has_cue or _has_cue(text, match.start(), match.end()), test_phrase=run.test_phrase))
    return out


def find_seed_phrase_runs(text: str) -> list[SeedPhraseRun]:
    """Every run of 12+ consecutive wordlist words in *text*, plain or base64-encoded
    (see module doc), in order."""
    words = _wordlist()
    if not text or words is None:
        return []
    return sorted(_plain_runs(text, words) + _encoded_runs(text, words), key=lambda run: run.start)


def _random_looking(run: list[tuple[int, int, int]]) -> bool:
    """True when some :data:`MIN_WORDS`-word stretch of *run* repeats at most
    ``MIN_WORDS * REPEATS_PER_WORD`` words — what a phrase drawn from random bits does, whole,
    cut short or mistyped. One pass with a sliding count, no checksum."""
    allowed = int(MIN_WORDS * REPEATS_PER_WORD)
    counts: dict[int, int] = {}
    for position, (_start, _end, index) in enumerate(run):
        counts[index] = counts.get(index, 0) + 1
        if position >= MIN_WORDS:
            gone = run[position - MIN_WORDS][2]
            counts[gone] -= 1
            if not counts[gone]:
                del counts[gone]
        if position >= MIN_WORDS - 1 and MIN_WORDS - len(counts) <= allowed:
            return True
    return False


def _phrase_shaped(text: str, run: list[tuple[int, int, int]]) -> bool:
    """True when *run* (12+ list words in *text*) has a seed phrase's shape: its words look drawn
    at random (:func:`_random_looking` — a whole phrase, one cut short or one mistyped: still a
    secret), or it is LABELLED as one (a cue word near it, or numbered words). Ordinary text made
    of list words reuses its few words (``echo loop-1 … echo loop-12``) and is neither (KI-556)."""
    return _random_looking(run) or _has_cue(text, run[0][0], run[-1][1])


def _spans(text: str, words: dict[str, int]) -> list[tuple[int, int]]:
    """Original spans of every PHRASE-SHAPED run (plain or base64-encoded; :func:`_phrase_shaped`)."""
    spans = [view.original_span(run[0][0], run[-1][1]) for view in readings(text) for run in _runs(view.text, words)
             if _phrase_shaped(view.text, run)]
    for match in list(_BASE64.finditer(text))[:_MAX_ENCODED]:
        decoded = _decoded_text(match.group(0))
        if decoded and any(_phrase_shaped(view.text, run) for view in readings(decoded) for run in _runs(view.text, words)):
            spans.append(match.span())
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def seed_phrase_spans(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` of every phrase-shaped run of 12+ list words in *text* (plain or
    base64), merged and in order — what :func:`redact_seed_phrases` removes. For callers that must map a
    phrase back onto the pieces it was assembled from (a list of words, a dict)."""
    words = _wordlist()
    return _spans(text, words) if text and words is not None else []


def redact_seed_phrases(text: str) -> str:
    """*text* with every seed phrase (plain or base64-encoded) replaced by :data:`MARKER`: a
    run of 12+ wordlist words with a phrase's shape (:func:`_phrase_shaped`) — words that look
    drawn at random, checksum or not (a phrase cut short or mistyped is still a secret), or a
    labelled run. An ordinary command made of list words is left as it is
    (KI-556). No checksum is computed here: a log full of list words costs one pass, not five
    per word (KI-382)."""
    words = _wordlist()
    if not text or words is None:
        return text
    for start, end in reversed(_spans(text, words)):
        text = text[:start] + MARKER + text[end:]
    return text
