"""How much an approval gives away: "unlimited" in every spelling an agent writes it.

A drainer asks for everything. Everything is written many ways — the number
2^256−1, ``MaxUint256``, ``type(uint256).max``, ``2n**256n-1n``, ``uint256(-1)``,
``BigInt(2)**BigInt(256)-BigInt(1)``, ``1e77``, ``$(cast max-uint)`` — and arrives with
shell or script punctuation still attached (``MAX)`` from ``$(cast calldata … MAX)``).
:func:`is_unlimited` reads them all; :func:`is_on` reads an approve-all flag.

Pure functions over the argument's text.

Usage::

    is_unlimited("2n ** 256n - 1n")    # True
    is_unlimited("25000000")           # False
    is_on("!0")                        # True (setApprovalForAll(operator, !0))
    is_unlimited_solana("ALL")         # True (spl-token approve … ALL …)
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

#: An amount at least this large is unlimited in practice. WHY 2^159 and not 2^255:
#: Permit2 amounts are uint160, so ITS unlimited is 2^160−1; and no real token has
#: anywhere near 2^159 base units in existence (the largest supplies are about 2^110).
UNLIMITED_FLOOR = 2 ** 159
#: ``spl-token approve`` takes UI amounts (decimals applied). u64::MAX at 9 decimals —
#: the most common mint precision — is 18446744073.7…; an approval this size or more is
#: everything the account will ever hold for almost any mint.
SOLANA_UNLIMITED_FLOOR = Decimal(18_446_744_073)
#: An exponent this large needs no arithmetic to be called unlimited (and bounds the work).
_HUGE_EXPONENT = 512
_FLOOR_DIGITS = len(str(UNLIMITED_FLOOR))

_MAX_NAMES = re.compile(
    r"maxuint(?:256|160)|max_uint(?:256|160)?|uint(?:256|160)_max|type\(uint(?:256|160)\)\.max"
    r"|castmax-uint|uint256\(-1\)|maxint256",
    re.IGNORECASE)
_BIGINT_CALL = re.compile(r"BigInt\(['\"]?(\d+)['\"]?\)")
_BIGINT_SUFFIX = re.compile(r"(\d)n\b")
#: base ** exponent, optionally minus one: 2**256-1, pow(2,256)-1, (1<<256)-1.
_POWER = re.compile(r"\(?(?:(\d+)\*\*(\d+)|pow\((\d+),(\d+)\)|1<<(\d+))\)?(-1)?")
_SCIENTIFIC = re.compile(r"\d+(?:\.\d+)?e\+?\d+", re.IGNORECASE)
_ON = frozenset({"true", "1", "1n", "!0", "0x1", "0x01"})


def _plain(text: str) -> str:
    """*text* without spaces, quotes, stuck punctuation or JavaScript BigInt spellings."""
    text = re.sub(r"\s+", "", str(text or "")).strip("'\"`,;")
    while text.endswith(")") and text.count(")") > text.count("("):
        text = text[:-1].rstrip("'\"`,;")   # the `)` of `$(cast calldata … MAX)`
    text = _BIGINT_CALL.sub(r"\1", text)
    return _BIGINT_SUFFIX.sub(r"\1", text)


def _power_value(match: re.Match) -> int:
    base, exponent = (match.group(1), match.group(2)) if match.group(1) else (match.group(3), match.group(4))
    if match.group(5):
        base, exponent = "2", match.group(5)
    # Read as text first: int() refuses decimal text past 4,300 digits, and one such number
    # once ended every check for the call (KI-489).
    base, exponent = base.lstrip("0") or "0", exponent.lstrip("0") or "0"
    minus_one = 1 if match.group(6) else 0
    if exponent == "0":
        return 1 - minus_one
    if base in ("0", "1"):
        return int(base) - minus_one
    if len(exponent) > len(str(_HUGE_EXPONENT)) or int(exponent) > _HUGE_EXPONENT or len(base) > _FLOOR_DIGITS:
        return UNLIMITED_FLOOR
    return int(base) ** int(exponent) - minus_one


def is_unlimited(text: str) -> bool:
    """Whether an amount argument, as written, is unlimited (see the module doc)."""
    plain = _plain(text)
    if not plain:
        return False
    if _MAX_NAMES.search(plain):
        return True
    power = _POWER.fullmatch(plain)
    if power:
        return _power_value(power) >= UNLIMITED_FLOOR
    if _SCIENTIFIC.fullmatch(plain):
        try:
            return Decimal(plain) >= UNLIMITED_FLOOR
        except InvalidOperation:
            return False
    digits = plain.replace("_", "")
    if digits.isdigit():
        # WHY not int(…, 0): it refuses a leading zero; and a number this long is past the
        # floor without converting it (int() refuses very long digit strings).
        significant = digits.lstrip("0") or "0"
        return len(significant) > _FLOOR_DIGITS or int(significant) >= UNLIMITED_FLOOR
    try:
        return int(digits, 16) >= UNLIMITED_FLOOR if digits.lower().startswith("0x") else False
    except ValueError:
        return False


def is_on(text: str) -> bool:
    """Whether an approve-all flag, as written, turns the approval on."""
    return _plain(text).lower() in _ON


def is_unlimited_solana(text: str) -> bool:
    """Whether an ``spl-token approve`` UI amount gives everything (see the floor above)."""
    plain = _plain(text)
    if plain.upper() == "ALL":
        return True
    try:
        return Decimal(plain) >= SOLANA_UNLIMITED_FLOOR
    except InvalidOperation:
        return False
