"""A minimal JSON5 -> JSON converter for OpenClaw's config files.

OpenClaw configs allow comments, trailing commas, unquoted object keys and single-quoted
strings; :func:`_json5_to_json` turns those into strict JSON so the stdlib ``json`` can parse
the result, in three passes over the text (Pipeline): comments out and every string
double-quoted → bare keys quoted → trailing commas dropped. Each later pass steps over
strings with :func:`_string_end`, so no pass ever edits a string's contents. Tested in
test_blackbox_openclaw_json5.py and, through attach, test_blackbox_attach.py.
"""

from __future__ import annotations

import json
import re

#: What a backslash escape in a single-quoted JSON5 string stands for.
_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0"}
#: An unquoted JSON5 object key (an ECMAScript identifier, ASCII only).
_BARE_KEY = re.compile(r"[$A-Za-z_][$A-Za-z0-9_]*")
#: What must follow a bare key, and what makes a comma a trailing one (matched in place, never by copying the rest).
_COLON_AHEAD, _CLOSE_AHEAD = re.compile(r"\s*:"), re.compile(r"\s*[}\]]")


def _json5_to_json(text: str) -> str:
    """Convert the JSON5 features commonly used by OpenClaw into strict JSON.

    Blackbox only needs those syntax features to merge one plugin entry; uncommon numeric
    JSON5 extensions fail safely (``json.loads`` refuses the result) rather than risking
    replacement of the user's config. An unterminated string or comment raises ValueError.
    """
    return _drop_trailing_commas(_quote_bare_keys(_strip_comments(text)))


def _string_end(text: str, start: int) -> int:
    """The index just past the double-quoted string that opens at *start* (ValueError when it never closes)."""
    i = start + 1
    escaped = False
    while i < len(text):
        current = text[i]
        i += 1
        if escaped:
            escaped = False
        elif current == "\\":
            escaped = True
        elif current == '"':
            return i
    raise ValueError("unterminated JSON5 string")


def _strip_comments(text: str) -> str:
    """Pass 1: comments removed (a block comment keeps its line breaks, so error line numbers
    still match) and every single-quoted string rewritten as a JSON string."""
    out: list[str] = []
    i = 0
    while i < len(text):
        pair = text[i:i + 2]
        if pair == "//":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
        elif pair == "/*":
            end = text.find("*/", i + 2)
            if end == -1:
                raise ValueError("unterminated JSON5 block comment")
            out.extend(ch for ch in text[i + 2:end] if ch in "\r\n")
            i = end + 2
        elif text[i] == '"':
            end = _string_end(text, i)
            out.append(text[i:end])
            i = end
        elif text[i] == "'":
            value, i = _single_quoted(text, i)
            out.append(json.dumps(value, ensure_ascii=False))
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _single_quoted(text: str, start: int) -> tuple[str, int]:
    """``(value, index past the closing quote)`` of the single-quoted string opening at *start*."""
    value: list[str] = []
    i = start + 1
    while i < len(text):
        current = text[i]
        i += 1
        if current == "'":
            return "".join(value), i
        if current != "\\":
            value.append(current)
            continue
        if i >= len(text):
            raise ValueError("unterminated JSON5 escape")
        escape = text[i]
        i += 1
        if escape in "\r\n":   # a line continuation: the break is not part of the value
            if escape == "\r" and text[i:i + 1] == "\n":
                i += 1
        elif escape in _ESCAPES:
            value.append(_ESCAPES[escape])
        elif escape == "x" and i + 2 <= len(text):
            value.append(chr(int(text[i:i + 2], 16)))
            i += 2
        elif escape == "u" and i + 4 <= len(text):
            value.append(chr(int(text[i:i + 4], 16)))
            i += 4
        else:
            value.append(escape)
    raise ValueError("unterminated JSON5 string")


def _quote_bare_keys(text: str) -> str:
    """Pass 2: an unquoted key after ``{`` or ``,`` (and before ``:``) written as a JSON string."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == '"':
            end = _string_end(text, i)
            out.append(text[i:end])
            i = end
            continue
        if text[i] not in "{,":
            out.append(text[i])
            i += 1
            continue
        out.append(text[i])
        i += 1
        while i < len(text) and text[i].isspace():
            out.append(text[i])
            i += 1
        key = _BARE_KEY.match(text, i)
        if key and _COLON_AHEAD.match(text, key.end()):
            out.append(json.dumps(key.group(0)))
            i = key.end()
    return "".join(out)


def _drop_trailing_commas(text: str) -> str:
    """Pass 3: a comma followed only by whitespace before ``}`` or ``]`` removed."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == '"':
            end = _string_end(text, i)
            out.append(text[i:end])
            i = end
            continue
        if text[i] == "," and _CLOSE_AHEAD.match(text, i + 1):
            i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)
