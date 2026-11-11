"""The JSON5 -> JSON converter OpenClaw configs are read through (attach/openclaw_json5.py).

Pinned case by case before the converter was split into its three passes, so the split is
proven to change nothing: every case's output is compared with json.loads of the strict form.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.attach.openclaw_json5 import _json5_to_json

CASES = [
    ('{"a": 1}', {"a": 1}),
    ("{\n  // a line comment\n  a: 1,\n}", {"a": 1}),
    ("{ /* block\n comment */ a: [1, 2, ], }", {"a": [1, 2]}),
    ("{a: 'single \\'quoted\\' \\n \\x41 \\u00e9', b: \"dq // not a comment, }\"}",
     {"a": "single 'quoted' \n A é", "b": "dq // not a comment, }"}),
    ("{$key_1: true, _x: null, 'quoted': 2}", {"$key_1": True, "_x": None, "quoted": 2}),
    ('{"s": "a \\" quote, ] inside", t: [ "x", ], }', {"s": 'a " quote, ] inside', "t": ["x"]}),
    ("{a: 'line\\\ncontinued'}", {"a": "linecontinued"}),
    ("{url: 'http://127.0.0.1:18789'}", {"url": "http://127.0.0.1:18789"}),
]


@pytest.mark.parametrize("text, expected", CASES)
def test_json5_becomes_strict_json(text, expected):
    assert json.loads(_json5_to_json(text)) == expected


@pytest.mark.parametrize("text", ['{"a": "open', "{a: 'open", "{/* open", "{a: '\\"])
def test_an_unterminated_string_or_comment_is_refused(text):
    with pytest.raises(ValueError):
        _json5_to_json(text)


def test_a_block_comment_keeps_its_line_breaks():
    """Line numbers in a later json error still point at the operator's own lines."""
    assert _json5_to_json("{/*\n\n*/}") == "{\n\n}"
