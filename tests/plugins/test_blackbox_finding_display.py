"""One threat on screen is decided once, on the server (audit/finding_display.py).

The dashboard's findingDisplayKey / findingRepresentativeRank (index.html) are run in node on
the same rows as the Python port: the keys and ranks must be equal, so the served values group
exactly as the page always did. Desktop and the dashboard both group on what they are served.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.audit import finding_display, findings

PAGE = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "dashboard" / "static" / "index.html"
ROWS = [
    {"framework": "hermes", "workspace": "", "turn_id": "t-1", "category": "injection", "evidence": "  Ignore   ALL previous ",
     "source": "public", "severity": "high"},
    {"framework": "hermes", "session_id": "s-9", "time": "2026-11-11T12:00:07Z", "category": "DEPENDENCY",
     "title": "evil pkg", "confirmed": True, "severity": "Critical",
     "context": {"turns": [{"role": "user", "text": "first"}, {"role": "assistant", "text": "x"},
                           {"role": "user", "text": "  Install   it  "}]}},
    {"framework": "openclaw", "workspace": "w", "agent_id": "a", "ts": 1763000000.9, "category": "made-up",
     "identifier": "ioc:domain:x.example", "confirmed": 1, "severity": "bogus"},
    {"profile": "p", "task_id": "k", "type": "secret", "matched": "AKIA…", "source": "LLM", "severity": "low"},
    {"timestamp": 1763000000123, "category": "", "source": "secret"},
    {"context": {"turns": [{"role": "User", "text": "capital U is not the user role"}]}, "time": "not a time"},
]


def _page_functions() -> str:
    html = PAGE.read_text(encoding="utf-8")
    parts = []
    for name in ("sevClass", "catKey", "srcKey", "findingTime", "normalizedFindingText", "findingLastUserText",
                 "findingDisplayKey", "findingRepresentativeRank"):
        match = re.search(rf"\n  function {name}\(.*?\n  \}}\n", html, re.DOTALL)
        assert match, name
        parts.append(match.group(0))
    tables = [re.search(rf"\n  var {name} = \{{.*?\}};\n", html, re.DOTALL).group(0) for name in ("SEV", "SEV_RANK")]
    cats = re.search(r"\n  var CATS = \{.*?\n  \};\n", html, re.DOTALL).group(0)
    src = re.search(r"\n  var SRC_META = \{.*?\n  \};\n", html, re.DOTALL).group(0)
    return "".join(tables) + cats + src + "".join(parts)


def test_the_served_key_and_rank_are_the_ones_the_page_computes():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    script = _page_functions() + ("var rows = JSON.parse(process.argv[1]);"
                                  "console.log(JSON.stringify(rows.map(function (f) { return [findingDisplayKey(f), findingRepresentativeRank(f)]; })));")
    page = json.loads(subprocess.run([node, "-e", script, json.dumps(ROWS)], capture_output=True, text=True, check=True).stdout)
    served = [[finding_display.display_key(row), finding_display.display_rank(row)] for row in ROWS]
    assert served == page


def test_every_findings_row_is_served_with_its_key_and_rank():
    row = findings._flatten_finding_row({"ts": 5, "finding": {"identifier": "ioc:domain:x.example", "severity": "high",
                                                               "category": "ioc", "source": "public"}}, "hermes")
    assert row["display_key"] == finding_display.display_key(row) and row["display_rank"] == 64


def test_both_pages_group_on_the_served_key_first():
    desktop = (PAGE.parents[2] / "desktop" / "plugin.js").read_text(encoding="utf-8")
    page = PAGE.read_text(encoding="utf-8")
    assert 'if (typeof f.display_key === "string" && f.display_key) return f.display_key;' in page
    assert "if (typeof finding.display_key === 'string' && finding.display_key) return finding.display_key" in desktop
    assert 'typeof f.display_rank === "number"' in page and "typeof finding.display_rank === 'number'" in desktop
