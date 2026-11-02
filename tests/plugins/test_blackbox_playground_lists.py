"""The sandbox Playground stays short however much the lane holds (2026-11-02).

On the everything-tester the panel had grown to one long scroll: 20 test rows (six of them one
profile-backup check), 37 lane entries from nine agents and 35 wallet cards. The script now folds
repeats of one check into "×N", filters the lane by sender, shows each list's newest LIST_CAP rows
behind "Show all", and draws one row per wallet that opens to its tests. Its open groups and
chosen filter live in `ui`, because the panel is redrawn from scratch every poll.

The Recent events column in the shields panel fills its column (it used to stop at 340 px under
a column stretched by the wallet list beside it).

These are text guards on the shipped assets (the dashboard has no JS test runner); the real-
browser pass against a live node is in the commit message.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

DASHBOARD = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "dashboard"
SCRIPT = (DASHBOARD / "playground_routes" / "playground.js").read_text(encoding="utf-8")
INDEX = (DASHBOARD / "static" / "index.html").read_text(encoding="utf-8")


def _function(name: str) -> str:
    match = re.search(rf"  function {name}\(.*?\n  }}\n", SCRIPT, re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match.group(0)


def test_the_script_parses():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    result = subprocess.run([node, "--check", str(DASHBOARD / "playground_routes" / "playground.js")],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_every_list_is_capped_with_a_show_all_switch():
    assert re.search(r"var LIST_CAP = \d+;", SCRIPT)
    capped = _function("cappedList")
    assert "items.slice(0, LIST_CAP)" in capped and '"Show all " + items.length' in capped
    assert 'cappedList("tests", foldTests(' in SCRIPT
    assert 'cappedList("lane", shown,' in SCRIPT


def test_repeats_of_one_check_fold_into_one_row():
    fold = _function("foldTests")
    assert "testWhen(row).slice(0, 19)" in fold and "times += 1" in fold
    assert '"×" + test.times' in _function("testRow")


def test_the_lane_is_filtered_by_sender_with_counts():
    chips = _function("laneChips")
    assert '"All " + entries.length' in chips and "aria-pressed" in chips
    assert "laneSender(e) === ui.laneFrom" in _function("drawLane")


def test_wallet_tests_draw_one_row_per_wallet_with_its_own_run():
    group = _function("walletGroup")
    assert "aria-expanded" in group and '"Run " + group.tests.length' in group
    assert "group.tests.map(function (test) { return test.id; })" in group
    assert "walletGroups().forEach" in _function("drawWallets")


def test_what_the_viewer_opened_survives_the_redraw():
    assert re.search(r"var ui = \{ laneFrom: \"all\", showAll: \{\}, openWallets: \{\} \};", SCRIPT)
    assert 'root.innerHTML = "";' in _function("draw")   # the redraw that `ui` outlives


def test_recent_events_fill_their_column():
    assert ".wp-col:has(> .wp-evlist) { display: flex; flex-direction: column; }" in INDEX
    rule = INDEX.split(".wp-col > .wp-evlist {", 1)[1].split("}", 1)[0]
    assert "contain: size" in rule and "flex: 1 1 auto" in rule
