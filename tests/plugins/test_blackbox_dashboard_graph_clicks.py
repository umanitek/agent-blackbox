"""Every bubble in the Local and Community graphs opens a detail window (real browser).

Seen 2026-10-13: in the Local graph a type bubble ("File access · 5 threats · click for
details") opened nothing — the click handler sent local type bubbles to "zoom here"
instead of a window — and each such zoom moved the graph, so the threat bubbles the
user tried next missed too. This drives the fixture dashboard of
test_blackbox_dashboard_browser.py (real app, compiled community tier, local findings)
through tests/plugins/dashboard_graph_clicks.mjs, which finds bubbles by their hover
card and clicks each one.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from test_blackbox_dashboard_browser import REPO, _chromium, fixture_app, served

SCRIPT = REPO / "tests" / "plugins" / "dashboard_graph_clicks.mjs"
pytestmark = pytest.mark.skipif(not (REPO / "node_modules" / "playwright").exists(),
                                reason="node_modules/playwright is needed for the browser pass")


def test_every_type_and_threat_bubble_opens_a_window(served, tmp_path):
    chromium = _chromium()
    if chromium is None:
        pytest.skip("no Chromium build in Playwright's cache (npx playwright install chromium)")
    out = tmp_path / "graph-clicks.json"
    # The sweep hovers the whole canvas point by point: 291 s on an idle Mac, past 400 s while the full
    # suite and a VM session ran beside it (2026-11-08) — the budget is time, not a correctness check.
    result = subprocess.run(["node", str(SCRIPT), served, str(out), "local", "community"], capture_output=True,
                            text=True, timeout=600, cwd=str(REPO), env={**os.environ, "PW_EXEC": chromium}, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["pageErrors"] == []
    for tier in ("local", "community"):
        clicks = summary["tiers"][tier]
        kinds = {click["kind"] for click in clicks}
        assert {"type", "threat"} <= kinds, (tier, clicks)          # the sweep found both kinds of bubble
        for click in clicks:
            assert click["opened"] and click["title"], (tier, click)
    local_types = [c for c in summary["tiers"]["local"] if c["kind"] == "type"]
    assert all(c["rows"] >= 1 for c in local_types), local_types   # a local type lists its threats, each clickable
