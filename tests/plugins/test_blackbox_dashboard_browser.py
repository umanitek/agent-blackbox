"""Real-browser smoke of the dashboard over fixture data (LES-002, KI-199).

Serves the REAL FastAPI app on a free loopback port over a fake node, a
community tier compiled from real signed rows (the adversarial suite's
helpers) and a seeded audit, then runs `dashboard_browser_pass.mjs`
(Playwright) at desktop and phone widths and asserts: zero page errors, zero
console errors, zero failed requests, zero horizontal overflow, the Refine
sections populated, no phone card cell squeezed under an unbreakable token,
and every shield's own page opened clean at both widths.

Skips, with the reason, when node, Playwright or a Chromium build is not on
this machine — a skipped smoke is visible; a missing one is not.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from _community_rows import GRAPH, NETWORK, Reporter, signed_dispute_row, signed_retraction_row, signed_row

REPO = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("dashboard_browser_pass.mjs")
PLAYWRIGHT = REPO / "node_modules" / "playwright"
pytestmark = pytest.mark.skipif(shutil.which("node") is None or not PLAYWRIGHT.exists(),
                                reason="node + node_modules/playwright are needed for the browser smoke")


#: The real home, read at import: the fixture below moves HOME into the test's temp folder,
#: but Playwright's browser cache lives under the real one.
_REAL_HOME = Path.home()


def _chromium() -> str | None:
    """A Chromium binary Playwright can drive: the env override, else any build
    in Playwright's cache (its own default may demand a newer build than the
    one installed), else None (= let Playwright pick, which may fail)."""
    if os.environ.get("PW_EXEC"):
        return os.environ["PW_EXEC"]
    cache = _REAL_HOME / "Library" / "Caches" / "ms-playwright"
    if not cache.exists():
        cache = _REAL_HOME / ".cache" / "ms-playwright"
    candidates = sorted(cache.glob("chromium*/**/Google Chrome for Testing"), reverse=True)
    candidates += sorted(cache.glob("chromium*/**/chrome-headless-shell"), reverse=True)
    candidates += sorted(cache.glob("chromium*/**/chrome"), reverse=True)
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def fixture_app(monkeypatch, tmp_path):
    """The real app wired to a fake node and a compiled community tier."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import test_blackbox_adversarial as adv
    from plugins.blackbox import audit, community, ruleset as ruleset_pkg
    from plugins.blackbox.kernel import dkg_client as dkg_module, signing
    from plugins.blackbox.kernel.config import BlackboxConfig
    from plugins.blackbox.kernel.signing import key_manifest as km
    from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
    from plugins.blackbox.ruleset import community_tier, compiler

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    # The served app's background loop discovers every Hermes home on the machine and attaches
    # Blackbox to it; with the real HOME it installed the test checkout into the developer's own
    # ~/.hermes on every run (seen 2026-10-13). Discovery must only ever see the test's folder.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home" / ".hermes"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("BLACKBOX_CONTEXT_GRAPH_ID", GRAPH)   # the community lives in this graph (one graph since 2026-10-16)
    root = Ed25519PrivateKey.generate()
    curators = [Ed25519PrivateKey.generate() for _ in range(3)]
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", signing.public_key_hex(root))
    keys = {"root": root, "curators": curators}
    manifest = km.KeyManifest(environment=NETWORK, graph=adv.VM_GRAPH, chain="", root_epoch=1, version=2,
                              curator_keys=tuple(sorted(signing.public_key_hex(k) for k in curators)),
                              curator_operators=("operator-a", "operator-b", "operator-c"), threshold=2,
                              promotion_author="0x" + "1" * 40, legacy_assets_hash=km.legacy_assets_hash([]))
    cfg = BlackboxConfig(report=True, context_graph_id=adv.VM_GRAPH, sync_interval=900)
    alice, bob, carol, newcomer = (adv._reporter(n) for n in ("alice", "bob", "carol", "newcomer"))
    malware, ioc, hostile = "dep:npm:evil-pkg@1.0.0", "ioc:ip:203.0.113.7", "ioc:domain:evil.example"
    verified = adv._verified_graph(keys, manifest, counted=[alice, bob], statements=[
        *adv._counted_rows([carol], keys, manifest, author_class="partner", org="acme"),
        adv._curator_row(Kind.REVOCATION, hostile, {"reason": "false-positive"}, curators[:2], manifest),
    ])
    advisory = [adv._curator_row(Kind.BACKLOG, "curator", {"lanes": "2,4", "until": "2026-10-09"}, curators[:2], manifest, graph=GRAPH)]

    def node():
        return adv._Node(verified=list(verified), curator=list(advisory),
                         reports=[signed_row(malware, alice), signed_row(malware, bob), signed_row(malware, carol),
                                  signed_row(ioc, alice), signed_row(hostile, newcomer),
                                  signed_row("dep:npm:left-pad@1.3.0", newcomer)],     # community-only, never materialized
                         disputes=[signed_dispute_row(ioc, bob, reason="internal-mirror")],
                         retractions=[signed_retraction_row("ioc:domain:oops.example", alice)])

    read = community.read_verified_reports(node(), cfg)
    assert read.available and read.reports
    prior = compiler.Ruleset()
    prior.community = {malware: {"identifier": malware, "firstSeen": time.time() - 5 * 86400}}
    rs = compiler.Ruleset()
    rs.ioc = {"ioc:ip:198.51.100.9": {"identifier": "ioc:ip:198.51.100.9", "source": "public", "severity": "high",
                                       "name": "known C2 endpoint", "category": "ioc"}}
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    community_tier.apply_community_tier(rs, node(), cfg, prior)
    rs.synced_at = time.time() - 120
    assert rs.community
    for identifier, decision in ((malware, "block"), (ioc, "flag")):
        audit.record(event="pre_tool_call", detail={"tool_name": "terminal", "decision": decision, "args": {"command": "npm install evil-pkg"}},
                     findings=[{"identifier": identifier, "category": "dependency", "severity": "high", "title": f"fixture {identifier}",
                                "source": "public", "confirmed": True}])
    for identifier in (malware, ioc):
        audit.record_share_outcome(identifier=identifier, category=identifier.split(":")[0], severity="high",
                                   subject=f"urn:guardian:report:fixture:{identifier}", asset_name=f"report-{identifier}",
                                   ok=True, outcome="accepted")

    class FakeDkg:
        def __init__(self, *a, **k):
            pass

        def reachable(self, timeout=None):
            return True

        def status(self):
            return {"networkId": NETWORK, "version": "10.0.20"}

        def context_graphs(self):
            return [{"id": GRAPH, "subscribed": True, "synced": True}]

        def query(self, *a, **k):
            return []

        def __getattr__(self, name):
            return lambda *a, **k: {}

    monkeypatch.setattr(dkg_module, "DkgClient", FakeDkg)       # create_app imports it from here
    monkeypatch.setattr(ruleset_pkg, "peek", lambda cfg: rs)
    monkeypatch.setattr(ruleset_pkg, "get", lambda cfg=None: rs)
    monkeypatch.setattr(community, "read_verified_reports", lambda client, cfg: read)
    # The verified-sync meter mid-sync: 137 of 564 assets downloaded, 124 compiled.
    from plugins.blackbox.dashboard import sync_meter
    from plugins.blackbox.sync.progress import RecoveryBacklog
    monkeypatch.setattr(ruleset_pkg, "verified_download_totals",
                        lambda client, graph, timeout=None: ruleset_pkg.DownloadTotals(assets=137, triples=1_531_200))
    monkeypatch.setattr(ruleset_pkg, "verified_progress", lambda graph: {"assets_compiled": 124})
    monkeypatch.setattr(sync_meter, "read_recovery_backlog", lambda home, graph: RecoveryBacklog(427, "2026-10-08 06:53:37"))
    from plugins.blackbox.dashboard import server
    return server.create_app()


@pytest.fixture
def served(fixture_app):
    """The fixture app on a free loopback port, in a thread; warmed until the community read landed."""
    uvicorn = pytest.importorskip("uvicorn")
    import httpx

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(fixture_app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, name="blackbox-browser-smoke", daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline and not server.started:
        time.sleep(0.1)
    assert server.started, "uvicorn did not start"
    # The dashboard's node reads are stale-while-revalidate: poll until the community read has landed.
    with httpx.Client(base_url=base, timeout=5) as client:
        while time.time() < deadline:
            client.get("/api/health")
            if client.get("/api/community-statements").json().get("available"):
                break
            time.sleep(0.5)
        assert client.get("/api/community-statements").json().get("available"), "community read never landed"
    yield base
    server.should_exit = True
    thread.join(10)


def test_the_dashboard_renders_clean_at_desktop_and_phone_widths(served, tmp_path):
    chromium = _chromium()
    if chromium is None:
        pytest.skip("no Chromium build in Playwright's cache (npx playwright install chromium)")
    env = {**os.environ, "PW_EXEC": chromium}
    result = subprocess.run(["node", str(SCRIPT), served, str(tmp_path)], capture_output=True, text=True, timeout=240,
                            cwd=str(REPO), env=env, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    summary = json.loads((tmp_path / "dashboard-browser-summary.json").read_text(encoding="utf-8"))
    assert [v["viewport"]["width"] for v in summary] == [1440, 390]
    for view in summary:
        width = view["viewport"]["width"]
        assert view["pageErrors"] == [], (width, view["pageErrors"])
        assert view["consoleErrors"] == [], (width, view["consoleErrors"])
        assert view["failedRequests"] == [], (width, view["failedRequests"])
        for check in view["checks"]:
            assert not check["horizontalOverflow"], (width, check)
        sections = view["sections"]
        assert "REVOKED" in sections["health-strip"] and "BACKLOG" in sections["health-strip"], (width, sections["health-strip"])
        # The Community graph section was removed (Amos, 2026-10-10); the tier tab and tiles remain.
        assert sections["community-panel-present"] is False, width
        assert sections["tab-community"] and sections["tab-community"].split()[-1].isdigit()
        # The summary tiles are filled from /api/community-stats (they sat on "—" before).
        assert sections["stat-community-count"].replace(",", "").isdigit(), (width, sections["stat-community-count"])
        assert sections["stat-sharing-state"] in {"on", "off", "paused"}, (width, sections["stat-sharing-state"])
        assert sections["vs-lookups"], (width, sections["vs-lookups"])   # where verified answers come from
        assert view["spillingCells"] == [], (width, view["spillingCells"])
        # Every shield's own page was opened too, so its errors and overflow are in the checks above
        # (the Trader page once overflowed a phone on an unbreakable path and had no icon, 2026-10-14).
        assert "/shields/trader" in sections["shield-pages"], (width, sections["shield-pages"])
        # The verified-sync meter is measured against the graph's real size (564 assets).
        assert sections["vs-pct"] == "22.0%", (width, sections["vs-pct"])
        assert sections["vs-chip"].lower() == "syncing", (width, sections["vs-chip"])
        assert "137 / 564" in sections["vs-val-downloaded"], (width, sections["vs-val-downloaded"])
        assert "427 more verified assets" in sections["vs-note"], (width, sections["vs-note"])


def test_the_served_app_never_touches_the_real_hermes_home(served):
    """Guard for the fixture above: the app's auto-attach loop ran while the browser tests
    were up and installed the checkout into the developer's real ~/.hermes. With HOME moved,
    discovery sees only the test folder, so the real home is never a target. (Checked from
    the discovery side: since Hermes 0.21.7 tests/home_io_guard.py refuses ANY file access
    to the real home in tests — a stat of it included — and catches a stray write there.)"""
    from plugins.blackbox.attach import hermes_homes

    assert str(Path.home()) != str(_REAL_HOME)
    homes = hermes_homes.discover_hermes_homes()
    assert all(str(home).startswith(str(Path.home())) for home in homes), homes


FRESHNESS = Path(__file__).with_name("dashboard_settings_freshness.mjs")


def test_settings_reopened_after_engage_shows_it_and_save_keeps_it(served, tmp_path):
    """2026-10-15 dashboard audit: Engage on the Trader banner, then a Settings Save, disengaged
    the shield — the page reopened the Settings copy it loaded before Engage and saved it back."""
    chromium = _chromium()
    if chromium is None:
        pytest.skip("no Chromium build in Playwright's cache (npx playwright install chromium)")
    result = subprocess.run(["node", str(FRESHNESS), served, str(tmp_path)], capture_output=True, text=True, timeout=240,
                            cwd=str(REPO), env={**os.environ, "PW_EXEC": chromium}, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    summary = json.loads((tmp_path / "settings-freshness-summary.json").read_text(encoding="utf-8"))
    assert summary["pageErrors"] == [] and summary["consoleErrors"] == [], summary
    assert summary["offBefore"] is False                 # the fixture starts with the shield off
    assert summary["onInForm"] is True                   # reopened Settings shows the Engage
    assert summary["enabledAfterSave"] is True           # and Save keeps it


READ_ONLY = Path(__file__).with_name("dashboard_read_only_view.mjs")


def test_a_read_only_view_says_changes_are_off_instead_of_network_error(served, tmp_path):
    """2026-10-15: through the demo's read-only view (it refuses /api/session) Save said "Network
    error. Settings not saved." and Engage could stay stuck on "Engaging…"."""
    chromium = _chromium()
    if chromium is None:
        pytest.skip("no Chromium build in Playwright's cache (npx playwright install chromium)")
    result = subprocess.run(["node", str(READ_ONLY), served, str(tmp_path)], capture_output=True, text=True, timeout=240,
                            cwd=str(REPO), env={**os.environ, "PW_EXEC": chromium}, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    summary = json.loads((tmp_path / "read-only-view-summary.json").read_text(encoding="utf-8"))
    assert summary["pageErrors"] == [], summary
    assert "switched off in this view" in summary["saveStatus"] and "Network error" not in summary["saveStatus"]
    assert summary["engageButton"].startswith("Engage ")   # back to its label, not stuck on "Engaging…"
