"""The Settings page posts only what the person changed or what it read — never a default for a
field it did not render (KI-582, FIX-0364, security round 3: saving File Shield's sandbox picker from a fresh
page posted ``"auto_attach": false`` while the server had true, so the save was held as weakening
"Stop protecting new agents automatically"; a person approving it would have switched auto-attach
off unknowingly). Root cause: ``normalizeSettings()`` (dashboard/static/index.html) never copied
``auto_attach``. The page's own functions run in Node (settings_payload_render.mjs); the server
judges the payload they build.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox.approvals import weakening
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import settings

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "plugins" / "blackbox" / "dashboard" / "static" / "index.html"
SCRIPT = Path(__file__).with_name("settings_payload_render.mjs")
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="needs node")


def _page_posts(tmp_path: Path, view: dict, edits: dict | None = None) -> dict:
    (tmp_path / "view.json").write_text(json.dumps(view), encoding="utf-8")
    argv = [NODE, str(SCRIPT), str(PAGE), str(tmp_path / "view.json")]
    if edits is not None:
        (tmp_path / "edits.json").write_text(json.dumps(edits), encoding="utf-8")
        argv.append(str(tmp_path / "edits.json"))
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=True)
    return json.loads(done.stdout)


def _served() -> dict:
    return TestClient(server.create_app(), base_url="http://127.0.0.1").get("/api/settings").json()


def test_a_save_from_a_fresh_page_keeps_auto_attach_and_is_not_held_as_weakening(tmp_path):
    assert settings.write_settings({"auto_attach": True, "mode": "block"})["ok"]
    view = _served()
    assert view["auto_attach"] is True
    rendered = _page_posts(tmp_path, view)
    assert rendered["toggle"] is True and rendered["payload"]["auto_attach"] is True
    assert weakening.reasons("/api/settings", rendered["payload"], weakening.Current.read()) == []


def test_a_field_the_server_did_not_serve_is_never_posted_unless_the_person_changed_it(tmp_path):
    view = {key: value for key, value in _served().items() if key not in ("auto_attach", "discover", "categories")}
    payload = _page_posts(tmp_path, view)["payload"]
    assert "auto_attach" not in payload and "discover" not in payload and "categories" not in payload
    assert payload["mode"] in ("block", "audit") and "osv_lookup" in payload   # what it read is posted as read
    changed = _page_posts(tmp_path, view, {"auto_attach": True})["payload"]
    assert changed["auto_attach"] is True   # the person's own change is posted


def test_reset_to_defaults_keeps_the_operators_auto_attach(tmp_path):
    assert settings.write_settings({"auto_attach": True})["ok"]
    payload = _page_posts(tmp_path, _served(), {"reset": True})["payload"]
    assert payload["auto_attach"] is True
