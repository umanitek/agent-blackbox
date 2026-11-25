"""The shield pages and their files, as the dashboard serves them (dashboard/shields_routes).

Every shield route and alias sits behind the app-wide browser boundary: the routes are
walked from the real app's ``app.routes`` (never a typed list), so a route added later is
covered without editing this file. The campaign aliases answer 307 to a FIXED Location. A
pack logo is found through the registry only — a traversal, an unknown shield or pack, or a
pack with no logo is 404 before any file is opened — and is served as an image, never a
document (``image/svg+xml``, ``nosniff``, a sandboxing CSP).
"""

from __future__ import annotations

import dataclasses
import re

import pytest
from fastapi.responses import FileResponse
from fastapi.testclient import TestClient

from plugins.blackbox import shields
from plugins.blackbox.dashboard import server, shields_routes

LOCAL = "http://127.0.0.1:9700"
FOREIGN = "https://attacker.example"
#: The route prefixes a shield owns (its API, its pages, the campaign aliases).
PREFIXES = ("/api/shields", "/shields", "/trader-shield")
#: A registered value for each path parameter, so every walked route is a real request.
PARAMETERS = {"shield_id": "trader", "pack_id": "metamask", "name": "status"}
ALIASES = {"/trader-shield": "/shields/trader",
           "/trader-shield/attacks.json": "/shields/trader/attacks.json",
           "/trader-shield/graph.json": "/shields/trader/graph.json"}
LOGO_HEADERS = {"content-type": "image/svg+xml", "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"}


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("HOME", str(tmp_path_factory.mktemp("home")))   # never the real ~/.hermes
        yield server.create_app()


def _shield_paths(app) -> list[str]:
    paths = sorted({route.path for route in app.routes if getattr(route, "path", "").startswith(PREFIXES)})
    return [re.sub(r"\{(\w+)\}", lambda match: PARAMETERS[match.group(1)], path) for path in paths]


def test_the_walk_finds_every_shield_route(app):
    walked = set(_shield_paths(app))
    assert set(ALIASES) <= walked
    assert {"/shields/trader", "/shields/trader/attacks.json", "/shields/trader/graph.json",
            "/shields/trader/content.json", "/shields/trader/packs/metamask/logo.svg", "/api/shields"} <= walked


def test_every_shield_route_refuses_a_foreign_host(app):
    with TestClient(app, base_url="http://attacker.example") as client:
        answers = {path: client.get(path, follow_redirects=False).status_code for path in _shield_paths(app)}
    assert answers == dict.fromkeys(answers, 403)


def test_every_shield_route_refuses_a_foreign_origin(app):
    with TestClient(app, base_url=LOCAL) as client:
        answers = {path: client.get(path, headers={"Origin": FOREIGN}, follow_redirects=False).status_code
                   for path in _shield_paths(app)}
    assert answers == dict.fromkeys(answers, 403)


@pytest.mark.parametrize("host", ["127.0.0.1:9700", "localhost:9700"])
def test_the_aliases_answer_307_to_a_fixed_location(app, host):
    with TestClient(app, base_url=f"http://{host}") as client:
        for alias, location in ALIASES.items():
            response = client.get(alias + "?next=//attacker.example", follow_redirects=False)
            assert (response.status_code, response.headers["location"]) == (307, location), alias


def test_the_aliases_land_on_what_they_name(app):
    with TestClient(app, base_url=LOCAL) as client:
        for alias, location in ALIASES.items():
            assert client.get(alias).content == client.get(location).content, alias


@pytest.mark.parametrize("path", [
    "/shields/trader/packs/..%2F..%2Fwallets%2Fmetamask/logo.svg",
    "/shields/trader/packs/%2E%2E/logo.svg",
    "/shields/..%2Ftrader/packs/metamask/logo.svg",
    "/shields/trader/packs/ghost/logo.svg",
    "/shields/ghost/packs/metamask/logo.svg",
    "/shields/ghost",
    "/shields/ghost/attacks.json",
    "/shields/ghost/graph.json",
    "/shields/ghost/content.json",
])
def test_traversal_and_unknown_names_are_404_before_any_file_is_opened(app, path, monkeypatch):
    def opened(*_args, **_kwargs):
        raise AssertionError("a file was opened for a name the registry does not know")

    monkeypatch.setattr(FileResponse, "__init__", opened)
    with TestClient(app, base_url=LOCAL) as client:
        assert client.get(path, follow_redirects=False).status_code == 404


#: OKX publishes no square icon as an SVG on its own domain (2026-10-16), so its pack ships none.
@pytest.mark.parametrize("pack_id", ["okx-wallet"])
def test_a_pack_without_a_logo_is_404(app, pack_id):
    assert shields.pack_logo("trader", pack_id) is None
    with TestClient(app, base_url=LOCAL) as client:
        assert client.get(f"/shields/trader/packs/{pack_id}/logo.svg").status_code == 404


def test_an_unavailable_pack_serves_no_logo_even_when_it_carries_one(app, monkeypatch):
    # A pack demoted to unavailable (say, a duplicate id) keeps its validated logo record;
    # the route still refuses it, because an unavailable pack is never shown.
    data = shields._registry()["data"]["trader"]
    demoted = tuple(dataclasses.replace(pack, status="unavailable") if pack.id == "metamask" else pack
                    for pack in data.packs)
    monkeypatch.setitem(shields._registry()["data"], "trader", dataclasses.replace(data, packs=demoted))
    assert shields.pack_logo("trader", "metamask") is None
    with TestClient(app, base_url=LOCAL) as client:
        assert client.get("/shields/trader/packs/metamask/logo.svg").status_code == 404


LOGO_PACKS = [(shield.id, pack.id) for shield in shields.all_shields() for pack in shields.loaded_packs(shield.id)
              if pack.status == "supported" and pack.logo is not None]


def test_the_logo_packs_are_the_ones_shipped_with_terms():
    assert LOGO_PACKS == [("trader", pack_id) for pack_id in (
        "metamask", "phantom", "exodus", "electrum", "solana-cli", "rabby", "coinbase-wallet", "trust-wallet", "keplr", "solflare")]


@pytest.mark.parametrize("shield_id, pack_id", LOGO_PACKS)
def test_a_logo_is_served_as_an_image_never_a_document(app, shield_id, pack_id):
    with TestClient(app, base_url=LOCAL) as client:
        response = client.get(f"/shields/{shield_id}/packs/{pack_id}/logo.svg")
    assert response.status_code == 200 and b"<svg" in response.content
    assert {name: response.headers.get(name) for name in LOGO_HEADERS} == LOGO_HEADERS


def test_a_shield_without_figures_answers_404(tmp_path, monkeypatch):
    from fastapi import FastAPI

    trader = shields.get("trader")
    bare = dataclasses.replace(trader, packs=tmp_path / "wallets", page=tmp_path / "page" / "trader.html")
    monkeypatch.setattr(shields, "get", lambda shield_id: bare if shield_id == "trader" else None)
    app = FastAPI()
    shields_routes.register_pages(app)
    client = TestClient(app)
    assert [client.get(f"/shields/trader/{name}").status_code for name in ("graph.json", "content.json")] == [404, 404]
    assert client.get("/shields/trader").status_code == 404


def test_the_page_and_its_files_are_served(app):
    with TestClient(app, base_url=LOCAL) as client:
        page = client.get("/shields/trader")
        content = client.get("/shields/trader/content.json")
        table = client.get("/shields/trader/attacks.json")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "Engage Trader Shield" in page.text
    assert content.json()["can"] and table.json()["systems"] and table.json()["tested_with"]


@pytest.mark.parametrize("broken", ['{"attacks": [', '{"a": 1, "a": 2}', "[" * 20 + "]" * 20])
def test_a_broken_attack_table_answers_404_never_a_500(tmp_path, monkeypatch, broken):
    from fastapi import FastAPI

    (tmp_path / "attacks.json").write_text(broken, encoding="utf-8")
    bare = dataclasses.replace(shields.get("trader"), packs=tmp_path / "wallets", attacks=tmp_path / "attacks.json")
    monkeypatch.setattr(shields, "get", lambda shield_id: bare if shield_id == "trader" else None)
    app = FastAPI()
    shields_routes.register_pages(app)
    response = TestClient(app, raise_server_exceptions=False).get("/shields/trader/attacks.json")
    assert (response.status_code, response.json()) == (404, {"error": "not found"})


def test_the_page_treats_a_failed_fetch_as_a_failure_not_an_empty_answer():
    # A 404 graph.json (a shield that ships none) or a 403 content.json must reach the page's
    # .catch() and its "open this from your dashboard" message — never render as zero counts
    # or empty lists because r.json() parsed the {"error": ...} body as if it were the data.
    page = shields.get("trader").page.read_text(encoding="utf-8")
    get_json = re.search(r"function getJSON\(url\) \{.*?\n  \}", page, re.DOTALL)
    assert get_json and "if (!r.ok) throw" in get_json.group(0)
    # Every read goes through getJSON; the one other fetch is the Engage POST, which reads r.ok itself.
    assert page.count("fetch(") == 2 and 'fetch(HERE + "../../api/settings", { method: "POST"' in page


def test_the_old_wallet_routes_are_gone_and_the_shield_routes_answer(app):
    """The page draws every shield from the shield routes; the wallet panel's routes and
    its logo folder are removed in the same change, so the page and the server cannot drift."""
    with TestClient(app, base_url=LOCAL) as client:
        gone = {path: client.get(path).status_code
                for path in ("/api/wallet-protection", "/api/wallet-protection/events", "/wallets/metamask.svg")}
        served = {path: client.get(path).status_code
                  for path in ("/api/shields", "/api/shields/trader/events", "/shields/trader/packs/metamask/logo.svg")}
        script = client.get("/shields.js")
    assert gone == dict.fromkeys(gone, 404)
    assert served == dict.fromkeys(served, 200)
    assert script.status_code == 200 and script.headers["content-type"].startswith("application/javascript")
    assert "no-store" in script.headers["cache-control"] and "BlackboxShields" in script.text
    plugin = shields_routes.SHIELDS_SCRIPT.parents[2]
    assert not (plugin / "dashboard" / "protection").exists() and not (plugin / "dashboard" / "static" / "wallets").exists()
