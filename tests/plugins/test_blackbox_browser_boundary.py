"""The shared browser boundary (kernel/browser_boundary, KI-028 / LES-006).

Exercises ``BrowserBoundary`` on a bare FastAPI app with both token-source
strategies: the dashboard's per-process token and a per-session lookup on a
MagicDNS host set (the curator key console's shape).
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from plugins.blackbox.kernel.browser_boundary import BrowserBoundary

LOOPBACK = {"127.0.0.1", "localhost", "[::1]"}
MAGIC_DNS = "curator-a.tail1234.ts.net"
PROCESS_TOKEN = "process-token-value"


def _app(allowed_hosts, token_for) -> fastapi.FastAPI:
    app = fastapi.FastAPI()
    BrowserBoundary(allowed_hosts, token_for).install(app)

    @app.get("/read")
    def read():
        return {"ok": True}

    @app.post("/change")
    def change():
        return {"changed": True}

    return app


@pytest.fixture()
def loopback_client():
    with TestClient(_app(LOOPBACK, lambda _request: PROCESS_TOKEN), base_url="http://127.0.0.1:9700") as client:
        yield client


def test_forged_host_refused():
    app = _app(LOOPBACK, lambda _request: PROCESS_TOKEN)
    with TestClient(app, base_url="http://attacker.example") as client:
        res = client.get("/read")
    assert res.status_code == 403
    assert res.json() == {"error": "forbidden host"}


def test_rebound_host_with_loopback_port_refused():
    app = _app(LOOPBACK, lambda _request: PROCESS_TOKEN)
    with TestClient(app, base_url="http://127.0.0.1.attacker.example:9700") as client:
        assert client.get("/read").status_code == 403


def test_foreign_origin_refused(loopback_client):
    res = loopback_client.post(
        "/change",
        headers={"Origin": "https://attacker.example", "X-Blackbox-Token": PROCESS_TOKEN},
    )
    assert res.status_code == 403
    assert res.json() == {"error": "forbidden origin"}


def test_missing_token_refused(loopback_client):
    res = loopback_client.post("/change")
    assert res.status_code == 403
    assert "token" in res.json()["error"]


def test_wrong_token_refused(loopback_client):
    res = loopback_client.post("/change", headers={"X-Blackbox-Token": "guess"})
    assert res.status_code == 403


def test_reads_need_no_token_and_local_origin_passes(loopback_client):
    res = loopback_client.get("/read", headers={"Origin": "http://localhost:9700"})
    assert res.status_code == 200


def test_process_token_passes(loopback_client):
    res = loopback_client.post("/change", headers={"X-Blackbox-Token": PROCESS_TOKEN})
    assert res.status_code == 200
    assert res.json() == {"changed": True}


def _session_lookup(sessions):
    """A per-session token source: the token bound to the request's cookie."""
    return lambda request: sessions.get(request.cookies.get("session", ""))


def test_magic_dns_host_with_per_session_token_accepted():
    sessions = {"sess-a": "token-a", "sess-b": "token-b"}
    app = _app({MAGIC_DNS}, _session_lookup(sessions))
    with TestClient(app, base_url=f"https://{MAGIC_DNS}") as client:
        client.cookies.set("session", "sess-a")
        res = client.post(
            "/change",
            headers={"Origin": f"https://{MAGIC_DNS}", "X-Blackbox-Token": "token-a"},
        )
    assert res.status_code == 200


def test_per_session_token_is_bound_to_its_session():
    sessions = {"sess-a": "token-a", "sess-b": "token-b"}
    app = _app({MAGIC_DNS}, _session_lookup(sessions))
    with TestClient(app, base_url=f"https://{MAGIC_DNS}") as client:
        client.cookies.set("session", "sess-a")
        assert client.post("/change", headers={"X-Blackbox-Token": "token-b"}).status_code == 403


def test_no_session_fails_closed_even_without_a_presented_token():
    app = _app({MAGIC_DNS}, _session_lookup({}))
    with TestClient(app, base_url=f"https://{MAGIC_DNS}") as client:
        assert client.post("/change").status_code == 403
        assert client.post("/change", headers={"X-Blackbox-Token": ""}).status_code == 403


def test_magic_dns_set_refuses_loopback_host():
    app = _app({MAGIC_DNS}, lambda _request: "token")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/read").status_code == 403


def test_allowlist_entries_match_case_insensitively():
    # A MagicDNS name copied from the Tailscale admin may carry capitals.
    app = _app({"Curator-A.Tail1234.TS.net"}, lambda _request: "token")
    with TestClient(app, base_url=f"https://{MAGIC_DNS}:8443") as client:
        assert client.get("/read").status_code == 200


def test_token_is_compared_in_constant_time(loopback_client, monkeypatch):
    from plugins.blackbox.kernel import browser_boundary

    calls = []
    real = browser_boundary.secrets.compare_digest

    def spy(presented, expected):
        calls.append((presented, expected))
        return real(presented, expected)

    monkeypatch.setattr(browser_boundary.secrets, "compare_digest", spy)
    assert loopback_client.post("/change", headers={"X-Blackbox-Token": "guess"}).status_code == 403
    assert calls == [(b"guess", PROCESS_TOKEN.encode())]   # as bytes: any header value compares, never raises


# ------------------------------------------------------------------ KI-390: the port is part of the origin


@pytest.mark.parametrize("origin", [
    "http://127.0.0.1:8000",      # another server on the same loopback
    "http://localhost:5173",      # a dev server
    "http://127.0.0.1",           # port 80
    "https://127.0.0.1:9700",     # the same port named explicitly: allowed (the scheme only picks a default port)
])
def test_an_origin_on_another_loopback_port_is_refused(loopback_client, origin):
    expected = 200 if origin == "https://127.0.0.1:9700" else 403
    res = loopback_client.post("/change", headers={"Origin": origin, "X-Blackbox-Token": PROCESS_TOKEN})
    assert res.status_code == expected
    if expected == 403:
        assert res.json() == {"error": "forbidden origin"}


def test_reads_from_another_loopback_port_are_refused_too(loopback_client):
    assert loopback_client.get("/read", headers={"Origin": "http://127.0.0.1:8000"}).status_code == 403


def test_the_same_port_under_a_loopback_alias_passes(loopback_client):
    res = loopback_client.post("/change", headers={"Origin": "http://localhost:9700", "X-Blackbox-Token": PROCESS_TOKEN})
    assert res.status_code == 200


def test_an_ipv6_loopback_origin_on_the_same_port_passes(loopback_client):
    ipv6 = {"Host": "[::1]:9700"}   # the test client cannot dial [::1]; the header is what the boundary reads
    assert loopback_client.get("/read", headers={**ipv6, "Origin": "http://[::1]:9700"}).status_code == 200
    assert loopback_client.get("/read", headers={**ipv6, "Origin": "http://[::1]:8000"}).status_code == 403


def test_a_default_port_origin_matches_a_host_header_without_a_port():
    with TestClient(_app({MAGIC_DNS}, lambda _request: "token"), base_url=f"https://{MAGIC_DNS}") as client:
        assert client.get("/read", headers={"Origin": f"https://{MAGIC_DNS}"}).status_code == 200
        assert client.get("/read", headers={"Origin": f"https://{MAGIC_DNS}:8443"}).status_code == 403


def test_the_dashboard_escape_covers_the_single_quote():
    """index.html's esc() — what every innerHTML insertion goes through — escapes ' like
    trader-shield.html's does, so a value can never close a single-quoted attribute."""
    import re
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    html = (Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    esc = re.search(r"  function esc\(s\) \{[\s\S]*?\n  \}\n", html).group(0)
    rendered = subprocess.run([node, "-e", esc + "console.log(esc(\"<a title='x' href=\\\"y\\\">&</a>\"));"],
                              capture_output=True, text=True, check=True).stdout.strip()
    assert rendered == "&lt;a title=&#39;x&#39; href=&quot;y&quot;&gt;&amp;&lt;/a&gt;"


def test_a_token_with_characters_outside_ascii_is_refused_not_an_error(loopback_client):
    """The server decodes headers as latin-1; comparing such a str raised TypeError inside the
    middleware, so the request got a 500 instead of a 403 (still refused, but not as designed)."""
    response = loopback_client.post("/change", headers={"X-Blackbox-Token": "tok\xe9n".encode("latin-1")})
    assert response.status_code == 403 and response.json() == {"error": "missing or invalid session token"}
