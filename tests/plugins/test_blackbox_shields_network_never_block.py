"""DNS Shield never refuses what keeps a Mac working and safe, and its lists cannot be redirected
off their hosts (review 2026-11-21, finding 13).

Contracts: Apple's services, certificate checks (OCSP / CRL), GitHub and localhost — with every
subdomain — and the person's allow list are taken out of every plan, from public lists AND the
verified graph; a spared verified entry is reported in the plan; a look-alike name is not spared;
the person's own block list is theirs; a list download follows a redirect only to HTTPS on an
allowed list host.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.network.protect import blocklists, enforcement, never_block


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(enforcement, "_plan_cache", {"key": None, "plan": None})
    return tmp_path


def test_apple_certificate_checks_github_and_this_machine_are_never_refused_but_look_alikes_are():
    for name in ("swscan.apple.com", "ocsp.apple.com", "ocsp.digicert.com", "raw.githubusercontent.com", "github.com", "localhost"):
        assert never_block.protected(name), name
    for name in ("apple.com.evil.example", "evilapple.com", "github.com-login.example", "notgithub.com"):
        assert not never_block.protected(name), name
    assert never_block.protected("cdn.my-own.example", allow=("my-own.example",))


def test_the_plan_spares_never_block_names_from_lists_and_the_graph_and_reports_the_graphs(monkeypatch):
    mode = network_mode.build(enabled=True, protections=(network_mode.DNS,), block=("github.com",))
    monkeypatch.setattr(network_mode, "list_packs", lambda: ())
    indicators = SimpleNamespace(domains=frozenset({"evil.example", "ocsp.digicert.com", "updates.apple.com"}), ips=frozenset(),
                                 complete=True, built_at=1.0)
    plan = enforcement.plan(mode, indicators)
    assert plan["dns"]["verified"] == ["evil.example"]
    assert plan["dns"]["spared"] == ["ocsp.digicert.com", "updates.apple.com"]
    assert "github.com" in plan["dns"]["block"], "the person's own block list is theirs"


def test_a_public_list_cannot_block_apple_or_github(monkeypatch):
    pack = SimpleNamespace(id="test-list", status="supported")
    mode = network_mode.build(enabled=True, protections=(network_mode.DNS,), lists=("test-list",))
    monkeypatch.setattr(network_mode, "list_packs", lambda: (pack,))
    monkeypatch.setattr(blocklists, "domains", lambda p: frozenset({"ads.example", "icloud.com", "api.github.com"}))
    plan = enforcement.plan(mode, None)
    assert plan["dns"]["lists"] == ["ads.example"]


@pytest.mark.parametrize("target, refused", [
    ("https://evil.example/list.txt", True),
    ("http://raw.githubusercontent.com/list.txt", True),
    ("https://user:pw@raw.githubusercontent.com/list.txt", True),
    ("https://small.oisd.nl/domainswild", False),
])
def test_a_list_download_follows_a_redirect_only_to_https_on_an_allowed_host(target, refused):
    handler = blocklists._StayOnAllowedHosts()
    request = urllib.request.Request("https://raw.githubusercontent.com/start.txt")
    if refused:
        with pytest.raises(urllib.error.HTTPError):
            handler.redirect_request(request, None, 302, "Found", {}, target)
    else:
        assert handler.redirect_request(request, None, 302, "Found", {}, target).full_url == target
