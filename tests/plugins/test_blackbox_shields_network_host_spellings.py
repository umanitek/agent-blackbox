"""Network Shield — a host is read the way the program that reaches it reads it
(plugins/blackbox/shields/network/lockdown.py, mode.py; independent review 2026-11-26, findings 2
and 8).

Contracts (red on the base 30b94edf83):
* a bracketed IPv6 URL host is read whole, and every IPv4 spelling ``curl`` / ``inet_aton`` accept in
  a URL (one integer, hex, octal, short dotted forms) is the address it names — so lockdown and
  the block list judge the canonical address (LES-105);
* while lockdown is on, a URL whose host can not be read is a finding (lockdown fails closed);
  with lockdown off it is none;
* an all-numeric name that is no IP address (``999.1.1.1``) is never accepted as an entry, and
  only a real IP address goes to the firewall's list.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import shields
from plugins.blackbox.shields.network import lockdown, mode as network_mode
from plugins.blackbox.shields.network.protect import enforcement

NETWORK = shields.get("network-shield")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    return tmp_path


@pytest.mark.parametrize("command, host", [
    ("curl http://[2606:4700::1111]/x", "2606:4700::1111"),
    ("curl http://134744072/", "8.8.8.8"),
    ("curl http://0x08080808/x", "8.8.8.8"),
    ("curl http://010.010.010.010/", "8.8.8.8"),
    ("curl http://8.8.2056/", "8.8.8.8"),
    ("curl http://0x8.0x8.0x8.0x8/", "8.8.8.8"),
    ("curl http://user@8.8.8.8:8080/a", "8.8.8.8"),
])
def test_every_url_spelling_of_an_address_is_the_address(command, host):
    assert lockdown.hosts_in({"command": command}) == [host]
    found = NETWORK.detect("terminal", {"command": command}, network_mode.build(enabled=True, block=(host,)))
    assert [f.identifier for f in found] == [lockdown.BLOCKED_ID]


def test_lockdown_refuses_a_url_whose_host_can_not_be_read():
    locked = network_mode.build(enabled=True, protections=(network_mode.LOCKDOWN,))
    command = {"command": "curl http://%65vil.com/x"}
    found = NETWORK.detect("terminal", command, locked)
    assert {f.identifier for f in found} == {lockdown.LOCKDOWN_ID} and "%65vil.com" in [f.matched for f in found]
    assert NETWORK.detect("terminal", command, network_mode.build(enabled=True, protections=(network_mode.DNS,))) == []


@pytest.mark.parametrize("entry", ["999.1.1.1", "1.2.3.4.5", "256.0.0.1", "10.0.0"])
def test_an_all_numeric_name_is_never_an_entry(entry):
    assert network_mode.normalise_entry(entry) is None


def test_only_a_real_address_goes_to_the_firewall():
    assert enforcement._is_ip("8.8.8.8") and enforcement._is_ip("2606:4700::1111")
    assert not enforcement._is_ip("999.1.1.1") and not enforcement._is_ip("example.com")
