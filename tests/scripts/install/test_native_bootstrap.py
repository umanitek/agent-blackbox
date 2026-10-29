"""Native bootstrap selection preserves installed stores, trust choices and job deadlines."""
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import urllib.error

import pytest

PATH = Path(__file__).resolve().parents[3] / "scripts" / "blackbox-native-bootstrap.py"
spec = importlib.util.spec_from_file_location("native_bootstrap_installer", PATH)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def fixture(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    java = tmp_path / "java"
    java.write_text("fixture")
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[-1] == "-version":
            return SimpleNamespace(returncode=0, stdout="", stderr='openjdk version "11.0.2"')
        return SimpleNamespace(returncode=0, stdout=json.dumps({"version": 1, "daemonRestart": True, "defaultEligible": False}))
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda _: str(java))
    monkeypatch.setattr(bootstrap.shutil, "disk_usage", lambda _: SimpleNamespace(free=20 * 2**30))
    monkeypatch.setattr(bootstrap, "provision_jar", lambda _: tmp_path / "runtime.jar")
    def select(mode="native", entry=None):
        return bootstrap.select_profile(home, tmp_path, tmp_path / "dkg", "graph", "graph", mode, entry or {}, run=run)
    return home, calls, select


def test_fresh_profile_keeps_registered_core_checks_and_requires_explicit_experimental_choice(tmp_path, monkeypatch):
    home, _calls, select = fixture(tmp_path, monkeypatch)
    assert select("auto") is None
    selected = select()
    assert selected["source"] == {"contextGraphId": "graph", "onChainId": "14", "mode": "core-cache",
                                 "sourcePolicy": "DKG_Core_chain_cache", "trustedCorePeerIds": []}
    assert selected["runtime"]["jarSha256"] == bootstrap.JAR_SHA256
    assert list(home.iterdir()) == []


def test_upgrades_never_replace_existing_stores_or_discard_native_journals(tmp_path, monkeypatch):
    home, calls, select = fixture(tmp_path, monkeypatch)
    installed = {"store": {"backend": "blazegraph", "options": {"url": "http://localhost/store"}}}
    path = home / "config.json"
    path.write_text(json.dumps(installed))
    assert select() is None
    assert json.loads(path.read_text()) == installed
    assert calls == []
    path.unlink()  # Test-owned fixture only.
    native = select()
    path.write_text(json.dumps({"publicSnapshotBootstrap": native}))
    assert select("auto") == native
    with pytest.raises(ValueError, match="cannot be switched"):
        select("oxigraph")


@pytest.mark.parametrize("entry", [
    {"snapshot_sync": {"DKG_Core_chain_cache": False}},
    {"snapshot_sync": {"trusted_core_peers": ["custom"]}},
    {"context_graph_id": "custom-graph"},
    {"graph_peer_id": "chosen-core"},
])
def test_explicit_trust_and_custom_graph_choices_are_not_migrated(tmp_path, monkeypatch, entry):
    home, calls, select = fixture(tmp_path, monkeypatch)
    assert select(entry=entry) is None
    assert calls == []
    assert list(home.iterdir()) == []


def test_bad_runtime_download_is_never_installed(tmp_path):
    class Download(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    with pytest.raises(ValueError, match="checksum"):
        bootstrap.provision_jar(tmp_path, download=lambda *args, **kwargs: Download(b"incorrect artifact"))
    assert not (tmp_path / "blazegraph-2.1.6-rc.jar").exists()
    assert len(list(tmp_path.glob("*.partial"))) == 1


def test_bootstrap_observation_preserves_deadline_and_requires_regular_readiness_afterward(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"publicSnapshotBootstrap": {"version": 1}}))
    (tmp_path / "daemon.pid").write_text(str(os.getpid()))
    now = [0.0]
    def pending(*args, **kwargs):
        raise urllib.error.HTTPError("http://localhost", 503, "starting", {},
                                     io.BytesIO(b'{"state":"public-bootstrap-starting","ready":false}'))
    def advance(_): now[0] = 3600
    with pytest.raises(ValueError, match="unchanged one-hour"):
        bootstrap.wait_for_bootstrap(tmp_path, "http://localhost", request=pending, clock=lambda: now[0], sleep=advance)

def test_blackbox_upgrade_retains_native_cli_and_refuses_incompatible_replacement(tmp_path):
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'publicSnapshotBootstrap': {'version': 1}}))
    def supported(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout='{"version":1,"daemonRestart":true}')
    assert bootstrap.retain_runtime(tmp_path, '/unused', run=supported)
    with pytest.raises(ValueError, match='did not replace'):
        bootstrap.retain_runtime(tmp_path, '/unused', run=lambda *a, **k: SimpleNamespace(returncode=1))
    assert json.loads(config.read_text()) == {'publicSnapshotBootstrap': {'version': 1}}


def test_missing_ordinary_config_does_not_add_a_new_readiness_gate(tmp_path):
    bootstrap.wait_for_bootstrap(tmp_path, 'http://localhost', request=lambda *a, **k: pytest.fail('ordinary path'))
