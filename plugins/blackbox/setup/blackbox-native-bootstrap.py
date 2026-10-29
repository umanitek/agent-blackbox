#!/usr/bin/env python3
"""Fresh native bootstrap selection and bounded startup observation; no store migration."""
from __future__ import annotations
import hashlib
import json
import os
import psutil
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

JAR_SHA256 = "930c38b5bce7c0ae99701c1f6ef3057c52f3f385d938e1397a3e05561c7df5de"
JAR_URL = "https://github.com/blazegraph/database/releases/download/BLAZEGRAPH_2_1_6_RC/blazegraph.jar"
PLAN = "public-bootstrap-plan.json"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def provision_jar(directory, download=urllib.request.urlopen):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "blazegraph-2.1.6-rc.jar"
    if target.exists():
        if target.is_symlink() or digest(target) != JAR_SHA256:
            raise ValueError("Existing native runtime differs from the pinned release")
        return target
    fd, name = tempfile.mkstemp(prefix="runtime-", suffix=".partial", dir=directory)
    # Failed downloads remain for diagnosis, never substitute unverified bytes.
    with os.fdopen(fd, "wb") as out, download(JAR_URL, timeout=120) as response:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 128 * 1024 * 1024:
                raise ValueError("Native runtime download exceeds bound")
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    if digest(name) != JAR_SHA256:
        raise ValueError("Native runtime checksum mismatch")
    # Exclusive link cannot replace a concurrent writer or an existing runtime.
    os.link(name, target)
    return target


def select_profile(home, cli_dir, dkg_bin, graph, default_graph, mode, entry, *, run=subprocess.run):
    home = Path(home)
    existing_path = home / "config.json"
    existing = json.loads(existing_path.read_text(encoding="utf-8-sig")) if existing_path.exists() else {}
    retained = existing.get("publicSnapshotBootstrap")
    if retained:
        if mode not in {"auto", "native"}:
            raise ValueError("An existing native journal cannot be switched to another store by setup")
    elif mode not in {"auto", "native"} or existing_path.exists():
        return None
    if not retained:
        if entry.get("graph_peer_id") or graph != default_graph or entry.get("context_graph_id", default_graph) != default_graph:
            return None
        snapshot = entry.get("snapshot_sync")
        if snapshot is not None and (not isinstance(snapshot, dict)
                or snapshot.get("DKG_Core_chain_cache") is not True
                or snapshot.get("trusted_core_peers") or snapshot.get("source_policy")
                or str(snapshot.get("on_chain_id", "14")) != "14" or snapshot.get("mode", "core-cache") != "core-cache"):
            return None
        allowed = {"auth.token", "blackbox-process-limits.json", PLAN}
        if home.exists() and any(p.name not in allowed or not p.is_file() or p.is_symlink() for p in home.iterdir()):
            return None
    result = run([str(dkg_bin), "sync", "bootstrap-capabilities"], capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        if retained:
            raise ValueError("Installed DKG cannot reopen the retained native journal")
        return None
    caps = json.loads(result.stdout)
    if caps.get("version") != 1 or caps.get("daemonRestart") is not True:
        raise ValueError("Installed native bootstrap contract is incompatible")
    if not retained and mode == "auto" and caps.get("defaultEligible") is not True:
        return None  # Remains experimental until the full mainnet lifecycle is validated.
    if retained:
        return retained
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")) if java_home else shutil.which("java")
    if not java:
        return None
    version = run([java, "-version"], capture_output=True, text=True, timeout=10, check=False)
    if version.returncode or not any(token in version.stderr + version.stdout for token in ['version "11.', 'openjdk 11.']):
        return None
    if shutil.disk_usage(home if home.exists() else home.parent).free <= 18 * 2**30:
        return None
    jar = provision_jar(Path(cli_dir) / "native-bootstrap-runtime")
    return {"version": 1, "source": {"contextGraphId": graph, "onChainId": "14", "mode": "core-cache",
            "sourcePolicy": "DKG_Core_chain_cache", "trustedCorePeerIds": []},
            "runtime": {"java": str(Path(java).resolve()), "jar": str(jar.resolve()), "jarSha256": JAR_SHA256}}


def wait_for_bootstrap(home, url, *, request=urllib.request.urlopen, clock=time.monotonic, sleep=time.sleep):
    path = Path(home) / "config.json"
    if not path.exists():
        return
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    if not config.get("publicSnapshotBootstrap"):
        return
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    if parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'} or parsed.username or parsed.password:
        raise ValueError("Native startup observation requires the owned local API")
    token_path = Path(home) / 'auth.token'
    tokens = [line.strip() for line in token_path.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.startswith('#')] if token_path.exists() else []
    headers = {'Authorization': 'Bearer ' + tokens[0]} if tokens else {}
    probe = urllib.request.Request(url.rstrip('/') + '/api/status', headers=headers)
    # This is the existing snapshot budget, followed by the unchanged runtime readiness check.
    started = clock()
    deadline = started + 3600
    observed_bootstrap = False
    while clock() < deadline:
        try:
            with request(probe, timeout=2) as response:
                if response.status == 200:
                    return  # Caller must still verify exact runtime, coverage and usable rules.
        except urllib.error.HTTPError as error:
            body = json.loads(error.read(4096)) if error.code == 503 else {}
            observed_bootstrap = error.code == 503 and body.get("state") == "public-bootstrap-starting"
            if error.code != 503 or body.get("state") != "public-bootstrap-starting":
                raise ValueError("Unexpected API response while waiting for native bootstrap") from error
        except urllib.error.URLError:
            pass  # The ordinary start command can return before the bootstrap listener binds.
        if not observed_bootstrap and clock() - started >= 90:
            raise ValueError("Native bootstrap did not start within the unchanged 90-second startup deadline")
        pid_file = Path(home) / "daemon.pid"
        if observed_bootstrap and not pid_file.exists():
            raise ValueError("Native bootstrap daemon identity disappeared; failed attempt is preserved")
        if observed_bootstrap:
            pid = int(pid_file.read_text(encoding="utf-8-sig").strip())
            if pid <= 0:
                raise ValueError("Invalid daemon identity while waiting for bootstrap")
            if not psutil.pid_exists(pid):
                raise ValueError("Native bootstrap daemon exited; failed attempt is preserved")
        sleep(min(2, max(0, deadline - clock())))
    raise ValueError("Native bootstrap observation reached the unchanged one-hour snapshot deadline")


def retain_runtime(home, binary, *, run=subprocess.run):
    """An experimental journal pins its compatible CLI until an explicit DKG upgrade."""
    path = Path(home) / 'config.json'
    if not path.exists() or not json.loads(path.read_text(encoding='utf-8-sig')).get('publicSnapshotBootstrap'):
        return False
    result = run([str(binary), 'sync', 'bootstrap-capabilities'], capture_output=True, text=True, timeout=10, check=False)
    caps = json.loads(result.stdout) if result.returncode == 0 else {}
    if caps.get('version') != 1 or caps.get('daemonRestart') is not True:
        raise ValueError('The retained native journal requires its compatible DKG runtime; setup did not replace it')
    return True


def main(args):
    if args[0] == 'retain':
        return 0 if retain_runtime(*args[1:]) else 3
    if args[0] == "wait":
        wait_for_bootstrap(*args[1:])
        return 0
    if args[0] != "plan" or len(args) != 8:
        raise ValueError("Expected plan HOME CLI_DIR DKG_BIN GRAPH DEFAULT_GRAPH MODE HERMES_CONFIG")
    _, home, cli_dir, binary, graph, default_graph, mode, hermes_config = args
    config_path = Path(hermes_config)
    entry = {}
    if config_path.exists():
        import yaml
        data = yaml.safe_load(config_path.read_text(encoding="utf-8-sig")) or {}
        entry = data.get("plugins", {}).get("entries", {}).get("blackbox", {})
    profile = select_profile(home, cli_dir, binary, graph, default_graph, mode, entry)
    if profile is None:
        if mode == "native":
            raise ValueError("Native bootstrap requires a fresh default-graph profile, compatible DKG, Java 11 and more than 18 GiB free; existing data was not changed")
        return 3
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    plan = home / PLAN
    if plan.exists():
        if json.loads(plan.read_text(encoding="utf-8-sig")) != profile:
            raise ValueError("Existing bootstrap plan differs; it was not changed")
    else:
        with plan.open("x", encoding="utf-8") as out:
            json.dump(profile, out); out.flush(); os.fsync(out.fileno())
        plan.chmod(0o600)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Native bootstrap unavailable: {exc}", file=sys.stderr)
        raise SystemExit(1)
