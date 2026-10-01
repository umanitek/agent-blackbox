"""Safety-profile behavior across managed DKG stop/start transitions."""

import argparse
import json
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox


config_mod = load_blackbox("config")
cli_mod = load_blackbox("cli")


SAFETY_ENV_NAMES = (
    "NODE_OPTIONS",
    "DKG_STORE_QUEUE_LIMIT",
    "DKG_STORE_ACK_QUEUE_LIMIT",
    "DKG_STORE_HEALTH_QUEUE_LIMIT",
    "DKG_STORE_NORMAL_QUEUE_LIMIT",
    "DKG_STORE_BACKGROUND_QUEUE_LIMIT",
    "DKG_LIST_CONTEXT_GRAPHS_PROJECTION",
)


@pytest.fixture
def managed_installation(tmp_path, monkeypatch):
    """An isolated installation, with no options inherited from the test host."""
    home = tmp_path / "dkg-home"
    home.mkdir()
    cli = tmp_path / "installation" / "cli.js"
    cli.parent.mkdir()
    cli.write_text("// fixture DKG CLI\n", encoding="utf-8")
    (home / "config.json").write_text("{}\n", encoding="utf-8")
    for name in SAFETY_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli_mod, "_managed_dkg_node_executable", lambda _cfg: None)
    return config_mod.BlackboxConfig(
        dkg_home=str(home),
        dkg_bin=str(cli),
        dkg_url="http://127.0.0.1:9320",
    )


class ManagedProcess:
    """A psutil boundary fixture whose identity can change during a read."""

    def __init__(self, cfg, *, pid=4242, env=None, argv=None):
        self.pid = pid
        self._env = dict(env or {})
        self._env.setdefault("DKG_HOME", cfg.dkg_home)
        self._argv = argv or ["/fixture/node", cfg.dkg_bin, "daemon-worker"]
        self.started_at = 1700000000.0
        self.alive = True
        self.read_env = None
        self.info = {"pid": pid, "cmdline": self._argv, "exe": "/fixture/node"}

    def cmdline(self):
        return list(self._argv)

    def environ(self):
        if self.read_env is not None:
            self.read_env()
        return dict(self._env)

    def create_time(self):
        return self.started_at

    def is_running(self):
        return self.alive

    def exe(self):
        return "/fixture/node"

    def cwd(self):
        return str(Path(self._argv[1]).parent)


def install_process(monkeypatch, cfg, process, *others):
    processes = [process, *others]
    (Path(cfg.dkg_home) / "daemon.pid").write_text(str(process.pid), encoding="utf-8")

    def get_process(pid):
        for candidate in processes:
            if candidate.pid == pid and candidate.alive:
                return candidate
        raise cli_mod.psutil.NoSuchProcess(pid)

    monkeypatch.setattr(cli_mod.psutil, "Process", get_process)
    monkeypatch.setattr(cli_mod.psutil, "process_iter", lambda _attrs=None: processes)


def install_restart_boundary(monkeypatch, process, on_stop=None):
    """Exercise actual restart orchestration without launching any process."""
    calls = []

    def run(command, **kwargs):
        action = command[-1]
        assert action in {"stop", "start"}
        calls.append((action, dict(kwargs["env"])))
        if action == "stop":
            if on_stop is not None:
                on_stop()
            process.alive = False
        return argparse.Namespace(returncode=0, stdout="", stderr="")

    class Client:
        def __init__(self, **_kwargs):
            pass

        def reachable(self, **_kwargs):
            return False

        def status(self, **_kwargs):
            return {"status": "ok"}

    monkeypatch.setattr(cli_mod.subprocess, "run", run)
    monkeypatch.setattr(cli_mod, "DkgClient", Client)
    monkeypatch.setattr(cli_mod.time, "sleep", lambda _seconds: None)
    return calls


@pytest.fixture
def safety():
    return load_blackbox("dkg_runtime_safety")


def profile(safety, *, heap=2048, common=512, ack=33, health=44, normal=55, background=66, projection=True):
    return safety.RuntimeSafetyProfile(
        max_old_space_size_mb=heap,
        store_queue_limit=common,
        store_ack_queue_limit=ack,
        store_health_queue_limit=health,
        store_normal_queue_limit=normal,
        store_background_queue_limit=background,
        list_context_graphs_projection=projection,
    )


def resolve_environment(safety, cfg, environment, *, live=None, saved=None, default_heap=3072, monkeypatch):
    monkeypatch.setattr(safety, "capture_runtime_safety", lambda *_args: live)
    monkeypatch.setattr(safety, "read_runtime_safety", lambda *_args: saved)
    monkeypatch.setattr(safety, "default_heap_mb", lambda: default_heap)
    result = dict(environment)
    safety.prepare_restart_environment(result, cfg.dkg_home, cfg.dkg_bin)
    return result


@pytest.mark.parametrize(
    "options,arguments,expected",
    [
        ("", [], None),
        ("--max-old-space-size=2048", [], 2048),
        ("--max_old_space_size 1024", [], 1024),
        ("--require=/private/loader.js --max-old-space-size=1536", [], 1536),
        ("--require --max-old-space-size=9999", [], None),
        ("--max-old-space-size=2048", ["--max-old-space-size=768"], 768),
        ("--max-old-space-size=2048", ["--max_old_space_size", "640"], 640),
        ("", ["--require", "--max-old-space-size=9999", "--max-old-space-size=768"], 768),
    ],
)
def test_heap_parser_extracts_only_numeric_setting_with_argv_precedence(safety, options, arguments, expected):
    assert safety.heap_limit_mb(options, arguments) == expected


@pytest.mark.parametrize("options", ["--max-old-space-size=0", "--max-old-space-size=-1", "--max-old-space-size=1.5", "--max-old-space-size=secret", "--max-old-space-size", "--max-old-space-size=2048 --max-old-space-size=bad"])
def test_heap_parser_rejects_invalid_explicit_memory_setting(safety, options):
    with pytest.raises(safety.RuntimeSafetyError):
        safety.heap_limit_mb(options)


def test_exact_live_worker_yields_typed_whitelist_and_effective_lane_values(safety, managed_installation, monkeypatch):
    cfg = managed_installation
    process = ManagedProcess(
        cfg,
        env={
            "NODE_OPTIONS": "--require=/private/loader.js --max-old-space-size=2048",
            "DKG_STORE_QUEUE_LIMIT": "512",
            "DKG_STORE_ACK_QUEUE_LIMIT": "21",
            "DKG_STORE_HEALTH_QUEUE_LIMIT": "22",
            "DKG_STORE_NORMAL_QUEUE_LIMIT": "23",
            "DKG_STORE_BACKGROUND_QUEUE_LIMIT": "24",
            "DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "1",
            "API_SECRET": "not-a-safety-setting",
        },
        argv=["/fixture/node", "--max-old-space-size=1024", cfg.dkg_bin, "daemon-worker"],
    )
    install_process(monkeypatch, cfg, process)

    captured = safety.capture_runtime_safety(cfg.dkg_home, cfg.dkg_bin)

    assert captured == profile(safety, heap=1024, ack=21, health=22, normal=23, background=24)
    assert "loader" not in repr(captured)
    assert "API_SECRET" not in repr(captured)


def test_live_missing_guards_preserve_actual_dkg_defaults(safety, managed_installation, monkeypatch):
    cfg = managed_installation
    install_process(monkeypatch, cfg, ManagedProcess(cfg))

    captured = safety.capture_runtime_safety(cfg.dkg_home, cfg.dkg_bin)

    assert captured == profile(safety, heap=None, common=64, ack=64, health=64, normal=64, background=64, projection=False)


@pytest.mark.parametrize("mismatch", ["installation", "home", "command", "executable", "preceding_entrypoint"])
def test_foreign_pid_cannot_supply_runtime_settings(safety, managed_installation, monkeypatch, mismatch):
    cfg = managed_installation
    process = ManagedProcess(cfg, env={"NODE_OPTIONS": "--max-old-space-size=9999"})
    if mismatch == "installation":
        process._argv = ["/fixture/node", str(Path(cfg.dkg_bin).parent / "foreign-cli.js"), "daemon-worker"]
    elif mismatch == "home":
        process._env["DKG_HOME"] = str(Path(cfg.dkg_home).parent / "foreign-home")
    elif mismatch == "command":
        process._argv[-1] = "query"
    elif mismatch == "preceding_entrypoint":
        process._argv = ["/fixture/node", "/foreign/script.js", cfg.dkg_bin, "daemon-worker"]
    else:
        process.exe = lambda: "/fixture/python"
        process.info["exe"] = "/fixture/python"
    process.info["cmdline"] = process._argv
    install_process(monkeypatch, cfg, process)

    assert safety.capture_runtime_safety(cfg.dkg_home, cfg.dkg_bin) is None


@pytest.mark.parametrize("identity_change", ["pid_reused", "exit", "entrypoint_swap", "executable_swap"])
def test_process_identity_is_rechecked_after_environment_read(safety, managed_installation, monkeypatch, identity_change):
    cfg = managed_installation
    process = ManagedProcess(cfg, env={"NODE_OPTIONS": "--max-old-space-size=2048"})

    def changed_identity():
        if identity_change == "pid_reused":
            process.started_at += 1
        elif identity_change == "exit":
            process.alive = False
        elif identity_change == "entrypoint_swap":
            process._argv = ["/fixture/node", "/foreign/script.js", cfg.dkg_bin, "daemon-worker"]
        else:
            process.exe = lambda: "/foreign/runtime/node"

    process.read_env = changed_identity
    install_process(monkeypatch, cfg, process)

    assert safety.capture_runtime_safety(cfg.dkg_home, cfg.dkg_bin) is None


def test_discovery_without_pid_file_prefers_worker_over_supervisor(safety, managed_installation, monkeypatch):
    cfg = managed_installation
    supervisor = ManagedProcess(cfg, pid=4242, env={"NODE_OPTIONS": "--max-old-space-size=4096"})
    supervisor._argv[-1] = "daemon-supervisor"
    worker = ManagedProcess(cfg, pid=4343, env={"NODE_OPTIONS": "--max-old-space-size=1024"})
    install_process(monkeypatch, cfg, supervisor, worker)
    (Path(cfg.dkg_home) / "daemon.pid").unlink()

    captured = safety.capture_runtime_safety(cfg.dkg_home, cfg.dkg_bin)

    assert captured.max_old_space_size_mb == 1024


def test_profile_round_trip_is_bound_to_canonical_home_and_installation(safety, managed_installation):
    cfg = managed_installation
    expected = profile(safety)
    safety.write_runtime_safety(expected, cfg.dkg_home, cfg.dkg_bin)

    assert safety.read_runtime_safety(cfg.dkg_home, cfg.dkg_bin) == expected
    assert safety.read_runtime_safety(cfg.dkg_home, str(Path(cfg.dkg_bin).parent / "other-cli.js")) is None
    relocated_home = Path(cfg.dkg_home).parent / "relocated-home"
    relocated_home.mkdir()
    marker = next(p for p in Path(cfg.dkg_home).iterdir() if p.name != "config.json")
    (relocated_home / marker.name).write_bytes(marker.read_bytes())
    assert safety.read_runtime_safety(str(relocated_home), cfg.dkg_bin) is None


def test_profile_is_atomic_private_and_contains_no_environment_blob(safety, managed_installation):
    cfg = managed_installation
    safety.write_runtime_safety(profile(safety), cfg.dkg_home, cfg.dkg_bin)
    markers = [p for p in Path(cfg.dkg_home).iterdir() if p.name != "config.json"]

    assert len(markers) == 1
    assert markers[0].stat().st_mode & 0o777 == 0o600
    payload = json.loads(markers[0].read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert "NODE_OPTIONS" not in markers[0].read_text(encoding="utf-8")


@pytest.mark.parametrize("malformation", ["invalid_json", "wrong_version", "unknown_field", "boolean_heap", "negative_queue", "unbounded_heap", "unbounded_queue", "string_queue", "duplicate_key", "oversized"])
def test_malformed_profile_cannot_override_safe_cold_restart(safety, managed_installation, monkeypatch, malformation):
    cfg = managed_installation
    safety.write_runtime_safety(profile(safety), cfg.dkg_home, cfg.dkg_bin)
    marker = next(p for p in Path(cfg.dkg_home).iterdir() if p.name != "config.json")
    payload = json.loads(marker.read_text(encoding="utf-8"))
    if malformation == "invalid_json":
        marker.write_text("{truncated", encoding="utf-8")
    elif malformation == "duplicate_key":
        marker.write_text(marker.read_text(encoding="utf-8").replace('"version": 1', '"version": 1, "version": 1'), encoding="utf-8")
    elif malformation == "oversized":
        marker.write_text(marker.read_text(encoding="utf-8") + " " * 4096, encoding="utf-8")
    else:
        if malformation == "wrong_version":
            payload["version"] = 99
        elif malformation == "unknown_field":
            payload["NODE_OPTIONS"] = "--require=/private/loader.js"
        else:
            # Find the typed profile object without coupling the test to its container key.
            settings = next((value for value in payload.values() if isinstance(value, dict) and "store_queue_limit" in value), payload)
            key, value = {
                "boolean_heap": ("max_old_space_size_mb", True),
                "negative_queue": ("store_queue_limit", -1),
                "unbounded_heap": ("max_old_space_size_mb", 2**31),
                "unbounded_queue": ("store_queue_limit", 2**31),
                "string_queue": ("store_queue_limit", "512"),
            }[malformation]
            settings[key] = value
        marker.write_text(json.dumps(payload), encoding="utf-8")
    assert safety.read_runtime_safety(cfg.dkg_home, cfg.dkg_bin) is None
    monkeypatch.setattr(safety, "capture_runtime_safety", lambda *_args: None)
    monkeypatch.setattr(safety, "default_heap_mb", lambda: 3072)
    environment = {}

    safety.prepare_restart_environment(environment, cfg.dkg_home, cfg.dkg_bin)

    assert environment["NODE_OPTIONS"] == "--max-old-space-size=3072"
    assert environment["DKG_STORE_QUEUE_LIMIT"] == "512"
    assert environment["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "1"


def test_caller_settings_override_live_and_saved_profile(safety, managed_installation, monkeypatch):
    cfg = managed_installation
    caller_options = "--trace-warnings --max-old-space-size=768"
    environment = resolve_environment(
        safety, cfg,
        {"NODE_OPTIONS": caller_options, "DKG_STORE_QUEUE_LIMIT": "90", "DKG_STORE_ACK_QUEUE_LIMIT": "12", "DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "0"},
        live=profile(safety, heap=1024), saved=profile(safety, heap=4096), monkeypatch=monkeypatch,
    )

    assert environment["NODE_OPTIONS"] == caller_options
    assert environment["DKG_STORE_QUEUE_LIMIT"] == "90"
    assert environment["DKG_STORE_ACK_QUEUE_LIMIT"] == "12"
    assert environment["DKG_STORE_HEALTH_QUEUE_LIMIT"] == "44"
    assert environment["DKG_STORE_NORMAL_QUEUE_LIMIT"] == "55"
    assert environment["DKG_STORE_BACKGROUND_QUEUE_LIMIT"] == "66"
    assert environment["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "0"


@pytest.mark.parametrize("source", ["live", "saved"])
@pytest.mark.parametrize("caller_common", ["512", "90"])
def test_caller_common_preserves_distinct_lane_limits(safety, managed_installation, monkeypatch, source, caller_common):
    selected = profile(safety, common=512, ack=32, health=512, normal=512, background=16)
    environment = resolve_environment(
        safety, managed_installation,
        {"DKG_STORE_QUEUE_LIMIT": caller_common},
        **{source: selected}, monkeypatch=monkeypatch,
    )

    assert environment["DKG_STORE_QUEUE_LIMIT"] == caller_common
    assert environment["DKG_STORE_ACK_QUEUE_LIMIT"] == "32"
    assert environment["DKG_STORE_BACKGROUND_QUEUE_LIMIT"] == "16"
    assert environment["DKG_STORE_HEALTH_QUEUE_LIMIT"] == caller_common
    assert environment["DKG_STORE_NORMAL_QUEUE_LIMIT"] == caller_common


def test_caller_common_propagates_to_uniform_cold_default_lanes(safety, managed_installation, monkeypatch):
    environment = resolve_environment(
        safety, managed_installation,
        {"DKG_STORE_QUEUE_LIMIT": "90"}, monkeypatch=monkeypatch,
    )

    assert environment["DKG_STORE_QUEUE_LIMIT"] == "90"
    assert [environment[f"DKG_STORE_{lane}_QUEUE_LIMIT"] for lane in ("ACK", "HEALTH", "NORMAL", "BACKGROUND")] == ["90"] * 4


def test_live_profile_precedes_saved_profile_without_flattening_lanes(safety, managed_installation, monkeypatch):
    environment = resolve_environment(safety, managed_installation, {}, live=profile(safety, heap=1024, common=70, ack=11, health=12, normal=13, background=14, projection=False), saved=profile(safety, heap=4096), monkeypatch=monkeypatch)

    assert environment["NODE_OPTIONS"] == "--max-old-space-size=1024"
    assert environment["DKG_STORE_QUEUE_LIMIT"] == "70"
    assert [environment[f"DKG_STORE_{lane}_QUEUE_LIMIT"] for lane in ("ACK", "HEALTH", "NORMAL", "BACKGROUND")] == ["11", "12", "13", "14"]
    assert environment["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "0"


def test_live_missing_heap_uses_saved_heap_and_keeps_intentional_caller_options(safety, managed_installation, monkeypatch):
    environment = resolve_environment(safety, managed_installation, {"NODE_OPTIONS": "--trace-warnings"}, live=profile(safety, heap=None), saved=profile(safety, heap=1536), monkeypatch=monkeypatch)

    assert environment["NODE_OPTIONS"] == "--trace-warnings --max-old-space-size=1536"


def test_cold_restart_restores_matching_saved_profile(safety, managed_installation, monkeypatch):
    environment = resolve_environment(safety, managed_installation, {}, saved=profile(safety, heap=1536, projection=False), monkeypatch=monkeypatch)

    assert environment["NODE_OPTIONS"] == "--max-old-space-size=1536"
    assert environment["DKG_STORE_ACK_QUEUE_LIMIT"] == "33"
    assert environment["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "0"


@pytest.mark.parametrize("name,value", [("NODE_OPTIONS", "--max-old-space-size=bad"), ("NODE_OPTIONS", "--max-old-space-size-percentage=75"), ("DKG_STORE_QUEUE_LIMIT", "0"), ("DKG_STORE_ACK_QUEUE_LIMIT", "-1"), ("DKG_LIST_CONTEXT_GRAPHS_PROJECTION", "maybe")])
def test_invalid_explicit_guard_fails_before_stop(safety, managed_installation, monkeypatch, name, value):
    cfg = managed_installation
    process = ManagedProcess(cfg)
    install_process(monkeypatch, cfg, process)
    calls = install_restart_boundary(monkeypatch, process)
    monkeypatch.setattr(safety, "default_heap_mb", lambda: 3072)
    monkeypatch.setenv(name, value)

    with pytest.raises(safety.RuntimeSafetyError):
        cli_mod._restart_managed_dkg(cfg)

    assert calls == []
    assert process.alive


def test_actual_restart_saves_whitelist_before_stop_and_restores_start_environment(safety, managed_installation, monkeypatch):
    cfg = managed_installation
    process = ManagedProcess(cfg, env={"NODE_OPTIONS": "--require=/private/loader.js --max-old-space-size=1536", "DKG_STORE_QUEUE_LIMIT": "512", "DKG_STORE_ACK_QUEUE_LIMIT": "31", "DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "1", "API_SECRET": "never-copy-this"})
    install_process(monkeypatch, cfg, process)

    def before_stop():
        persisted = safety.read_runtime_safety(cfg.dkg_home, cfg.dkg_bin)
        assert persisted.max_old_space_size_mb == 1536
        assert persisted.store_ack_queue_limit == 31

    calls = install_restart_boundary(monkeypatch, process, before_stop)

    cli_mod._restart_managed_dkg(cfg)

    assert [action for action, _env in calls] == ["stop", "start"]
    start_environment = calls[1][1]
    assert start_environment["NODE_OPTIONS"] == "--max-old-space-size=1536"
    assert start_environment["DKG_STORE_QUEUE_LIMIT"] == "512"
    assert start_environment["DKG_STORE_ACK_QUEUE_LIMIT"] == "31"
    assert start_environment["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "1"
    assert "API_SECRET" not in start_environment
    assert "/private/loader.js" not in json.dumps(start_environment)


@pytest.mark.parametrize("physical_gib,cgroup_limit,expected", [(8, str(4 * 1024**3), 3072), (2, "max", 1536), (16, "max", 8192), (0, "max", 8192)])
def test_cold_heap_respects_physical_and_cgroup_ceiling(safety, monkeypatch, physical_gib, cgroup_limit, expected):
    original_read = Path.read_text

    def read_memory_limit(path, *args, **kwargs):
        if str(path) == "/sys/fs/cgroup/memory.max":
            return cgroup_limit
        if str(path) == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
            raise FileNotFoundError
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_memory_limit)
    monkeypatch.setattr(safety.psutil, "virtual_memory", lambda: argparse.Namespace(total=physical_gib * 1024**3))

    assert safety.default_heap_mb() == expected


def test_cold_heap_rejects_memory_ceiling_too_small_for_positive_cap(safety, monkeypatch):
    original_read = Path.read_text

    def read_memory_limit(path, *args, **kwargs):
        if str(path) == "/sys/fs/cgroup/memory.max":
            return "1"
        if str(path) == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
            raise FileNotFoundError
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_memory_limit)
    monkeypatch.setattr(safety.psutil, "virtual_memory", lambda: argparse.Namespace(total=8 * 1024**3))

    with pytest.raises(safety.RuntimeSafetyError):
        safety.default_heap_mb()


@pytest.mark.parametrize("source", ["environment", "arguments"])
def test_unrecognized_live_heap_preserves_other_guards_during_cold_fallback(safety, managed_installation, monkeypatch, source):
    cfg = managed_installation
    environment = {"DKG_STORE_QUEUE_LIMIT": "123", "DKG_STORE_ACK_QUEUE_LIMIT": "17", "DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "1"}
    argv = ["/fixture/node", cfg.dkg_bin, "daemon-worker"]
    if source == "environment":
        environment["NODE_OPTIONS"] = "--require=/private/loader.js --max-old-space-size-percentage=75"
    else:
        argv[1:1] = ["--max-old-space-size-percentage", "75"]
    process = ManagedProcess(cfg, env=environment, argv=argv)
    install_process(monkeypatch, cfg, process)
    monkeypatch.setattr(safety, "default_heap_mb", lambda: 1536)
    environment = {}

    safety.prepare_restart_environment(environment, cfg.dkg_home, cfg.dkg_bin)

    assert environment["NODE_OPTIONS"] == "--max-old-space-size=1536"
    assert environment["DKG_STORE_QUEUE_LIMIT"] == "123"
    assert environment["DKG_STORE_ACK_QUEUE_LIMIT"] == "17"
    assert environment["DKG_LIST_CONTEXT_GRAPHS_PROJECTION"] == "1"
    assert "/private/loader.js" not in json.dumps(environment)


def test_symlinked_profile_fails_before_stopping_managed_node(safety, managed_installation, monkeypatch, tmp_path):
    cfg = managed_installation
    target = tmp_path / "unrelated-state.json"
    target.write_text("existing-unrelated-state", encoding="utf-8")
    (Path(cfg.dkg_home) / safety.PROFILE_NAME).symlink_to(target)
    process = ManagedProcess(cfg)
    install_process(monkeypatch, cfg, process)
    calls = install_restart_boundary(monkeypatch, process)
    monkeypatch.setattr(safety, "default_heap_mb", lambda: 3072)

    assert safety.read_runtime_safety(cfg.dkg_home, cfg.dkg_bin) is None
    with pytest.raises(safety.RuntimeSafetyError):
        cli_mod._restart_managed_dkg(cfg)

    assert calls == []
    assert target.read_text(encoding="utf-8") == "existing-unrelated-state"
