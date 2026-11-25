"""The shipped Tomcat image must receive and retain Blackbox's JVM sizing."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("helper", ["scripts", "plugins/blackbox/setup"])
def test_effective_tomcat_heap_is_reused_without_replacing_store(tmp_path, helper):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    module = tmp_path / "node_modules/@origintrail-official/dkg/dist/daemon/blazegraph-docker.js"
    module.parent.mkdir(parents=True)
    (module.parents[2] / "package.json").write_text('{"type":"module"}')
    module.write_text(
        "export async function provisionBlazegraphDocker(options) {\n"
        " const existing = await options.docker.run(['inspect', 'dkg-blazegraph-test']);\n"
        " if (existing.exitCode !== 0) throw Error('configured store was replaced');\n"
        " return {url: 'http://127.0.0.1:10001/sparql', reused: true};\n"
        "}\n"
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.log"
    inspect = json.dumps([{"Config": {"Env": ["JAVA_OPTS=-Xmx1g", "TOMCAT_JAVA_OPTS=-Xms512m -Xmx4g"]}}])
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
        "case \"$1\" in\n"
        f" inspect) printf '%s\\n' {shlex.quote(inspect)} ;;\n"
        " info) echo 4 ;;\n"
        " update) exit 0 ;;\n"
        " *) exit 2 ;;\n"
        "esac\n"
    )
    docker.chmod(0o755)
    source = Path(__file__).resolve().parents[3] / helper / "blackbox-blazegraph.mjs"
    result = subprocess.run(
        [node, str(source), str(tmp_path), "blackbox-test", "10001"],
        env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")},
        capture_output=True, text=True, check=True,
    )
    assert json.loads(result.stdout)["reused"] is True
    assert calls.read_text().splitlines() == [
        "inspect dkg-blazegraph-test", "info --format {{.NCPU}}",
        "update --cpus 4 dkg-blazegraph-test",
    ]


def _provision(tmp_path, helper, env_heap, inspect_opts=None):
    """Runs the provisioner with a fake DKG module that inspects the store, then makes a new one
    when the inspect said none is there; answers the docker calls."""
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    module = tmp_path / "node_modules/@origintrail-official/dkg/dist/daemon/blazegraph-docker.js"
    module.parent.mkdir(parents=True)
    (module.parents[2] / "package.json").write_text('{"type":"module"}')
    module.write_text(
        "export async function provisionBlazegraphDocker(options) {\n"
        " const existing = await options.docker.run(['inspect', 'dkg-blazegraph-test']);\n"
        " if (existing.exitCode !== 0) await options.docker.run(['run', '-d', '--name', 'dkg-blazegraph-test', 'img']);\n"
        " return {url: 'http://127.0.0.1:10001/sparql', reused: existing.exitCode === 0};\n"
        "}\n"
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls.log"
    inspect = json.dumps([{"Config": {"Env": [f"TOMCAT_JAVA_OPTS={inspect_opts}"]}}]) if inspect_opts else ""
    (fake_bin / "docker").write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
        "case \"$1\" in\n"
        + (f" inspect) printf '%s\\n' {shlex.quote(inspect)} ;;\n" if inspect else " inspect) exit 1 ;;\n")
        + " info) echo 4 ;;\n update|stop|rename|run) exit 0 ;;\n *) exit 2 ;;\nesac\n"
    )
    (fake_bin / "docker").chmod(0o755)
    source = Path(__file__).resolve().parents[3] / helper / "blackbox-blazegraph.mjs"
    env = {**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")}
    env.pop("BLACKBOX_BLAZEGRAPH_HEAP", None)
    if env_heap is not None:
        env["BLACKBOX_BLAZEGRAPH_HEAP"] = env_heap
    result = subprocess.run([node, str(source), str(tmp_path), "blackbox-test", "10001"], env=env,
                            capture_output=True, text=True, check=False)
    return result, calls.read_text().splitlines()


@pytest.mark.parametrize("helper", ["scripts", "plugins/blackbox/setup"])
@pytest.mark.parametrize("env_heap, expected", [(None, "-Xmx4g"), ("2g", "-Xmx2g"), ("3072M", "-Xmx3072m"), ("512m", "-Xmx4g"), ("lots", "-Xmx4g")])
def test_the_heap_cap_is_a_setting_with_a_floor(tmp_path, helper, env_heap, expected):
    """KI-675 (Linux round L2): the store's JVM was 2.5 GB of Blackbox's ~4 GB. Its cap is
    BLACKBOX_BLAZEGRAPH_HEAP (default 4g); below 1g or not a size, the default is used and said."""
    result, calls = _provision(tmp_path, helper, env_heap)
    run = next(call for call in calls if call.startswith("run "))
    assert f"TOMCAT_JAVA_OPTS=-Xms512m {expected}" in run, (run, result.stderr)
    assert ("is not a heap of at least 1g" in result.stderr) == (env_heap in ("512m", "lots"))


@pytest.mark.parametrize("helper", ["scripts", "plugins/blackbox/setup"])
def test_a_store_already_at_the_chosen_cap_is_reused(tmp_path, helper):
    result, calls = _provision(tmp_path, helper, "2g", inspect_opts="-Xms512m -Xmx2g")
    assert json.loads(result.stdout)["reused"] is True, result.stderr
    assert not any(call.startswith(("stop ", "rename ", "run ")) for call in calls), calls
