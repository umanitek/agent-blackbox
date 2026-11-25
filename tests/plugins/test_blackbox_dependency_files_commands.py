"""Which installs a command runs and in which folder (KI-595).

An install that names no package (``npm ci``, ``uv sync``, ``pip install -r``) is judged by the
files in the folder it runs in, so the folder must be the right one: the tool call's own
working-folder argument, the caller's folder, every ``cd`` before it and the manager's own
folder option. A named install is found too (its lockfile is read after it runs).
"""

from __future__ import annotations

import pytest

from _blackbox_loader import load_blackbox

commands = load_blackbox("detection.manifests.commands")
checks = load_blackbox("detection.manifests.checks")
action_context = load_blackbox("kernel.action_context")
detection = load_blackbox("detection")


def _one(command: str, folder: str = "/home/me"):
    [site] = commands.install_sites(command, folder)
    return site


@pytest.mark.parametrize("command, manager", [
    ("npm install", "npm"), ("npm i", "npm"), ("npm ci", "npm"), ("pnpm install", "pnpm"), ("pnpm i", "pnpm"),
    ("yarn", "yarn"), ("yarn install", "yarn"), ("bun install", "bun"), ("uv sync", "uv"), ("poetry install", "poetry"),
    ("pipenv install", "pipenv"), ("cargo build", "cargo"), ("cargo fetch", "cargo"), ("bundle install", "bundle"),
    ("bundle", "bundle"),
])
def test_installs_that_name_no_package_install_from_files(command, manager):
    site = _one(command)
    assert (site.manager, site.folder, site.from_files) == (manager, "/home/me", True)


def test_npm_ci_reads_the_lockfile_only():
    assert _one("npm ci").strict is True and _one("npm install").strict is False


@pytest.mark.parametrize("command, files", [
    ("pip install -r requirements.txt", ("/home/me/requirements.txt",)),
    ("pip3 install -r a.txt --requirement=b.txt -c c.txt", ("/home/me/a.txt", "/home/me/b.txt", "/home/me/c.txt")),
    ("python3 -m pip install -r /etc/x/req.txt", ("/etc/x/req.txt",)),
    ("uv pip install -r req.txt", ("/home/me/req.txt",)),
    ("uv pip sync req.lock.txt", ("/home/me/req.lock.txt",)),
])
def test_requirements_files_are_named_absolutely(command, files):
    assert _one(command).files == files


@pytest.mark.parametrize("command", ["pip install .", "pip install -e .", "pip install ./lib"])
def test_a_project_install_reads_its_pyproject(command):
    assert _one(command).project is True


@pytest.mark.parametrize("command, folder", [
    ("cd app && npm ci", "/home/me/app"),
    ("cd /srv/web; yarn", "/srv/web"),
    ("cd app && cd ../other && npm install", "/home/me/other"),
    ("npm --prefix web install", "/home/me/web"),
    ("pnpm -C web install", "/home/me/web"),
    ("yarn --cwd web install", "/home/me/web"),
    ("uv sync --project sub", "/home/me/sub"),
    ("poetry -C sub install", "/home/me/sub"),
    ("bundle install --gemfile x/Gemfile", "/home/me/x"),
    ("cargo build --manifest-path crate/Cargo.toml", "/home/me/crate"),
    ("cargo install --path tool", "/home/me/tool"),
    ("FOO=1 sudo -E npm ci", "/home/me"),
])
def test_the_folder_follows_cd_and_the_managers_own_option(command, folder):
    assert _one(command).folder == folder


def test_a_named_install_is_found_for_the_after_install_check():
    site = _one("npm install express")
    assert site.named == ("express",) and site.from_files is False


@pytest.mark.parametrize("command", ["yarn build", "npm run test", "bun run dev", "echo npm ci", "cargo test",
                                     "bundle exec rake", "ls", 'echo "unclosed'])
def test_other_commands_are_not_installs(command):
    assert commands.install_sites(command, "/home/me") == []


def test_an_unclosed_quote_does_not_raise():
    assert commands.install_sites('npm ci "oops', "/home/me")[0].manager == "npm"


def test_the_call_folder_argument_then_the_callers_folder():
    assert checks.call_folder({"workdir": "/srv/app"}) == "/srv/app"
    with action_context.working_in("/home/me"):
        assert checks.call_folder({"cwd": "sub"}) == "/home/me/sub"
        assert checks.call_folder({"command": "npm ci"}) == "/home/me"
    assert checks.call_folder({"command": "npm ci"}) == ""


def test_an_unknown_folder_is_a_note_not_silence():
    check = checks.check_install_files("terminal", {"command": "npm ci"}, None)
    assert check.notes == ["dependencies not checked: the folder the install runs in is not known"]


def test_named_runners_stay_covered_by_the_named_install_parser():
    """npx / pnpm dlx / bunx fetch a package and run it: checked by name, as before."""
    for command, name in [("npx cowsay hi", "cowsay"), ("pnpm dlx create-vite", "create-vite"),
                          ("bunx evil@1.0.0", "evil")]:
        assert [dep["name"] for dep in detection.parse_dependency_installs(command)] == [name]
