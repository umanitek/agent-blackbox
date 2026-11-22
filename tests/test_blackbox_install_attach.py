"""The installers protect their own Hermes home, and every other agent — now and later — on ONE yes.

Hermes catalog review (22cb7e62, KI-429 / LES-067): every Hermes profile is its own trust and
credential boundary, so Blackbox must not join them by a silent default. 2026-11-19 (Amos:
"every new profile and every new instance, automatically"): the installer asks ONCE whether to
protect every agent on the machine now and every one added later. Enter or no answer is yes (the
question is on screen); "n" changes nothing more; no terminal asks nothing and protects only the
installer's own home. BLACKBOX_AUTO_ATTACH=1/0 answers for scripts and for Hermes Desktop's setup switch,
an earlier yes is kept on a re-run, and the one writer of the setting is
`blackbox attach --all --auto` (tests/plugins/test_blackbox_attach_auto.py). These tests run the
installer's real functions with a fake `hermes` that records what it is asked.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO / "scripts" / "blackbox-install.ps1"


def _body(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _run(tmp_path: Path, *, answer: str = "no-terminal", saved: str = "false", env: dict[str, str] | None = None) -> list[str]:
    """Run attach_all_agents; *answer* is what the terminal question returns: "yes", "no" or
    "no-terminal" (the real ask returns 1 without a terminal, like "no"); *saved* the saved setting."""
    calls = tmp_path / "calls"
    calls.write_text("", encoding="utf-8")
    hermes = tmp_path / "hermes"
    hermes.write_text(f'#!/bin/sh\necho "$*" >> {shlex.quote(str(calls))}\nexit 0\n', encoding="utf-8")
    hermes.chmod(0o755)
    asked = tmp_path / "asked"
    script = f"""
HERMES_BIN={shlex.quote(str(hermes))}
HERMES_HOME={shlex.quote(str(tmp_path / "hermes-home"))}
heading() {{ :; }}; step() {{ :; }}; ok() {{ :; }}; warn() {{ :; }}
saved_auto_attach() {{ echo {shlex.quote(saved)}; }}
ask_protect_every_agent() {{ echo asked > {shlex.quote(str(asked))}; [ {shlex.quote(answer)} = yes ]; }}
auto_attach_answer() {{
{_body("auto_attach_answer")}
}}
attach_all_agents() {{
{_body("attach_all_agents")}
}}
attach_all_agents
"""
    clean = {k: v for k, v in os.environ.items() if k not in ("BLACKBOX_AUTO_ATTACH", "BLACKBOX_ATTACH_ALL")}
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, env={**clean, **(env or {})})
    assert result.returncode == 0, result.stderr
    return calls.read_text(encoding="utf-8").splitlines() + (["<asked>"] if asked.exists() else [])


def _own(tmp_path: Path) -> str:
    return f"blackbox attach {tmp_path / 'hermes-home'}"


def test_a_yes_protects_every_agent_now_and_later(tmp_path):
    assert _run(tmp_path, answer="yes") == [_own(tmp_path), "blackbox attach --all --auto", "<asked>"]


def test_a_no_changes_nothing_more_and_is_asked_once(tmp_path):
    assert _run(tmp_path, answer="no") == [_own(tmp_path), "<asked>"]


def test_with_no_terminal_only_the_installers_own_home_is_protected(tmp_path):
    calls = _run(tmp_path, answer="no-terminal")
    assert calls[:1] == [_own(tmp_path)] and not any("--all" in call or "--auto" in call for call in calls)


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_blackbox_auto_attach_answers_yes_without_asking(tmp_path, value):
    assert _run(tmp_path, env={"BLACKBOX_AUTO_ATTACH": value}) == [_own(tmp_path), "blackbox attach --all --auto"]


@pytest.mark.parametrize("value", ["0", "false", "no"])
def test_blackbox_auto_attach_answers_no_without_asking(tmp_path, value):
    assert _run(tmp_path, answer="yes", env={"BLACKBOX_AUTO_ATTACH": value}) == [_own(tmp_path)]


def test_an_earlier_yes_is_kept_on_a_rerun_without_asking(tmp_path):
    assert _run(tmp_path, answer="no", saved="true") == [_own(tmp_path), "blackbox attach --all --auto"]


@pytest.mark.parametrize("value", ["1", "true", "YES"])
def test_attach_all_still_protects_every_agent_now_after_a_no(tmp_path, value):
    calls = _run(tmp_path, answer="no", env={"BLACKBOX_ATTACH_ALL": value})
    assert calls == [_own(tmp_path), "blackbox attach --all", "<asked>"]


def test_the_question_says_now_and_later_and_defaults_to_yes():
    body = _body("ask_protect_every_agent")
    assert "[Y/n]" in body and "now and later" in body and "/dev/tty" in body
    assert re.search(r"n\|N\|no\|NO\|No\) return 1", body) and "*) return 0" in body   # only an explicit no declines


def test_the_windows_installer_asks_the_same_once_and_uses_the_same_writer():
    text = INSTALL_PS1.read_text(encoding="utf-8-sig")
    body = text[text.index("function Get-AutoAttachAnswer"):text.index("# ── Guided next steps")]
    calls = [line.strip() for line in body.splitlines() if line.strip().startswith("& $HermesBin blackbox attach")]
    assert calls == ["& $HermesBin blackbox attach $HermesHome", "& $HermesBin blackbox attach --all --auto",
                     "& $HermesBin blackbox attach --all"]
    assert "[Y/n]" in body and "BLACKBOX_AUTO_ATTACH" in body and "IsInputRedirected" in body
    assert "-notmatch '^(n|no)$'" in body   # only an explicit no declines


def test_both_installer_copies_are_identical():
    setup = REPO / "plugins" / "blackbox" / "setup"
    assert (setup / "blackbox-install.sh").read_bytes() == INSTALL_SH.read_bytes()
    assert (setup / "blackbox-install.ps1").read_bytes() == INSTALL_PS1.read_bytes()
