"""Guard: this repo's AGENTS.md must load into the system prompt whole.

AGENTS.md is auto-injected as a context file (``agent.prompt_builder._load_agents_md``);
past the context-file cap it is silently head/tail truncated. We pin the cap in the
profile configs to keep it whole — this test fails if AGENTS.md outgrows the pin, so
the fix (trim the guide, or raise the pin) stays deliberate, not a silent regression.
"""
from pathlib import Path

from agent import prompt_builder as pb
from _blackbox_loader import load_blackbox

cli_mod = load_blackbox("cli")
PIN = cli_mod._BLACKBOX_CONTEXT_FILE_MAX_CHARS


def _repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "AGENTS.md").exists() and (parent / "pyproject.toml").exists():
            return parent
    raise AssertionError("could not locate repo root (AGENTS.md + pyproject.toml)")


def test_repo_agents_md_loads_whole_at_pinned_cap(monkeypatch):
    # Use the pinned cap, not the machine's live ~/.hermes config, so this guards
    # the repo invariant on any machine / in CI.
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {"context_file_max_chars": PIN},
    )

    repo_root = _repo_root()
    loaded = pb._load_agents_md(repo_root)
    assert loaded, "AGENTS.md should load as a context file from the repo root"

    raw = (repo_root / "AGENTS.md").read_text(encoding="utf-8").strip()
    full_len = len(f"## AGENTS.md\n\n{raw}")  # mirrors _load_agents_md's wrapper
    assert "[...truncated AGENTS.md" not in loaded, (
        f"AGENTS.md is {full_len} chars as loaded but the pinned context-file cap "
        f"is {PIN}; it would be head/tail truncated in the system prompt. Trim the "
        f"guide, or raise the pin (_BLACKBOX_CONTEXT_FILE_MAX_CHARS in "
        f"plugins/blackbox/cli.py + context_file_max_chars in the profile configs)."
    )
