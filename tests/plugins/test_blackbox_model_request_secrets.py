"""KI-381: a wallet secret on its way to the model provider is seen.

Before: ``on_pre_api_request`` ran injection checks only, so a seed phrase the user
pasted, or one a tool read from disk or a web page, went to the model provider with no
finding. The hook can only observe there (blocking happens at the tool call), so it
records a Trader Shield finding naming where the secret was. The requests are built the
way Hermes builds them — Chat Completions ``messages`` AND the Responses API ``input``
list from Hermes' own converter (LES-051). Secrets are made at run time (LES-022).
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent.codex_responses_adapter import _chat_messages_to_responses_input
from plugins.blackbox import audit
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import api_request, hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.crypto_secrets import seed_phrase
from plugins.blackbox.shields.trader import mode as trader_mode
from plugins.blackbox.ruleset import Ruleset
from _blackbox_fakes import dkg_client_fake

WORDS = seed_phrase.WORDLIST_FILE.read_text(encoding="ascii").split()
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def phrase() -> str:
    entropy = os.urandom(16)
    value = int.from_bytes(entropy, "big") << 4 | hashlib.sha256(entropy).digest()[0] >> 4
    return " ".join(WORDS[(value >> (11 * (11 - i))) & 0x7FF] for i in range(12))


def solana_export() -> str:
    """A fresh keypair as Phantom exports it: canonical base58, one '1' per leading zero byte.
    Without the padding a key whose seed starts with a zero byte (1 in 256) decodes to 63 bytes
    and the verifier rightly rejects it (CI flake, run 38927008162)."""
    private = Ed25519PrivateKey.generate()
    data = private.private_bytes_raw() + private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    number, out = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        out = BASE58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def chat(tool_name: str, output: str, ask: str = "Read the file and summarise it.") -> list[dict]:
    """One turn as Hermes stores it: the user asks, the assistant calls a tool, the tool answers."""
    return [
        {"role": "user", "content": ask},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": tool_name, "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": output},
    ]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Trader Shield on, audit writing ON into a throwaway BLACKBOX_HOME (no node)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "DkgClient", dkg_client_fake(lambda **k: (_ for _ in ()).throw(OSError("no node in tests"))))
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=True))
    api_request._seen_api_findings.clear()
    return tmp_path / "bb"


def secret_rows() -> list[tuple[str, str, str]]:
    return [(row["identifier"], row["severity"], row["found_in"]) for row in audit.read_findings(limit=20)
            if str(row["identifier"]).startswith("secret:")]


def logged(home) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in home.rglob("*") if path.is_file())


def assert_not_logged(home, secret: str) -> None:
    words = secret.split()
    text = logged(home)
    for first, second in itertools.pairwise(words):
        assert not re.search(rf"\b{first}[^A-Za-z]{{1,40}}{second}\b", text), (first, second)


def test_a_seed_phrase_the_user_pastes_is_recorded_not_logged(home):
    secret = phrase()
    message = f"here is my wallet seed: {secret} — check the balance"
    result = hooks.on_pre_api_request(session_id="s1", turn_id="t1", model="m", user_message=message,
                                      request_messages=[{"role": "user", "content": message}])
    assert result is None                                                   # observe only
    assert ("secret:seed-phrase", "critical", "in-user-prompt") in secret_rows()
    assert_not_logged(home, secret)


@pytest.mark.parametrize("shape", ["chat-completions", "responses"])
def test_a_seed_phrase_in_a_tool_output_is_seen_in_both_wire_shapes(home, shape):
    secret = phrase()
    request = chat("read_file", f"notes.txt:\n{secret}\n")   # no cue word: a high flag
    if shape == "responses":
        request = _chat_messages_to_responses_input(request)
        assert any(item.get("type") == "function_call_output" for item in request)   # the real Responses shape
    hooks.on_pre_api_request(session_id=f"s-{shape}", turn_id="t1", model="m",
                             user_message="Read the file and summarise it.", request_messages=request)
    assert ("secret:seed-phrase", "high", "in-tool-output") in secret_rows()
    assert_not_logged(home, secret)


def test_a_solana_key_on_a_fetched_page_is_seen(home):
    key = solana_export()
    request = _chat_messages_to_responses_input(chat("web_extract", f"Paste your key to claim: {key}"))
    hooks.on_pre_api_request(session_id="s3", turn_id="t1", model="m", user_message="Open the airdrop page.",
                             request_messages=request)
    assert ("secret:solana-private-key", "high", "in-fetched-page") in secret_rows()
    assert key not in logged(home)


def test_an_earlier_turn_is_not_reported_again(home):
    secret = phrase()
    request = chat("read_file", f"seed: {secret}") + [{"role": "user", "content": "thanks, now list my files"}]
    hooks.on_pre_api_request(session_id="s4", turn_id="t2", model="m", user_message="thanks, now list my files",
                             request_messages=request)
    assert secret_rows() == []


def test_nothing_is_recorded_while_trader_shield_is_off(home, monkeypatch):
    monkeypatch.setattr(trader_mode, "current", lambda: trader_mode.build(enabled=False))
    message = f"my seed: {phrase()}"
    hooks.on_pre_api_request(session_id="s5", turn_id="t1", model="m", user_message=message,
                             request_messages=[{"role": "user", "content": message}])
    assert secret_rows() == []
