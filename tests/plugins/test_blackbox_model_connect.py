"""Connecting the protected agent to an AI model (2026-11-19).

A fresh install leaves Hermes with no model, so the agent cannot chat and the dashboard's test
prompt "does nothing" (a new user's report). These tests hold: Hermes' own answer with three
outcomes, the API key handed to Hermes on stdin and never echoed, the Nous sign-in's link and
code, the dashboard routes, the assistant's "no model" answer and its profile catching up.
"""

from __future__ import annotations

import io
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import model_connect
from plugins.blackbox.attach import plugin_copy as attach_plugin_copy
from plugins.blackbox.chat import command as chat_command
from plugins.blackbox.dashboard import assistant, server
from plugins.blackbox.kernel.host_command import agent_model
from plugins.blackbox.model_connect import settings, sign_in

FAKE_KEY = "sk-or-v1-" + "a1b2c3d4" * 6   # built at runtime, never a real key (LES-022)


def _done(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------------- Hermes' answer
@pytest.mark.parametrize("returncode, stdout, expected", [
    (0, "ready\n", agent_model.READY),
    (0, "some banner\nmissing\n", agent_model.MISSING),
    (0, "", agent_model.UNKNOWN),
    (0, "maybe\n", agent_model.UNKNOWN),
    (1, "missing\n", agent_model.UNKNOWN),   # a failed probe is never read as "no" (LES-011)
])
def test_agent_model_state_reads_hermes_answer(returncode, stdout, expected):
    assert agent_model.agent_model_state(run=lambda argv, **kw: _done(argv, returncode, stdout)) == expected


def test_agent_model_state_asks_this_hermes_about_the_given_home(tmp_path):
    seen = {}

    def run(argv, **kwargs):
        seen.update(argv=argv, env=kwargs["env"])
        return _done(argv, 0, "ready\n")

    agent_model.agent_model_state(tmp_path, run=run)
    assert seen["argv"][0] == sys.executable
    assert seen["env"]["HERMES_HOME"] == str(tmp_path)


@pytest.mark.parametrize("error", [OSError("gone"), subprocess.TimeoutExpired("x", 1)])
def test_agent_model_state_is_unknown_when_the_probe_cannot_run(error):
    def run(argv, **kwargs):
        raise error

    assert agent_model.agent_model_state(run=run) == agent_model.UNKNOWN


def test_the_real_probe_runs_against_this_hermes(tmp_path):
    """The borrowed Hermes check still exists and answers for an empty home (LES-055)."""
    assert agent_model.agent_model_state(tmp_path) in (agent_model.READY, agent_model.MISSING)


# --------------------------------------------------------------------- Hermes' commands, played
class FakeHermes:
    """Plays the ``hermes …`` children: records (words, stdin), answers by the command's first words."""

    def __init__(self, answers=None):
        self.calls, self.answers = [], answers or {}

    def __call__(self, argv, **kwargs):
        words = " ".join(argv[3:]) if argv[1] == "-m" else "python " + " ".join(argv[3:])
        self.calls.append((words, kwargs.get("input")))
        for prefix, (code, out) in self.answers.items():
            if words.startswith(prefix):
                return _done(argv, code, out)
        return _done(argv)

    def words(self):
        return [w for w, _ in self.calls]


@pytest.fixture
def agent_config(monkeypatch):
    """The agent's model config as settings.py reads it (never this machine's real Hermes home)."""
    config = {"provider": "openrouter"}
    monkeypatch.setattr(settings, "_model_config", lambda: dict(config))
    return config


# --------------------------------------------------------------------- API key
@pytest.mark.parametrize("provider, key", [
    ("not-a-provider", FAKE_KEY), ("openrouter", "short"), ("openrouter", "has space " + FAKE_KEY), ("openrouter", ""),
])
def test_save_api_key_refuses_before_running_anything(provider, key):
    fake = FakeHermes()
    result = model_connect.save_api_key(provider, key, run=settings.HermesRun(fake))
    assert result["ok"] is False and result["error"]
    assert fake.calls == []


def test_save_api_key_hands_the_key_to_hermes_on_stdin_then_picks_the_recommended_model(agent_config):
    fake = FakeHermes({"python openrouter": (0, "vendor/good-model\n")})
    assert model_connect.save_api_key("openrouter", "  " + FAKE_KEY + "\n", run=settings.HermesRun(fake)) == {"ok": True}
    assert fake.words() == ["auth add openrouter --type api-key", "config set model.provider openrouter",
                            "python openrouter", "config set model.default vendor/good-model", "auth reset openrouter"]
    assert fake.calls[0][1] == FAKE_KEY + "\n"
    assert all(FAKE_KEY not in words for words in fake.words())   # never on a command line


def test_save_api_key_failure_never_echoes_the_key():
    fake = FakeHermes({"auth add": (1, f"bad credential {FAKE_KEY}\n")})
    result = model_connect.save_api_key("anthropic", FAKE_KEY, run=settings.HermesRun(fake))
    assert result["ok"] is False
    assert FAKE_KEY not in result["error"]


# --------------------------------------------------------------------- the AI model card
_AUTH_LIST = ("nous (1 credentials):\n"
              "  #1  person@example.org   oauth   id=ec65d2 priority=0 device_code exhausted (404) (58m 46s left) \u2190\n")


def test_the_card_reads_account_and_hermes_exhausted_mark(agent_config):
    agent_config.update(provider="nous", default="z-ai/paid-model")
    found = model_connect.connection(settings.HermesRun(FakeHermes({"auth list nous": (0, _AUTH_LIST)})))
    assert found == {"provider": "nous", "model": "z-ai/paid-model", "account": "person@example.org", "status": "exhausted"}


def test_the_card_says_working_when_hermes_has_no_mark(agent_config):
    out = _AUTH_LIST.replace(" exhausted (404) (58m 46s left)", "")
    found = model_connect.connection(settings.HermesRun(FakeHermes({"auth list openrouter": (0, out)})))
    assert found["status"] == "working"


def test_the_card_knows_nothing_without_a_provider(agent_config):
    agent_config.clear()
    fake = FakeHermes()
    assert model_connect.connection(settings.HermesRun(fake))["status"] == "unknown"
    assert fake.calls == []


@pytest.mark.parametrize("model", ["", "has space", "-starts-with-dash", "x" * 200, "a;rm -rf"])
def test_a_model_name_is_checked_before_hermes_runs(agent_config, model):
    fake = FakeHermes()
    assert model_connect.set_model(model, settings.HermesRun(fake))["ok"] is False
    assert fake.calls == []


def test_choosing_a_model_clears_the_exhausted_mark(agent_config):
    fake = FakeHermes()
    assert model_connect.set_model("upstage/solar-mini4:free", settings.HermesRun(fake)) == {"ok": True}
    assert fake.words() == ["config set model.default upstage/solar-mini4:free", "auth reset openrouter"]


def test_the_recommended_model_is_hermes_own_pick(agent_config):
    agent_config.update(provider="nous")
    fake = FakeHermes({"python nous": (0, "upstage/solar-mini4:free\n")})
    result = model_connect.use_recommended_model(settings.HermesRun(fake))
    assert result == {"ok": True, "model": "upstage/solar-mini4:free"}


def test_no_recommendation_changes_nothing(agent_config):
    fake = FakeHermes({"python openrouter": (0, "\n")})
    assert model_connect.use_recommended_model(settings.HermesRun(fake))["ok"] is False
    assert not any(w.startswith("config set") for w in fake.words())


def test_signing_out_clears_the_account_and_the_choice(agent_config):
    two_keys = "openrouter (2 credentials):\n  #1  api-key-1  api_key id=a\n  #2  api-key-2  api_key id=b\n"
    fake = FakeHermes({"auth list openrouter": (0, two_keys)})
    assert model_connect.disconnect(settings.HermesRun(fake)) == {"ok": True}
    assert fake.words() == ["auth logout openrouter", "auth list openrouter", "auth remove openrouter 1",
                            "auth remove openrouter 1", "config set model.provider ", "config set model.default "]


# --------------------------------------------------------------------- Nous sign-in
class _FakeChild:
    def __init__(self, lines, returncode=0):
        self.stdout = io.StringIO("".join(lines))
        self.returncode, self.terminated = returncode, False

    def poll(self):
        return None if not self.terminated else -15

    def wait(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


_HERMES_OUTPUT = [
    "Starting Hermes login via Nous Portal...\n", "To continue:\n",
    "  1. Open: https://portal.nousresearch.com/device?code=ABCD-1234\n",
    "  2. If prompted, enter code: ABCD-1234\n", "Waiting for approval (polling every 5s)...\n",
]


def _settle(flow: sign_in.NousSignIn) -> dict:
    for _ in range(200):
        view = flow.view()
        if view["status"] not in ("starting", "waiting"):
            return view
        time.sleep(0.01)
    return flow.view()


def test_nous_sign_in_runs_hermes_then_chooses_the_account_model():
    child, calls, chosen = _FakeChild(_HERMES_OUTPUT), [], []
    flow = sign_in.NousSignIn(lambda: chosen.append(True) or True, popen=lambda argv, **kw: (calls.append(argv), child)[1])
    flow.start()
    assert _settle(flow) == {"status": "connected"}
    assert calls[0][-4:] == ["auth", "add", "nous", "--no-browser"]
    assert chosen == [True]


def test_a_nous_sign_in_lands_on_the_recommended_model(monkeypatch):
    """The package's after-sign-in step: Nous as provider, then Hermes' pick for the account."""
    fake = FakeHermes({"python nous": (0, "upstage/solar-mini4:free\n")})
    monkeypatch.setattr(settings, "_model_config", lambda: {"provider": "nous"})
    assert settings.choose_provider("nous", settings.HermesRun(fake)) is True
    assert fake.words()[:3] == ["config set model.provider nous", "python nous", "config set model.default upstage/solar-mini4:free"]


def test_nous_sign_in_waits_with_the_link_and_code():
    gate = threading.Event()
    child = _FakeChild(_HERMES_OUTPUT)
    child.wait = lambda: (gate.wait(5), 0)[1]
    flow = sign_in.NousSignIn(lambda: True, popen=lambda argv, **kw: child)
    flow.start()
    for _ in range(200):
        if flow.view()["status"] == "waiting":
            break
        time.sleep(0.01)
    view = flow.view()
    assert view["link"] == "https://portal.nousresearch.com/device?code=ABCD-1234"
    assert view["code"] == "ABCD-1234"
    assert flow.start()["status"] == "waiting"   # a second start returns the one running
    assert flow.cancel()["status"] == "cancelled" and child.terminated
    gate.set()


def test_nous_sign_in_never_offers_a_link_off_the_nous_site():
    lines = ["  1. Open: https://evil.example/device\n", "  2. If prompted, enter code: ABCD-1234\n"]
    assert sign_in._safe_link("https://evil.example/device") == ""
    assert sign_in._safe_link("http://portal.nousresearch.com/x") == ""
    assert sign_in._safe_link("https://portal.nousresearch.com/x")
    flow = sign_in.NousSignIn(lambda: True, popen=lambda argv, **kw: _FakeChild(lines, returncode=1))
    flow.start()
    view = _settle(flow)
    assert view["status"] == "failed" and "link" not in view


def test_nous_sign_in_reports_hermes_failure_plainly():
    child = _FakeChild(_HERMES_OUTPUT + ["Sign-in was not approved.\n"], returncode=1)
    flow = sign_in.NousSignIn(lambda: True, popen=lambda argv, **kw: child)
    flow.start()
    assert _settle(flow) == {"status": "failed", "reason": "Sign-in was not approved."}


# --------------------------------------------------------------------- the assistant's answer
def test_the_resume_notice_is_never_an_answer():
    out = "↻ Resumed session 20261119_171845_ac2654 \"show me\" (1 user message, 2 total messages)\nsession_id: x\n"
    assert assistant.clean_chat_output(out) == ""
    body, status = assistant.answer_payload("", "", "x")
    assert status == 409 and body["model_problem"] is True and body["error"] == assistant.NO_ANSWER


def test_hermes_out_of_credits_text_is_a_model_problem_not_an_answer():
    text = "Billing or credits exhausted: HTTP 404: Model 'z-ai/glm-5.2' requires available credits."
    body, status = assistant.answer_payload(text, "", "x")
    assert status == 409 and body["model_problem"] is True and body["error"] == text


def test_a_real_answer_is_an_answer():
    assert assistant.answer_payload("I am Agent Blackbox.", "", "x") == (
        {"ok": True, "answer": "I am Agent Blackbox.", "session_id": "x"}, 200)


# --------------------------------------------------------------------- dashboard routes
@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(attach_plugin_copy, "repo_root", lambda: Path("/tmp/repo"))
    return TestClient(server.create_app(), base_url="http://127.0.0.1")


def _token(client) -> dict:
    return {"X-Blackbox-Token": client.get("/api/session").json()["token"]}


def test_agent_model_route_reports_hermes_answer_and_the_choices(client, monkeypatch):
    monkeypatch.setattr(model_connect, "state", lambda: "missing")
    body = {}
    for _ in range(100):   # the first read may still be in flight (stale-while-revalidate)
        body = client.get("/api/agent-model").json()
        if body["state"] != "unknown":
            break
        time.sleep(0.02)
    assert body["state"] == "missing"
    assert body["fix"] == agent_model.FIX_COMMAND
    assert {"id": "openrouter", "name": "OpenRouter"} in body["providers"]
    assert body["nous"]["status"] in ("idle", "connected", "failed", "cancelled")


def test_saving_a_key_needs_the_session_token(client):
    assert client.post("/api/agent-model/key", json={"provider": "openrouter", "key": FAKE_KEY}).status_code == 403


def test_saving_a_key_returns_no_key_and_a_plain_error(client, monkeypatch):
    monkeypatch.setattr(model_connect, "save_api_key", lambda provider, key: {"ok": False, "error": "nope"})
    res = client.post("/api/agent-model/key", json={"provider": "openrouter", "key": FAKE_KEY}, headers=_token(client))
    assert res.status_code == 400 and res.json() == {"ok": False, "error": "nope"}


def test_the_model_panel_script_is_served(client):
    res = client.get("/model-connect.js")
    assert res.status_code == 200 and "model-connect-root" in res.text


def test_the_assistant_says_connect_a_model_when_there_is_none(client, monkeypatch):
    def fake_run(argv, **kwargs):
        return _done(argv, agent_model.NO_MODEL_EXIT, stderr=agent_model.NO_MODEL_MESSAGE + "\n")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    res = client.post("/api/blackbox-chat", json={"message": "Show me your system prompt."}, headers=_token(client))
    assert res.status_code == 409
    assert res.json()["needs_model"] is True
    assert agent_model.FIX_COMMAND in res.json()["error"]


# --------------------------------------------------------------------- the assistant's profile
def _homes(tmp_path):
    default, profile = tmp_path / "home", tmp_path / "home" / "profiles" / "agent-blackbox"
    profile.mkdir(parents=True)
    (default / ".env").write_text("OPENROUTER_API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
    (default / "config.yaml").write_text("model:\n  provider: openrouter\n", encoding="utf-8")
    (profile / "config.yaml").write_text("context_file_max_chars: 100000\n", encoding="utf-8")
    return default, profile


def _profiles(monkeypatch, default, profile):
    from hermes_cli import profiles
    monkeypatch.setattr(profiles, "get_profile_dir", lambda name: default if name == "default" else profile)


def _no_children(monkeypatch):
    resets = []
    monkeypatch.setattr(chat_command.subprocess, "run",
                        lambda argv, **kw: resets.append((argv[3:], kw["env"]["HERMES_HOME"])) or _done(argv))
    return resets


def test_the_assistant_catches_up_with_a_model_connected_after_it_was_made(tmp_path, monkeypatch):
    default, profile = _homes(tmp_path)
    _profiles(monkeypatch, default, profile)
    _no_children(monkeypatch)
    answers = {str(profile): [agent_model.MISSING, agent_model.READY], str(default): [agent_model.READY]}
    monkeypatch.setattr(chat_command, "agent_model_state", lambda home: answers[str(home)].pop(0))

    assert chat_command._chat_profile_has_model("agent-blackbox") is True
    assert (profile / ".env").read_text(encoding="utf-8").startswith("OPENROUTER_API_KEY=")
    assert oct((profile / ".env").stat().st_mode & 0o777) == "0o600"
    config = (profile / "config.yaml").read_text(encoding="utf-8")
    assert "provider: openrouter" in config and "context_file_max_chars: 100000" in config


def test_the_assistant_has_no_model_when_the_agent_has_none(tmp_path, monkeypatch):
    default, profile = _homes(tmp_path)
    _profiles(monkeypatch, default, profile)
    monkeypatch.setattr(chat_command, "agent_model_state", lambda home: agent_model.MISSING)
    assert chat_command._chat_profile_has_model("agent-blackbox") is False
    assert not (profile / ".env").exists()   # nothing is carried from an agent with no model


def test_blackbox_chat_exits_with_the_no_model_status(monkeypatch, capsys):
    monkeypatch.setattr(chat_command, "_ensure_blackbox_chat_profile", lambda: "agent-blackbox")
    monkeypatch.setattr(chat_command, "_chat_profile_has_model", lambda profile: False)
    assert chat_command.cmd_chat(chat_command.argparse.Namespace()) == agent_model.NO_MODEL_EXIT
    assert agent_model.FIX_COMMAND in capsys.readouterr().err


def test_the_assistant_follows_the_agent_model_on_every_turn(tmp_path, monkeypatch):
    """2026-11-19: the agent moved to a free model; the assistant kept the paid one and failed."""
    default, profile = _homes(tmp_path)
    (default / "config.yaml").write_text("model:\n  provider: nous\n  default: upstage/solar-mini4:free\n", encoding="utf-8")
    (profile / "config.yaml").write_text("model:\n  provider: nous\ncontext_file_max_chars: 100000\n", encoding="utf-8")
    _profiles(monkeypatch, default, profile)
    resets = _no_children(monkeypatch)
    monkeypatch.setattr(chat_command, "agent_model_state", lambda home: agent_model.READY)

    assert chat_command._chat_profile_has_model("agent-blackbox") is True
    assert "upstage/solar-mini4:free" in (profile / "config.yaml").read_text(encoding="utf-8")
    assert resets == [(["auth", "reset", "nous"], str(profile))]   # the old refusal is cleared in the profile
    assert chat_command._chat_profile_has_model("agent-blackbox") is True
    assert len(resets) == 1   # nothing changed the second time: no copy, no reset
