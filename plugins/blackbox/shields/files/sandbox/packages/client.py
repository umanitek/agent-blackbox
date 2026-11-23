"""The ``brew`` a sandboxed agent runs: it asks Blackbox to install, and prints what Homebrew says.

Copied into ``<agent-bin>/sandbox-tools`` as ``brew-client.py`` and started by the ``brew`` shim
there (first on the SANDBOXED PATH only). Standard library only; it runs inside the sandbox.

``brew install|upgrade|reinstall|uninstall …`` is sent to Blackbox's dashboard (loopback, with
its session token): ``POST /api/shields/file-shield/api/brew`` with the argv alone. Blackbox
validates it, decides the sandbox permission and answers with a job at once; the threat-graph
check of each package and the Homebrew run happen in that job, outside the sandbox. The client
prints the output as it arrives (``GET …/brew-job``) and exits with brew's exit code, or prints
the job's refusal (a package a threat rule lists) and exits 1. When the person is asked first
(the ``homebrew`` sandbox permission on "ask"), the dashboard answers 423 while the question is
open; the client waits, sending the same request again, until it runs or is refused. (428, the
approval gate holding a request, is waited on alike.)

BUSY, NOT GONE (KI-632): during Blackbox's first threat-graph sync the dashboard can take seconds
to answer. A read (the session token, the job's output) that gets no answer within
:data:`ANSWER_SECONDS` is asked again, for up to :data:`BUSY_SECONDS` in all. The POST is sent
once per ask (it starts an install: asking twice could install twice) and waits up to
:data:`BUSY_SECONDS`. FAIL CLOSED: when Blackbox does not answer, nothing is run for the agent, and
the message says why (not running, or busy for N s) and what to do.

The ``open`` stand-in runs it with ``--action open-link`` / ``--action open-app``: one request to
that endpoint, waited on the same way, and Blackbox's answer printed.

A package manager's shim (``npm``, ``pipx``, ``pip``, ``cargo``, ``gem``, ``uv``) runs it with
``--manager <id>`` for a global install: ``POST …/install`` and ``GET …/install-job`` instead.

Usage (what the shim runs)::

    python3 brew-client.py http://127.0.0.1:9700 install tree
    python3 brew-client.py http://127.0.0.1:9700 --manager npm install -g typescript
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

POLL_SECONDS = 1.0
#: How long the client waits for the person's approval ("ask me each time").
APPROVAL_SECONDS = 10 * 60
#: How long one read waits for an answer before it is asked again. The dashboard answers these in
#: milliseconds; a read that takes longer means it is busy, not gone.
ANSWER_SECONDS = 10
#: How long the client keeps asking a busy Blackbox (no answer at all) before it gives up.
BUSY_SECONDS = 120
HELD = 428
#: The person has not answered the permission request yet (``packages.WAITING``).
WAITING = 423
#: Where the client was when Blackbox stopped answering (the message differs: KI-632).
BEFORE, ASKED, RUNNING = "before", "asked", "running"


class Unanswered(Exception):
    """Blackbox gave no answer: *busy* (it is up but did not answer in *seconds*) or not reachable."""

    def __init__(self, busy: bool, seconds: float = 0.0, detail: str = "") -> None:
        super().__init__(detail)
        self.busy, self.seconds, self.detail = busy, seconds, detail


def _gave_up(program: str, argv: list, error: Unanswered, phase: str) -> str:
    """The sentence the agent reads when Blackbox did not answer: why, and what to do."""
    command = f"{program} {' '.join(argv)}"
    if phase == RUNNING:
        why = f"for {error.seconds:.0f} s" if error.busy else f"({error.detail})"
        return (f"Blackbox stopped answering {why} while it ran `{command}`; it may still finish. "
                "Check in a minute before you run it in your own terminal.")
    if phase == ASKED and error.busy:
        return (f"Blackbox was asked to run `{command}` but did not answer within {error.seconds:.0f} s (it is busy, "
                "perhaps syncing its threat graph); it may still run it. Check in a minute before you run it in your own terminal.")
    if error.busy:
        return (f"Blackbox couldn't install this: it was busy and did not answer within {error.seconds:.0f} s (perhaps "
                f"syncing its threat graph). Nothing was installed; try again in a minute, or run `{command}` in your own terminal.")
    return (f"Blackbox couldn't install this: Blackbox is not answering ({error.detail}). Nothing was installed; "
            f"run `{command}` in your own terminal.")


def _timed_out(error: OSError) -> bool:
    # A connect timeout arrives wrapped in URLError; a read timeout as TimeoutError itself.
    return isinstance(getattr(error, "reason", error), TimeoutError)


def _call(url: str, path: str, token: str, body: object = None, timeout: float = 0.0) -> tuple:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"content-type": "application/json", **({"X-Blackbox-Token": token} if token else {})}
    request = urllib.request.Request(url + path, data=data, method="POST" if data is not None else "GET", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout or ANSWER_SECONDS) as response:
            return response.status, json.loads(response.read(1024 * 1024) or b"{}")
    except urllib.error.HTTPError as answer:
        try:
            return answer.code, json.loads(answer.read(65536) or b"{}")
        except ValueError:
            return answer.code, {}


def _read(url: str, path: str, token: str = "") -> tuple:
    """A GET, asked again while Blackbox is busy (no answer in :data:`ANSWER_SECONDS`), for up to
    :data:`BUSY_SECONDS`; raises :class:`Unanswered`."""
    first = time.monotonic()
    while True:
        try:
            return _call(url, path, token)
        except OSError as error:
            waited = time.monotonic() - first
            if not _timed_out(error):
                raise Unanswered(False, waited, f"nothing answers at {url}: {getattr(error, 'reason', error)}") from None
            if waited >= BUSY_SECONDS:
                raise Unanswered(True, waited) from None
        except ValueError:
            raise Unanswered(False, time.monotonic() - first, "its answer could not be read") from None


def _ask(url: str, path: str, token: str, body: dict) -> tuple:
    """The POST that starts the request: sent once (not idempotent), waiting up to :data:`BUSY_SECONDS`."""
    try:
        return _call(url, path, token, body, timeout=BUSY_SECONDS)
    except OSError as error:
        raise Unanswered(_timed_out(error), BUSY_SECONDS, str(getattr(error, "reason", error))) from None
    except ValueError:
        raise Unanswered(False, 0.0, "its answer could not be read") from None


def _action(url: str, action: str, words: list) -> int:
    """A brokered action (``open-link``, ``open-app`` …): one request, waited on while the person
    is asked, then Blackbox's answer printed."""
    try:
        with urllib.request.urlopen(f"{url}/api/session", timeout=ANSWER_SECONDS) as response:
            token = json.loads(response.read(65536)).get("token", "")
        asking = {"argv": words, "pid": os.getppid(), "cwd": os.getcwd()}
        status, answer = _call(url, f"/api/shields/file-shield/api/{action}", token, asking)
        deadline = time.monotonic() + APPROVAL_SECONDS
        if status in (HELD, WAITING):
            print("Blackbox: waiting for your approval to do this outside the sandbox …", file=sys.stderr)
        while status in (HELD, WAITING) and time.monotonic() < deadline:
            time.sleep(POLL_SECONDS * 2)
            status, answer = _call(url, f"/api/shields/file-shield/api/{action}", token, asking)
    except (OSError, ValueError):
        print(f"Blackbox couldn't do this ({action}); do it yourself.", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Blackbox's sandbox refused this ({action}): {answer.get('error') or 'not allowed'}", file=sys.stderr)
        return 1
    print(str(answer.get("message") or ""))
    return int(answer.get("exit") or 0)


def _follow(url: str, endpoint: str, token: str, job: str, refused: str) -> int:
    """Prints the job's output as it comes; its exit code, or 1 with *refused* + the reason."""
    line = 0
    while True:
        status, state = _read(url, f"/api/shields/file-shield/api/{endpoint}-job?job={job}&from={line}", token)
        if status != 200:
            raise Unanswered(False, 0.0, "it lost the job")
        for text in state.get("lines") or []:
            print(text, flush=True)
        line = int(state.get("next") or line)
        if state.get("refused"):
            print(f"{refused}: {state['refused']}", file=sys.stderr)
            return 1
        if state.get("done"):
            return int(state.get("exit") or 0)
        time.sleep(POLL_SECONDS)


def main(argv: list) -> int:
    url, words = argv[1].rstrip("/"), argv[2:]
    if words[:1] == ["--action"] and len(words) > 1:
        return _action(url, words[1], words[2:])
    manager = words[1] if words[:1] == ["--manager"] and len(words) > 1 else ""
    words = words[2:] if manager else words
    endpoint, program = ("install", manager) if manager else ("brew", "brew")
    refused, phase = f"Blackbox's sandbox refused this ({program} {' '.join(words)})", BEFORE
    try:
        _, session = _read(url, "/api/session")
        token = str(session.get("token") or "")
        # Who asks: this process's parent (the agent's shell), so Blackbox names the agent (KI-605).
        asking = {"argv": words, "pid": os.getppid(), "cwd": os.getcwd(), **({"manager": manager} if manager else {})}
        phase = ASKED
        status, answer = _ask(url, f"/api/shields/file-shield/api/{endpoint}", token, asking)
        deadline = time.monotonic() + APPROVAL_SECONDS
        if status in (HELD, WAITING):
            print("Blackbox: waiting for your approval to run this outside the sandbox …", file=sys.stderr)
        while status in (HELD, WAITING) and time.monotonic() < deadline:
            time.sleep(POLL_SECONDS * 2)
            status, answer = _ask(url, f"/api/shields/file-shield/api/{endpoint}", token, asking)
        if status != 200:
            error = answer.get("error") or "; ".join(answer.get("errors") or []) or "not approved"
            print(f"{refused}: {error}", file=sys.stderr)
            return 1
        phase = RUNNING
        return _follow(url, endpoint, token, str(answer.get("job", "")), refused)
    except Unanswered as error:
        print(_gave_up(program, words, error, phase), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
