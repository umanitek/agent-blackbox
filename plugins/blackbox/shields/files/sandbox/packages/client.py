"""The ``brew`` a sandboxed agent runs: it asks Blackbox to install, and prints what Homebrew says.

Copied into ``<agent-bin>/sandbox-tools`` as ``brew-client.py`` and started by the ``brew`` shim
there (first on the SANDBOXED PATH only). Standard library only; it runs inside the sandbox.

``brew install|upgrade|reinstall|uninstall …`` is sent to Blackbox's dashboard (loopback, with
its session token): ``POST /api/shields/file-shield/api/brew`` with the argv alone. Blackbox
validates it, checks each package against the threat graph and runs Homebrew outside the
sandbox. The client prints the output as it arrives (``GET …/brew-job``) and exits with brew's
exit code. When the person is asked first (the ``homebrew`` sandbox permission on "ask"), the
dashboard answers 423 while the question is open; the client waits, sending the same request
again, until it runs or is refused. (428, the approval gate holding a request, is waited on alike.)
FAIL CLOSED: when Blackbox can not be reached, nothing is installed and the agent is told to run
brew in the person's own terminal.

Usage (what the shim runs)::

    python3 brew-client.py http://127.0.0.1:9700 install tree
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
TIMEOUT_SECONDS = 10
HELD = 428
#: The person has not answered the permission request yet (``packages.WAITING``).
WAITING = 423


def _unreachable(argv: list) -> str:
    return f"Blackbox couldn't install this; run `brew {' '.join(argv)}` in your own terminal."


def _call(url: str, path: str, token: str, body: object = None) -> tuple:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url + path, data=data, method="POST" if data is not None else "GET",
                                     headers={"content-type": "application/json", "X-Blackbox-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read(1024 * 1024) or b"{}")
    except urllib.error.HTTPError as answer:
        try:
            return answer.code, json.loads(answer.read(65536) or b"{}")
        except ValueError:
            return answer.code, {}


def main(argv: list) -> int:
    url, words = argv[1].rstrip("/"), argv[2:]
    try:
        with urllib.request.urlopen(f"{url}/api/session", timeout=TIMEOUT_SECONDS) as response:
            token = json.loads(response.read(65536)).get("token", "")
        # Who asks: this process's parent (the agent's shell), so Blackbox names the agent (KI-605).
        asking = {"argv": words, "pid": os.getppid(), "cwd": os.getcwd()}
        status, answer = _call(url, "/api/shields/file-shield/api/brew", token, asking)
        deadline = time.monotonic() + APPROVAL_SECONDS
        if status in (HELD, WAITING):
            print("Blackbox: waiting for your approval to run this outside the sandbox …", file=sys.stderr)
        while status in (HELD, WAITING) and time.monotonic() < deadline:
            time.sleep(POLL_SECONDS * 2)
            status, answer = _call(url, "/api/shields/file-shield/api/brew", token, asking)
        if status != 200:
            error = answer.get("error") or "; ".join(answer.get("errors") or []) or "not approved"
            print(f"Blackbox's sandbox refused this (brew {' '.join(words)}): {error}", file=sys.stderr)
            return 1
        job, line = answer.get("job", ""), 0
        while True:
            status, state = _call(url, f"/api/shields/file-shield/api/brew-job?job={job}&from={line}", token)
            if status != 200:
                raise OSError("lost the job")
            for text in state.get("lines") or []:
                print(text, flush=True)
            line = int(state.get("next") or line)
            if state.get("done"):
                return int(state.get("exit") or 0)
            time.sleep(POLL_SECONDS)
    except (OSError, ValueError):
        print(_unreachable(words), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
