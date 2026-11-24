"""``blackbox approve`` — confirm held changes from the person's own terminal (KI-659, design F9).

For a machine where the system draws no password dialog (a Linux server without pkexec) and no
companion app is paired: lists what is waiting, asks yes / no on the terminal itself
(``/dev/tty`` — never a pipe, so a script or an agent can not answer), and proves each yes with
the person's sudo password (:mod:`.terminal`: ``sudo -k`` then ``sudo`` writes the dashboard's
one-time challenge where only root can). Exit 0 when every yes was approved, 1 otherwise,
2 when there is no terminal.

Usage::

    blackbox approve
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import urllib.error
import urllib.request
from typing import Any, Callable, TextIO

from ..kernel.config import load_blackbox_config
from . import terminal

TIMEOUT_SECONDS = 10
#: How long the person has to type their sudo password.
SUDO_SECONDS = 180
Run = Callable[[list[str], TextIO], int]


def _call(url: str, path: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(url + path, method="POST" if body is not None else "GET",
                                     data=json.dumps(body).encode("utf-8") if body is not None else None,
                                     headers={"content-type": "application/json", "X-Blackbox-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            answer = json.loads(response.read(65536))
    except urllib.error.HTTPError as refused:
        answer = json.loads(refused.read(65536) or b"{}")
    return answer if isinstance(answer, dict) else {}


def _sudo(argv: list[str], tty: TextIO) -> int:
    try:
        return subprocess.run(["sudo", *argv], stdin=tty, timeout=SUDO_SECONDS, check=False).returncode
    except subprocess.TimeoutExpired:
        return 1   # no password in time: nothing proved


def approve(url: str, tty: TextIO, run: Run = _sudo) -> int:
    """Ask about each held change on *tty* and prove each yes through sudo (*run*: tests pass a fake)."""
    with urllib.request.urlopen(url + "/api/session", timeout=TIMEOUT_SECONDS) as response:
        token = json.loads(response.read(65536)).get("token", "")
    waiting = _call(url, "/api/companion/approvals", token).get("waiting") or []
    if not waiting:
        print("Nothing is waiting for your confirmation.", file=tty)
        return 0
    failed = 0
    for held in waiting:
        print("Turn protection DOWN: " + "; ".join(held.get("reasons") or []), file=tty)
        print("Approve this change? Only if YOU asked for it. [y/N] ", end="", file=tty, flush=True)
        if tty.readline().strip().lower() not in ("y", "yes"):
            print("Left as it is: protection stays on.", file=tty)
            continue
        challenge = _call(url, "/api/approvals/terminal-challenge", token, {"id": held.get("id", "")})
        folder, nonce, request_id = challenge.get("folder", ""), challenge.get("nonce", ""), str(held.get("id", ""))
        if not challenge.get("ok") or not terminal.REQUEST_ID.fullmatch(request_id):
            failed += 1
            print(f"Not confirmed: {challenge.get('error', 'the dashboard refused')}.", file=tty)
            continue
        run(["-k"], tty)   # sudo asks for the password again, whatever this terminal had cached
        wrote = run(["/bin/sh", "-c", terminal.WRITE_PROOF, "sh", folder, request_id, nonce], tty) == 0
        ok = wrote and bool(_call(url, "/api/approvals/terminal-confirm", token, {"id": request_id}).get("ok"))
        run(["-n", "rm", "-f", f"{folder}/{request_id}"], tty)
        run(["-k"], tty)
        failed += not ok
        print("Approved: the change is applied when the dashboard sends it again." if ok else "Not confirmed: protection stays on.", file=tty)
    return 1 if failed else 0


#: The person's own terminal: never a pipe, so a script or an agent can not answer.
TERMINAL = "/dev/tty"


def open_terminal(path: str = TERMINAL) -> TextIO:
    """*path* open for reading AND writing as text, with a real descriptor (sudo reads the password
    from it). WHY not ``open(path, "r+")``: Python's text read-write mode needs a SEEKABLE file and
    a terminal is not one — it raised "File or stream is not seekable" on every terminal, so
    ``blackbox approve`` always said it had none (KI-673, Linux round L2). An unbuffered binary
    handle under a text wrapper reads a line as the terminal hands it over and writes at once.
    Raises OSError when there is no terminal."""
    raw = open(path, "r+b", buffering=0)   # the caller closes the wrapper, and with it this handle
    return io.TextIOWrapper(raw, encoding="utf-8", errors="replace", line_buffering=True, write_through=True)


def cmd_approve(_args: argparse.Namespace) -> int:
    try:
        tty = open_terminal()
    except OSError:
        print("blackbox approve needs your own terminal (it asks you there, and sudo asks for your password).")
        return 2
    with tty:
        return approve(f"http://127.0.0.1:{load_blackbox_config().dashboard_port}", tty)


def add_approve_parser(sub: Any) -> None:
    sub.add_parser("approve", help="Confirm held changes from your own terminal (sudo asks for your password)").set_defaults(func=cmd_approve)
