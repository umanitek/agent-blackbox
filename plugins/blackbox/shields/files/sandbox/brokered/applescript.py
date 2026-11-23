"""``applescript``: one AppleScript a sandboxed agent asks Blackbox to run outside the sandbox
(sandbox permission ``applescript``: block by default, or ask — and only ever "once", F5).

The ``osascript`` stand-in (``platform.osascript_shim``) sends ``-e`` lines or one script file's
text. Only plain AppleScript text, at most :data:`MAX_SCRIPT_CHARS` (no compiled ``.scpt``, no
JavaScript). Each script is its own question: the person sees the WHOLE script (the request's
``detail``, in the ``permission-requests`` read), and "Allow once" is bound to that exact text (its
digest); the next script asks again.

**Security cost:** the script drives other apps outside the sandbox — a full escape for that run.

Usage::

    API_WRITES["applescript"](context, {"argv": ["-e", 'tell application "Music" to pause'], "pid": 4242})
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from ..... import audit
from ....shield_api import ShieldApiError, ShieldContext
from .. import platform
from .asking import Asking, decide

PERMISSION = "applescript"
MAX_SCRIPT_CHARS = 16 * 1024


def parse(argv: Any, folder: str) -> str:
    """The script's text for ``osascript <argv>``; raises ShieldApiError for anything else."""
    words = argv if isinstance(argv, list) and all(isinstance(word, str) for word in argv) else []
    if words[:1] == ["-e"]:
        if len(words) % 2 or any(flag != "-e" for flag in words[0::2]):
            raise ShieldApiError(400, "Blackbox runs osascript -e '<line>' … or one AppleScript file, nothing else")
        script = "\n".join(words[1::2])
    elif len(words) == 1:
        path = os.path.realpath(os.path.join(folder or "/", os.path.expanduser(words[0])))
        try:
            with open(path, "rb") as handle:   # windows-footgun: ok (bytes, decoded below)
                raw = handle.read(MAX_SCRIPT_CHARS + 1)
            script = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            raise ShieldApiError(400, f"{words[0]} is not a readable AppleScript text file (a compiled .scpt is not run)") from None
    else:
        raise ShieldApiError(400, "Blackbox runs osascript -e '<line>' … or one AppleScript file, nothing else")
    if not script.strip() or len(script) > MAX_SCRIPT_CHARS or "\x00" in script:
        raise ShieldApiError(400, f"the script must be AppleScript text of at most {MAX_SCRIPT_CHARS} characters")
    return script


def run(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    if set(body) - {"argv", "pid", "cwd"}:
        raise ShieldApiError(400, "a request carries the script only")
    asked = Asking.of(context, body)
    script = parse(body.get("argv"), asked.folder)
    decide(PERMISSION, asked, script, show_whole=True)
    code, output = platform.run_script(script)
    audit.record_for(audit.SANDBOX_RECORDER, event="brokered_applescript", workspace=asked.folder,
                     detail={"agent": asked.agent, "chars": len(script), "exit": code})
    return {"message": output, "exit": code}


__all__ = ["MAX_SCRIPT_CHARS", "PERMISSION", "parse", "run"]
