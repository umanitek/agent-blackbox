"""The person's words in a prompt an agent's hook reports: the agent's OWN text set aside.

WHY (KI-579, real Cline 3.0.75 headless runs, 2026-11-22): Cline appends "[SYSTEM] This run is not
complete until you call … submit_and_exit …" to every headless prompt, and the verified graph's
"Attacker-supplied [SYSTEM] tag" rule flagged EVERY Cline prompt. The prompt-injection check must
judge what the person (or an attacker in the person's text) wrote, not the agent's boilerplate.

What is set aside is documented per agent in the catalogue (``Host.prompt_wrapper``,
``Host.prompt_additions``) and matched EXACTLY: an addition only as a whole sentence at the very
end of the prompt, the wrapper only around the whole rest. Anything else — a ``[SYSTEM]`` tag
anywhere in the person's text, a near-copy of the agent's sentence — stays and is checked.

Usage::

    persons_words("cline", '<user_input mode="yolo">fix it</user_input>\n[SYSTEM] This run …')   # "fix it"
"""

from __future__ import annotations

import re
from functools import lru_cache

from ...kernel.agent_hosts import BY_ID

#: The most additions set aside from one prompt (an agent appends its sentence once).
MAX_ADDITIONS = 4


@lru_cache(maxsize=32)
def _patterns(agent: str) -> tuple[re.Pattern[str] | None, tuple[re.Pattern[str], ...]]:
    host = BY_ID.get(agent)
    if host is None:
        return None, ()
    wrapper = re.compile(rf"\s*{host.prompt_wrapper}\s*", re.DOTALL) if host.prompt_wrapper else None
    additions = tuple(re.compile(rf"(?:^|\s+)(?:{addition})\s*$") for addition in host.prompt_additions)
    return wrapper, additions


def persons_words(agent: str, text: str) -> str:
    """*text* (a prompt *agent*'s hook reported) without the agent's own wrapper and appended
    sentences; *text* unchanged for an agent that documents none."""
    wrapper, additions = _patterns(agent)
    for _ in range(MAX_ADDITIONS):
        found = next((match for match in (pattern.search(text) for pattern in additions) if match), None)
        if found is None:
            break
        text = text[:found.start()]
    unwrapped = wrapper.fullmatch(text) if wrapper is not None else None
    return unwrapped.group(1).strip() if unwrapped else text
