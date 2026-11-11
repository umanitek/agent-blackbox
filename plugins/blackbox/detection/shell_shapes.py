"""Escalation shapes: turn a shell tool call into a stable arg-shape signature.

``normalize_arg_shape(tool_name, args)`` returns one of a small closed set of
dangerous shapes (``remote-script-pipe``, ``rm-rf-system-paths``, …) or None —
the identifier detection and reports use for escalations. The regexes are
tuned against false positives; ``NO_AUTO_NOMINATE_SHAPES`` lists shapes that
match curated rules only.
"""

from __future__ import annotations

import re
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Arg-shape normalization
# ---------------------------------------------------------------------------

# A remote-download-piped-to-interpreter shape: `curl ... | sh`, `wget ... | bash`.
REMOTE_SCRIPT_RE = re.compile(
    r"\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b",
    re.IGNORECASE,
)
# `rm -rf` against DANGEROUS roots only. Matches the short combined/split forms
# (`-rf`, `-fr`, `-r -f`) and the long forms (`--recursive --force`). The target
# arm is deliberately narrow: whole-system roots, a bare `/`, a whole-home wipe
# (`~`, `~/`, `$HOME`), or a security-sensitive home dir (`~/.ssh` etc.). Routine
# cleanup — `rm -rf node_modules`, `~/.cache`, `~/build`, `/var/tmp/...` — does
# NOT match, so ordinary dev work stays quiet.
RM_RF_SYSTEM_RE = re.compile(
    r"\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r|"
    r"--recursive\s+--force|--force\s+--recursive|-r\s+--force|--recursive\s+-f)\b[\s\S]{0,200}"
    r"(?:"
    r"\s/(?:etc|usr|bin|sbin|opt|private|System|Library)\b"          # system roots
    r"|\s/var(?!/(?:tmp|folders))\b"                                 # /var but not temp
    r"|\s/\s*(?=[;&|]|$)"                                            # bare / (root)
    r"|\s(?:~|\$HOME)/?(?=\s|[;&|]|$)"                               # whole home wipe
    r"|\s(?:~|\$HOME)/\.(?:ssh|aws|gnupg|gpg|kube|docker|password-store)\b"  # sensitive home dirs
    r")",
    re.IGNORECASE,
)
# `chmod 777` against a SENSITIVE target (system root or security dir). World-
# writable perms on a scratch/build/public dir are common and harmless, so a
# bare `chmod 777 ./public` no longer fires.
CHMOD_WORLD_RE = re.compile(
    r"\bchmod\s+(?:-R\s+)?0?777\b[\s\S]{0,200}"
    r"(?:\s/(?:etc|usr|bin|sbin|var|opt|private|System|Library)\b|\s/\s*(?=[;&|]|$)"
    r"|\s(?:~|\$HOME)/?\.?(?:ssh|aws|gnupg))",
    re.IGNORECASE,
)
# Piping a fetched payload straight into eval.
CURL_EVAL_RE = re.compile(r"\b(?:curl|wget)\b[\s\S]{0,300}\|\s*eval\b", re.IGNORECASE)
# Disabling TLS verification on a network fetch. `-k`/`--insecure` mean "skip
# cert check" for curl only; for wget `-k` is `--convert-links` (benign), whose
# insecure flag is `--no-check-certificate`. Keep them ecosystem-specific so a
# routine `wget -k` mirror isn't misflagged.
INSECURE_FETCH_RE = re.compile(
    # curl: --insecure, --no-check-certificate, or a short-flag group containing
    # `k` (`-k`, `-sk`, `-ks`, `-fsSLk`). Kept as a plain char class (no inline
    # case flags) so the TS port stays byte-identical for parity.
    r"\bcurl\b[\s\S]{0,200}(?:--insecure|--no-check-certificate|\s-[a-z]*k[a-z]*\b)"
    r"|\bwget\b[\s\S]{0,200}--no-check-certificate",
    re.IGNORECASE,
)
# A local/private/dev host — an insecure TLS fetch against one of these is
# routine (self-signed dev servers, internal endpoints), not a threat.
_LOCAL_HOST_RE = re.compile(
    r"(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0|\[::1\]|\b10\.\d+\.\d+\.\d+"
    r"|\b192\.168\.\d+\.\d+|\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\.local\b|\.internal\b)",
    re.IGNORECASE,
)

# Ordered so the most specific / most dangerous shape wins for a given command.
_SHELL_SHAPE_RULES = (
    ("remote-script-pipe", REMOTE_SCRIPT_RE),
    ("remote-eval-pipe", CURL_EVAL_RE),
    ("rm-rf-system-paths", RM_RF_SYSTEM_RE),
    ("chmod-world-writable", CHMOD_WORLD_RE),
    ("insecure-tls-fetch", INSECURE_FETCH_RE),
)

# Shapes that Blackbox still MATCHES against curated graph rules but never
# auto-nominates as heuristic candidates. `remote-script-pipe` (`curl … | bash`)
# is the canonical install idiom for rustup, nvm, Homebrew, oh-my-zsh, etc., so
# firing + reporting on the shape alone would flag routine agent behaviour and
# flood the community graph. A known-bad
# `curl|bash` into the graph and Blackbox will match it.
NO_AUTO_NOMINATE_SHAPES = frozenset({"remote-script-pipe"})

#: Every escalation arg shape detection can name — the closed vocabulary a
#: community escalation report is validated against (Refine R1).
ESCALATION_SHAPES = frozenset(shape for shape, _rule in _SHELL_SHAPE_RULES)

# Tool names whose payload is treated as a shell command string.
SHELL_TOOLS = {"terminal", "shell", "bash", "run_command", "exec", "command"}
_COMMAND_KEYS = ("command", "cmd", "shell", "script", "input")

#: A command is read whole up to twice this many characters; a longer one by its first and
#: its last this-many (the secret scanners' rule, KI-376): harmless text before or after an
#: action never moves it out of the checks, and the cost stays bounded on any input. An
#: action in the middle of a command longer than twice this is a known gap.
COMMAND_SCAN_WINDOW = 50_000


def _bounded(command: str) -> str:
    """*command* as the checks read it (see :data:`COMMAND_SCAN_WINDOW`); the two halves of a
    long one are joined by a newline, which ends a shell command."""
    if len(command) <= 2 * COMMAND_SCAN_WINDOW:
        return command
    return command[:COMMAND_SCAN_WINDOW] + "\n" + command[-COMMAND_SCAN_WINDOW:]


def command_from_args(tool_name: str, args: Any) -> str:
    """The shell command a tool call carries, as the checks read it: its ``command``-like
    argument, else (shell tools only) its string arguments joined; "" for anything else."""
    if isinstance(args, str):
        return _bounded(args)
    if not isinstance(args, dict):
        return ""
    for key in _COMMAND_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val:
            return _bounded(val)
    # Fall back to concatenating string values for shell-like tools only.
    if (tool_name or "").lower() in SHELL_TOOLS:
        parts = [v for v in args.values() if isinstance(v, str)]
        return _bounded(" ".join(parts))
    return ""


def normalize_arg_shape(tool_name: str, args: Any) -> Optional[str]:
    """Derive a deterministic escalation ``argShape`` for a tool call.

    Returns a stable slug (e.g. ``remote-script-pipe``) or ``None`` when the
    call does not match any known dangerous shape. Deterministic and pure so
    independent clients agree on identifiers.
    """
    command = command_from_args(tool_name, args)
    if not command:
        return None
    for shape, pattern in _SHELL_SHAPE_RULES:
        try:
            if pattern.search(command):
                # Insecure TLS against a localhost / private / .local host is
                # routine dev work, not a threat — skip it (other shapes still win).
                if shape == "insecure-tls-fetch" and _LOCAL_HOST_RE.search(command):
                    continue
                return shape
        except re.error:  # pragma: no cover - static patterns
            continue
    return None
