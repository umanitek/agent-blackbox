"""The catalogue of sandbox permissions: every ability the person can unlock or lock per agent and
per project, what each costs, how it is enforced, and the list nothing unlocks.

Founder decisions (2026-11-23, F1–F9 as recommended): global installs allowed through Blackbox's
broker (F1); the agent tool folders blocked now that the global-installs broker ships (F2); "Always" means this agent
in this project (F3); Docker asks, per project (F4); AppleScript only ever asks once (F5); the
most specific scope wins both ways, the never-list above all (F6); ssh to this Mac never (F7);
keychain and clipboard allowed, camera and microphone blocked once the OS check is proven (F8);
hooks-only agents get folder rules and the persistence places only (F9).

``controllable`` is False where Blackbox can not yet prove the OS enforces it (probed on macOS
27.2, 2026-11-23): such a permission is listed as "not controllable yet" and no rule for it is
accepted, so the page never promises what the kernel does not do. It is per OS: on Linux the
camera and microphone ARE controllable (their devices and sound servers are hidden inside the
sandbox), and the keychain is blocked whatever the rule (the session bus that reaches the keyring
is hidden in phase 1, founder decision F4). The sentences name the machine as a person does on it
(``kernel.os_layout.machine_words``: "this Mac", "this computer").

Usage::

    BY_ID["docker"].default     # Mode.ASK
    NEVER                       # what no permission unlocks
"""

from __future__ import annotations

import sys

from .....kernel.os_layout import machine_words
from .model import Mode, Never, Permission, Route

LINUX = sys.platform.startswith("linux")
#: "this Mac" / "this computer".
THIS_MACHINE = machine_words()

BLOCK_ASK_ALLOW = (Mode.BLOCK, Mode.ASK, Mode.ALLOW)
BLOCK_ALLOW = (Mode.BLOCK, Mode.ALLOW)
#: Why a permission is "not controllable yet": its OS check is not proven on a real service.
UNPROVEN = (f"not controllable yet: Blackbox has not yet proven that {'Linux' if LINUX else 'macOS'} enforces it, so it is "
            "not offered")
#: Linux, phase 1 (F4): the keyring is reached over the session bus, which the sandbox hides.
KEYCHAIN_BLOCKED = ("blocked inside the sandbox on Linux for now: the session bus that reaches your keyring is hidden "
                    "there (gh and git fall back to their own token files)")
#: The refusal kinds (``agent_hooks`` sandbox errors) that mean an agent wanted a permission.
KIND_DOCKER, KIND_LOCAL_PORT, KIND_TOOL_FOLDER = "docker", "local-port", "tool-folder"
KIND_OPEN_APP, KIND_APP_DRIVER, KIND_SIGNAL = "open-app", "app-driver", "signal"
#: Linux: the display server refused (the clipboard is the display there).
KIND_DISPLAY = "display"

PERMISSIONS: tuple[Permission, ...] = (
    Permission("homebrew", "Homebrew installs", "brew install, upgrade, reinstall and uninstall, done by Blackbox for the agent",
               "Homebrew's install scripts run outside the sandbox with your rights", Route.BROKER, Mode.ALLOW, BLOCK_ASK_ALLOW),
    Permission("global-installs", "Global installs", "npm i -g, pipx install, pip install --user, cargo install, gem install, "
               "uv tool install — done by Blackbox for the agent, names only, each checked against the threat rules",
               "the package's install scripts run outside the sandbox, and its program lands on your PATH",
               Route.BROKER, Mode.ALLOW, BLOCK_ASK_ALLOW),
    Permission("tool-folders", "Writing to your tool folders", "direct writes to ~/.local/bin, ~/.cargo/bin, ~/go/bin, ~/bin "
               "and the other program folders on your PATH that you own",
               "a program the agent leaves there runs outside the sandbox the next time you type its name",
               Route.PROFILE, Mode.BLOCK, BLOCK_ALLOW, refusal_kinds=(KIND_TOOL_FOLDER,)),   # F2: blocked once the broker ships
    Permission("open-links", "Opening web links", "open https://… in your browser (sign-ins such as gh auth login --web)",
               "the page loads outside the sandbox, and a link can carry data out", Route.BROKER, Mode.ALLOW, BLOCK_ASK_ALLOW,
               refusal_kinds=(KIND_OPEN_APP,)),
    Permission("open-apps", "Opening files in apps", "open -a App file, for an installed app that is not an app driver",
               "the app works on the file outside the sandbox, with your rights", Route.BROKER, Mode.ASK, BLOCK_ASK_ALLOW,
               refusal_kinds=(KIND_OPEN_APP,)),
    Permission("applescript", "AppleScript", "one osascript script at a time, shown to you in full before it runs",
               "the script drives other apps outside the sandbox — a full escape for that run",
               Route.BROKER, Mode.BLOCK, (Mode.BLOCK, Mode.ASK), refusal_kinds=(KIND_APP_DRIVER,)),
    Permission("stop-processes", "Stopping your programs", "stop a stray dev server or a program holding a port",
               "a wrong process id would stop a program you are using", Route.BROKER, Mode.ASK, BLOCK_ASK_ALLOW,
               refusal_kinds=(KIND_SIGNAL,), acts_on_answer=True),
    Permission("docker", "Docker", "docker and colima: the container engine's socket",
               "a container runs outside the sandbox and can mount any folder, protected ones too",
               Route.PROFILE, Mode.ASK, BLOCK_ASK_ALLOW, refusal_kinds=(KIND_DOCKER,)),
    Permission("local-ports", f"Services on {THIS_MACHINE}", f"connecting to programs listening on {THIS_MACHINE} (databases, dev servers)",
               f"the agent can talk to anything listening on {THIS_MACHINE}", Route.PROFILE, Mode.ALLOW, BLOCK_ALLOW,
               refusal_kinds=(KIND_LOCAL_PORT,), ports=True),
    Permission("clipboard", "Clipboard", "pbpaste and reading what you last copied",
               "what you last copied may be a password or a key (blocking it also stops copy and paste inside an editor "
               "opened in the sandbox)", Route.PROFILE, Mode.ALLOW, BLOCK_ALLOW,
               refusal_kinds=(KIND_DISPLAY,) if LINUX else ()),
    Permission("keychain", "Keychain", "security, git's keychain helper and agent sign-ins that use your keychain",
               "the agent can use keychain items that trust the tool it runs", Route.PROFILE, Mode.ALLOW, BLOCK_ALLOW,
               controllable=False, note=KEYCHAIN_BLOCKED if LINUX else UNPROVEN),
    Permission("camera-mic", "Camera and microphone", "recording from the camera or the microphone",
               "the agent could record you", Route.PROFILE, Mode.BLOCK, BLOCK_ALLOW, controllable=LINUX,
               note="" if LINUX else UNPROVEN),
)
BY_ID: dict[str, Permission] = {permission.id: permission for permission in PERMISSIONS}

#: What no permission unlocks (rendered last in every profile; the validator refuses rules on them).
NEVER: tuple[Never, ...] = (
    Never("blackbox", "Blackbox's own files", "its settings, keys, canary, rendered profiles and project index"),
    Never("settings", "Hermes' config.yaml and .env", "they hold every Blackbox setting"),
    Never("hooks", "Every agent's hook settings and your shell startup files", "they keep later agents inside the sandbox"),
    Never("persistence", "Places something starts from by itself",
          ("systemd units, autostart entries, cron and at, ~/.ssh login files, Homebrew's folders" if LINUX else
           "launchd jobs, login items, cron and at, ~/.ssh login files, Homebrew's folders") + ": a job left there runs outside the sandbox"),
    Never("protected", "Your protected files and folders", "File Shield's list"),
    Never("ssh-self", f"ssh into {THIS_MACHINE}", "a login runs outside the sandbox (F7); " + (
          "the system protection helper refuses it per agent, to every address of this computer" if LINUX else
          "Seatbelt's localhost filter covers every address of this Mac (probed on macOS 27.2)")),
    Never("signals", "Signals to programs outside the sandbox", "use Stopping your programs instead"),
    Never("privilege", "sudo, setuid programs and new " + ("systemd" if LINUX else "launchd") + " jobs",
          "the sandbox runs with no new privileges" if LINUX else "macOS does not run setuid programs inside a sandbox"),
    Never("dashboard", "Blocking Blackbox's dashboard port", "the sandbox's own tools talk to it"),
)
#: What Blackbox can not control from the sandbox at all (shown for information).
NOT_CONTROLLABLE: tuple[Never, ...] = (
    Never("screen", "Screen capture", "on X11 any program with the display can read the screen; Wayland asks you through "
          "the desktop portal" if LINUX else "macOS asks you for the terminal app itself (Privacy & Security), not for the agent"),
    Never("setuid", "setuid tools", "they run without their privileges inside the sandbox (sudo, su, pkexec, crontab)" if LINUX
          else "macOS never runs them inside a sandbox (sudo, top, crontab)"),
)


def profile_permissions() -> tuple[Permission, ...]:
    """The controllable permissions enforced in the Seatbelt profile."""
    return tuple(each for each in PERMISSIONS if each.route is Route.PROFILE and each.controllable)


__all__ = ["BLOCK_ALLOW", "BLOCK_ASK_ALLOW", "BY_ID", "KEYCHAIN_BLOCKED", "KIND_APP_DRIVER", "KIND_DISPLAY", "KIND_DOCKER",
           "KIND_LOCAL_PORT", "KIND_OPEN_APP", "KIND_SIGNAL", "KIND_TOOL_FOLDER", "LINUX", "NEVER", "NOT_CONTROLLABLE", "PERMISSIONS",
           "THIS_MACHINE", "UNPROVEN", "profile_permissions"]
