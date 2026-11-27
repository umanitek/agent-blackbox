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

from .....kernel import constants, persistence_places
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
               "Homebrew's install scripts run outside the sandbox with your rights", Route.BROKER, Mode.ALLOW, BLOCK_ASK_ALLOW,
               when_blocked="brew install and the other Homebrew commands are refused; the agent tells you to run them yourself"),
    Permission("global-installs", "Global installs", "npm i -g, pipx install, pip install --user, cargo install, gem install, "
               "uv tool install — done by Blackbox for the agent, names only, each checked against the threat rules",
               "the package's install scripts run outside the sandbox, and its program lands on your PATH",
               Route.BROKER, Mode.ALLOW, BLOCK_ASK_ALLOW,
               when_blocked="npm i -g, pipx install and the like are refused; installs into the project (npm i, pip in a venv) still work"),
    Permission("tool-folders", "Writing to your tool folders", "direct writes to ~/.local/bin, ~/.cargo/bin, ~/go/bin, ~/bin "
               "and the other program folders on your PATH that you own",
               "a program the agent leaves there runs outside the sandbox the next time you type its name",
               Route.PROFILE, Mode.BLOCK, BLOCK_ALLOW, refusal_kinds=(KIND_TOOL_FOLDER,),
               when_blocked="the agent can not drop a program into ~/.local/bin or the other folders on your PATH"),   # F2: blocked once the broker ships
    Permission("open-links", "Opening web links", "open https://… in your browser (sign-ins such as gh auth login --web)",
               "the page loads outside the sandbox, and a link can carry data out", Route.BROKER, Mode.ALLOW, BLOCK_ASK_ALLOW,
               refusal_kinds=(KIND_OPEN_APP,),
               when_blocked="the agent can not open a page in your browser; sign-ins that need a browser (gh auth login --web) stop"),
    Permission("open-apps", "Opening files in apps", "open -a App file, for an installed app that is not an app driver",
               "the app works on the file outside the sandbox, with your rights", Route.BROKER, Mode.ASK, BLOCK_ASK_ALLOW,
               refusal_kinds=(KIND_OPEN_APP,),
               when_blocked="open -a App file is refused; the agent can still read and write the file itself"),
    Permission("applescript", "AppleScript", "one osascript script at a time, shown to you in full before it runs",
               "the script drives other apps outside the sandbox — a full escape for that run",
               Route.BROKER, Mode.BLOCK, (Mode.BLOCK, Mode.ASK), refusal_kinds=(KIND_APP_DRIVER,),
               when_blocked="osascript is refused; nothing drives your other apps"),
    Permission("stop-processes", "Stopping your programs", "stop a stray dev server or a program holding a port",
               "a wrong process id would stop a program you are using", Route.BROKER, Mode.ASK, BLOCK_ASK_ALLOW,
               refusal_kinds=(KIND_SIGNAL,), acts_on_answer=True,
               when_blocked="the agent can not stop a program outside the sandbox; you stop it yourself"),
    Permission("docker", "Docker", "docker and colima: the container engine's socket",
               "a container runs outside the sandbox and can mount any folder, protected ones too",
               Route.PROFILE, Mode.ASK, BLOCK_ASK_ALLOW, refusal_kinds=(KIND_DOCKER,),
               when_blocked="docker and colima commands fail: the container engine's socket is closed"),
    Permission("local-ports", f"Services on {THIS_MACHINE}", f"connecting to programs listening on {THIS_MACHINE} (databases, dev servers)",
               f"the agent can talk to anything listening on {THIS_MACHINE}", Route.PROFILE, Mode.ALLOW, BLOCK_ALLOW,
               refusal_kinds=(KIND_LOCAL_PORT,), ports=True,
               when_blocked="connections to databases and dev servers on this machine fail, except the ports you list"),
    Permission("clipboard", "Clipboard", "pbpaste and reading what you last copied",
               "what you last copied may be a password or a key (blocking it also stops copy and paste inside an editor "
               "opened in the sandbox)", Route.PROFILE, Mode.ALLOW, BLOCK_ALLOW,
               refusal_kinds=(KIND_DISPLAY,) if LINUX else (),
               when_blocked="pbpaste and reading what you copied fail (copy and paste inside a sandboxed editor stops too)"),
    Permission("keychain", "Keychain", "security, git's keychain helper and agent sign-ins that use your keychain",
               "the agent can use keychain items that trust the tool it runs", Route.PROFILE, Mode.ALLOW, BLOCK_ALLOW,
               controllable=False, note=KEYCHAIN_BLOCKED if LINUX else UNPROVEN,
               when_blocked="keychain reads fail; git and gh fall back to their own token files"),
    Permission("camera-mic", "Camera and microphone", "recording from the camera or the microphone",
               "the agent could record you", Route.PROFILE, Mode.BLOCK, BLOCK_ALLOW, controllable=LINUX,
               note="" if LINUX else UNPROVEN,
               when_blocked="the camera and microphone can not be opened"),
    Permission("user-apps", "Opening apps you installed", "open an app you put in Applications yourself (Brave, Slack, an app "
               "you dragged in), not only the system's and the ones an administrator installed",
               "an app you own can be replaced by any program running as you; an agent that swapped one in could have it "
               "run outside the sandbox", Route.BROKER, Mode.BLOCK, BLOCK_ASK_ALLOW, refusal_kinds=(KIND_OPEN_APP,),
               when_blocked="only system apps and apps an administrator installed can be opened; the agent tells you which "
               "app it wanted"),
    Permission("startup-items", "Adding things that start by themselves", "add launchd jobs, login items, cron and at jobs, "
               "systemd units and SSH login files, for an agent that runs outside the sandbox",
               "what it adds runs later by itself, outside Blackbox's checks, until you find and remove it", Route.HOOK,
               Mode.BLOCK, BLOCK_ALLOW, hook_findings=(persistence_places.STARTUP_ITEM,),
               when_blocked="the change is refused in every mode and the agent tells you to make it yourself; inside the "
                            "sandbox these places stay closed whatever you pick"),
    Permission("shell-startup", "Editing your shell startup files", "edit ~/.zshrc, ~/.bashrc, ~/.profile and the other "
               "files your shell reads when it starts; Blackbox's own line in them stays protected",
               "what it adds runs in your next terminal, outside the sandbox and with your rights", Route.HOOK, Mode.BLOCK,
               BLOCK_ALLOW, hook_findings=(persistence_places.SHELL_STARTUP,),
               when_blocked="the edit is refused in every mode; inside the sandbox these files stay closed whatever you pick"),
    Permission("root-writes", "sudo changes to system folders", "sudo writes into /etc, /usr, /boot and the machine's other "
               "own folders",
               "the agent can change how the whole machine works, for every user", Route.HOOK, Mode.BLOCK, BLOCK_ALLOW,
               hook_findings=(persistence_places.ROOT_WRITE,),
               when_blocked="in Block mode the command is refused (in Audit mode it is recorded); other sudo use is only "
                            "flagged"),
    Permission("unnamed-publisher", "Installs that name no publisher", "install a package whose command names no publisher "
               "while a kill rule for a whole publisher is in force",
               "a package from the killed publisher can come in under a name that does not show it", Route.HOOK, Mode.BLOCK,
               BLOCK_ALLOW, hook_findings=(constants.UNNAMED_PUBLISHER,),
               when_blocked="while a publisher kill is in force, such installs are refused; with no publisher kill nothing "
                            "changes"),
    Permission("vulnerable-packages", "Packages with known vulnerabilities", "install a package version with a published "
               "vulnerability (it is still flagged on the dashboard)",
               "a vulnerable version stays in the project until someone upgrades it", Route.HOOK, Mode.ALLOW, BLOCK_ALLOW,
               hook_findings=(constants.KIND_VULNERABILITY,),
               when_blocked="in Block mode the install is refused and the agent is told to pick a fixed version; malware is "
                            "refused either way"),
)
BY_ID: dict[str, Permission] = {permission.id: permission for permission in PERMISSIONS}

#: What no permission unlocks (rendered last in every profile; the validator refuses rules on them).
NEVER: tuple[Never, ...] = (
    Never("blackbox", "Blackbox's own files", "its settings, keys, canary, rendered profiles and project index"),
    Never("settings", "Hermes' config.yaml and .env", "they hold every Blackbox setting"),
    Never("hooks", "Every agent's hook settings, and your shell startup files from inside the sandbox",
          "they keep later agents inside the sandbox (outside it, see Editing your shell startup files)"),
    Never("persistence", "Places something starts from by itself, from inside the sandbox",
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
#: The rules that protect Blackbox itself, for every agent in every mode, sandboxed or not. No setting
#: relaxes them: an agent that could have one relaxed could switch Blackbox off (shown read-only,
#: with the reason, wherever the permissions are shown).
ALWAYS_ON: tuple[Never, ...] = (
    Never("own-settings", "Changing Blackbox's settings, files or keys",
          "an agent that could change them could switch its own checks off"),
    Never("hook-switches", "Switching off any agent's hooks", "the hooks are how every tool call reaches Blackbox"),
    Never("control-api", "Using Blackbox's dashboard or control API", "approvals and settings live there"),
    Never("own-processes", "Stopping or signalling Blackbox, the system or other users' programs",
          "stopping Blackbox would stop every check"),
    Never("app-drivers", "Opening apps that drive other apps (Terminal, Script Editor, Automator, Shortcuts, System Settings)",
          "they run anything outside the sandbox; AppleScript is its own permission"),
    Never("unreadable", "Tool calls too large, too deep or too broken to read",
          "a call Blackbox could not read has not been checked (see the hook size limit)"),
    Never("protected-items", "Your protected files and folders", "your own File Shield list; change the list itself instead"),
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


__all__ = ["ALWAYS_ON", "BLOCK_ALLOW", "BLOCK_ASK_ALLOW", "BY_ID", "KEYCHAIN_BLOCKED", "KIND_APP_DRIVER", "KIND_DISPLAY", "KIND_DOCKER",
           "KIND_LOCAL_PORT", "KIND_OPEN_APP", "KIND_SIGNAL", "KIND_TOOL_FOLDER", "LINUX", "NEVER", "NOT_CONTROLLABLE", "PERMISSIONS",
           "THIS_MACHINE", "UNPROVEN", "profile_permissions"]
