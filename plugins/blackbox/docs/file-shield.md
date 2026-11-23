# File Shield — keeping AI agents away from what you protect

File Shield is Blackbox's third shield. You choose files and folders; no AI agent may touch them.
It is switched on in Settings (or from a companion app), like Trader Shield and Network Shield.

## What it does

* **Protected files and folders.** You add a file or a folder (from `~/` or `/`). A folder protects
  everything inside it. Adding one applies at once. Removing one turns protection down, so Blackbox
  asks you first (the same approval as every other weakening change).
* **Every agent.** Hermes, Blackbox's own assistant, Claude Code, Codex, Cursor, Gemini CLI, GitHub
  Copilot CLI, Windsurf, Cline, OpenCode, OpenClaw and their MCP tools. Every one of their tool calls
  passes Blackbox's guard, and the guard asks File Shield.
* **Every route a tool call names.** Opening, copying, archiving, listing, changing, moving or
  deleting the item; a `cd` into it; a command over a folder that holds it (deleting `~/Documents`
  when `~/Documents/Taxes` is protected); code that opens it; an MCP tool's path. Every spelling is
  judged as the real place it names: `~`, `$HOME`, `..` and links all resolve first.
* **Every mode.** Audit mode too. It is your own explicit rule, like Blackbox's self-protection.
* **Prompts.** A prompt that names a protected item is flagged (the prompt itself is never kept).
  The tool call it leads to is what is refused.
* **Shown to you.** Every refusal is a local finding (`files:file-hit`, `files:folder-hit`) on the
  File Shield page, in the dashboard and in any companion app. These findings never leave your
  machine and never carry a file's contents.
* **Real time.** With the system protection helper installed, the helper watches every protected
  item and every watched folder with the operating system's own file events (FSEvents on macOS) and
  reports each change within about a second, signed with the helper's key.

## How far it reaches — plainly

This is **Layer 1**: Blackbox's guard, which sees every tool call an agent makes. It reads text; it
does not run anything. Within that, it judges:

- every path a command or a code tool names, as the shell or the language would join it
  (`'Doc''uments'`, `'Doc' + 'uments'`, the home folder asked for as `process.env.HOME`,
  `os.homedir()`, `Dir.home`, `ENV['HOME']`, `Path.home()` or `os.path.expanduser('~')`);
- a script an agent writes (through its file tool, a heredoc, `echo`/`printf … >` or `… | tee`), by
  its text, when it is written;
- any script file a command runs (`python3 r.py`, `node x.js`, `bash x.sh`, `./x`), read from disk
  when it is run (up to 256 KiB) with the arguments the command hands it (`sys.argv`,
  `process.argv`, `ARGV`, `$1`), in the folder the agent works in — also when it is handed to
  another shell (`bash -lc '…'`, `/bin/zsh -lc '…'`);
- a script written AND run in the same command (`cat > r.py <<EOF … EOF && python3 r.py`,
  `printf … > x.sh; sh x.sh`, `… | tee x.py; python3 x.py`): the text it writes is the text judged,
  because the file does not exist yet when the hook looks (security round 6);
- the same script reading for the startup places: a script the agent runs whose text writes an SSH
  login file, a launchd job, a login item or a cron table is refused like the write itself.

What only the sandbox (Layer 2, below) stops, because no text says which file will be opened:

- a path a program builds while it runs from anything else — input it reads, a file or the network,
  environment variables other than the home folder, values it computes;
- a compiled program, or a script fetched and run in one go;
- a script whose behaviour is only known at run time: it writes or fetches the code it then runs,
  decodes or decrypts it, picks a path by a condition, a loop or a value it computes, or is changed
  between the hook's look and the run (another process, a second command racing it);
- a script run by a program the hook does not know as a runner (an interpreter under another name,
  a build tool, a test runner, `make`, a package's own install script);
- a script larger than 256 KiB (flagged, not judged).

**Hooks only can never be a guarantee.** Layer 1 judges what a call SAYS; a script can always be
written so that what it does is decided only when it runs. For an agent on hooks only — one you
took out of the sandbox, one started another way, an IDE that starts its own agent — Blackbox
refuses everything it can read and flags what it cannot, and that is all. The sandbox (Layer 2) is
the guarantee: the kernel refuses the open, the write or the job whatever the script computes.
- Hermes's `execute_code` tool beyond what its code text says. When the Hermes agent is picked for
  the sandbox, Blackbox sets Hermes's interpreter-launcher hook point
  (`HERMES_EXECUTE_CODE_LAUNCHER`) to its sandbox launcher, so that Python runs inside the sandbox
  too and the agent shows as "sandboxed (kernel-enforced)". When the launcher is missing, or the
  Hermes has no such hook point, execute_code still runs, outside the sandbox, and the agent shows
  as "terminal tool sandboxed; execute_code hooks only", with the reason.

When a script that reads its paths at run time is run beside a protected item, or is too large to
read, File Shield flags it and says why, rather than showing a plain "allowed".

Only the operating system can see every file a process opens. That is **Layer 2**, the agent
sandbox, for the coding agents you pick (macOS today):

> Agents run inside Blackbox's sandbox: they can't use sudo, change their own hook settings or
> your shell startup files, or reach protected items. Turn off per agent if a tool you need
> doesn't work.

**On by default.** Until the operating system's own file checks (Layer 3) exist, every agent
Blackbox finds runs inside the sandbox by default: on install, upgrade and `blackbox attach` each
detected agent is picked, unless you took it out of the sandbox before — your choice is kept
(`sandbox_declined`) and never overridden, upgrades included. Taking an agent out asks you first
(the companion app's dialog, or your password). A File Shield you turned off stays off
(`SANDBOX_DEFAULT = "on"` in `shields/files/sandbox/defaults.py`, since security round 5 proved the
sandbox with real agents).

- Blackbox writes a launcher for each agent you pick (`claude`, `codex`, `cursor-agent`, `gemini`,
  `copilot`, `cline`, `opencode`) and puts its folder first on your PATH (one marked block at the
  end of `~/.zshrc`, and `~/.bashrc` / `~/.bash_profile` when you have them). Starting the agent
  from a terminal then starts it inside macOS's own sandbox, built from your protected list.
- That block can not be undone by an agent: inside the sandbox no shell startup file (`~/.zshrc`,
  `~/.zprofile`, `~/.zlogin`, `~/.bashrc` …) can be written at all, and outside it Blackbox's guard
  refuses any agent edit of the block (your own lines stay editable). If something removes or
  changes the block anyway, File Shield puts it back within seconds and tells you.
- Inside it, nothing the agent starts — a script, a program it compiled, Python, a shell — can
  open, copy, list, change, move, link or delete a protected item, or rename a folder above one,
  or change Blackbox itself. The kernel refuses it; no hook is needed and none can be skipped.
  Each refusal is shown with the program's name and counts as a File Shield hit.
- **Nothing is left to start by itself later — for every agent, sandboxed or not.** The places
  something starts from on its own or that you run later — launchd jobs (`~/Library/LaunchAgents`
  and the system's), login and background items, cron and `at`, OpenSSH's login files
  (`~/.ssh/authorized_keys`, `authorized_keys2`, `rc`, `environment`), your shell startup files and
  Homebrew's own folders — are ONE list (`kernel/persistence_places`). The sandbox's profile closes
  them to writes, and Blackbox's hooks refuse an agent's write to them in every mode, by any route
  (`>>`, `tee`, `cp`, a script it writes or runs, Python, a file tool, Codex's `apply_patch`), plus
  the commands that schedule a job without naming a file (`crontab -`, `at`, `launchctl
  bootstrap|load|submit`, `sfltool add-item`, `defaults write com.apple.loginwindow …`), also handed
  to another shell. On hooks only this is as far as a hook can read (above); in the sandbox the
  kernel refuses a write to those files and folders whatever the script computes (the login
  window's preference files included: a direct `cp` or `plutil` of them is refused). Measured on
  macOS 27 with a throwaway domain: a preference written through macOS's preferences service
  (`defaults write`, `CFPreferences` from code) is written BY that service (cfprefsd), so the
  sandbox's file rules do not see it, and Seatbelt's `user-preference-write` rule is accepted but
  not enforced for it. The hook refuses the command; a script that does it while it runs may pass
  on the login window's domain until the VM test of the real domain is done. A prepared rule
  (`CLOSE_PREFERENCES_THROUGH_CFPREFSD`, off) closes cfprefsd to the sandbox so preferences are
  written directly and the file rules hold; other preferences keep working. Reading them, and
  running a program from Homebrew's folders, stays allowed. If you meant it, add the job, key or
  line yourself in your own terminal.
- **Your own program folders are closed to writes** (`~/.local/bin`, `~/.cargo/bin`, `~/go/bin`,
  `~/bin`, `~/.npm-global`, `~/Library/Python/*/bin` and every PATH folder inside your home that you
  own): a program an agent left there would run outside the sandbox the next time you type its
  name. Global installs go through Blackbox instead (below). The sandbox permission `tool-folders`
  opens them again. Network Shield's persistence watch still raises a **critical** alert for every
  new program an agent writes into a folder on your PATH.
- Cursor and Windsurf can be opened inside the sandbox from File Shield's page ("Open protected";
  quit the editor first). Blackbox says it is running only once it still runs a few seconds later.
  These editors sandbox their own web pages, and two sandboxes can not nest, so inside Blackbox's
  sandbox the editor runs with its own one off: Blackbox's sandbox then covers the whole editor and
  your protected items, but its web pages lose that extra isolation. Apps from the App Store can not
  be opened inside at all.
- The dashboard shows, per agent session, whether it ran inside the sandbox — proven by a file
  only a sandboxed process can not read, so it can not be faked.

What Layer 2 can not do, plainly:

- An agent started another way (a full path, an IDE that starts it itself) is not inside — it keeps
  Layer 1.
- **sudo and other setuid tools.** macOS does not start a setuid program inside any sandbox, and no
  rule can allow it. `sudo`, `su`, `top`, `crontab -l` (and `at`, `login`, `quota`) answer with
  "Blackbox's sandbox refused this (top): macOS doesn't allow setuid programs inside the agent
  sandbox; run it in your own terminal". `ps` works: the sandbox gets its own copy without the
  setuid bit (first on the sandboxed PATH only; an absolute `/bin/ps` still fails). Use
  `ps -Ao pid,pcpu,comm -r` instead of `top`.
- **Homebrew installs: Blackbox installs for the agent.** Homebrew runs each install inside its own
  sandbox, and macOS will not start a second sandbox inside one (`sandbox_apply: Operation not
  permitted`). So inside the sandbox `brew` is Blackbox's shim: `brew install|upgrade|reinstall|
  uninstall <names>` (and `--cask`) is sent to Blackbox, which accepts package names from
  Homebrew's official taps only (no other tap, URL, file, `--HEAD`, `--build-from-source` / `-s` or
  other flags beyond `--cask`, `--formula`, `--quiet`, `--verbose`), refuses a package a threat rule
  lists, and runs a fixed `/opt/homebrew/bin/brew install <names>` as you, with a clean
  environment, streaming the output back. Each run is recorded and you are notified. Other `brew`
  commands (`list`, `info`, `search`, `outdated`, `deps`) run inside the sandbox as they are.
  It is decided by the sandbox permission `homebrew` (below): `allow` (default: allow and notify),
  `ask` (you answer Allow once / Always for this agent here / Keep blocked) or `block`; the older
  setting `agent_packages.installs` is read until you set the permission. If Blackbox can't be
  reached, nothing is installed and the agent is told to run `brew` in
  your own terminal. **Security cost:** Homebrew's own install scripts run outside the sandbox,
  with your rights, exactly as when you run `brew` yourself. Other tools that sandbox themselves
  (SwiftPM manifest builds, an agent's own sandbox mode) still can't run inside.
- **Opening or driving other apps** goes through Blackbox, never straight from inside: the
  sandbox keeps LaunchServices (`open`) and `osascript` / `automator` / `shortcuts` closed, because
  the other app would do the work outside the sandbox. Blackbox opens a web link, a folder, or a
  file in a named app for the agent, and runs one AppleScript you have read, each under its
  sandbox permission (below). Not covered: a program the agent compiles itself that sends
  AppleEvents through macOS's own frameworks. The only rule that stops that inside a sandbox makes
  every app launch from the agent hang, so it is not used; the OS's own file checks (Layer 3) close it.
- **A folder that holds a protected item** is not swept whole, sandboxed or not: `grep -r … ~` or
  `zip -r b.zip ~/Documents` is refused when `~/Documents` holds a protected folder, with "~/Documents
  contains a protected folder; exclude it or work on a subfolder" — name the subfolders or files you
  need (an exclude option alone is not enough).
- When the sandbox refuses something, the agent is told "Blackbox's sandbox refused this (…)" beside
  the error, and the refusal counts on the session (every kind, not only files).
- A running agent keeps the protection it started with; restart it after you change the list or a
  permission. File Shield's page names each running agent that still has its old permissions and
  offers to stop it (you confirm).
- Linux and Windows: not yet (Layer 1 only there).

## Sandbox permissions

The sandbox is on by default and closes more than an agent sometimes needs. Each ability below is a
**permission** you set to block, ask (you are asked each time: Allow once / Always for this agent
in this project / Keep blocked) or allow — for every agent, one agent, one project folder, or one
agent in one project; the most specific rule wins, in both directions. Turning one up asks you
first (your password or the companion app). A permission enforced by **the profile** reaches an
agent at its next start (the Hermes agent: its next command); one done by **Blackbox** (outside the
sandbox, checked and recorded) applies at once.

| Permission | What it unlocks | Done by | Default | Cost of allowing it |
|---|---|---|---|---|
| Homebrew installs | `brew install/upgrade/reinstall/uninstall` | Blackbox | allow | install scripts run outside, with your rights |
| Global installs | `npm i -g`, `pipx install`, `pip install --user`, `cargo install`, `gem install`, `uv tool install` — names only, threat-checked | Blackbox | allow | install scripts run outside; the program lands on your PATH |
| Writing to your tool folders | direct writes to `~/.local/bin` and the other folders above | profile | block | a program left there runs outside the sandbox later |
| Opening web links | `open https://…` (sign-ins) — threat-checked, http/https only | Blackbox | allow | the page loads outside; a link can carry data out |
| Opening files in apps | `open -a App file`, a folder in Finder — never Terminal or another app that runs commands, never a protected file | Blackbox | ask | the app works on the file outside |
| AppleScript | one `osascript` script at a time, shown to you in full | Blackbox | block (ask: once only, never always) | a full escape for that run |
| Stopping your programs | stopping a stray dev server or a port holder the agent may not signal itself — never Blackbox, macOS, another user's or another agent's process | Blackbox | ask | a wrong process would stop a program you use |
| Docker | the container engine's socket (Docker Desktop, colima, OrbStack, Lima, Podman, Rancher's `~/.rd`) and ports 2375/2376 | profile | ask | a container runs outside and can mount any folder |
| Services on this Mac | connecting to programs listening on this Mac; when blocked, listed ports (and Blackbox's dashboard) stay reachable | profile | allow | the agent can talk to anything on this Mac |
| Clipboard | `pbpaste` and reading what you copied (blocking it also stops copy and paste in an editor opened in the sandbox) | profile | allow | what you copied may be a password |
| Keychain | `security`, git's keychain helper | profile | allow | **not controllable yet** — not proven on a real keychain |
| Camera and microphone | recording | profile | — | **not controllable yet** — not proven on a real device |

**Folder rules** keep a folder out of reach (`none`: no read, no write) or read-only (`read`) for
every agent, one agent or one project — they only ever tighten. Mounting a protected item (or a
folder holding one) into a container is refused by the hooks too (`docker run -v …`).

**Never unlocked**, whatever you set: Blackbox's own files, Hermes' `config.yaml` and `.env`, every
agent's hook settings and your shell startup files, the places something starts from by itself,
your protected items, ssh into this Mac (Seatbelt's `localhost` covers every address of this Mac),
signals to programs outside the sandbox, sudo / setuid programs, and blocking Blackbox's dashboard.
Not controllable at all: screen capture (macOS asks you for the terminal app itself) and setuid tools.

```yaml
plugins:
  entries:
    blackbox:
      agent_sandbox:
        permissions:   # at most 200; a permission not named keeps its default
          - {permission: docker, mode: allow, agent: claude-code, project: "~/work/shop"}
          - {permission: global-installs, mode: ask}
          - {permission: local-ports, mode: block, ports: [5432, 3000]}
        folders:       # at most 100
          - {path: "~/clients", access: none}
          - {path: "~/work/shop/secrets", access: read, agent: codex}
```

Agents on hooks only (not in the sandbox) get the folder rules and the startup places through their
hooks; the other permissions need the sandbox. The hook reads the same folder rules the profile is
built from, for the agent and the folder it works in: a folder kept out refuses any touch (reading,
listing, a `cd`, writing, a whole-tree command on a folder above it); a read-only folder refuses
writes, redirects, deletes, moves, new files and permission changes there, and stays readable. Like
every hook check, it judges what a call names: a program that builds a path while it runs is stopped
only by the sandbox.

## Setting

```yaml
plugins:
  entries:
    blackbox:
      shields:
        file-shield:
          enabled: true
          protected: ["~/Documents/Taxes", "~/.config/my-app/token.json"]
          folders: ["~/Downloads"]
          sandboxed: ["claude-code", "codex"]   # Layer 2 — taking one off asks you first
```

The whole disk, your whole home folder and the folders that hold every user (`/Users`) cannot be
protected: that would stop every agent from working at all.

## Endpoints

`/api/shields/file-shield/api/<name>` — reads `protected`, `hits`, `changes`, `sandbox` (which agents
are sandboxed, their launchers, the editors that can be opened inside), `watch-plan` (signed, for
the helper), `permissions` (the permissions, your rules, the never-list, `restart_needed`),
`permission-requests`, `brew-job`, `install-job`; writes `protect`, `unprotect` (held for your
approval), `open-protected` (`{"app": "cursor"}`), `file-report` (the helper's, signed — including
the sandbox's refusals), `permission-set` / `permission-clear` / `folder-set` / `folder-clear`
(turning up is held for your approval), `permission-answer` (`{"id", "choice"}`), `stop-agent`
(held for your approval), and the brokers `brew`, `install`, `open-link`, `open-app`, `applescript`.
