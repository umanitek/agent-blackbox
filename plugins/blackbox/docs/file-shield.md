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
  `process.argv`, `ARGV`, `$1`), in the folder the agent works in.

What only the sandbox (Layer 2, below) stops, because no text says which file will be opened:

- a path a program builds while it runs from anything else — input it reads, a file or the network,
  environment variables other than the home folder, values it computes;
- a compiled program, or a script fetched and run in one go;
- a script larger than 256 KiB (flagged, not judged);
- Hermes's `execute_code` tool beyond what its code text says: Hermes starts that Python by its
  full path, outside the sandboxed shells, so it stays on Layer 1 even when the Hermes agent is
  picked for the sandbox (shown as "terminal tool sandboxed; execute_code hooks only").

When a script that reads its paths at run time is run beside a protected item, or is too large to
read, File Shield flags it and says why, rather than showing a plain "allowed".

Only the operating system can see every file a process opens. That is **Layer 2**, the agent
sandbox, for the coding agents you pick (macOS today):

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
- A sandboxed agent can not run `sudo` (no sandbox can run setuid programs) — that is why you pick
  agents one by one.
- Driving another app is refused inside: `osascript` (AppleScript and JavaScript), `automator`,
  `shortcuts` and `open` (the other app would do the work outside the sandbox). Not covered: a
  program the agent compiles itself that sends AppleEvents through macOS's own frameworks. The
  only rule that stops that inside a sandbox makes every app launch from the agent hang (opening
  a browser to log in, `open`), so it is not used; the OS's own file checks (Layer 3) close it.
- A running agent keeps the protection it started with; restart it after you change the list.
- Linux and Windows: not yet (Layer 1 only there).

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
the helper); writes `protect`, `unprotect` (held for your approval), `open-protected`
(`{"app": "cursor"}`), `file-report` (the helper's, signed — including the sandbox's refusals).
