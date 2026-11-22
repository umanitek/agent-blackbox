# File Shield — keeping AI agents away from what you protect

File Shield is Blackbox's third shield. You choose files and folders; no AI agent may touch them.
It is switched on in Settings (or from Blackbox Desktop), like Trader Shield and Network Shield.

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
  File Shield page, in the dashboard and in Blackbox Desktop. These findings never leave your
  machine and never carry a file's contents.
* **Real time.** With the system protection helper installed, the helper watches every protected
  item and every watched folder with the operating system's own file events (FSEvents on macOS) and
  reports each change within about a second, signed with the helper's key.

## How far it reaches — plainly

This is **Layer 1**: Blackbox's guard, which sees every tool call an agent makes. What it cannot
see: a program an agent wrote or downloaded, and then runs, opens files without naming them in a
tool call. Layer 1 cannot tell which files such a program opens.

Only the operating system can see every file a process opens. That is **Layer 2**, the agent
sandbox, for the coding agents you pick (macOS today):

- Blackbox writes a launcher for each agent you pick (`claude`, `codex`, `cursor-agent`, `gemini`,
  `copilot`, `cline`, `opencode`) and puts its folder first on your PATH (one marked block at the
  end of `~/.zshrc`, and `~/.bashrc` / `~/.bash_profile` when you have them). Starting the agent
  from a terminal then starts it inside macOS's own sandbox, built from your protected list.
- Inside it, nothing the agent starts — a script, a program it compiled, Python, a shell — can
  open, copy, list, change, move, link or delete a protected item, or rename a folder above one,
  or change Blackbox itself. The kernel refuses it; no hook is needed and none can be skipped.
  Each refusal is shown with the program's name and counts as a File Shield hit.
- Cursor and Windsurf can be opened inside the sandbox from File Shield's page ("Open protected";
  quit the editor first).
- The dashboard shows, per agent session, whether it ran inside the sandbox — proven by a file
  only a sandboxed process can not read, so it can not be faked.

What Layer 2 can not do, plainly:

- An agent started another way (a full path, an IDE that starts it itself) is not inside — it keeps
  Layer 1.
- A sandboxed agent can not run `sudo` (no sandbox can run setuid programs) — that is why you pick
  agents one by one.
- It does not stop an agent driving another app with AppleEvents (`osascript`): that app does the
  work outside the sandbox.
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
