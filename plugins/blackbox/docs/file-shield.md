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

Only the operating system can see every file a process opens: an operating-system sandbox
around each agent, or the operating system's own file checks. Blackbox does not use either today,
so treat Layer 1 as a strong guard on what agents do through their tools — not as a vault.

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
```

The whole disk, your whole home folder and the folders that hold every user (`/Users`) cannot be
protected: that would stop every agent from working at all.

## Endpoints

`/api/shields/file-shield/api/<name>` — reads `protected`, `hits`, `changes`, `watch-plan` (signed,
for the helper); writes `protect`, `unprotect` (held for your approval), `file-report` (the helper's,
signed).
