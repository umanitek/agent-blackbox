# GitHub Copilot CLI: how Blackbox protects it

**Docs reviewed:** https://docs.github.com/en/copilot (the hooks pages for Copilot CLI and the coding agent; accessed 2026-11-21; the page states no version). Sections reviewed: hook files (`version`, `hooks`), preToolUse (`permissionDecision`), postToolUse, userPromptSubmitted, sessionStart / sessionEnd.

**Hook config:** `~/.copilot/hooks/blackbox.json` (a file of Blackbox's own; `{"version":1,"hooks":{...}}`). The docs describe repository hooks in `.github/hooks/*.json`. The user-level folder must be **verified on the VM**.

## Events

| Copilot event | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `sessionStart` / `sessionEnd` | session_start / stop | session | record |
| `userPromptSubmitted` | prompt | `prompt` | **record and flag only**. The docs say this hook's output is ignored |
| `preToolUse` | pre_tool | `toolName`, `toolArgs` | **refuse**: `{"permissionDecision":"deny"}` |
| `postToolUse` | post_tool | `toolResult.textResultForLlm` | **record and flag only**. The output is ignored, as documented |

## Tool mapping
`bash` becomes `terminal`. `edit` / `create` (`path`, `new_str` / `file_text`) become `write_file`. `create` was allowed on Blackbox's files before 2026-11-21. `view` becomes `read_file`.

## Gaps
Injections in a prompt or a tool output can only be **recorded**. The block that matters, a tool call that follows the injection, is still refused at preToolUse. "ask" support varies by version.

## VM test
`npm i -g @github/copilot`. It needs a GitHub sign-in with a Copilot seat.
- Confirm the hook folder.
- Expect preToolUse denials, and prompt and output injections recorded.

## Re-read 2026-11-22

Source: <https://docs.github.com/en/copilot/reference/hooks-configuration>.

- `subagentStart`, `subagentStop` and `agentStop` are hooked; hooks inside a sub-agent carry `agentId` / `agentType`. `COPILOT_HOME` moves the home (hooked when learned).
- The Copilot cloud agent reads only `.github/hooks/*.json` in the repository: not covered.
