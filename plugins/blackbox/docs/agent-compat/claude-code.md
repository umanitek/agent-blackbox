# Claude Code: how Blackbox protects it

**Docs reviewed:** https://code.claude.com/docs/en/hooks (accessed 2026-11-21, the latest published page; it states no version). Sections reviewed: Hook events, Hook input, PreToolUse decision control, UserPromptSubmit decision control, PostToolUse decision control, Exit code behaviour, Configuration (`settings.json`).

**Hook config Blackbox writes:** `~/.claude/settings.json` → `hooks` (nested style, matcher `*`), one entry per event, running the Blackbox runner. Only Blackbox's entry is added; the person's own hooks are kept.

## Events → what Blackbox does

| Claude Code event | Blackbox event | Sent to the local guard | Blackbox can |
|---|---|---|---|
| `SessionStart` | session_start | session | record |
| `UserPromptSubmit` | prompt | `prompt` (bounded 256 KB) | **refuse the prompt**: `{"decision":"block","reason"}` |
| `PreToolUse` | pre_tool | `tool_name` + full `tool_input` | **refuse the tool**: `hookSpecificOutput.permissionDecision: "deny"` |
| `PostToolUse` | post_tool | `tool_response` (bounded 256 KB) | **flag the output to the model**: `{"decision":"block","reason"}` + `additionalContext`. Claude still sees the output; the reason sits beside it |
| `Stop` / `SessionEnd` | turn_end / stop | session | record |

## Tool mapping (self-protection)
`Bash.command` becomes `terminal`. `Write`/`Edit`/`MultiEdit` become `write_file` (`file_path`, plus `content` or `new_string`). `NotebookEdit` becomes `write_file` (`notebook_path`, `new_source`); before 2026-11-21 it was allowed on Blackbox's files. `Read` becomes `read_file`.

## Gaps
- PostToolUse cannot remove the output unless `updatedToolOutput` is used. Blackbox puts its reason beside the output instead (the decision is recorded).
- A tool Claude runs on a remote server (an MCP connector in the cloud) has no local hook.

## Tests
`tests/plugins/test_blackbox_agent_security.py` and `test_blackbox_agent_hooks.py`: the prompt and output reach the guard; a verified injection is blocked in Block mode and only flagged in Audit; the deny format; NotebookEdit on an add-on folder in the Hermes home is refused; dashboard curl and service kills are refused; nothing beyond the matched phrase is recorded.

## VM test
`npm i -g @anthropic-ai/claude-code`. It needs a sign-in (an Anthropic account or API key), so it cannot run unsigned.
- Protect Claude Code in Blackbox → Agents.
- Ask it to `cat` a file containing an injection phrase from the verified graph → expect the PostToolUse reason, and an injection finding under claude-code.
- Paste the injection as a prompt → expect it refused.
- Ask it to `rm -rf ~/.hermes/plugins/blackbox` → expect it refused.
- Ask it to edit `~/.claude/settings.json` to remove Blackbox → expect it refused.
