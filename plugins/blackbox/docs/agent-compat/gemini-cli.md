# Gemini CLI: how Blackbox protects it

**Docs reviewed:** https://geminicli.com/docs/hooks/reference (accessed 2026-11-21; the page states no version). Sections reviewed: hook events, BeforeTool / AfterTool / BeforeAgent decisions, `settings.json` `hooks`, `hooksConfig.enabled` / `hooksConfig.disabled`.

**Hook config:** `~/.gemini/settings.json` → `hooks` (nested, matcher `.*`).

## Events

| Gemini event | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `SessionStart` | session_start | session | record |
| `BeforeAgent` | prompt | `prompt` | **refuse the turn** (the message is dropped): `{"decision":"deny","reason"}` |
| `BeforeTool` | pre_tool | `tool_name`, `tool_input` | **refuse the tool** |
| `AfterTool` | post_tool | `tool_response` (`llmContent`) | **replace the result** with Blackbox's reason: `{"decision":"deny"}` |
| `SessionEnd` | stop | session | record |

## Tool mapping
`run_shell_command` becomes `terminal`. `write_file` and `replace` become `write_file` (`file_path`, `content` / `new_string`). `read_file` and `read_many_files` become `read_file`.

## Self-protection
Editing `settings.json` to remove Blackbox's hook, or to set `hooksConfig.disabled`, is refused. An unrelated edit to the file is allowed.

## VM test
`npm i -g @google/gemini-cli`. Run `gemini` with a Google sign-in, or `GEMINI_API_KEY`.
- Same checks as the others; expect AfterTool to replace the output with the reason.
