# Codex CLI: how Blackbox protects it

**Docs reviewed:** https://developers.openai.com/codex/hooks (accessed 2026-11-21; hooks are documented as stable since Codex **v0.124**). Sections reviewed: Configuration (`hooks.json` / `[hooks]` in `config.toml`), PreToolUse, PostToolUse, UserPromptSubmit, matchers, Limitations (hosted tools).

**Hook config:** `~/.codex/hooks.json` (nested). Codex asks the person to trust new hooks once: run `codex`, type `/hooks` and trust Blackbox's.

## Events

| Codex event | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `SessionStart` | session_start | session | record |
| `UserPromptSubmit` | prompt | `prompt` | **refuse the prompt**: `{"decision":"block","reason"}` (matchers are ignored for this event, as documented) |
| `PreToolUse` | pre_tool | `tool_name`, `tool_input` | **refuse**: `hookSpecificOutput.permissionDecision: "deny"` |
| `PostToolUse` | post_tool | `tool_response` | **replace the output** with Blackbox's reason: `{"decision":"block","reason"}` |
| `Stop` | turn_end | session | record |

## Tool mapping
`shell` (`command` as a string or argv) becomes `terminal`. `apply_patch` (patch text in `input`/`patch`, or inside argv) is judged **file by file**: each `*** Add/Update/Delete File:` and `*** Move to:` becomes a `write_file` check. Before 2026-11-21 a patch passed in `input` that deleted Blackbox's files was allowed.

## Gaps
- Hosted tools (web search run by OpenAI) have no local hook, as documented.

## Tests
`test_blackbox_agent_security.py`: both apply_patch shapes are refused on an add-on folder in the Hermes home; the prompt is blocked; the output is blocked and replaced (`post_output`).

## VM test
`npm i -g @openai/codex`. It needs a ChatGPT sign-in or API key.
- Protect it, then trust the hook via `/hooks`.
- Same four checks as Claude Code, plus "apply a patch that deletes `~/.hermes/plugins/blackbox/__init__.py`" → expect it refused.

## Re-read 2026-11-22: instances, profiles, switches

Source: <https://developers.openai.com/codex/hooks>, <https://developers.openai.com/codex/config-advanced>.

- **Sub-agents are tracked:** `SubagentStart` / `SubagentStop` carry the PARENT `session_id` plus `agent_id` and `agent_type`; `SessionEnd` now ends the session (it does not run for sub-agents).
- **Profiles:** `CODEX_HOME` moves the home (hooked when learned). `--profile <name>` only layers `<name>.config.toml` over the same home, so the same `hooks.json` applies.
- **What keeps hooks from running:** an untrusted hook (Codex records trust per hook hash, so NEW events mean one more `/hooks` review), `[features].hooks = false`, `allow_managed_hooks_only` in `requirements.toml`, and Codex Cloud (local hooks do not run there). Hosted tools such as WebSearch do not pass the hook path.
