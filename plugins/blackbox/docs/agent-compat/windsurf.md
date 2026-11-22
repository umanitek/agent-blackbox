# Windsurf (Devin): how Blackbox protects it

**Docs reviewed:** https://docs.devin.ai/desktop/cascade/hooks (accessed 2026-11-21). Windsurf ships as Devin.app since 2026-11, and the docs moved from docs.windsurf.com. Sections reviewed: hook events, `tool_info` fields, exit-code behaviour (exit 2 = block, pre-hooks only), configuration locations.

**Hook config:** `~/.codeium/windsurf/hooks.json` (flat). The renamed docs also mention `.windsurf/hooks.json` and `.devin/hooks.v1.json`. **Which user-level file Devin reads must be verified on the VM.**

## Events

| Windsurf event | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `pre_user_prompt` | prompt | `tool_info.user_prompt` | **refuse**: exit 2 |
| `pre_run_command` | pre_tool | `tool_info.command_line` | **refuse**: exit 2 |
| `pre_read_code` | pre_tool | `tool_info.file_path`; **Blackbox reads the file** (regular files, bounded) | **refuse the read** of a file carrying a verified injection, or of a protected file |
| `pre_write_code` | pre_tool | `file_path` + `edits` | **refuse** |
| `pre_mcp_tool_use` | pre_tool | tool + input | **refuse** |
| `post_run_command` | post_tool | `tool_info.output` | record and flag only (post-hooks cannot block) |

## VM test
Devin.app needs a sign-in.
- Confirm the hooks file.
- `cat` the injection file → expect pre_read_code to refuse it.
- Prompt with the injection → expect it refused.
- Delete Blackbox's plugin → expect it refused.

## Re-read 2026-11-22: the vendor's docs moved

The Cascade hooks page now redirects to Devin Local's customisation page, which describes Devin's own hooks (`.devin/hooks.v1.json`, a `hooks` key in `~/.config/devin/config.json`). Blackbox keeps the Cascade hooks file for installs that still read it and adds a separate **Devin** entry (see `devin.md`). Whether a current Devin.app still reads `~/.codeium/windsurf/hooks.json` is unverified.
