# OpenCode: how Blackbox protects it

**Docs reviewed:** https://opencode.ai/docs/plugins (accessed 2026-11-21). Sections reviewed: plugin loading from `~/.config/opencode/plugin/`, `tool.execute.before` (throwing blocks), `tool.execute.after` (may change `output.output`), the v2 `ctx.tool.hook("execute.before")` note (legacy names fail silently on v2).

**Hook config:** `~/.config/opencode/plugin/blackbox.js`, a plugin file of Blackbox's own. It runs the runner with Node's `spawnSync` and fails open.

## Events

| OpenCode hook | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `tool.execute.before` | pre_tool | `tool`, `args` | **refuse**: the plugin throws Blackbox's reason |
| `tool.execute.after` | post_tool | `output.output` (bounded 256 KB) | **replace the output**: the plugin sets `output.output` to Blackbox's notice |

## Tool mapping
`bash` becomes `terminal`. `edit` and `write` (`filePath`, `newString` / `content`) become `write_file`. `filePath` was not read before 2026-11-21, so edits to Blackbox's files were allowed. `read` becomes `read_file`.

## Gaps
- No prompt hook is wired. Whether `chat.message` can block is not documented, so prompts are not checked. The tool call an injected prompt leads to is still checked.
- OpenCode **v2** plugins use `ctx.tool.hook(...)`, and the legacy names used here fail silently there. **Verify the installed version on the VM.** If it is v2, the plugin template needs the v2 form.

## VM test
`npm i -g opencode-ai`. It needs a provider key. A free OpenCode Zen model may run without a paid key; verify.
- Edit Blackbox's plugin → expect the throw.
- `cat` the injection file → expect the output replaced.
