/**
 * shellFiles.ts, escalationShapes.ts and dependencyInstalls.ts must answer exactly as the canonical
 * Python (detection/paths/shell_files.py, detection/command_line/): the same words for every
 * command, the same path arguments, the same escalation shapes and the same installs by name,
 * against the shared fixture tests/parity/shell_files_fixtures.json (regenerate:
 * tests/parity/generate_shell_files.py).
 *
 * Node loads the .ts files as they are (type stripping, Node >= 22.18); the source imports its
 * siblings as `./x.js` (what tsc and esbuild resolve), so a resolve hook maps such an import to
 * the `.ts` beside it — no build, no tsx:
 *   node integrations/openclaw/test/shell-files-parity.mjs
 * Exits non-zero on any mismatch; prints "PASS <n> cases" on success.
 */
import { readFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith(".") && specifier.endsWith(".js") && context.parentURL?.endsWith(".ts")) {
      return next(specifier.slice(0, -3) + ".ts", context);
    }
    return next(specifier, context);
  },
});
const { codeFileArgs, shellFileArgs, splitWords, withNestedCommands } = await import("../src/shellFiles.ts");
const { shapesOf } = await import("../src/escalationShapes.ts");
const { parseDependencyInstalls } = await import("../src/dependencyInstalls.ts");

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(here, "..", "..", "..", "tests", "parity", "shell_files_fixtures.json"), "utf8"));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const failures = [];
for (const { command, words, args } of fixture.commands) {
  const gotWords = command ? splitWords(command) : [];
  if (!same(gotWords, words)) failures.push({ command, expectedWords: words, gotWords });
  const got = shellFileArgs(command);
  if (!same(got, args)) failures.push({ command, expected: args, got });
}
for (const { code, args } of fixture.code) {
  const got = codeFileArgs(code);
  if (!same(got, args)) failures.push({ code, expected: args, got });
}
for (const { command, read } of fixture.nested) {
  const got = withNestedCommands(command);
  if (got !== read) failures.push({ command, expectedRead: read, got });
}
for (const { command, shapes } of fixture.shapes) {
  const got = shapesOf(command);
  if (!same(got, shapes)) failures.push({ command, expectedShapes: shapes, got });
}
for (const { command, packages } of fixture.installs) {
  const got = parseDependencyInstalls(command);
  if (!same(got, packages)) failures.push({ command, expectedPackages: packages, got });
}
if (failures.length) {
  console.error(JSON.stringify(failures, null, 1));
  console.error(`FAIL ${failures.length} mismatches`);
  process.exit(1);
}
const cases = fixture.commands.length + fixture.code.length + fixture.nested.length + fixture.shapes.length + fixture.installs.length;
console.log(`PASS ${cases} cases`);
