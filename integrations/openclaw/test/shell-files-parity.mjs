/**
 * shellFiles.ts must answer exactly as the canonical Python (detection/paths/shell_files.py):
 * the same words for every command and the same path arguments, against the shared fixture
 * tests/parity/shell_files_fixtures.json (regenerate: tests/parity/generate_shell_files.py).
 *
 * shellFiles.ts imports nothing, so Node loads it as it is (type stripping, Node >= 22.18):
 *   node integrations/openclaw/test/shell-files-parity.mjs
 * Exits non-zero on any mismatch; prints "PASS <n> cases" on success.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { codeFileArgs, shellFileArgs, splitWords } from "../src/shellFiles.ts";

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
if (failures.length) {
  console.error(JSON.stringify(failures, null, 1));
  console.error(`FAIL ${failures.length} mismatches`);
  process.exit(1);
}
console.log(`PASS ${fixture.commands.length + fixture.code.length} cases`);
