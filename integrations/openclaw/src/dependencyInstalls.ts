/**
 * Which packages a shell command installs by name — the OpenClaw runtime's copy of
 * `plugins/blackbox/detection/command_line/dependency_installs.py` (the canonical side; read its
 * module doc for the why of every rule). `pip install evil==1.0` is pypi `evil` `1.0`.
 *
 * The words are the shell's own (`splitWords`, the ONE lexer in shellFiles.ts), so quoting or
 * escaping a name changes nothing: `pip install e"v"il`, `ev\il` and `npm install e''vil` all
 * install `evil`. A requirement is read the way pip reads it — extras and every comparison taken
 * off the name; only an exact pin (`==` / `===`) gives a version. An option's value
 * (`-r req.txt`, `--index-url URL`, `--registry URL`) is never a package.
 *
 * Held to the Python by `tests/parity/shell_files_fixtures.json` ("installs") through
 * `test/shell-files-parity.mjs`, and by `identifier_fixtures.json` ("dependencyParses").
 *
 * Usage:
 *   parseDependencyInstalls('pip install "evil[x]>=1" requests==2.31.0')
 *   // [{ ecosystem: "pypi", name: "evil", version: "" }, { ecosystem: "pypi", name: "requests", version: "2.31.0" }]
 */
import { SEPARATORS, splitWords } from "./shellFiles.js";

export interface ParsedPackage {
  ecosystem: string;
  name: string;
  version: string;
}

/** The cheap gate, read with quotes and backslashes taken out: no manager word, no parse. */
const MANAGER_WORD = /(?<![\p{L}\p{N}_])(?:pip|uv|uvx|pipx|npm|pnpm|yarn|bun|bunx|npx|cargo|gem|brew)/iu;
// Python's `$` (no MULTILINE) also matches just before a final newline: `(?=\n?$)` is that in JS.
const PIP = /^pip(?:\d+(?:\.\d+)*)?(?=\n?$)/;
const PYTHON = /^python(?:\d+(?:\.\d+)*)?(?=\n?$)/;
/** manager → {subcommand (or "" for none): ecosystem}. */
const MANAGERS: Record<string, Record<string, string>> = {
  pip: { install: "pypi" },
  uv: { add: "pypi" },
  uvx: { "": "pypi" },
  pipx: { install: "pypi", run: "pypi" },
  npm: { install: "npm", i: "npm", add: "npm" },
  pnpm: { add: "npm", dlx: "npm" },
  yarn: { add: "npm", dlx: "npm" },
  bun: { add: "npm", install: "npm", i: "npm" },
  npx: { "": "npm" },
  bunx: { "": "npm" },
  cargo: { add: "cargo" },
  gem: { install: "rubygems" },
  brew: { install: "homebrew" },
};
/** Two-word subcommands: `uv pip install`, `uv tool install|run`, `yarn global add`. */
const DEEPER: Record<string, readonly string[]> = { "uv pip": ["install"], "uv tool": ["install", "run"], "yarn global": ["add"] };
/** Subcommands that run the first package they name; every later word is its own argument. */
const RUNS_FIRST = new Set(["", "run", "dlx"]);
/** Options whose next word is their value (a file, an address, a folder), never a package. */
const VALUE_OPTIONS = new Set([
  "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
  "--index", "--default-index", "-f", "--find-links", "-t", "--target", "--python", "-p", "--prefix", "--root",
  "--src", "--platform", "--python-version", "--implementation", "--abi", "--cache-dir", "--trusted-host",
  "--proxy", "--timeout", "--retries", "--cert", "--client-cert", "--log", "--report", "--exists-action",
  "--upgrade-strategy", "--progress-bar", "--group", "--extra", "--registry", "--tag", "--cache", "--userconfig",
  "-C", "--dir", "--cwd", "--filter", "-w", "--workspace", "--otp", "--scope", "--omit", "--include",
  "--install-strategy", "--source", "--version", "-v", "--install-dir", "--bindir", "--features", "-F",
  "--manifest-path", "--package", "--rename", "--branch", "--rev", "--git", "--path",
]);
/** Options that take a value only for one ecosystem (`-v` is gem's version, a flag elsewhere). */
const ECOSYSTEM_ONLY: Record<string, string> = { "-v": "rubygems", "--version": "rubygems", "-p": "pypi", "-F": "cargo", "-C": "npm" };
/** A PEP 508 requirement: the name, optional extras, then an optional version clause. */
const REQUIREMENT = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*((?:===|==|~=|!=|>=|<=|<|>|@|;).*)?(?=\n?$)/;
const EXACT_PIN = /^===?\s*([A-Za-z0-9._+!-]+)\s*(?:;.*)?(?=\n?$)/;
const NOT_A_NAME = ["http://", "https://", "/", ".", "~", "git+", "file:", "@git"];
const ARCHIVE_ENDINGS = [".whl", ".tar.gz", ".tgz", ".zip", ".gem"];
const NPM_NAME = /^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/;
const OTHER_NAME = /^[A-Za-z0-9._+/-]+$/;

/** `{name, version}` for one install word in `ecosystem`, or null when it names no package. */
function packageOf(raw: string, ecosystem: string): { name: string; version: string } | null {
  const token = raw.trim();
  if (!token || NOT_A_NAME.some((prefix) => token.startsWith(prefix)) || ARCHIVE_ENDINGS.some((end) => token.toLowerCase().endsWith(end))) {
    return null;
  }
  if (ecosystem === "pypi" || ecosystem === "rubygems") {
    const found = REQUIREMENT.exec(token);
    if (!found) return null;
    const pin = EXACT_PIN.exec(found[2] ?? "");
    return { name: found[1]!, version: pin ? pin[1]! : "" };
  }
  const at = token.lastIndexOf("@");
  if (at > 0) return { name: token.slice(0, at), version: token.slice(at + 1) };   // a scoped npm name starts with @
  return (ecosystem === "npm" ? NPM_NAME : OTHER_NAME).test(token) ? { name: token, version: "" } : null;
}

/** `[ecosystem, subcommand, where its packages start]` for a manager word at `index`, else `["", "", -1]`. */
function managerAt(words: string[], index: number): [string, string, number] {
  const word = words[index]!;
  let name = word.slice(word.lastIndexOf("/") + 1).toLowerCase();
  if (PYTHON.test(name) && words[index + 1] === "-m" && index + 2 < words.length) {
    index += 2;
    name = words[index]!.toLowerCase();
  }
  if (PIP.test(name)) name = "pip";
  const table = Object.hasOwn(MANAGERS, name) ? MANAGERS[name]! : null;
  if (!table) return ["", "", -1];
  const sub = index + 1 < words.length ? words[index + 1]!.toLowerCase() : "";
  const deeper = Object.hasOwn(DEEPER, `${name} ${sub}`) ? DEEPER[`${name} ${sub}`]! : null;
  if (deeper) {
    const third = index + 2 < words.length ? words[index + 2]!.toLowerCase() : "";
    if (!deeper.includes(third)) return ["", "", -1];
    return [name === "uv" ? "pypi" : "npm", third === "run" ? "run" : third, index + 3];
  }
  if (Object.hasOwn(table, "")) return [table[""]!, "", index + 1];
  return Object.hasOwn(table, sub) ? [table[sub]!, sub, index + 2] : ["", "", -1];
}

/**
 * Every package `command` installs by name, as `[{ecosystem, name, version}, ...]` in order, each
 * once (see the module doc). Empty when the command installs nothing by name.
 */
export function parseDependencyInstalls(command: string): ParsedPackage[] {
  if (!command || !MANAGER_WORD.test(command.replace(/["'\\]/g, ""))) return [];
  const words = splitWords(command);
  const out: ParsedPackage[] = [];
  const seen = new Set<string>();
  let index = 0;
  while (index < words.length) {
    const [ecosystem, sub, start] = managerAt(words, index);
    if (start < 0) { index += 1; continue; }
    index = start;
    while (index < words.length && !SEPARATORS.has(words[index]!)) {
      const word = words[index]!;
      index += 1;
      if (word.startsWith("-")) {
        if (VALUE_OPTIONS.has(word) && (ECOSYSTEM_ONLY[word] ?? ecosystem) === ecosystem) index += 1;
        continue;
      }
      const parsed = packageOf(word, ecosystem);
      if (!parsed) continue;
      const key = `${ecosystem}:${parsed.name.toLowerCase()}:${parsed.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ ecosystem, name: parsed.name, version: parsed.version });
      }
      if (RUNS_FIRST.has(sub)) break;   // `npx pkg arg…`: only the first word is a package, the rest are its arguments
    }
    while (index < words.length && !SEPARATORS.has(words[index]!)) index += 1;
  }
  return out;
}
