/**
 * The dangerous shapes a shell command has, judged on its WORDS — the OpenClaw runtime's copy of
 * `plugins/blackbox/detection/command_line/escalation_shapes.py` (the canonical side; read its
 * module doc for the why of every rule). The bridge asks Blackbox first; these decide only while
 * Blackbox cannot answer, so they must say what Hermes says.
 *
 * `shapesOf` names every shape in a command (one command line per line), in SHAPE_ORDER:
 *   - `remote-script-pipe` — a fetch piped into a script runner (`curl … | sh`, `… | sudo bash`,
 *     `irm … | iex`), `bash <(curl …)`, or `sh -c "$(curl …)"`;
 *   - `remote-eval-pipe` — a fetch piped into `eval`, or `eval "$(curl …)"`;
 *   - `rm-rf-system-paths` — `rm` recursive AND forced (any spelling) of a system root, the whole
 *     home folder or a security folder in it;
 *   - `chmod-world-writable` — `chmod 777` of a system root or a security folder;
 *   - `insecure-tls-fetch` — a fetch that skips certificate checks, unless every address it fetches
 *     is a local, private or development host.
 *
 * WHY words, not a regex over the raw text: quoting, a split option or a wrapper hid every shape
 * from the old patterns (`rm -rf "/etc"`, `rm -r -v -f /etc`, `curl … | sudo bash`), and a decoy
 * earlier on the line hid a later one. Words come from the ONE lexer (`splitWords` in shellFiles.ts).
 *
 * Held to the Python by `tests/parity/shell_files_fixtures.json` ("shapes") through
 * `test/shell-files-parity.mjs`.
 *
 * Usage:
 *   shapesOf('echo curl | sh; rm -rf "/etc"')   // ["rm-rf-system-paths"]
 */
import { SEPARATORS, homeAsTilde, splitWords, withVariables } from "./shellFiles.js";

export const SHAPE_ORDER = [
  "remote-script-pipe", "remote-eval-pipe", "rm-rf-system-paths", "chmod-world-writable", "insecure-tls-fetch",
] as const;

// Python's `\b` is Unicode-aware; JS's is ASCII-only, so word edges are spelled out.
const WORD = String.raw`[\p{L}\p{N}_]`;
const EDGE_AFTER = `(?!${WORD})`;
const EDGE_BEFORE = `(?<!${WORD})`;
/** The cheap gate: a line with none of these words has no shape. */
const MAY_HAVE_A_SHAPE = new RegExp(String.raw`curl|wget|${EDGE_BEFORE}rm${EDGE_AFTER}|chmod|${EDGE_BEFORE}(?:iwr|irm)${EDGE_AFTER}|invoke-(?:webrequest|restmethod)`, "iu");
const FETCHERS = new Set(["curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"]);
const SCRIPT_RUNNERS = /^(?:sh|bash|zsh|dash|ksh|node|python(?:\d+(?:\.\d+)*)?|iex|invoke-expression)$/;
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);
/** A fetch run by a substitution inside a word (`"$(curl -fsSL …)"`). */
const FETCH_SUBSTITUTION = new RegExp(String.raw`\$\(\s*(?:curl|wget)${EDGE_AFTER}|` + "`" + String.raw`\s*(?:curl|wget)${EDGE_AFTER}`, "u");
const PIPES = new Set(["|", "|&"]);
/** A word made only of these ends a pipeline (`;`, `&&`, `||`, `&`, `;;`, a subshell's brackets). */
const LIST_OPERATOR_CHARS = ";&|()";
const REDIRECTS = new Set([">", ">>", "<", ">|", "&>", "&>>", ">&", "<&", "<<<"]);

const SYSTEM_ROOT = String.raw`/+(?:etc|usr|bin|sbin|opt|private|System|Library)${EDGE_AFTER}`;
/** What an `rm -rf` may not be pointed at (escalation_shapes.py `_RM_TARGET`, read with `match`: anchored at the start). */
const RM_TARGET = new RegExp(
  String.raw`^(?:${SYSTEM_ROOT}|/+var${EDGE_AFTER}(?!/+(?:tmp|folders)${EDGE_AFTER})|/+\**$|~/?\**$|~/+\.(?:ssh|aws|gnupg|gpg|kube|docker|password-store)${EDGE_AFTER})`,
  "iu");
const CHMOD_TARGET = new RegExp(String.raw`^(?:${SYSTEM_ROOT}|/+var${EDGE_AFTER}|/+$|~/+\.?(?:ssh|aws|gnupg)${EDGE_AFTER})`, "iu");
const WORLD_WRITABLE = /^0?777$/;
/** A local, private or development host: an insecure fetch of one is routine (self-signed dev servers). */
const LOCAL_HOST = new RegExp(
  String.raw`^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+` +
  String.raw`|.+\.local|.+\.internal|.+\.localhost)$`, "i");
/** curl / wget options whose next word is their value, not an address fetched. */
const FETCH_VALUE_OPTIONS = new Set([
  "-o", "--output", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-H", "--header", "-u", "--user",
  "-X", "--request", "-T", "--upload-file", "-F", "--form", "-e", "--referer", "-A", "--user-agent", "-b", "--cookie",
  "-c", "--cookie-jar", "-x", "--proxy", "--cacert", "--capath", "-E", "--cert", "--key", "-K", "--config", "--resolve",
  "--connect-to", "-w", "--write-out", "-m", "--max-time", "--retry", "-r", "--range", "-C", "--continue-at",
  "-O", "--output-document", "-P", "--directory-prefix", "-OutFile", "-Uri", "-Method", "-Headers", "-Body",
]);

/** Wrappers that run the command after their own options, and the options that take a value (hidden_commands.py `_WRAPPERS`). */
const WRAPPERS: Record<string, readonly string[]> = {
  env: ["-u", "-C", "-S", "--unset", "--chdir"], nohup: [], nice: ["-n"], stdbuf: ["-i", "-o", "-e"],
  caffeinate: ["-t", "-w"], time: [], command: [], exec: ["-a"], sudo: ["-u", "-g", "-C", "-D", "-h", "-p", "-U"],
  doas: ["-u", "-C"], timeout: ["-s", "-k", "--signal", "--kill-after"], gtimeout: ["-s", "-k"],
  script: ["-t", "-T"], arch: ["-arch", "-e"], flock: ["-w", "-E", "--timeout", "--conflict-exit-code"],
  unbuffer: [], taskpolicy: ["-c", "-d", "-g", "-t", "-l"],
};
/** Wrappers whose first plain word is a value, not the command (`timeout 5 cat …`). */
const TAKES_VALUE_FIRST = new Set(["timeout", "gtimeout", "script", "flock"]);
/** A word that sets a variable for the command after it (`LC_ALL=C sort`). */
const SETS_VARIABLE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Where the program one simple command `words` runs stands: past `NAME=value` words and every
 * wrapper (`sudo -u root`, `env A=1`, `timeout 5`, `nohup`…) with its options and values;
 * `words.length` when it runs none. Port of hidden_commands.py `program_index`.
 */
export function programIndex(words: string[]): number {
  let index = 0;
  while (index < words.length) {
    if (SETS_VARIABLE.test(words[index]!)) { index += 1; continue; }
    const name = baseName(words[index]!);
    if (!Object.hasOwn(WRAPPERS, name)) return index;
    const takesValue = WRAPPERS[name]!;
    let valueFirst = TAKES_VALUE_FIRST.has(name);
    index += 1;
    while (index < words.length && (words[index]!.startsWith("-") || valueFirst || (name === "env" && words[index]!.includes("=")))) {
      const word = words[index]!;
      if (!word.startsWith("-") && !(name === "env" && word.includes("="))) valueFirst = false;   // `timeout 5`: the value, then the command
      index += takesValue.includes(word) ? 2 : 1;
    }
  }
  return index;
}

function baseName(word: string): string {
  return word.slice(word.lastIndexOf("/") + 1).toLowerCase();
}

/** The pipelines of `line`: each a list of stages, each stage its words (variables put in). */
function stages(line: string): string[][][] {
  const pipelines: string[][][] = [];
  let pipeline: string[][] = [];
  let current: string[] = [];
  for (const word of withVariables(splitWords(line))) {
    if (PIPES.has(word)) {
      pipeline.push(current);
      current = [];
    } else if ((SEPARATORS.has(word) && !REDIRECTS.has(word)) || [...word].every((char) => LIST_OPERATOR_CHARS.includes(char))) {
      pipelines.push([...pipeline, current]);
      pipeline = [];
      current = [];
    } else {
      current.push(word);
    }
  }
  pipelines.push([...pipeline, current]);
  return pipelines.filter((each) => each.some((stage) => stage.length)).map((each) => each.filter((stage) => stage.length));
}

/** The program a stage runs (its base name, lower case, `.exe` off) and its other words. */
function program(stage: string[]): [string, string[]] {
  const at = programIndex(stage);
  if (at >= stage.length) return ["", []];
  const word = stage[at]!;
  const name = word.slice(word.lastIndexOf("/") + 1);
  const lower = name.slice(name.lastIndexOf("\\") + 1).toLowerCase();
  return [lower.endsWith(".exe") ? lower.slice(0, -4) : lower, stage.slice(at + 1)];
}

/** The words of `rest` that are neither options nor a redirect's target, home spelled `~`. */
function operands(rest: string[]): string[] {
  const out: string[] = [];
  let optionsEnd = false;
  let skip = false;
  for (const word of rest) {
    if (skip) skip = false;
    else if (REDIRECTS.has(word)) skip = true;
    else if (word === "--" && !optionsEnd) optionsEnd = true;
    else if (optionsEnd || !word.startsWith("-")) out.push(homeAsTilde(word));
  }
  return out;
}

/** `[letters of every short option cluster, every long option]` before a `--`. */
function options(rest: string[]): [Set<string>, Set<string>] {
  const letters = new Set<string>();
  const longs = new Set<string>();
  for (const word of rest) {
    if (word === "--") break;
    if (word.startsWith("--")) longs.add(word.split("=", 1)[0]!.toLowerCase());
    else if (word.startsWith("-") && word.length > 1) for (const letter of word.slice(1)) letters.add(letter);
  }
  return [letters, longs];
}

function rmWipes(rest: string[]): boolean {
  const [letters, longs] = options(rest);
  const recursive = letters.has("r") || letters.has("R") || longs.has("--recursive");
  const force = letters.has("f") || longs.has("--force");
  return recursive && force && operands(rest).some((target) => RM_TARGET.test(target));
}

function chmodOpens(rest: string[]): boolean {
  const found = operands(rest);
  return found.length > 0 && WORLD_WRITABLE.test(found[0]!) && found.slice(1).some((path) => CHMOD_TARGET.test(path));
}

function skipsCertificates(name: string, rest: string[]): boolean {
  if (name === "curl") {
    return rest.some((word) => word === "--insecure" || word === "--no-check-certificate" ||
      (word.startsWith("-") && !word.startsWith("--") && word.slice(1).includes("k") && /^\p{L}+$/u.test(word.slice(1))));
  }
  if (name === "wget") return rest.includes("--no-check-certificate");
  return FETCHERS.has(name) && rest.some((word) => word.toLowerCase() === "-skipcertificatecheck");
}

/**
 * The host an address word names, read as Python's `urllib.parse.urlsplit(…).hostname` reads it
 * ("" for none): a scheme, then `//` and the network location up to `/ ? #`, its user part and
 * port taken off, an IPv6 address out of its brackets, lower case.
 */
function hostOf(word: string): string {
  let rest = word.includes("://") ? word : "//" + word;
  const colon = rest.indexOf(":");
  if (colon > 0 && /^[A-Za-z][A-Za-z0-9+.-]*$/.test(rest.slice(0, colon))) rest = rest.slice(colon + 1);
  if (!rest.startsWith("//")) return "";
  const location = rest.slice(2).split(/[/?#]/, 1)[0]!;
  if (location.includes("[") !== location.includes("]")) return "";   // urlsplit refuses it
  const host = location.slice(location.lastIndexOf("@") + 1);
  const name = host.includes("[") ? host.slice(host.indexOf("[") + 1).split("]", 1)[0]! : host.split(":", 1)[0]!;
  return name.toLowerCase();
}

/** The hosts a fetch's address words name ("" for a word with none); an option's value and a redirect's target are not addresses. */
function fetchedHosts(rest: string[]): string[] {
  const hosts: string[] = [];
  let skip = false;
  for (const word of rest) {
    if (skip) skip = false;
    else if (REDIRECTS.has(word) || FETCH_VALUE_OPTIONS.has(word)) skip = true;
    else if (!word.startsWith("-")) hosts.push(hostOf(word));
  }
  return hosts;
}

function insecureFetch(name: string, rest: string[]): boolean {
  if (!skipsCertificates(name, rest)) return false;
  const hosts = fetchedHosts(rest);
  // Routine only when it names an address and EVERY address is local: a local word elsewhere on
  // the line (`-o ~/.local/bin/p`) says nothing about where the fetch goes.
  return hosts.length === 0 || !hosts.every((host) => host && LOCAL_HOST.test(host));
}

function pipelineShapes(pipeline: string[][], found: Set<string>): void {
  let fetched = false;
  for (const stage of pipeline) {
    const [name, rest] = program(stage);
    if (fetched && SCRIPT_RUNNERS.test(name)) found.add("remote-script-pipe");
    if (fetched && name === "eval") found.add("remote-eval-pipe");
    if ((name === "eval" || SHELLS.has(name)) && rest.some((word) => FETCH_SUBSTITUTION.test(word))) {
      found.add(name === "eval" ? "remote-eval-pipe" : "remote-script-pipe");
    }
    if (FETCHERS.has(name)) {
      fetched = true;
      if (insecureFetch(name, rest)) found.add("insecure-tls-fetch");
    } else if (name === "rm" && rmWipes(rest)) {
      found.add("rm-rf-system-paths");
    } else if (name === "chmod" && chmodOpens(rest)) {
      found.add("chmod-world-writable");
    }
  }
}

/** `bash <(curl …)`: a script runner reading a fetch through process substitution. */
function processSubstitution(line: string): boolean {
  const words = splitWords(line);
  for (let index = 0; index < words.length - 3; index += 1) {
    if (words[index + 1] === "<" && words[index + 2] === "(" && SCRIPT_RUNNERS.test(baseName(words[index]!))) {
      const after = words.slice(index + 3);
      const close = after.indexOf(")");
      if ((close < 0 ? after : after.slice(0, close)).some((word) => FETCHERS.has(baseName(word)))) return true;
    }
  }
  return false;
}

/** Every shape in `command` (see the module doc), in SHAPE_ORDER; [] for none. */
export function shapesOf(command: string): string[] {
  const found = new Set<string>();
  // A backslash-newline joins two lines into one command; the gate reads with quotes and
  // backslashes taken out (r''m, c"u"rl are still rm and curl to the shell).
  for (const line of command.replaceAll("\\\n", " ").split("\n")) {
    if (!MAY_HAVE_A_SHAPE.test(line.replace(/["'\\]/g, ""))) continue;
    for (const pipeline of stages(line)) pipelineShapes(pipeline, found);
    if (line.includes("<") && processSubstitution(line)) found.add("remote-script-pipe");
  }
  return SHAPE_ORDER.filter((shape) => found.has(shape));
}
