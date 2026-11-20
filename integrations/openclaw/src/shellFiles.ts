/**
 * Which files a shell command reads, copies or packs up — the OpenClaw runtime's copy of
 * `plugins/blackbox/detection/paths/shell_files.py` (the canonical side; read its module doc
 * for the why of every rule).
 *
 * A file tool names its path in an argument; a shell command hides it among words. Until
 * 2026-11-20 this bridge applied its path rules to file tools only, so `exec cat ~/.ssh/id_rsa`
 * passed unseen while Hermes blocked the same command on the same machine. This module turns a
 * command line into the paths it touches, so the protected-path rule sees the shell channel too.
 *
 * It must answer exactly as the Python does: `tests/parity/shell_files_fixtures.json` is
 * generated from the Python and asserted here by `test/shell-files-parity.mjs` (and on the
 * Python side by tests/plugins/test_blackbox_shell_files_parity.py). Words are split by a port
 * of Python's `shlex` (POSIX mode, punctuation `;&|<>`, `#` comments) — see `splitWords`.
 *
 * No imports: Node can run this file as it is (type stripping), which is how the parity test
 * loads it without a build.
 *
 * Usage:
 *   for (const arg of shellFileArgs("tar czf out.tgz ~/Library/Application\\ Support/Google/Chrome"))
 *     arg.path, arg.recursive, arg.destination   // "out.tgz" is the destination
 *   codeFileArgs("print(open('/home/me/.ssh/id_rsa').read())")   // a code tool's Python
 */

/** One path a shell command touches. `path` is the word as written (`~`, `$HOME` not expanded). */
export interface ShellFileArg {
  path: string;
  command: string;
  /** True when the command takes a folder argument as everything inside it. */
  recursive: boolean;
  /** True for where a copy or archive WRITES (`cp src DEST`) — nothing is read from it. */
  destination: boolean;
}

const READ_COMMANDS = new Set([
  "cat", "less", "more", "head", "tail", "bat", "xxd", "hexdump", "strings", "od", "nl",
  "base64", "base32", "sqlite3", "jq",
  "awk", "gawk", "sed", "sort", "uniq", "wc", "cut", "paste", "rev", "tac", "column", "fold", "iconv",
  "diff", "cmp", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "file",
  "zcat", "gzcat", "bzcat", "xzcat", "zless",
  "vim", "vi", "view", "nano", "emacs", "open", "xdg-open", "code", "pbcopy",
  "type", "get-content", "gc",
]);
/** Commands that send a file somewhere: `-d @FILE`, `-F name=@FILE`, `-T FILE`, `file://`. */
const UPLOAD_COMMANDS = new Set(["curl", "wget", "http", "https"]);
const UPLOAD_FILE_OPTIONS = new Set(["-T", "--upload-file", "--post-file", "--body-file"]);
/** `NAME=VALUE` at the start of a word: a variable set on the command line. */
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/;
const VARIABLE_USE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;
/** Commands whose words name things rather than read them; what they print may be piped to `xargs`. */
const NAMING_COMMANDS = new Set(["echo", "printf"]);
const RECURSIVE_COMMANDS = new Set([
  "cp", "scp", "rsync", "tar", "zip", "7z", "7za", "rar", "ditto", "mv", "gzip", "rg", "ln", "link",
  "copy", "xcopy", "robocopy", "copy-item", "cpi", "compress-archive", "move-item",
]);
const RECURSIVE_WITH_FLAG: Record<string, readonly string[]> = {
  grep: ["-r", "-R", "--recursive"], egrep: ["-r", "-R"], fgrep: ["-r", "-R"],
};
const SEPARATORS = new Set([";", "&&", "||", "|", "&", ">", ">>", "<", "|&"]);
const COPY_COMMANDS = new Set([
  "cp", "scp", "rsync", "mv", "ditto", "copy", "xcopy", "robocopy", "copy-item", "cpi", "move-item", "ln", "link",
]);
const ARCHIVE_FIRST = new Set(["zip", "7z", "7za", "rar"]);
const INTERPRETERS: Record<string, readonly string[]> = {
  python: ["-c"], python3: ["-c"], python2: ["-c"], py: ["-c"],
  node: ["-e", "--eval", "-p", "--print"], nodejs: ["-e", "--eval", "-p", "--print"],
  bun: ["-e", "--eval"], deno: ["eval"], ruby: ["-e"], perl: ["-e", "-E"], php: ["-r"], osascript: ["-e"],
};
const LITERAL = /(['"`])((?:\\.|(?!\1).){1,1024}?)\1/g;
const WHOLE_FOLDER_CODE = /copytree|make_archive|tarfile|zipfile|os\.walk|\bwalk\(|rglob|glob\(|readdirSync|readdir\(|cpSync|archiver|ZipFile|Dir\.glob|File\.find/;
const HOME_CODE = /homedir\(|expanduser|Path\.home|environ\[.HOME.\]|getenv\(.HOME.\)|env\.HOME|ENV\[.HOME.\]|Dir\.home/;
const HEREDOC = /^[^\n]*?\b(python[23]?|node|ruby|perl|php|bun)\b[^\n]*<<-?\s*(['"]?)(\w+)\2[^\n]*\n([\s\S]*?)\n\s*\3\s*$/gm;
const FIND_EXEC = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
const WINDOWS_PATH = /[A-Za-z]:\\|%[A-Za-z_]+%\\/;

const WHITESPACE = " \t\r\n";
const PUNCTUATION = ";&|<>";
const QUOTES = "'\"";

/** Thrown for an unbalanced quote or a trailing backslash, as Python's shlex raises ValueError. */
class SplitError extends Error {}

/**
 * Python `shlex.shlex(command, posix, punctuation_chars=";&|<>")` with `whitespace_split = True`,
 * read to the end: the state machine of `shlex.read_token`, one method per state. `#` starts a
 * comment to the end of the line (also inside a word), a run of punctuation is one word, and in
 * POSIX mode quotes are removed and a backslash escapes the next character.
 *
 * Pattern: State — `state` is " " (between words), a quote character (inside that quote), "\\"
 * (after a backslash), "a" (in a word), "c" (in a run of punctuation) or null (input ended).
 * Each state method takes the next character and returns true when the current word is complete.
 */
class ShlexReader {
  private position = 0;
  private readonly pushback: string[] = [];
  private state: string | null = " ";
  private token = "";
  private quoted = false;
  private escapedState = " ";
  private readonly command: string;
  private readonly posix: boolean;

  // Plain fields, not constructor parameter properties: Node's type stripping (how the parity
  // test loads this file without a build) only accepts syntax it can erase.
  constructor(command: string, posix: boolean) {
    this.command = command;
    this.posix = posix;
  }

  /** Every word of the command, in order. */
  words(): string[] {
    const out: string[] = [];
    for (;;) {
      const word = this.readWord();
      if (word !== null) out.push(word);
      if (this.state === null) return out;
    }
  }

  /** The next word, or null when nothing was read (the end, or only a comment). */
  private readWord(): string | null {
    this.token = "";
    this.quoted = false;
    this.escapedState = " ";
    while (!this.step(this.read())) { /* keep reading */ }
    const empty = this.token === "" && !(this.posix && this.quoted);
    return empty ? null : this.token;
  }

  private read(): string {
    return this.pushback.pop() ?? (this.position < this.command.length ? this.command[this.position++]! : "");
  }

  private skipLine(): void {
    const end = this.command.indexOf("\n", this.position);
    this.position = end === -1 ? this.command.length : end + 1;
  }

  /** True when a word boundary ends a word that has content (an empty quoted word counts in POSIX mode). */
  private wordIsComplete(): boolean {
    return this.token !== "" || (this.posix && this.quoted);
  }

  private step(next: string): boolean {
    if (this.state === null) { this.token = ""; return true; }
    if (this.state === " ") return this.betweenWords(next);
    if (QUOTES.includes(this.state)) return this.insideQuote(next, this.state);
    if (this.state === "\\") return this.afterBackslash(next, this.state);
    return this.insideWord(next);
  }

  private betweenWords(next: string): boolean {
    if (!next) { this.state = null; return true; }
    if (WHITESPACE.includes(next)) return this.wordIsComplete();
    if (next === "#") { this.skipLine(); return false; }
    if (this.posix && next === "\\") { this.escapedState = "a"; this.state = next; return false; }
    if (PUNCTUATION.includes(next)) { this.token = next; this.state = "c"; return false; }
    if (QUOTES.includes(next)) { if (!this.posix) this.token = next; this.state = next; return false; }
    this.token = next;   // a word character, or any other one (whitespace_split)
    this.state = "a";
    return false;
  }

  private insideQuote(next: string, quote: string): boolean {
    this.quoted = true;
    if (!next) throw new SplitError("No closing quotation");
    if (next === quote) {
      if (this.posix) { this.state = "a"; return false; }
      this.token += next;
      this.state = " ";
      return true;
    }
    if (this.posix && next === "\\" && quote === '"') { this.escapedState = quote; this.state = next; return false; }
    this.token += next;
    return false;
  }

  private afterBackslash(next: string, backslash: string): boolean {
    if (!next) throw new SplitError("No escaped character");
    if (QUOTES.includes(this.escapedState) && next !== backslash && next !== this.escapedState) this.token += backslash;
    this.token += next;
    this.state = this.escapedState;
    return false;
  }

  /** In a word ("a") or a run of punctuation ("c"). */
  private insideWord(next: string): boolean {
    if (!next) { this.state = null; return true; }
    if (WHITESPACE.includes(next)) { this.state = " "; return this.wordIsComplete(); }
    if (next === "#") return this.commentInWord();
    if (this.state === "c") return this.insidePunctuation(next);
    if (this.posix && QUOTES.includes(next)) { this.state = next; return false; }
    if (this.posix && next === "\\") { this.escapedState = "a"; this.state = next; return false; }
    if (!PUNCTUATION.includes(next)) { this.token += next; return false; }
    this.pushback.push(next);
    this.state = " ";
    return this.wordIsComplete();
  }

  private commentInWord(): boolean {
    this.skipLine();
    if (!this.posix) return false;
    this.state = " ";
    return this.wordIsComplete();
  }

  private insidePunctuation(next: string): boolean {
    if (PUNCTUATION.includes(next)) { this.token += next; return false; }
    this.pushback.push(next);
    this.state = " ";
    return true;
  }
}

function shlexSplit(command: string, posix: boolean): string[] {
  return new ShlexReader(command, posix).words();
}

function stripQuotes(word: string): string {
  return word.replace(/^["']+|["']+$/g, "");
}

/** The shell words of `command`; an unparsable line falls back to whitespace splitting. */
export function splitWords(command: string): string[] {
  try {
    if (WINDOWS_PATH.test(command)) return shlexSplit(command, false).map(stripQuotes);
    return shlexSplit(command, true);
  } catch (error) {
    if (!(error instanceof SplitError)) throw error;
    return command.split(/\s+/).filter(Boolean);
  }
}

function baseName(word: string): string {
  return word.slice(word.lastIndexOf("/") + 1).toLowerCase();
}

function looksLikePath(word: string): boolean {
  return word.includes("/") || word.includes("\\") || /^(?:~|\.|\$HOME|%)/.test(word) || word.includes(".");
}

function isAlpha(word: string): boolean {
  return /^\p{L}+$/u.test(word);
}

function segmentEnd(words: string[], start: number): number {
  let end = start;
  while (end < words.length && !SEPARATORS.has(words[end]!)) end += 1;
  return end;
}

function readsFiles(name: string): boolean {
  return READ_COMMANDS.has(name) || RECURSIVE_COMMANDS.has(name) || name in RECURSIVE_WITH_FLAG;
}

function isAnchored(path: string): boolean {
  return /^(?:\/|~|\$HOME|%)/.test(path) || /^[A-Za-z]:[\\/]/.test(path);
}

function withoutDotSlash(path: string): string {
  return path.startsWith("./") ? path.slice(2) : path;
}

function trimTrailingSlashes(path: string): string {
  return path.replace(/\/+$/, "");
}

/** The path arguments `name` writes to rather than reads (see the Python `_destinations`). */
function destinations(name: string, args: string[], paths: string[]): Set<string> {
  if (COPY_COMMANDS.has(name)) {
    for (let i = 0; i + 1 < args.length; i += 1) {
      if (args[i] === "-t" || args[i] === "--target-directory") return new Set([args[i + 1]!]);
    }
    const target = args.find((word) => word.startsWith("--target-directory="));
    if (target) return new Set([target.slice(target.indexOf("=") + 1)]);
    return paths.length >= 2 ? new Set([paths[paths.length - 1]!]) : new Set();
  }
  if (name === "tar") {
    const clusters = args
      .filter((word, position) => (word.startsWith("-") && !word.startsWith("--")) || (position === 0 && isAlpha(word)))
      .map((word) => word.replace(/^-+/, ""));
    if (clusters.some((cluster) => /[xt]/.test(cluster)) || args.some((word) => ["--extract", "--list", "--get"].includes(word))) {
      return new Set();
    }
    for (let i = 0; i + 1 < args.length; i += 1) {
      const flag = args[i]!;
      const letters = flag.replace(/^-+/, "");
      if (!flag.startsWith("--") && letters.includes("f") && isAlpha(letters)) return new Set([args[i + 1]!]);
    }
    return new Set();
  }
  if (ARCHIVE_FIRST.has(name)) {
    if (paths.length === 0) return new Set();
    if (args.slice(0, args.indexOf(paths[0]!)).includes("-")) return new Set();
    return new Set([paths[0]!]);
  }
  if (name === "compress-archive") {
    const position = args.map((word) => word.toLowerCase()).indexOf("-destinationpath");
    if (position !== -1) return position + 1 < args.length ? new Set([args[position + 1]!]) : new Set();
  }
  return new Set();
}

/** `words` with the variables set earlier on the same line put in where they are used (`H=$HOME; cat $H/x`). */
function withVariables(words: string[]): string[] {
  const values = new Map<string, string>();
  return words.map((word) => {
    const assignment = ASSIGNMENT.exec(word);
    if (assignment) {
      values.set(assignment[1]!, assignment[2]!);
      return word;
    }
    if (values.size === 0 || !word.includes("$")) return word;
    return word.replace(VARIABLE_USE, (whole, braced: string | undefined, bare: string | undefined) => values.get(braced ?? bare ?? "") ?? whole);
  });
}

/** `< FILE`: the file a command is fed, whatever the command is. */
function redirectedIn(words: string[], index: number): [ShellFileArg[], number] {
  if (index + 1 >= words.length || SEPARATORS.has(words[index + 1]!)) return [[], index + 1];
  return [[{ path: words[index + 1]!, command: "<", recursive: false, destination: false }], index + 2];
}

/** `echo FILE … | xargs READER`: the names the echo printed are what the reader reads. */
function xargsArgs(words: string[], index: number, named: string[]): [ShellFileArg[], number] {
  const end = segmentEnd(words, index + 1);
  const command = words.slice(index + 1, end).find((word) => !word.startsWith("-") && word !== "{}") ?? "";
  const reader = baseName(command);
  if (!readsFiles(reader)) return [[], end];
  const recursive = RECURSIVE_COMMANDS.has(reader);
  return [named.filter(looksLikePath).map((word) => ({ path: word, command: reader, recursive, destination: false })), end];
}

/** The files an upload command sends: `file://PATH`, `@PATH` and the word after `-T` and its kin. */
function uploadArgs(name: string, args: string[]): ShellFileArg[] {
  const paths: string[] = [];
  args.forEach((word, position) => {
    if (word.startsWith("file://")) paths.push(word.slice("file://".length));
    else if (word.includes("@") && !word.startsWith("-") && (word.startsWith("@") || word.includes("=@"))) paths.push(word.slice(word.indexOf("@") + 1));
    else if (UPLOAD_FILE_OPTIONS.has(word) && position + 1 < args.length) paths.push(args[position + 1]!);
  });
  return paths.filter(Boolean).map((path) => ({ path, command: name, recursive: false, destination: false }));
}

function commandArgs(name: string, words: string[], index: number, inKnownFolder = false): [ShellFileArg[], number] {
  if (UPLOAD_COMMANDS.has(name)) {
    const stop = segmentEnd(words, index + 1);
    return [uploadArgs(name, words.slice(index + 1, stop)), stop];
  }
  if (name === "dd") {
    const stop = segmentEnd(words, index + 1);
    const inputs = words.slice(index + 1, stop).filter((word) => word.startsWith("if=") && word.length > 3);
    return [inputs.map((word) => ({ path: word.slice(3), command: "dd", recursive: false, destination: false })), stop];
  }
  const reads = READ_COMMANDS.has(name);
  let recursive = RECURSIVE_COMMANDS.has(name);
  const flags = RECURSIVE_WITH_FLAG[name];
  if (!(reads || recursive || flags)) return [[], index + 1];
  const end = segmentEnd(words, index + 1);
  const args = words.slice(index + 1, end);
  if (flags) {
    recursive = args.some((word) => flags.includes(word) || (word.startsWith("-") && !word.startsWith("--") && /[rR]/.test(word)));
  }
  const oldStyleTarFlags = name === "tar" && args.length > 0 && isAlpha(args[0]!);
  const paths = args.filter((word, position) =>
    !word.startsWith("-") && !(oldStyleTarFlags && position === 0) &&
    (looksLikePath(word) || ((RECURSIVE_COMMANDS.has(name) || inKnownFolder) && word !== "{}")));
  const written = destinations(name, args, paths);
  return [paths.map((word) => ({ path: word, command: name, recursive, destination: written.has(word) })), end];
}

/** Whether `find … | xargs COMMAND` at the pipe in `position` hands what it finds to a reader. */
function xargsFeedsAReader(words: string[], position: number): boolean {
  if (position >= words.length || words[position] !== "|") return false;
  const xargs = position + 1;
  if (xargs >= words.length || words[xargs]!.slice(words[xargs]!.lastIndexOf("/") + 1) !== "xargs") return false;
  const command = words.slice(xargs + 1, segmentEnd(words, xargs + 1)).find((word) => !word.startsWith("-") && word !== "{}") ?? "";
  return readsFiles(baseName(command));
}

function findArgs(words: string[], index: number): [ShellFileArg[], number] {
  let position = index + 1;
  const roots: string[] = [];
  while (position < words.length && !/^[-(!]/.test(words[position]!) && !SEPARATORS.has(words[position]!)) {
    roots.push(words[position]!);
    position += 1;
  }
  let feedsAReader = false;
  while (position < words.length && (words[position] === ";" || !SEPARATORS.has(words[position]!))) {
    if (FIND_EXEC.has(words[position]!) && position + 1 < words.length) {
      feedsAReader = feedsAReader || readsFiles(baseName(words[position + 1]!));
      while (position < words.length && words[position] !== ";" && words[position] !== "+") position += 1;
    } else if (words[position] === ";") {
      break;
    }
    position += 1;
  }
  feedsAReader = feedsAReader || xargsFeedsAReader(words, position);
  if (!feedsAReader) return [[], position];
  return [roots.map((root) => ({ path: root, command: "find", recursive: true, destination: false })), position];
}

function pathsInCode(interpreter: string, code: string): ShellFileArg[] {
  const recursive = WHOLE_FOLDER_CODE.test(code);
  const joinsHome = HOME_CODE.test(code);
  const found: ShellFileArg[] = [];
  for (const match of code.matchAll(LITERAL)) {
    const literal = match[2]!;
    if (literal.includes("://") || !(literal.includes("/") || literal.includes("\\") || literal.startsWith("~"))) continue;
    found.push({ path: literal, command: interpreter, recursive, destination: false });
    if (joinsHome && !/^[/~$%]/.test(literal) && !/^[A-Za-z]:/.test(literal)) {
      found.push({ path: "~/" + withoutDotSlash(literal), command: interpreter, recursive, destination: false });
    }
  }
  return found;
}

function scriptArgs(name: string, words: string[], index: number): [ShellFileArg[], number] {
  const end = segmentEnd(words, index + 1);
  const options = INTERPRETERS[name]!;
  const found: ShellFileArg[] = [];
  for (let position = index + 1; position < end - 1; position += 1) {
    if (options.includes(words[position]!)) found.push(...pathsInCode(name, words[position + 1]!));
  }
  return [found, end];
}

function cd(words: string[], index: number, folder: string): [string, number] {
  const end = segmentEnd(words, index + 1);
  const targets = words.slice(index + 1, end).filter((word) => !word.startsWith("-") || word === "-");
  const target = targets[0] ?? "~";
  if (target === "-" || (target.startsWith("$") && !target.startsWith("$HOME"))) return ["", end];
  if (isAnchored(target)) return [trimTrailingSlashes(target) || "/", end];
  return [folder ? trimTrailingSlashes(folder) + "/" + target : "", end];
}

/** The home folder named by a variable at the start of a path: `$HOME`, `${HOME}`, `%USERPROFILE%`. */
const HOME_VARIABLE = /^(?:\$HOME(?![A-Za-z0-9_])|\$\{HOME\}|%USERPROFILE%)/;

/**
 * `path` with a leading home-folder variable written as `~`: every rule that reads these paths
 * expands `~` and none expanded `$HOME` — a blocked `cat ~/.ssh/key` was retried as
 * `cat $HOME/.ssh/key` by a real agent and went through (2026-11-20).
 */
function homeAsTilde(path: string): string {
  return path.replace(HOME_VARIABLE, "~");
}

/** `arg` with a relative path placed under the folder an earlier `cd` moved to, and the home folder written `~`. */
function fromFolder(arg: ShellFileArg, folder: string): ShellFileArg {
  let path = arg.path;
  if (folder && !isAnchored(path)) {
    const relative = withoutDotSlash(path);
    path = relative === "." || relative === "" ? folder : trimTrailingSlashes(folder) + "/" + relative;
  }
  path = homeAsTilde(path);
  return path === arg.path ? arg : { ...arg, path };
}

/**
 * Every path argument of a read, copy or archive command in `command`, duplicates removed
 * (first kept). Where a copy or archive writes is marked `destination`.
 */
export function shellFileArgs(command: string): ShellFileArg[] {
  if (!command) return [];
  const words = withVariables(splitWords(command));
  const out: ShellFileArg[] = [];
  const seen = new Set<string>();
  let folder = "";
  let named: string[] = [];   // the words of the last echo / printf, in case they are piped to xargs
  const keep = (found: ShellFileArg[]): void => {
    for (const each of found) {
      const arg = fromFolder(each, folder);
      if (!seen.has(arg.path)) { seen.add(arg.path); out.push(arg); }
    }
  };
  let index = 0;
  while (index < words.length) {
    const name = baseName(words[index]!);
    let found: ShellFileArg[];
    if (name === "cd" || name === "pushd") {
      [folder, index] = cd(words, index, folder);
      continue;
    }
    if (name === "find") [found, index] = findArgs(words, index);
    else if (name in INTERPRETERS) [found, index] = scriptArgs(name, words, index);
    else if (name === "<") [found, index] = redirectedIn(words, index);
    else if (NAMING_COMMANDS.has(name)) {
      const end = segmentEnd(words, index + 1);
      named = words.slice(index + 1, end);
      found = [];
      index = end;
    } else if (name === "xargs") [found, index] = xargsArgs(words, index, named);
    else [found, index] = commandArgs(name, words, index, Boolean(folder));
    keep(found);
  }
  for (const match of command.matchAll(HEREDOC)) keep(pathsInCode(match[1]!, match[4]!));
  return out;
}

/** The paths a piece of `code` reads, for tools that run code directly (as `python3 -c CODE`). */
export function codeFileArgs(code: string, language = "python"): ShellFileArg[] {
  return pathsInCode(language, code || "").map((arg) => fromFolder(arg, ""));
}
