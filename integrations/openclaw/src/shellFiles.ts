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
/**
 * A variable where it is used: `$NAME`, `${NAME}`, or `${NAME<op>WORD}` with a default (`:-` `-`),
 * an assignment (`:=` `=`) or a check (`:?` `?`).
 */
const PARAMETER = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
/** Commands whose words name things rather than read them; what they print may be piped to `xargs`. */
const NAMING_COMMANDS = new Set(["echo", "printf"]);
const RECURSIVE_COMMANDS = new Set([
  "cp", "scp", "rsync", "tar", "zip", "7z", "7za", "rar", "ditto", "mv", "gzip", "rg", "ln", "link",
  "copy", "xcopy", "robocopy", "copy-item", "cpi", "compress-archive", "move-item",
]);
const RECURSIVE_WITH_FLAG: Record<string, readonly string[]> = {
  grep: ["-r", "-R", "--recursive"], egrep: ["-r", "-R"], fgrep: ["-r", "-R"],
};
/** The words that end one simple command: the list operators, pipes, redirects and a subshell's brackets. */
export const SEPARATORS: ReadonlySet<string> = new Set([";", "&&", "||", "|", "&", ">", ">>", "<", "|&", "(", ")"]);
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

/** The most words one brace-expanded word becomes; a group past it is left as written. */
const MAX_BRACE_WORDS = 64;
const OPERATOR_CHARS = ";&|<>";
const SUBSHELL_CHARS = "()";
const WHITESPACE = " \t\r\n";
/**
 * Brace-expansion marks for an UNQUOTED `{` `,` `}` while a word is built (a quoted or escaped one
 * is a literal character): private-use code points, never typed in a real command.
 */
const OPEN = "\ue000";
const COMMA = "\ue001";
const CLOSE = "\ue002";
const MARK_OF: Record<string, string> = { "{": OPEN, ",": COMMA, "}": CLOSE };
// Python's `$` (no MULTILINE) also matches just before a final newline: `(?=\n?$)` is that in JS.
/** What a word holds just before a backslash that makes it a Windows path (lexer.py `_WINDOWS_BEFORE`). */
const WINDOWS_BEFORE = new RegExp(String.raw`(?:^|[^A-Za-z0-9])[A-Za-z]:(?=\n?$)|%[A-Za-z_][A-Za-z0-9_]*%(?=\n?$)|^\.{1,2}(?=\n?$)|^~(?=\n?$)|^\$HOME(?=\n?$)|^\$env:[A-Za-z_][\p{L}\p{N}_]*(?=\n?$)`, "iu");
/** A Windows path inside double quotes (`"C:\Program Files\x"`): its backslashes stay as written. */
const WINDOWS_INSIDE = /(?:^|[^A-Za-z0-9])[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\|^(?:\.{1,2}|~)\\/;
/** A run of characters that mean nothing special inside a word. */
const PLAIN = /[^\s;&|<>()\\'"$`{},]+/y;
const SEQUENCE = /^(-?\d{1,6})\.\.(-?\d{1,6})(?=\n?$)|^([A-Za-z])\.\.([A-Za-z])(?=\n?$)/;
const DOUBLE_QUOTE_ESCAPE = /\\([$`"\\\n])/g;

/** Thrown for a quote or a `$(` that never closes (lexer.py `_Unbalanced`). */
class Unbalanced extends Error {}

function literalMarks(text: string): string {
  return text.replace(/[\ue000-\ue002]/g, (mark) => (mark === OPEN ? "{" : mark === COMMA ? "," : "}"));
}

/** The index just past the `closeChar` that balances the `openChar` before `start`; quotes inside are skipped as the shell skips them. */
function closing(text: string, start: number, openChar: string, closeChar: string): number {
  let depth = 1;
  let index = start;
  while (index < text.length) {
    const char = text[index]!;
    if (char === "\\") { index += 2; continue; }
    if ((char === "'" || char === '"') && openChar !== "`") {
      const end = char === "'" ? text.indexOf("'", index + 1) : doubleQuoteEnd(text, index + 1);
      if (end < 0) throw new Unbalanced(text);
      index = end + 1;
      continue;
    }
    if (char === closeChar && (openChar !== closeChar || depth === 1)) {
      depth -= 1;
      if (depth === 0) return index + 1;
    } else if (char === openChar) {
      depth += 1;
    }
    index += 1;
  }
  throw new Unbalanced(text);
}

/** The index of the `"` that closes a double-quoted run starting at `start`, or -1. */
function doubleQuoteEnd(text: string, start: number): number {
  let index = start;
  while (index < text.length) {
    const char = text[index]!;
    if (char === "\\") index += 2;
    else if (char === '"') return index;
    else if (text.startsWith("$(", index) || text.startsWith("${", index)) {
      index = closing(text, index + 2, text[index + 1]!, text[index + 1] === "(" ? ")" : "}");
    } else if (char === "`") index = closing(text, index + 1, "`", "`");
    else index += 1;
  }
  return -1;
}

/**
 * One pass over one line — port of lexer.py `_Lexer`, the ONE shell lexer: whitespace separates
 * words; `'…'` keeps everything literal; `"…"` keeps all but `\$ \` \" \\` and a line continuation;
 * a backslash outside quotes takes the next character literally; runs of `;&|<>` are operator
 * words and `(` / `)` words of their own; `$(…)`, `${…}` and backticks stay whole; `#` starts a
 * comment only at the start of a word; brace expansion up to MAX_BRACE_WORDS. A backslash is a
 * separator, not an escape, in a word that is a Windows path — decided PER WORD.
 *
 * Pattern: State — the word being built and whether it is a Windows path.
 */
class Lexer {
  private index = 0;
  private readonly words: string[] = [];
  private current: string[] = [];
  private started = false;
  private windows = false;
  unresolved = false;
  private readonly text: string;

  // A plain field, not a constructor parameter property: Node's type stripping (how the parity
  // test loads this file without a build) only accepts syntax it can erase.
  constructor(text: string) {
    this.text = text;
  }

  private finish(): void {
    if (this.started) this.words.push(...expanded(this.current.join(""), this));
    this.current = [];
    this.started = false;
    this.windows = false;
  }

  run(): string[] {
    const text = this.text;
    const length = text.length;
    while (this.index < length) {
      const char = text[this.index]!;
      if (WHITESPACE.includes(char)) {
        this.finish();
        this.index += 1;
      } else if (char === "#" && !this.started) {
        const newline = text.indexOf("\n", this.index);
        this.index = newline < 0 ? length : newline;
      } else if (OPERATOR_CHARS.includes(char) || SUBSHELL_CHARS.includes(char)) {
        this.finish();
        let end = this.index + 1;
        while (OPERATOR_CHARS.includes(char) && end < length && OPERATOR_CHARS.includes(text[end]!)) end += 1;
        this.words.push(text.slice(this.index, end));
        this.index = end;
      } else {
        this.started = true;
        this.wordPart(char);
      }
    }
    this.finish();
    return this.words;
  }

  private wordPart(char: string): void {
    const text = this.text;
    if (char === "\\") {
      this.backslash();
    } else if (char === "'") {
      const end = text.indexOf("'", this.index + 1);
      if (end < 0) throw new Unbalanced(text);
      this.current.push(text.slice(this.index + 1, end));
      this.index = end + 1;
    } else if (char === '"') {
      this.doubleQuoted();
    } else if (text.startsWith("$(", this.index) || text.startsWith("${", this.index)) {
      const open = text[this.index + 1]!;
      const end = closing(text, this.index + 2, open, open === "(" ? ")" : "}");
      this.current.push(text.slice(this.index, end));
      this.index = end;
    } else if (char === "`") {
      const end = closing(text, this.index + 1, "`", "`");
      this.current.push(text.slice(this.index, end));
      this.index = end;
    } else {
      PLAIN.lastIndex = this.index;
      const plain = PLAIN.exec(text);
      if (plain) {
        this.current.push(plain[0]);
        this.index = PLAIN.lastIndex;
      } else {
        this.current.push(MARK_OF[char] ?? char);
        this.index += 1;
      }
    }
  }

  private backslash(): void {
    const text = this.text;
    const at = this.index;
    if (this.windows || WINDOWS_BEFORE.test(literalMarks(this.current.join("")))) {
      this.windows = true;
      this.current.push("\\");
      this.index = at + 1;
    } else if (at + 1 < text.length) {
      if (text[at + 1] !== "\n") this.current.push(text[at + 1]!);   // a line continuation joins the lines
      this.index = at + 2;
    } else {
      this.index = at + 1;
    }
  }

  private doubleQuoted(): void {
    const text = this.text;
    const end = doubleQuoteEnd(text, this.index + 1);
    if (end < 0) throw new Unbalanced(text);
    let inner = text.slice(this.index + 1, end);
    if (WINDOWS_INSIDE.test(literalMarks(this.current.join("")) + inner)) this.windows = true;
    if (!this.windows) inner = inner.replace(DOUBLE_QUOTE_ESCAPE, (_whole, escaped: string) => (escaped === "\n" ? "" : escaped));
    this.current.push(inner);
    this.index = end + 1;
  }
}

/** `word` (with brace marks) as the words brace expansion makes of it, marks made literal. */
function expanded(word: string, lexer: Lexer): string[] {
  if (!word.includes(OPEN)) return [literalMarks(word)];
  const found = alternatives(word);
  if (found === null) {
    lexer.unresolved = true;
    return [literalMarks(word)];
  }
  return found.map(literalMarks);
}

/** The index of the `}` mark closing the `{` mark at `start` (-1 for none) and the top-level commas. */
function groupEnd(word: string, start: number): [number, number[]] {
  let depth = 0;
  const commas: number[] = [];
  for (let index = start; index < word.length; index += 1) {
    const char = word[index];
    if (char === OPEN) depth += 1;
    else if (char === CLOSE) {
      depth -= 1;
      if (depth === 0) return [index, commas];
    } else if (char === COMMA && depth === 1) commas.push(index);
  }
  return [-1, commas];
}

/** `1..3` / `a..c` as its items (at most one past MAX_BRACE_WORDS, so a longer one is seen as too long), null when no sequence. */
function sequence(body: string): string[] | null {
  const found = SEQUENCE.exec(body);
  if (!found) return null;
  const numbers = found[1] !== undefined;
  const first = numbers ? Number(found[1]) : found[3]!.charCodeAt(0);
  const last = numbers ? Number(found[2]) : found[4]!.charCodeAt(0);
  const step = last >= first ? 1 : -1;
  const out: string[] = [];
  for (let value = first; out.length <= MAX_BRACE_WORDS && (step > 0 ? value <= last : value >= last); value += step) {
    out.push(numbers ? String(value) : String.fromCharCode(value));
  }
  return out;
}

/** Every word `word`'s brace groups make, at most MAX_BRACE_WORDS (null past it). */
function alternatives(word: string): string[] | null {
  let start = word.indexOf(OPEN);
  while (start >= 0) {
    const [end, commas] = groupEnd(word, start);
    if (end < 0) return [word];
    const body = word.slice(start + 1, end);
    let choices: string[] | null;
    if (commas.length) {
      const cuts = [start, ...commas, end];
      choices = cuts.slice(0, -1).map((cut, at) => word.slice(cut + 1, cuts[at + 1]));
    } else {
      choices = body.includes(OPEN) ? null : sequence(literalMarks(body));
    }
    if (choices !== null) {
      const out: string[] = [];
      const prefix = word.slice(0, start);
      const suffix = word.slice(end + 1);
      for (const choice of choices) {
        const rest = alternatives(choice + suffix);
        if (rest === null || out.length + rest.length > MAX_BRACE_WORDS) return null;
        out.push(...rest.map((each) => prefix + each));
      }
      return out;
    }
    start = word.indexOf(OPEN, start + 1);   // `{}` or `{x}`: a literal brace; look further on
  }
  return [word];
}

/** The shell words of `command` (see `Lexer`); an unbalanced quote falls back to whitespace splitting. */
export function splitWords(command: string): string[] {
  try {
    return new Lexer(command).run();
  } catch (error) {
    if (!(error instanceof Unbalanced)) throw error;
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

/**
 * `words` with the variables set earlier on the same line put in where they are used
 * (`H=$HOME; cat $H/x`). `${HOME<op>…}` is `$HOME` (it is always set), and a variable not set on
 * the line that carries a default (`${NOPE:-~}`) reads as its default — what the shell gives for an
 * unset one. Any other variable is kept as written; an assignment word itself too.
 * Port of shell_words.py `with_variables`.
 */
export function withVariables(words: string[]): string[] {
  const values = new Map<string, string>();
  const value = (whole: string, braced?: string, operator?: string, fallback?: string, bare?: string): string => {
    const name = braced ?? bare ?? "";
    const set = values.get(name);
    if (set !== undefined) return set;
    if (name === "HOME") return "$HOME";
    return operator && ["-", "="].includes(operator.replace(/^:/, "")) ? fallback ?? "" : whole;
  };
  return words.map((word) => {
    const assignment = ASSIGNMENT.exec(word);
    if (assignment) {
      values.set(assignment[1]!, assignment[2]!);
      return word;
    }
    return word.includes("$") ? word.replace(PARAMETER, value) : word;
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
  const operands = name === "tar" ? tarOperands(args, paths, written) : paths;
  return [operands.map((word) => ({ path: word, command: name, recursive, destination: written.has(word) })), end];
}

/**
 * tar's file operands as files on disk (port of Python `_tar_operands`): `-C DIR` /
 * `--directory=DIR` changes the folder operands are read in and is not itself read, and an
 * extraction or listing reads only its archive (other operands are members inside it).
 */
function tarOperands(args: string[], paths: string[], written: Set<string>): string[] {
  let folder = "";
  const skip = new Set<string>();
  for (let i = 0; i + 1 < args.length; i++) {
    if (args[i] === "-C" || args[i] === "--directory") {
      folder = args[i + 1]!;
      skip.add(args[i + 1]!);
    }
  }
  const long = args.find((word) => word.startsWith("--directory="));
  if (long) folder = long.split("=", 2)[1] ?? folder;
  const operands = paths.filter((word) => !skip.has(word));
  const clusters = args
    .filter((word, position) => (word.startsWith("-") && !word.startsWith("--")) || (position === 0 && isAlpha(word)))
    .map((word) => word.replace(/^-+/, ""));
  if (clusters.some((cluster) => /[xt]/.test(cluster)) || args.some((word) => ["--extract", "--list", "--get"].includes(word))) {
    let archive = "";
    for (let i = 0; i + 1 < args.length; i++) {
      const flag = args[i]!.replace(/^-+/, "");
      if (!args[i]!.startsWith("--") && flag.includes("f") && isAlpha(flag)) {
        archive = args[i + 1]!;
        break;
      }
    }
    return operands.includes(archive) ? [archive] : [];
  }
  if (!folder) return operands;
  return operands.map((word) => (written.has(word) || isAnchored(word) ? word : folder.replace(/\/+$/, "") + "/" + word));
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
  // find's own `;` `\(` `\)` are its expression, not the end of the command.
  while (position < words.length && ([";", "(", ")"].includes(words[position]!) || !SEPARATORS.has(words[position]!))) {
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

/** How code asks for the person's home folder (shell_scripts._HOME_ASKED). */
const HOME_ASKED_SOURCE = String.raw`\b(?:pathlib\.)?Path\.home\(\s*\)|\bos\.path\.expanduser\(\s*['"]~['"]\s*\)` +
  String.raw`|\bos\.environ\s*\[\s*['"]HOME['"]\s*\]|\bos\.environ\.get\(\s*['"]HOME['"]\s*\)` +
  String.raw`|\bos\.getenv\(\s*['"]HOME['"]\s*\)|\bprocess\.env\.HOME\b|\bprocess\.env\s*\[\s*['"]HOME['"]\s*\]` +
  String.raw`|(?:\brequire\(\s*['"](?:node:)?os['"]\s*\)|\b\w+)\.homedir\(\s*\)|\bDir\.home\b(?:\(\s*\))?` +
  String.raw`|\bENV\s*\[\s*['"]HOME['"]\s*\]|\$ENV\{\s*['"]?HOME['"]?\s*\}`;
const HOME_ASKED = new RegExp(HOME_ASKED_SOURCE, "g");
const TEMPLATE_HOME = new RegExp(String.raw`\$\{\s*(` + HOME_ASKED_SOURCE + String.raw`)\s*\}`, "g");
/** Where each language keeps its command-line arguments, and the index of the first one. */
const ARGV: Record<string, [RegExp, number]> = {
  python: [/\bsys\.argv\s*\[\s*(\d{1,2})\s*\]/g, 1],
  node: [/\bprocess\.argv\s*\[\s*(\d{1,2})\s*\]/g, 1],
  ruby: [/(?<![$\w])ARGV\s*\[\s*(\d{1,2})\s*\]/g, 0],
  perl: [/\$ARGV\s*\[\s*(\d{1,2})\s*\]/g, 0],
};
const LANGUAGE: Record<string, string> = {
  python: "python", python3: "python", python2: "python", py: "python", node: "node", nodejs: "node",
  bun: "node", deno: "node", ruby: "ruby", perl: "perl",
};
/** Two literals joined: `'a' + 'b'`, `'a' . 'b'` (Perl), `'a' / 'b'` (a path). */
const JOINED = /(['"`])((?:\\.|(?!\1)[^\\\n]){0,1024})\1\s*([+./])\s*(['"`])((?:\\.|(?!\4)[^\\\n]){0,1024})\4/;
/** A literal alone in brackets that are not a call: `('Doc' + 'uments')` once joined. */
const BRACKETED = /(?<![\w\])\]])\(\s*((['"`])(?:\\.|(?!\2)[^\\\n]){0,1024}\2)\s*\)/;
const MAX_JOINS = 64;
const JOIN_CALL = /(?:\bjoinpath|\bos\.path\.join|\bpath\.join|\bpath\.resolve|\bFile\.join|\bPath)\s*\(([^()]{1,1024})\)/g;
const SLASH_CHAIN = /(?:\)|\w)\s*\/\s*['"][^'"\n]{1,256}['"](?:\s*\/\s*['"][^'"\n]{1,256}['"])*/g;
const JOIN_PART = /['"`]([^'"`\n]{1,256})['"`]/g;

/** `code` with what it builds statically written out: the home folder as `~`, its arguments, joined literals as one. */
function resolved(interpreter: string, code: string, argv: readonly string[] = []): string {
  let text = code.replace(TEMPLATE_HOME, "~").replace(HOME_ASKED, () => JSON.stringify("~"));
  const language = LANGUAGE[interpreter];
  if (language && ARGV[language] && argv.length) {
    const [pattern, first] = ARGV[language]!;
    text = text.replace(pattern, (whole, index: string) => {
      const at = Number(index) - first;
      return at >= 0 && at < argv.length ? JSON.stringify(argv[at]) : whole;
    });
  }
  for (let round = 0; round < MAX_JOINS; round += 1) {
    const joined = text.replace(JOINED, (_whole, _q1, left: string, operator: string, _q2, right: string) =>
      JSON.stringify(operator === "/" ? left.replace(/\/+$/, "") + "/" + right.replace(/^\/+/, "") : left + right))
      .replace(BRACKETED, (_whole, literal: string) => literal);
    if (joined === text) break;
    text = joined;
  }
  return text;
}

function trimSlashes(part: string): string {
  return part.replace(/^\/+|\/+$/g, "");
}

/** Paths `code` builds by joining literals (shell_scripts._joined_paths). */
function joinedPaths(code: string): string[] {
  const out: string[] = [];
  const matches = [...[...code.matchAll(JOIN_CALL)].map((m) => m[1]!), ...[...code.matchAll(SLASH_CHAIN)].map((m) => m[0])];
  for (const piece of matches) {
    const raw = [...piece.matchAll(JOIN_PART)].map((m) => m[1]!);
    const parts = raw.map(trimSlashes).filter((part) => part);
    if (parts.length >= 2 && !parts.some((part) => part.includes("://"))) out.push((raw[0]!.startsWith("/") ? "/" : "") + parts.join("/"));
  }
  return out;
}

function literalsOf(code: string): string[] {
  return [...[...code.matchAll(LITERAL)].map((match) => match[2]!), ...joinedPaths(code)];
}

function pathsInCode(interpreter: string, code: string, argv: readonly string[] = []): ShellFileArg[] {
  const recursive = WHOLE_FOLDER_CODE.test(code);
  const joinsHome = HOME_CODE.test(code);
  const found: ShellFileArg[] = [];
  const written = resolved(interpreter, code, argv);
  const literals = [...new Set([...literalsOf(code), ...(written !== code ? literalsOf(written) : [])])];
  for (const literal of literals) {
    if (literal.includes("://") || !(literal.includes("/") || literal.includes("\\") || literal.startsWith("~"))) continue;
    found.push({ path: literal, command: interpreter, recursive, destination: false });
    if (joinsHome && !/^[/~$%]/.test(literal) && !/^[A-Za-z]:/.test(literal)) {
      found.push({ path: "~/" + withoutDotSlash(literal), command: interpreter, recursive, destination: false });
    }
  }
  const once = new Map<string, ShellFileArg>();
  for (const arg of found) once.set(`${arg.path}\u0000${arg.recursive}`, once.get(`${arg.path}\u0000${arg.recursive}`) ?? arg);
  return [...once.values()];
}

function scriptArgs(name: string, words: string[], index: number): [ShellFileArg[], number] {
  const end = segmentEnd(words, index + 1);
  const options = INTERPRETERS[name]!;
  const found: ShellFileArg[] = [];
  for (let position = index + 1; position < end - 1; position += 1) {
    if (options.includes(words[position]!)) found.push(...pathsInCode(name, words[position + 1]!, words.slice(position + 2, end)));
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

/**
 * The home folder named by a variable at the start of a path: `$HOME`, `${HOME}`, `%USERPROFILE%`;
 * `${HOME:-x}` / `${HOME-x}` / `${HOME:=x}` / `${HOME:?}` too (it is always set), and PowerShell's
 * `$env:USERPROFILE` / `$env:HOME`.
 */
const HOME_VARIABLE = /^(?:\$HOME(?![A-Za-z0-9_])|\$\{HOME(?::?[-=?][^}]*)?\}|%USERPROFILE%|\$[Ee][Nn][Vv]:(?:[Uu][Ss][Ee][Rr][Pp][Rr][Oo][Ff][Ii][Ll][Ee]|[Hh][Oo][Mm][Ee])(?![A-Za-z0-9_]))/;

/**
 * `path` with a leading home-folder variable written as `~`: every rule that reads these paths
 * expands `~` and none expanded `$HOME` — a blocked `cat ~/.ssh/key` was retried as
 * `cat $HOME/.ssh/key` by a real agent and went through (2026-11-20).
 */
export function homeAsTilde(path: string): string {
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

const NESTED_SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
const NESTING_DEPTH = 3;
const COMMAND_ENDS = new Set([";", "&&", "||", "|", "&"]);

/** The commands `command` hands to another shell: the word after a shell's `-c`, and what follows `eval`. */
function nestedCode(command: string): string[] {
  const words = splitWords(command);
  const found: string[] = [];
  words.forEach((word, position) => {
    const name = baseName(word);
    if (NESTED_SHELLS.has(name)) {
      for (let offset = position + 1; offset < words.length - 1; offset += 1) {
        const option = words[offset]!;
        if (!option.startsWith("-")) break;
        if (!option.startsWith("--") && option.endsWith("c")) { found.push(words[offset + 1]!); break; }
      }
    } else if (name === "eval") {
      const rest = words.slice(position + 1);
      const end = rest.findIndex((each) => COMMAND_ENDS.has(each));
      found.push(rest.slice(0, end === -1 ? rest.length : end).join(" "));
    }
  });
  return found.filter((code) => code.trim());
}

/**
 * `command` followed, one per line, by every command it hands to another shell (`sh -c '…'`,
 * `bash -c`, `eval`), three shells deep — so every check sees a wrapped command as it sees any
 * other. Port of Python `detection/shell_shapes.py::with_nested_commands`.
 */
export function withNestedCommands(command: string, depth = NESTING_DEPTH): string {
  if (depth <= 0 || ![" -c", "c ", "eval"].some((marker) => command.includes(marker))) return command;
  const inner = nestedCode(command).map((code) => withNestedCommands(code, depth - 1));
  return inner.length ? [command, ...inner].join("\n") : command;
}

/** The paths a piece of `code` reads, for tools that run code directly (as `python3 -c CODE`). */
export function codeFileArgs(code: string, language = "python"): ShellFileArg[] {
  return pathsInCode(language, code || "").map((arg) => fromFolder(arg, ""));
}
