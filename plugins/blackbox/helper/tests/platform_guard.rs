//! Structure guard for the helper's per-OS layout (Amos 2026-11-21): every call the helper makes
//! to the operating system lives under `src/platform/<os>/`, and only the build for that OS
//! compiles it.
//!
//! * `os_calls_stay_in_platform` — no system tool, path or API is named in code outside
//!   `src/platform/` (comments may mention them; code may not). A new system call goes into
//!   `platform/macos/` behind the `Enforcer` / `Observer` traits in `platform/mod.rs`, with the
//!   matching method in `unsupported.rs` (later `windows/`, `linux/`).
//! * `each_os_folder_is_compiled_only_for_its_os` — `platform/mod.rs` declares `macos` only under
//!   `#[cfg(target_os = "macos")]` and the fallback only under the opposite.
//!
//! The scanner itself is tested by `the_scanner_*`, so a broken guard cannot pass silently.

use std::path::{Path, PathBuf};

/// Names of macOS tools, paths and APIs that only `platform/macos/` may use.
const MACOS_ONLY: &[&str] = &[
    "pfctl", "networksetup", "launchctl", "scutil", "nettop", "codesign", "spctl", "osascript",
    "netstat", "/usr/bin/log", "socketfilterfw", "systemsetup", "fdesetup", "csrutil", "sysadminctl",
    "/usr/bin/defaults", "plutil", "sfltool", "kmutil", "systemextensionsctl", "ipconfig", "/sbin/route",
    "libproc", "proc_pidpath", "sysctlbyname", "/library/", "/system/library", "launchdaemons",
];

/// The code of one line, without a `//` comment (a `//` inside a string literal is kept).
fn code_of(line: &str) -> &str {
    let mut quotes = 0;
    let bytes = line.as_bytes();
    for index in 0..bytes.len() {
        match bytes[index] {
            b'"' if index == 0 || bytes[index - 1] != b'\\' => quotes += 1,
            b'/' if quotes % 2 == 0 && bytes.get(index + 1) == Some(&b'/') => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Every (line number, name) in *text* whose code names a macOS-only tool, path or API.
fn violations(text: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let code = code_of(line).to_ascii_lowercase();
        for name in MACOS_ONLY {
            if code.contains(name) {
                found.push((index + 1, *name));
            }
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("source folder readable") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

#[test]
fn os_calls_stay_in_platform() {
    let src = source();
    let platform = src.join("platform");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 10, "the scan found the sources");
    let mut problems = Vec::new();
    for file in files.iter().filter(|file| !file.starts_with(&platform)) {
        let text = std::fs::read_to_string(file).expect("source readable");
        for (line, name) in violations(&text) {
            problems.push(format!("{}:{line} names `{name}`", file.strip_prefix(&src).unwrap().display()));
        }
    }
    assert!(problems.is_empty(), "system calls outside src/platform/ — move them into platform/macos/:\n{}", problems.join("\n"));
}

#[test]
fn each_os_folder_is_compiled_only_for_its_os() {
    let text = std::fs::read_to_string(source().join("platform/mod.rs")).expect("platform/mod.rs");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let declared_after = |declaration: &str| lines.windows(2).filter(|pair| pair[1] == declaration).map(|pair| pair[0]).collect::<Vec<_>>();
    assert_eq!(declared_after("pub mod macos;"), vec![r#"#[cfg(target_os = "macos")]"#]);
    assert_eq!(declared_after("mod unsupported;"), vec![r#"#[cfg(not(target_os = "macos"))]"#]);
}

#[test]
fn the_scanner_flags_a_system_call_in_code() {
    assert_eq!(violations(r#"let out = Command::new("/bin/launchctl").arg("print");"#), vec![(1, "launchctl")]);
    assert_eq!(violations("let n = unsafe { libc::proc_pidpath(pid, b, len) };"), vec![(1, "proc_pidpath")]);
    assert_eq!(violations(r#"pub const HOME: &str = "/Library/Application Support/Blackbox";"#), vec![(1, "/library/")]);
    let url_then_call = r#"let url = "http://127.0.0.1"; run("/sbin/pfctl");"#;
    assert_eq!(violations(url_then_call), vec![(1, "pfctl")], "a // inside a string is not a comment");
}

#[test]
fn the_scanner_ignores_comments() {
    assert!(violations("//! reads pfctl's answer\n    // netstat failing costs nothing").is_empty());
    assert!(violations(r#"let every = 2; // like nettop"#).is_empty());
    assert!(violations("fn reading() -> u32 { 1 }").is_empty());
}
