//! Structure guard for the helper's per-OS layout (Amos 2026-11-21): every call the helper makes
//! to the operating system lives under `src/platform/<os>/`, and only the build for that OS
//! compiles it.
//!
//! * `os_calls_stay_in_platform` — no system tool, path or API is named in code outside
//!   `src/platform/` (comments may mention them; code may not). A new system call goes into
//!   `platform/<os>/` behind the `Enforcer` / `Observer` traits in `platform/mod.rs`, with the
//!   matching method in every other OS folder and in `unsupported.rs`.
//! * `each_os_folder_names_only_its_own_os` — `platform/linux/` names no macOS tool and
//!   `platform/macos/` no Linux one (a copy-paste between ports would otherwise compile away
//!   silently on the other OS).
//! * `each_os_folder_is_compiled_only_for_its_os` — `platform/mod.rs` declares `macos` only under
//!   `#[cfg(target_os = "macos")]`, `linux` only under `#[cfg(target_os = "linux")]`, and the
//!   fallback only for every other OS.
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

/// Names of Linux tools, paths and APIs that only `platform/linux/` may use (lower case: the
/// scan lower-cases each line).
const LINUX_ONLY: &[&str] = &[
    "nft", "resolvectl", "systemctl", "busctl", "nmcli", "apparmor_parser", "restorecon", "/proc/net",
    "/etc/systemd", "fanotify", "landlock", "sock_diag", "/var/lib/blackbox",
];

/// Every (line number, name) in *text* whose code names a macOS-only or Linux-only tool, path or API.
fn violations(text: &str) -> Vec<(usize, &'static str)> {
    violations_of(text, &[MACOS_ONLY, LINUX_ONLY])
}

/// Every (line number, name) in *text* whose code names one of *lists*' names.
fn violations_of(text: &str, lists: &[&[&'static str]]) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let code = code_of(line).to_ascii_lowercase();
        for name in lists.iter().flat_map(|list| list.iter()) {
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
    assert!(problems.is_empty(), "system calls outside src/platform/ — move them into platform/<os>/:\n{}", problems.join("\n"));
}

#[test]
fn each_os_folder_names_only_its_own_os() {
    let platform = source().join("platform");
    let mut problems = Vec::new();
    let mut scanned = 0;
    for (folder, foreign) in [("linux", MACOS_ONLY), ("macos", LINUX_ONLY)] {
        // WHY the check: an installer's sparse checkout carries only its own OS's folder.
        if !platform.join(folder).is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&platform.join(folder), &mut files);
        scanned += files.len();
        for file in &files {
            let text = std::fs::read_to_string(file).expect("source readable");
            for (line, name) in violations_of(&text, &[foreign]) {
                problems.push(format!("{}:{line} names `{name}`", file.strip_prefix(&platform).unwrap().display()));
            }
        }
    }
    assert!(scanned > 0, "the scan found an OS folder's sources");
    assert!(problems.is_empty(), "another OS's tool inside an OS folder:\n{}", problems.join("\n"));
}

#[test]
fn each_os_folder_is_compiled_only_for_its_os() {
    let text = std::fs::read_to_string(source().join("platform/mod.rs")).expect("platform/mod.rs");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let declared_after = |declaration: &str| lines.windows(2).filter(|pair| pair[1] == declaration).map(|pair| pair[0]).collect::<Vec<_>>();
    assert_eq!(declared_after("pub mod macos;"), vec![r#"#[cfg(target_os = "macos")]"#]);
    assert_eq!(declared_after("pub mod linux;"), vec![r#"#[cfg(target_os = "linux")]"#]);
    assert_eq!(declared_after("mod unsupported;"), vec![r#"#[cfg(not(any(target_os = "macos", target_os = "linux")))]"#]);
}

#[test]
fn the_scanner_flags_a_system_call_in_code() {
    assert_eq!(violations(r#"let out = Command::new("/bin/launchctl").arg("print");"#), vec![(1, "launchctl")]);
    assert_eq!(violations("let n = unsafe { libc::proc_pidpath(pid, b, len) };"), vec![(1, "proc_pidpath")]);
    assert_eq!(violations(r#"pub const HOME: &str = "/Library/Application Support/Blackbox";"#), vec![(1, "/library/")]);
    let url_then_call = r#"let url = "http://127.0.0.1"; run("/sbin/pfctl");"#;
    assert_eq!(violations(url_then_call), vec![(1, "pfctl")], "a // inside a string is not a comment");
    assert_eq!(violations(r#"run("/usr/sbin/nft", &["-f", "-"]);"#), vec![(1, "nft")]);
    assert_eq!(violations(r#"let unit = "/etc/systemd/system/x.service";"#), vec![(1, "/etc/systemd")]);
    assert_eq!(violations(r#"let fd = unsafe { libc::socket(libc::AF_NETLINK, 0, libc::NETLINK_SOCK_DIAG) };"#), vec![(1, "sock_diag")]);
}

#[test]
fn the_scanner_ignores_comments() {
    assert!(violations("//! reads pfctl's answer\n    // netstat failing costs nothing").is_empty());
    assert!(violations(r#"let every = 2; // like nettop"#).is_empty());
    assert!(violations("fn reading() -> u32 { 1 }").is_empty());
}
