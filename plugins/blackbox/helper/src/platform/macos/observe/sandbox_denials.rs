//! File Shield Layer 2's refusals as macOS logs them: one `log stream` child (the helper's own),
//! filtered to the kernel sandbox's `deny` messages that name one of the watched paths — so the
//! person sees "the sandbox stopped python3 reaching ~/Documents/Taxes/2025.pdf" within a second.
//!
//! A message reads `Sandbox: python3(4242) deny(1) file-read-data /Users/me/Taxes/2025.pdf`; only
//! the program's name, the path and that it was refused leave this module (as a [`Change`] of kind
//! `denied`). The plugin keeps only denials inside the person's CURRENT protected items. Observing
//! only — the kernel already refused; nothing here changes the system.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;

use serde_json::Value;

use super::file_watch::Change;

const LOG: &str = "/usr/bin/log";
/// The longest program name passed on (the plugin's own limit).
const MAX_PROGRAM_CHARS: usize = 64;
/// Most paths one predicate names (the plan's own limit is larger; the rest are the plugin's to drop).
const MAX_PREDICATE_PATHS: usize = 64;

/// The predicate: the sandbox kext's deny messages naming one of *paths*.
pub fn predicate(paths: &[String]) -> Option<String> {
    let named: Vec<String> = paths.iter().take(MAX_PREDICATE_PATHS)
        .map(|p| format!("eventMessage CONTAINS \"{}\"", p.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    if named.is_empty() {
        return None;
    }
    Some(format!("senderImagePath ENDSWITH \"/Sandbox\" AND eventMessage BEGINSWITH \"Sandbox: \" \
AND eventMessage CONTAINS \" deny(\" AND ({})", named.join(" OR ")))
}

/// One deny message as a change: `Sandbox: <program>(<pid>) deny(<n>) <operation> <path>` for a
/// file operation; None for anything else.
pub fn parse(message: &str) -> Option<Change> {
    let rest = message.strip_prefix("Sandbox: ")?;
    let deny_at = rest.find(") deny(")?;
    let (program, pid) = rest[..deny_at].rsplit_once('(')?;
    let pid: u32 = pid.parse().unwrap_or(0);
    let after = &rest[deny_at + ") deny(".len()..];
    let after = &after[after.find(") ")? + 2..];
    let (operation, path) = after.split_once(' ')?;
    if !operation.starts_with("file-") || !path.starts_with('/') {
        return None;
    }
    let program: String = program.chars().filter(|c| !c.is_control()).take(MAX_PROGRAM_CHARS).collect();
    Some(Change { path: path.to_string(), kind: "denied", program, pid })
}

/// A running `log stream` over the sandbox's denials; ends (killed and waited for) when dropped.
pub struct Denials {
    child: Child,
}

impl Denials {
    /// Starts reading denials for *paths*, each sent as a [`Change`]; None when nothing to watch or
    /// `log` could not start (the FSEvents watch still runs).
    pub fn start(paths: &[String], sender: Sender<Change>) -> Option<Denials> {
        let predicate = predicate(paths)?;
        let mut child = Command::new(LOG)
            .args(["stream", "--style", "ndjson", "--predicate", &predicate])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
        let stdout = child.stdout.take()?;
        std::thread::Builder::new().name("blackbox-sandbox-denials".into()).spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let Ok(value) = serde_json::from_str::<Value>(&line) else { continue };
                if let Some(change) = value.get("eventMessage").and_then(Value::as_str).and_then(parse) {
                    if sender.send(change).is_err() {
                        break;
                    }
                }
            }
        }).ok()?;
        Some(Denials { child })
    }
}

impl Drop for Denials {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_denial_names_the_program_and_the_path() {
        let change = parse("Sandbox: python3.14(4242) deny(1) file-read-data /Users/me/Taxes/2025 return.pdf").unwrap();
        assert_eq!(change, Change { path: "/Users/me/Taxes/2025 return.pdf".into(), kind: "denied", program: "python3.14".into(), pid: 4242 });
        let odd = parse("Sandbox: Code Helper (Plugin)(77) deny(1) file-write-unlink /Users/me/Taxes").unwrap();
        assert_eq!((odd.program.as_str(), odd.path.as_str()), ("Code Helper (Plugin)", "/Users/me/Taxes"));
    }

    #[test]
    fn anything_else_is_not_a_change() {
        assert_eq!(parse("Sandbox: curl(1) deny(1) network-outbound 127.0.0.1:22"), None);
        assert_eq!(parse("System Policy: cat(1) deny(1) file-read-data /x"), None);
        assert_eq!(parse("Sandbox: cat(1) allow file-read-data /x"), None);
        assert_eq!(parse("Sandbox: cat(1) deny(1) file-read-data relative"), None);
    }

    #[test]
    fn the_predicate_names_each_path_quoted_and_nothing_without_paths() {
        assert_eq!(predicate(&[]), None);
        let text = predicate(&["/Users/me/a \"b\"".into()]).unwrap();
        assert!(text.contains("eventMessage CONTAINS \"/Users/me/a \\\"b\\\"\""), "{text}");
        assert!(text.starts_with("senderImagePath ENDSWITH \"/Sandbox\""));
    }

    #[test]
    fn a_real_sandbox_denial_is_read_from_the_log() {
        use std::sync::mpsc::channel;
        use std::time::{Duration, Instant};
        let folder = std::env::temp_dir().join(format!("bb-denials-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let folder = folder.canonicalize().unwrap();
        let secret = folder.join("secret.txt");
        std::fs::write(&secret, b"s").unwrap();
        let profile = folder.join("p.sb");
        std::fs::write(&profile, format!("(version 1)\n(allow default)\n(deny file-read* (literal \"{}\"))\n", secret.display())).unwrap();
        let (sender, receiver) = channel();
        let watched = vec![secret.to_string_lossy().into_owned()];
        let denials = Denials::start(&watched, sender).expect("log stream");
        std::thread::sleep(Duration::from_millis(1500));   // the stream reports from its start onwards
        let _ = Command::new("/usr/bin/sandbox-exec").arg("-f").arg(&profile).arg("/bin/cat").arg(&secret)
            .stdout(Stdio::null()).stderr(Stdio::null()).status();
        let started = Instant::now();
        let mut seen = None;
        while started.elapsed() < Duration::from_secs(15) && seen.is_none() {
            seen = receiver.recv_timeout(Duration::from_millis(500)).ok();
        }
        drop(denials);
        let _ = std::fs::remove_dir_all(&folder);
        let change = seen.expect("the denial was read from the log");
        assert_eq!((change.kind, change.program.as_str()), ("denied", "cat"));
        assert!(change.path.ends_with("secret.txt"), "{change:?}");
    }
}
