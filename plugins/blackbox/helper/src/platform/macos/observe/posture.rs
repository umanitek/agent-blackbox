//! Posture: the raw facts behind the security posture check, read as root every
//! [`POSTURE_EVERY`] (or at once when the app asks for a fresh check). Observing only — the
//! add-on (`network/monitor/posture.py`) turns these into checks, a score and advice.
//!
//! Facts: FileVault (`fdesetup status`), the macOS firewall and its stealth mode
//! (`socketfilterfw`), Gatekeeper (`spctl --status`), SIP (`csrutil status`), automatic updates
//! (`com.apple.SoftwareUpdate`), the sharing services (listening ports 22 / 5900 / 3283 / 445 from
//! the exposure look, and whether ARDAgent runs), AirDrop discoverability per user, the screen
//! lock (`sysadminctl -screenLock status`) and the guest account (`com.apple.loginwindow`).

use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};

use super::tamper::parse_firewall;
// Reading sudo's rules is every OS's (platform/system_watch).
pub use crate::platform::system_watch::sudoers::{passwordless_sudo, sudoers_skips_password};

pub const POSTURE_EVERY: Duration = Duration::from_secs(60);
const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

fn both(program: &str, args: &[&str]) -> String {
    crate::command::output(Command::new(program).args(args), crate::command::TIMEOUT)
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))).unwrap_or_default()
}

/// `on` / `off` / `unknown` from a status line: *on* and *off* are the words that decide.
pub fn on_off(text: &str, on: &[&str], off: &[&str]) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if off.iter().any(|word| lower.contains(word)) { "off" }
    else if on.iter().any(|word| lower.contains(word)) { "on" }
    else { "unknown" }
}

/// A `defaults read` value ("" when the key is not set).
fn default_value(domain: &str, key: &str) -> String {
    let out = crate::command::output(Command::new("/usr/bin/defaults").args(["read", domain, key]), crate::command::TIMEOUT);
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}

/// Every local user's AirDrop discoverability (`Everyone`, `Contacts Only`, `Off`, or "" for unset).
fn airdrop() -> Vec<Value> {
    let Ok(users) = fs::read_dir("/Users") else { return vec![] };
    users.flatten().map(|u| u.file_name().to_string_lossy().into_owned()).filter(|n| n != "Shared" && !n.starts_with('.'))
        .map(|name| json!({"user": name.clone(), "mode": default_value(&format!("/Users/{name}/Library/Preferences/com.apple.sharingd"), "DiscoverableMode")}))
        .collect()
}

/// The screen lock from `sysadminctl -screenLock status` ("immediate", a delay, "off", or "unknown").
pub fn parse_screen_lock(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("screenlock is off") { "off".into() }
    else if lower.contains("immediate") { "immediate".into() }
    else if let Some(rest) = lower.split("delay is").nth(1) { rest.trim().trim_end_matches('.').to_string() }
    else { "unknown".into() }
}

/// The facts now. *listening* is the set of TCP ports reachable from the network (exposure).
pub fn look(listening: &BTreeSet<u16>) -> Value {
    let ard_running = crate::command::output(Command::new("/usr/bin/pgrep").args(["-x", "ARDAgent"]), crate::command::TIMEOUT).map(|o| o.status.success()).unwrap_or(false);
    json!({
        "filevault": on_off(&both("/usr/bin/fdesetup", &["status"]), &["filevault is on"], &["filevault is off"]),
        "firewall": parse_firewall(&both(FIREWALL, &["--getglobalstate"])),
        "stealth": on_off(&both(FIREWALL, &["--getstealthmode"]), &["is on", "enabled"], &["is off", "disabled"]),
        "gatekeeper": on_off(&both("/usr/sbin/spctl", &["--status"]), &["assessments enabled"], &["assessments disabled"]),
        "sip": on_off(&both("/usr/bin/csrutil", &["status"]), &["status: enabled"], &["status: disabled"]),
        "updates": {
            "check": default_value("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"),
            "download": default_value("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"),
            "security": default_value("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"),
        },
        "remote_login": listening.contains(&22),
        "screen_sharing": listening.contains(&5900),
        "remote_management": ard_running || listening.contains(&3283),
        "file_sharing": listening.contains(&445),
        "airdrop": airdrop(),
        "screen_lock": parse_screen_lock(&both("/usr/sbin/sysadminctl", &["-screenLock", "status"])),
        "guest": default_value("/Library/Preferences/com.apple.loginwindow", "GuestEnabled"),
        "passwordless_sudo": passwordless_sudo(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines_parse() {
        assert_eq!(on_off("FileVault is On.", &["filevault is on"], &["filevault is off"]), "on");
        assert_eq!(on_off("FileVault is Off.", &["filevault is on"], &["filevault is off"]), "off");
        assert_eq!(on_off("assessments enabled", &["assessments enabled"], &["assessments disabled"]), "on");
        assert_eq!(on_off("System Integrity Protection status: enabled.", &["status: enabled"], &["status: disabled"]), "on");
        assert_eq!(on_off("Firewall stealth mode is on", &["is on", "enabled"], &["is off", "disabled"]), "on");
        assert_eq!(parse_screen_lock("2026-11-21 sysadminctl[1:2] screenLock delay is immediate"), "immediate");
        assert_eq!(parse_screen_lock("screenLock delay is 300 seconds"), "300 seconds");
        assert_eq!(parse_screen_lock("screenLock is off"), "off");
    }

    #[test]
    fn a_look_has_every_fact() {
        let facts = look(&BTreeSet::from([22]));
        for key in ["filevault", "firewall", "stealth", "gatekeeper", "sip", "updates", "remote_login", "screen_sharing", "remote_management", "file_sharing", "airdrop", "screen_lock", "guest", "passwordless_sudo"] {
            assert!(facts.get(key).is_some(), "{key}");
        }
        assert_eq!(facts["remote_login"], true);
    }
}
