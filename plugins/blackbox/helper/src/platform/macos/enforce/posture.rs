//! Posture fixes: the few one-click changes that are safe to make for the person (asked first in
//! the app). Each is applied only when the Mac is not already in the safe state, and remembered
//! with what it changed ([`Fixes`], saved in the helper's folder) so it can be put back exactly.
//!
//! **Undo:** a fix the plan no longer lists — the person pressed Undo, or Network Shield was
//! switched off — is reversed; when the helper stops, every applied fix is reversed. A fix that
//! found the Mac already safe changed nothing and reverses nothing.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

/// Every fix the helper knows; any other id in a plan is ignored.
pub const FIXES: [&str; 7] = ["firewall-on", "stealth-on", "guest-off", "screen-sharing-off", "file-sharing-off", "remote-login-off", "remote-management-off"];
const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
const KICKSTART: &str = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart";
/// The system services a fix may switch off, with their LaunchDaemon plist.
const SERVICES: [(&str, &str, &str); 3] = [
    ("screen-sharing-off", "com.apple.screensharing", "/System/Library/LaunchDaemons/com.apple.screensharing.plist"),
    ("file-sharing-off", "com.apple.smbd", "/System/Library/LaunchDaemons/com.apple.smbd.plist"),
    ("remote-login-off", "com.openssh.sshd", "/System/Library/LaunchDaemons/ssh.plist"),
];

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = crate::command::output(Command::new(program).args(args), crate::command::TIMEOUT).map_err(|e| format!("{program}: {e}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() { Ok(text) } else { Err(format!("{program} {}: {}", args.join(" "), text.trim())) }
}

/// Whether *label* is disabled in `launchctl print-disabled system`.
pub fn service_disabled(print_disabled: &str, label: &str) -> bool {
    print_disabled.lines().any(|line| line.contains(&format!("\"{label}\"")) && (line.contains("=> disabled") || line.contains("=> true")))
}

/// True when the Mac is already in the state fix *id* makes.
fn already_safe(id: &str) -> bool {
    let text = |program: &str, args: &[&str]| run(program, args).unwrap_or_default().to_ascii_lowercase();
    match id {
        "firewall-on" => { let t = text(FIREWALL, &["--getglobalstate"]); t.contains("enabled") || t.contains("state = 1") || t.contains("state = 2") }
        "stealth-on" => { let t = text(FIREWALL, &["--getstealthmode"]); t.contains("is on") || (t.contains("enabled") && !t.contains("disabled")) }
        "guest-off" => text("/usr/bin/defaults", &["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]).trim() != "1",
        "remote-management-off" => !crate::command::output(Command::new("/usr/bin/pgrep").args(["-x", "ARDAgent"]), crate::command::TIMEOUT).map(|o| o.status.success()).unwrap_or(false),
        _ => SERVICES.iter().find(|(fix, _, _)| *fix == id)
            .map(|(_, label, _)| service_disabled(&run("/bin/launchctl", &["print-disabled", "system"]).unwrap_or_default(), label))
            .unwrap_or(true),
    }
}

fn apply(id: &str) -> Result<(), String> {
    match id {
        "firewall-on" => run(FIREWALL, &["--setglobalstate", "on"]).map(drop),
        "stealth-on" => run(FIREWALL, &["--setstealthmode", "on"]).map(drop),
        "guest-off" => run("/usr/sbin/sysadminctl", &["-guestAccount", "off"]).map(drop),
        "remote-management-off" => run(KICKSTART, &["-deactivate", "-stop"]).map(drop),
        _ => {
            let (_, label, _) = SERVICES.iter().find(|(fix, _, _)| *fix == id).ok_or("unknown fix")?;
            run("/bin/launchctl", &["disable", &format!("system/{label}")])?;
            let _ = run("/bin/launchctl", &["bootout", &format!("system/{label}")]);   // may not be loaded
            Ok(())
        }
    }
}

fn undo(id: &str) -> Result<(), String> {
    match id {
        "firewall-on" => run(FIREWALL, &["--setglobalstate", "off"]).map(drop),
        "stealth-on" => run(FIREWALL, &["--setstealthmode", "off"]).map(drop),
        "guest-off" => run("/usr/sbin/sysadminctl", &["-guestAccount", "on"]).map(drop),
        "remote-management-off" => run(KICKSTART, &["-activate", "-restart", "-agent"]).map(drop),
        _ => {
            let (_, label, plist) = SERVICES.iter().find(|(fix, _, _)| *fix == id).ok_or("unknown fix")?;
            run("/bin/launchctl", &["enable", &format!("system/{label}")])?;
            let _ = run("/bin/launchctl", &["bootstrap", "system", plist]);
            Ok(())
        }
    }
}

/// The fixes applied now and what each changed ("changed", or "already" when the Mac was safe).
#[derive(Debug, Default)]
pub struct Fixes {
    path: PathBuf,
    applied: BTreeMap<String, String>,
}

impl Fixes {
    pub fn load(path: PathBuf) -> Fixes {
        let applied = fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        Fixes { path, applied }
    }

    fn save(&self) {
        if let Ok(text) = serde_json::to_string(&self.applied) {
            let _ = crate::private_files::write(&self.path, text.as_bytes());
        }
    }

    /// Makes the applied set equal *desired* (unknown ids ignored); answers one event per change.
    pub fn follow(&mut self, desired: &[String]) -> Vec<Value> {
        let wanted: Vec<&str> = FIXES.iter().copied().filter(|id| desired.iter().any(|d| d == id)).collect();
        let mut events = Vec::new();
        let to_apply: Vec<&str> = wanted.iter().copied().filter(|id| !self.applied.contains_key(*id)).collect();
        for id in to_apply {
            let outcome = if already_safe(id) { Ok("already") } else { apply(id).map(|_| "changed") };
            match outcome {
                Ok(how) => { self.applied.insert(id.to_string(), how.to_string()); events.push(json!({"kind": "fix-applied", "fix": id, "how": how})); }
                Err(error) => events.push(json!({"kind": "fix-failed", "fix": id, "error": error.chars().take(300).collect::<String>()})),
            }
        }
        let drop_ids: Vec<String> = self.applied.keys().filter(|id| !wanted.contains(&id.as_str())).cloned().collect();
        for id in drop_ids {
            events.push(self.reverse(&id));
        }
        self.save();
        events
    }

    fn reverse(&mut self, id: &str) -> Value {
        let how = self.applied.remove(id).unwrap_or_default();
        if how != "changed" {
            return json!({"kind": "fix-undone", "fix": id, "how": "nothing to undo"});
        }
        match undo(id) {
            Ok(()) => json!({"kind": "fix-undone", "fix": id, "how": "restored"}),
            Err(error) => json!({"kind": "fix-failed", "fix": id, "error": error.chars().take(300).collect::<String>()}),
        }
    }

    /// The helper stops: every applied fix is reversed.
    pub fn undo_all(&mut self) -> Vec<Value> {
        let events = self.follow(&[]);
        self.save();
        events
    }

    pub fn applied(&self) -> Vec<String> {
        self.applied.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_services_parse() {
        let text = "disabled services = {\n\t\"com.apple.screensharing\" => disabled\n\t\"com.openssh.sshd\" => enabled\n\t\"com.apple.smbd\" => true\n}\n";
        assert!(service_disabled(text, "com.apple.screensharing"));
        assert!(!service_disabled(text, "com.openssh.sshd"));
        assert!(service_disabled(text, "com.apple.smbd"));
    }

    #[test]
    fn an_empty_plan_reverses_nothing_that_was_never_applied_and_unknown_ids_are_ignored() {
        let path = std::env::temp_dir().join(format!("bb-fixes-{}.json", std::process::id()));
        let mut fixes = Fixes::load(path.clone());
        assert!(fixes.follow(&["format-the-disk".into()]).is_empty(), "an unknown fix id does nothing");
        assert!(fixes.undo_all().is_empty());
        assert!(fixes.applied().is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_fix_that_found_the_mac_safe_reverses_nothing() {
        let path = std::env::temp_dir().join(format!("bb-fixes-safe-{}.json", std::process::id()));
        let mut fixes = Fixes { path: path.clone(), applied: BTreeMap::from([("guest-off".to_string(), "already".to_string())]) };
        let events = fixes.follow(&[]);
        assert_eq!(events[0]["how"], "nothing to undo");
        let _ = fs::remove_file(path);
    }
}
