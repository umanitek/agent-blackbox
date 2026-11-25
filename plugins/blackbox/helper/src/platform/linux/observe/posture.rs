//! Posture on Linux: the raw facts behind the security posture check, read as root every
//! [`POSTURE_EVERY`] (or at once when the app asks). Observing only, and on Linux report-only:
//! no posture fix changes the system here (founder decision F8, Linux deep layers).
//!
//! Facts: full-disk encryption (a LUKS device under `/sys/block/*/dm/uuid`), the system firewall
//! (as [`super::tamper::firewall`]), Secure Boot (the `SecureBoot` EFI variable), automatic
//! updates (Debian / Ubuntu's `20auto-upgrades`, Fedora's `dnf-automatic` timer), the sharing
//! services (listening ports 22 / 5900 / 3389 / 445 from the exposure look), the display
//! manager's automatic login (GDM's `custom.conf`), SSH password logins (`sshd -T`) and whether
//! sudo needs no password.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};

use crate::platform::system_watch::sudoers::passwordless_sudo;

pub const POSTURE_EVERY: Duration = Duration::from_secs(60);
pub const BLOCK_DEVICES: &str = "/sys/block";
/// The EFI global variable `SecureBoot` (its GUID is the UEFI specification's).
pub const SECURE_BOOT: &str = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
pub const AUTO_UPGRADES: &str = "/etc/apt/apt.conf.d/20auto-upgrades";
pub const TIMER_WANTS: &str = "/etc/systemd/system/timers.target.wants";
pub const GDM_CONFIGS: &[&str] = &["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"];
pub const SSHD_COMMANDS: &[&str] = &["/usr/sbin/sshd", "/sbin/sshd"];
const SMALL: u64 = 64 * 1024;

fn text(path: &str) -> Option<String> {
    crate::safe_read::read_regular(Path::new(path), SMALL).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Secure Boot from the EFI variable's bytes (4 attribute bytes, then the value): on | off | unknown.
pub fn parse_secure_boot(bytes: Option<&[u8]>) -> &'static str {
    match bytes.and_then(|b| b.get(4)) {
        Some(1) => "on",
        Some(0) => "off",
        _ => "unknown",
    }
}

/// Whether Debian / Ubuntu's `20auto-upgrades` turns unattended upgrades on.
pub fn parse_auto_upgrades(text: &str) -> bool {
    text.lines().map(str::trim).filter(|line| !line.starts_with("//")).any(|line| {
        line.starts_with("APT::Periodic::Unattended-Upgrade") && line.split('"').nth(1).is_some_and(|value| value != "0")
    })
}

/// GDM's automatic login from its `custom.conf`: on | off.
pub fn parse_gdm_autologin(text: &str) -> &'static str {
    let on = text.lines().map(str::trim).filter(|line| !line.starts_with('#'))
        .any(|line| line.replace(' ', "").eq_ignore_ascii_case("AutomaticLoginEnable=true"));
    if on { "on" } else { "off" }
}

/// `passwordauthentication` from `sshd -T`: yes | no | unknown.
pub fn parse_sshd_password(text: &str) -> &'static str {
    match text.lines().find_map(|line| line.strip_prefix("passwordauthentication ")).map(str::trim) {
        Some("yes") => "yes",
        Some("no") => "no",
        _ => "unknown",
    }
}

/// on when a block device is a LUKS mapping, off when none is, unknown when unreadable.
fn disk_encryption() -> &'static str {
    let Ok(devices) = fs::read_dir(BLOCK_DEVICES) else { return "unknown" };
    let luks = devices.flatten().any(|device| {
        text(&device.path().join("dm/uuid").display().to_string()).is_some_and(|uuid| uuid.starts_with("CRYPT-LUKS"))
    });
    if luks { "on" } else { "off" }
}

fn automatic_updates() -> &'static str {
    if text(AUTO_UPGRADES).is_some_and(|t| parse_auto_upgrades(&t)) {
        return "on";
    }
    let dnf = fs::read_dir(TIMER_WANTS).map(|entries| entries.flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("dnf-automatic"))).unwrap_or(false);
    if dnf { "on" } else if Path::new(AUTO_UPGRADES).exists() || Path::new(TIMER_WANTS).is_dir() { "off" } else { "unknown" }
}

fn gdm_autologin() -> &'static str {
    GDM_CONFIGS.iter().find_map(|path| text(path)).map(|t| parse_gdm_autologin(&t)).unwrap_or("unknown")
}

fn ssh_password_logins() -> &'static str {
    let Some(sshd) = SSHD_COMMANDS.iter().find(|path| Path::new(path).exists()) else { return "unknown" };
    crate::command::output(Command::new(sshd).arg("-T"), crate::command::TIMEOUT).ok()
        .map(|out| parse_sshd_password(&String::from_utf8_lossy(&out.stdout))).unwrap_or("unknown")
}

/// The facts now. *listening* is the set of TCP ports reachable from the network (exposure).
pub fn look(listening: &BTreeSet<u16>) -> Value {
    json!({
        "disk_encryption": disk_encryption(),
        "firewall": super::tamper::firewall(),
        "secure_boot": parse_secure_boot(crate::safe_read::read_regular(Path::new(SECURE_BOOT), 64).as_deref()),
        "updates": {"automatic": automatic_updates()},
        "remote_login": listening.contains(&22),
        "screen_sharing": listening.contains(&5900) || listening.contains(&3389),
        "file_sharing": listening.contains(&445),
        "autologin": gdm_autologin(),
        "ssh_password_logins": ssh_password_logins(),
        "passwordless_sudo": passwordless_sudo(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_facts_parse() {
        assert_eq!(parse_secure_boot(Some(&[6, 0, 0, 0, 1])), "on");
        assert_eq!(parse_secure_boot(Some(&[6, 0, 0, 0, 0])), "off");
        assert_eq!(parse_secure_boot(None), "unknown");
        assert!(parse_auto_upgrades("APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"));
        assert!(!parse_auto_upgrades("APT::Periodic::Unattended-Upgrade \"0\";\n// APT::Periodic::Unattended-Upgrade \"1\";\n"));
        assert_eq!(parse_gdm_autologin("[daemon]\nAutomaticLoginEnable = true\nAutomaticLogin = amos\n"), "on");
        assert_eq!(parse_gdm_autologin("[daemon]\n# AutomaticLoginEnable=true\n"), "off");
        assert_eq!(parse_sshd_password("port 22\npasswordauthentication yes\npubkeyauthentication yes\n"), "yes");
        assert_eq!(parse_sshd_password(""), "unknown");
    }
}
