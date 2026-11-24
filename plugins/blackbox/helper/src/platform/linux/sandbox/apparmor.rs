//! The AppArmor rule that lets the sandbox launcher make its user namespaces on Ubuntu 23.10+
//! (founder decision F2). Ubuntu restricts unprivileged user namespaces
//! (`kernel.apparmor_restrict_unprivileged_userns=1`): `unshare` still succeeds, but the new
//! namespace has no capabilities, so no mount can be made and the sandbox would fall back to hooks
//! only. One profile names the launcher's installed path and allows it `userns`; it is
//! `unconfined` otherwise (it adds a right, takes none), and what the launcher starts inherits it —
//! so nested sandboxes (Claude Code's bubblewrap, an Electron app) keep working inside.
//!
//! Called by the helper's install (as root, after the launcher is in place) and its uninstall:
//! [`install`] writes `/etc/apparmor.d/blackbox-sandbox` and loads it; [`remove`] unloads and
//! deletes it. A machine without the restriction (Debian, Fedora, Ubuntu 22.04) or without
//! AppArmor gets nothing ([`needed`]).

use std::path::Path;
use std::process::Command;

/// The profile's file.
pub const PROFILE_FILE: &str = "/etc/apparmor.d/blackbox-sandbox";
/// The profile's name.
pub const PROFILE_NAME: &str = "blackbox-sandbox";
/// Ubuntu's switch (present only where the kernel can restrict user namespaces).
pub const RESTRICT_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
/// Where `apparmor_parser` lives.
pub const PARSERS: &[&str] = &["/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"];

/// The profile text for the launcher at *binary* (an absolute path without spaces or quotes —
/// the install's own constant).
pub fn profile_text(binary: &str) -> String {
    format!("# Blackbox's agent sandbox launcher may create user namespaces (Ubuntu restricts them).\n\
             # Written by Blackbox's system protection helper; removed by its uninstall.\n\
             abi <abi/4.0>,\n\
             include <tunables/global>\n\n\
             profile {PROFILE_NAME} {binary} flags=(unconfined) {{\n  userns,\n\n  include if exists <local/{PROFILE_NAME}>\n}}\n")
}

/// Whether this machine needs the rule: the restriction exists (on or off: the person may switch
/// it on later) and AppArmor's parser is there to load it.
pub fn needed() -> bool {
    Path::new(RESTRICT_SYSCTL).exists() && parser().is_some()
}

fn parser() -> Option<&'static str> {
    PARSERS.iter().copied().find(|path| Path::new(path).exists())
}

fn run_parser(flag: &str) -> Result<(), String> {
    let parser = parser().ok_or("AppArmor's apparmor_parser is not installed")?;
    let out = crate::command::output(Command::new(parser).args([flag, PROFILE_FILE]), crate::command::TIMEOUT)
        .map_err(|error| format!("apparmor_parser {flag}: {error}"))?;
    if !out.status.success() {
        return Err(format!("apparmor_parser {flag}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Writes and loads the rule for the launcher at *binary*; Ok(false) when this machine does not
/// need it. Root only (the install).
pub fn install(binary: &str) -> Result<bool, String> {
    if !binary.starts_with('/') || binary.contains(|c: char| c.is_whitespace() || c == '"' || c == '\0') {
        return Err(format!("not a launcher path the rule can name: {binary:?}"));
    }
    if !needed() {
        return Ok(false);
    }
    let staged = format!("{PROFILE_FILE}.blackbox-new");
    std::fs::write(&staged, profile_text(binary)).map_err(|error| format!("{staged}: {error}"))?;
    std::fs::rename(&staged, PROFILE_FILE).map_err(|error| format!("{PROFILE_FILE}: {error}"))?;
    run_parser("-r")?;
    Ok(true)
}

/// Unloads and deletes the rule; answers what failed (nothing → empty). Root only (the uninstall).
pub fn remove() -> Vec<String> {
    if !Path::new(PROFILE_FILE).exists() {
        return vec![];
    }
    let mut failed = vec![];
    if let Err(why) = run_parser("-R") {
        failed.push(why);
    }
    if let Err(error) = std::fs::remove_file(PROFILE_FILE) {
        failed.push(format!("{PROFILE_FILE}: {error}"));
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_names_the_launcher_and_only_adds_user_namespaces() {
        let text = profile_text("/usr/local/libexec/blackbox/blackbox-sandbox");
        assert!(text.contains("profile blackbox-sandbox /usr/local/libexec/blackbox/blackbox-sandbox flags=(unconfined) {"));
        assert!(text.contains("  userns,\n"));
        assert!(text.starts_with('#') && text.contains("abi <abi/4.0>,"));
        let rules: Vec<&str> = text.lines().map(str::trim).filter(|l| l.ends_with(',') && !l.starts_with("abi")).collect();
        assert_eq!(rules, vec!["userns,"], "no other right is granted");
    }

    #[test]
    fn a_path_the_rule_can_not_name_safely_is_refused_before_anything_is_written() {
        for bad in ["relative/x", "/a b", "/a\"b"] {
            assert!(install(bad).is_err(), "{bad:?}");
        }
    }
}
