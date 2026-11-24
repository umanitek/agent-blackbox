//! Whether sudo lets someone run commands as root without a password — the same rules files
//! (`/etc/sudoers`, `/etc/sudoers.d/*`) on macOS and Linux, readable only by root, which is why
//! the helper's posture look answers it and not the plugin.

/// True when *text* (a sudoers file) lets someone run commands as root without a password:
/// a line that is not a comment and carries `NOPASSWD`.
pub fn sudoers_skips_password(text: &str) -> bool {
    text.lines().map(str::trim).any(|line| !line.starts_with('#') && line.to_ascii_uppercase().contains("NOPASSWD"))
}

/// Whether sudo needs no password on this machine: "yes" | "no" | "unknown" (the rules could not be
/// read). Only root can read them, which is why the helper answers this and not the plugin.
pub fn passwordless_sudo() -> &'static str {
    let Ok(main) = std::fs::read_to_string("/etc/sudoers") else { return "unknown" };
    let mut texts = vec![main];
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        texts.extend(entries.flatten().take(200).filter_map(|entry| std::fs::read_to_string(entry.path()).ok()));
    }
    if texts.iter().any(|text| sudoers_skips_password(text)) { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sudoers_line_without_a_password_is_seen_and_a_comment_is_not() {
        assert!(sudoers_skips_password("root ALL=(ALL) ALL\nadmin ALL=(ALL) NOPASSWD: ALL\n"));
        assert!(sudoers_skips_password("%admin ALL = (ALL) nopasswd: /usr/bin/true"));
        assert!(!sudoers_skips_password("# admin ALL=(ALL) NOPASSWD: ALL\n%admin ALL=(ALL) ALL\n"));
        assert!(!sudoers_skips_password(""));
    }
}
