//! pf's status — read only (`pfctl -s info`). Its own module so the observers (the tamper watch)
//! can ask without naming anything that changes the system (observe/'s structural guard), and the
//! pf applier verifies its own work with the same reader.

use std::process::Command;

/// `Status: Enabled …` → Some(true); `Status: Disabled …` → Some(false); anything else None.
pub fn parse(text: &str) -> Option<bool> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("Status:")?.trim_start();
        if rest.starts_with("Enabled") { Some(true) } else if rest.starts_with("Disabled") { Some(false) } else { None }
    })
}

/// pf's status now (None when it cannot be read, e.g. not root).
pub fn read() -> Option<bool> {
    let out = crate::command::output(Command::new("/sbin/pfctl").args(["-s", "info"]), crate::command::TIMEOUT).ok()?;
    parse(&format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_line_reads() {
        assert_eq!(parse("No ALTQ support in kernel\nStatus: Enabled for 0 days 00:01:02           Debug: Urgent"), Some(true));
        assert_eq!(parse("Status: Disabled                              Debug: Urgent"), Some(false));
        assert_eq!(parse("pfctl: /dev/pf: Permission denied"), None);
    }
}
