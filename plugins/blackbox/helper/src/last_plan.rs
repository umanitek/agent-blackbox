//! The last plan the helper applied, kept so a restart re-applies it at once.
//!
//! WHY (E2E 2026-11-21): after a restart or an upgrade the helper started empty and waited for
//! the plugin's next plan — about a minute in which DNS Shield refused nothing and the firewall's
//! table was empty. The plan's exact bytes are saved in the helper's root-only folder each time a
//! new one is applied (verified first when the helper is paired, [`crate::link`]) and read back
//! at start ([`load`]).
//!
//! Usage: `last_plan::save(home, &body)` after applying; `last_plan::load(home)` at start.

use std::path::{Path, PathBuf};

use crate::plan::Plan;
use crate::{private_files, safe_read};

/// The file, in the helper's root-only folder.
pub const FILE: &str = "last-plan.json";
/// The largest saved plan read back (the verified graph's lists are a few megabytes).
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

fn path(home: &Path) -> PathBuf {
    home.join(FILE)
}

/// Saves *body* (a plan's exact bytes) owner-only; a failure is not fatal — the next plan comes anyway.
pub fn save(home: &Path, body: &[u8]) {
    let _ = private_files::write(&path(home), body);
}

/// The saved plan, when there is one that reads as a plan (a damaged or oversized file is ignored).
pub fn load(home: &Path) -> Option<Plan> {
    let bytes = safe_read::read_regular(&path(home), MAX_BYTES)?;
    let plan: Plan = serde_json::from_slice(&bytes).ok()?;
    (!plan.unchanged && !plan.version.is_empty()).then_some(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-last-plan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_saved_plan_comes_back_at_start_owner_only() {
        let dir = home("saved");
        let body = br#"{"version":"v7","dns":{"enabled":true,"verified":["bad.example"]},"firewall":{"enabled":true,"ips":["1.0.164.165"]}}"#;
        save(&dir, body);
        let plan = load(&dir).expect("the saved plan");
        assert_eq!(plan.version, "v7");
        assert!(plan.dns.enabled && plan.firewall.enabled && plan.dns.verified == ["bad.example"]);
        let mode = std::fs::metadata(dir.join(FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "only the helper (root) may read it");
    }

    #[test]
    fn nothing_usable_means_nothing_applied() {
        let dir = home("none");
        assert!(load(&dir).is_none());                                // none saved yet
        save(&dir, b"not json");
        assert!(load(&dir).is_none());                                // damaged
        save(&dir, br#"{"unchanged":true,"version":"v1"}"#);
        assert!(load(&dir).is_none());                                // "unchanged" is not a plan
    }
}
