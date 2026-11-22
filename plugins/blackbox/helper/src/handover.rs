//! A planned hand-over from one helper to the next (an upgrade): the old helper leaves the Mac's
//! protection in place when it stops, and the new one takes it over from the saved plan.
//!
//! WHY (KI-537, E2E full4 2026-11-22): an upgrade stopped the old helper, which put DNS back and
//! emptied the firewall as on any stop; the new one re-applied the saved plan about a second
//! later — a 1–2 s window with no DNS Shield and no Threat Firewall on every update.
//!
//! The installer ([`begin`], root, inside the helper's root-only folder) marks the hand-over
//! before it stops the old helper; the old helper's stop sees it ([`pending`]) and keeps DNS and
//! the pf rules; the new helper clears it ([`clear`]) once it has applied its saved plan. The
//! mark lasts [`LIFETIME`] at most: a stale one (an install that died) never keeps a later,
//! ordinary stop from putting the Mac back. While the two swap, DNS points at a resolver that is
//! briefly not answering: a lookup fails for that moment (the safe side) instead of resolving a
//! listed domain. An upgrade that ends with no helper at all puts DNS and the firewall back
//! (the installer's failure path), so the Mac is never left offline.
//!
//! Usage:
//!
//! ```text
//! handover::begin(home)?;                    // installer, before stopping the old helper
//! handover::pending(home, SystemTime::now()) // old helper, when it stops
//! handover::clear(home);                     // new helper, after its saved plan is applied
//! ```

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The mark's file name, inside the helper's root-only folder.
pub const MARK: &str = "handover";
/// How long a mark counts: an upgrade stops the old helper within seconds of marking.
pub const LIFETIME: Duration = Duration::from_secs(120);

/// Marks a hand-over about to happen in *home* (the time, in seconds since the epoch).
pub fn begin(home: &Path) -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_secs();
    fs::write(home.join(MARK), format!("{now}\n")).map_err(|error| format!("{}: {error}", home.join(MARK).display()))
}

/// True when a hand-over was marked in *home* less than [`LIFETIME`] before *now*.
pub fn pending(home: &Path, now: SystemTime) -> bool {
    let Ok(text) = fs::read_to_string(home.join(MARK)) else { return false };
    let Ok(marked) = text.trim().parse::<u64>() else { return false };
    let Ok(now) = now.duration_since(UNIX_EPOCH) else { return false };
    now.as_secs() >= marked && now.as_secs() - marked < LIFETIME.as_secs()
}

/// Ends the hand-over in *home* (the new helper has taken over, or the upgrade is over).
pub fn clear(home: &Path) {
    let _ = fs::remove_file(home.join(MARK));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-handover-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_fresh_mark_is_pending_a_stale_or_missing_one_is_not() {
        let home = temp("mark");
        assert!(!pending(&home, SystemTime::now()));
        begin(&home).unwrap();
        assert!(pending(&home, SystemTime::now()));
        assert!(!pending(&home, SystemTime::now() + LIFETIME + Duration::from_secs(1)));
        clear(&home);
        assert!(!pending(&home, SystemTime::now()));
        fs::write(home.join(MARK), "not a time").unwrap();
        assert!(!pending(&home, SystemTime::now()));
    }
}
