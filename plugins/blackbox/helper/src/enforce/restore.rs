//! Tamper guard (opt-in, off by default): while DNS Shield is on, a change of the Mac's DNS
//! away from Blackbox's resolver is put back at once. Uses the same [`super::system`] code that
//! points DNS at the resolver; the servers saved when DNS Shield was switched on stay the ones
//! restored later (a tampered value never becomes the "original").
//!
//! **Undo:** nothing of its own to undo — DNS Shield's own restore puts the saved servers back
//! when it is switched off.

use serde_json::{json, Value};

use super::system;

/// Blackbox's resolver address.
pub const RESOLVER: &str = "127.0.0.1";

/// True when *servers* (the Mac's first resolver) no longer point at Blackbox's resolver.
pub fn drifted(servers: &[String]) -> bool {
    servers.first().map(String::as_str) != Some(RESOLVER)
}

/// Puts DNS back when *guard* and *dns_active* and the servers drifted; answers an event.
pub fn guard_dns(guard: bool, dns_active: bool, servers: &[String], now: u64) -> Option<Value> {
    if !guard || !dns_active || servers.is_empty() || !drifted(servers) {
        return None;
    }
    Some(match system::point_dns_at_shield() {
        Ok(_) => json!({"kind": "dns-restored", "ts": now, "was": servers}),
        Err(error) => json!({"kind": "dns-restore-failed", "ts": now, "error": error.chars().take(300).collect::<String>()}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_guarded_active_drift_is_restored() {
        assert!(guard_dns(false, true, &["8.8.8.8".into()], 1).is_none(), "the guard is opt-in");
        assert!(guard_dns(true, false, &["8.8.8.8".into()], 1).is_none(), "DNS Shield off: nothing to guard");
        assert!(guard_dns(true, true, &["127.0.0.1".into()], 1).is_none(), "not drifted");
        assert!(drifted(&["8.8.8.8".into()]) && !drifted(&["127.0.0.1".into(), "1.1.1.1".into()]));
    }
}
