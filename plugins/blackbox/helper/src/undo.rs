//! What stopping the helper puts back, and putting the Mac back from the saved state.

#[allow(unused_imports)]
use crate::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopping {
    /// launchd stopped the service (repair, update, removal through launchctl).
    Service,
    /// `blackbox-netd uninstall`; *undo_hardening* only when the person explicitly chose it.
    Uninstall { undo_hardening: bool },
}

/// What stopping puts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Undo {
    /// The Mac's own DNS servers (pointing at a resolver that is gone would take it offline).
    pub dns: bool,
    /// Blackbox's pf rules and its pf reference.
    pub filter: bool,
    /// The posture fixes (firewall on, guest off, …).
    pub hardening: bool,
}

/// The one rule (security finding: removing or repairing the helper silently re-opened the Mac by
/// reversing every posture fix): hardening is undone only when the person explicitly asks.
pub fn undo_for(how: Stopping) -> Undo {
    Undo { dns: true, filter: true, hardening: matches!(how, Stopping::Uninstall { undo_hardening: true }) }
}

/// Puts the system back from the saved state alone — for `uninstall`, which runs while the
/// service is stopped (or dead), through this OS's *enforcer*. Answers what failed (nothing → empty).
pub fn put_back(enforcer: &impl Enforcer, undo: Undo) -> Vec<String> {
    let mut errors = vec![];
    let mut state = State::load();
    if undo.dns && !state.saved_dns.is_empty() {
        let failed = enforcer.restore_dns(&state.saved_dns);
        if failed.is_empty() { state.saved_dns.clear(); state.dns_active = false; }
        errors.extend(failed);
    }
    if undo.filter {
        match enforcer.apply_filter(&platform::Filter::default(), state.pf_token.take()) {
            Ok(_) => {
                state.firewall_active = false;
                state.cut_active = false;
                state.ssh_lockdown_active = false;
                state.remote_lock_active = false;
            }
            Err(error) => errors.push(error),
        }
    }
    if undo.hardening {
        enforcer.undo_hardening();
    }
    state.save();
    errors
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_or_repairing_the_helper_never_reopens_the_mac() {
        let service = undo_for(Stopping::Service);
        assert!(service.dns && service.filter, "what needs the running helper is put back");
        assert!(!service.hardening, "posture hardening stays when the service stops");
        assert!(!undo_for(Stopping::Uninstall { undo_hardening: false }).hardening);
        assert!(undo_for(Stopping::Uninstall { undo_hardening: true }).hardening, "only the person's explicit choice");
    }
}
