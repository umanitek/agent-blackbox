//! [`MacEnforcer`]: the [`Enforcer`] for macOS — the Mac's DNS settings (`enforce::system`),
//! pf (`enforce::pf`), ending a session (`enforce::sessions`) and the posture fixes (the system
//! watch keeps them, `system_guard`). Stateless: each call reads or changes the Mac directly.

use std::net::{IpAddr, SocketAddr};

use super::enforce::{pf, sessions, system};
use super::system_guard;
use crate::platform::{Enforcer, Filter, Pointed, SavedDns};

/// macOS's enforcer (no state of its own; the saved state is the helper's).
#[derive(Debug, Default, Clone, Copy)]
pub struct MacEnforcer;

impl Enforcer for MacEnforcer {
    fn point_dns_at_shield(&self, already: &SavedDns) -> Pointed {
        system::point_dns_at_shield(already)
    }

    fn restore_dns(&self, saved: &SavedDns) -> Vec<String> {
        system::restore_dns(saved)
    }

    fn current_upstreams(&self) -> Vec<SocketAddr> {
        system::current_upstreams()
    }

    fn dhcp_upstreams(&self) -> Vec<SocketAddr> {
        system::dhcp_upstreams()
    }

    fn upstreams_from_saved(&self, saved: &SavedDns) -> Vec<SocketAddr> {
        system::upstreams_from_saved(saved)
    }

    fn boot_time(&self) -> u64 {
        pf::boot_time()
    }

    fn apply_filter(&self, filter: &Filter, token: Option<String>) -> Result<Option<String>, String> {
        pf::apply(filter, token)
    }

    fn kill_states(&self, ip: &IpAddr) -> Result<u64, String> {
        pf::kill_states(ip)
    }

    fn dropped(&self) -> u64 {
        pf::dropped()
    }

    fn filter_enabled(&self) -> Option<bool> {
        pf::enabled()
    }

    fn filter_intact(&self, filter: &Filter) -> Option<bool> {
        pf::intact(filter)
    }

    fn dns_in_effect(&self) -> Option<bool> {
        system::shield_in_effect()
    }

    fn end_session(&self, pid: u32) -> Result<(), String> {
        sessions::end(pid)
    }

    fn undo_hardening(&self) {
        system_guard::undo_hardening();
    }
}
