//! What the helper changes on Linux: the firewall (`enforce::nft`, one nftables table of
//! Blackbox's own) and DNS Shield's system settings (`enforce::dns`). Ending a session answers
//! [`super::NOT_YET`] until its build step lands; the daemon never calls any of this while
//! [`super::SUPPORTED`] is false.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use super::enforce::{dns, nft};
use super::{procfs, NOT_YET};
use crate::platform::{Enforcer, Filter, SavedDns};

/// The Linux enforcer (no state of its own; the saved state is the helper's).
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEnforcer;

impl Enforcer for LinuxEnforcer {
    fn point_dns_at_shield(&self) -> Result<SavedDns, String> {
        let (actions, saved) = dns::point(&dns::read_view());
        let errors = dns::run(&actions);
        if errors.is_empty() { Ok(saved) } else { Err(errors.join("; ")) }
    }

    fn restore_dns(&self, saved: &SavedDns) -> Vec<String> {
        dns::run(&dns::restore(saved))
    }

    fn current_upstreams(&self) -> Vec<SocketAddr> {
        dns::current_upstreams()
    }

    fn dhcp_upstreams(&self) -> Vec<SocketAddr> {
        dns::dhcp_upstreams()
    }

    fn upstreams_from_saved(&self, saved: &SavedDns) -> Vec<SocketAddr> {
        dns::upstreams_from_saved(saved)
    }

    fn boot_time(&self) -> u64 {
        procfs::boot_time(Path::new(procfs::PROC))
    }

    fn apply_filter(&self, filter: &Filter, _token: Option<String>) -> Result<Option<String>, String> {
        // WHY the token is not needed: the table is replaced whole on every apply, and removing
        // it releases nothing another program holds (macOS's pf token has no Linux counterpart).
        nft::apply(filter)
    }

    fn kill_states(&self, ip: &IpAddr) -> Result<u64, String> {
        nft::kill_states(ip)
    }

    fn dropped(&self) -> u64 {
        nft::dropped()
    }

    fn filter_enabled(&self) -> Option<bool> {
        nft::enabled()
    }

    fn filter_intact(&self, filter: &Filter) -> Option<bool> {
        nft::intact(filter)
    }

    fn end_session(&self, _pid: u32) -> Result<(), String> { Err(NOT_YET.into()) }
    fn undo_hardening(&self) {}
}
