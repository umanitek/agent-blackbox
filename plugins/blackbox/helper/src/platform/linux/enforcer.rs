//! What the helper changes on Linux: the firewall (`enforce::nft`, one nftables table of
//! Blackbox's own). DNS Shield's system settings (`enforce::dns`) and ending a session answer
//! [`super::NOT_YET`] until their build steps land; the daemon never calls any of this while
//! [`super::SUPPORTED`] is false.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use super::enforce::nft;
use super::{procfs, NOT_YET};
use crate::platform::{Enforcer, Filter, SavedDns};

/// The Linux enforcer (no state of its own; the saved state is the helper's).
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEnforcer;

impl Enforcer for LinuxEnforcer {
    fn point_dns_at_shield(&self) -> Result<SavedDns, String> { Err(NOT_YET.into()) }
    fn restore_dns(&self, _saved: &SavedDns) -> Vec<String> { vec![] }
    fn current_upstreams(&self) -> Vec<SocketAddr> { vec![] }
    fn dhcp_upstreams(&self) -> Vec<SocketAddr> { vec![] }
    fn upstreams_from_saved(&self, _saved: &SavedDns) -> Vec<SocketAddr> { vec![] }

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

    fn end_session(&self, _pid: u32) -> Result<(), String> { Err(NOT_YET.into()) }
    fn undo_hardening(&self) {}
}
