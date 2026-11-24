//! What the helper changes on Linux. Each part answers [`super::NOT_YET`] until its build step
//! lands (nftables, DNS Shield); the daemon never calls them while [`super::SUPPORTED`] is false.

use std::net::{IpAddr, SocketAddr};

use crate::platform::{Enforcer, Filter, SavedDns};

use super::NOT_YET;

/// The Linux enforcer.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEnforcer;

impl Enforcer for LinuxEnforcer {
    fn point_dns_at_shield(&self) -> Result<SavedDns, String> { Err(NOT_YET.into()) }
    fn restore_dns(&self, _saved: &SavedDns) -> Vec<String> { vec![] }
    fn current_upstreams(&self) -> Vec<SocketAddr> { vec![] }
    fn dhcp_upstreams(&self) -> Vec<SocketAddr> { vec![] }
    fn upstreams_from_saved(&self, _saved: &SavedDns) -> Vec<SocketAddr> { vec![] }
    fn boot_time(&self) -> u64 { 0 }
    fn apply_filter(&self, filter: &Filter, _token: Option<String>) -> Result<Option<String>, String> {
        if filter.is_off() { Ok(None) } else { Err(NOT_YET.into()) }
    }
    fn kill_states(&self, _ip: &IpAddr) -> Result<u64, String> { Err(NOT_YET.into()) }
    fn dropped(&self) -> u64 { 0 }
    fn filter_enabled(&self) -> Option<bool> { None }
    fn end_session(&self, _pid: u32) -> Result<(), String> { Err(NOT_YET.into()) }
    fn undo_hardening(&self) {}
}
