//! The socket and interface records every OS's reader answers with (macOS's:
//! `platform/macos/sockets.rs`, libproc + getifaddrs). OS-neutral data only.

use std::net::IpAddr;

/// One socket of a process.
#[derive(Debug, Clone, PartialEq)]
pub struct Socket {
    pub pid: u32,
    /// `tcp4`, `tcp6`, `udp4` or `udp6` (nettop's spelling).
    pub protocol: String,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    /// nettop's spelling of the TCP state (`Established`, `Listen` …); empty for UDP.
    pub state: &'static str,
}

impl Socket {
    /// A TCP socket waiting for connections (its local port is served by this Mac).
    pub fn listening(&self) -> bool {
        self.state == "Listen"
    }

    /// A socket talking to a peer (not listening, not an unconnected UDP socket).
    pub fn connected(&self) -> bool {
        self.remote_port != 0 && !self.remote_ip.is_unspecified() && !self.listening()
    }
}

/// One interface's counters since the system started: bytes and packets each way, 64-bit (they
/// no longer wrap at 4 GiB — KI-588), so one reader serves the traffic tiles and per-interface
/// packet figures alike.
#[derive(Debug, Clone, PartialEq)]
pub struct Iface {
    pub name: String,
    pub loopback: bool,
    pub up: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}
