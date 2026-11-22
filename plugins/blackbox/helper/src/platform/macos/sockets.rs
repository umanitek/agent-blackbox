//! Every process's sockets and the interfaces' byte counters, read natively (native/sockets.c:
//! libproc + getifaddrs) — no program started, a few milliseconds a pass. The helper's watches
//! read it as root; a live collector (an add-on) may read it as the person (fast tier).
//!
//! Only processes this user may inspect are listed (root's and other users' are not); the slow
//! tier's `nettop` snapshot still covers those. The C side flattens libproc's unions into the two
//! `#[repr(C)]` records below; [`layouts_match`] checks both sides agree.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// The records are OS-neutral (platform/sockets.rs); this file is macOS's reader of them.
pub use crate::platform::sockets::{Iface, Socket};

/// The most sockets read per pass, and descriptors looked at per process (bounded work).
const MAX_SOCKETS: usize = 8192;
const MAX_FDS_PER_PROCESS: i32 = 4096;
const MAX_IFACES: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSocket {
    pid: i32,
    family: u8,
    protocol: u8,
    tcp_state: i16,
    local_port: u16,
    remote_port: u16,
    local_addr: [u8; 16],
    remote_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawIface {
    name: [u8; 16],
    loopback: u8,
    up: u8,
    _pad: [u8; 2],
    bytes_in: u32,
    bytes_out: u32,
}

extern "C" {
    fn bb_list_sockets(out: *mut RawSocket, cap: i32, fd_cap: i32) -> i32;
    fn bb_list_ifaces(out: *mut RawIface, cap: i32) -> i32;
    fn bb_socket_size() -> usize;
    fn bb_iface_size() -> usize;
}

/// nettop's names for the TCP states (sys/proc_info.h TSI_S_*), so both tiers read alike.
pub fn tcp_state_name(state: i16) -> &'static str {
    match state {
        0 => "Closed", 1 => "Listen", 2 => "SynSent", 3 => "SynReceived", 4 => "Established", 5 => "CloseWait",
        6 => "FinWait1", 7 => "Closing", 8 => "LastAck", 9 => "FinWait2", 10 => "TimeWait", _ => "",
    }
}

fn address(family: u8, bytes: &[u8; 16]) -> IpAddr {
    if family == 4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        let v6 = Ipv6Addr::from(*bytes);
        v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
    }
}

fn socket_of(raw: &RawSocket) -> Socket {
    let tcp = raw.protocol == 6;
    Socket {
        pid: raw.pid.max(0) as u32,
        protocol: format!("{}{}", if tcp { "tcp" } else { "udp" }, raw.family),
        local_ip: address(raw.family, &raw.local_addr),
        local_port: raw.local_port,
        remote_ip: address(raw.family, &raw.remote_addr),
        remote_port: raw.remote_port,
        state: if tcp { tcp_state_name(raw.tcp_state) } else { "" },
    }
}

/// Reuses its buffers between passes (no allocation per tick).
pub struct Reader {
    sockets: Vec<RawSocket>,
    ifaces: Vec<RawIface>,
}

impl Default for Reader {
    fn default() -> Self {
        let empty_socket = RawSocket { pid: 0, family: 0, protocol: 0, tcp_state: 0, local_port: 0, remote_port: 0, local_addr: [0; 16], remote_addr: [0; 16] };
        let empty_iface = RawIface { name: [0; 16], loopback: 0, up: 0, _pad: [0; 2], bytes_in: 0, bytes_out: 0 };
        Reader { sockets: vec![empty_socket; MAX_SOCKETS], ifaces: vec![empty_iface; MAX_IFACES] }
    }
}

impl Reader {
    /// Every socket of every process this user may inspect.
    pub fn sockets(&mut self) -> Vec<Socket> {
        // SAFETY: the buffer holds MAX_SOCKETS records of the layout the C side writes
        // (checked by layouts_match); C writes at most `cap` of them and answers how many.
        let count = unsafe { bb_list_sockets(self.sockets.as_mut_ptr(), MAX_SOCKETS as i32, MAX_FDS_PER_PROCESS) };
        self.sockets[..count.clamp(0, MAX_SOCKETS as i32) as usize].iter().map(socket_of).collect()
    }

    /// Every link-level interface's counters.
    pub fn ifaces(&mut self) -> Vec<Iface> {
        // SAFETY: as above, MAX_IFACES records of the checked layout.
        let count = unsafe { bb_list_ifaces(self.ifaces.as_mut_ptr(), MAX_IFACES as i32) };
        self.ifaces[..count.clamp(0, MAX_IFACES as i32) as usize].iter().map(|raw| {
            let end = raw.name.iter().position(|&b| b == 0).unwrap_or(raw.name.len());
            Iface { name: String::from_utf8_lossy(&raw.name[..end]).into_owned(), loopback: raw.loopback != 0, up: raw.up != 0,
                    bytes_in: raw.bytes_in, bytes_out: raw.bytes_out }
        }).collect()
    }
}

/// True when the Rust records and the C records have the same size.
pub fn layouts_match() -> bool {
    // SAFETY: plain functions answering sizeof.
    unsafe { bb_socket_size() == std::mem::size_of::<RawSocket>() && bb_iface_size() == std::mem::size_of::<RawIface>() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rust_and_c_records_agree() {
        assert!(layouts_match());
    }

    #[test]
    fn a_raw_record_becomes_a_socket_in_nettops_spelling() {
        let mut remote = [0u8; 16];
        remote[..4].copy_from_slice(&[45, 130, 148, 102]);
        let raw = RawSocket { pid: 812, family: 4, protocol: 6, tcp_state: 4, local_port: 50000, remote_port: 443, local_addr: [0; 16], remote_addr: remote };
        let socket = socket_of(&raw);
        assert_eq!(socket.protocol, "tcp4");
        assert_eq!(socket.remote_ip, "45.130.148.102".parse::<IpAddr>().unwrap());
        assert_eq!(socket.state, "Established");
        assert!(socket.connected());
        let listen = RawSocket { tcp_state: 1, remote_port: 0, remote_addr: [0; 16], ..raw };
        assert!(socket_of(&listen).listening() && !socket_of(&listen).connected());
    }

    #[test]
    fn an_ipv4_mapped_ipv6_address_reads_as_ipv4() {
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(address(6, &mapped.octets()), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn this_macs_own_sockets_and_interfaces_are_read() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut reader = Reader::default();
        let mine = reader.sockets().into_iter().any(|s| s.pid == std::process::id() && s.local_port == port && s.listening());
        assert!(mine, "this test's own listening socket is seen");
        assert!(reader.ifaces().iter().any(|i| i.loopback), "lo0 is listed");
    }
}
