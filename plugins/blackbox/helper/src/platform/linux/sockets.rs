//! Linux's socket and interface reader: the kernel's socket table over `NETLINK_SOCK_DIAG`
//! ([`super::sock_diag`] builds and reads the messages), each socket's process found by its inode
//! among `/proc/<pid>/fd/*`, and the interfaces' 64-bit counters from `/proc/net/dev`. No program
//! started. Root sees every process's sockets; another user sees all sockets but only their own
//! processes' (a socket whose process is not readable has pid 0).
//!
//! Same surface as macOS's reader (`Reader::sockets`, `Reader::ifaces`), answering the OS-neutral
//! records of `platform/sockets.rs`.

use std::collections::HashMap;
use std::path::Path;

pub use crate::platform::sockets::{Iface, Socket};

use super::procfs;
use super::sock_diag::{self, DiagSocket};

/// The most sockets read per pass (bounded work, as on macOS).
const MAX_SOCKETS: usize = 8192;
/// One receive (the kernel fills up to this; a dump spans several).
const RECEIVE: usize = 32 * 1024;
/// The most receives one dump may take (8192 sockets at 72+ bytes each fit in far fewer).
const MAX_RECEIVES: usize = 256;

/// Reads the socket table; holds nothing between passes.
#[derive(Debug, Default)]
pub struct Reader;

impl Reader {
    /// Every TCP and UDP socket, IPv4 and IPv6, with its process where it can be told.
    pub fn sockets(&mut self) -> Vec<Socket> {
        let mut found = Vec::new();
        for (family, protocol) in [(sock_diag::AF_INET, sock_diag::IPPROTO_TCP), (sock_diag::AF_INET6, sock_diag::IPPROTO_TCP),
                                   (sock_diag::AF_INET, sock_diag::IPPROTO_UDP), (sock_diag::AF_INET6, sock_diag::IPPROTO_UDP)] {
            found.extend(dump(family, protocol).unwrap_or_default());
            if found.len() >= MAX_SOCKETS { break; }
        }
        found.truncate(MAX_SOCKETS);
        let owners = owners(Path::new(procfs::PROC));
        found.iter().map(|raw| socket_of(raw, owners.get(&raw.inode).copied().unwrap_or(0))).collect()
    }

    /// Every interface's counters.
    pub fn ifaces(&mut self) -> Vec<Iface> {
        procfs::ifaces(Path::new(procfs::PROC), Path::new(procfs::SYS_NET))
    }
}

/// One kernel record as the OS-neutral socket, in nettop's spelling.
pub fn socket_of(raw: &DiagSocket, pid: u32) -> Socket {
    Socket {
        pid,
        protocol: format!("{}{}", if raw.tcp { "tcp" } else { "udp" }, raw.family),
        local_ip: raw.local_ip,
        local_port: raw.local_port,
        remote_ip: raw.remote_ip,
        remote_port: raw.remote_port,
        state: if raw.tcp { sock_diag::tcp_state_name(raw.state) } else { "" },
    }
}

/// Which process holds each socket inode (the first one found: a socket shared by a parent and
/// its child is the parent's), from every process under *proc*.
pub fn owners(proc: &Path) -> HashMap<u64, u32> {
    let mut found = HashMap::new();
    for pid in procfs::pids(proc) {
        for inode in procfs::socket_inodes(proc, pid) {
            found.entry(inode).or_insert(pid);
        }
    }
    found
}

/// One dump of the kernel's table for *family* and *protocol*; None when netlink refused.
fn dump(family: u8, protocol: u8) -> Option<Vec<DiagSocket>> {
    // SAFETY: a plain socket call; the descriptor is closed below on every path.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return None;
    }
    let found = exchange(fd, family, protocol);
    // SAFETY: fd is ours and open.
    unsafe { libc::close(fd) };
    found
}

fn exchange(fd: i32, family: u8, protocol: u8) -> Option<Vec<DiagSocket>> {
    let request = sock_diag::request(family, protocol, 1);
    // SAFETY: a zeroed sockaddr_nl addressed to the kernel (pid 0), passed with its own size.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: request outlives the call; the address is a valid sockaddr_nl of the given length.
    let sent = unsafe {
        libc::sendto(fd, request.as_ptr().cast(), request.len(), 0, (&kernel as *const libc::sockaddr_nl).cast(),
                     std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t)
    };
    if sent < 0 {
        return None;
    }
    let mut buffer = vec![0u8; RECEIVE];
    let mut sockets = Vec::new();
    for _ in 0..MAX_RECEIVES {
        // SAFETY: the buffer holds RECEIVE bytes and recv writes at most that many.
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received <= 0 {
            return None;
        }
        let answer = sock_diag::parse(&buffer[..received as usize], protocol == sock_diag::IPPROTO_TCP);
        if answer.error.is_some() {
            return None;
        }
        sockets.extend(answer.sockets);
        if answer.done || sockets.len() >= MAX_SOCKETS {
            return Some(sockets);
        }
    }
    Some(sockets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_record_becomes_a_socket_in_the_shared_spelling() {
        let raw = DiagSocket { family: 4, tcp: true, state: 10, local_ip: "0.0.0.0".parse().unwrap(), local_port: 22,
                               remote_ip: "0.0.0.0".parse().unwrap(), remote_port: 0, uid: 0, inode: 7 };
        let socket = socket_of(&raw, 900);
        assert_eq!((socket.protocol.as_str(), socket.state, socket.pid), ("tcp4", "Listen", 900));
        assert!(socket.listening() && !socket.connected());
        let udp = socket_of(&DiagSocket { tcp: false, family: 6, state: 7, ..raw }, 0);
        assert_eq!((udp.protocol.as_str(), udp.state), ("udp6", ""));
    }

    /// The real kernel, unprivileged: this test's own listening socket is in the table with its pid.
    #[test]
    fn this_machines_own_sockets_and_interfaces_are_read() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut reader = Reader;
        let mine = reader.sockets().into_iter().any(|s| s.pid == std::process::id() && s.local_port == port && s.listening());
        assert!(mine, "this test's own listening socket is seen");
        assert!(reader.ifaces().iter().any(|i| i.loopback && i.up), "lo is listed");
    }
}
