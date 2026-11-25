//! The kernel's socket table over netlink (`NETLINK_SOCK_DIAG`, `inet_diag`), as bytes: the dump
//! request [`request`] builds, and [`parse`] reading the answer — no system call here, so a test
//! feeds it recorded buffers. [`super::sockets`] sends and receives.
//!
//! Layouts (linux/netlink.h, linux/inet_diag.h; fixed by the kernel ABI): `nlmsghdr` 16 bytes
//! (len, type, flags, seq, pid — host order); `inet_diag_req_v2` 56 bytes (family, protocol, ext,
//! pad, states, then an `inet_diag_sockid`); `inet_diag_sockid` 48 bytes (sport, dport — network
//! order —, src[16], dst[16], if, cookie[8]); `inet_diag_msg` 72 bytes (family, state, timer,
//! retrans, the sockid, expires, rqueue, wqueue, uid, inode). Messages are 4-byte aligned.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
/// `SOCK_DIAG_BY_FAMILY`: the request and answer message type.
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const HEADER: usize = 16;
const REQUEST: usize = 56;
const MESSAGE: usize = 72;
/// Every TCP state (bit N = state N).
const ALL_STATES: u32 = u32::MAX;

/// One socket of the kernel's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagSocket {
    /// 4 or 6.
    pub family: u8,
    pub tcp: bool,
    /// The kernel's TCP state number (`TCP_ESTABLISHED` 1 … `TCP_CLOSING` 11).
    pub state: u8,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub uid: u32,
    /// The socket's inode: `/proc/<pid>/fd/*` links to `socket:[inode]` name its process.
    pub inode: u64,
}

/// What one received buffer held.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Answer {
    pub sockets: Vec<DiagSocket>,
    /// The dump ended (`NLMSG_DONE`).
    pub done: bool,
    /// The kernel refused the request (`NLMSG_ERROR` with a non-zero errno).
    pub error: Option<i32>,
}

/// nettop's names for the kernel's TCP states (linux/tcp_states.h), so every OS reads alike.
pub fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "Established", 2 => "SynSent", 3 => "SynReceived", 4 => "FinWait1", 5 => "FinWait2", 6 => "TimeWait",
        7 => "Closed", 8 => "CloseWait", 9 => "LastAck", 10 => "Listen", 11 => "Closing", _ => "",
    }
}

/// The dump request for every socket of *family* (`AF_INET` / `AF_INET6`) and *protocol*.
pub fn request(family: u8, protocol: u8, seq: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + REQUEST);
    bytes.extend_from_slice(&((HEADER + REQUEST) as u32).to_ne_bytes());
    bytes.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    bytes.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    bytes.extend_from_slice(&seq.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend_from_slice(&[family, protocol, 0, 0]);
    bytes.extend_from_slice(&ALL_STATES.to_ne_bytes());
    bytes.extend_from_slice(&[0u8; 48]);
    bytes
}

fn u16_ne(bytes: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([bytes[at], bytes[at + 1]])
}

fn u32_ne(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn address(family: u8, raw: &[u8]) -> IpAddr {
    if family == AF_INET {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&raw[..16]);
        let v6 = Ipv6Addr::from(octets);
        v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
    }
}

fn message(body: &[u8], tcp: bool) -> Option<DiagSocket> {
    if body.len() < MESSAGE {
        return None;
    }
    let family = body[0];
    if family != AF_INET && family != AF_INET6 {
        return None;
    }
    // The sockid starts at 4: sport, dport (network order), src[16], dst[16].
    Some(DiagSocket {
        family: if family == AF_INET { 4 } else { 6 },
        tcp,
        state: body[1],
        local_port: u16::from_be_bytes([body[4], body[5]]),
        remote_port: u16::from_be_bytes([body[6], body[7]]),
        local_ip: address(family, &body[8..24]),
        remote_ip: address(family, &body[24..40]),
        uid: u32_ne(body, 64),
        inode: u64::from(u32_ne(body, 68)),
    })
}

/// Every message in *buffer* (one `recv`); *tcp* says which protocol was asked for (the answer
/// does not carry it). A truncated or malformed message ends the reading of this buffer.
pub fn parse(buffer: &[u8], tcp: bool) -> Answer {
    let mut answer = Answer::default();
    let mut at = 0;
    while at + HEADER <= buffer.len() {
        let length = u32_ne(buffer, at) as usize;
        if length < HEADER || at + length > buffer.len() {
            break;
        }
        let body = &buffer[at + HEADER..at + length];
        match u16_ne(buffer, at + 4) {
            NLMSG_DONE => answer.done = true,
            NLMSG_ERROR => {
                let errno = if body.len() >= 4 { i32::from_ne_bytes([body[0], body[1], body[2], body[3]]) } else { -1 };
                if errno != 0 {
                    answer.error = Some(-errno);
                }
                answer.done = true;
            }
            SOCK_DIAG_BY_FAMILY => answer.sockets.extend(message(body, tcp)),
            _ => {}
        }
        at += (length + 3) & !3;
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One answer message as the kernel writes it.
    fn diag(family: u8, state: u8, local: (&[u8], u16), remote: (&[u8], u16), uid: u32, inode: u32) -> Vec<u8> {
        let mut body = vec![family, state, 0, 0];
        body.extend_from_slice(&local.1.to_be_bytes());
        body.extend_from_slice(&remote.1.to_be_bytes());
        let mut src = [0u8; 16];
        src[..local.0.len()].copy_from_slice(local.0);
        let mut dst = [0u8; 16];
        dst[..remote.0.len()].copy_from_slice(remote.0);
        body.extend_from_slice(&src);
        body.extend_from_slice(&dst);
        body.extend_from_slice(&[0u8; 12]);           // if, cookie
        body.extend_from_slice(&[0u8; 12]);           // expires, rqueue, wqueue
        body.extend_from_slice(&uid.to_ne_bytes());
        body.extend_from_slice(&inode.to_ne_bytes());
        framed(SOCK_DIAG_BY_FAMILY, &body)
    }

    fn framed(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = ((HEADER + body.len()) as u32).to_ne_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        bytes.extend_from_slice(body);
        while bytes.len() % 4 != 0 { bytes.push(0); }
        bytes
    }

    #[test]
    fn the_request_is_a_dump_of_every_state_for_one_family_and_protocol() {
        let bytes = request(AF_INET6, IPPROTO_TCP, 7);
        assert_eq!(bytes.len(), HEADER + REQUEST);
        assert_eq!(u32_ne(&bytes, 0) as usize, bytes.len());
        assert_eq!(u16_ne(&bytes, 4), SOCK_DIAG_BY_FAMILY);
        assert_eq!(u16_ne(&bytes, 6), NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(u32_ne(&bytes, 8), 7);
        assert_eq!(&bytes[16..18], &[AF_INET6, IPPROTO_TCP]);
        assert_eq!(u32_ne(&bytes, 20), u32::MAX);
    }

    #[test]
    fn an_answer_reads_into_sockets_until_done() {
        let mut buffer = diag(AF_INET, 10, (&[0, 0, 0, 0], 22), (&[0, 0, 0, 0], 0), 0, 1111);
        buffer.extend(diag(AF_INET, 1, (&[192, 168, 64, 5], 22), (&[192, 168, 64, 1], 52814), 0, 2222));
        let mapped: Ipv6Addr = "::ffff:10.0.0.9".parse().unwrap();
        buffer.extend(diag(AF_INET6, 1, (&mapped.octets(), 443), (&mapped.octets(), 40000), 1000, 3333));
        buffer.extend(framed(NLMSG_DONE, &[0u8; 4]));
        let answer = parse(&buffer, true);
        assert!(answer.done && answer.error.is_none());
        assert_eq!(answer.sockets.len(), 3);
        let listen = &answer.sockets[0];
        assert_eq!((tcp_state_name(listen.state), listen.local_port, listen.inode), ("Listen", 22, 1111));
        let ssh = &answer.sockets[1];
        assert_eq!((ssh.remote_ip, ssh.remote_port, tcp_state_name(ssh.state)), ("192.168.64.1".parse().unwrap(), 52814, "Established"));
        assert_eq!(answer.sockets[2].local_ip, "10.0.0.9".parse::<IpAddr>().unwrap(), "a mapped address reads as IPv4");
        assert_eq!((answer.sockets[2].family, answer.sockets[2].uid), (6, 1000));
    }

    #[test]
    fn a_refusal_or_a_truncated_buffer_never_reads_past_its_end() {
        let refused = framed(NLMSG_ERROR, &(-13i32).to_ne_bytes());
        assert_eq!(parse(&refused, true), Answer { sockets: vec![], done: true, error: Some(13) });
        let mut cut = diag(AF_INET, 1, (&[1, 2, 3, 4], 1), (&[5, 6, 7, 8], 2), 0, 9);
        cut.truncate(40);
        assert_eq!(parse(&cut, false), Answer::default());
        assert_eq!(parse(&[0u8; 3], false), Answer::default());
    }
}
