//! The addresses an upstream DNS answer gives — so Network Shield can say which name a remote
//! address was looked up as (KI-588: a companion app's Activity view shows "this connection is to
//! api.example.com", not only an IP). Read from answers the resolver relays anyway; nothing is
//! asked of anyone, nothing is changed in the answer.
//!
//! Bounded: at most [`MAX_RECORDS`] answer records are read per packet; a malformed packet yields
//! nothing. Only A (IPv4) and AAAA (IPv6) records count; a CNAME chain's final addresses are
//! credited to the name the client asked for (the question), which is the name the person sees.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
/// The most answer records read from one packet (and questions skipped).
pub const MAX_RECORDS: usize = 64;

/// The end of the name that starts at *at* (a compression pointer ends it after two bytes).
fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
    for _ in 0..128 {
        let length = *packet.get(at)?;
        if length & 0xC0 == 0xC0 {
            packet.get(at + 1)?;
            return Some(at + 2);
        }
        if length == 0 {
            return Some(at + 1);
        }
        if length > 63 {
            return None;
        }
        at += 1 + length as usize;
    }
    None
}

fn word(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]))
}

/// Every A / AAAA address in a successful answer *packet*; empty for a query, an error answer or
/// anything malformed.
pub fn answer_addresses(packet: &[u8]) -> Vec<IpAddr> {
    let mut found = Vec::new();
    if packet.len() < HEADER || packet[2] & 0x80 == 0 || packet[3] & 0x0f != 0 {
        return found;
    }
    let (questions, answers) = (word(packet, 4).unwrap_or(0) as usize, word(packet, 6).unwrap_or(0) as usize);
    let mut at = HEADER;
    for _ in 0..questions.min(MAX_RECORDS) {
        match skip_name(packet, at) {
            Some(end) => at = end + 4,
            None => return found,
        }
    }
    for _ in 0..answers.min(MAX_RECORDS) {
        let Some(end) = skip_name(packet, at) else { return found };
        let (Some(kind), Some(length)) = (word(packet, end), word(packet, end + 8)) else { return found };
        let data = end + 10;
        let Some(bytes) = packet.get(data..data + length as usize) else { return found };
        match (kind, bytes.len()) {
            (TYPE_A, 4) => found.push(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                found.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        at = data + length as usize;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer to `www.example.com` (id 0xabcd): a CNAME to `cdn.example.net` (compressed
    /// owner name), then an A and an AAAA record for it.
    fn answer() -> Vec<u8> {
        let mut packet = vec![0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        // CNAME: owner = pointer to the question (offset 12), type 5, class 1, ttl, rdata = cdn.example.net
        let target: Vec<u8> = [&[3u8][..], b"cdn", &[7], b"example", &[3], b"net", &[0]].concat();
        packet.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let cname_at = packet.len();
        packet.extend_from_slice(&target);
        packet.extend_from_slice(&[0xC0, cname_at as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
        packet.extend_from_slice(&[0xC0, cname_at as u8, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        packet.extend_from_slice(&"2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse::<Ipv6Addr>().unwrap().octets());
        packet
    }

    #[test]
    fn the_addresses_of_an_answer_are_read_through_a_cname_and_compression() {
        let found = answer_addresses(&answer());
        assert_eq!(found, vec!["93.184.215.14".parse::<IpAddr>().unwrap(),
                               "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn a_query_an_error_or_a_cut_packet_gives_nothing() {
        let mut query = answer();
        query[2] &= 0x7f;
        assert!(answer_addresses(&query).is_empty(), "a query is not an answer");
        let mut nxdomain = answer();
        nxdomain[3] = 0x83;
        assert!(answer_addresses(&nxdomain).is_empty(), "an error answer carries no addresses");
        let full = answer();
        let cut = &full[..full.len() - 5];
        assert_eq!(answer_addresses(cut).len(), 1, "the record cut short is dropped, the whole one before it kept");
        assert!(answer_addresses(&[0xC0; 40]).is_empty());
    }
}
