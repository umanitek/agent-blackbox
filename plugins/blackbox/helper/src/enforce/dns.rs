//! DNS Shield's resolver: a forwarding DNS server on 127.0.0.1:53 that refuses blocked names.
//!
//! Every query is read just far enough to get its first question name. A blocked name gets an
//! NXDOMAIN answer at once (microseconds: the lists are in memory); anything else is forwarded
//! byte for byte to the upstream servers the Mac used before the Shield was switched on, and the
//! answer is relayed back unchanged. UDP and TCP (for long answers) are both served.
//!
//! Fail-safe: a forwarding error answers SERVFAIL so the client retries; turning the Shield off
//! (or the helper stopping) restores the Mac's own DNS settings (see `system`).

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Where the resolver listens.
pub const LISTEN: &str = "127.0.0.1:53";
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PACKET: usize = 4096;
/// Recent blocks kept for the app.
const MAX_EVENTS: usize = 500;
/// The DNS header length.
const HEADER: usize = 12;

/// Which list of Network Shield's plan refused a name (the plan's own names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListKind {
    /// Blackbox's verified threat graph (malicious domains).
    Verified,
    /// The public block lists the user chose (ads, trackers, malware).
    Lists,
    /// The user's own block list.
    Block,
}

/// The names to refuse, with the user's allow list on top — exactly as the plan states them.
#[derive(Default)]
pub struct Blocklists {
    pub verified: HashSet<String>,
    pub lists: HashSet<String>,
    pub block: HashSet<String>,
    pub allow: HashSet<String>,
}

impl Blocklists {
    /// The list that blocks `name` (or one of its parent domains), unless the user allowed it.
    pub fn verdict(&self, name: &str) -> Option<ListKind> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if suffixes(&name).any(|suffix| self.allow.contains(suffix)) {
            return None;
        }
        for suffix in suffixes(&name) {
            if self.block.contains(suffix) {
                return Some(ListKind::Block);
            }
            if self.verified.contains(suffix) {
                return Some(ListKind::Verified);
            }
            if self.lists.contains(suffix) {
                return Some(ListKind::Lists);
            }
        }
        None
    }
}

/// `a.b.c.com`, `b.c.com`, `c.com` — never the bare top-level domain.
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(name);
    std::iter::from_fn(move || {
        let current = rest?;
        rest = current.split_once('.').map(|(_, tail)| tail).filter(|tail| tail.contains('.'));
        Some(current)
    })
    .filter(|suffix| suffix.contains('.'))
}

/// One refused query, shown in the app.
#[derive(Debug, Clone, Serialize)]
pub struct BlockEvent {
    pub ts: u64,
    pub domain: String,
    pub list: ListKind,
}

/// Refusals since the last report: per (name, list), how many and when last.
pub type PendingBlocks = std::collections::HashMap<(String, ListKind), (u64, u64)>;

/// Shared resolver state.
pub struct Resolver {
    pub lists: RwLock<Blocklists>,
    pub upstreams: RwLock<Vec<SocketAddr>>,
    pub events: Mutex<VecDeque<BlockEvent>>,
    pub queries: std::sync::atomic::AtomicU64,
    pub blocked: std::sync::atomic::AtomicU64,
    /// Bounded: at most [`MAX_PENDING`] distinct names wait for the next report.
    pending: Mutex<PendingBlocks>,
    /// True once the resolver is bound and serving; false if it stopped. The Mac's DNS is pointed
    /// here only while this is true AND a [`self_test`] answers (security finding: DNS used to be
    /// switched even when binding :53 had failed, taking the Mac offline).
    pub alive: std::sync::atomic::AtomicBool,
}

/// A name the resolver answers itself (NXDOMAIN, never forwarded): `.invalid` can never resolve
/// on the internet (RFC 6761), so answering it proves only that this resolver is up.
pub const SELF_TEST_NAME: &str = "blackbox-self-test.invalid";

/// Distinct refused names kept for one report (the plugin accepts 500 per report).
pub const MAX_PENDING: usize = 500;

impl Resolver {
    pub fn new(upstreams: Vec<SocketAddr>) -> Arc<Resolver> {
        Arc::new(Resolver {
            lists: RwLock::new(Blocklists::default()),
            upstreams: RwLock::new(upstreams),
            events: Mutex::new(VecDeque::new()),
            queries: Default::default(),
            blocked: Default::default(),
            pending: Mutex::new(PendingBlocks::new()),
            alive: Default::default(),
        })
    }

    /// The answer for one query packet: NXDOMAIN for a blocked name, else the upstream's.
    pub fn answer(&self, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
        use std::sync::atomic::Ordering::Relaxed;
        self.queries.fetch_add(1, Relaxed);
        let name = question_name(query)?;
        if name == SELF_TEST_NAME {
            return refusal(query, RCODE_NXDOMAIN);
        }
        let verdict = self.lists.read().ok()?.verdict(&name);
        if let Some(list) = verdict {
            self.blocked.fetch_add(1, Relaxed);
            let ts = now();
            if let Ok(mut pending) = self.pending.lock() {
                if pending.len() < MAX_PENDING || pending.contains_key(&(name.clone(), list)) {
                    let entry = pending.entry((name.clone(), list)).or_insert((0, ts));
                    entry.0 += 1;
                    entry.1 = ts;
                }
            }
            if let Ok(mut events) = self.events.lock() {
                if events.len() >= MAX_EVENTS {
                    events.pop_front();
                }
                events.push_back(BlockEvent { ts, domain: name, list });
            }
            return refusal(query, RCODE_NXDOMAIN);
        }
        let upstreams = self.upstreams.read().ok()?.clone();
        upstreams
            .iter()
            .find_map(|upstream| if tcp { forward_tcp(query, *upstream) } else { forward_udp(query, *upstream) })
            .or_else(|| refusal(query, RCODE_SERVFAIL))
    }
}

impl Resolver {
    /// Takes the refusals gathered since the last call (for the report to the plugin).
    pub fn drain_pending(&self) -> PendingBlocks {
        self.pending.lock().map(|mut pending| std::mem::take(&mut *pending)).unwrap_or_default()
    }
}

/// Serves UDP and TCP on [`LISTEN`] until the process ends.
pub fn serve(resolver: Arc<Resolver>) -> std::io::Result<()> {
    serve_on(resolver, LISTEN)
}

/// [`serve`] on *address* (tests use a free port). Marks the resolver alive once bound and not
/// alive when it stops.
pub fn serve_on(resolver: Arc<Resolver>, address: &str) -> std::io::Result<()> {
    let result = serve_bound(resolver.clone(), address);
    resolver.alive.store(false, std::sync::atomic::Ordering::SeqCst);
    result
}

fn serve_bound(resolver: Arc<Resolver>, address: &str) -> std::io::Result<()> {
    let udp = UdpSocket::bind(address)?;
    let tcp = TcpListener::bind(address)?;
    resolver.alive.store(true, std::sync::atomic::Ordering::SeqCst);
    let tcp_resolver = resolver.clone();
    thread::Builder::new().name("blackbox-netd-dns-tcp".into()).spawn(move || {
        for stream in tcp.incoming().flatten() {
            let resolver = tcp_resolver.clone();
            let _ = thread::Builder::new().name("blackbox-netd-dns-conn".into()).spawn(move || serve_tcp(stream, &resolver));
        }
    })?;
    let mut buffer = [0u8; MAX_PACKET];
    loop {
        let (size, client) = match udp.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(_) => continue,
        };
        let query = buffer[..size].to_vec();
        let (resolver, socket) = (resolver.clone(), udp.try_clone()?);
        let _ = thread::Builder::new().name("blackbox-netd-dns-query".into()).spawn(move || {
            if let Some(answer) = resolver.answer(&query, false) {
                let _ = socket.send_to(&answer, client);
            }
        });
    }
}

fn serve_tcp(mut stream: TcpStream, resolver: &Resolver) {
    let _ = stream.set_read_timeout(Some(UPSTREAM_TIMEOUT));
    while let Some(query) = read_tcp_message(&mut stream) {
        let Some(answer) = resolver.answer(&query, true) else { return };
        let length = (answer.len() as u16).to_be_bytes();
        if stream.write_all(&length).and_then(|_| stream.write_all(&answer)).is_err() {
            return;
        }
    }
}

fn read_tcp_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).ok()?;
    let mut message = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

fn forward_udp(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(if upstream.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT)).ok()?;
    socket.send_to(query, upstream).ok()?;
    let mut buffer = [0u8; MAX_PACKET];
    loop {
        let (size, from) = socket.recv_from(&mut buffer).ok()?;
        // Only the upstream's answer to this query id counts.
        if from == upstream && size >= 2 && buffer[..2] == query[..2] {
            return Some(buffer[..size].to_vec());
        }
    }
}

fn forward_tcp(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&upstream, UPSTREAM_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT)).ok()?;
    stream.write_all(&(query.len() as u16).to_be_bytes()).ok()?;
    stream.write_all(query).ok()?;
    read_tcp_message(&mut stream)
}

const RCODE_NXDOMAIN: u8 = 3;
const RCODE_SERVFAIL: u8 = 2;

/// The first question's name, lower case, without the final dot. `None` for anything that is
/// not a well-formed standard query with at least one question.
pub fn question_name(packet: &[u8]) -> Option<String> {
    if packet.len() < HEADER || packet[2] & 0x80 != 0 || u16::from_be_bytes([packet[4], packet[5]]) == 0 {
        return None;
    }
    let mut labels = Vec::new();
    let mut at = HEADER;
    loop {
        let length = *packet.get(at)? as usize;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None; // compression pointers never appear in a question we accept
        }
        let label = packet.get(at + 1..at + 1 + length)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += 1 + length;
        if at > 255 + HEADER {
            return None;
        }
    }
    Some(labels.join("."))
}

/// The end of the first question (name + type + class), or `None`.
fn question_end(packet: &[u8]) -> Option<usize> {
    let mut at = HEADER;
    loop {
        let length = *packet.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        at += length;
    }
    (packet.len() >= at + 4).then_some(at + 4)
}

/// An answer with no records and `rcode`, echoing the query's id, opcode, RD bit and question.
/// Whether a resolver on *address* answers the self-test query within *timeout*.
pub fn self_test(address: &str, timeout: Duration) -> bool {
    let mut id = [0u8; 2];
    if getrandom::getrandom(&mut id).is_err() {
        return false;
    }
    let Ok(socket) = UdpSocket::bind("127.0.0.1:0") else { return false };
    if socket.set_read_timeout(Some(timeout)).is_err() || socket.send_to(&query_packet(id, SELF_TEST_NAME), address).is_err() {
        return false;
    }
    let mut buffer = [0u8; MAX_PACKET];
    matches!(socket.recv_from(&mut buffer), Ok((size, _)) if size >= 12 && buffer[..2] == id && buffer[2] & 0x80 != 0)
}

/// A minimal standard query (one question, type A, class IN) for *name* with *id*.
pub fn query_packet(id: [u8; 2], name: &str) -> Vec<u8> {
    let mut packet = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

pub fn refusal(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let end = question_end(query)?;
    let mut answer = query[..end].to_vec();
    answer[2] = 0x80 | (query[2] & 0x79); // QR=1, keep opcode and RD, clear AA and TC
    answer[3] = 0x80 | rcode; // RA=1
    answer[4..6].copy_from_slice(&1u16.to_be_bytes());
    answer[6..12].fill(0);
    Some(answer)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A standard A query for `name` with id 0xabcd and RD set.
    fn query(name: &str) -> Vec<u8> {
        let mut packet = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }

    #[test]
    fn reads_the_question_name() {
        assert_eq!(question_name(&query("Login.Evil.EXAMPLE")).as_deref(), Some("login.evil.example"));
        assert_eq!(question_name(&[0u8; 5]), None);
        let mut response = query("a.com");
        response[2] |= 0x80;
        assert_eq!(question_name(&response), None, "answers are not queries");
    }

    #[test]
    fn the_self_test_answers_only_while_the_resolver_serves() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let address = format!("127.0.0.1:{port}");
        assert!(!self_test(&address, Duration::from_millis(300)), "nothing serves yet");
        let resolver = Resolver::new(vec![]);   // no upstream at all: the self-test is answered locally
        let (serving, at) = (resolver.clone(), address.clone());
        thread::spawn(move || serve_on(serving, &at));
        for _ in 0..50 {
            if resolver.alive.load(std::sync::atomic::Ordering::SeqCst) { break; }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(self_test(&address, Duration::from_secs(1)));
    }

    #[test]
    fn refusal_is_a_well_formed_nxdomain_for_the_same_question() {
        let q = query("evil.example");
        let answer = refusal(&q, RCODE_NXDOMAIN).unwrap();
        assert_eq!(&answer[..2], &[0xab, 0xcd]);
        assert_eq!(answer[2] & 0x80, 0x80, "QR set");
        assert_eq!(answer[2] & 0x01, 0x01, "RD kept");
        assert_eq!(answer[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(&answer[12..], &q[12..], "question echoed");
        assert_eq!(&answer[6..12], &[0; 6], "no records");
    }

    #[test]
    fn verdict_matches_parent_domains_and_respects_allow() {
        let mut lists = Blocklists::default();
        lists.verified.insert("evil.example".into());
        lists.lists.insert("ads.tracker.com".into());
        lists.block.insert("blocked.test".into());
        assert_eq!(lists.verdict("cdn.evil.example."), Some(ListKind::Verified));
        assert_eq!(lists.verdict("x.ads.tracker.com"), Some(ListKind::Lists));
        assert_eq!(lists.verdict("www.blocked.test"), Some(ListKind::Block));
        assert_eq!(lists.verdict("example"), None);
        assert_eq!(lists.verdict("good.example"), None);
        lists.allow.insert("evil.example".into());
        assert_eq!(lists.verdict("cdn.evil.example"), None, "allow wins");
    }

    #[test]
    fn a_blocked_name_is_answered_locally_and_recorded() {
        let resolver = Resolver::new(vec![]);
        resolver.lists.write().unwrap().verified.insert("evil.example".into());
        let answer = resolver.answer(&query("www.evil.example"), false).unwrap();
        assert_eq!(answer[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(resolver.events.lock().unwrap()[0].domain, "www.evil.example");
        resolver.answer(&query("www.evil.example"), false).unwrap();
        let pending = resolver.drain_pending();
        assert_eq!(pending[&("www.evil.example".to_string(), ListKind::Verified)].0, 2);
        assert!(resolver.drain_pending().is_empty(), "a drain takes them");
    }

    #[test]
    fn with_no_reachable_upstream_an_allowed_name_gets_servfail() {
        let resolver = Resolver::new(vec![]);
        let answer = resolver.answer(&query("fine.example"), false).unwrap();
        assert_eq!(answer[3] & 0x0f, RCODE_SERVFAIL);
    }
}
