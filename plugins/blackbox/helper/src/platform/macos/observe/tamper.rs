//! Tampering: the settings an attacker changes to get around protection, read every
//! [`TAMPER_EVERY`] (observing only):
//!
//! * which DNS servers the Mac asks (`scutil --dns`, the first resolver) — away from Blackbox's
//!   resolver (127.0.0.1) while DNS Shield is on means someone changed it;
//! * a system proxy or proxy auto-config (`scutil --proxy`) — traffic quietly routed elsewhere;
//! * VPN configurations (`scutil --nc list`) — a new one can carry traffic past the firewall;
//! * the macOS Application Firewall's state (`socketfilterfw --getglobalstate`);
//! * Blackbox's own helper — its LaunchDaemon plist and binary fingerprints.
//!
//! The first look is the baseline; afterwards each change queues an event.

use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const TAMPER_EVERY: Duration = Duration::from_secs(5);
const MAX_PENDING: usize = 100;
const HELPER_FILES: [&str; 2] = ["/Library/LaunchDaemons/ai.umanitek.blackbox.netd.plist", "/Library/Application Support/Blackbox/netd/blackbox-netd"];
const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// One look at the settings that matter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Look {
    pub dns_servers: Vec<String>,
    pub proxy: Vec<String>,
    pub vpn_count: usize,
    /// on | off | block-all | unknown
    pub firewall: String,
    pub helper: Vec<String>,
    /// pf (the packet filter Blackbox's firewall uses): enabled | disabled | unknown.
    pub pf: String,
}

impl Look {
    pub fn json(&self) -> Value {
        json!({"dns_servers": self.dns_servers, "proxy": self.proxy, "vpn_count": self.vpn_count, "firewall": self.firewall,
               "helper_files": self.helper.len(), "pf": self.pf})
    }
}

/// The first resolver's name servers from `scutil --dns`.
pub fn parse_dns(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let mut in_first = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("resolver #") {
            if in_first { break; }
            in_first = line == "resolver #1";
        } else if in_first && line.starts_with("nameserver[") {
            if let Some((_, server)) = line.split_once(':') { servers.push(server.trim().to_string()); }
        }
    }
    servers
}

/// The proxies switched on in `scutil --proxy` (`HTTPEnable : 1` → `http`).
pub fn parse_proxy(text: &str) -> Vec<String> {
    const KINDS: [(&str, &str); 5] = [("HTTPEnable", "http"), ("HTTPSEnable", "https"), ("SOCKSEnable", "socks"),
                                     ("ProxyAutoConfigEnable", "auto-config"), ("ProxyAutoDiscoveryEnable", "auto-discovery")];
    KINDS.iter().filter(|(key, _)| text.lines().any(|line| {
        let mut parts = line.split(':').map(str::trim);
        parts.next() == Some(key) && parts.next() == Some("1")
    })).map(|(_, name)| name.to_string()).collect()
}

/// How many VPN configurations `scutil --nc list` lists (each line starts with `*`).
pub fn parse_vpns(text: &str) -> usize {
    text.lines().filter(|line| line.trim_start().starts_with('*')).count()
}

/// The firewall's state from `socketfilterfw --getglobalstate`.
pub fn parse_firewall(text: &str) -> String {
    let text = text.to_ascii_lowercase();
    if text.contains("state = 2") || text.contains("block all") { "block-all".into() }
    else if text.contains("enabled") || text.contains("state = 1") { "on".into() }
    else if text.contains("disabled") || text.contains("state = 0") { "off".into() }
    else { "unknown".into() }
}

fn output(program: &str, args: &[&str]) -> String {
    crate::command::output(Command::new(program).args(args), crate::command::TIMEOUT).map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

fn fingerprint(path: &str) -> String {
    crate::safe_read::read_regular(std::path::Path::new(path), 64 * 1024 * 1024).ok_or(()).map(|bytes| Sha256::digest(&bytes).iter().take(8).map(|b| format!("{b:02x}")).collect()).unwrap_or_else(|_| "missing".into())
}

/// Looks at everything now.
pub fn look() -> Look {
    Look {
        dns_servers: parse_dns(&output("/usr/sbin/scutil", &["--dns"])),
        proxy: parse_proxy(&output("/usr/sbin/scutil", &["--proxy"])),
        vpn_count: parse_vpns(&output("/usr/sbin/scutil", &["--nc", "list"])),
        firewall: parse_firewall(&output(FIREWALL, &["--getglobalstate"])),
        helper: HELPER_FILES.iter().map(|path| fingerprint(path)).collect(),
        pf: match crate::platform::macos::pf_status::read() {
            Some(true) => "enabled", Some(false) => "disabled", None => "unknown",
        }.into(),
    }
}

/// What the last look saw and the events not yet reported.
#[derive(Debug, Default)]
pub struct Tamper {
    last: Option<Look>,
    pending: Vec<Value>,
}

impl Tamper {
    /// Compares *now_look* with the last; queues events. True when it queued any.
    pub fn tick(&mut self, now_look: Look, now: u64) -> bool {
        let before = self.pending.len();
        if let Some(last) = self.last.clone() {
            if last.dns_servers != now_look.dns_servers {
                self.push(json!({"kind": "dns-changed", "ts": now, "servers": now_look.dns_servers, "was": last.dns_servers}));
            }
            if last.proxy != now_look.proxy {
                self.push(json!({"kind": if now_look.proxy.is_empty() { "proxy-removed" } else { "proxy-set" }, "ts": now, "proxies": now_look.proxy}));
            }
            if now_look.vpn_count > last.vpn_count {
                self.push(json!({"kind": "vpn-added", "ts": now, "count": now_look.vpn_count}));
            }
            if last.firewall != now_look.firewall && now_look.firewall != "unknown" {
                self.push(json!({"kind": "firewall-changed", "ts": now, "state": now_look.firewall, "was": last.firewall}));
            }
            // pf switched off under Blackbox (by another root process): the firewall, cut
            // and lockdowns stop enforcing — the person must hear it (security finding).
            if last.pf == "enabled" && now_look.pf == "disabled" {
                self.push(json!({"kind": "pf-disabled", "ts": now}));
            }
            if last.helper != now_look.helper {
                self.push(json!({"kind": "helper-modified", "ts": now}));
            }
        }
        self.last = Some(now_look);
        self.pending.len() > before
    }

    fn push(&mut self, event: Value) {
        if self.pending.len() < MAX_PENDING { self.pending.push(event); }
    }

    pub fn snapshot(&self) -> Value {
        self.last.as_ref().map(Look::json).unwrap_or(Value::Null)
    }

    /// The DNS servers the last look saw (empty before the first).
    pub fn dns_servers(&self) -> Vec<String> {
        self.last.as_ref().map(|l| l.dns_servers.clone()).unwrap_or_default()
    }

    pub fn take_events(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending)
    }

    pub fn reset(&mut self) {
        *self = Tamper::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_switched_off_under_blackbox_is_an_event() {
        let on = Look { pf: "enabled".into(), ..Default::default() };
        let off = Look { pf: "disabled".into(), ..Default::default() };
        let mut tamper = Tamper::default();
        assert!(!tamper.tick(on.clone(), 1), "the first look is a baseline");
        assert!(tamper.tick(off, 2));
        assert_eq!(tamper.take_events()[0]["kind"], "pf-disabled");
    }

    #[test]
    fn the_settings_parse() {
        let dns = "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.0.1\n  nameserver[1] : 1.1.1.1\n  flags    : Request A records\n\nresolver #2\n  nameserver[0] : 8.8.8.8\n";
        assert_eq!(parse_dns(dns), vec!["127.0.0.1", "1.1.1.1"]);
        assert_eq!(parse_proxy("<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 10.0.0.9\n  HTTPSEnable : 0\n  ProxyAutoConfigEnable : 1\n}\n"), vec!["http", "auto-config"]);
        assert_eq!(parse_vpns("Available network connection services in the current set (*=enabled):\n* (Disconnected)   ABC VPN (com.wireguard)  \"Work\"\n"), 1);
        assert_eq!(parse_firewall("Firewall is enabled. (State = 1)"), "on");
        assert_eq!(parse_firewall("Firewall is disabled. (State = 0)"), "off");
        assert_eq!(parse_firewall("Firewall is blocking all non-essential incoming connections. (State = 2)"), "block-all");
    }

    #[test]
    fn changes_after_the_baseline_are_events() {
        let mut tamper = Tamper::default();
        let base = Look { dns_servers: vec!["127.0.0.1".into()], firewall: "on".into(), ..Default::default() };
        assert!(!tamper.tick(base.clone(), 1), "the first look is the baseline");
        let changed = Look { dns_servers: vec!["8.8.8.8".into()], proxy: vec!["socks".into()], vpn_count: 1, firewall: "off".into(), ..Default::default() };
        assert!(tamper.tick(changed, 2));
        let kinds: Vec<String> = tamper.take_events().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds, vec!["dns-changed", "proxy-set", "vpn-added", "firewall-changed"]);
    }
}
