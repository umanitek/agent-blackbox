//! Tampering, on every OS: one look at the settings an attacker changes to get around protection
//! ([`Look`]: the DNS servers asked, proxies, VPNs, the system firewall, Blackbox's helper files
//! and the packet filter Blackbox's firewall uses) and [`Tamper`] — the last look and the events a
//! change queues (the first look is the baseline). Each OS reads its own look
//! (`platform/<os>/observe/tamper.rs`). Observing only.

use serde_json::{json, Value};

const MAX_PENDING: usize = 100;

/// One look at the settings that matter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Look {
    pub dns_servers: Vec<String>,
    pub proxy: Vec<String>,
    pub vpn_count: usize,
    /// on | off | block-all | unknown
    pub firewall: String,
    pub helper: Vec<String>,
    /// The packet filter Blackbox's firewall uses (pf on macOS, its nftables table on Linux): enabled | disabled | unknown.
    pub pf: String,
}

impl Look {
    pub fn json(&self) -> Value {
        json!({"dns_servers": self.dns_servers, "proxy": self.proxy, "vpn_count": self.vpn_count, "firewall": self.firewall,
               "helper_files": self.helper.len(), "pf": self.pf})
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
