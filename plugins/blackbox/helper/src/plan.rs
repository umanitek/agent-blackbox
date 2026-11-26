//! The plan as the plugin sends it (`plugins/blackbox/shields/network/enforcement.py::plan`), and
//! what each part of the helper takes from it. Every address goes through `IpAddr` or
//! [`crate::platform::source`] here, so nothing unchecked reaches the firewall.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use serde::Deserialize;

use crate::dns;
use crate::platform::{source, EndRequest};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Plan {
    pub version: String,
    pub unchanged: bool,
    pub dns: DnsPlan,
    pub firewall: FirewallPlan,
    pub cut: CutPlan,
    pub ssh: SshPlan,
    /// Lock remote access, blocked addresses, and sessions the user chose to end.
    pub remote: RemotePlan,
    /// Watch SSH and the login files (true only while the shield is on).
    pub watch: bool,
    pub allow: Vec<String>,
    /// The verified graph's lists in this plan are NOT the whole truth (the graph or its store
    /// is down, not read yet, or only partly read): keep the verified domains and firewall
    /// addresses last applied and add these ([`Plan::keep_from`]). False from an older plugin.
    pub keep_verified: bool,
}

/// The verified graph's lists the helper last applied: what a `keep_verified` plan keeps.
///
/// WHY (E2E recheck 2026-11-21): with the graph node down, the plugin served a plan with empty
/// verified lists and the helper applied it as "block nothing" — the firewall's table emptied
/// and listed domains resolved. A source that is down never clears protection; only switching a
/// protection off, or a complete list that no longer holds an entry, does.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The resolver's own verified set (shared, not a copy: KI-675).
    pub verified: Arc<dns::Names>,
    pub firewall: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DnsPlan {
    pub enabled: bool,
    pub verified: Vec<String>,
    pub lists: Vec<String>,
    pub block: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FirewallPlan {
    pub enabled: bool,
    pub ips: Vec<String>,
}

/// The malicious addresses this Mac is connected to right now: cut them.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct CutPlan {
    pub enabled: bool,
    pub ips: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SshPlan {
    pub lockdown: bool,
    pub allow: Vec<String>,
}

/// The remote-access part of the plan (all off/empty from a plugin that does not send it).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RemotePlan {
    /// Lock remote access: the remote-access ports closed to everyone but this Mac.
    pub lock: bool,
    /// Addresses refused inbound entirely (blocked by the user, or for repeated failed logins).
    pub block: Vec<String>,
    /// Sessions the user confirmed ending (each checked against the watch before acting).
    pub end: Vec<EndRequest>,
}

impl Plan {
    /// Adds *kept* to this plan's verified domains and firewall addresses when the plan says the
    /// graph's lists are incomplete. A protection the plan switches OFF is left off (its list is
    /// not refilled): switching off is the one way a kept list is cleared.
    pub fn keep_from(&mut self, kept: &Kept) {
        if !self.keep_verified {
            return;
        }
        fn union<'a>(now: &mut Vec<String>, before: impl Iterator<Item = &'a str>) {
            let missing: Vec<String> = {
                let seen: HashSet<&str> = now.iter().map(String::as_str).collect();
                before.filter(|item| !seen.contains(item)).map(str::to_string).collect()
            };
            now.extend(missing);
        }
        if self.dns.enabled {
            union(&mut self.dns.verified, kept.verified.iter().map(|name| &**name));
        }
        if self.firewall.enabled {
            union(&mut self.firewall.ips, kept.firewall.iter().map(String::as_str));
        }
    }

    /// What a later incomplete plan keeps from this one (nothing of a protection that is off):
    /// *lists* is what [`Plan::take_blocklists`] made of it.
    pub fn kept(&self, lists: &dns::Blocklists) -> Kept {
        Kept {
            verified: if self.dns.enabled { Arc::clone(&lists.verified) } else { Arc::default() },
            firewall: if self.firewall.enabled { self.firewall.ips.clone() } else { vec![] },
        }
    }

    /// The resolver's sets for this plan (all empty while DNS Shield is off), MOVED out of it: each
    /// name is lower-cased in its own allocation, so a complete graph's names are never held twice
    /// (KI-675: a second, lower-cased copy and a kept clone made the helper ~366 MB). The plan's
    /// DNS lists are empty afterwards.
    pub fn take_blocklists(&mut self) -> dns::Blocklists {
        fn names(items: Vec<String>) -> dns::Names {
            items.into_iter().map(|mut item| { item.make_ascii_lowercase(); item.into_boxed_str() }).collect()
        }
        let allow = names(self.allow.clone());
        if !self.dns.enabled {
            return dns::Blocklists { allow, ..Default::default() };
        }
        dns::Blocklists { verified: Arc::new(names(std::mem::take(&mut self.dns.verified))),
                          lists: names(std::mem::take(&mut self.dns.lists)), block: names(std::mem::take(&mut self.dns.block)), allow }
    }

    fn allowed(&self) -> HashSet<IpAddr> {
        self.allow.iter().filter_map(|item| item.parse().ok()).collect()
    }

    fn addresses(&self, items: &[String]) -> Vec<IpAddr> {
        let allowed = self.allowed();
        items.iter().filter_map(|item| item.parse::<IpAddr>().ok()).filter(|ip| !allowed.contains(ip)).collect()
    }

    /// The firewall's table: the plan's IPs, minus any address the user allowed.
    pub fn firewall_ips(&self) -> Vec<IpAddr> {
        self.addresses(&self.firewall.ips)
    }

    /// The addresses to cut now, minus any the user allowed.
    pub fn cut_ips(&self) -> Vec<IpAddr> {
        self.addresses(&self.cut.ips)
    }

    /// The valid SSH sources (anything else is dropped, never passed to pf).
    pub fn ssh_sources(&self) -> Vec<String> {
        self.ssh.allow.iter().filter_map(|item| source(item)).collect()
    }

    /// The addresses to refuse inbound (valid ones only), or None when there are none.
    pub fn remote_block(&self) -> Option<Vec<IpAddr>> {
        let ips: Vec<IpAddr> = self.remote.block.iter().filter_map(|item| item.parse().ok())
            .filter(|ip: &IpAddr| !ip.is_loopback() && !ip.is_unspecified()).collect();
        (!ips.is_empty()).then_some(ips)
    }

    /// Whether *ip* is on the user's always-allow list.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.allowed().contains(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_with_dns_off_refuses_nothing() {
        let mut plan: Plan = serde_json::from_str(r#"{"version":"v","dns":{"enabled":false,"verified":["evil.example"]},"allow":["ok.example"]}"#).unwrap();
        let lists = plan.take_blocklists();
        assert!(lists.verified.is_empty() && lists.allow.contains("ok.example"));
    }

    #[test]
    fn a_plan_maps_to_the_resolvers_sets_the_tables_and_the_ssh_sources() {
        let mut plan: Plan = serde_json::from_str(r#"{"version":"v","dns":{"enabled":true,"verified":["Evil.Example"],"lists":["ads.example"],"block":["mine.example"]},
            "firewall":{"enabled":true,"ips":["45.130.148.102","198.51.100.7","not-an-ip"]},
            "cut":{"enabled":true,"ips":["45.130.148.102","198.51.100.7"]},
            "ssh":{"lockdown":true,"allow":["192.168.1.0/24","nonsense","10.0.0.0/99"]},"watch":true,
            "allow":["198.51.100.7"]}"#).unwrap();
        let lists = plan.take_blocklists();
        assert!(plan.dns.verified.is_empty(), "the names were moved, not copied");
        assert!(lists.verified.contains("evil.example") && lists.lists.contains("ads.example") && lists.block.contains("mine.example"));
        let evil: IpAddr = "45.130.148.102".parse().unwrap();
        assert_eq!(plan.firewall_ips(), vec![evil]);
        assert_eq!(plan.cut_ips(), vec![evil], "an allowed address is never cut");
        assert_eq!(plan.ssh_sources(), vec!["192.168.1.0/24".to_string()]);
        assert!(plan.watch && plan.ssh.lockdown);
    }

    #[test]
    fn the_remote_part_parses_and_never_passes_a_bad_or_local_address() {
        let plan: Plan = serde_json::from_str(r#"{"version":"v","remote":{"lock":true,"block":["203.0.113.9","127.0.0.1","nonsense","::"],
            "end":[{"session_id":"ssh-800-1.2.3.4-5","pid":800,"started":101}]}}"#).unwrap();
        assert!(plan.remote.lock);
        assert_eq!(plan.remote_block(), Some(vec!["203.0.113.9".parse::<IpAddr>().unwrap()]));
        assert_eq!(plan.remote.end[0].pid, 800);
        let older: Plan = serde_json::from_str(r#"{"version":"v"}"#).unwrap();
        assert!(!older.remote.lock && older.remote_block().is_none() && older.remote.end.is_empty());
    }

    #[test]
    fn an_unchanged_answer_and_an_older_plan_parse() {
        let plan: Plan = serde_json::from_str(r#"{"version":"v","unchanged":true}"#).unwrap();
        assert!(plan.unchanged && !plan.dns.enabled && !plan.watch && !plan.cut.enabled && !plan.ssh.lockdown);
    }

    fn parse(json: &str) -> Plan {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_plan_built_while_the_graph_is_down_keeps_the_last_lists() {
        let complete = parse(r#"{"version":"v1","dns":{"enabled":true,"verified":["evil.example"]},"firewall":{"enabled":true,"ips":["1.0.164.165"]}}"#);
        let mut complete = complete;
        let lists = complete.take_blocklists();
        let kept = complete.kept(&lists);
        let mut down = parse(r#"{"version":"v2","keep_verified":true,"dns":{"enabled":true,"verified":[]},"firewall":{"enabled":true,"ips":[]}}"#);
        down.keep_from(&kept);
        assert!(down.take_blocklists().verified.contains("evil.example"), "a listed domain stays refused");
        assert_eq!(down.firewall_ips(), vec!["1.0.164.165".parse::<IpAddr>().unwrap()], "the table is not emptied");
    }

    #[test]
    fn a_partial_read_adds_to_the_kept_lists_and_never_shrinks_them() {
        let kept = Kept { verified: Arc::new(["a.example", "b.example"].into_iter().map(Into::into).collect()), firewall: vec!["1.0.164.165".into()] };
        let mut partial = parse(r#"{"version":"v3","keep_verified":true,"dns":{"enabled":true,"verified":["b.example","c.example"]},"firewall":{"enabled":true,"ips":["203.0.113.9"]}}"#);
        partial.keep_from(&kept);
        assert_eq!(partial.dns.verified.len(), 3, "no duplicates");
        let verified = partial.take_blocklists().verified;
        assert!(["a.example", "b.example", "c.example"].iter().all(|name| verified.contains(*name)));
        assert_eq!(partial.firewall_ips().len(), 2);
    }

    #[test]
    fn switching_a_protection_off_or_a_complete_list_is_what_clears() {
        let kept = Kept { verified: Arc::new(["evil.example"].into_iter().map(Into::into).collect()), firewall: vec!["1.0.164.165".into()] };
        let mut off = parse(r#"{"version":"v4","keep_verified":true,"dns":{"enabled":false},"firewall":{"enabled":false}}"#);
        off.keep_from(&kept);
        let lists = off.take_blocklists();
        assert!(lists.verified.is_empty() && off.firewall.ips.is_empty() && off.kept(&lists) == Kept::default());
        let mut complete = parse(r#"{"version":"v5","dns":{"enabled":true,"verified":["other.example"]},"firewall":{"enabled":true,"ips":[]}}"#);
        complete.keep_from(&kept);
        assert!(!complete.take_blocklists().verified.contains("evil.example"), "a complete list replaces the kept one");
        assert!(complete.firewall_ips().is_empty());
    }
}
