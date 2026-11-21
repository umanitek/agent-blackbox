//! The plan as the plugin sends it (`plugins/blackbox/shields/network/enforcement.py::plan`), and
//! what each part of the helper takes from it. Every address goes through `IpAddr` or
//! [`crate::platform::source`] here, so nothing unchecked reaches the firewall.

use std::collections::HashSet;
use std::net::IpAddr;

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
    /// The resolver's sets for this plan (all empty while DNS Shield is off).
    pub fn blocklists(&self) -> dns::Blocklists {
        let set = |items: &[String]| items.iter().map(|item| item.to_ascii_lowercase()).collect::<HashSet<_>>();
        if !self.dns.enabled {
            return dns::Blocklists { allow: set(&self.allow), ..Default::default() };
        }
        dns::Blocklists { verified: set(&self.dns.verified), lists: set(&self.dns.lists), block: set(&self.dns.block), allow: set(&self.allow) }
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
        let plan: Plan = serde_json::from_str(r#"{"version":"v","dns":{"enabled":false,"verified":["evil.example"]},"allow":["ok.example"]}"#).unwrap();
        let lists = plan.blocklists();
        assert!(lists.verified.is_empty() && lists.allow.contains("ok.example"));
    }

    #[test]
    fn a_plan_maps_to_the_resolvers_sets_the_tables_and_the_ssh_sources() {
        let plan: Plan = serde_json::from_str(r#"{"version":"v","dns":{"enabled":true,"verified":["Evil.Example"],"lists":["ads.example"],"block":["mine.example"]},
            "firewall":{"enabled":true,"ips":["45.130.148.102","198.51.100.7","not-an-ip"]},
            "cut":{"enabled":true,"ips":["45.130.148.102","198.51.100.7"]},
            "ssh":{"lockdown":true,"allow":["192.168.1.0/24","nonsense","10.0.0.0/99"]},"watch":true,
            "allow":["198.51.100.7"]}"#).unwrap();
        let lists = plan.blocklists();
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
}
