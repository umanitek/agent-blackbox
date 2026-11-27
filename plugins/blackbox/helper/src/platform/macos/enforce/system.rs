//! The Mac's DNS settings: what the helper changes, and how it puts it back.
//!
//! Every enabled network service is pointed at 127.0.0.1 with `networksetup`; the servers each
//! service had before are saved and restored exactly (an empty list means "automatic from DHCP"
//! and is restored as `Empty`). The packet filter is [`super::pf`].

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;

use super::restore::RESOLVER;
use crate::platform::{Pointed, SavedDns};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SCUTIL: &str = "/usr/sbin/scutil";
/// Used when the Mac had no upstream DNS of its own to forward to.

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = crate::command::output(Command::new(program).args(args), crate::command::TIMEOUT).map_err(|error| format!("{program}: {error}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if output.status.success() { Ok(text) } else { Err(format!("{program} {}: {}", args.join(" "), text.trim())) }
}

// ── DNS ────────────────────────────────────────────────────────────────────────────────────

/// The enabled network services (`networksetup -listallnetworkservices`; `*` marks disabled).
pub fn parse_services(text: &str) -> Vec<String> {
    text.lines().skip(1).map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('*')).map(str::to_string).collect()
}

/// The DNS servers a service has set by hand; empty when it uses DHCP's.
pub fn parse_dns_servers(text: &str) -> Vec<String> {
    if text.contains("There aren't any DNS Servers") {
        return vec![];
    }
    text.lines().map(str::trim).filter(|line| line.parse::<IpAddr>().is_ok()).map(str::to_string).collect()
}

/// Points every enabled service at the Shield and returns what each had before ([`point_with`]).
pub fn point_dns_at_shield(already: &SavedDns) -> Pointed {
    let pointed = point_with(already, |args| run(NETWORKSETUP, args));
    flush_dns_caches();
    pointed
}

/// [`point_dns_at_shield`] through *networksetup* (args → its output; tests pass a stand-in).
/// Every service is tried, one failure never stops the rest, and what was saved before a failure
/// is answered with it ([`Pointed`]). A service already at 127.0.0.1 is skipped only when
/// *already* holds its original; with none (it was lost) it is saved as "automatic" — WHY: putting
/// back 127.0.0.1 would leave the Mac on a resolver that is gone once DNS Shield is off, while
/// "automatic" takes this network's own servers again.
pub fn point_with(already: &SavedDns, mut networksetup: impl FnMut(&[&str]) -> Result<String, String>) -> Pointed {
    let mut pointed = Pointed::default();
    let services = match networksetup(&["-listallnetworkservices"]) {
        Ok(text) => parse_services(&text),
        Err(error) => return Pointed { error: Some(error), ..pointed },
    };
    let mut errors = vec![];
    for service in services {
        // WHY an unreadable service is left alone: saving "none" for it would put back "automatic"
        // later in place of servers the person set by hand.
        let current = match networksetup(&["-getdnsservers", &service]) {
            Ok(text) => parse_dns_servers(&text),
            Err(error) => { errors.push(error); continue; }
        };
        if current == [RESOLVER] {
            if !already.contains_key(&service) {
                pointed.saved.insert(service, vec![]);
            }
            continue;
        }
        match networksetup(&["-setdnsservers", &service, RESOLVER]) {
            Ok(_) => { pointed.saved.insert(service, current); }
            Err(error) => errors.push(error),
        }
    }
    pointed.error = (!errors.is_empty()).then(|| errors.join("; "));
    pointed
}

/// The commands that make macOS drop the answers it cached from the servers it used before
/// (KI-649): the directory-service cache, and mDNSResponder (which re-reads its servers on HUP).
pub const FLUSH_COMMANDS: [(&str, &[&str]); 2] = [("/usr/bin/dscacheutil", &["-flushcache"]), ("/usr/bin/killall", &["-HUP", "mDNSResponder"])];

/// Runs [`FLUSH_COMMANDS`]; a failure only means old answers expire on their own.
fn flush_dns_caches() {
    for (program, args) in FLUSH_COMMANDS {
        let _ = run(program, args);
    }
}

/// Puts back what [`point_dns_at_shield`] saved. Errors are collected, never stop the rest.
pub fn restore_dns(saved: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut errors = vec![];
    for (service, servers) in saved {
        let mut args = vec!["-setdnsservers", service.as_str()];
        if servers.is_empty() {
            args.push("Empty");
        } else {
            args.extend(servers.iter().map(String::as_str));
        }
        if let Err(error) = run(NETWORKSETUP, &args) {
            errors.push(error);
        }
    }
    flush_dns_caches();
    errors
}

/// The upstreams to forward to: the servers the Mac resolves with (from `scutil --dns`, which
/// includes DHCP-given ones) minus the Shield itself. NEVER a public resolver nobody chose
/// (security finding: queries used to go silently to Cloudflare / Quad9): when none is known the
/// answer is empty and DNS Shield stays off, saying why.
///
/// Scoped resolvers (a block with `domain :` — a VPN's company domains, `.local`) are NOT
/// upstreams: macOS keeps sending those domains straight to their own servers whatever the
/// service's DNS is, so they keep working, and the rest of the internet's names never leak to them.
pub fn upstreams_from_scutil(text: &str) -> Vec<SocketAddr> {
    let mut seen = std::collections::BTreeSet::new();
    let general: String = text.split("resolver #")
        .filter(|block| !block.lines().any(|line| line.trim_start().starts_with("domain ") || line.trim_start().starts_with("domain:")))
        .collect::<Vec<_>>().join("\n");
    let upstreams: Vec<SocketAddr> = general
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver[").and_then(|rest| rest.split_once(':')).map(|(_, ip)| ip.trim()))
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback())
        .filter(|ip| seen.insert(*ip))
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    upstreams
}

/// The DNS servers this network handed out (DHCP) on the default route's interface. Used while
/// DNS Shield is on (the Mac's own settings then show only 127.0.0.1), so moving to another
/// network follows that network's servers instead of the last one's.
pub fn dhcp_upstreams() -> Vec<SocketAddr> {
    let route = run("/sbin/route", &["-n", "get", "default"]).unwrap_or_default();
    let Some(interface) = parse_default_interface(&route) else { return vec![] };
    parse_dhcp_dns(&run("/usr/sbin/ipconfig", &["getpacket", &interface]).unwrap_or_default())
}

/// `interface: en0` from `route -n get default`.
pub fn parse_default_interface(text: &str) -> Option<String> {
    text.lines().find_map(|line| line.trim().strip_prefix("interface:").map(|i| i.trim().to_string())).filter(|i| !i.is_empty())
}

/// `domain_name_server (ip_mult): {192.168.1.1, 192.168.1.2}` from `ipconfig getpacket`.
pub fn parse_dhcp_dns(text: &str) -> Vec<SocketAddr> {
    let Some(line) = text.lines().find(|line| line.trim_start().starts_with("domain_name_server")) else { return vec![] };
    let inside = line.split_once('{').and_then(|(_, rest)| rest.split_once('}')).map(|(list, _)| list).unwrap_or("");
    inside.split(',').filter_map(|ip| ip.trim().parse::<IpAddr>().ok()).filter(|ip| !ip.is_loopback())
        .map(|ip| SocketAddr::new(ip, 53)).collect()
}

/// Whether DNS Shield is in effect now: the Mac's first general resolver (`scutil --dns`, what the
/// system really asks) is Blackbox's. None when scutil can not be read.
pub fn shield_in_effect() -> Option<bool> {
    run(SCUTIL, &["--dns"]).ok().map(|text| first_nameserver(&text).as_deref() == Some(super::restore::RESOLVER))
}

/// The first `nameserver[0]` of the general configuration (before "DNS configuration (for scoped
/// queries)"), "" when none is set.
pub fn first_nameserver(scutil: &str) -> Option<String> {
    let general = scutil.split("for scoped queries").next().unwrap_or("");
    general.lines().find_map(|line| line.trim().strip_prefix("nameserver[0] :").map(|ip| ip.trim().to_string()))
}

/// Reads the Mac's current resolvers. Call before pointing DNS at the Shield.
pub fn current_upstreams() -> Vec<SocketAddr> {
    upstreams_from_scutil(&run(SCUTIL, &["--dns"]).unwrap_or_default())
}

/// The servers saved for each service, as upstreams (used after a restart, when scutil already
/// shows only the Shield).
pub fn upstreams_from_saved(saved: &BTreeMap<String, Vec<String>>) -> Vec<SocketAddr> {
    let text: String = saved.values().flatten().map(|ip| format!("nameserver[0] : {ip}\n")).collect();
    upstreams_from_scutil(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shield_is_in_effect_only_when_the_general_resolver_is_ours() {
        // bb-w12-a (W12): Ethernet had no DNS servers set, scutil showed the router, state said dns_active.
        let router = "DNS configuration\n\nresolver #1\n  search domain[0] : localdomain\n  nameserver[0] : 192.168.64.1\n\
                      \nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.168.64.1\n";
        assert_eq!(first_nameserver(router).as_deref(), Some("192.168.64.1"));
        let ours = "DNS configuration\n\nresolver #1\n  nameserver[0] : 127.0.0.1\n\nDNS configuration (for scoped queries)\n\
                    \nresolver #1\n  nameserver[0] : 192.168.64.1\n";
        assert_eq!(first_nameserver(ours).as_deref(), Some("127.0.0.1"), "a scoped resolver below does not count");
        assert_eq!(first_nameserver("DNS configuration\n\nresolver #1\n  domain : local\n"), None);
    }

    /// Review finding 2026-11-26 (partial DNS switch): a failure on one service kept the originals
    /// already saved for the others, and a retry never takes a service already at 127.0.0.1 with
    /// no saved original as "already ours".
    #[test]
    fn a_failure_on_one_service_keeps_what_the_others_had_and_a_retry_never_loses_an_original() {
        let mut dns: BTreeMap<String, Vec<String>> = BTreeMap::from([("Ethernet".into(), vec!["192.168.1.1".into()]), ("Wi-Fi".into(), vec![])]);
        let mut fail_wifi = true;
        let fake = |dns: &mut BTreeMap<String, Vec<String>>, fail: bool, args: &[&str]| -> Result<String, String> {
            match args {
                ["-listallnetworkservices"] => Ok("An asterisk (*) denotes that a network service is disabled.\nEthernet\nWi-Fi\n".into()),
                ["-getdnsservers", service] => Ok(dns[*service].join("\n")),
                ["-setdnsservers", "Wi-Fi", _] if fail => Err("networksetup: timed out".into()),
                ["-setdnsservers", service, ip] => { dns.insert(service.to_string(), vec![ip.to_string()]); Ok(String::new()) }
                _ => Err(format!("unexpected {args:?}")),
            }
        };
        let first = point_with(&SavedDns::new(), |args| fake(&mut dns, fail_wifi, args));
        assert!(first.error.is_some());
        assert_eq!(first.saved, SavedDns::from([("Ethernet".into(), vec!["192.168.1.1".to_string()])]), "Ethernet's original is kept with the error");
        fail_wifi = false;
        let retry = point_with(&first.saved, |args| fake(&mut dns, fail_wifi, args));
        assert_eq!(retry, Pointed { saved: SavedDns::from([("Wi-Fi".into(), vec![])]), error: None }, "Ethernet is ours with its original saved");
        let lost = point_with(&SavedDns::new(), |args| fake(&mut dns, fail_wifi, args));
        assert_eq!(lost.saved, SavedDns::from([("Ethernet".into(), vec![]), ("Wi-Fi".into(), vec![])]),
                   "at 127.0.0.1 with no original: put back as automatic, never as 127.0.0.1");
    }

    #[test]
    fn services_skip_the_header_and_disabled_ones() {
        let text = "An asterisk (*) denotes that a network service is disabled.\nEthernet\n*Thunderbolt Bridge\nWi-Fi\n";
        assert_eq!(parse_services(text), ["Ethernet", "Wi-Fi"]);
    }

    #[test]
    fn dns_servers_or_dhcp() {
        assert!(parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert_eq!(parse_dns_servers("192.168.1.1\n2001:4860:4860::8888\n"), ["192.168.1.1", "2001:4860:4860::8888"]);
    }

    #[test]
    fn upstreams_skip_the_shield_and_never_fall_back_to_public_resolvers() {
        let text = "resolver #1\n  nameserver[0] : 127.0.0.1\n  nameserver[1] : 192.168.64.1\nresolver #2\n  nameserver[0] : 192.168.64.1\n";
        assert_eq!(upstreams_from_scutil(text), ["192.168.64.1:53".parse::<SocketAddr>().unwrap()]);
        assert!(upstreams_from_scutil("  nameserver[0] : 127.0.0.1\n").is_empty(), "no silent Cloudflare / Quad9");
        assert!(upstreams_from_saved(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_vpns_scoped_resolver_is_kept_out_of_the_general_upstreams() {
        let text = "resolver #1\n  nameserver[0] : 192.168.1.1\nresolver #2\n  domain   : corp.example\n  nameserver[0] : 10.8.0.1\n";
        assert_eq!(upstreams_from_scutil(text), ["192.168.1.1:53".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn the_networks_own_dns_servers_are_read_from_dhcp() {
        assert_eq!(parse_default_interface("   route to: default\ndestination: default\n  interface: en0\n"), Some("en0".into()));
        let packet = "op = BOOTREPLY\nOptions count is 9\ndomain_name_server (ip_mult): {192.168.1.1, 192.168.1.2}\nend (none):\n";
        assert_eq!(parse_dhcp_dns(packet), ["192.168.1.1:53".parse::<SocketAddr>().unwrap(), "192.168.1.2:53".parse().unwrap()]);
        assert!(parse_dhcp_dns("op = BOOTREPLY\n").is_empty());
    }
}
