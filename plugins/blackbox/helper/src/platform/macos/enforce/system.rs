//! The Mac's DNS settings: what the helper changes, and how it puts it back.
//!
//! Every enabled network service is pointed at 127.0.0.1 with `networksetup`; the servers each
//! service had before are saved and restored exactly (an empty list means "automatic from DHCP"
//! and is restored as `Empty`). The packet filter is [`super::pf`].

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;

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

/// Points every enabled service at the Shield and returns what each had before.
pub fn point_dns_at_shield() -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut saved = BTreeMap::new();
    for service in parse_services(&run(NETWORKSETUP, &["-listallnetworkservices"])?) {
        let current = parse_dns_servers(&run(NETWORKSETUP, &["-getdnsservers", &service]).unwrap_or_default());
        if current == ["127.0.0.1"] {
            continue; // already ours (a restart): keep the earlier saved value
        }
        run(NETWORKSETUP, &["-setdnsservers", &service, "127.0.0.1"])?;
        saved.insert(service, current);
    }
    Ok(saved)
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
