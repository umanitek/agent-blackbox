//! Tampering on Linux: one look every [`TAMPER_EVERY`] at the settings an attacker changes to get
//! around protection (observing only), filled into the every-OS [`Look`]:
//!
//! * the DNS servers the system asks — `/etc/resolv.conf`, or behind systemd-resolved's stub
//!   (127.0.0.53 / .54) the servers resolved itself asks (`/run/systemd/resolve/resolv.conf`);
//! * a proxy set for every program (`http_proxy`, `https_proxy`, `all_proxy` in `/etc/environment`);
//! * VPN and tunnel interfaces (`/sys/class/net`: WireGuard, tun / tap, PPP, Tailscale …);
//! * the system firewall: ufw's switch (`/etc/ufw/ufw.conf`), else whether firewalld runs;
//! * Blackbox's own helper — its systemd unit and binary fingerprints;
//! * the packet filter Blackbox's firewall uses: whether nftables answers (`nft list tables`).
//!   WHY not "is Blackbox's table there": the table is removed whenever the person turns the
//!   firewall's protections off, so its absence is not tampering; a flushed ruleset under an
//!   active plan is seen and re-applied by the firewall's own check (`filter_enabled`).

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

pub use crate::platform::system_watch::tamper::{Look, Tamper};

use crate::platform::linux::{procfs, BINARY, UNIT};

pub const TAMPER_EVERY: Duration = Duration::from_secs(5);
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
pub const RESOLVED_UPSTREAMS: &str = "/run/systemd/resolve/resolv.conf";
pub const ENVIRONMENT: &str = "/etc/environment";
pub const UFW_CONF: &str = "/etc/ufw/ufw.conf";
pub const NFT_COMMANDS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];
/// systemd-resolved's local stub addresses: a resolv.conf naming only these says nothing about
/// where queries really go.
const RESOLVED_STUBS: &[&str] = &["127.0.0.53", "127.0.0.54"];
/// Interface name prefixes that are a VPN or a tunnel.
const TUNNEL_PREFIXES: &[&str] = &["wg", "tun", "tap", "ppp", "tailscale", "nordlynx", "proton", "ipsec", "vti", "zt"];
const SMALL: u64 = 64 * 1024;

/// The `nameserver` lines of a resolv.conf.
pub fn parse_resolv(text: &str) -> Vec<String> {
    text.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("nameserver")).then(|| words.next().map(str::to_string)).flatten()
    }).collect()
}

/// The proxies switched on for every program in `/etc/environment` (`http_proxy=…` → `http`).
pub fn parse_environment_proxy(text: &str) -> Vec<String> {
    const KINDS: [(&str, &str); 3] = [("http_proxy", "http"), ("https_proxy", "https"), ("all_proxy", "socks")];
    KINDS.iter().filter(|(key, _)| text.lines().any(|line| {
        let line = line.trim().trim_start_matches("export ").to_ascii_lowercase();
        line.split_once('=').is_some_and(|(name, value)| name.trim() == *key && !value.trim().trim_matches(['"', '\'']).is_empty())
    })).map(|(_, kind)| kind.to_string()).collect()
}

/// How many of *names* (network interfaces) are a VPN or tunnel.
pub fn count_tunnels<'a>(names: impl Iterator<Item = &'a str>) -> usize {
    names.filter(|name| TUNNEL_PREFIXES.iter().any(|prefix| name.starts_with(prefix))).count()
}

/// ufw's switch from `ufw.conf` (`ENABLED=yes|no`): on | off | None (not said).
pub fn parse_ufw(text: &str) -> Option<&'static str> {
    text.lines().find_map(|line| line.trim().strip_prefix("ENABLED=")).map(|value| {
        if value.trim().trim_matches('"').eq_ignore_ascii_case("yes") { "on" } else { "off" }
    })
}

fn text(path: &str) -> Option<String> {
    crate::safe_read::read_regular(Path::new(path), SMALL).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// The DNS servers the system asks (see the module doc).
pub fn dns_servers() -> Vec<String> {
    let servers = parse_resolv(&text(RESOLV_CONF).unwrap_or_default());
    if !servers.is_empty() && servers.iter().all(|server| RESOLVED_STUBS.contains(&server.as_str())) {
        return parse_resolv(&text(RESOLVED_UPSTREAMS).unwrap_or_default());
    }
    servers
}

/// The system firewall: on | off | unknown (ufw's switch, else firewalld running).
pub fn firewall() -> String {
    if let Some(state) = text(UFW_CONF).as_deref().and_then(parse_ufw) {
        return state.into();
    }
    let proc = Path::new(procfs::PROC);
    let firewalld = procfs::pids(proc).into_iter().any(|pid| procfs::stat(proc, pid).is_some_and(|s| s.comm == "firewalld"));
    if firewalld { "on".into() } else { "unknown".into() }
}

fn tunnels() -> usize {
    let Ok(entries) = fs::read_dir(procfs::SYS_NET) else { return 0 };
    let names: Vec<String> = entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    count_tunnels(names.iter().map(String::as_str))
}

fn nftables() -> String {
    let Some(nft) = NFT_COMMANDS.iter().find(|path| Path::new(path).exists()) else { return "unknown".into() };
    match crate::command::output(Command::new(nft).args(["list", "tables"]), crate::command::TIMEOUT) {
        Ok(out) if out.status.success() => "enabled".into(),
        _ => "unknown".into(),
    }
}

fn fingerprint(path: &str) -> String {
    crate::safe_read::read_regular(Path::new(path), 64 * 1024 * 1024)
        .map(|bytes| Sha256::digest(&bytes).iter().take(8).map(|b| format!("{b:02x}")).collect())
        .unwrap_or_else(|| "missing".into())
}

/// Looks at everything now.
pub fn look() -> Look {
    Look {
        dns_servers: dns_servers(),
        proxy: parse_environment_proxy(&text(ENVIRONMENT).unwrap_or_default()),
        vpn_count: tunnels(),
        firewall: firewall(),
        helper: [UNIT, BINARY].iter().map(|path| fingerprint(path)).collect(),
        pf: nftables(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_parse() {
        let resolv = "# Generated by NetworkManager\nsearch lan\nnameserver 192.168.1.1\nnameserver  fd00::1 \noptions edns0\n";
        assert_eq!(parse_resolv(resolv), vec!["192.168.1.1", "fd00::1"]);
        assert_eq!(parse_resolv("nameserver 127.0.0.53\noptions edns0 trust-ad\n"), vec!["127.0.0.53"]);
        let environment = "PATH=\"/usr/local/sbin:/usr/bin\"\nhttp_proxy=\"http://10.0.0.9:3128\"\nHTTPS_PROXY=http://10.0.0.9:3128\nno_proxy=localhost\nall_proxy=\"\"\n";
        assert_eq!(parse_environment_proxy(environment), vec!["http", "https"]);
        assert_eq!(count_tunnels(["lo", "enp0s1", "wg0", "tailscale0", "docker0", "tun1"].into_iter()), 3);
        assert_eq!(parse_ufw("# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n"), Some("on"));
        assert_eq!(parse_ufw("ENABLED=no\n"), Some("off"));
        assert_eq!(parse_ufw(""), None);
    }
}
