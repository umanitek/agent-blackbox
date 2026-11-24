//! DNS Shield's system settings on Linux: point the system's DNS at Blackbox's resolver
//! (127.0.0.1:53) and put back exactly what was there (design "Linux deep layers" §2.2). Three
//! ways a Linux machine resolves, each its own [`Mode`]:
//!
//! * **Resolved** (systemd-resolved owns `/etc/resolv.conf`): a drop-in
//!   `/etc/systemd/resolved.conf.d/90-blackbox-dns-shield.conf` gives resolved the global server
//!   127.0.0.1 for every domain (`Domains=~.`), and each link loses its default route
//!   (`resolvectl default-route <link> false`) so no query also goes to the link's own servers; a
//!   link's routing domains (a VPN's split DNS) keep working. Restore: the drop-in removed,
//!   resolved restarted, each link's default route put back as it was.
//! * **NetworkManager** (NetworkManager writes resolv.conf itself): a drop-in
//!   `/etc/NetworkManager/conf.d/90-blackbox-dns-shield.conf` with a global DNS of 127.0.0.1,
//!   then `nmcli general reload`. Restore: the drop-in removed, reloaded.
//! * **Plain** (nothing manages it): `/etc/resolv.conf` replaced (atomically) by one naming
//!   127.0.0.1. Restore: its bytes back exactly, or the link it was, back.
//!
//! What was there is kept in the helper's saved state ([`SavedDns`], keys below) — never a
//! tampered value: a setting that is already Blackbox's is not saved as "the original".
//! Pattern: **Command** — [`point`] and [`restore`] only PLAN a list of [`Action`]s from a
//! [`DnsView`] (pure, tested on recorded views); [`run`] carries them out.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use crate::platform::SavedDns;

pub const RESOLV_CONF: &str = "/etc/resolv.conf";
pub const RESOLVED_DIR: &str = "/run/systemd/resolve";
pub const RESOLVED_UPSTREAMS: &str = "/run/systemd/resolve/resolv.conf";
pub const RESOLVED_DROP_IN: &str = "/etc/systemd/resolved.conf.d/90-blackbox-dns-shield.conf";
pub const NM_DROP_IN: &str = "/etc/NetworkManager/conf.d/90-blackbox-dns-shield.conf";
pub const NETWORKD_LEASES: &str = "/run/systemd/netif/leases";
pub const RESOLVECTL: &str = "resolvectl";
pub const SYSTEMCTL: &str = "systemctl";
pub const NMCLI: &str = "nmcli";
/// Blackbox's resolver.
pub const RESOLVER: &str = "127.0.0.1";
/// The first line of every file Blackbox writes here: how a setting already ours is told.
pub const MARK: &str = "# Blackbox DNS Shield";
pub const RESOLVED_TEXT: &str = "# Blackbox DNS Shield — removed when DNS Shield is turned off.\n[Resolve]\nDNS=127.0.0.1\nDomains=~.\n";
pub const NM_TEXT: &str = "# Blackbox DNS Shield — removed when DNS Shield is turned off.\n[global-dns-domain-*]\nservers=127.0.0.1\n";
pub const PLAIN_TEXT: &str = "# Blackbox DNS Shield — the original comes back when DNS Shield is turned off.\nnameserver 127.0.0.1\n";
/// Saved-state keys (each maps to a list of strings).
pub const MODE_KEY: &str = "linux-mode";
pub const LINK_SERVERS: &str = "resolved-link:";
pub const LINK_ROUTE: &str = "resolved-default-route:";
pub const RESOLV_BYTES: &str = "resolv.conf-hex";
pub const RESOLV_LINK: &str = "resolv.conf-link";
const SMALL: u64 = 64 * 1024;
const STUBS: [&str; 2] = ["127.0.0.53", "127.0.0.54"];

/// How this machine resolves (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Resolved,
    NetworkManager,
    Plain,
}

impl Mode {
    fn name(self) -> &'static str {
        match self { Mode::Resolved => "resolved", Mode::NetworkManager => "networkmanager", Mode::Plain => "plain" }
    }
}

/// One of systemd-resolved's links.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub servers: Vec<String>,
    /// `resolvectl default-route`'s answer for it ("yes" / "no"; "" unknown).
    pub default_route: String,
}

/// What the system's DNS looks like now: read by [`read_view`], or recorded for a test.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsView {
    pub resolv: Vec<u8>,
    /// Where `/etc/resolv.conf` points, when it is a link.
    pub resolv_link: Option<String>,
    pub resolved_running: bool,
    pub links: Vec<Link>,
    pub resolved_drop_in: bool,
    pub nm_drop_in: bool,
}

/// One change to the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Write *bytes* to *path* (mode 0644), replacing it atomically.
    Write(String, Vec<u8>),
    Remove(String),
    /// Make *path* (second) a link to *target* (first).
    Symlink(String, String),
    Run(Vec<String>),
}

/// The `nameserver` addresses of a resolv.conf.
pub fn nameservers(text: &str) -> Vec<String> {
    text.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("nameserver")).then(|| words.next().map(str::to_string)).flatten()
    }).collect()
}

/// `Link 2 (enp0s1): a b` lines of `resolvectl dns` / `default-route` → {name: words}.
pub fn parse_links(text: &str) -> BTreeMap<String, Vec<String>> {
    text.lines().filter_map(|line| {
        let rest = line.trim().strip_prefix("Link ")?;
        let (head, values) = rest.split_once(':')?;
        let name = head.split_once('(')?.1.trim_end_matches(')').trim().to_string();
        Some((name, values.split_whitespace().map(str::to_string).collect()))
    }).collect()
}

/// How the machine of *view* resolves.
pub fn mode(view: &DnsView) -> Mode {
    let text = String::from_utf8_lossy(&view.resolv);
    let servers = nameservers(&text);
    let stub_only = !servers.is_empty() && servers.iter().all(|s| STUBS.contains(&s.as_str()));
    let resolved_link = view.resolv_link.as_deref().is_some_and(|target| target.contains("/run/systemd/resolve/"));
    if view.resolved_running && (resolved_link || stub_only || view.resolved_drop_in) {
        Mode::Resolved
    } else if text.contains("Generated by NetworkManager") || view.nm_drop_in {
        Mode::NetworkManager
    } else {
        Mode::Plain
    }
}

fn run_line(words: &[&str]) -> Action {
    Action::Run(words.iter().map(|w| w.to_string()).collect())
}

/// What pointing DNS at the resolver does, and what to save. Nothing already Blackbox's is saved.
pub fn point(view: &DnsView) -> (Vec<Action>, SavedDns) {
    let mode = mode(view);
    let mut saved = SavedDns::new();
    saved.insert(MODE_KEY.into(), vec![mode.name().into()]);
    let ours = String::from_utf8_lossy(&view.resolv).starts_with(MARK);
    if !ours && mode != Mode::Resolved {
        saved.insert(RESOLV_BYTES.into(), vec![hex::encode(&view.resolv)]);
        if let Some(target) = &view.resolv_link { saved.insert(RESOLV_LINK.into(), vec![target.clone()]); }
    }
    let actions = match mode {
        Mode::Resolved => {
            let mut actions = vec![Action::Write(RESOLVED_DROP_IN.into(), RESOLVED_TEXT.into()), run_line(&[SYSTEMCTL, "restart", "systemd-resolved"])];
            for link in view.links.iter().filter(|link| !link.servers.is_empty() || link.default_route == "yes") {
                if !view.resolved_drop_in {   // a drop-in already there: these links were already changed by us
                    saved.insert(format!("{LINK_SERVERS}{}", link.name), link.servers.clone());
                    saved.insert(format!("{LINK_ROUTE}{}", link.name), vec![link.default_route.clone()]);
                }
                actions.push(run_line(&[RESOLVECTL, "default-route", &link.name, "false"]));
            }
            actions
        }
        Mode::NetworkManager => vec![Action::Write(NM_DROP_IN.into(), NM_TEXT.into()), run_line(&[NMCLI, "general", "reload"])],
        Mode::Plain => vec![Action::Write(RESOLV_CONF.into(), PLAIN_TEXT.into())],
    };
    (actions, saved)
}

/// What putting back *saved* does (an empty plan when nothing was saved).
pub fn restore(saved: &SavedDns) -> Vec<Action> {
    let mode = saved.get(MODE_KEY).and_then(|v| v.first()).map(String::as_str).unwrap_or("");
    let mut actions = vec![];
    match mode {
        "resolved" => {
            actions.push(Action::Remove(RESOLVED_DROP_IN.into()));
            actions.push(run_line(&[SYSTEMCTL, "restart", "systemd-resolved"]));
            for (key, value) in saved.iter().filter(|(key, _)| key.starts_with(LINK_ROUTE)) {
                let route = if value.first().map(String::as_str) == Some("no") { "false" } else { "true" };
                actions.push(run_line(&[RESOLVECTL, "default-route", &key[LINK_ROUTE.len()..], route]));
            }
        }
        "networkmanager" => {
            actions.push(Action::Remove(NM_DROP_IN.into()));
            actions.push(run_line(&[NMCLI, "general", "reload"]));
        }
        "plain" => match (saved.get(RESOLV_LINK).and_then(|v| v.first()), saved.get(RESOLV_BYTES).and_then(|v| v.first())) {
            (Some(target), _) => actions.push(Action::Symlink(target.clone(), RESOLV_CONF.into())),
            (None, Some(bytes)) => actions.push(Action::Write(RESOLV_CONF.into(), hex::decode(bytes).unwrap_or_default())),
            (None, None) => {}
        },
        _ => {}
    }
    actions
}

/// Whether DNS no longer points at the resolver in *view* (someone changed it under DNS Shield).
pub fn drifted(view: &DnsView) -> bool {
    match mode(view) {
        Mode::Resolved => !view.resolved_drop_in || view.links.iter().any(|link| !link.servers.is_empty() && link.default_route == "yes"),
        Mode::NetworkManager => !view.nm_drop_in,
        Mode::Plain => nameservers(&String::from_utf8_lossy(&view.resolv)) != [RESOLVER],
    }
}

/// Non-loopback addresses among *servers*, as port-53 upstreams, each once.
pub fn upstreams(servers: impl IntoIterator<Item = String>) -> Vec<SocketAddr> {
    let mut seen = std::collections::BTreeSet::new();
    servers.into_iter().filter_map(|s| s.split('%').next()?.parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback() && seen.insert(*ip)).map(|ip| SocketAddr::new(ip, 53)).collect()
}

/// The upstreams the saved settings name (after a restart, when the system shows only ours).
pub fn upstreams_from_saved(saved: &SavedDns) -> Vec<SocketAddr> {
    let mut servers: Vec<String> = saved.iter().filter(|(key, _)| key.starts_with(LINK_SERVERS)).flat_map(|(_, v)| v.clone()).collect();
    if let Some(bytes) = saved.get(RESOLV_BYTES).and_then(|v| v.first()).and_then(|h| hex::decode(h).ok()) {
        servers.extend(nameservers(&String::from_utf8_lossy(&bytes)));
    }
    upstreams(servers)
}

/// `IP4.DNS[1]:192.168.1.1` lines of `nmcli -t -f IP4.DNS,IP6.DNS dev show`, and `DNS=a b` lines of
/// systemd-networkd's lease files: the servers this network handed out.
pub fn parse_dhcp(nmcli: &str, leases: &str) -> Vec<String> {
    let from_nm = nmcli.lines().filter_map(|line| line.split_once(':')).filter(|(key, _)| key.contains(".DNS[")).map(|(_, v)| v.trim().to_string());
    let from_leases = leases.lines().filter_map(|line| line.strip_prefix("DNS=")).flat_map(|v| v.split_whitespace().map(str::to_string).collect::<Vec<_>>());
    from_nm.chain(from_leases).collect()
}

// ── reading and changing the system ───────────────────────────────────────────────────────

fn text(path: &str) -> String {
    crate::safe_read::read_regular(Path::new(path), SMALL).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

fn output(words: &[&str]) -> Option<String> {
    let out = crate::command::output(Command::new(words[0]).args(&words[1..]), crate::command::TIMEOUT).ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The system's DNS now.
pub fn read_view() -> DnsView {
    let resolv_link = fs::read_link(RESOLV_CONF).ok().map(|target| target.display().to_string());
    // The file itself or what it points to (a link is the system's own, read as such).
    let resolv = fs::read(RESOLV_CONF).ok().filter(|b| b.len() as u64 <= SMALL).unwrap_or_default();
    let resolved_running = Path::new(RESOLVED_UPSTREAMS).exists() || Path::new(RESOLVED_DIR).join("io.systemd.Resolve").exists();
    let mut links = vec![];
    if resolved_running {
        let servers = parse_links(&output(&[RESOLVECTL, "dns"]).unwrap_or_default());
        let routes = parse_links(&output(&[RESOLVECTL, "default-route"]).unwrap_or_default());
        for (name, found) in servers {
            let default_route = routes.get(&name).and_then(|v| v.first().cloned()).unwrap_or_default();
            links.push(Link { name, servers: found, default_route });
        }
    }
    DnsView { resolv, resolv_link, resolved_running, links,
              resolved_drop_in: Path::new(RESOLVED_DROP_IN).exists(), nm_drop_in: Path::new(NM_DROP_IN).exists() }
}

fn write_atomically(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let target = Path::new(path);
    if let Some(folder) = target.parent() { fs::create_dir_all(folder)?; }
    let temporary = format!("{path}.blackbox-new");
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o644).custom_flags(libc::O_NOFOLLOW).open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
    fs::rename(&temporary, target)   // replaces a link with the file: the saved link comes back on restore
}

/// Carries out *actions* in order; answers what failed (nothing → empty). One failure never
/// stops the rest: a restore puts back all it can.
pub fn run(actions: &[Action]) -> Vec<String> {
    let mut errors = vec![];
    for action in actions {
        let result = match action {
            Action::Write(path, bytes) => write_atomically(path, bytes).map_err(|e| format!("{path}: {e}")),
            Action::Remove(path) => match fs::remove_file(path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(format!("{path}: {error}")),
                _ => Ok(()),
            },
            Action::Symlink(target, path) => {
                let _ = fs::remove_file(path);
                std::os::unix::fs::symlink(target, path).map_err(|e| format!("{path} -> {target}: {e}"))
            }
            Action::Run(words) => {
                let words: Vec<&str> = words.iter().map(String::as_str).collect();
                output(&words).map(|_| ()).ok_or_else(|| format!("{} failed", words.join(" ")))
            }
        };
        if let Err(error) = result { errors.push(error); }
    }
    errors
}

/// The servers the system resolves with now (resolved's real upstreams behind its stub).
pub fn current_upstreams() -> Vec<SocketAddr> {
    let view = read_view();
    let source = if mode(&view) == Mode::Resolved { text(RESOLVED_UPSTREAMS) } else { String::from_utf8_lossy(&view.resolv).into_owned() };
    let mut servers = nameservers(&source);
    servers.extend(view.links.into_iter().flat_map(|link| link.servers));
    upstreams(servers)
}

/// The servers this network handed out (NetworkManager's, else systemd-networkd's leases).
pub fn dhcp_upstreams() -> Vec<SocketAddr> {
    let nm = output(&[NMCLI, "-t", "-f", "IP4.DNS,IP6.DNS", "dev", "show"]).unwrap_or_default();
    let leases: String = fs::read_dir(NETWORKD_LEASES).map(|entries| entries.flatten().take(64)
        .map(|e| text(&e.path().display().to_string())).collect()).unwrap_or_default();
    upstreams(parse_dhcp(&nm, &leases))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved_view() -> DnsView {
        DnsView { resolv: b"nameserver 127.0.0.53\noptions edns0 trust-ad\n".to_vec(),
                  resolv_link: Some("../run/systemd/resolve/stub-resolv.conf".into()), resolved_running: true,
                  links: vec![Link { name: "enp0s1".into(), servers: vec!["192.168.64.1".into()], default_route: "yes".into() },
                              Link { name: "wg0".into(), servers: vec!["10.8.0.1".into()], default_route: "no".into() }],
                  ..Default::default() }
    }

    #[test]
    fn resolved_gets_a_drop_in_and_each_link_loses_its_default_route_then_all_comes_back() {
        let view = resolved_view();
        assert_eq!(mode(&view), Mode::Resolved);
        let (actions, saved) = point(&view);
        assert_eq!(actions[0], Action::Write(RESOLVED_DROP_IN.into(), RESOLVED_TEXT.into()));
        assert!(actions.contains(&run_line(&[RESOLVECTL, "default-route", "enp0s1", "false"])));
        assert_eq!(saved["resolved-default-route:wg0"], vec!["no"]);
        assert_eq!(upstreams_from_saved(&saved), vec!["192.168.64.1:53".parse().unwrap(), "10.8.0.1:53".parse().unwrap()]);
        let back = restore(&saved);
        assert_eq!(back[0], Action::Remove(RESOLVED_DROP_IN.into()));
        assert!(back.contains(&run_line(&[RESOLVECTL, "default-route", "enp0s1", "true"])));
        assert!(back.contains(&run_line(&[RESOLVECTL, "default-route", "wg0", "false"])), "a link without a default route stays without");
        let again = DnsView { resolved_drop_in: true, ..resolved_view() };
        assert!(!point(&again).1.keys().any(|k| k.starts_with(LINK_ROUTE)), "an already-changed link is never saved as the original");
    }

    #[test]
    fn plain_and_networkmanager_resolv_conf_come_back_exactly() {
        let original = b"# my own\nnameserver 9.9.9.9\nsearch home\n".to_vec();
        let plain = DnsView { resolv: original.clone(), ..Default::default() };
        let (actions, saved) = point(&plain);
        assert_eq!(actions, vec![Action::Write(RESOLV_CONF.into(), PLAIN_TEXT.into())]);
        assert_eq!(restore(&saved), vec![Action::Write(RESOLV_CONF.into(), original)]);
        assert_eq!(upstreams_from_saved(&saved), vec!["9.9.9.9:53".parse().unwrap()]);
        let linked = DnsView { resolv_link: Some("/run/resolvconf/resolv.conf".into()), ..plain.clone() };
        assert_eq!(restore(&point(&linked).1), vec![Action::Symlink("/run/resolvconf/resolv.conf".into(), RESOLV_CONF.into())]);
        let ours = DnsView { resolv: PLAIN_TEXT.into(), ..Default::default() };
        assert!(!point(&ours).1.contains_key(RESOLV_BYTES), "ours is never saved as the original");
        let nm = DnsView { resolv: b"# Generated by NetworkManager\nnameserver 192.168.1.1\n".to_vec(), ..Default::default() };
        assert_eq!(point(&nm).0[0], Action::Write(NM_DROP_IN.into(), NM_TEXT.into()));
        assert_eq!(restore(&point(&nm).1)[0], Action::Remove(NM_DROP_IN.into()));
        assert!(restore(&SavedDns::new()).is_empty());
    }

    #[test]
    fn drift_links_and_dhcp_parse() {
        assert!(drifted(&resolved_view()), "no drop-in yet");
        let pointed = DnsView { resolved_drop_in: true, links: vec![], ..resolved_view() };
        assert!(!drifted(&pointed));
        assert!(!drifted(&DnsView { resolv: PLAIN_TEXT.into(), ..Default::default() }));
        let links = parse_links("Global: 1.1.1.1\nLink 2 (enp0s1): 192.168.64.1 fe80::1%enp0s1\nLink 3 (wg0):\n");
        assert_eq!(links["enp0s1"], vec!["192.168.64.1", "fe80::1%enp0s1"]);
        assert!(links["wg0"].is_empty());
        let dhcp = parse_dhcp("IP4.DNS[1]:192.168.1.1\nIP6.DNS[1]:fd00::1\nGENERAL.DEVICE:x\n", "ADDRESS=1\nDNS=10.0.0.1 10.0.0.2\n");
        assert_eq!(dhcp, vec!["192.168.1.1", "fd00::1", "10.0.0.1", "10.0.0.2"]);
        assert_eq!(upstreams(["127.0.0.1".into(), "fe80::1%eth0".into(), "fe80::1".into()]), vec!["[fe80::1]:53".parse().unwrap()]);
    }
}
