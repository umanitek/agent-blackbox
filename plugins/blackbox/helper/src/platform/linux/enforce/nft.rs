//! Network Shield's firewall on Linux: one nftables table of Blackbox's own, `inet blackbox_netd`,
//! for everything it enforces (design "Linux deep layers" §2.1). It holds eight sets (IPv4 and
//! IPv6 of each list; `flags interval` with `auto-merge`, so a network and an address inside it
//! may both be listed) and only the rules of the protections that are on:
//!
//! - **Threat Firewall** — `threats4/6`: traffic to and from the verified graph's addresses dropped;
//! - **Cut malicious connections** — `cut4/6`: dropped both ways, and their open sockets and
//!   connection-tracking entries ended ([`kill_states`]);
//! - **SSH lockdown** — `ssh_allow4/6`: SSH in (TCP 22) from anywhere but this machine and the
//!   allowed sources gets a reset;
//! - **Lock remote access** — the remote-access ports ([`REMOTE_PORTS`]) refused to everyone but
//!   this machine itself, ahead of SSH lockdown's allow list (the lock always wins);
//! - **Blocked addresses** — `remote_block4/6`: refused inbound entirely.
//!
//! Each apply replaces the whole table in ONE `nft -f -` transaction (create, delete, create:
//! nothing is ever half-loaded), and an all-off filter deletes it. Coexistence: the chains hook
//! at priority `filter - 10` and only ever drop or reject — never accept — so another firewall's
//! (ufw, firewalld, Docker's) refusals still hold. The table is Blackbox's alone: no system file
//! is edited, and no other table is touched.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::platform::Filter;

/// Where `nft` lives across distributions.
pub const NFT_COMMANDS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];
pub const SS_COMMANDS: &[&str] = &["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss"];
pub const CONNTRACK_COMMANDS: &[&str] = &["/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack"];
/// The table's family and name.
pub const TABLE: &str = "inet blackbox_netd";
/// What `apply_filter` answers while the table is loaded (the plan / report loop saves it).
pub const TOKEN: &str = "nft:blackbox_netd";
/// The ports Lock remote access closes: SSH, RDP, VNC (5900–5903), RustDesk, TeamViewer, Splashtop.
pub const REMOTE_PORTS: &str = "{ 22, 3389, 5900-5903, 21115-21119, 5938, 7070 }";
/// Loading a large threat set can take a moment; still bounded.
const NFT_TIMEOUT: Duration = Duration::from_secs(60);
pub const NOT_INSTALLED: &str = "the firewall needs nftables (the nft command): install the nftables package";

/// The eight sets: (name, element type).
const SETS: [(&str, &str); 8] = [
    ("threats4", "ipv4_addr"), ("threats6", "ipv6_addr"), ("cut4", "ipv4_addr"), ("cut6", "ipv6_addr"),
    ("ssh_allow4", "ipv4_addr"), ("ssh_allow6", "ipv6_addr"), ("remote_block4", "ipv4_addr"), ("remote_block6", "ipv6_addr"),
];

/// Creating then deleting the table first makes "replace" one transaction that cannot fail on a
/// table that is not there yet.
fn reset_lines() -> String {
    format!("table {TABLE}\ndelete table {TABLE}\n")
}

/// The script that removes the table (the all-off filter).
pub fn delete_script() -> String {
    reset_lines()
}

fn split(list: &[String]) -> (Vec<String>, Vec<String>) {
    let unique: BTreeSet<&String> = list.iter().collect();
    unique.into_iter().cloned().partition(|entry| !entry.contains(':'))
}

fn addresses(list: &Option<Vec<IpAddr>>) -> Vec<String> {
    list.iter().flatten().map(IpAddr::to_string).collect()
}

fn set_line(name: &str, kind: &str, elements: &[String]) -> String {
    let elements = if elements.is_empty() { String::new() } else { format!(" elements = {{ {} }}", elements.join(", ")) };
    format!("\tset {name} {{ type {kind}; flags interval; auto-merge;{elements} }}\n")
}

/// The whole table for *filter*, as one `nft -f` script (see the module doc).
pub fn ruleset(filter: &Filter) -> String {
    let (threats4, threats6) = split(&addresses(&filter.threats));
    let (cut4, cut6) = split(&addresses(&filter.cut));
    let (ssh4, ssh6) = split(filter.ssh_allow.as_deref().unwrap_or(&[]));
    let (block4, block6) = split(&addresses(&filter.remote_block));
    let lists = [&threats4, &threats6, &cut4, &cut6, &ssh4, &ssh6, &block4, &block6];
    let mut text = reset_lines();
    text.push_str(&format!("table {TABLE} {{\n"));
    for ((name, kind), elements) in SETS.iter().zip(lists) {
        text.push_str(&set_line(name, kind, elements));
    }
    let mut output = vec![];
    let mut input = vec![];
    if filter.remote_block.is_some() {
        input.push("ip saddr @remote_block4 counter drop".to_string());
        input.push("ip6 saddr @remote_block6 counter drop".to_string());
    }
    if filter.remote_lock {
        input.push(format!("iif != \"lo\" tcp dport {REMOTE_PORTS} counter reject with tcp reset"));
    }
    for (on, set) in [(filter.threats.is_some(), "threats"), (filter.cut.is_some(), "cut")] {
        if on {
            output.push(format!("ip daddr @{set}4 counter drop"));
            output.push(format!("ip6 daddr @{set}6 counter drop"));
            input.push(format!("ip saddr @{set}4 counter drop"));
            input.push(format!("ip6 saddr @{set}6 counter drop"));
        }
    }
    if filter.ssh_allow.is_some() {
        input.push("iif != \"lo\" tcp dport 22 ip saddr != @ssh_allow4 counter reject with tcp reset".to_string());
        input.push("iif != \"lo\" tcp dport 22 ip6 saddr != @ssh_allow6 counter reject with tcp reset".to_string());
    }
    for (chain, hook, rules) in [("output", "output", output), ("input", "input", input)] {
        text.push_str(&format!("\tchain {chain} {{\n\t\ttype filter hook {hook} priority filter - 10; policy accept;\n"));
        for rule in rules {
            text.push_str(&format!("\t\t{rule}\n"));
        }
        text.push_str("\t}\n");
    }
    text.push_str("}\n");
    text
}

/// Packets the table's rules counted (each rule's `counter`), from `nft -j list table` output.
pub fn parse_dropped(json: &str) -> u64 {
    rules_of(json).iter().map(|rule| {
        rule["expr"].as_array().into_iter().flatten().filter_map(|expr| expr["counter"]["packets"].as_u64()).sum::<u64>()
    }).sum()
}

/// The rules in `nft -j list table` output (none when it is not JSON).
fn rules_of(json: &str) -> Vec<Value> {
    let parsed: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    parsed["nftables"].as_array().into_iter().flatten().filter_map(|item| item.get("rule").cloned()).collect()
}

/// Whether `nft -j list table` output shows the table with at least one rule.
pub fn parse_enforcing(json: &str) -> bool {
    !rules_of(json).is_empty()
}

/// `ss -K` prints one line per socket it ended; `conntrack -D` says "N flow entries have been deleted".
pub fn parse_killed(ss: &str, conntrack: &str) -> u64 {
    let sockets = ss.lines().filter(|line| !line.trim().is_empty()).count() as u64;
    let flows: u64 = conntrack.lines().filter_map(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let at = words.iter().position(|word| *word == "flow")?;
        words.get(at.checked_sub(1)?)?.parse::<u64>().ok()
    }).sum();
    sockets + flows
}

fn first(commands: &[&'static str]) -> Option<&'static str> {
    commands.iter().copied().find(|path| Path::new(path).exists())
}

fn nft(args: &[&str], input: Option<&str>) -> Result<String, String> {
    let program = first(NFT_COMMANDS).ok_or(NOT_INSTALLED)?;
    let output = crate::command::output_with_input(Command::new(program).args(args), input.map(str::as_bytes), NFT_TIMEOUT)
        .map_err(|error| format!("{program}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!("nft {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim()))
    }
}

/// Loads one `nft -f` script (another of Blackbox's own tables: the agent guard's).
pub fn load(script: &str) -> Result<(), String> {
    nft(&["-f", "-"], Some(script)).map(|_| ())
}

/// Makes the table enforce *filter*; answers [`TOKEN`] while it is loaded, None once it is removed.
pub fn apply(filter: &Filter) -> Result<Option<String>, String> {
    if filter.is_off() {
        // Removing what was never loaded succeeds; without nft there is nothing of ours to remove.
        if first(NFT_COMMANDS).is_none() {
            return Ok(None);
        }
        return nft(&["-f", "-"], Some(&delete_script())).map(|_| None);
    }
    nft(&["-f", "-"], Some(&ruleset(filter)))?;
    match enabled() {
        Some(true) => Ok(Some(TOKEN.to_string())),
        Some(false) => Err("the firewall table was loaded but is not there: another program removed it".into()),
        None => Err("the firewall table's status could not be read".into()),
    }
}

fn listing() -> Option<String> {
    nft(&["-j", "list", "table", "inet", "blackbox_netd"], None).ok()
}

/// Whether the table is loaded with its rules (None when nftables cannot be asked).
pub fn enabled() -> Option<bool> {
    first(NFT_COMMANDS)?;
    Some(listing().is_some_and(|json| parse_enforcing(&json)))
}

/// Packets the table's rules dropped or refused so far.
pub fn dropped() -> u64 {
    listing().map(|json| parse_dropped(&json)).unwrap_or(0)
}

/// Ends every open socket and connection-tracking entry to or from *ip*; answers how many.
pub fn kill_states(ip: &IpAddr) -> Result<u64, String> {
    let address = ip.to_string();
    let ss = first(SS_COMMANDS).map(|program| {
        crate::command::output(Command::new(program).args(["-K", "-H", "dst", &address]), crate::command::TIMEOUT)
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    });
    let conntrack = first(CONNTRACK_COMMANDS).map(|program| {
        ["-s", "-d"].iter().map(|side| crate::command::output(Command::new(program).args(["-D", side, &address]), crate::command::TIMEOUT)
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned()).unwrap_or_default()).collect::<String>()
    });
    if ss.is_none() && conntrack.is_none() {
        return Err("neither ss nor conntrack is installed: open connections end on their own".into());
    }
    Ok(parse_killed(&ss.unwrap_or_default(), &conntrack.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_protection() -> Filter {
        Filter {
            threats: Some(vec!["203.0.113.7".parse().unwrap(), "2001:db8::7".parse().unwrap(), "203.0.113.7".parse().unwrap()]),
            cut: Some(vec!["198.51.100.9".parse().unwrap()]),
            ssh_allow: Some(vec!["192.168.1.0/24".into(), "192.168.1.5".into(), "fd00::/8".into()]),
            remote_lock: true,
            remote_block: Some(vec![]),
        }
    }

    #[test]
    fn only_the_protections_that_are_on_have_rules() {
        let threats = ruleset(&Filter { threats: Some(vec![]), ..Default::default() });
        assert!(threats.contains("ip daddr @threats4 counter drop") && threats.contains("ip6 saddr @threats6 counter drop"));
        assert!(!threats.contains("@cut4 counter") && !threats.contains("dport 22"));
        assert!(threats.starts_with("table inet blackbox_netd\ndelete table inet blackbox_netd\ntable inet blackbox_netd {\n"));
        assert_eq!(threats.matches("\tset ").count(), 8, "every set always exists");
        let rules = threats.lines().filter(|line| line.starts_with("\t\t") && !line.contains("type filter hook"));
        assert!(rules.clone().count() == 4 && rules.into_iter().all(|rule| !rule.contains("accept")), "our rules never accept");
    }

    #[test]
    fn the_lock_and_blocks_come_before_ssh_lockdowns_allow_list_and_lists_split_by_family() {
        let text = ruleset(&every_protection());
        let blocked = text.find("ip saddr @remote_block4 counter drop").unwrap();
        let lock = text.find("iif != \"lo\" tcp dport { 22, 3389").unwrap();
        let ssh = text.find("ip saddr != @ssh_allow4").unwrap();
        assert!(blocked < lock && lock < ssh, "the lock wins over the SSH allow list");
        assert!(text.contains("set threats4 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.7 } }"), "once");
        assert!(text.contains("set threats6 { type ipv6_addr; flags interval; auto-merge; elements = { 2001:db8::7 } }"));
        assert!(text.contains("elements = { 192.168.1.0/24, 192.168.1.5 }") && text.contains("elements = { fd00::/8 }"));
        assert!(text.contains("ip6 saddr != @ssh_allow6"), "IPv6 SSH is locked down too");
        assert_eq!(delete_script(), "table inet blackbox_netd\ndelete table inet blackbox_netd\n");
    }

    #[test]
    fn counters_listings_and_kills_parse() {
        let listing = r#"{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"table": {"family": "inet", "name": "blackbox_netd"}},
            {"rule": {"chain": "output", "expr": [{"match": {}}, {"counter": {"packets": 4, "bytes": 240}}, {"drop": null}]}},
            {"rule": {"chain": "input", "expr": [{"counter": {"packets": 3, "bytes": 180}}, {"drop": null}]}}]}"#;
        assert_eq!(parse_dropped(listing), 7);
        assert!(parse_enforcing(listing));
        assert!(!parse_enforcing(r#"{"nftables": [{"table": {"name": "blackbox_netd"}}]}"#) && !parse_enforcing("Error"));
        let ss = "tcp ESTAB 0 0 10.0.0.5:41822 198.51.100.9:443\ntcp ESTAB 0 0 10.0.0.5:41830 198.51.100.9:443\n";
        let conntrack = "conntrack v1.4.8 (conntrack-tools): 3 flow entries have been deleted.\nconntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n";
        assert_eq!(parse_killed(ss, conntrack), 5);
        assert_eq!(parse_killed("", ""), 0);
    }

    /// Runs *script* (sh) inside a new user + network namespace (`unshare -rn`): root there, with
    /// no reach outside. None when this machine has no unprivileged namespaces (the test then
    /// skips, unless BLACKBOX_REQUIRE_NETNS=1 says it must run — CI's helper job).
    fn in_private_netns(script: &str, input: &str) -> Option<std::process::Output> {
        let usable = Command::new("unshare").args(["-rn", "true"]).output().map(|o| o.status.success()).unwrap_or(false)
            && first(NFT_COMMANDS).is_some();
        if !usable {
            assert!(std::env::var("BLACKBOX_REQUIRE_NETNS").as_deref() != Ok("1"), "no unprivileged network namespace or nft here");
            eprintln!("skipped: no unprivileged network namespace or nft on this machine");
            return None;
        }
        crate::command::output_with_input(Command::new("unshare").args(["-rn", "sh", "-c", script]), Some(input.as_bytes()), NFT_TIMEOUT).ok()
    }

    #[test]
    fn the_whole_table_loads_replaces_and_is_removed_in_a_private_network_namespace() {
        let nft = first(NFT_COMMANDS).unwrap_or("nft");
        let script = format!("{nft} -f - && {nft} -j list table inet blackbox_netd");
        let Some(loaded) = in_private_netns(&script, &ruleset(&every_protection())) else { return };
        assert!(loaded.status.success(), "nft refused the ruleset: {}", String::from_utf8_lossy(&loaded.stderr));
        assert!(parse_enforcing(&String::from_utf8_lossy(&loaded.stdout)));
        // Applying twice (the reset lines), then the all-off script, leaves no table.
        let twice = format!("{}{}", ruleset(&every_protection()), delete_script());
        let script = format!("{nft} -f - && ! {nft} list table inet blackbox_netd 2>/dev/null");
        let removed = in_private_netns(&script, &twice).expect("namespaces were usable a moment ago");
        assert!(removed.status.success(), "{}", String::from_utf8_lossy(&removed.stderr));
    }

    #[test]
    fn a_threat_address_is_dropped_and_counted_in_a_private_network_namespace() {
        let nft = first(NFT_COMMANDS).unwrap_or("nft");
        let filter = Filter { threats: Some(vec!["127.0.0.2".parse().unwrap()]), ..Default::default() };
        // bash's /dev/tcp sends a SYN through the output chain; the drop leaves it to time out.
        let script = format!("ip link set lo up; {nft} -f - && (timeout 2 bash -c 'echo > /dev/tcp/127.0.0.2/9' 2>/dev/null; \
                              {nft} -j list table inet blackbox_netd)");
        let Some(done) = in_private_netns(&script, &ruleset(&filter)) else { return };
        let listing = String::from_utf8_lossy(&done.stdout);
        assert!(parse_dropped(&listing) >= 1, "the SYN to the threat address was dropped and counted: {listing}");
    }
}
