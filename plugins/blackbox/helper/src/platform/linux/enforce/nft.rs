//! Network Shield's firewall on Linux: one nftables table of Blackbox's own, `inet blackbox_netd`,
//! for everything it enforces (design "Linux deep layers" §2.1). It holds eight sets (IPv4 and
//! IPv6 of each list; `flags interval` with `auto-merge`, so a network and an address inside it
//! may both be listed) and only the rules of the protections that are on:
//!
//! - **Threat Firewall** — `threats4/6`: traffic to the verified graph's addresses REJECTED, from
//!   them dropped;
//! - **Cut malicious connections** — `cut4/6`: the same both ways, and their open sockets and
//!   connection-tracking entries ended ([`kill_states`]);
//! - **SSH lockdown** — `ssh_allow4/6`: SSH in (TCP 22) from anywhere but this machine and the
//!   allowed sources gets a reset;
//! - **Lock remote access** — the remote-access ports ([`REMOTE_PORTS`]) refused to everyone but
//!   this machine itself, ahead of SSH lockdown's allow list (the lock always wins);
//! - **Blocked addresses** — `remote_block4/6`: refused inbound entirely.
//!
//! Each apply replaces the whole table in ONE `nft -f -` transaction (create, delete, create:
//! nothing is ever half-loaded), and an all-off filter deletes it.
//!
//! **Reject out, drop in** (KI-680, Linux round L3: a listed address's SYN was dropped, so curl and
//! Python hung to their own timeouts, 5–6 s, and the agent read a network fault). A packet THIS
//! machine sends to a listed address is refused at once: TCP with a reset ([`REFUSE_TCP`], the
//! program reads "Connection refused"), anything else with an ICMP "administratively prohibited"
//! ([`REFUSE_OTHER`]). WHY a reset for TCP, not the ICMP alone: measured with real nft on kernel 6.8
//! (Ubuntu 22.04, a private network namespace), an ICMP reject failed a connect only after the first
//! SYN retransmit (~1 s), a reset in 2 ms. A packet a listed address sends here is dropped silently — answering it would
//! tell the threat that this machine is there, and a reject could be reflected at someone else.
//! The inbound drop skips loopback ([`FROM_OUTSIDE`]): the reject's ICMP answer carries the listed
//! address as its SOURCE and reaches this machine through `lo`, so an unqualified drop swallowed
//! Blackbox's own refusal and the connect hung anyway (found by the netns test on Ubuntu 22.04,
//! kernel 6.8). A packet from a listed address on the network never arrives on `lo`.
//!
//! **Counting** ([`dropped`]): every rule counts into a NAMED counter of the table ([`COUNTERS`]),
//! read with `nft -j list counters table …` — a small answer, unlike the whole table with its
//! tens of thousands of set elements. Replacing the table on each apply would reset them (KI-680:
//! the report said 0 while nft had counted), so what they held is carried over first.
//!
//! Coexistence: the chains hook
//! at priority `filter - 10` and only ever drop or reject — never accept — so another firewall's
//! (ufw, firewalld, Docker's) refusals still hold. The table is Blackbox's alone: no system file
//! is edited, and no other table is touched.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// What a refused outgoing packet gets (see the module doc): TCP a reset, the rest an ICMP refusal.
pub const REFUSE_TCP: &str = "meta l4proto tcp";
pub const REFUSE_TCP_WITH: &str = "reject with tcp reset";
pub const REFUSE_OTHER: &str = "reject with icmpx admin-prohibited";
/// What the inbound threat / cut drops match first: not loopback (see the module doc).
pub const FROM_OUTSIDE: &str = "iif != \"lo\"";
/// The table's named counters, one per kind of rule.
pub const COUNTERS: [&str; 7] = ["threats_out", "threats_in", "cut_out", "cut_in", "remote_block", "remote_lock", "ssh_lockdown"];
/// What the counters held before the table was last replaced (reset by a replacement).
static CARRIED: AtomicU64 = AtomicU64::new(0);

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

/// The rules of the two chains for *filter*: `(output, input)`.
fn rules(filter: &Filter) -> (Vec<String>, Vec<String>) {
    let mut output = vec![];
    let mut input = vec![];
    if filter.remote_block.is_some() {
        input.push("ip saddr @remote_block4 counter name remote_block drop".to_string());
        input.push("ip6 saddr @remote_block6 counter name remote_block drop".to_string());
    }
    if filter.remote_lock {
        input.push(format!("iif != \"lo\" tcp dport {REMOTE_PORTS} counter name remote_lock reject with tcp reset"));
    }
    for (on, set) in [(filter.threats.is_some(), "threats"), (filter.cut.is_some(), "cut")] {
        if on {
            for (family, version) in [("ip", 4), ("ip6", 6)] {
                output.push(format!("{family} daddr @{set}{version} {REFUSE_TCP} counter name {set}_out {REFUSE_TCP_WITH}"));
                output.push(format!("{family} daddr @{set}{version} counter name {set}_out {REFUSE_OTHER}"));
            }
            input.push(format!("{FROM_OUTSIDE} ip saddr @{set}4 counter name {set}_in drop"));
            input.push(format!("{FROM_OUTSIDE} ip6 saddr @{set}6 counter name {set}_in drop"));
        }
    }
    if filter.ssh_allow.is_some() {
        input.push("iif != \"lo\" tcp dport 22 ip saddr != @ssh_allow4 counter name ssh_lockdown reject with tcp reset".to_string());
        input.push("iif != \"lo\" tcp dport 22 ip6 saddr != @ssh_allow6 counter name ssh_lockdown reject with tcp reset".to_string());
    }
    (output, input)
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
    for name in COUNTERS {
        text.push_str(&format!("\tcounter {name} {{ packets 0 bytes 0 }}\n"));
    }
    let (output, input) = rules(filter);
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

/// Packets the table's named counters hold, from `nft -j list counters table …` output (only
/// Blackbox's table's counters count).
pub fn parse_dropped(json: &str) -> u64 {
    let parsed: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    parsed["nftables"].as_array().into_iter().flatten()
        .filter_map(|item| item.get("counter"))
        .filter(|counter| counter["table"] == "blackbox_netd" && COUNTERS.contains(&counter["name"].as_str().unwrap_or("")))
        .filter_map(|counter| counter["packets"].as_u64())
        .sum()
}

/// The rules in `nft -j list table` output (none when it is not JSON).
fn rules_of(json: &str) -> Vec<Value> {
    let parsed: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    parsed["nftables"].as_array().into_iter().flatten().filter_map(|item| item.get("rule").cloned()).collect()
}

/// Whether `nft -j list chain …` output (or the whole table's) holds at least one rule.
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
        carry_counts();
        return nft(&["-f", "-"], Some(&delete_script())).map(|_| None);
    }
    carry_counts();
    nft(&["-f", "-"], Some(&ruleset(filter)))?;
    match enabled() {
        Some(true) => Ok(Some(TOKEN.to_string())),
        Some(false) => Err("the firewall table was loaded but is not there: another program removed it".into()),
        None => Err("the firewall table's status could not be read".into()),
    }
}

/// The table's counters now (0 when it is not loaded).
fn counted_now() -> u64 {
    nft(&["-j", "list", "counters", "table", "inet", "blackbox_netd"], None).map(|json| parse_dropped(&json)).unwrap_or(0)
}

/// Keeps what the counters hold before a replacement resets them.
fn carry_counts() {
    CARRIED.fetch_add(counted_now(), Ordering::Relaxed);
}

/// Whether the table is loaded with its rules (None when nftables cannot be asked). Its two chains
/// are listed, never the whole table: the sets' elements are not read every few seconds.
pub fn enabled() -> Option<bool> {
    first(NFT_COMMANDS)?;
    Some(["output", "input"].iter().any(|chain| {
        nft(&["-j", "list", "chain", "inet", "blackbox_netd", chain], None).is_ok_and(|json| parse_enforcing(&json))
    }))
}

/// Whether each chain listing (`nft -j list chain …` output, None when it could not be read — the
/// table or chain is gone) holds exactly the number of rules *filter* loads there.
pub fn chains_intact(filter: &Filter, output: Option<&str>, input: Option<&str>) -> bool {
    let (want_out, want_in) = rules(filter);
    [(output, want_out.len()), (input, want_in.len())].iter()
        .all(|(json, want)| json.is_some_and(|json| rules_of(json).len() == *want))
}

/// Whether the table still holds the rules *filter* loaded (None when nftables cannot be asked).
/// Cheap enough for every plan cycle: the two chains are listed, never the sets' elements (KI-688,
/// Linux round L4: after `nft flush table inet blackbox_netd` the rules came back only when the
/// plan next CHANGED — 90–150 s once the threat graph was complete — because nothing looked).
/// A flushed, deleted or edited chain (a rule removed, or one slipped in) reads as not intact.
pub fn intact(filter: &Filter) -> Option<bool> {
    first(NFT_COMMANDS)?;
    let list = |chain: &str| nft(&["-j", "list", "chain", "inet", "blackbox_netd", chain], None).ok();
    Some(chains_intact(filter, list("output").as_deref(), list("input").as_deref()))
}

/// Packets the table's rules dropped or refused since the helper started (across replacements).
pub fn dropped() -> u64 {
    CARRIED.load(Ordering::Relaxed) + counted_now()
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
        assert!(threats.contains("ip daddr @threats4 meta l4proto tcp counter name threats_out reject with tcp reset")
                && threats.contains("ip daddr @threats4 counter name threats_out reject with icmpx admin-prohibited")
                && threats.contains("iif != \"lo\" ip6 saddr @threats6 counter name threats_in drop"));
        assert!(!threats.contains("@cut4 counter") && !threats.contains("dport 22"));
        assert_eq!(threats.matches("\tcounter ").count(), COUNTERS.len(), "every counter always exists");
        assert!(threats.starts_with("table inet blackbox_netd\ndelete table inet blackbox_netd\ntable inet blackbox_netd {\n"));
        assert_eq!(threats.matches("\tset ").count(), 8, "every set always exists");
        let rules = threats.lines().filter(|line| line.starts_with("\t\t") && !line.contains("type filter hook"));
        assert!(rules.clone().count() == 6 && rules.into_iter().all(|rule| !rule.contains("accept")), "our rules never accept");
    }

    #[test]
    fn the_lock_and_blocks_come_before_ssh_lockdowns_allow_list_and_lists_split_by_family() {
        let text = ruleset(&every_protection());
        let blocked = text.find("ip saddr @remote_block4 counter name remote_block drop").unwrap();
        let lock = text.find("iif != \"lo\" tcp dport { 22, 3389").unwrap();
        let ssh = text.find("ip saddr != @ssh_allow4").unwrap();
        assert!(blocked < lock && lock < ssh, "the lock wins over the SSH allow list");
        assert!(text.contains("set threats4 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.7 } }"), "once");
        assert!(text.contains("set threats6 { type ipv6_addr; flags interval; auto-merge; elements = { 2001:db8::7 } }"));
        assert!(text.contains("elements = { 192.168.1.0/24, 192.168.1.5 }") && text.contains("elements = { fd00::/8 }"));
        assert!(text.contains("ip6 saddr != @ssh_allow6"), "IPv6 SSH is locked down too");
        assert_eq!(delete_script(), "table inet blackbox_netd\ndelete table inet blackbox_netd\n");
    }

    /// KI-680 (Linux round L3): a packet this machine sends to a listed address is refused at once,
    /// never dropped (curl and Python hung 5–6 s); one a listed address sends here is dropped.
    #[test]
    fn a_listed_address_is_refused_out_at_once_and_dropped_in() {
        let text = ruleset(&every_protection());
        let output: Vec<&str> = text.lines().skip_while(|l| !l.contains("chain output")).take_while(|l| !l.contains("chain input")).collect();
        let input: Vec<&str> = text.lines().skip_while(|l| !l.contains("chain input")).collect();
        let listed_out: Vec<&&str> = output.iter().filter(|l| l.contains("daddr @")).collect();
        assert_eq!(listed_out.len(), 8, "threats and cut, IPv4 and IPv6, TCP and the rest: {output:?}");
        for pair in listed_out.chunks(2) {
            assert!(pair[0].ends_with(&format!("{REFUSE_TCP} counter name {} {REFUSE_TCP_WITH}", pair[0].split("counter name ").nth(1).unwrap().split(' ').next().unwrap())),
                    "TCP first, with a reset: {pair:?}");
            assert!(pair[1].ends_with(REFUSE_OTHER), "then everything else: {pair:?}");
        }
        assert!(!output.iter().any(|l| l.ends_with(" drop")), "nothing this machine sends is dropped: {output:?}");
        let listed_in: Vec<&&str> = input.iter().filter(|l| l.contains("saddr @threats") || l.contains("saddr @cut")).collect();
        assert!(listed_in.len() == 4 && listed_in.iter().all(|l| l.ends_with(" drop") && l.starts_with(&format!("\t\t{FROM_OUTSIDE} "))),
                "dropped in, but never Blackbox's own reject coming back through lo: {input:?}");
    }

    #[test]
    fn counters_listings_and_kills_parse() {
        // `nft -j list counters table inet blackbox_netd` (libnftables-json(5): a counter object).
        let counters = r#"{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
            {"counter": {"family": "inet", "name": "threats_out", "table": "blackbox_netd", "handle": 9, "packets": 8, "bytes": 480}},
            {"counter": {"family": "inet", "name": "threats_in", "table": "blackbox_netd", "handle": 10, "packets": 3, "bytes": 180}},
            {"counter": {"family": "inet", "name": "threats_out", "table": "someone_else", "handle": 2, "packets": 99, "bytes": 1}}]}"#;
        assert_eq!(parse_dropped(counters), 11, "only Blackbox's table's counters");
        assert_eq!(parse_dropped("Error: No such file or directory"), 0);
        let listing = r#"{"nftables": [{"metainfo": {"version": "1.0.9"}},
            {"rule": {"chain": "output", "expr": [{"match": {}}, {"counter": "threats_out"}, {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}]}}]}"#;
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
    fn a_threat_address_is_refused_at_once_and_counted_in_a_private_network_namespace() {
        let nft = first(NFT_COMMANDS).unwrap_or("nft");
        let filter = Filter { threats: Some(vec!["127.0.0.2".parse().unwrap()]), ..Default::default() };
        // bash's /dev/tcp sends a SYN through the output chain: refused, it fails at once (a drop
        // would wait out the 5 s timeout and print nothing). Then the counters, as `dropped` reads them.
        let script = format!("ip link set lo up; {nft} -f - && (start=$(date +%s%N); timeout 5 bash -c 'echo > /dev/tcp/127.0.0.2/9'; \
                              echo \"RC=$? MS=$(( ($(date +%s%N) - start) / 1000000 ))\" >&2; \
                              {nft} -j list counters table inet blackbox_netd)");
        let Some(done) = in_private_netns(&script, &ruleset(&filter)) else { return };
        let (out, err) = (String::from_utf8_lossy(&done.stdout), String::from_utf8_lossy(&done.stderr));
        let ms: u64 = err.split("MS=").nth(1).and_then(|rest| rest.trim().split_whitespace().next()?.parse().ok()).unwrap_or(u64::MAX);
        assert!(err.contains("RC=1") && ms < 1000, "the connect failed at once, not by timeout (124): {err}");
        assert!(parse_dropped(&out) >= 1, "the refused SYN was counted: {out}");
    }

    #[test]
    fn a_chain_listing_is_intact_only_with_exactly_the_rules_the_filter_loads() {
        let filter = every_protection();
        let (out, inp) = rules(&filter);
        let listing = |count: usize| format!("{{\"nftables\": [{}]}}", vec!["{\"rule\": {}}"; count].join(","));
        assert!(chains_intact(&filter, Some(&listing(out.len())), Some(&listing(inp.len()))));
        assert!(!chains_intact(&filter, Some(&listing(0)), Some(&listing(0))), "a flushed table");
        assert!(!chains_intact(&filter, None, Some(&listing(inp.len()))), "a deleted chain or table");
        assert!(!chains_intact(&filter, Some(&listing(out.len() + 1)), Some(&listing(inp.len()))), "a rule slipped in");
        assert!(!chains_intact(&filter, Some(&listing(out.len() - 1)), Some(&listing(inp.len()))), "a rule removed");
    }

    /// KI-688, real nft: a whole threat set the size of the complete graph's (28,216 addresses in
    /// Linux round L4) is flushed by "root"; the chain listings say so, and ONE `nft -f` of the
    /// filter puts every rule back — well inside the 30 s promise (measured, printed).
    #[test]
    fn a_flushed_table_with_a_complete_graphs_set_reads_as_not_intact_and_one_load_restores_it() {
        let nft = first(NFT_COMMANDS).unwrap_or("nft");
        let threats: Vec<IpAddr> = (0..28_216u32).map(|n| IpAddr::from([10, (n >> 16) as u8, (n >> 8) as u8, n as u8])).collect();
        let filter = Filter { threats: Some(threats), cut: Some(vec![]), ..Default::default() };
        let list = format!("echo ==; {nft} -j list chain inet blackbox_netd output; echo ==; {nft} -j list chain inet blackbox_netd input");
        let script = format!("f=$(mktemp); cat > \"$f\"; {nft} -f \"$f\" && {nft} flush table inet blackbox_netd && {list}; \
                              start=$(date +%s%N); {nft} -f \"$f\"; echo \"MS=$(( ($(date +%s%N) - start) / 1000000 ))\" >&2; {list}; rm -f \"$f\"");
        let Some(done) = in_private_netns(&script, &ruleset(&filter)) else { return };
        let (out, err) = (String::from_utf8_lossy(&done.stdout), String::from_utf8_lossy(&done.stderr));
        let parts: Vec<&str> = out.split("==\n").collect();
        assert_eq!(parts.len(), 5, "four listings: {out:.400} {err}");
        assert!(!chains_intact(&filter, Some(parts[1]), Some(parts[2])), "a flushed table is not intact");
        assert!(chains_intact(&filter, Some(parts[3]), Some(parts[4])), "one load restores every rule: {err}");
        let ms: u64 = err.split("MS=").nth(1).and_then(|rest| rest.trim().split_whitespace().next()?.parse().ok()).unwrap_or(u64::MAX);
        eprintln!("reloading the table with 28,216 addresses took {ms} ms");
        assert!(ms < 10_000, "{err}");
    }
}
