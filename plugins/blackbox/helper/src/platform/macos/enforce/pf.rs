//! Network Shield's packet filter: one pf anchor of Blackbox's own for everything it enforces.
//!
//! The anchor is `com.apple/250.BlackboxFirewall` (the stock `/etc/pf.conf` evaluates every
//! `com.apple/*` anchor, so no system file is edited). It holds three tables and only the rules
//! of the protections that are on:
//!
//! - **Threat Firewall** — `<bb_threats>`: refuse traffic to (at once, `block return`) and drop
//!   traffic from the verified graph's addresses;
//! - **Cut malicious connections** — `<bb_cut>`: the addresses the plugin told the helper to cut,
//!   dropped both ways, and their open states killed (`pfctl -k`), so a connection already open
//!   ends instead of living on in pf's state table;
//! - **SSH lockdown** — `<bb_ssh_allow>`: SSH in (TCP port 22) passes from this machine and the
//!   allowed sources only; everything else gets a reset.
//! - **Lock remote access** — no one gets in on the remote-access ports ([`REMOTE_PORTS`]: SSH,
//!   Screen Sharing, Remote Management, file sharing, Remote Apple Events) except from this Mac
//!   itself; ahead of SSH lockdown's allow list, so the lock always wins.
//! - **Blocked addresses** — `<bb_remote_block>`: addresses the user blocked, or that kept failing
//!   to log in (brute-force auto-block), refused inbound entirely.
//!
//! pf is enabled with a reference token and released with that same token when nothing is on,
//! so another program's use of pf is never switched off. Nothing here decides what is malicious:
//! the lists come from the plan.

use std::net::IpAddr;
use std::process::Command;

use crate::platform::Filter;

const PFCTL: &str = "/sbin/pfctl";
pub const ANCHOR: &str = "com.apple/250.BlackboxFirewall";
const THREATS: &str = "bb_threats";
const CUT: &str = "bb_cut";
const SSH_ALLOW: &str = "bb_ssh_allow";
const REMOTE_BLOCK: &str = "bb_remote_block";
/// The ports Lock remote access closes: SSH, Screen Sharing, Remote Management, SMB, Remote Apple Events.
pub const REMOTE_PORTS: &str = "{ 22 5900 3283 445 3031 }";

/// The anchor's rules for *filter*: the tables always, the rules of each protection that is on.
pub fn rules(filter: &Filter) -> String {
    let mut text = format!("table <{THREATS}> persist\ntable <{CUT}> persist\ntable <{SSH_ALLOW}> persist\ntable <{REMOTE_BLOCK}> persist\n");
    if filter.remote_block.is_some() {
        text.push_str(&format!("block drop in quick from <{REMOTE_BLOCK}>\n"));
    }
    if filter.remote_lock {
        text.push_str(&format!(
            "pass in quick on lo0 proto tcp to any port {REMOTE_PORTS}\nblock return in quick proto tcp to any port {REMOTE_PORTS}\n"
        ));
    }
    // Outbound is refused with `return` (TCP RST / ICMP unreachable: this Mac's connect fails at
    // once — a dropped SYN hangs it 5–75 s, LES-156); inbound from a listed address is dropped.
    if filter.threats.is_some() {
        text.push_str(&format!("block return out quick to <{THREATS}>\nblock drop in quick from <{THREATS}>\n"));
    }
    if filter.cut.is_some() {
        text.push_str(&format!("block return out quick to <{CUT}>\nblock drop in quick from <{CUT}>\n"));
    }
    if filter.ssh_allow.is_some() {
        text.push_str(&format!(
            "pass in quick on lo0 proto tcp to any port 22\npass in quick proto tcp from <{SSH_ALLOW}> to any port 22\n\
             block return in quick proto tcp to any port 22\n"
        ));
    }
    text
}

/// pfctl loading a large table can take a moment; still bounded.
const PFCTL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn run(args: &[&str], input: Option<&str>) -> Result<String, String> {
    let output = crate::command::output_with_input(Command::new(PFCTL).args(args), input.map(str::as_bytes), PFCTL_TIMEOUT)
        .map_err(|error| format!("{PFCTL}: {error}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    if output.status.success() { Ok(text) } else { Err(format!("pfctl {}: {}", args.join(" "), text.trim())) }
}

fn replace_table(table: &str, entries: &[String]) -> Result<(), String> {
    let list: String = entries.iter().map(|entry| format!("{entry}\n")).collect();
    run(&["-a", ANCHOR, "-t", table, "-T", "replace", "-f", "-"], Some(&list)).map(|_| ())
}

/// Makes the anchor enforce *filter*. Answers pf's reference token to keep: None once nothing
/// is on (the anchor emptied and the token released), else the token held or newly taken.
pub fn apply(filter: &Filter, token: Option<String>) -> Result<Option<String>, String> {
    if filter.is_off() {
        let mut errors = vec![];
        if let Err(error) = run(&["-a", ANCHOR, "-F", "all"], None) {
            errors.push(error);
        }
        if let Some(token) = token.as_deref() {
            if let Err(error) = run(&["-X", token], None) {
                errors.push(error);
            }
        }
        return if errors.is_empty() { Ok(None) } else { Err(errors.join("; ")) };
    }
    run(&["-a", ANCHOR, "-f", "-"], Some(&rules(filter)))?;
    let ips = |list: &Option<Vec<IpAddr>>| list.iter().flatten().map(IpAddr::to_string).collect::<Vec<_>>();
    replace_table(THREATS, &ips(&filter.threats))?;
    replace_table(CUT, &ips(&filter.cut))?;
    replace_table(SSH_ALLOW, filter.ssh_allow.as_deref().unwrap_or(&[]))?;
    replace_table(REMOTE_BLOCK, &ips(&filter.remote_block))?;
    // WHY verify and not trust the token: after a reboot (or `pfctl -d` by another root process) a
    // saved token no longer means pf is on — the anchor loads but nothing is enforced while the app
    // says "active" (security finding). pf must be seen Enabled after every apply.
    let mut token = token;
    if needs_enable(token.as_deref(), enabled()) {
        let output = run(&["-E"], None)?;
        token = Some(parse_token(&output).ok_or_else(|| format!("pfctl -E gave no token: {}", output.trim()))?);
    }
    match enabled() {
        Some(true) => Ok(token),
        Some(false) => Err("pf did not stay enabled: the firewall rules are loaded but not enforced".into()),
        None => Err("pf's status could not be read".into()),
    }
}

/// Whether pf still enforces what *filter* loaded (None when pf can not be asked): pf enabled, the
/// anchor holding as many rules as [`rules`] gives, and each table that should hold addresses still
/// holding one of them (its first, asked with `pfctl -T test`: one lookup, the table never listed).
/// Asked every plan cycle (LES-141: three or four pfctl calls, never a 28k-address listing).
/// WHY (KI-695, macOS round R8): after a root `pfctl -a … -F all`, a table flush or `pfctl -d` the
/// firewall never came back (17 min) and the overview still said "active" — nothing looked.
pub fn intact(filter: &Filter) -> Option<bool> {
    if filter.is_off() {
        return Some(true);
    }
    if !enabled()? {
        return Some(false);
    }
    let listed = run(&["-a", ANCHOR, "-s", "rules"], None).ok()?;
    if rule_count(&listed) != rule_count(&rules(filter)) {
        return Some(false);
    }
    Some(canaries(filter).iter().all(|(table, entry)| run(&["-a", ANCHOR, "-t", table, "-T", "test", entry], None).is_ok()))
}

/// The rules (not the table lines) in a ruleset text: `pfctl -s rules` output or [`rules`]. A rule
/// written with a list (`port { 22 5900 … }`) counts once per item: pf loads, and lists, one rule each.
pub fn rule_count(text: &str) -> usize {
    text.lines().map(str::trim_start).filter(|line| line.starts_with("block") || line.starts_with("pass"))
        .map(|line| line.split('{').skip(1).map(|list| list.split('}').next().unwrap_or("").split([' ', ',']).filter(|item| !item.is_empty()).count().max(1)).product::<usize>())
        .sum()
}

/// One entry each table of *filter* should hold, `(table, entry)`: its first, for a table not empty.
pub fn canaries(filter: &Filter) -> Vec<(&'static str, String)> {
    let first = |list: &Option<Vec<IpAddr>>| list.as_ref().and_then(|ips| ips.first()).map(IpAddr::to_string);
    [(THREATS, first(&filter.threats)), (CUT, first(&filter.cut)),
     (SSH_ALLOW, filter.ssh_allow.as_ref().and_then(|list| list.first().cloned())), (REMOTE_BLOCK, first(&filter.remote_block))]
        .into_iter().filter_map(|(table, entry)| entry.map(|entry| (table, entry))).collect()
}

/// Whether pf must be (re-)enabled: no token of ours, or pf seen disabled despite one.
pub fn needs_enable(token: Option<&str>, status: Option<bool>) -> bool {
    token.is_none() || status == Some(false)
}

/// pf's status now (`pfctl -s info`): Some(true) Enabled, Some(false) Disabled, None unreadable.
pub fn enabled() -> Option<bool> {
    crate::platform::macos::pf_status::read()
}

/// When this Mac last started (kern.boottime, unix seconds; 0 if unreadable). A pf token saved
/// under another boot is stale.
pub fn boot_time() -> u64 {
    let mut boot = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut size = std::mem::size_of::<libc::timeval>();
    let name = std::ffi::CString::new("kern.boottime").expect("a static name");
    // SAFETY: sysctlbyname writes at most `size` bytes into `boot`, a valid timeval.
    let rc = unsafe { libc::sysctlbyname(name.as_ptr(), (&mut boot as *mut libc::timeval).cast(), &mut size, std::ptr::null_mut(), 0) };
    if rc == 0 { boot.tv_sec.max(0) as u64 } else { 0 }
}

/// Ends every pf state to or from *ip* (both directions); answers how many were killed.
pub fn kill_states(ip: &IpAddr) -> Result<u64, String> {
    let any = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
    let address = ip.to_string();
    let from = run(&["-k", &address], None)?;
    let to = run(&["-k", any, "-k", &address], None)?;
    Ok(parse_killed(&from) + parse_killed(&to))
}

/// Packets the anchor's rules have dropped so far.
pub fn dropped() -> u64 {
    run(&["-a", ANCHOR, "-v", "-s", "rules"], None).map(|text| parse_dropped(&text)).unwrap_or(0)
}

/// `Token : 1234` from `pfctl -E`.
pub fn parse_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| line.trim().strip_prefix("Token :").map(|token| token.trim().to_string())).filter(|t| !t.is_empty())
}

/// Sums `Packets: N` over the block rules in `pfctl -v -s rules` output (pass rules are not drops).
pub fn parse_dropped(text: &str) -> u64 {
    let mut total = 0;
    let mut blocking = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("block") || line.starts_with("pass") {
            blocking = line.starts_with("block");
        } else if blocking {
            if let Some(count) = line.split("Packets:").nth(1).and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok()) {
                total += count;
            }
        }
    }
    total
}

/// `killed 2 states from 1 sources and 0 destinations` → 2.
pub fn parse_killed(text: &str) -> u64 {
    text.split_whitespace().skip_while(|word| *word != "killed").nth(1).and_then(|n| n.parse().ok()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_token_does_not_count_when_pf_is_seen_disabled() {
        assert!(needs_enable(None, Some(true)), "no token of ours: enable");
        assert!(needs_enable(Some("123"), Some(false)), "a stale token (reboot, pfctl -d): enable again");
        assert!(!needs_enable(Some("123"), Some(true)));
                assert!(boot_time() > 1_600_000_000, "this Mac's boot time reads");
    }

    #[test]
    fn only_the_protections_that_are_on_have_rules() {
        let none = rules(&Filter { threats: Some(vec![]), ..Default::default() });
        assert!(none.contains("block drop in quick from <bb_threats>") && !none.contains("bb_cut>\n") && !none.contains("port 22"));
        let all = rules(&Filter { threats: None, cut: Some(vec![]), ssh_allow: Some(vec![]), ..Default::default() });
        assert!(all.contains("block return out quick to <bb_cut>") && !all.contains("to <bb_threats>"));
        let lo = all.find("on lo0").unwrap();
        let allow = all.find("from <bb_ssh_allow>").unwrap();
        let refuse = all.find("block return in quick proto tcp to any port 22").unwrap();
        assert!(lo < allow && allow < refuse, "the passes come before the refusal");
        assert!(Filter::default().is_off());
    }

    /// LES-156 on macOS (review finding 2026-11-26): outbound to a listed address is refused with
    /// `return` (pf answers a TCP RST / an ICMP unreachable, so the connect fails at once) — a
    /// `drop` let it hang 5–75 s; inbound from it is still dropped silently.
    #[test]
    fn outbound_to_a_listed_address_is_refused_at_once_and_inbound_is_dropped() {
        let text = rules(&Filter { threats: Some(vec![]), cut: Some(vec![]), ..Default::default() });
        for table in ["bb_threats", "bb_cut"] {
            assert!(text.contains(&format!("block return out quick to <{table}>\n")), "{text}");
            assert!(text.contains(&format!("block drop in quick from <{table}>\n")), "{text}");
        }
        assert!(!text.contains("block drop out"), "{text}");
    }

    #[test]
    fn the_remote_lock_and_blocks_come_before_ssh_lockdowns_allow_list() {
        let text = rules(&Filter { ssh_allow: Some(vec![]), remote_lock: true, remote_block: Some(vec![]), ..Default::default() });
        let blocked = text.find("block drop in quick from <bb_remote_block>").unwrap();
        let lock = text.find("block return in quick proto tcp to any port { 22 5900 3283 445 3031 }").unwrap();
        let allow = text.find("from <bb_ssh_allow>").unwrap();
        assert!(blocked < lock && lock < allow, "the lock wins over the SSH allow list");
        assert!(text.contains("pass in quick on lo0 proto tcp to any port { 22 5900 3283 445 3031 }"), "this Mac itself still reaches them");
        assert!(!Filter { remote_lock: true, ..Default::default() }.is_off());
        assert!(!rules(&Filter::default()).contains("port { 22"), "off: no lock rules");
    }

    #[test]
    fn the_intact_check_counts_rules_and_asks_one_entry_per_table() {
        let filter = Filter { threats: Some(vec!["203.0.113.7".parse().unwrap(), "203.0.113.8".parse().unwrap()]),
                              cut: Some(vec![]), ssh_allow: Some(vec!["192.168.1.0/24".into()]), ..Default::default() };
        // What `pfctl -a … -s rules` prints for that filter (pf's own spelling of each rule).
        let listed = "block return out quick to <bb_threats>\nblock drop in quick from <bb_threats>\n\
                      block return out quick to <bb_cut>\nblock drop in quick from <bb_cut>\n\
                      pass in quick on lo0 proto tcp from any to any port = 22 flags S/SA keep state\n\
                      pass in quick proto tcp from <bb_ssh_allow> to any port = 22 flags S/SA keep state\n\
                      block return in quick proto tcp from any to any port = 22\n";
        assert_eq!(rule_count(listed), rule_count(&rules(&filter)), "an intact anchor");
        assert_eq!(rule_count(""), 0, "a flushed anchor (`pfctl -a … -F all`) holds none");
        let locked = rules(&Filter { remote_lock: true, ..Default::default() });
        assert_eq!(rule_count(&locked), 10, "each port of the lock's list is a rule of its own, as pf lists them");
        assert_eq!(canaries(&filter), vec![("bb_threats", "203.0.113.7".to_string()), ("bb_ssh_allow", "192.168.1.0/24".to_string())],
                   "an empty table has nothing to ask; each other one its first entry");
        assert_eq!(intact(&Filter::default()), Some(true), "nothing on: nothing to keep");
    }

    #[test]
    fn pf_token_counters_and_kills() {
        assert_eq!(parse_token("pf enabled\nToken : 13861413712377352527\n").as_deref(), Some("13861413712377352527"));
        assert_eq!(parse_token("pf already enabled\n"), None);
        let rules = "block drop out quick to <bb_threats>\n  [ Evaluations: 10  Packets: 4  Bytes: 240  States: 0 ]\n\
                     pass in quick on lo0 proto tcp from any to any port = 22 flags S/SA keep state\n  [ Evaluations: 3  Packets: 9  Bytes: 1  States: 1 ]\n\
                     block drop in quick from <bb_threats>\n  [ Evaluations: 10  Packets: 3  Bytes: 180  States: 0 ]\n";
        assert_eq!(parse_dropped(rules), 7);
        assert_eq!(parse_killed("killed 2 states from 1 sources and 0 destinations\n"), 2);
        assert_eq!(parse_killed("no states\n"), 0);
    }
}
