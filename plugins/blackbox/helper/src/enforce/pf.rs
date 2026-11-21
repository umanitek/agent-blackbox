//! Network Shield's packet filter: one pf anchor of Blackbox's own for everything it enforces.
//!
//! The anchor is `com.apple/250.BlackboxFirewall` (the stock `/etc/pf.conf` evaluates every
//! `com.apple/*` anchor, so no system file is edited). It holds three tables and only the rules
//! of the protections that are on:
//!
//! - **Threat Firewall** — `<bb_threats>`: drop traffic to and from the verified graph's addresses;
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

const PFCTL: &str = "/sbin/pfctl";
pub const ANCHOR: &str = "com.apple/250.BlackboxFirewall";
const THREATS: &str = "bb_threats";
const CUT: &str = "bb_cut";
const SSH_ALLOW: &str = "bb_ssh_allow";
const REMOTE_BLOCK: &str = "bb_remote_block";
/// The ports Lock remote access closes: SSH, Screen Sharing, Remote Management, SMB, Remote Apple Events.
pub const REMOTE_PORTS: &str = "{ 22 5900 3283 445 3031 }";

/// What the anchor must enforce; `None` = that protection is off.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    pub threats: Option<Vec<IpAddr>>,
    pub cut: Option<Vec<IpAddr>>,
    /// Allowed SSH sources: addresses or networks, already checked by [`source`].
    pub ssh_allow: Option<Vec<String>>,
    /// Lock remote access: the remote-access ports closed to everyone but this Mac.
    pub remote_lock: bool,
    /// Addresses refused inbound entirely (blocked by the user or for repeated failed logins).
    pub remote_block: Option<Vec<IpAddr>>,
}

impl Filter {
    pub fn is_off(&self) -> bool {
        self.threats.is_none() && self.cut.is_none() && self.ssh_allow.is_none() && !self.remote_lock && self.remote_block.is_none()
    }
}

/// An SSH source in canonical form (`192.168.1.0/24`, `10.0.0.5`, `fd00::/8`); None when invalid.
/// Everything that goes into a pf table passes through this or `IpAddr`.
pub fn source(text: &str) -> Option<String> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let ip: IpAddr = address.trim().parse().ok()?;
    match prefix {
        None => Some(ip.to_string()),
        Some(prefix) => {
            let bits: u8 = prefix.trim().parse().ok()?;
            let most = if ip.is_ipv4() { 32 } else { 128 };
            (bits <= most).then(|| format!("{ip}/{bits}"))
        }
    }
}

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
    if filter.threats.is_some() {
        text.push_str(&format!("block drop out quick to <{THREATS}>\nblock drop in quick from <{THREATS}>\n"));
    }
    if filter.cut.is_some() {
        text.push_str(&format!("block drop out quick to <{CUT}>\nblock drop in quick from <{CUT}>\n"));
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
    if token.is_some() {
        return Ok(token);
    }
    let output = run(&["-E"], None)?;
    parse_token(&output).map(Some).ok_or_else(|| format!("pfctl -E gave no token: {}", output.trim()))
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
    fn only_the_protections_that_are_on_have_rules() {
        let none = rules(&Filter { threats: Some(vec![]), ..Default::default() });
        assert!(none.contains("block drop in quick from <bb_threats>") && !none.contains("bb_cut>\n") && !none.contains("port 22"));
        let all = rules(&Filter { threats: None, cut: Some(vec![]), ssh_allow: Some(vec![]), ..Default::default() });
        assert!(all.contains("block drop out quick to <bb_cut>") && !all.contains("to <bb_threats>"));
        let lo = all.find("on lo0").unwrap();
        let allow = all.find("from <bb_ssh_allow>").unwrap();
        let refuse = all.find("block return in quick proto tcp to any port 22").unwrap();
        assert!(lo < allow && allow < refuse, "the passes come before the refusal");
        assert!(Filter::default().is_off());
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
    fn ssh_sources_are_addresses_or_networks_only() {
        assert_eq!(source("192.168.1.0/24").as_deref(), Some("192.168.1.0/24"));
        assert_eq!(source("10.0.0.5").as_deref(), Some("10.0.0.5"));
        assert_eq!(source("fd00::/8").as_deref(), Some("fd00::/8"));
        for bad in ["10.0.0.0/33", "example.com", "1.2.3.4/x", "1.2.3.4\nblock all", ""] {
            assert_eq!(source(bad), None, "{bad:?}");
        }
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
