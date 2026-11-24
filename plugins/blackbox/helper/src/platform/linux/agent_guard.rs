//! The agent guard: per-agent network rules for sandboxed agents (design "Linux deep layers" §1.3
//! and §2.4, build step 17). Linux's agent sandbox runs each agent in its own cgroup scope,
//! `<user manager>/blackbox-agents.slice/blackbox-agent-<digest12>-<id>.scope`
//! (`sandbox/scope.rs`); this guard keeps one nftables table of its own, `inet blackbox_agents`,
//! with a chain per running scope that refuses, for that agent only:
//!
//! * ssh back into this computer (TCP 22 to any local address) — always: the never-list;
//! * Docker's TCP ports (2375, 2376) to this computer — while its policy refuses Docker;
//! * every other local TCP port but the ones its policy lists, DNS (53) and the dashboard's — while
//!   its policy blocks `local-ports`.
//!
//! The rules come from File Shield's watch plan (`agents`, keyed by the policy digest a scope's
//! name carries); a scope whose digest the plan does not name gets the never-list rule only.
//! Refusals are drops in the output hook, which the agent's `connect` sees as EPERM (the
//! sandbox's refusal wording reads it). Like the firewall table, the chains only ever drop —
//! never accept — and the table is replaced in ONE `nft -f` transaction.
//!
//! After a table holding a scope is loaded, `/run/blackbox-netd/agents/<scope>.ready` is written:
//! the launcher waits for it (at most 500 ms) before it starts the agent. WHY a 100 ms look at the
//! cgroup tree: that wait is the bound an agent's first connections are unguarded within, so the
//! look keeps its pace (LES-141); reading a few cgroup folders costs microseconds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::sandbox::scope;

/// The cgroup v2 tree.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The table's family and name.
pub const TABLE: &str = "inet blackbox_agents";
/// How often the cgroup tree is looked at (see the module doc: a security bound).
pub const LOOK_EVERY: Duration = Duration::from_millis(100);
/// How often the plan is fetched.
pub const PLAN_EVERY: Duration = Duration::from_secs(2);
const TIMEOUT: Duration = Duration::from_secs(10);
const PLAN_PATH: &str = "/api/shields/file-shield/api/watch-plan";
/// The most scopes and rules one table holds (bounded work for any plan).
pub const MAX_SCOPES: usize = 512;
pub const MAX_ALLOWED_PORTS: usize = 64;
/// Docker's TCP ports (plain and TLS).
pub const DOCKER_PORTS: [u16; 2] = [2375, 2376];
const SSH_PORT: u16 = 22;
const DNS_PORT: u16 = 53;

/// One policy's network rules, as the plan carries them.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct AgentRule {
    pub digest: String,
    pub local_ports: bool,
    pub allow: Vec<u16>,
    pub docker_tcp: bool,
}

/// The part of the watch plan this guard reads.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Plan {
    pub agents: Vec<AgentRule>,
}

impl Plan {
    /// The rules by digest (12 hex characters), the first one per digest kept.
    pub fn by_digest(&self) -> BTreeMap<String, AgentRule> {
        let mut found = BTreeMap::new();
        for rule in self.agents.iter().take(MAX_SCOPES) {
            let digest: String = rule.digest.chars().take(scope::DIGEST_CHARS).collect();
            if digest.len() == scope::DIGEST_CHARS && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                found.entry(digest.to_ascii_lowercase()).or_insert_with(|| rule.clone());
            }
        }
        found
    }
}

/// One running agent's scope: its unit name and its path below the cgroup root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scope {
    pub unit: String,
    pub path: String,
}

fn folders(path: &Path) -> Vec<(String, PathBuf)> {
    let mut found: Vec<(String, PathBuf)> = fs::read_dir(path).map(|entries| {
        entries.filter_map(Result::ok).filter(|e| e.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter_map(|e| e.file_name().to_str().map(|name| (name.to_string(), e.path()))).collect()
    }).unwrap_or_default();
    found.sort();
    found
}

/// Every sandboxed agent's scope under *root* (`/sys/fs/cgroup`), at most [`MAX_SCOPES`].
pub fn scopes(root: &Path) -> Vec<Scope> {
    let mut found = Vec::new();
    for (user_slice, user_path) in folders(&root.join("user.slice")).into_iter().filter(|(name, _)| name.starts_with("user-")) {
        for (manager, manager_path) in folders(&user_path).into_iter().filter(|(name, _)| name.starts_with("user@")) {
            for (unit, _) in folders(&manager_path.join(scope::SLICE)) {
                if scope::digest_of_unit(&unit).is_some() && found.len() < MAX_SCOPES {
                    found.push(Scope { path: format!("user.slice/{user_slice}/{manager}/{}/{unit}", scope::SLICE), unit });
                }
            }
        }
    }
    found
}

fn ports(list: &[u16]) -> String {
    let set: BTreeSet<u16> = list.iter().copied().collect();
    format!("{{ {} }}", set.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
}

/// The whole table for *scopes* under *rules*, as one `nft -f` script (see the module doc);
/// *dashboard*: the dashboard's port, always reachable.
pub fn ruleset(scopes: &[Scope], rules: &BTreeMap<String, AgentRule>, dashboard: u16) -> String {
    let mut text = format!("table {TABLE}\ndelete table {TABLE}\n");
    if scopes.is_empty() {
        return text;
    }
    text.push_str(&format!("table {TABLE} {{\n\tchain output {{\n\t\ttype filter hook output priority filter - 5; policy accept;\n"));
    for (index, scope) in scopes.iter().enumerate() {
        let level = scope.path.matches('/').count() + 1;
        // A cgroup path is ours (unit names are checked hex): no quote can be in it.
        text.push_str(&format!("\t\tsocket cgroupv2 level {level} \"{}\" jump agent_{index}\n", scope.path));
    }
    text.push_str("\t}\n");
    for (index, scope) in scopes.iter().enumerate() {
        let rule = scope::digest_of_unit(&scope.unit).and_then(|digest| rules.get(digest)).cloned().unwrap_or_default();
        text.push_str(&format!("\tchain agent_{index} {{\n"));
        text.push_str(&format!("\t\tfib daddr type local tcp dport {SSH_PORT} counter drop\n"));
        if rule.docker_tcp {
            text.push_str(&format!("\t\tfib daddr type local tcp dport {} counter drop\n", ports(&DOCKER_PORTS)));
        }
        if rule.local_ports {
            let mut open: Vec<u16> = rule.allow.iter().copied().filter(|port| *port != SSH_PORT).take(MAX_ALLOWED_PORTS).collect();
            open.push(DNS_PORT);
            if dashboard > 0 {
                open.push(dashboard);
            }
            if rule.docker_tcp {
                open.retain(|port| !DOCKER_PORTS.contains(port));
            }
            text.push_str(&format!("\t\tfib daddr type local tcp dport != {} counter drop\n", ports(&open)));
        }
        text.push_str("\t}\n");
    }
    text.push_str("}\n");
    text
}

/// Writes a readiness mark in *folder* for each of *scopes* and removes every other one.
pub fn mark_ready(folder: &Path, scopes: &[Scope]) -> std::io::Result<()> {
    fs::create_dir_all(folder)?;
    let wanted: BTreeSet<String> = scopes.iter().map(|scope| format!("{}.ready", scope.unit)).collect();
    for (name, path) in fs::read_dir(folder)?.filter_map(Result::ok).filter_map(|e| e.file_name().to_str().map(|n| (n.to_string(), e.path()))) {
        if name.ends_with(".ready") && !wanted.contains(&name) {
            let _ = fs::remove_file(path);
        }
    }
    for name in &wanted {
        let path = folder.join(name);
        if !path.exists() {
            fs::write(path, b"1\n")?;
        }
    }
    Ok(())
}

/// The loop (started beside the helper's watches; runs until the process ends). Fail-open: an
/// unreadable plan keeps the last one; a table that does not load leaves no readiness mark, so
/// the launcher says the rules are not applied. The dashboard's port comes in each policy's
/// `allow` list (the plugin adds it), so the table needs no port of its own here.
pub fn run() {
    let Ok(mut link) = crate::link::Link::new(Path::new(super::HOME)) else { return };
    let mut rules: BTreeMap<String, AgentRule> = BTreeMap::new();
    let mut last_plan: Option<Instant> = None;
    let mut loaded: Option<(Vec<Scope>, BTreeMap<String, AgentRule>)> = None;
    loop {
        if last_plan.is_none_or(|at| at.elapsed() >= PLAN_EVERY) {
            last_plan = Some(Instant::now());
            if let crate::link::Fetched::Plan(plan) = link.plan::<Plan>(PLAN_PATH, "", TIMEOUT) {
                rules = plan.by_digest();
            }
        }
        let now = scopes(Path::new(CGROUP_ROOT));
        if loaded.as_ref() != Some(&(now.clone(), rules.clone())) {
            match super::enforce::nft::load(&ruleset(&now, &rules, 0)) {
                Ok(()) => {
                    let _ = mark_ready(Path::new(scope::READY_FOLDER), &now);
                    loaded = Some((now, rules.clone()));
                }
                Err(_) => {
                    let _ = mark_ready(Path::new(scope::READY_FOLDER), &[]);
                    loaded = None;
                }
            }
        }
        std::thread::sleep(LOOK_EVERY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: &str = "blackbox-agent-0123456789ab-5f3c.scope";

    fn tree(root: &Path, units: &[&str]) {
        for unit in units {
            fs::create_dir_all(root.join("user.slice/user-1000.slice/user@1000.service").join(scope::SLICE).join(unit)).unwrap();
        }
        fs::create_dir_all(root.join("user.slice/user-1000.slice/user@1000.service/app.slice/gnome-shell.scope")).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("bb-agent-guard-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn only_the_sandboxs_own_scopes_are_found() {
        let root = scratch("scopes");
        tree(&root, &[UNIT, "blackbox-agent-nodigest-1.scope", "something-else.scope"]);
        assert_eq!(scopes(&root), vec![Scope { unit: UNIT.into(),
            path: format!("user.slice/user-1000.slice/user@1000.service/blackbox-agents.slice/{UNIT}") }]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn each_scope_gets_the_never_list_and_its_own_policys_rules() {
        let plan: Plan = serde_json::from_str(r#"{"watch": true, "paths": [], "agents": [
            {"digest": "0123456789abcdef", "local_ports": true, "allow": [5432, 22, 2375], "docker_tcp": true}]}"#).unwrap();
        let other = Scope { unit: "blackbox-agent-ffffffffffff-1.scope".into(), path: "user.slice/u/user@1/blackbox-agents.slice/blackbox-agent-ffffffffffff-1.scope".into() };
        let mine = Scope { unit: UNIT.into(), path: format!("user.slice/u/user@1/blackbox-agents.slice/{UNIT}") };
        let text = ruleset(&[mine, other], &plan.by_digest(), 9700);
        assert!(text.starts_with("table inet blackbox_agents\ndelete table inet blackbox_agents\n"));
        assert!(text.contains(&format!("socket cgroupv2 level 5 \"user.slice/u/user@1/blackbox-agents.slice/{UNIT}\" jump agent_0")));
        let chain = |index: usize| text.split(&format!("chain agent_{index} {{")).nth(1).unwrap().split('}').next().unwrap().to_string();
        let mine = chain(0);
        assert!(mine.contains("tcp dport 22 counter drop"));
        assert!(mine.contains("tcp dport { 2375, 2376 } counter drop"));
        assert!(mine.contains("tcp dport != { 53, 5432, 9700 } counter drop"), "listed ports, DNS and the dashboard stay open — never 22 or Docker's: {mine}");
        let other = chain(1);
        assert!(other.contains("tcp dport 22 counter drop") && !other.contains("!="), "an unknown policy: the never-list only");
        assert_eq!(text.matches("accept").count(), 1, "only the hook chain's policy says accept: no rule ever accepts");
    }

    #[test]
    fn no_scope_removes_the_table() {
        assert_eq!(ruleset(&[], &BTreeMap::new(), 9700), "table inet blackbox_agents\ndelete table inet blackbox_agents\n");
    }

    #[test]
    fn a_plan_digest_that_is_not_hex_is_ignored() {
        let plan: Plan = serde_json::from_str(r#"{"agents": [{"digest": "../../etc"}, {"digest": "0123456789AB"}]}"#).unwrap();
        assert_eq!(plan.by_digest().keys().cloned().collect::<Vec<_>>(), vec!["0123456789ab"]);
    }

    #[test]
    fn readiness_marks_follow_the_loaded_scopes() {
        let folder = scratch("ready");
        let scope = |unit: &str| Scope { unit: unit.into(), path: String::new() };
        mark_ready(&folder, &[scope(UNIT), scope("blackbox-agent-ffffffffffff-1.scope")]).unwrap();
        assert!(folder.join(format!("{UNIT}.ready")).exists());
        mark_ready(&folder, &[scope(UNIT)]).unwrap();
        assert!(!folder.join("blackbox-agent-ffffffffffff-1.scope.ready").exists());
        let _ = fs::remove_dir_all(folder);
    }

    /// The rules on a real kernel, inside a private user + network namespace (CI's helper lane):
    /// this test process's own cgroup stands in for an agent's scope.
    #[test]
    fn a_blocked_local_port_is_refused_and_a_listed_one_is_not_in_a_private_network_namespace() {
        let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") else { return };
        let Some(path) = cgroup.lines().find_map(|line| line.strip_prefix("0::/")).filter(|path| !path.is_empty()) else { return };
        let me = Scope { unit: UNIT.into(), path: path.to_string() };
        let rules = Plan { agents: vec![AgentRule { digest: "0123456789ab".into(), local_ports: true, allow: vec![5432], docker_tcp: false }] };
        let script = ruleset(&[me], &rules.by_digest(), 0);
        let nft = super::super::enforce::nft::NFT_COMMANDS.iter().find(|path| Path::new(path).exists());
        let usable = std::process::Command::new("unshare").args(["-rn", "true"]).output().is_ok_and(|out| out.status.success());
        let (Some(nft), true) = (nft, usable) else {
            assert!(std::env::var("BLACKBOX_REQUIRE_NETNS").as_deref() != Ok("1"), "no unprivileged network namespace or nft here");
            return;
        };
        let check = format!("ip link set lo up; {nft} -f - || exit 3; \
                             (echo > /dev/tcp/127.0.0.1/7777) 2>&1 | grep -qi 'not permitted' || exit 4; \
                             (echo > /dev/tcp/127.0.0.1/5432) 2>&1 | grep -qi 'refused' || exit 5");
        let done = crate::command::output_with_input(std::process::Command::new("unshare").args(["-rn", "bash", "-c", &check]),
                                                     Some(script.as_bytes()), Duration::from_secs(30)).unwrap();
        assert!(done.status.success(), "exit {:?}: {}", done.status.code(), String::from_utf8_lossy(&done.stderr));
    }
}
