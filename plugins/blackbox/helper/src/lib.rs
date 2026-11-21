//! `blackbox-netd`: Network Shield's enforcer — the small root helper that applies the plan.
//!
//! **It decides nothing.** All policy lives in the Blackbox plugin's Network Shield
//! (`plugins/blackbox/shields/network`): what DNS must refuse, which IPs the firewall drops,
//! which connections to cut, who may SSH in, whether to watch. This process only:
//!
//! 1. pulls the plan every [`PLAN_EVERY`] from the plugin
//!    (`GET /api/shields/network-shield/api/enforcement?have=<version>`; an unchanged plan costs
//!    nothing) and applies it — the resolver's sets, the Mac's DNS settings, the pf anchor
//!    ([`pf`]: threats, cut connections, SSH lockdown);
//! 2. while the plan says `watch`, looks every [`watch::WATCH_EVERY`] at SSH into this Mac and
//!    the login files ([`watch`]) — observing only, never a file's contents;
//! 3. reports back every [`REPORT_EVERY`], and **at once** when something happened (a new SSH
//!    session, a changed file, a cut connection): `POST …/api/enforcer-report`.
//!
//! It opens no port of its own besides DNS on 127.0.0.1:53, and takes no commands from the app:
//! there is no control API to attack. Runs as a LaunchDaemon (`ai.umanitek.blackbox.netd`),
//! installed with one admin approval (by Blackbox's installer when the person turns on system
//! protection, or by Blackbox Desktop). When the plugin cannot be reached it
//! keeps enforcing the last plan; when it is stopped it puts the Mac's DNS settings and pf back.
//!
//! Modules: [`dns`] (the resolver), [`system`] (DNS settings), [`pf`] (the packet filter),
//! [`plan`] (the plan), [`watch`] (SSH and login files).

pub mod enforce;
pub mod observe;
pub mod command;
pub mod install;
pub mod link;
pub mod pf_status;
pub mod plan;
pub mod private_files;
pub mod safe_read;
pub mod sockets;
mod system_guard;

// The orchestration below names each part directly; observe and enforce stay separate modules.
pub use enforce::{dns, pf, sessions, system};
pub use observe::{logstream, remote, remote_procs, watch};

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use plan::Plan;

/// The LaunchDaemon label.
pub const LABEL: &str = "ai.umanitek.blackbox.netd";
/// The helper's root-owned folder.
pub const HOME: &str = "/Library/Application Support/Blackbox/netd";
const PLAN_PATH: &str = "/api/shields/network-shield/api/enforcement";
const REPORT_PATH: &str = "/api/shields/network-shield/api/enforcer-report";
pub const PLAN_EVERY: Duration = Duration::from_secs(15);
/// The plan is asked for this often while watching (an unchanged plan costs one tiny answer), so a
/// session the user chose to end, a lock or a block takes effect within seconds.
pub const PLAN_EVERY_WATCHING: Duration = Duration::from_secs(3);
pub const REPORT_EVERY: Duration = Duration::from_secs(30);
const PLAN_TIMEOUT: Duration = Duration::from_secs(120);
const REPORT_TIMEOUT: Duration = Duration::from_secs(15);
/// The most addresses kept cut at once (the oldest are released first).
const MAX_CUT: usize = 5000;

fn state_path() -> PathBuf {
    Path::new(HOME).join("state.json")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What survives a restart: what the helper changed on the Mac, so it can always put it back.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// What each network service's DNS was before DNS Shield took over (restored exactly).
    pub saved_dns: BTreeMap<String, Vec<String>>,
    pub dns_active: bool,
    pub firewall_active: bool,
    pub cut_active: bool,
    pub ssh_lockdown_active: bool,
    pub remote_lock_active: bool,
    pub pf_token: Option<String>,
    /// The addresses cut so far (kept blocked while cutting is on).
    pub cut_ips: Vec<String>,
    /// The plan version last applied (for the record; the next start re-applies the plan in full).
    pub version: String,
    /// The boot the pf token belongs to (kern.boottime): a token from another boot is stale.
    pub boot: u64,
}

impl State {
    fn load() -> State {
        fs::read_to_string(state_path()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    fn save(&self) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = private_files::write(&state_path(), text.as_bytes());
        }
    }
}

/// Wakes the reporter early (something happened that the plugin should hear about now).
#[derive(Default)]
struct Wake {
    due: Mutex<bool>,
    signal: Condvar,
}

impl Wake {
    fn now(&self) {
        *self.due.lock().unwrap() = true;
        self.signal.notify_one();
    }

    /// Waits for a wake or the timeout, whichever is first.
    fn wait(&self, timeout: Duration) {
        let due = self.due.lock().unwrap();
        let (mut due, _) = self.signal.wait_timeout_while(due, timeout, |due| !*due).unwrap();
        *due = false;
    }
}

/// The running helper.
struct Helper {
    state: Mutex<State>,
    resolver: Arc<dns::Resolver>,
    /// The one authenticated link to the plugin (plans verified, reports signed): [`link`].
    link: Mutex<link::Link>,
    last_error: Mutex<Option<String>>,
    /// Each protection's own last failure (None when it applied): the report says which one failed.
    failures: Mutex<Failures>,
    /// The plan version applied in THIS process. Not the saved one: after a restart the resolver
    /// is empty, so the first plan must come in full (asking `have=<saved>` would answer
    /// `unchanged` and leave DNS Shield refusing nothing).
    applied: Mutex<String>,
    watching: AtomicBool,
    watch: Mutex<watch::Watch>,
    /// Who is in this Mac (remote sessions), the login-log child, and what it needs to look.
    remote: Mutex<remote::Remote>,
    logs: Mutex<logstream::Stream>,
    sockets: Mutex<crate::sockets::Reader>,
    procs: Mutex<remote_procs::ProcReader>,
    /// End requests already acted on (each is carried out once).
    ended: Mutex<HashSet<String>>,
    wake: Wake,
}

static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn on_terminate(_: libc::c_int) {
    STOPPING.store(true, Ordering::SeqCst);
}

/// Starts a named helper thread (a crash then names it instead of "<unknown>").
fn named<F: FnOnce() + Send + 'static>(name: &str, work: F) {
    if let Err(error) = thread::Builder::new().name(name.into()).spawn(work) {
        eprintln!("blackbox-netd: could not start {name}: {error}");
    }
}

/// The helper's entry point (launchd runs it as root).
/// The last failure of each part of a plan: DNS (switching the Mac's DNS) and the filter (pf:
/// Threat Firewall, cut connections, SSH lockdown, Lock remote access share one apply).
#[derive(Debug, Clone, Default)]
struct Failures {
    dns: Option<String>,
    filter: Option<String>,
}

/// Per protection: whether it is applied now and, if its last apply failed, why — so the screen
/// never shows "on" for a protection that did not take (security finding).
fn protections(state: &State, failures: &Failures) -> Value {
    let one = |applied: bool, error: &Option<String>| json!({"applied": applied, "error": error});
    json!({
        "dns": one(state.dns_active, &failures.dns),
        "firewall": one(state.firewall_active, &failures.filter),
        "cut": one(state.cut_active, &failures.filter),
        "ssh_lockdown": one(state.ssh_lockdown_active, &failures.filter),
        "remote_lock": one(state.remote_lock_active, &failures.filter),
    })
}

/// Why the helper is stopping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopping {
    /// launchd stopped the service (repair, update, removal through launchctl).
    Service,
    /// `blackbox-netd uninstall`; *undo_hardening* only when the person explicitly chose it.
    Uninstall { undo_hardening: bool },
}

/// What stopping puts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Undo {
    /// The Mac's own DNS servers (pointing at a resolver that is gone would take it offline).
    pub dns: bool,
    /// Blackbox's pf rules and its pf reference.
    pub filter: bool,
    /// The posture fixes (firewall on, guest off, …).
    pub hardening: bool,
}

/// The one rule (security finding: removing or repairing the helper silently re-opened the Mac by
/// reversing every posture fix): hardening is undone only when the person explicitly asks.
pub fn undo_for(how: Stopping) -> Undo {
    Undo { dns: true, filter: true, hardening: matches!(how, Stopping::Uninstall { undo_hardening: true }) }
}

/// Puts the Mac back from the saved state alone — for `uninstall`, which runs while the
/// service is stopped (or dead). Answers what failed (nothing → empty).
pub fn put_back(undo: Undo) -> Vec<String> {
    let mut errors = vec![];
    let mut state = State::load();
    if undo.dns && !state.saved_dns.is_empty() {
        let failed = system::restore_dns(&state.saved_dns);
        if failed.is_empty() { state.saved_dns.clear(); state.dns_active = false; }
        errors.extend(failed);
    }
    if undo.filter {
        match pf::apply(&pf::Filter::default(), state.pf_token.take()) {
            Ok(_) => {
                state.firewall_active = false;
                state.cut_active = false;
                state.ssh_lockdown_active = false;
                state.remote_lock_active = false;
            }
            Err(error) => errors.push(error),
        }
    }
    if undo.hardening {
        system_guard::undo_hardening();
    }
    state.save();
    errors
}

/// How long the resolver has to answer its self-test.
const DNS_SELF_TEST_TIMEOUT: Duration = Duration::from_secs(1);

/// The upstreams to forward to, in order of trust: what the person set (*saved*, after a
/// restart), else what the Mac resolves with now, else what this network handed out by DHCP.
/// Empty when none is known — never a public resolver nobody chose.
fn known_upstreams(saved: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    pick_upstreams(saved.to_vec(), system::current_upstreams, system::dhcp_upstreams)
}

fn pick_upstreams(saved: Vec<std::net::SocketAddr>, current: impl FnOnce() -> Vec<std::net::SocketAddr>,
                  dhcp: impl FnOnce() -> Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    if !saved.is_empty() { return saved; }
    let now = current();
    if !now.is_empty() { now } else { dhcp() }
}

pub fn run() -> Result<(), String> {
    private_files::ensure_dir(Path::new(HOME)).map_err(|error| format!("{HOME}: {error}"))?;
    let mut state = State::load();
    // After a reboot the saved pf token is meaningless: drop it, so the first plan enables pf and
    // verifies it (pf::apply) instead of trusting a token from another boot.
    let boot = pf::boot_time();
    if state.boot != boot {
        state.pf_token = None;
        state.boot = boot;
        state.save();
    }
    let saved = if state.dns_active { system::upstreams_from_saved(&state.saved_dns) } else { vec![] };
    let upstreams = known_upstreams(&saved);
    let helper = Arc::new(Helper {
        resolver: dns::Resolver::new(upstreams),
        state: Mutex::new(state),
        link: Mutex::new(link::Link::new(Path::new(HOME))?),
        last_error: Mutex::new(None),
        failures: Mutex::new(Failures::default()),
        applied: Mutex::new(String::new()),
        watching: AtomicBool::new(false),
        watch: Mutex::new(watch::Watch::default()),
        remote: Mutex::new(remote::Remote::default()),
        logs: Mutex::new(logstream::Stream::default()),
        sockets: Mutex::new(crate::sockets::Reader::default()),
        procs: Mutex::new(remote_procs::ProcReader::default()),
        ended: Mutex::new(HashSet::new()),
        wake: Wake::default(),
    });

    let resolver = helper.resolver.clone();
    named("blackbox-netd-dns", move || {
        if let Err(error) = dns::serve(resolver) {
            eprintln!("blackbox-netd: the DNS resolver stopped: {error}");
        }
    });

    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_terminate as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_terminate as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }

    let reporter = helper.clone();
    named("blackbox-netd-report", move || loop {
        reporter.wake.wait(REPORT_EVERY);
        reporter.report();
    });
    let watcher = helper.clone();
    named("blackbox-netd-watch", move || loop {
        watcher.look();
        thread::sleep(watch::WATCH_EVERY);
    });
    // Exposure, persistence, tampering and posture (+ posture fixes, the DNS tamper guard): its own
    // small plan and report (system_guard), so neither loop waits on the other.
    // Every helper thread is named (`named`), so a crash log says which one it was. The stack
    // overflow first seen on a test VM was NOT stack size: it was logstream::Stream's stop/Drop
    // recursion (fixed there, with a regression test). The larger stack stays as headroom.
    let _ = thread::Builder::new().name("blackbox-system-guard".into()).stack_size(system_guard::STACK_BYTES).spawn(system_guard::run);
    let remoter = helper.clone();
    named("blackbox-netd-remote", move || loop {
        remoter.look_remote();
        thread::sleep(remote::REMOTE_EVERY);
    });

    loop {
        if STOPPING.load(Ordering::SeqCst) {
            helper.stop();
            return Ok(());
        }
        helper.follow_plan();
        helper.keep_dns_safe();
        let every = if helper.watching.load(Ordering::SeqCst) { PLAN_EVERY_WATCHING } else { PLAN_EVERY };
        for _ in 0..(every.as_millis() / 200) {
            if STOPPING.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Helper {
    /// Pulls the plan and applies it when it changed. Keeps the last plan when the plugin is away
    /// or cannot prove it is Blackbox's plugin ([`link`]): nothing is ever undone for that.
    fn follow_plan(&self) {
        let have: String = self.applied.lock().map(|applied| applied.clone()).unwrap_or_default()
            .chars().filter(char::is_ascii_alphanumeric).collect();
        let fetched = self.link.lock().unwrap().plan::<Plan>(PLAN_PATH, &format!("have={have}"), PLAN_TIMEOUT);
        let plan = match fetched {
            link::Fetched::Plan(plan) => plan,
            link::Fetched::Refused(why) => {
                *self.last_error.lock().unwrap() = Some(why);
                return;
            }
        };
        if plan.unchanged {
            return;
        }
        let mut errors = vec![];
        if let Ok(mut lists) = self.resolver.lists.write() {
            *lists = plan.blocklists();
        }
        let dns_error = self.set_dns(plan.dns.enabled);
        let filter_error = self.set_filter(&plan);
        *self.failures.lock().unwrap() = Failures { dns: dns_error.clone(), filter: filter_error.clone() };
        errors.extend(dns_error);
        errors.extend(filter_error);
        self.watching.store(plan.watch, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            state.version = plan.version.clone();
            state.save();
        }
        *self.applied.lock().unwrap() = plan.version.clone();
        *self.last_error.lock().unwrap() = (!errors.is_empty()).then(|| errors.join("; "));
    }

    fn set_dns(&self, enabled: bool) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        if enabled == state.dns_active {
            return None;
        }
        let result = if enabled {
            // Switch the Mac's DNS only to a resolver that is up and answering, with a real
            // upstream to forward to (security finding: a failed bind or an empty upstream list
            // used to take the Mac offline, or send its queries to public resolvers nobody chose).
            let upstreams = known_upstreams(&[]);
            if upstreams.is_empty() {
                return Some("DNS Shield stays off: no DNS server of this network is known to forward to".into());
            }
            if !self.resolver_answers() {
                return Some("DNS Shield stays off: Blackbox's resolver is not answering on 127.0.0.1:53".into());
            }
            *self.resolver.upstreams.write().unwrap() = upstreams;
            system::point_dns_at_shield().map(|saved| {
                for (service, servers) in saved {
                    state.saved_dns.entry(service).or_insert(servers);
                }
            })
        } else {
            let errors = system::restore_dns(&state.saved_dns);
            if errors.is_empty() { state.saved_dns.clear(); Ok(()) } else { Err(errors.join("; ")) }
        };
        if result.is_ok() {
            state.dns_active = enabled;
        }
        state.save();
        result.err()
    }

    /// Whether the resolver is serving and answers a test query now.
    fn resolver_answers(&self) -> bool {
        self.resolver.alive.load(Ordering::SeqCst) && dns::self_test(dns::LISTEN, DNS_SELF_TEST_TIMEOUT)
    }

    /// Every plan cycle while DNS Shield is on: follow the network the Mac is on now (its DHCP
    /// servers), and if the resolver died, put the Mac's own DNS back at once and say so — the
    /// next plan turns it on again only when the resolver answers.
    fn keep_dns_safe(&self) {
        if !self.state.lock().map(|state| state.dns_active).unwrap_or(false) {
            return;
        }
        if !self.resolver_answers() {
            let error = self.set_dns(false).unwrap_or_default();
            *self.applied.lock().unwrap() = String::new();   // re-apply the plan in full next time
            *self.last_error.lock().unwrap() = Some(format!("DNS Shield's resolver stopped answering; the Mac's own DNS was put back {error}").trim().to_string());
            return;
        }
        let now = system::dhcp_upstreams();
        if !now.is_empty() {
            if let Ok(mut upstreams) = self.resolver.upstreams.write() {
                if *upstreams != now { *upstreams = now; }
            }
        }
    }

    /// Makes pf enforce the plan's firewall, cut and SSH lockdown; kills the open connections to
    /// newly cut addresses and queues an event for each.
    fn set_filter(&self, plan: &Plan) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        let mut newly: Vec<IpAddr> = vec![];
        if plan.cut.enabled {
            state.cut_ips.retain(|ip| ip.parse::<IpAddr>().map(|ip| !plan.is_allowed(&ip)).unwrap_or(false));
            for ip in plan.cut_ips() {
                if !state.cut_ips.contains(&ip.to_string()) {
                    state.cut_ips.push(ip.to_string());
                    newly.push(ip);
                }
            }
            let extra = state.cut_ips.len().saturating_sub(MAX_CUT);
            state.cut_ips.drain(..extra);
        } else {
            state.cut_ips.clear();
        }
        let threats = plan.firewall.enabled.then(|| plan.firewall_ips());
        let filter = pf::Filter {
            threats: threats.clone(),
            cut: plan.cut.enabled.then(|| state.cut_ips.iter().filter_map(|ip| ip.parse().ok()).collect()),
            ssh_allow: plan.ssh.lockdown.then(|| plan.ssh_sources()),
            remote_lock: plan.remote.lock,
            remote_block: plan.remote_block(),
        };
        let result = pf::apply(&filter, state.pf_token.clone());
        if let Ok(token) = &result {
            state.pf_token = token.clone();
            state.firewall_active = threats.map(|ips| !ips.is_empty()).unwrap_or(false);
            state.cut_active = plan.cut.enabled;
            state.ssh_lockdown_active = plan.ssh.lockdown;
            state.remote_lock_active = plan.remote.lock;
        }
        state.save();
        drop(state);
        self.end_sessions(plan);
        if result.is_ok() && !newly.is_empty() {
            let mut watch = self.watch.lock().unwrap();
            for ip in &newly {
                let _ = pf::kill_states(ip);   // the anchor's rule already drops it; this ends open states too
                watch.push(json!({"kind": "connection-cut", "ts": now(), "remote_ip": ip.to_string()}));
            }
            drop(watch);
            self.wake.now();
        }
        result.err()
    }

    /// One look at SSH and the login files, while the plan says watch; nothing while it does not.
    fn look(&self) {
        if !self.watching.load(Ordering::SeqCst) {
            self.watch.lock().unwrap().reset();
            return;
        }
        let (netstat, files) = watch::look();
        let news = self.watch.lock().unwrap().tick(&netstat, files, now());
        if news {
            self.wake.now();
        }
    }

    /// One look at who is in this Mac, while the plan says watch: the login log (its child started
    /// on first use, stopped when watching stops), the inbound sessions and their processes.
    fn look_remote(&self) {
        if !self.watching.load(Ordering::SeqCst) {
            self.logs.lock().unwrap().stop();
            self.remote.lock().unwrap().reset();
            return;
        }
        let logins = {
            let mut logs = self.logs.lock().unwrap();
            logs.ensure_running();
            logs.drain()
        };
        let inbound: Vec<remote::Inbound> = self.sockets.lock().unwrap().sockets().into_iter()
            .filter(|s| remote::REMOTE_PORTS.iter().any(|(port, _)| *port == s.local_port))
            .map(|s| remote::Inbound { pid: s.pid, local_ip: s.local_ip, local_port: s.local_port, remote_ip: s.remote_ip,
                                       remote_port: s.remote_port, listening: s.listening(), established: s.state == "Established" })
            .collect();
        // The process table only when someone is in or a login just happened (it costs more).
        let procs = if inbound.iter().any(|s| s.established) || !logins.is_empty() {
            self.procs.lock().unwrap().read()
        } else {
            remote_procs::Procs::new()
        };
        if self.remote.lock().unwrap().tick(&inbound, &procs, logins, now()) {
            self.wake.now();
        }
    }

    /// Carries out the plan's end requests the user confirmed — each once, each only after
    /// [`sessions::verify`] says it is still exactly that session — and reports what happened.
    fn end_sessions(&self, plan: &Plan) {
        let mut ended = self.ended.lock().unwrap();
        ended.retain(|id| plan.remote.end.iter().any(|request| &request.session_id == id));
        for request in &plan.remote.end {
            if !ended.insert(request.session_id.clone()) {
                continue;
            }
            let live = self.remote.lock().unwrap().session(&request.session_id).cloned();
            let process = self.procs.lock().unwrap().read().get(&request.pid).map(|p| (p.name.clone(), p.start));
            let checked = sessions::verify(request, live.as_ref(), process.as_ref().map(|(name, start)| (name.as_str(), *start)));
            let event = match (checked.and_then(|_| sessions::end(request.pid)), live) {
                (Ok(()), Some(session)) => remote::session_event("remote-session-ended", &session, now(), "ended"),
                (result, _) => json!({"kind": "remote-end-refused", "ts": now(), "session_id": request.session_id,
                                      "reason": result.err().unwrap_or_default()}),
            };
            self.remote.lock().unwrap().push(event);
            self.wake.now();
        }
    }

    /// The report body: running, what is active, counters, the names refused since last time, and
    /// (while watching) the watch snapshot and the events not yet reported.
    fn report_body(&self, events: Vec<Value>, remote_events: Vec<Value>) -> Value {
        let state = self.state.lock().map(|state| state.clone()).unwrap_or_default();
        let blocks: Vec<Value> = self.resolver.drain_pending().into_iter()
            .map(|((domain, list), (count, ts))| json!({"domain": domain, "list": list, "count": count, "ts": ts}))
            .collect();
        let snapshot = if self.watching.load(Ordering::SeqCst) { self.watch.lock().unwrap().snapshot() } else { None };
        let pf_on = state.firewall_active || state.cut_active || state.ssh_lockdown_active || state.remote_lock_active;
        let remote = if self.watching.load(Ordering::SeqCst) { self.remote.lock().unwrap().snapshot() } else { None };
        json!({
            "running": true, "dns_active": state.dns_active, "firewall_active": state.firewall_active,
            "cut_active": state.cut_active, "ssh_lockdown_active": state.ssh_lockdown_active,
            "version": state.version, "queries": self.resolver.queries.load(std::sync::atomic::Ordering::Relaxed),
            // What the person needs to trust the screen: whether the link is authenticated and the
            // last thing that failed (null when everything applied).
            "auth": self.link.lock().map(|link| link.mode()).unwrap_or("legacy"),
            "last_error": self.last_error.lock().ok().and_then(|e| e.clone()),
            "resolver_ok": self.resolver.alive.load(Ordering::SeqCst),
            "dns_error": self.failures.lock().ok().and_then(|f| f.dns.clone()),
            "filter_error": self.failures.lock().ok().and_then(|f| f.filter.clone()),
            "protections": protections(&state, &self.failures.lock().map(|f| f.clone()).unwrap_or_default()),
            "firewall_dropped": if pf_on { pf::dropped() } else { 0 },
            // What is really enforced, not what was asked: pf must be seen Enabled.
            "pf_enabled": if pf_on { pf::enabled() } else { None },
            "blocks": blocks, "watch": snapshot, "events": events,
            // Under its own key, so a plugin that predates it ignores it instead of refusing the report.
            "remote": remote.map(|snapshot| json!({"snapshot": snapshot, "events": remote_events, "lock_active": state.remote_lock_active})),
        })
    }

    fn report(&self) {
        let remote_on = self.remote.lock().map(|remote| remote.snapshot().is_some()).unwrap_or(false);
        // While the remote watch runs it reports SSH sessions in full; the older SSH events would repeat them.
        let events: Vec<Value> = self.watch.lock().map(|mut watch| watch.drain()).unwrap_or_default().into_iter()
            .filter(|event| !(remote_on && event["kind"].as_str().is_some_and(|kind| kind.starts_with("ssh-session"))))
            .collect();
        let remote_events = self.remote.lock().map(|mut remote| remote.drain()).unwrap_or_default();
        let body = self.report_body(events.clone(), remote_events.clone());
        // Only to a server that proved it is Blackbox's plugin; signed ([`link`]).
        if self.link.lock().unwrap().post(REPORT_PATH, &body, REPORT_TIMEOUT) {
            return;
        }
        // Not delivered (the plugin away, or not proven): keep the events for the next report.
        if !events.is_empty() {
            self.watch.lock().unwrap().requeue(events);
        }
        if !remote_events.is_empty() {
            self.remote.lock().unwrap().requeue(remote_events);
        }
    }

    /// Puts the Mac back: DNS settings restored, the pf anchor emptied and pf released.
    /// The service stops (launchd's SIGTERM: a repair, an update, a removal). DNS and the pf
    /// rules need the running helper, so they are put back; posture hardening is NOT — it keeps
    /// the Mac safe without the helper ([`undo_for`]).
    fn stop(&self) {
        let undo = undo_for(Stopping::Service);
        if undo.dns { let _ = self.set_dns(false); }
        if undo.filter { let _ = self.set_filter(&Plan::default()); }
        self.watching.store(false, Ordering::SeqCst);
        self.logs.lock().unwrap().stop();
        if undo.hardening { system_guard::undo_hardening(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_or_repairing_the_helper_never_reopens_the_mac() {
        let service = undo_for(Stopping::Service);
        assert!(service.dns && service.filter, "what needs the running helper is put back");
        assert!(!service.hardening, "posture hardening stays when the service stops");
        assert!(!undo_for(Stopping::Uninstall { undo_hardening: false }).hardening);
        assert!(undo_for(Stopping::Uninstall { undo_hardening: true }).hardening, "only the person's explicit choice");
    }


    #[test]
    fn each_protection_reports_whether_it_applied_and_why_not() {
        let state = State { dns_active: false, firewall_active: true, ..Default::default() };
        let failures = Failures { dns: Some("no DNS server known".into()), filter: None };
        let report = protections(&state, &failures);
        assert_eq!(report["dns"]["applied"], false);
        assert_eq!(report["dns"]["error"], "no DNS server known");
        assert_eq!(report["firewall"]["applied"], true);
        assert!(report["firewall"]["error"].is_null());
    }


    #[test]
    fn upstreams_come_from_the_person_then_the_mac_then_dhcp_never_a_public_resolver() {
        let a: std::net::SocketAddr = "192.168.1.1:53".parse().unwrap();
        let b: std::net::SocketAddr = "10.0.0.1:53".parse().unwrap();
        assert_eq!(pick_upstreams(vec![a], || vec![b], Vec::new), [a]);
        assert_eq!(pick_upstreams(vec![], || vec![b], || vec![a]), [b]);
        assert_eq!(pick_upstreams(vec![], Vec::new, || vec![a]), [a]);
        assert!(pick_upstreams(vec![], Vec::new, Vec::new).is_empty(), "nothing known: DNS Shield stays off");
    }


    #[test]
    fn a_wake_ends_the_wait_early() {
        let wake = Arc::new(Wake::default());
        let other = wake.clone();
        let started = std::time::Instant::now();
        let waiter = thread::Builder::new().name("blackbox-netd-wait".into()).spawn(move || other.wait(Duration::from_secs(30)))
            .expect("a thread for the wait");
        wake.now();
        waiter.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
