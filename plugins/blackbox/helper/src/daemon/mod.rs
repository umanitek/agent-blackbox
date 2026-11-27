//! The running helper: its parts, its threads and its loop ([`run`]). Its methods live in
//! [`apply`] (applying a plan), [`look`] (watching) and [`reporting`] (reports and stopping).

mod apply;
mod filter_keeper;
mod look;
mod reporting;

#[allow(unused_imports)]
use crate::*;
use crate::state::now;

/// The most addresses kept cut at once (the oldest are released first).
const MAX_CUT: usize = 5000;

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
    /// What the helper changes on this system, and what it watches ([`crate::platform`]).
    enforcer: SystemEnforcer,
    observer: SystemObserver,
    /// End requests already acted on (each is carried out once).
    ended: Mutex<HashSet<String>>,
    /// The verified graph's lists last applied: what a `keep_verified` plan keeps (the graph's
    /// store being down never clears protection — [`crate::plan::Kept`]).
    kept: Mutex<crate::plan::Kept>,
    /// The filter the plan wants and the one loaded: what [`Helper::keep_filter_intact`] tries
    /// again when it failed, and loads again when another program removed or changed the rules.
    filtered: Mutex<filter_keeper::FilterKeeper>,
    /// Whether the plan last applied wants DNS Shield on: what [`Helper::keep_dns_safe`] keeps true
    /// in effect, also when switching it on failed (a boot before the resolver answered).
    dns_wanted: AtomicBool,
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

impl Failures {
    /// What the last apply could not do, as the report's `last_error` (None when it all applied).
    fn still_failing(&self) -> Option<String> {
        let left: Vec<&str> = [self.dns.as_deref(), self.filter.as_deref()].into_iter().flatten().collect();
        (!left.is_empty()).then(|| left.join("; "))
    }
}

/// What is really in effect now, measured (LES-166): the system's DNS points at the resolver, and
/// the firewall still holds the rules loaded. False only when seen otherwise (unreadable counts as
/// in effect: nothing is re-applied for it either).
#[derive(Debug, Clone, Copy)]
struct InEffect {
    dns: bool,
    filter: bool,
}

/// Per protection: whether it is applied AND in effect now and, if its last apply failed, why — so
/// the screen never shows "on" for a protection that did not take (security finding), nor for one
/// whose rules another program removed (review finding 2026-11-26: after a flush of Blackbox's
/// table the card still said "remote locked").
fn protections(state: &State, failures: &Failures, in_effect: InEffect) -> Value {
    let one = |applied: bool, error: &Option<String>| json!({"applied": applied, "error": error});
    json!({
        "dns": one(state.dns_active && in_effect.dns, &failures.dns),
        "firewall": one(state.firewall_active && in_effect.filter, &failures.filter),
        "cut": one(state.cut_active && in_effect.filter, &failures.filter),
        "ssh_lockdown": one(state.ssh_lockdown_active && in_effect.filter, &failures.filter),
        "remote_lock": one(state.remote_lock_active && in_effect.filter, &failures.filter),
    })
}

/// Why the helper is stopping.

/// How long the resolver has to answer its self-test.
const DNS_SELF_TEST_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the forwarding proof waits: two upstreams tried in turn, each for the resolver's own
/// upstream timeout (3 s), plus a margin.
const DNS_FORWARD_PROOF_TIMEOUT: Duration = Duration::from_secs(7);

/// The upstreams to forward to, in order of trust: what the person set (*saved*, after a
/// restart), else what the system resolves with now, else what this network handed out by DHCP.
/// Empty when none is known — never a public resolver nobody chose.
fn known_upstreams(enforcer: &impl Enforcer, saved: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    pick_upstreams(saved.to_vec(), || enforcer.current_upstreams(), || enforcer.dhcp_upstreams())
}

fn pick_upstreams(saved: Vec<std::net::SocketAddr>, current: impl FnOnce() -> Vec<std::net::SocketAddr>,
                  dhcp: impl FnOnce() -> Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    if !saved.is_empty() { return saved; }
    let now = current();
    if !now.is_empty() { now } else { dhcp() }
}


pub fn run() -> Result<(), String> {
    if !platform::SUPPORTED {
        return Err("Blackbox's system protection helper does not support this operating system yet".into());
    }
    private_files::ensure_dir(Path::new(HOME)).map_err(|error| format!("{HOME}: {error}"))?;
    let mut state = State::load();
    // After a reboot the saved pf token is meaningless: drop it, so the first plan enables pf and
    // verifies it (Enforcer::apply_filter) instead of trusting a token from another boot.
    let enforcer = SystemEnforcer::default();
    let boot = enforcer.boot_time();
    if state.boot != boot {
        state.pf_token = None;
        state.boot = boot;
        state.save();
    }
    let saved = if state.dns_active { enforcer.upstreams_from_saved(&state.saved_dns) } else { vec![] };
    let upstreams = known_upstreams(&enforcer, &saved);
    let helper = Arc::new(Helper {
        resolver: dns::Resolver::new(upstreams),
        state: Mutex::new(state),
        link: Mutex::new(link::Link::new(Path::new(HOME))?),
        last_error: Mutex::new(None),
        failures: Mutex::new(Failures::default()),
        applied: Mutex::new(String::new()),
        watching: AtomicBool::new(false),
        enforcer,
        observer: SystemObserver::default(),
        ended: Mutex::new(HashSet::new()),
        kept: Mutex::new(crate::plan::Kept::default()),
        filtered: Mutex::new(filter_keeper::FilterKeeper::default()),
        dns_wanted: AtomicBool::new(false),
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
        thread::sleep(<SystemObserver as Observer>::WATCH_EVERY);
    });
    // Exposure, persistence, tampering and posture (+ posture fixes, the DNS tamper guard): its own
    // small plan and report (system_guard), so neither loop waits on the other.
    // Every helper thread is named (`named`), so a crash log says which one it was. The stack
    // overflow first seen on a test VM was NOT stack size: it was the macOS log reader's
    // stop/Drop recursion (fixed there, with a regression test). The larger stack stays as headroom.
    let guard = helper.clone();
    let _ = thread::Builder::new().name("blackbox-system-guard".into()).stack_size(<SystemObserver as Observer>::SYSTEM_WATCH_STACK)
        .spawn(move || guard.observer.run_system_watch());
    // File Shield's real-time watch: its own small plan and report (platform/<os>/file_shield).
    let files = helper.clone();
    named("blackbox-file-watch", move || files.observer.run_file_watch());
    let remoter = helper.clone();
    named("blackbox-netd-remote", move || loop {
        remoter.look_remote();
        thread::sleep(<SystemObserver as Observer>::REMOTE_EVERY);
    });

    helper.apply_saved_plan();   // no gap after a restart or an upgrade (last_plan)
    crate::handover::clear(Path::new(HOME));   // taken over: the next ordinary stop puts the Mac back
    loop {
        if STOPPING.load(Ordering::SeqCst) {
            helper.stop();
            return Ok(());
        }
        // What is in effect first, then the plan. WHY the order (fix wave W12, macOS VM after a helper
        // restart: DNS Shield came back 50 s later; Linux round L5: the firewall ~60 s after boot):
        // reading the plan can wait on a busy or starting dashboard for up to PLAN_TIMEOUT, and the
        // checks that put the last applied plan back must not wait behind it.
        helper.keep_dns_safe();
        helper.keep_filter_intact();
        helper.follow_plan();
        let every = if helper.watching.load(Ordering::SeqCst) { PLAN_EVERY_WATCHING } else { PLAN_EVERY };
        for _ in 0..(every.as_millis() / 200) {
            if STOPPING.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn each_protection_reports_whether_it_applied_and_why_not() {
        let state = State { dns_active: false, firewall_active: true, ..Default::default() };
        let failures = Failures { dns: Some("no DNS server known".into()), filter: None };
        let report = protections(&state, &failures, InEffect { dns: true, filter: true });
        assert_eq!(report["dns"]["applied"], false);
        assert_eq!(report["dns"]["error"], "no DNS server known");
        assert_eq!(report["firewall"]["applied"], true);
        assert!(report["firewall"]["error"].is_null());
    }

    /// Review finding 2026-11-26 (LES-166): every firewall-backed protection reads off once the
    /// rules are seen gone (`nft flush table inet blackbox_netd`), whatever the saved state says.
    #[test]
    fn a_protection_whose_rules_were_removed_is_not_reported_as_applied() {
        let state = State { dns_active: true, firewall_active: true, cut_active: true, ssh_lockdown_active: true,
                            remote_lock_active: true, ..Default::default() };
        let flushed = protections(&state, &Failures::default(), InEffect { dns: true, filter: false });
        for part in ["firewall", "cut", "ssh_lockdown", "remote_lock"] {
            assert_eq!(flushed[part]["applied"], false, "{part}");
        }
        assert_eq!(flushed["dns"]["applied"], true);
        let dns_reset = protections(&state, &Failures::default(), InEffect { dns: false, filter: true });
        assert_eq!(dns_reset["dns"]["applied"], false);
        assert_eq!(dns_reset["remote_lock"]["applied"], true);
    }


    #[test]
    fn a_plan_read_again_clears_the_read_failure_but_not_what_did_not_apply() {
        // KI-701: an unchanged plan read after a failed read left "the plan could not be read".
        assert_eq!(Failures::default().still_failing(), None);
        let failures = Failures { dns: None, filter: Some("pf did not stay enabled".into()) };
        assert_eq!(failures.still_failing().as_deref(), Some("pf did not stay enabled"));
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
