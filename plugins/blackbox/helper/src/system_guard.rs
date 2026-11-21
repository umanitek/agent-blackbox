//! The system watch: exposure, persistence, tampering and posture (observe), and their two
//! protections — posture fixes and the DNS tamper guard (enforce). Runs in its own thread beside
//! the plan / report loop in [`super`], with its own small plan and report so the two never wait
//! on each other:
//!
//! * every [`PLAN_EVERY`]: `GET …/api/system-plan` → whether to watch (Network Shield on), the
//!   posture fixes the person asked for, the tamper guard, and a counter that asks for a fresh
//!   posture look;
//! * every [`TICK`] while watching: listeners (exposure) — then on their own cadence persistence
//!   (folders 5 s, commands 60 s, kernel extensions 300 s), tampering (5 s), posture (60 s);
//! * `POST …/api/system-report` at once when an event happened, else every [`REPORT_EVERY`].
//!
//! Off (the plugin says so; an unreachable plugin keeps the last plan): nothing is watched and every applied fix is
//! undone; the next watch starts from a fresh baseline. On helper stop: [`stop`] undoes the fixes.
//!
//! It talks to the plugin through its own [`crate::link::Link`] (the same authenticated link:
//! plans verified, reports signed and sent only to a server that proved the key).

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use super::enforce::{posture::Fixes, restore};
use super::observe::{exposure, persistence, posture, tamper};
use crate::sockets::Reader;

const PLAN_PATH: &str = "/api/shields/network-shield/api/system-plan";
const REPORT_PATH: &str = "/api/shields/network-shield/api/system-report";
pub const TICK: Duration = Duration::from_secs(1);
pub const PLAN_EVERY: Duration = Duration::from_secs(2);
pub const REPORT_EVERY: Duration = Duration::from_secs(10);
const TIMEOUT: Duration = Duration::from_secs(10);
/// The loop's thread stack (larger than Rust's 2 MiB default: the root-run looks are big).
pub const STACK_BYTES: usize = 8 * 1024 * 1024;

/// The small plan this loop follows (all off by default: an old plugin or none means off).
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct SystemPlan {
    pub watch: bool,
    pub posture_fixes: Vec<String>,
    pub tamper_guard: bool,
    pub posture_refresh: u64,
}

static FIXES: OnceLock<Mutex<Fixes>> = OnceLock::new();

fn fixes() -> &'static Mutex<Fixes> {
    FIXES.get_or_init(|| Mutex::new(Fixes::load(std::path::Path::new(super::HOME).join("posture-fixes.json"))))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Whether DNS Shield is applied now (the plan / report loop's saved state).
fn dns_active() -> bool {
    std::fs::read_to_string(std::path::Path::new(super::HOME).join("state.json")).ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v["dns_active"].as_bool()).unwrap_or(false)
}

struct Client {
    link: crate::link::Link,
}

impl Client {
    /// The plan when the verified plugin answers; None keeps the last one (never undone for it).
    fn plan(&mut self) -> Option<SystemPlan> {
        match self.link.plan::<SystemPlan>(PLAN_PATH, "", TIMEOUT) {
            crate::link::Fetched::Plan(plan) => Some(plan),
            crate::link::Fetched::Refused(_) => None,
        }
    }

    fn post(&mut self, body: &Value) {
        let _ = self.link.post(REPORT_PATH, body, TIMEOUT);
    }
}

/// Everything the loop remembers between ticks.
#[derive(Default)]
struct Watchers {
    exposure: exposure::Exposure,
    persistence: persistence::Persistence,
    tamper: tamper::Tamper,
    posture: Value,
    last_posture: Option<Instant>,
    last_folders: Option<Instant>,
    last_commands: Option<Instant>,
    last_kexts: Option<Instant>,
    last_tamper: Option<Instant>,
    posture_refresh: u64,
    events: Vec<Value>,
}

impl Watchers {
    fn due(last: Option<Instant>, every: Duration) -> bool {
        last.is_none_or(|at| at.elapsed() >= every)
    }

    fn tick(&mut self, reader: &mut Reader, plan: &SystemPlan) -> bool {
        let at = now();
        let found = exposure::listeners(&reader.sockets(), &exposure::program_of);
        let ports: BTreeSet<u16> = found.iter().filter(|l| l.protocol.starts_with("tcp")).map(|l| l.port).collect();
        let mut happened = self.exposure.tick(found, at);
        if Self::due(self.last_folders, persistence::FOLDERS_EVERY) {
            self.last_folders = Some(Instant::now());
            let kinds = ["launch-agent", "launch-daemon", "user-agent", "cron", "periodic"];
            happened |= self.persistence.update(&kinds, persistence::file_items(&self.persistence.known()), at);
        }
        if Self::due(self.last_commands, persistence::COMMANDS_EVERY) {
            let with_kexts = Self::due(self.last_kexts, persistence::KEXTS_EVERY);
            self.last_commands = Some(Instant::now());
            if with_kexts { self.last_kexts = Some(Instant::now()); }
            for (kind, items) in persistence::command_items(with_kexts) {
                if let Some(items) = items { happened |= self.persistence.update(&[kind], items, at); }
            }
            self.persistence.baseline_done();   // files and commands have both been looked at once
        }
        if Self::due(self.last_tamper, tamper::TAMPER_EVERY) {
            self.last_tamper = Some(Instant::now());
            happened |= self.tamper.tick(tamper::look(), at);
            if let Some(event) = restore::guard_dns(plan.tamper_guard, dns_active(), &self.tamper.dns_servers(), at) {
                self.events.push(event);
                happened = true;
            }
        }
        if plan.posture_refresh != self.posture_refresh || Self::due(self.last_posture, posture::POSTURE_EVERY) {
            self.posture_refresh = plan.posture_refresh;
            self.last_posture = Some(Instant::now());
            self.posture = posture::look(&ports);
            happened = true;
        }
        happened
    }

    fn report(&mut self, fix_events: Vec<Value>) -> Value {
        let mut events = std::mem::take(&mut self.events);
        events.extend(self.exposure.take_events());
        events.extend(self.persistence.take_events());
        events.extend(self.tamper.take_events());
        let at = now();
        events.extend(fix_events.into_iter().map(|mut e| { e["ts"] = json!(at); e }));
        json!({"watching": true, "at": at, "exposure": self.exposure.snapshot(), "persistence": self.persistence.snapshot(),
               "tamper": self.tamper.snapshot(), "posture": self.posture, "fixes": fixes().lock().map(|f| f.applied()).unwrap_or_default(),
               "events": events})
    }
}

/// The loop (started by the helper; runs until the process ends).
pub fn run() {
    let Ok(link) = crate::link::Link::new(std::path::Path::new(super::HOME)) else { return };
    let mut client = Client { link };
    let mut reader = Reader::default();
    let mut watchers = Watchers::default();
    let mut plan = SystemPlan::default();
    let (mut last_plan, mut last_report): (Option<Instant>, Option<Instant>) = (None, None);
    loop {
        if Watchers::due(last_plan, PLAN_EVERY) {
            last_plan = Some(Instant::now());
            // An unreachable plugin keeps the last plan: a dashboard restart must not undo and
            // re-apply fixes (that would switch the person's firewall off and on). Only an
            // explicit "watch": false from the plugin turns everything off.
            if let Some(fresh) = client.plan() { plan = fresh; }
        }
        let fix_events = fixes().lock().map(|mut f| f.follow(if plan.watch { &plan.posture_fixes } else { &[] })).unwrap_or_default();
        if !plan.watch {
            watchers = Watchers::default();
            if !fix_events.is_empty() { client.post(&json!({"watching": false, "at": now(), "events": fix_events})); }
            thread::sleep(PLAN_EVERY);
            continue;
        }
        let happened = watchers.tick(&mut reader, &plan) || !fix_events.is_empty();
        if happened || Watchers::due(last_report, REPORT_EVERY) {
            last_report = Some(Instant::now());
            let body = watchers.report(fix_events);
            client.post(&body);
        }
        thread::sleep(TICK);
    }
}

/// The helper stops: every applied posture fix is reversed.
/// Reverses every posture fix — only on the person's explicit choice ([`crate::undo_for`]).
pub fn undo_hardening() {
    if let Ok(mut f) = fixes().lock() {
        let _ = f.undo_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_or_older_plan_means_off() {
        let plan: SystemPlan = serde_json::from_str("{}").unwrap();
        assert!(!plan.watch && plan.posture_fixes.is_empty() && !plan.tamper_guard);
        let plan: SystemPlan = serde_json::from_str(r#"{"watch":true,"posture_fixes":["firewall-on"],"tamper_guard":true,"posture_refresh":3}"#).unwrap();
        assert_eq!(plan, SystemPlan { watch: true, posture_fixes: vec!["firewall-on".into()], tamper_guard: true, posture_refresh: 3 });
    }
}

#[cfg(test)]
mod stack_tests {
    use super::*;

    /// Each observer runs in a thread with Rust's default 2 MiB stack, as in the helper.
    #[test]
    #[ignore]
    fn every_look_fits_a_default_thread_stack() {
        for (name, look) in [
            ("exposure", (|| { let mut r = Reader::default(); let _ = exposure::listeners(&r.sockets(), &exposure::program_of); }) as fn()),
            ("files", || { let _ = persistence::file_items(&Default::default()); }),
            ("commands", || { let _ = persistence::command_items(true); }),
            ("tamper", || { let _ = tamper::look(); }),
            ("posture", || { let _ = posture::look(&BTreeSet::new()); }),
        ] {
            let done = thread::Builder::new().stack_size(2 * 1024 * 1024).spawn(look).unwrap().join();
            assert!(done.is_ok(), "{name}");
            eprintln!("{name}: ok");
        }
    }
}
