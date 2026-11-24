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
use std::time::Instant;

use serde_json::{json, Value};

use super::enforce::{posture::Fixes, restore};
use super::observe::{exposure, persistence, posture, run_later, tamper};
use crate::platform::system_watch::plan::{cap_events, dns_active, due, now, Client, SystemPlan, PLAN_EVERY, REPORT_EVERY, RUN_LATER_CAP, TICK};
pub use crate::platform::system_watch::plan::STACK_BYTES;

use crate::platform::macos::sockets::Reader;

static FIXES: OnceLock<Mutex<Fixes>> = OnceLock::new();

fn fixes() -> &'static Mutex<Fixes> {
    FIXES.get_or_init(|| Mutex::new(Fixes::load(std::path::Path::new(super::HOME).join("posture-fixes.json"))))
}

/// Everything the loop remembers between ticks.
#[derive(Default)]
struct Watchers {
    exposure: exposure::Exposure,
    persistence: persistence::Persistence,
    /// Shell startup files, OpenSSH's login files, `at` jobs and PATH programs (`run_later`); its
    /// items are not in the report's snapshot (thousands of links), only its events.
    run_later: persistence::Persistence,
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
    fn tick(&mut self, reader: &mut Reader, plan: &SystemPlan) -> bool {
        let at = now();
        let found = exposure::listeners(&reader.sockets(), &exposure::program_of);
        let ports: BTreeSet<u16> = found.iter().filter(|l| l.protocol.starts_with("tcp")).map(|l| l.port).collect();
        let mut happened = self.exposure.tick(found, at);
        if due(self.last_folders, persistence::FOLDERS_EVERY) {
            self.last_folders = Some(Instant::now());
            let kinds = ["launch-agent", "launch-daemon", "user-agent", "cron", "periodic"];
            happened |= self.persistence.update(&kinds, persistence::file_items(&self.persistence.known()), at);
            happened |= self.run_later.update_capped(run_later::KINDS, run_later::items(&run_later::homes()), at, RUN_LATER_CAP);
            self.run_later.baseline_done();
        }
        if due(self.last_commands, persistence::COMMANDS_EVERY) {
            let with_kexts = due(self.last_kexts, persistence::KEXTS_EVERY);
            self.last_commands = Some(Instant::now());
            if with_kexts { self.last_kexts = Some(Instant::now()); }
            for (kind, items) in persistence::command_items(with_kexts) {
                if let Some(items) = items { happened |= self.persistence.update(&[kind], items, at); }
            }
            self.persistence.baseline_done();   // files and commands have both been looked at once
        }
        if due(self.last_tamper, tamper::TAMPER_EVERY) {
            self.last_tamper = Some(Instant::now());
            happened |= self.tamper.tick(tamper::look(), at);
            if let Some(event) = restore::guard_dns(plan.tamper_guard, dns_active(std::path::Path::new(super::HOME)), &self.tamper.dns_servers(), at) {
                self.events.push(event);
                happened = true;
            }
        }
        if plan.posture_refresh != self.posture_refresh || due(self.last_posture, posture::POSTURE_EVERY) {
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
        events.extend(self.run_later.take_events());
        self.events = cap_events(&mut events);
        json!({"watching": true, "at": at, "exposure": self.exposure.snapshot(), "persistence": self.persistence.snapshot(),
               "tamper": self.tamper.snapshot(), "posture": self.posture, "fixes": fixes().lock().map(|f| f.applied()).unwrap_or_default(),
               "events": events})
    }
}

/// The loop (started by the helper; runs until the process ends).
pub fn run() {
    let Ok(link) = crate::link::Link::new(std::path::Path::new(super::HOME)) else { return };
    let mut client = Client::new(link);
    let mut reader = Reader::default();
    let mut watchers = Watchers::default();
    let mut plan = SystemPlan::default();
    let (mut last_plan, mut last_report): (Option<Instant>, Option<Instant>) = (None, None);
    loop {
        if due(last_plan, PLAN_EVERY) {
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
        if happened || due(last_report, REPORT_EVERY) {
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
