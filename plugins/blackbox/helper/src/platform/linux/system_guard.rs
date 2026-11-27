//! The system watch on Linux: exposure, persistence, the run-later places, tampering and posture
//! (the phase-A readers in [`super::observe`]), and the DNS tamper guard — the same loop, plan and
//! report as macOS's (the talk with the plugin is every OS's: `platform/system_watch/plan.rs`):
//!
//! * every `PLAN_EVERY`: the small plan (watch, the DNS tamper guard, a fresh posture look);
//! * every `TICK` while watching: listeners (exposure) — then on their own cadence persistence
//!   and the run-later places (5 s), tampering (5 s) and posture (60 s);
//! * a report at once when an event happened, else every `REPORT_EVERY`.
//!
//! Posture fixes are report-only on Linux for now (design decision F8): the plan's
//! `posture_fixes` are read and none is applied, so the report's `fixes` stays empty. The DNS
//! tamper guard (opt-in) re-asserts DNS Shield when someone points the system's DNS elsewhere
//! while it is on (`enforce::dns::drifted` → the same `point` that switched it on); the servers
//! saved when DNS Shield was switched on stay the ones restored later.

use std::collections::BTreeSet;
use std::path::Path;
use std::thread;
use std::time::Instant;

use serde_json::{json, Value};

use super::enforce::dns;
use super::observe::{exposure, persistence, posture, run_later, tamper};
use super::sockets::Reader;
use crate::platform::system_watch::plan::{cap_events, dns_active, due, now, Client, SystemPlan, PLAN_EVERY, REPORT_EVERY, RUN_LATER_CAP, TICK};
pub use crate::platform::system_watch::plan::STACK_BYTES;

/// Everything the loop remembers between ticks.
#[derive(Default)]
struct Watchers {
    exposure: exposure::Exposure,
    persistence: crate::platform::system_watch::items::Persistence,
    run_later: crate::platform::system_watch::items::Persistence,
    tamper: crate::platform::system_watch::tamper::Tamper,
    posture: Value,
    last_posture: Option<Instant>,
    last_folders: Option<Instant>,
    last_tamper: Option<Instant>,
    posture_refresh: u64,
    events: Vec<Value>,
}

/// The tamper guard's answer: DNS Shield re-asserted (or why not) when it is on, guarded and drifted.
pub fn guard_dns(guard: bool, active: bool, view: &dns::DnsView, at: u64) -> Option<Value> {
    if !guard || !active || !dns::drifted(view) {
        return None;
    }
    let (actions, _saved) = dns::point(view, &crate::platform::SavedDns::new());   // the original servers stay the ones saved at switch-on
    let errors = dns::run(&actions);
    Some(if errors.is_empty() { json!({"kind": "dns-restored", "ts": at, "was": tamper::dns_servers()}) }
         else { json!({"kind": "dns-restore-failed", "ts": at, "error": errors.join("; ").chars().take(300).collect::<String>()}) })
}

impl Watchers {
    fn tick(&mut self, reader: &mut Reader, plan: &SystemPlan) -> bool {
        let at = now();
        let found = exposure::listeners(&reader.sockets(), &exposure::program_of);
        let ports: BTreeSet<u16> = found.iter().filter(|l| l.protocol.starts_with("tcp")).map(|l| l.port).collect();
        let mut happened = self.exposure.tick(found, at);
        if due(self.last_folders, persistence::FOLDERS_EVERY) {
            self.last_folders = Some(Instant::now());
            let homes = persistence::homes();
            happened |= self.persistence.update(persistence::KINDS, persistence::file_items(&homes, &self.persistence.known()), at);
            happened |= self.run_later.update_capped(run_later::KINDS, run_later::items(&homes), at, RUN_LATER_CAP);
            self.persistence.baseline_done();
            self.run_later.baseline_done();
        }
        if due(self.last_tamper, tamper::TAMPER_EVERY) {
            self.last_tamper = Some(Instant::now());
            happened |= self.tamper.tick(tamper::look(), at);
            if let Some(event) = guard_dns(plan.tamper_guard, dns_active(Path::new(super::HOME)), &dns::read_view(), at) {
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

    fn report(&mut self) -> Value {
        let mut events = std::mem::take(&mut self.events);
        events.extend(self.exposure.take_events());
        events.extend(self.persistence.take_events());
        events.extend(self.tamper.take_events());
        events.extend(self.run_later.take_events());
        self.events = cap_events(&mut events);
        json!({"watching": true, "at": now(), "exposure": self.exposure.snapshot(), "persistence": self.persistence.snapshot(),
               "tamper": self.tamper.snapshot(), "posture": self.posture, "fixes": [], "events": events})
    }
}

/// The loop (started by the helper; runs until the process ends).
pub fn run() {
    let Ok(link) = crate::link::Link::new(Path::new(super::HOME)) else { return };
    let mut client = Client::new(link);
    let mut reader = Reader::default();
    let mut watchers = Watchers::default();
    let mut plan = SystemPlan::default();
    let (mut last_plan, mut last_report): (Option<Instant>, Option<Instant>) = (None, None);
    loop {
        if due(last_plan, PLAN_EVERY) {
            last_plan = Some(Instant::now());
            // An unreachable plugin keeps the last plan; only an explicit "watch": false turns it off.
            if let Some(fresh) = client.plan() { plan = fresh; }
        }
        if !plan.watch {
            watchers = Watchers::default();
            thread::sleep(PLAN_EVERY);
            continue;
        }
        let happened = watchers.tick(&mut reader, &plan);
        if happened || due(last_report, REPORT_EVERY) {
            last_report = Some(Instant::now());
            let body = watchers.report();
            client.post(&body);
        }
        thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dns_guard_acts_only_when_guarded_on_and_drifted() {
        let view = dns::DnsView::default();
        assert!(guard_dns(false, true, &view, 1).is_none(), "the guard is opt-in");
        assert!(guard_dns(true, false, &view, 1).is_none(), "DNS Shield off: nothing to guard");
    }
}
