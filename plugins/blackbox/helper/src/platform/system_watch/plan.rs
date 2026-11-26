//! The system watch loop's talk with the plugin, the same on every OS: the small plan it follows
//! (`GET …/api/system-plan`: whether to watch, the posture fixes asked for, the DNS tamper guard,
//! a counter that asks for a fresh posture look), the report it sends (`POST …/api/system-report`)
//! through the helper's authenticated [`crate::link::Link`], the loop's cadence, and the bound on
//! one report's events. Each OS's `system_guard` runs the loop with its own readers.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

/// The most events one report carries (the dashboard's `system_report.MAX_EVENTS_PER_REPORT`).
pub const MAX_EVENTS_PER_REPORT: usize = 300;
const PLAN_PATH: &str = "/api/shields/network-shield/api/system-plan";
const REPORT_PATH: &str = "/api/shields/network-shield/api/system-report";
pub const TICK: Duration = Duration::from_secs(1);
pub const PLAN_EVERY: Duration = Duration::from_secs(2);
pub const REPORT_EVERY: Duration = Duration::from_secs(10);
const TIMEOUT: Duration = Duration::from_secs(10);
/// The loop's thread stack (larger than Rust's 2 MiB default: the root-run looks are big).
pub const STACK_BYTES: usize = 8 * 1024 * 1024;
/// The most run-later items kept (every PATH folder entry on a machine).
pub const RUN_LATER_CAP: usize = 20_000;

/// The small plan the loop follows (all off by default: an old plugin or none means off).
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct SystemPlan {
    pub watch: bool,
    pub posture_fixes: Vec<String>,
    pub tamper_guard: bool,
    pub posture_refresh: u64,
}

/// The plugin, as the loop reaches it.
pub struct Client {
    link: crate::link::Link,
}

impl Client {
    pub fn new(link: crate::link::Link) -> Client {
        Client { link }
    }

    /// The plan when the verified plugin answers; None keeps the last one (never undone for it).
    pub fn plan(&mut self) -> Option<SystemPlan> {
        match self.link.plan::<SystemPlan>(PLAN_PATH, "", TIMEOUT) {
            crate::link::Fetched::Plan(plan) => Some(plan),
            crate::link::Fetched::Refused(_) => None,
        }
    }

    pub fn post(&mut self, body: &Value) {
        let _ = self.link.post(REPORT_PATH, body, TIMEOUT);
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// True when *every* has passed since *last* (or it never ran).
pub fn due(last: Option<Instant>, every: Duration) -> bool {
    last.is_none_or(|at| at.elapsed() >= every)
}

/// Whether DNS Shield is applied now (the plan / report loop's saved state in *home*).
pub fn dns_active(home: &std::path::Path) -> bool {
    std::fs::read_to_string(home.join("state.json")).ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v["dns_active"].as_bool()).unwrap_or(false)
}

/// Keeps *events* to one report's worth and answers the rest for the next report: the dashboard
/// refuses a longer report; a flood loses its oldest tail, never memory.
pub fn cap_events(events: &mut Vec<Value>) -> Vec<Value> {
    if events.len() <= MAX_EVENTS_PER_REPORT {
        return Vec::new();
    }
    let mut rest = events.split_off(MAX_EVENTS_PER_REPORT);
    rest.truncate(MAX_EVENTS_PER_REPORT);
    rest
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

    #[test]
    fn a_report_carries_at_most_its_bound() {
        let mut events: Vec<Value> = (0..MAX_EVENTS_PER_REPORT * 3).map(|n| Value::from(n as u64)).collect();
        let rest = cap_events(&mut events);
        assert_eq!((events.len(), rest.len()), (MAX_EVENTS_PER_REPORT, MAX_EVENTS_PER_REPORT));
    }
}
