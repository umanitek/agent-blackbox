//! File Shield's real-time watch: what to watch comes from the plugin, each change goes back to it.
//! Runs in its own thread beside the plan / report loop and the system watch, with its own small
//! plan and report so none waits on another:
//!
//! * every [`PLAN_EVERY`]: `GET …/file-shield/api/watch-plan` (signed for this helper's nonce) →
//!   whether to watch and which absolute paths (every protected item and watched folder);
//! * an FSEvents stream over the paths that exist ([`super::observe::file_watch`]), started again
//!   when the set changes;
//! * each change, batched for [`BATCH`] (FSEvents delivers in bursts), `POST …/file-report`,
//!   signed — so the person sees it within about a second.
//!
//! An unreachable plugin keeps the last plan (a dashboard restart never stops the watch); only an
//! explicit `"watch": false` stops it. The plugin checks every path again and keeps only those
//! inside its current items and folders: the helper reports, the plugin decides.

use std::path::Path;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use super::observe::file_watch::{Change, Watch};

const PLAN_PATH: &str = "/api/shields/file-shield/api/watch-plan";
const REPORT_PATH: &str = "/api/shields/file-shield/api/file-report";
pub const PLAN_EVERY: Duration = Duration::from_secs(2);
/// How long changes are gathered before one report (FSEvents delivers in bursts).
pub const BATCH: Duration = Duration::from_millis(300);
const TIMEOUT: Duration = Duration::from_secs(10);
/// Most paths one plan may name, and most events one report carries (the plugin's own limit).
pub const MAX_PATHS: usize = 256;
pub const MAX_EVENTS: usize = 200;
const MAX_PATH_CHARS: usize = 1024;

/// The small plan this loop follows (off by default: an old plugin or none means off).
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct WatchPlan {
    pub watch: bool,
    pub paths: Vec<String>,
}

/// The plan's paths this helper may watch: absolute, not the whole disk, no NUL, bounded — and,
/// unless *all*, only those that exist now (FSEvents watches what is there), sorted, no repeats.
pub fn watchable(plan: &WatchPlan, exists: impl Fn(&str) -> bool) -> Vec<String> {
    if !plan.watch {
        return vec![];
    }
    let mut paths: Vec<String> = plan.paths.iter()
        .filter(|p| p.starts_with('/') && p.as_str() != "/" && p.len() <= MAX_PATH_CHARS && !p.contains('\0'))
        .filter(|p| exists(p))
        .take(MAX_PATHS).cloned().collect();
    paths.sort();
    paths.dedup();
    paths
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// One report's body: each change with its time, at most [`MAX_EVENTS`] (the rest wait for the next).
pub fn report(changes: &mut Vec<Change>, at: u64) -> Value {
    let taken: Vec<Change> = changes.drain(..changes.len().min(MAX_EVENTS)).collect();
    json!({"at": at, "events": taken.iter().map(|c| json!({"path": c.path, "kind": c.kind, "ts": at})).collect::<Vec<_>>()})
}

/// The loop (started by the helper; runs until the process ends).
pub fn run() {
    let Ok(mut link) = crate::link::Link::new(Path::new(super::HOME)) else { return };
    let mut plan = WatchPlan::default();
    let mut watching: Vec<String> = vec![];
    let mut stream: Option<(Watch, Receiver<Change>)> = None;
    let mut pending: Vec<Change> = vec![];
    let mut last_plan: Option<Instant> = None;
    loop {
        if last_plan.is_none_or(|at| at.elapsed() >= PLAN_EVERY) {
            last_plan = Some(Instant::now());
            if let crate::link::Fetched::Plan(fresh) = link.plan::<WatchPlan>(PLAN_PATH, "", TIMEOUT) {
                plan = fresh;
            }
            let wanted = watchable(&plan, |p| Path::new(p).exists());
            if wanted != watching {
                stream = None;   // stops the old stream first
                watching = wanted;
                if !watching.is_empty() {
                    let (sender, receiver) = channel();
                    stream = Watch::start(&watching, sender).map(|watch| (watch, receiver));
                }
            }
        }
        let Some((_, receiver)) = &stream else {
            std::thread::sleep(PLAN_EVERY);
            continue;
        };
        match receiver.recv_timeout(PLAN_EVERY) {
            Ok(change) => {
                pending.push(change);
                let started = Instant::now();
                while started.elapsed() < BATCH {
                    match receiver.recv_timeout(BATCH.saturating_sub(started.elapsed())) {
                        Ok(more) => pending.push(more),
                        Err(_) => break,
                    }
                }
                while !pending.is_empty() {
                    let body = report(&mut pending, now());
                    if !link.post(REPORT_PATH, &body, TIMEOUT) {
                        break;   // not delivered: these are dropped (a change is news only now)
                    }
                }
                pending.clear();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => stream = None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_or_older_plan_means_off() {
        let plan: WatchPlan = serde_json::from_str("{}").unwrap();
        assert!(watchable(&plan, |_| true).is_empty());
        let plan: WatchPlan = serde_json::from_str(r#"{"watch":false,"paths":["/Users/me/Downloads"]}"#).unwrap();
        assert!(watchable(&plan, |_| true).is_empty());
    }

    #[test]
    fn only_absolute_existing_bounded_paths_are_watched() {
        let plan = WatchPlan { watch: true, paths: vec!["/Users/me/Taxes".into(), "relative".into(), "/".into(),
            "/Users/me/a\0b".into(), "/Users/me/Taxes".into(), "/Users/me/gone".into(), format!("/{}", "x".repeat(1100))] };
        assert_eq!(watchable(&plan, |p| p != "/Users/me/gone"), vec!["/Users/me/Taxes".to_string()]);
        let many = WatchPlan { watch: true, paths: (0..400).map(|i| format!("/p/{i}")).collect() };
        assert_eq!(watchable(&many, |_| true).len(), MAX_PATHS);
    }

    #[test]
    fn a_report_carries_at_most_the_plugins_limit_and_keeps_the_rest() {
        let mut changes: Vec<Change> = (0..250).map(|i| Change { path: format!("/p/{i}"), kind: "created" }).collect();
        let body = report(&mut changes, 7);
        assert_eq!(body["events"].as_array().unwrap().len(), MAX_EVENTS);
        assert_eq!(body["events"][0], json!({"path": "/p/0", "kind": "created", "ts": 7}));
        assert_eq!(changes.len(), 50);
    }
}
