//! Reporting to the plugin, and stopping.

#[allow(unused_imports)]
use super::*;

impl Helper {
    /// The report body: running, what is active, counters, the names refused since last time, and
    /// (while watching) the watch snapshot and the events not yet reported.
    pub(super) fn report_body(&self, events: Vec<Value>, remote_events: Vec<Value>) -> Value {
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

    pub(super) fn report(&self) {
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
    pub(super) fn stop(&self) {
        let undo = undo_for(Stopping::Service);
        if undo.dns { let _ = self.set_dns(false); }
        if undo.filter { let _ = self.set_filter(&Plan::default()); }
        self.watching.store(false, Ordering::SeqCst);
        self.logs.lock().unwrap().stop();
        if undo.hardening { system_guard::undo_hardening(); }
    }
}
