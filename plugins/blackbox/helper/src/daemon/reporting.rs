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
        // Which name each looked-up address was asked as (KI-588) — under its own key, so an older
        // plugin ignores it.
        let resolved: Vec<Value> = self.resolver.drain_resolved().into_iter()
            .map(|(ip, (domain, ts))| json!({"ip": ip.to_string(), "domain": domain, "ts": ts}))
            .collect();
        let snapshot = if self.watching.load(Ordering::SeqCst) { self.observer.watch_snapshot() } else { None };
        let pf_on = state.firewall_active || state.cut_active || state.ssh_lockdown_active || state.remote_lock_active;
        // What is really enforced (KI-695): a filter another root program flushed, emptied or
        // switched off is not "active" until it is loaded again (`keep_filter_intact`).
        // Every firewall-backed flag (threats, cut, SSH lockdown, remote lock) and DNS is ANDed with
        // what is measured in effect (LES-166), here and in `protections`.
        let in_effect_filter = self.filtered.lock().ok().and_then(|keeper| keeper.in_effect());
        let in_effect = InEffect {
            dns: self.enforcer.dns_in_effect() != Some(false),
            filter: in_effect_filter.is_none_or(|filter| self.enforcer.filter_intact(&filter) != Some(false)),
        };
        let remote = if self.watching.load(Ordering::SeqCst) { self.observer.remote_snapshot() } else { None };
        let failures = self.failures.lock().map(|f| f.clone()).unwrap_or_default();
        json!({
            "running": true, "dns_active": state.dns_active && in_effect.dns, "firewall_active": state.firewall_active && in_effect.filter,
            "cut_active": state.cut_active && in_effect.filter, "ssh_lockdown_active": state.ssh_lockdown_active && in_effect.filter,
            "version": state.version, "queries": self.resolver.queries.load(std::sync::atomic::Ordering::Relaxed),
            // What the person needs to trust the screen: whether the link is authenticated and the
            // last thing that failed (null when everything applied).
            "auth": self.link.lock().map(|link| link.mode()).unwrap_or("broken"),
            "last_error": self.last_error.lock().ok().and_then(|e| e.clone()),
            "resolver_ok": self.resolver.alive.load(Ordering::SeqCst),
            "dns_error": failures.dns,
            "filter_error": failures.filter,
            "protections": protections(&state, &failures, in_effect),
            "firewall_dropped": if pf_on { self.enforcer.dropped() } else { 0 },
            // What is really enforced, not what was asked: pf must be seen Enabled.
            "pf_enabled": if pf_on { self.enforcer.filter_enabled() } else { None },
            "blocks": blocks, "resolved": resolved, "watch": snapshot, "events": events,
            // Under its own key, so a plugin that predates it ignores it instead of refusing the report.
            "remote": remote.map(|snapshot| json!({"snapshot": snapshot, "events": remote_events, "lock_active": state.remote_lock_active && in_effect.filter})),
        })
    }

    pub(super) fn report(&self) {
        let remote_on = self.observer.remote_snapshot().is_some();
        let (watch_events, remote_events) = self.observer.drain();
        // While the remote watch runs it reports SSH sessions in full; the older SSH events would repeat them.
        let events: Vec<Value> = watch_events.into_iter()
            .filter(|event| !(remote_on && event["kind"].as_str().is_some_and(|kind| kind.starts_with("ssh-session"))))
            .collect();
        let body = self.report_body(events.clone(), remote_events.clone());
        // Only to a server that proved it is Blackbox's plugin; signed ([`link`]).
        if self.link.lock().unwrap().post(REPORT_PATH, &body, REPORT_TIMEOUT) {
            return;
        }
        // Not delivered (the plugin away, or not proven): keep the events for the next report.
        self.observer.requeue(events, remote_events);
    }

    /// Puts the system back: DNS settings restored, the firewall's rules removed and it released.
    /// The service stops (launchd's SIGTERM: a repair, an update, a removal). DNS and the pf
    /// rules need the running helper, so they are put back — except in an upgrade's hand-over, when the
    /// next helper takes them over at once; posture hardening is NOT — it keeps
    /// the Mac safe without the helper ([`undo_for`]).
    pub(super) fn stop(&self) {
        // An upgrade hands over to the next helper: the Mac's protection stays in place (KI-537).
        let how = if crate::handover::pending(Path::new(HOME), SystemTime::now()) { Stopping::Handover } else { Stopping::Service };
        let undo = undo_for(how);
        if undo.dns { let _ = self.set_dns(false); }
        if undo.filter { let _ = self.set_filter(&Plan::default()); }
        self.watching.store(false, Ordering::SeqCst);
        self.observer.stop();
        if undo.hardening { self.enforcer.undo_hardening(); }
    }
}
