//! Applying a plan: DNS, the filter, keeping DNS safe.

#[allow(unused_imports)]
use super::*;
use super::filter_keeper::{FilterKeeper, Kept};

impl Helper {
    /// Pulls the plan and applies it when it changed. Keeps the last plan when the plugin is away
    /// or cannot prove it is Blackbox's plugin ([`link`]): nothing is ever undone for that.
    pub(super) fn follow_plan(&self) {
        let have: String = self.applied.lock().map(|applied| applied.clone()).unwrap_or_default()
            .chars().filter(char::is_ascii_alphanumeric).collect();
        let (fetched, body) = {
            let mut link = self.link.lock().unwrap();
            let fetched = link.plan::<Plan>(PLAN_PATH, &format!("have={have}"), PLAN_TIMEOUT);
            (fetched, link.take_body())
        };
        let plan = match fetched {
            link::Fetched::Plan(plan) => plan,
            link::Fetched::Refused(why) => {
                *self.last_error.lock().unwrap() = Some(why);
                return;
            }
        };
        if plan.unchanged {
            // The plan was read: a failure to read it earlier is over (KI-701, macOS round R8: the
            // overview said "the plan could not be read" for minutes after the plan was read again,
            // because only a CHANGED plan cleared it). What the last apply could not do still shows.
            let failures = self.failures.lock().map(|f| f.clone()).unwrap_or_default();
            *self.last_error.lock().unwrap() = failures.still_failing();
            return;
        }
        let complete = !plan.keep_verified;
        self.apply_plan(plan);
        // Only a complete plan replaces the saved one: after a restart an incomplete one (graph
        // down) would come back without the lists it kept.
        if let (true, Some(body)) = (complete, body) {
            last_plan::save(Path::new(HOME), &body);
        }
    }

    /// At start, before the first plan arrives: the last plan this helper applied, again — so a
    /// restart or an upgrade leaves no gap in which DNS Shield refuses nothing and the firewall's
    /// table is empty (E2E 2026-11-21: ~60 s). End requests are NOT carried over: a session the
    /// person ended before the restart is not ended again by an old plan.
    pub(super) fn apply_saved_plan(&self) {
        if let Some(mut plan) = last_plan::load(Path::new(HOME)) {
            plan.remote.end.clear();
            self.apply_plan(plan);
        }
    }

    /// Applies *plan*: the resolver's lists, DNS, the filter, watching; records the version.
    /// An incomplete plan (`keep_verified`) keeps the verified lists last applied first.
    fn apply_plan(&self, mut plan: Plan) {
        if let Ok(kept) = self.kept.lock() {
            plan.keep_from(&kept);
        }
        let lists = plan.take_blocklists();
        if let Ok(mut kept) = self.kept.lock() {
            *kept = plan.kept(&lists);   // the resolver's own set, shared: never a second copy (KI-675)
        }
        let plan = &plan;
        let mut errors = vec![];
        if let Ok(mut current) = self.resolver.lists.write() {
            *current = lists;
        }
        self.dns_wanted.store(plan.dns.enabled, Ordering::SeqCst);
        let dns_error = self.set_dns(plan.dns.enabled);
        let filter_error = self.set_filter(plan);
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

    pub(super) fn set_dns(&self, enabled: bool) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        // WHY "off" also runs with DNS Shield not active but originals saved: a switch that failed
        // half-way pointed some services already, and they must come back too.
        let done = if enabled { state.dns_active } else { !state.dns_active && state.saved_dns.is_empty() };
        if done {
            return None;
        }
        let result = if enabled {
            // Switch the Mac's DNS only to a resolver that is up and answering, with a real
            // upstream to forward to (security finding: a failed bind or an empty upstream list
            // used to take the Mac offline, or send its queries to public resolvers nobody chose).
            let upstreams = known_upstreams(&self.enforcer, &[]);
            if upstreams.is_empty() {
                return Some("DNS Shield stays off: no DNS server of this network is known to forward to".into());
            }
            if !self.resolver_answers() {
                return Some("DNS Shield stays off: Blackbox's resolver is not answering on 127.0.0.1:53".into());
            }
            *self.resolver.upstreams.write().unwrap() = upstreams;
            // The way out proven too, BEFORE the Mac depends on it (KI-649: switched while forwarding
            // did not work yet, nothing resolved for about a minute). The next plan cycle retries.
            if !dns::forwards(dns::LISTEN, DNS_FORWARD_PROOF_TIMEOUT) {
                return Some("DNS Shield stays off for now: Blackbox's resolver could not reach this network's DNS servers yet; it tries again".into());
            }
            let pointed = self.enforcer.point_dns_at_shield(&state.saved_dns);
            keep_originals(&mut state, pointed.saved);
            pointed.error.map_or(Ok(()), Err)
        } else {
            let errors = self.enforcer.restore_dns(&state.saved_dns);
            if errors.is_empty() { state.saved_dns.clear(); Ok(()) } else { Err(errors.join("; ")) }
        };
        if result.is_ok() {
            state.dns_active = enabled;
        }
        state.save();
        result.err()
    }

    /// Whether the resolver is serving and answers a test query now.
    pub(super) fn resolver_answers(&self) -> bool {
        self.resolver.alive.load(Ordering::SeqCst) && dns::self_test(dns::LISTEN, DNS_SELF_TEST_TIMEOUT)
    }

    /// Every plan cycle while DNS Shield is on: follow the network the Mac is on now (its DHCP
    /// servers), and if the resolver died, put the Mac's own DNS back at once and say so — the
    /// next plan turns it on again only when the resolver answers.
    pub(super) fn keep_dns_safe(&self) {
        let (active, partly) = self.state.lock().map(|state| (state.dns_active, !state.dns_active && !state.saved_dns.is_empty()))
            .unwrap_or((false, false));
        let wanted = self.dns_wanted.load(Ordering::SeqCst);
        if partly && (!wanted || !self.resolver_answers()) {
            // A switch that failed half-way left some services on the resolver: put them back when
            // DNS Shield is not wanted or its resolver is not answering (else they resolve nothing).
            let error = self.set_dns(false);
            self.note(Part::Dns, error);
        }
        if !active && wanted {
            // The plan wants DNS Shield on and it is not: switching it on failed (a boot before the
            // resolver or the network answered), or the service's stop at shutdown put the system's
            // DNS back. An unchanged plan is never applied again, so this is where it is retried
            // (security finding 2026-11-25-linux-dns-shield-is-silently-off-after-a, Linux round L5).
            let error = self.set_dns(true);
            if error.is_none() {
                self.observer.record(json!({"kind": "dns-shield-restored", "ts": now()}));
            }
            self.note(Part::Dns, error);
            return;
        }
        if !active {
            return;
        }
        if !self.resolver_answers() {
            let error = self.set_dns(false).unwrap_or_default();
            *self.applied.lock().unwrap() = String::new();   // re-apply the plan in full next time
            self.note(Part::Dns, Some(format!("DNS Shield's resolver stopped answering; the Mac's own DNS was put back {error}").trim().to_string()));
            return;
        }
        self.keep_dns_in_effect();
        let now = self.enforcer.dhcp_upstreams();
        if !now.is_empty() {
            if let Ok(mut upstreams) = self.resolver.upstreams.write() {
                if *upstreams != now { *upstreams = now; }
            }
        }
    }

    /// While DNS Shield is on: when the system's DNS does not really point at the resolver (a
    /// reboot dropped the resolver drop-in, a network change or another program reset it), DNS is
    /// pointed at it again at once and the restoration recorded (`dns-shield-restored`, HIGH in the
    /// plugin). The servers saved when DNS Shield was switched on stay the ones put back later.
    /// WHY (security finding 2026-11-25-linux-dns-shield-is-silently-off-after-a, Linux round L5,
    /// and the same on macOS, fix wave W12): only the SAVED state was trusted — after a reboot the
    /// machine used the router's DNS, listed domains resolved, and dns_active said true for minutes.
    fn keep_dns_in_effect(&self) {
        if self.enforcer.dns_in_effect() != Some(false) {
            return;
        }
        let Ok(mut state) = self.state.lock() else { return };
        let pointed = self.enforcer.point_dns_at_shield(&state.saved_dns);
        keep_originals(&mut state, pointed.saved);
        state.save();
        drop(state);
        if pointed.error.is_none() {
            self.observer.record(json!({"kind": "dns-shield-restored", "ts": now()}));
            self.wake.now();
        }
        self.note(Part::Dns, pointed.error.map(|error| format!("DNS Shield was not in effect and could not be put back: {error}")));
    }

    /// Every plan cycle (every 3 s while the shield watches): a filter whose apply failed is tried
    /// again, and when the firewall no longer holds the rules last applied — another program (root)
    /// flushed, deleted or edited Blackbox's table — they are loaded again at once, in one
    /// transaction, and the restoration is recorded (`firewall-restored`, HIGH in the plugin); a
    /// failure stays in [`Failures`] until it is fixed. WHY (KI-688, Linux round L4): nothing
    /// looked; the rules came back only when the plan next changed, 90–150 s once the threat graph
    /// was complete. The look is cheap (two chain listings, never the sets' elements) and keeps
    /// its pace (LES-141); the plan is not fetched again for it (a complete one is ~45 MB).
    pub(super) fn keep_filter_intact(&self) {
        match self.with_filter(|keeper, apply, intact| keeper.keep(apply, intact)) {
            Kept::Unchanged => {}
            Kept::Applied(cut) => {
                self.note(Part::Filter, None);
                self.end_cut(&cut);
            }
            Kept::Restored => {
                self.note(Part::Filter, None);
                self.observer.record(json!({"kind": "firewall-restored", "ts": now()}));
                self.wake.now();
            }
            Kept::Failed(error) => self.note(Part::Filter, Some(error)),
        }
    }

    /// Makes the firewall enforce the plan's threats, cut and SSH lockdown; kills the open connections to
    /// newly cut addresses and queues an event for each. A filter that does not load stays wanted:
    /// [`Helper::keep_filter_intact`] tries it again every cycle ([`FilterKeeper`]).
    pub(super) fn set_filter(&self, plan: &Plan) -> Option<String> {
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
        let filter = platform::Filter {
            threats: plan.firewall.enabled.then(|| plan.firewall_ips()),
            cut: plan.cut.enabled.then(|| state.cut_ips.iter().filter_map(|ip| ip.parse().ok()).collect()),
            ssh_allow: plan.ssh.lockdown.then(|| plan.ssh_sources()),
            remote_lock: plan.remote.lock,
            remote_block: plan.remote_block(),
        };
        state.save();
        drop(state);
        let result = self.with_filter(|keeper, apply, _| keeper.set(filter, newly, apply));
        self.end_sessions(plan);
        match result {
            Ok(cut) => { self.end_cut(&cut); None }
            Err(error) => Some(error),
        }
    }

    /// Runs *step* on a copy of the [`FilterKeeper`] with the firewall's `apply` (the saved pf
    /// token in and out) and `intact`, then stores the copy and — when anything was loaded — the
    /// token and the flags of the filter in effect. WHY a copy: the report thread reads the keeper,
    /// and a firewall load can take up to its timeout; only this (the plan) thread changes it.
    fn with_filter<R>(&self, step: impl FnOnce(&mut FilterKeeper, &mut dyn FnMut(&platform::Filter) -> Result<(), String>,
                                             &dyn Fn(&platform::Filter) -> Option<bool>) -> R) -> R {
        let mut keeper = self.filtered.lock().map(|keeper| keeper.clone()).unwrap_or_default();
        let mut token = self.state.lock().ok().and_then(|state| state.pf_token.clone());
        let mut loaded = false;
        let answer = step(&mut keeper, &mut |filter| {
            loaded = true;
            self.enforcer.apply_filter(filter, token.clone()).map(|new| token = new)
        }, &|filter| self.enforcer.filter_intact(filter));
        let in_effect = keeper.in_effect();
        if let Ok(mut slot) = self.filtered.lock() {
            *slot = keeper;
        }
        if loaded {
            if let Ok(mut state) = self.state.lock() {
                state.pf_token = token;
                state.firewall_active = in_effect.as_ref().and_then(|filter| filter.threats.as_ref()).is_some_and(|ips| !ips.is_empty());
                state.cut_active = in_effect.as_ref().is_some_and(|filter| filter.cut.is_some());
                state.ssh_lockdown_active = in_effect.as_ref().is_some_and(|filter| filter.ssh_allow.is_some());
                state.remote_lock_active = in_effect.as_ref().is_some_and(|filter| filter.remote_lock);
                state.save();
            }
        }
        answer
    }

    /// Ends the open connections to *cut* (the filter that cuts them is loaded) and queues an event each.
    fn end_cut(&self, cut: &[IpAddr]) {
        if cut.is_empty() {
            return;
        }
        for ip in cut {
            let _ = self.enforcer.kill_states(ip);   // the filter already drops it; this ends open states too
            self.observer.record(json!({"kind": "connection-cut", "ts": now(), "remote_ip": ip.to_string()}));
        }
        self.wake.now();
    }

    /// Records what the loop's own retry or restore of one *part* came to: a failure stays in
    /// [`Failures`] — in every report until it is fixed, never overwritten by the next unchanged
    /// plan (review finding 2026-11-26) — and `last_error` says what still fails.
    fn note(&self, part: Part, error: Option<String>) {
        let Ok(mut failures) = self.failures.lock() else { return };
        match part {
            Part::Dns => failures.dns = error,
            Part::Filter => failures.filter = error,
        }
        *self.last_error.lock().unwrap() = failures.still_failing();
    }
}

/// Which part of a plan [`Helper::note`] records.
enum Part {
    Dns,
    Filter,
}

/// Adds the originals *found* to the saved ones; an original saved earlier is never replaced (a
/// value found later may be one DNS Shield or another program set).
fn keep_originals(state: &mut State, found: platform::SavedDns) {
    for (service, servers) in found {
        state.saved_dns.entry(service).or_insert(servers);
    }
}
