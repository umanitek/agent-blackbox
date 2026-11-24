//! Applying a plan: DNS, the filter, keeping DNS safe.

#[allow(unused_imports)]
use super::*;

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
        if let Ok(mut kept) = self.kept.lock() {
            plan.keep_from(&kept);
            *kept = plan.kept();
        }
        let plan = &plan;
        let mut errors = vec![];
        if let Ok(mut lists) = self.resolver.lists.write() {
            *lists = plan.blocklists();
        }
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
        if enabled == state.dns_active {
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
            self.enforcer.point_dns_at_shield().map(|saved| {
                for (service, servers) in saved {
                    state.saved_dns.entry(service).or_insert(servers);
                }
            })
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
        if !self.state.lock().map(|state| state.dns_active).unwrap_or(false) {
            return;
        }
        if !self.resolver_answers() {
            let error = self.set_dns(false).unwrap_or_default();
            *self.applied.lock().unwrap() = String::new();   // re-apply the plan in full next time
            *self.last_error.lock().unwrap() = Some(format!("DNS Shield's resolver stopped answering; the Mac's own DNS was put back {error}").trim().to_string());
            return;
        }
        let now = self.enforcer.dhcp_upstreams();
        if !now.is_empty() {
            if let Ok(mut upstreams) = self.resolver.upstreams.write() {
                if *upstreams != now { *upstreams = now; }
            }
        }
    }

    /// Makes the firewall enforce the plan's threats, cut and SSH lockdown; kills the open connections to
    /// newly cut addresses and queues an event for each.
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
        let threats = plan.firewall.enabled.then(|| plan.firewall_ips());
        let filter = platform::Filter {
            threats: threats.clone(),
            cut: plan.cut.enabled.then(|| state.cut_ips.iter().filter_map(|ip| ip.parse().ok()).collect()),
            ssh_allow: plan.ssh.lockdown.then(|| plan.ssh_sources()),
            remote_lock: plan.remote.lock,
            remote_block: plan.remote_block(),
        };
        let result = self.enforcer.apply_filter(&filter, state.pf_token.clone());
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
            for ip in &newly {
                let _ = self.enforcer.kill_states(ip);   // the filter already drops it; this ends open states too
                self.observer.record(json!({"kind": "connection-cut", "ts": now(), "remote_ip": ip.to_string()}));
            }
            self.wake.now();
        }
        result.err()
    }
}
