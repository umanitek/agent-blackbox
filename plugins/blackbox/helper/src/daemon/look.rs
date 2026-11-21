//! Watching: SSH and login files, who is in this Mac, ending sessions.

#[allow(unused_imports)]
use super::*;

impl Helper {
    /// One look at SSH and the login files, while the plan says watch; nothing while it does not.
    pub(super) fn look(&self) {
        if !self.watching.load(Ordering::SeqCst) {
            self.watch.lock().unwrap().reset();
            return;
        }
        let (netstat, files) = watch::look();
        let news = self.watch.lock().unwrap().tick(&netstat, files, now());
        if news {
            self.wake.now();
        }
    }

    /// One look at who is in this Mac, while the plan says watch: the login log (its child started
    /// on first use, stopped when watching stops), the inbound sessions and their processes.
    pub(super) fn look_remote(&self) {
        if !self.watching.load(Ordering::SeqCst) {
            self.logs.lock().unwrap().stop();
            self.remote.lock().unwrap().reset();
            return;
        }
        let logins = {
            let mut logs = self.logs.lock().unwrap();
            logs.ensure_running();
            logs.drain()
        };
        let inbound: Vec<remote::Inbound> = self.sockets.lock().unwrap().sockets().into_iter()
            .filter(|s| remote::REMOTE_PORTS.iter().any(|(port, _)| *port == s.local_port))
            .map(|s| remote::Inbound { pid: s.pid, local_ip: s.local_ip, local_port: s.local_port, remote_ip: s.remote_ip,
                                       remote_port: s.remote_port, listening: s.listening(), established: s.state == "Established" })
            .collect();
        // The process table only when someone is in or a login just happened (it costs more).
        let procs = if inbound.iter().any(|s| s.established) || !logins.is_empty() {
            self.procs.lock().unwrap().read()
        } else {
            remote_procs::Procs::new()
        };
        if self.remote.lock().unwrap().tick(&inbound, &procs, logins, now()) {
            self.wake.now();
        }
    }

    /// Carries out the plan's end requests the user confirmed — each once, each only after
    /// [`sessions::verify`] says it is still exactly that session — and reports what happened.
    pub(super) fn end_sessions(&self, plan: &Plan) {
        let mut ended = self.ended.lock().unwrap();
        ended.retain(|id| plan.remote.end.iter().any(|request| &request.session_id == id));
        for request in &plan.remote.end {
            if !ended.insert(request.session_id.clone()) {
                continue;
            }
            let live = self.remote.lock().unwrap().session(&request.session_id).cloned();
            let process = self.procs.lock().unwrap().read().get(&request.pid).map(|p| (p.name.clone(), p.start));
            let checked = sessions::verify(request, live.as_ref(), process.as_ref().map(|(name, start)| (name.as_str(), *start)));
            let event = match (checked.and_then(|_| sessions::end(request.pid)), live) {
                (Ok(()), Some(session)) => remote::session_event("remote-session-ended", &session, now(), "ended"),
                (result, _) => json!({"kind": "remote-end-refused", "ts": now(), "session_id": request.session_id,
                                      "reason": result.err().unwrap_or_default()}),
            };
            self.remote.lock().unwrap().push(event);
            self.wake.now();
        }
    }
}
