//! [`MacObserver`]: the [`Observer`] for macOS — SSH and the login files (`observe::watch`),
//! who is in this Mac and how (`observe::{logstream, remote, remote_procs}` over the libproc
//! socket reader), checking an end request (`enforce::sessions::verify`, which only reads) and
//! the system watch loop (`system_guard`). Its state lives here between looks.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use super::enforce::sessions;
use super::observe::{logstream, remote, remote_procs, watch};
use super::sockets;
use super::system_guard;
use crate::platform::{EndRequest, Observer};
use crate::state::now;

/// macOS's observer: what it saw last, the login-log reader and the socket / process readers.
#[derive(Default)]
pub struct MacObserver {
    watch: Mutex<watch::Watch>,
    remote: Mutex<remote::Remote>,
    logs: Mutex<logstream::Stream>,
    sockets: Mutex<sockets::Reader>,
    procs: Mutex<remote_procs::ProcReader>,
}

impl Observer for MacObserver {
    const WATCH_EVERY: Duration = watch::WATCH_EVERY;
    const REMOTE_EVERY: Duration = remote::REMOTE_EVERY;
    const SYSTEM_WATCH_STACK: usize = system_guard::STACK_BYTES;

    fn look(&self, watching: bool) -> bool {
        if !watching {
            self.watch.lock().unwrap().reset();
            return false;
        }
        let (netstat, files) = watch::look();
        self.watch.lock().unwrap().tick(&netstat, files, now())
    }

    fn look_remote(&self, watching: bool) -> bool {
        if !watching {
            self.logs.lock().unwrap().stop();
            self.remote.lock().unwrap().reset();
            return false;
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
        self.remote.lock().unwrap().tick(&inbound, &procs, logins, now())
    }

    fn verify_end(&self, request: &EndRequest) -> Result<(), String> {
        let live = self.remote.lock().unwrap().session(&request.session_id).cloned();
        let process = self.procs.lock().unwrap().read().get(&request.pid).map(|p| (p.name.clone(), p.start));
        sessions::verify(request, live.as_ref(), process.as_ref().map(|(name, start)| (name.as_str(), *start)))
    }

    fn record_end(&self, request: &EndRequest, result: Result<(), String>) {
        let live = self.remote.lock().unwrap().session(&request.session_id).cloned();
        let event = match (result, live) {
            (Ok(()), Some(session)) => remote::session_event("remote-session-ended", &session, now(), "ended"),
            (result, _) => json!({"kind": "remote-end-refused", "ts": now(), "session_id": request.session_id,
                                  "reason": result.err().unwrap_or_default()}),
        };
        self.remote.lock().unwrap().push(event);
    }

    fn record(&self, event: Value) {
        self.watch.lock().unwrap().push(event);
    }

    fn watch_snapshot(&self) -> Option<Value> {
        self.watch.lock().unwrap().snapshot()
    }

    fn remote_snapshot(&self) -> Option<Value> {
        self.remote.lock().unwrap().snapshot()
    }

    fn drain(&self) -> (Vec<Value>, Vec<Value>) {
        let watch = self.watch.lock().map(|mut watch| watch.drain()).unwrap_or_default();
        let remote = self.remote.lock().map(|mut remote| remote.drain()).unwrap_or_default();
        (watch, remote)
    }

    fn requeue(&self, watch: Vec<Value>, remote: Vec<Value>) {
        if !watch.is_empty() {
            self.watch.lock().unwrap().requeue(watch);
        }
        if !remote.is_empty() {
            self.remote.lock().unwrap().requeue(remote);
        }
    }

    fn stop(&self) {
        self.logs.lock().unwrap().stop();
    }

    fn run_system_watch(&self) {
        system_guard::run();
    }

    fn run_file_watch(&self) {
        super::file_shield::run();
    }
}
