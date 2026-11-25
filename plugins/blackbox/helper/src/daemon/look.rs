//! Watching: SSH and login files, who is in this Mac, ending sessions.

#[allow(unused_imports)]
use super::*;

impl Helper {
    /// One look at SSH and the login files, while the plan says watch; nothing while it does not.
    pub(super) fn look(&self) {
        if self.observer.look(self.watching.load(Ordering::SeqCst)) {
            self.wake.now();
        }
    }

    /// One look at who is in this system and how, while the plan says watch.
    pub(super) fn look_remote(&self) {
        if self.observer.look_remote(self.watching.load(Ordering::SeqCst)) {
            self.wake.now();
        }
    }

    /// Carries out the plan's end requests the user confirmed — each once, each only after
    /// [`Observer::verify_end`] says it is still exactly that session — and reports what happened.
    pub(super) fn end_sessions(&self, plan: &Plan) {
        let mut ended = self.ended.lock().unwrap();
        ended.retain(|id| plan.remote.end.iter().any(|request| &request.session_id == id));
        for request in &plan.remote.end {
            if !ended.insert(request.session_id.clone()) {
                continue;
            }
            let result = self.observer.verify_end(request).and_then(|_| self.enforcer.end_session(request.pid));
            self.observer.record_end(request, result);
            self.wake.now();
        }
    }
}
