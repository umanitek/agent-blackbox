//! [`FilterKeeper`]: the filter the plan wants, the one really loaded, and the loop's retry.
//!
//! Pattern: **State** — two filters and the cut addresses whose open connections are still to be
//! ended; [`FilterKeeper::set`] (a new plan) and [`FilterKeeper::keep`] (every plan cycle) are the
//! only transitions. The firewall itself is reached through the closures the daemon passes
//! (`apply`, `intact`), so every transition is tested without touching the system.
//!
//! WHY (review finding 2026-11-26, HIGH): the plan version was recorded as applied even when the
//! firewall apply failed (the firewall tool timed out), and the filter kept for
//! `keep_filter_intact` was cleared — the Threat Firewall stayed empty until the plan CHANGED, and
//! the rules that had worked were not put back. Now a filter that did not load stays wanted and
//! is tried again every cycle (like DNS Shield's `dns_wanted`), and while it fails, the filter
//! that last loaded is kept in effect.

use std::net::IpAddr;
use std::sync::Arc;

use crate::platform::Filter;

/// What one [`FilterKeeper::keep`] did.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Kept {
    /// Nothing to do: the wanted filter is loaded and intact (or cannot be read).
    Unchanged,
    /// The wanted filter, which had failed to load, loaded now. Carries the cut addresses whose
    /// open connections are still to be ended.
    Applied(Vec<IpAddr>),
    /// Another program removed or changed the rules; they were loaded again.
    Restored,
    /// Loading failed (the text says what); the filter that last loaded was kept in effect.
    Failed(String),
}

/// The plan's filter and the one in effect (see the module doc). Cheap to clone (the filters,
/// tens of thousands of addresses, are shared), so the daemon works on a copy and never holds its
/// lock while the firewall loads.
#[derive(Debug, Clone, Default)]
pub(super) struct FilterKeeper {
    /// What the last plan asked for (None before any plan).
    wanted: Option<Arc<Filter>>,
    /// The filter that last loaded successfully (None: nothing of ours has loaded in this process).
    applied: Option<Arc<Filter>>,
    /// Newly cut addresses whose open connections end once the filter that cuts them loaded.
    unkilled: Vec<IpAddr>,
}

impl FilterKeeper {
    /// A new plan's *filter*: loaded through *apply* now. On success answers the newly cut
    /// addresses to end the open connections of; on failure the filter stays wanted (and
    /// [`FilterKeeper::keep`] tries again) and *newly* waits for it.
    pub(super) fn set(&mut self, filter: Filter, newly: Vec<IpAddr>,
                      apply: &mut dyn FnMut(&Filter) -> Result<(), String>) -> Result<Vec<IpAddr>, String> {
        let filter = Arc::new(filter);
        self.unkilled.extend(newly);
        self.wanted = Some(filter.clone());
        apply(&filter)?;
        self.applied = Some(filter);
        Ok(std::mem::take(&mut self.unkilled))
    }

    /// One plan cycle: a wanted filter that did not load is tried again (and while it fails the
    /// filter that last loaded is put back when it is not intact); a loaded one that another
    /// program removed or changed (*intact* answers `Some(false)`) is loaded again.
    pub(super) fn keep(&mut self, apply: &mut dyn FnMut(&Filter) -> Result<(), String>,
                       intact: &dyn Fn(&Filter) -> Option<bool>) -> Kept {
        if let Some(wanted) = self.wanted.clone().filter(|wanted| !self.applied.as_ref().is_some_and(|applied| Arc::ptr_eq(applied, wanted))) {
            return match apply(&wanted) {
                Ok(()) => {
                    self.applied = Some(wanted);
                    Kept::Applied(std::mem::take(&mut self.unkilled))
                }
                Err(error) => {
                    if let Some(last) = self.in_effect() {
                        if intact(&last) == Some(false) {
                            let _ = apply(&last);   // best effort: the error above is what is reported
                        }
                    }
                    Kept::Failed(error)
                }
            };
        }
        let Some(applied) = self.in_effect() else { return Kept::Unchanged };
        if intact(&applied) != Some(false) {
            return Kept::Unchanged;
        }
        match apply(&applied) {
            Ok(()) => Kept::Restored,
            Err(error) => Kept::Failed(format!("the firewall's rules were removed and could not be loaded again: {error}")),
        }
    }

    /// The filter of ours that is loaded now and holds rules (None when every protection is off
    /// or nothing loaded yet): what the report checks is still intact.
    pub(super) fn in_effect(&self) -> Option<Arc<Filter>> {
        self.applied.clone().filter(|filter| !filter.is_off())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn threats(ip: &str) -> Filter {
        Filter { threats: Some(vec![ip.parse().unwrap()]), ..Default::default() }
    }

    /// The HIGH finding: a filter whose apply failed is tried again on the next cycle, without a
    /// new plan, and the cut connections it carried end once it loads.
    #[test]
    fn a_filter_that_failed_to_load_is_tried_again_every_cycle_until_it_loads() {
        let mut keeper = FilterKeeper::default();
        let cut: IpAddr = "198.51.100.9".parse().unwrap();
        let fails = RefCell::new(true);
        let loaded = RefCell::new(vec![]);
        let mut apply = |filter: &Filter| if *fails.borrow() { Err("the load timed out".to_string()) } else { loaded.borrow_mut().push(filter.clone()); Ok(()) };
        assert!(keeper.set(threats("203.0.113.7"), vec![cut], &mut apply).is_err());
        assert_eq!(keeper.in_effect(), None, "nothing loaded: nothing reported as in effect");
        assert_eq!(keeper.keep(&mut apply, &|_| Some(true)), Kept::Failed("the load timed out".into()));
        *fails.borrow_mut() = false;
        assert_eq!(keeper.keep(&mut apply, &|_| Some(true)), Kept::Applied(vec![cut]), "loaded on the next cycle, the cut ends then");
        assert_eq!(loaded.borrow().as_slice(), [threats("203.0.113.7")]);
        assert_eq!(keeper.keep(&mut apply, &|_| Some(true)), Kept::Unchanged);
    }

    /// While a new filter fails, the rules that worked before are kept in effect (put back when
    /// the failed apply left them broken); a removed filter is loaded again.
    #[test]
    fn while_a_new_filter_fails_the_last_one_that_loaded_stays_in_effect() {
        let mut keeper = FilterKeeper::default();
        let (old, new) = (threats("203.0.113.7"), threats("203.0.113.8"));
        let loads = RefCell::new(vec![]);
        let mut apply = |filter: &Filter| { loads.borrow_mut().push(filter.clone()); if *filter == new { Err("the load timed out".to_string()) } else { Ok(()) } };
        keeper.set(old.clone(), vec![], &mut apply).unwrap();
        assert!(keeper.set(new.clone(), vec![], &mut apply).is_err());
        assert_eq!(keeper.in_effect().as_deref(), Some(&old));
        loads.borrow_mut().clear();
        assert!(matches!(keeper.keep(&mut apply, &|_| Some(true)), Kept::Failed(_)));
        assert_eq!(loads.borrow().as_slice(), [new.clone()], "the old rules were intact: only the new one tried");
        loads.borrow_mut().clear();
        assert!(matches!(keeper.keep(&mut apply, &|_| Some(false)), Kept::Failed(_)));
        assert_eq!(loads.borrow().as_slice(), [new, old.clone()], "the failed apply broke them: the old rules come back");
        let mut keeper = FilterKeeper::default();
        keeper.set(old.clone(), vec![], &mut |_| Ok(())).unwrap();
        assert_eq!(keeper.keep(&mut |_| Ok(()), &|_| Some(false)), Kept::Restored);
        assert_eq!(keeper.keep(&mut |_| Ok(()), &|_| None), Kept::Unchanged, "unreadable: nothing re-applied");
        keeper.set(Filter::default(), vec![], &mut |_| Ok(())).unwrap();
        assert_eq!(keeper.in_effect(), None, "every protection off");
    }
}
