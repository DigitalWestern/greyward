//! Test-only pause points: named stages of one planner-to-closure
//! invocation where a test runs its own code, so a concurrent writer can
//! act at an exact stage instead of racing for it.
//!
//! The points belong to one invocation. A test builds a [`PausePoints`],
//! hands it to that invocation's `Attribution` (`with_pauses`), and every
//! stage the invocation reaches runs the hooks registered for it on the
//! invocation's own thread. Nothing is process-global: another test, or a
//! second invocation in the same test, sees none of these hooks unless it
//! is handed the same value. The whole module is compiled for tests only,
//! and so is every call site that fires a point.

#![cfg(test)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Where an invocation is, between capturing its inputs and publishing its
/// closure. Each producer fires the points it passes; a point may be
/// reached more than once (one `Staged` per confined planner run).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PausePoint {
    /// The planner has read the resolution files and computed the basis it
    /// will bind the plan to, and has run nothing yet.
    Captured,
    /// A confined run has copied the project into its immutable stage and
    /// has not yet compared the stage with the consumed basis. A planner's
    /// detached run holds no project lock here.
    Staged,
    /// The plan is complete and rechecked against the basis; nothing of it
    /// is published yet, and no project lock is held.
    Planned,
    /// The producer is about to take the project lock to publish.
    Publishing,
    /// The project lock is held and the resolution join has not run. A
    /// producer that joins before switching its projection reaches this
    /// twice: before that join, and again in the closure writer.
    Joining,
    /// The closure is written and the project lock is still held.
    Published,
}

type Hook = Box<dyn FnMut(usize) + Send>;

/// The hooks of one invocation, and how often it reached each point.
#[derive(Default)]
pub(crate) struct PausePoints {
    hooks: Mutex<BTreeMap<PausePoint, Vec<Hook>>>,
    hits: Mutex<BTreeMap<PausePoint, usize>>,
}

impl std::fmt::Debug for PausePoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PausePoints")
            .field("hits", &*lock(&self.hits))
            .finish()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl PausePoints {
    pub(crate) fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Run `hook` each time the invocation reaches `point`, with the
    /// 1-based count of arrivals at it so far.
    pub(crate) fn on(&self, point: PausePoint, hook: impl FnMut(usize) + Send + 'static) {
        lock(&self.hooks)
            .entry(point)
            .or_default()
            .push(Box::new(hook));
    }

    /// Run `hook` once, at the `nth` (1-based) arrival at `point`.
    pub(crate) fn at(&self, point: PausePoint, nth: usize, hook: impl FnOnce() + Send + 'static) {
        let mut hook = Some(hook);
        self.on(point, move |arrival| {
            if arrival == nth {
                if let Some(hook) = hook.take() {
                    hook();
                }
            }
        });
    }

    /// How many times the invocation reached `point`. A test asserts it,
    /// so an interleaving it meant to exercise cannot silently not happen.
    pub(crate) fn hits(&self, point: PausePoint) -> usize {
        lock(&self.hits).get(&point).copied().unwrap_or(0)
    }

    /// The invocation reached `point`: count it and run its hooks. The
    /// hooks are taken out while they run, so a hook may itself drive a
    /// whole second invocation (with its own points) without deadlock.
    pub(crate) fn reach(&self, point: PausePoint) {
        let arrival = {
            let mut hits = lock(&self.hits);
            let count = hits.entry(point).or_default();
            *count += 1;
            *count
        };
        let mut running = lock(&self.hooks).remove(&point).unwrap_or_default();
        for hook in &mut running {
            hook(arrival);
        }
        let mut hooks = lock(&self.hooks);
        let added = hooks.remove(&point).unwrap_or_default();
        running.extend(added);
        hooks.insert(point, running);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn hooks_run_at_their_point_and_arrival_only() {
        let points = PausePoints::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        points.on(PausePoint::Staged, move |arrival| {
            log.lock().unwrap().push(arrival)
        });
        let second = Arc::new(AtomicUsize::new(0));
        let count = second.clone();
        points.at(PausePoint::Staged, 2, move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        points.reach(PausePoint::Captured);
        for _ in 0..3 {
            points.reach(PausePoint::Staged);
        }
        assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3]);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(points.hits(PausePoint::Captured), 1);
        assert_eq!(points.hits(PausePoint::Staged), 3);
        assert_eq!(points.hits(PausePoint::Published), 0);
    }

    /// A hook can reach points of the same value (a nested invocation
    /// handed the same points by mistake) without deadlocking.
    #[test]
    fn a_hook_may_reach_points_itself() {
        let points = PausePoints::new();
        let inner = points.clone();
        points.at(PausePoint::Planned, 1, move || {
            inner.reach(PausePoint::Planned);
            inner.reach(PausePoint::Joining);
        });
        points.reach(PausePoint::Planned);
        assert_eq!(points.hits(PausePoint::Planned), 2);
        assert_eq!(points.hits(PausePoint::Joining), 1);
    }

    /// Two invocations' points are independent, so tests running in
    /// parallel cannot see each other's hooks.
    #[test]
    fn points_are_scoped_to_the_value_they_were_registered_on() {
        let first = PausePoints::new();
        let second = PausePoints::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let count = ran.clone();
        first.on(PausePoint::Joining, move |_| {
            count.fetch_add(1, Ordering::SeqCst);
        });
        second.reach(PausePoint::Joining);
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        first.reach(PausePoint::Joining);
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }
}
