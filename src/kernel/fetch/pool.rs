//! A small bounded pool for independent verified downloads (#745): a
//! lock's wheels or tarballs, a toolchain's components. Blocking `ureq`
//! per thread, `std::thread::scope`, no async runtime.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// How many downloads `fetch_each` runs at once. Each one is mostly
/// waiting on the network, so a few threads cut a sync's wait by about
/// this factor; kept low because registries rate-limit, and it bounds the
/// disk writes a slow medium sees at once.
pub(crate) const FETCH_WORKERS: usize = 4;

/// Run `fetch` over every job on up to [`FETCH_WORKERS`] threads, and
/// return each job's result at its own index, whatever order they finished
/// in. Each job still goes through `cache_or_download`, so every guarantee
/// holds per artifact. Bytes are verified before they are published into
/// `cache/<algo>/`, a partial download is never visible (each attempt
/// streams into its own randomly named file under `tmp/`, so two threads on
/// one digest never share one), and an error carries the same text as the
/// call made alone.
///
/// Jobs start in input order. Once one fails no further job starts, so a
/// caller that stops at the first error in input order sees the same
/// error it would have seen fetching one at a time: every job before the
/// failed one had started and runs to its end. A job never reached holds
/// an error saying so; such a slot comes after a failure, where an
/// in-order caller has already stopped.
///
/// A single job runs on the calling thread with its own progress line, as
/// before. A larger batch shares one line (`ui::Batch`), erased before
/// this returns.
pub(crate) fn fetch_each<J, T>(
    jobs: &[J],
    fetch: impl Fn(&J) -> io::Result<T> + Sync,
) -> Vec<io::Result<T>>
where
    J: Sync,
    T: Send,
{
    if jobs.len() < 2 {
        return jobs.iter().map(&fetch).collect();
    }
    let next = AtomicUsize::new(0);
    // The lowest index that has failed so far, `usize::MAX` while none has.
    let failed = AtomicUsize::new(usize::MAX);
    let slots: Vec<Mutex<Option<io::Result<T>>>> = jobs.iter().map(|_| Mutex::new(None)).collect();
    let batch = crate::kernel::ui::Batch::start(jobs.len());
    // What the calling thread carries that a worker thread would not: the
    // operation's policy (a registry download reads its `[sources]` and
    // credentials from it, and a bare thread would read the default) and
    // the phase the downloads are timed under.
    let policy = crate::kernel::policy::effective();
    let parent = crate::kernel::ui::current_phase();
    std::thread::scope(|scope| {
        for _ in 0..FETCH_WORKERS.min(jobs.len()) {
            scope.spawn(|| {
                let _policy = crate::kernel::policy::PolicyScope::inherit(policy.clone());
                let _t = parent.phase("download pool");
                crate::kernel::ui::in_batch(&batch, || loop {
                    // Indices are handed out in order, so every index below
                    // a failed one was taken before it and is finished, not
                    // skipped.
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= jobs.len() || index > failed.load(Ordering::SeqCst) {
                        break;
                    }
                    let result = fetch(&jobs[index]);
                    if result.is_err() {
                        failed.fetch_min(index, Ordering::SeqCst);
                    }
                    batch.finished();
                    *slots[index]
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
                })
            });
        }
    });
    drop(batch);
    slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .unwrap_or_else(|| {
                    Err(io::Error::other(
                        "not fetched: an earlier download in the same batch failed",
                    ))
                })
        })
        .collect()
}

/// [`fetch_each`] for a caller that needs every job: the results in input
/// order, or the first failure in input order.
pub(crate) fn fetch_all<J, T>(
    jobs: &[J],
    fetch: impl Fn(&J) -> io::Result<T> + Sync,
) -> io::Result<Vec<T>>
where
    J: Sync,
    T: Send,
{
    fetch_each(jobs, fetch).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pool returns every result at its job's index, whatever order
    /// the jobs finished in, and really runs them side by side.
    #[test]
    fn a_batch_returns_results_in_input_order() {
        let running = AtomicUsize::new(0);
        let widest = AtomicUsize::new(0);
        let jobs: Vec<u64> = (0..12).collect();
        let results = fetch_all(&jobs, |&job| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            widest.fetch_max(now, Ordering::SeqCst);
            // Later jobs finish first.
            std::thread::sleep(std::time::Duration::from_millis(30 - 2 * job));
            running.fetch_sub(1, Ordering::SeqCst);
            Ok(job * 10)
        })
        .unwrap();
        assert_eq!(results, jobs.iter().map(|job| job * 10).collect::<Vec<_>>());
        let widest = widest.load(Ordering::SeqCst);
        assert!(widest > 1 && widest <= FETCH_WORKERS, "{widest}");
    }

    /// Two failures: the one reported is the first in input order, even
    /// when the later one fails first, and no job after a failure starts.
    #[test]
    fn a_batch_reports_the_first_failure_in_input_order() {
        let started = AtomicUsize::new(0);
        let jobs: Vec<usize> = (0..40).collect();
        let error = fetch_all(&jobs, |&job| {
            started.fetch_add(1, Ordering::SeqCst);
            match job {
                // Fails late, after job 3 has already failed.
                2 => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    Err(io::Error::other("job 2 failed"))
                }
                3 => Err(io::Error::other("job 3 failed")),
                _ => Ok(job),
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "job 2 failed");
        // Jobs are handed out in order, so at most one per worker started
        // past the failure before it was seen.
        let started = started.load(Ordering::SeqCst);
        assert!(started < 4 + FETCH_WORKERS, "{started} of 40 jobs started");
    }

    /// `fetch_each` keeps every result in its slot, failures included, for
    /// a caller that interleaves the downloads with other work in order.
    #[test]
    fn each_result_stays_at_its_index() {
        let jobs = [1, 2, 3];
        let results = fetch_each(&jobs, |&job| {
            if job == 2 {
                Err(io::Error::other("two"))
            } else {
                Ok(job)
            }
        });
        assert_eq!(results[0].as_ref().unwrap(), &1);
        assert_eq!(results[1].as_ref().unwrap_err().to_string(), "two");
        assert_eq!(results.len(), 3);
    }

    /// A worker reads the caller's policy, not the default a bare thread
    /// would: a registry download takes its `[sources]` from it.
    #[test]
    fn workers_read_the_callers_policy() {
        let policy = crate::kernel::policy::Policy {
            strict: true,
            ..Default::default()
        };
        let _scope = crate::kernel::policy::PolicyScope::install(policy);
        let jobs: Vec<usize> = (0..8).collect();
        let strict = fetch_all(&jobs, |_| Ok(crate::kernel::policy::strict())).unwrap();
        assert!(strict.iter().all(|&s| s), "{strict:?}");
    }
}
