//! Checkpoints of an append-only transparency log, for `young-package`.
//!
//! Some registries record no upload time ward can trust: Go's module proxy
//! gives only a commit time, which whoever made the commit sets. Go's
//! checksum database is an append-only log instead, and the record number
//! it gives a module version is a position in it: every record before the
//! tree's size was logged before that tree was signed. So a signed tree
//! head ward saw at some time says "everything below this size was logged
//! by then".
//!
//! A checkpoint is one such head: the verified tree size and the local
//! time ward observed it. Every verified head ward serves (the tool's own
//! checksum-database traffic, and ward's lookups) is appended to
//! `<store>/resolve/tlog/<log name>` as a line `<size> <unix seconds>`. A
//! version passes when its record number is below the size of the newest
//! checkpoint observed at least the minimum age before the resolution; a
//! later record's age is unknown. The binary also carries one seed
//! checkpoint per log (verified when it was generated, and again on load),
//! so a fresh store has one to judge by once the seed is old enough.
//!
//! The history is thinned as it grows: every checkpoint of the last two
//! days, then the largest of each UTC day, back to the longest minimum age
//! a policy may set (and the newest one older than that). The file is only
//! as trustworthy as the store's permissions: anyone who can write it can
//! claim any checkpoint, and a local clock that was set back when a head
//! was observed dates the head too early.

use crate::kernel::policy::MAX_MIN_AGE_DAYS;
use crate::kernel::store::Store;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const SECONDS_PER_DAY: i64 = 86_400;
/// The checkpoint files' namespace in the store.
const TLOG_DIR: &str = "resolve/tlog";
/// Past this many lines, the history is thinned on the next append.
const THIN_AFTER: usize = 512;
/// Everything observed this recently is kept as it is.
const KEEP_ALL_SECONDS: i64 = 2 * SECONDS_PER_DAY;

/// An append-only log a registry protocol judges age by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Log {
    /// The log's name, as its signed heads name it (`sum.golang.org`); the
    /// checkpoint file is named after it.
    pub name: &'static str,
    /// The checkpoint the binary carries, when it verified.
    pub seed: Option<Checkpoint>,
}

/// A verified tree size and when ward observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Checkpoint {
    pub size: u64,
    /// Unix seconds, by the local clock.
    pub observed: i64,
}

fn path(store: &Store, log: &str) -> io::Result<PathBuf> {
    if log.is_empty() || log.starts_with('.') || log.contains(['/', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{log:?} is not a log name"),
        ));
    }
    store.ensure_namespace(Path::new(TLOG_DIR))?;
    Ok(store.root.join(TLOG_DIR).join(log))
}

/// Append a checkpoint of `log`, thinning the history when it has grown.
pub fn record(store: &Store, log: &str, checkpoint: Checkpoint) -> io::Result<()> {
    let path = path(store, log)?;
    let line = format!("{} {}\n", checkpoint.size, checkpoint.observed);
    // One short write in append mode: concurrent writers interleave whole
    // lines.
    fs::File::options()
        .create(true)
        .append(true)
        .open(&path)?
        .write_all(line.as_bytes())?;
    let text = fs::read_to_string(&path)?;
    if text.lines().count() > THIN_AFTER {
        let kept = thin(parse(&text), checkpoint.observed);
        let mut out = String::new();
        for checkpoint in &kept {
            out.push_str(&format!("{} {}\n", checkpoint.size, checkpoint.observed));
        }
        // Rewritten beside the file and renamed over it. A line another
        // writer appends meanwhile may be lost: a lost checkpoint only
        // passes fewer versions.
        let fresh = path.with_file_name(format!(".{log}.thin-{}", std::process::id()));
        let written = fs::write(&fresh, out).and_then(|()| fs::rename(&fresh, &path));
        if written.is_err() {
            let _ = fs::remove_file(&fresh);
        }
        written?;
    }
    Ok(())
}

/// Every checkpoint of `log` the store holds, and its seed.
pub fn load(store: &Store, log: &Log) -> io::Result<Vec<Checkpoint>> {
    let path = path(store, log.name)?;
    let mut checkpoints = match fs::read_to_string(&path) {
        Ok(text) => parse(&text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    checkpoints.extend(log.seed);
    Ok(checkpoints)
}

/// The lines that parse; a torn or foreign line is skipped.
fn parse(text: &str) -> Vec<Checkpoint> {
    text.lines()
        .filter_map(|line| {
            let (size, observed) = line.split_once(' ')?;
            Some(Checkpoint {
                size: size.parse().ok()?,
                observed: observed.parse().ok()?,
            })
        })
        .collect()
}

/// The checkpoint to judge by at `before` (the resolution time less the
/// minimum age): the largest tree observed no later than it.
pub fn eligible(checkpoints: &[Checkpoint], before: i64) -> Option<Checkpoint> {
    checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.observed <= before)
        .max_by_key(|checkpoint| (checkpoint.size, std::cmp::Reverse(checkpoint.observed)))
        .copied()
}

/// What thinning keeps at `now`: every checkpoint of the last two days (or
/// later, should the clock have gone back), the largest of each older UTC
/// day back to the longest minimum age, and the largest older than that.
fn thin(mut checkpoints: Vec<Checkpoint>, now: i64) -> Vec<Checkpoint> {
    let window = (i64::from(MAX_MIN_AGE_DAYS) + 1) * SECONDS_PER_DAY;
    checkpoints.sort();
    checkpoints.dedup();
    let mut kept: Vec<Checkpoint> = Vec::new();
    let mut days: std::collections::BTreeMap<i64, Checkpoint> = Default::default();
    let mut oldest: Option<Checkpoint> = None;
    for checkpoint in checkpoints {
        let age = now - checkpoint.observed;
        if age < KEEP_ALL_SECONDS {
            kept.push(checkpoint);
        } else if age <= window {
            let day = checkpoint.observed.div_euclid(SECONDS_PER_DAY);
            let best = days.entry(day).or_insert(checkpoint);
            if checkpoint.size > best.size {
                *best = checkpoint;
            }
        } else if oldest.is_none_or(|best| checkpoint.size > best.size) {
            oldest = Some(checkpoint);
        }
    }
    kept.extend(days.into_values());
    kept.extend(oldest);
    kept.sort_by_key(|checkpoint| (checkpoint.observed, checkpoint.size));
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(size: u64, observed: i64) -> Checkpoint {
        Checkpoint { size, observed }
    }

    #[test]
    fn checkpoints_append_load_with_the_seed_and_skip_torn_lines() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        let log = Log {
            name: "sum.example",
            seed: Some(at(5, 100)),
        };
        assert_eq!(load(&store, &log).unwrap(), vec![at(5, 100)]);
        record(&store, log.name, at(10, 200)).unwrap();
        let file = store.root.join(TLOG_DIR).join(log.name);
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(b"garbage\n12 3")
            .unwrap();
        record(&store, log.name, at(20, 300)).unwrap();
        // The torn "12 3" ran into the next line, so neither parses whole.
        let loaded = load(&store, &log).unwrap();
        assert!(loaded.contains(&at(10, 200)), "{loaded:?}");
        assert!(loaded.contains(&at(5, 100)), "{loaded:?}");
        assert!(!loaded.iter().any(|checkpoint| checkpoint.size == 12));
        assert!(record(&store, "../escape", at(1, 1)).is_err());
    }

    #[test]
    fn the_eligible_checkpoint_is_the_largest_observed_in_time() {
        let all = [at(10, 100), at(30, 300), at(20, 200)];
        assert_eq!(eligible(&all, 250), Some(at(20, 200)));
        assert_eq!(eligible(&all, 300), Some(at(30, 300)));
        assert_eq!(eligible(&all, 99), None);
    }

    #[test]
    fn thinning_keeps_two_days_then_one_a_day_then_the_oldest_needed() {
        let now = 1_000 * SECONDS_PER_DAY;
        let window = (i64::from(MAX_MIN_AGE_DAYS) + 1) * SECONDS_PER_DAY;
        let recent = [at(900, now - 60), at(901, now - SECONDS_PER_DAY)];
        let day = now - 10 * SECONDS_PER_DAY;
        let day = day - day.rem_euclid(SECONDS_PER_DAY);
        let older = [at(500, day + 10), at(510, day + 20), at(505, day + 30)];
        let ancient = [at(1, now - window - 10), at(2, now - window - 5)];
        let all: Vec<Checkpoint> = recent
            .iter()
            .chain(&older)
            .chain(&ancient)
            .copied()
            .collect();
        let kept = thin(all, now);
        assert_eq!(
            kept,
            vec![
                at(2, now - window - 5),
                at(510, day + 20),
                recent[1],
                recent[0]
            ]
        );
        // Whatever the largest minimum age, the answer is unchanged.
        let before = now - i64::from(MAX_MIN_AGE_DAYS) * SECONDS_PER_DAY;
        let full: Vec<Checkpoint> = recent
            .iter()
            .chain(&older)
            .chain(&ancient)
            .copied()
            .collect();
        assert_eq!(eligible(&kept, before), eligible(&full, before));
    }

    #[test]
    fn a_long_history_is_thinned_on_append() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        let now = 1_000 * SECONDS_PER_DAY;
        for hour in 0..(THIN_AFTER as i64 + 10) {
            let observed = now - 30 * SECONDS_PER_DAY + hour * 3_600;
            record(&store, "sum.example", at(hour as u64, observed)).unwrap();
        }
        let file = store.root.join(TLOG_DIR).join("sum.example");
        let lines = fs::read_to_string(file).unwrap().lines().count();
        assert!(lines < THIN_AFTER, "{lines} lines");
    }
}
