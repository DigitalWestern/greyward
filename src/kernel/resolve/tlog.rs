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
//! A checkpoint is one such head: the verified tree size, its root hash,
//! and the local time ward observed it. Verified heads ward serves (the
//! tool's own checksum-database traffic, and ward's lookups) are appended
//! to `<store>/resolve/tlog/<log name>` as lines
//! `<size> <unix seconds> <root, base64>`. A version passes when its
//! record number is below the size of the largest checkpoint observed at
//! least the minimum age before the resolution; a later record's age is
//! unknown. The binary also carries one seed checkpoint per log (verified
//! when it was generated, and again on load), so a fresh store has one to
//! judge by once the seed is old enough.
//!
//! What is checked of the log, and what is not:
//!
//! - Each head's signature, by the log's key, before it is kept.
//! - A head of a size already kept must carry the same root: two roots for
//!   one size mean the log forked (or a head is forged), and the body that
//!   carried the second is refused ([`RecordError::Fork`]). A head smaller
//!   than one already kept is no error: lookup answers carry whatever head
//!   the database had cached.
//! - Consistency between heads of different sizes (the log's consistency
//!   proofs) is not checked, nor that a record sits in the tree it claims:
//!   the record number is trusted from the TLS connection to the database
//!   and the signed head it arrives with.
//!
//! The file grows by at most one line per [`MIN_SPACING_SECONDS`] and none
//! for a head already kept, and is thinned as it grows: every checkpoint of
//! the last two days, then the largest of each UTC day, back to the longest
//! minimum age a policy may set (and the largest one older than that).
//! Appends and the thinning rewrite run under an exclusive lock on a file
//! beside it. The file is only as trustworthy as the store's permissions:
//! anyone who can write it can claim any checkpoint, and a local clock that
//! was set back when a head was observed dates the head too early.

use crate::kernel::policy::MAX_MIN_AGE_DAYS;
use crate::kernel::store::Store;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const SECONDS_PER_DAY: i64 = 86_400;
/// The checkpoint files' namespace in the store.
const TLOG_DIR: &str = "resolve/tlog";
/// Past this many lines, the history is thinned on the next append, when
/// thinning drops at least a quarter of it.
const THIN_AFTER: usize = 1024;
/// Everything observed this recently is kept as it is.
const KEEP_ALL_SECONDS: i64 = 2 * SECONDS_PER_DAY;
/// A head observed this soon after (or before) a kept checkpoint is not
/// kept: a busy log signs a new head every few seconds, and one a few
/// minutes newer changes no verdict.
pub const MIN_SPACING_SECONDS: i64 = 10 * 60;

/// An append-only log a registry protocol judges age by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Log {
    /// The log's name, as its signed heads name it (`sum.golang.org`); the
    /// checkpoint file is named after it.
    pub name: &'static str,
    /// The checkpoint the binary carries, when it verified.
    pub seed: Option<Checkpoint>,
}

/// A verified tree head: how many records the tree held, and its root hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub size: u64,
    pub root: [u8; 32],
}

/// A verified tree head and when ward observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Checkpoint {
    pub size: u64,
    /// Unix seconds, by the local clock.
    pub observed: i64,
    pub root: [u8; 32],
}

impl Checkpoint {
    pub fn new(head: Head, observed: i64) -> Self {
        Checkpoint {
            size: head.size,
            observed,
            root: head.root,
        }
    }

    fn line(&self) -> String {
        format!(
            "{} {} {}\n",
            self.size,
            self.observed,
            crate::kernel::base64::encode(&self.root)
        )
    }
}

/// Why a head was not kept.
#[derive(Debug)]
pub enum RecordError {
    /// The log signed two different trees of one size: it forked, or a
    /// head is forged. Whatever carried the head is refused.
    Fork(String),
    /// The checkpoint file could not be read or written: a missing
    /// checkpoint only passes fewer versions.
    Io(io::Error),
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Fork(why) => f.write_str(why),
            RecordError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl From<io::Error> for RecordError {
    fn from(error: io::Error) -> Self {
        RecordError::Io(error)
    }
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

/// Keep `head` of `log`, observed at `observed`, unless a checkpoint of
/// the same head or one observed within [`MIN_SPACING_SECONDS`] is kept
/// already; thin the history when it has grown. `true` when a line was
/// appended. A head whose size a kept checkpoint (or the seed) has with
/// another root is [`RecordError::Fork`], however it was observed.
pub fn record(store: &Store, log: &Log, head: Head, observed: i64) -> Result<bool, RecordError> {
    let path = path(store, log.name)?;
    let lock = fs::File::options()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.with_file_name(format!(".{}.lock", log.name)))?;
    lock.lock()?;
    let mut kept = read(&path)?;
    kept.extend(log.seed);
    if let Some(other) = kept
        .iter()
        .find(|kept| kept.size == head.size && kept.root != head.root)
    {
        let base64 = crate::kernel::base64::encode;
        return Err(RecordError::Fork(format!(
            "{} signed two different trees of {} records: root {} (observed {}) and root {} now; \
             the log forked, or one head is forged",
            log.name,
            head.size,
            base64(&other.root),
            super::age::format_utc(other.observed),
            base64(&head.root),
        )));
    }
    let near = |kept: &Checkpoint| (kept.observed - observed).abs() < MIN_SPACING_SECONDS;
    if kept.iter().any(|kept| kept.size == head.size || near(kept)) {
        return Ok(false);
    }
    let checkpoint = Checkpoint::new(head, observed);
    fs::File::options()
        .create(true)
        .append(true)
        .open(&path)?
        .write_all(checkpoint.line().as_bytes())?;
    let text = fs::read_to_string(&path)?;
    let lines = text.lines().count();
    if lines > THIN_AFTER {
        let thinned = thin(parse(&text), observed);
        // Only when it drops a quarter: a history thinning cannot shrink
        // is not rewritten on every append.
        if thinned.len() * 4 <= lines * 3 {
            let out: String = thinned.iter().map(Checkpoint::line).collect();
            // Rewritten beside the file and renamed over it, under the
            // lock, so no append is lost meanwhile.
            let fresh = path.with_file_name(format!(".{}.thin", log.name));
            let written = fs::write(&fresh, out).and_then(|()| fs::rename(&fresh, &path));
            if written.is_err() {
                let _ = fs::remove_file(&fresh);
            }
            written?;
        }
    }
    Ok(true)
}

/// Every checkpoint of `log` the store holds, and its seed.
pub fn load(store: &Store, log: &Log) -> io::Result<Vec<Checkpoint>> {
    let mut checkpoints = read(&path(store, log.name)?)?;
    checkpoints.extend(log.seed);
    Ok(checkpoints)
}

fn read(path: &Path) -> io::Result<Vec<Checkpoint>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse(&text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// The lines that parse; a torn or foreign line is skipped.
fn parse(text: &str) -> Vec<Checkpoint> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split(' ');
            let (size, observed, root) = (words.next()?, words.next()?, words.next()?);
            if words.next().is_some() {
                return None;
            }
            Some(Checkpoint {
                size: size.parse().ok()?,
                observed: observed.parse().ok()?,
                root: crate::kernel::base64::decode_padded(root)?
                    .try_into()
                    .ok()?,
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

    /// A distinct root per size, as a log that never forks has.
    fn head(size: u64) -> Head {
        let mut root = [0; 32];
        root[..8].copy_from_slice(&size.to_be_bytes());
        Head { size, root }
    }

    fn at(size: u64, observed: i64) -> Checkpoint {
        Checkpoint::new(head(size), observed)
    }

    const EXAMPLE: Log = Log {
        name: "sum.example",
        seed: None,
    };

    #[test]
    fn checkpoints_append_load_with_the_seed_and_skip_torn_lines() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        let log = Log {
            name: "sum.example",
            seed: Some(at(5, 100)),
        };
        assert_eq!(load(&store, &log).unwrap(), vec![at(5, 100)]);
        assert!(record(&store, &log, head(10), 2_000).unwrap());
        let file = store.root.join(TLOG_DIR).join(log.name);
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(b"garbage\n12 3")
            .unwrap();
        assert!(record(&store, &log, head(20), 3_000).unwrap());
        // The torn "12 3" ran into the next line, so neither parses whole.
        let loaded = load(&store, &log).unwrap();
        assert!(loaded.contains(&at(10, 2_000)), "{loaded:?}");
        assert!(loaded.contains(&at(5, 100)), "{loaded:?}");
        assert!(!loaded.iter().any(|checkpoint| checkpoint.size == 12));
        let escape = Log {
            name: "../escape",
            seed: None,
        };
        assert!(record(&store, &escape, head(1), 1).is_err());
    }

    #[test]
    fn a_kept_head_or_one_observed_too_soon_is_not_kept_again() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        assert!(record(&store, &EXAMPLE, head(10), 10_000).unwrap());
        // The same head a day later, a newer one minutes later.
        assert!(!record(&store, &EXAMPLE, head(10), 10_000 + SECONDS_PER_DAY).unwrap());
        assert!(!record(&store, &EXAMPLE, head(11), 10_000 + 60).unwrap());
        assert!(!record(&store, &EXAMPLE, head(9), 10_000 - 60).unwrap());
        assert!(record(&store, &EXAMPLE, head(11), 10_000 + MIN_SPACING_SECONDS).unwrap());
        assert_eq!(
            load(&store, &EXAMPLE).unwrap(),
            vec![at(10, 10_000), at(11, 10_000 + MIN_SPACING_SECONDS)]
        );
    }

    #[test]
    fn one_size_with_two_roots_is_a_fork_and_a_smaller_head_is_not() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        let log = Log {
            name: "sum.example",
            seed: Some(at(5, 100)),
        };
        assert!(record(&store, &log, head(10), 10_000).unwrap());
        let mut forked = head(10);
        forked.root[31] ^= 1;
        let error = record(&store, &log, forked, 20_000).unwrap_err();
        assert!(
            matches!(&error, RecordError::Fork(why) if why.contains("two different trees of 10")),
            "{error}"
        );
        // Against the seed too.
        let mut forked = head(5);
        forked.root[0] ^= 1;
        assert!(matches!(
            record(&store, &log, forked, 30_000),
            Err(RecordError::Fork(_))
        ));
        // An older, smaller head, as a cached lookup answer carries.
        assert!(record(&store, &log, head(7), 40_000).unwrap());
        assert_eq!(
            load(&store, &log).unwrap(),
            vec![at(10, 10_000), at(7, 40_000), at(5, 100)]
        );
    }

    #[test]
    fn concurrent_appends_lose_nothing() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        let store = std::sync::Arc::new(store);
        let threads: Vec<_> = (0..8u64)
            .map(|thread| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for step in 0..40u64 {
                        let size = thread * 1_000 + step;
                        let observed = (size as i64) * MIN_SPACING_SECONDS;
                        assert!(record(&store, &EXAMPLE, head(size), observed).unwrap());
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let mut loaded = load(&store, &EXAMPLE).unwrap();
        loaded.sort();
        let mut expected: Vec<Checkpoint> = (0..8u64)
            .flat_map(|thread| (0..40u64).map(move |step| thread * 1_000 + step))
            .map(|size| at(size, (size as i64) * MIN_SPACING_SECONDS))
            .collect();
        expected.sort();
        assert_eq!(loaded, expected);
        let file = store.root.join(TLOG_DIR).join(EXAMPLE.name);
        assert_eq!(fs::read_to_string(file).unwrap().lines().count(), 320);
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
        let kept = thin(all.clone(), now);
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
        assert_eq!(eligible(&kept, before), eligible(&all, before));
    }

    #[test]
    fn a_long_history_is_thinned_on_append() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("tlog");
        let file = store.root.join(TLOG_DIR).join(EXAMPLE.name);
        let start = 1_000 * SECONDS_PER_DAY;
        let hours = THIN_AFTER as i64 + 10;
        for hour in 0..hours {
            record(&store, &EXAMPLE, head(hour as u64), start + hour * 3_600).unwrap();
            let lines = fs::read_to_string(&file).unwrap().lines().count();
            assert!(lines <= THIN_AFTER, "{lines} lines after hour {hour}");
        }
        let lines = fs::read_to_string(&file).unwrap().lines().count();
        // Two days of hourly heads and one a day before them.
        assert!(lines < 120, "{lines} lines");
        // Every head of the last two days is still there.
        let last = start + (hours - 1) * 3_600;
        let loaded = load(&store, &EXAMPLE).unwrap();
        for hour in 0..48 {
            let observed = last - hour * 3_600;
            assert!(
                loaded.iter().any(|kept| kept.observed == observed),
                "{hour}"
            );
        }
    }
}
