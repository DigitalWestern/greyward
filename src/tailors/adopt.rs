//! What `ward update --adopt` shares across ecosystems: the optional
//! [`Adopter`] capability a tailor offers through `Tailor::adopter`, what
//! the command hands it, what it reports, and the ecosystem-neutral review
//! of the original pins against the compiled ones.
//!
//! A lock no resolver wrote (a hand-hashed `requirements.txt`) proves which
//! bytes to install but not how the dependency set was chosen, so `ward
//! attest` never signs it. Adopting has the ecosystem's resolver compile it
//! through an edit door, which publishes the lock with its signed record.
//! The resolver must not quietly move a pin: a compile that changes a
//! pinned version, drops a pin, or stops accepting an original hash is
//! withheld, with the diff shown, unless the request accepts changes.

use super::edit::EditHost;
use crate::kernel::context::Context;
use crate::kernel::resolve::ResolutionDoor;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// An ecosystem's `ward update --adopt`, reached through
/// `Tailor::adopter`: having one is what makes the ecosystem adoptable.
/// Target selection requires it, so an ecosystem without one is refused
/// (named) or skipped (unnamed) before the store is opened.
pub trait Adopter: Sync {
    /// Turn the lock in `adoption.project` that no resolver wrote into one
    /// this ecosystem's resolver compiles through `door` (an edit door), so
    /// the door publishes it with its signed resolution record. The
    /// original's pins are the resolver's preferences, never upgraded, and
    /// the compiled pins are reviewed against them before anything is
    /// published ([`changes`]). A project whose lock already comes from a
    /// resolver has nothing to adopt.
    fn adopt_lock(
        &self,
        ctx: &Context,
        adoption: &LockAdoption<'_>,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Adoption>;
}

/// What `ward update --adopt` hands an [`Adopter`].
pub struct LockAdoption<'a> {
    /// The project adopted in (the nearest project from the working
    /// directory upward).
    pub project: &'a Path,
    pub host: &'a dyn EditHost,
    /// `--accept-changes`: publish a compile that changes a pinned version
    /// or loses an original hash. Without it such a compile is withheld.
    pub accept_changes: bool,
}

/// One package a lock pins: its version and the integrity hashes the lock
/// accepts for it (`sha256:<hex>`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pin {
    pub version: String,
    pub hashes: BTreeSet<String>,
}

/// A lock's pins by package (a key may carry an environment marker when
/// one package is pinned once per marker).
pub type Pins = BTreeMap<String, Pin>;

/// What `Adopter::adopt_lock` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adoption {
    /// Nothing here needs adopting: the lock already comes from a
    /// resolver, or there is none. The text says why and what to run.
    Nothing(String),
    Adopted(Adopted),
    /// The compile changed what the original pins ([`changes`] lists how)
    /// and the request did not accept changes, so nothing was published.
    /// `review` describes the compile that was withheld.
    Withheld {
        review: Adopted,
        changes: Vec<String>,
    },
}

/// A lock no resolver wrote, compiled by the ecosystem's resolver through
/// the resolution door, with its signed record published (or, inside
/// [`Adoption::Withheld`], the compile that was not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adopted {
    /// The files written, project-relative, for the report line.
    pub files: Vec<String>,
    /// Where the sync after adoption runs.
    pub sync_root: PathBuf,
    /// The lock the resolver wrote, project-relative.
    pub lock: String,
    /// The pins the original lock stated, and the ones the resolver
    /// compiled: the command prints the difference for review.
    pub before: Pins,
    pub after: Pins,
}

/// Every way `after` departs from what `before` pinned: a version that
/// changed, a pin the compiled lock dropped, and an original hash it no
/// longer accepts. A package the resolver added is not a change to an
/// original pin. Empty means the compile kept every pin and every hash.
pub fn changes(before: &Pins, after: &Pins) -> Vec<String> {
    let mut found = Vec::new();
    for (name, old) in before {
        let lost: Vec<&String> = match after.get(name) {
            None => {
                found.push(format!(
                    "{name} {} is not in the compiled lock",
                    old.version
                ));
                old.hashes.iter().collect()
            }
            Some(new) => {
                if new.version != old.version {
                    found.push(format!("{name} {} -> {}", old.version, new.version));
                }
                old.hashes.difference(&new.hashes).collect()
            }
        };
        for hash in lost {
            found.push(format!("{name}: the original hash {hash} is lost"));
        }
    }
    found
}

/// The review lines for one adoption: a line per package (`=` kept, `~`
/// version changed, `+` added by the resolver, `-` not in the compiled
/// lock), and a `!` line for every original hash the compiled lock no
/// longer accepts, a dropped package's included.
pub fn pin_diff(before: &Pins, after: &Pins) -> Vec<String> {
    let mut lines = Vec::new();
    for (name, old) in before {
        let lost: Vec<&String> = match after.get(name) {
            None => {
                lines.push(format!(
                    "- {name} {} (not in the compiled lock)",
                    old.version
                ));
                old.hashes.iter().collect()
            }
            Some(new) if old.version == new.version => {
                let kept = old.hashes.intersection(&new.hashes).count();
                let added = new.hashes.difference(&old.hashes).count();
                lines.push(format!(
                    "= {name} {} (hashes: {kept} of {} kept, {added} added)",
                    new.version,
                    old.hashes.len()
                ));
                old.hashes.difference(&new.hashes).collect()
            }
            Some(new) => {
                lines.push(format!("~ {name} {} -> {}", old.version, new.version));
                old.hashes.difference(&new.hashes).collect()
            }
        };
        for hash in lost {
            lines.push(format!(
                "! {name}: the original hash {hash} is not in the compiled lock"
            ));
        }
    }
    for (name, new) in after {
        if !before.contains_key(name) {
            lines.push(format!("+ {name} {} (added by the resolver)", new.version));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(version: &str, hashes: &[&str]) -> Pin {
        Pin {
            version: version.to_string(),
            hashes: hashes.iter().map(|hash| hash.to_string()).collect(),
        }
    }

    fn sample() -> (Pins, Pins) {
        let before: Pins = [
            ("six".to_string(), pin("1.16.0", &["sha256:a"])),
            ("idna".to_string(), pin("3.9", &["sha256:i"])),
            ("gone".to_string(), pin("1.0", &["sha256:g1", "sha256:g2"])),
            ("swapped".to_string(), pin("2.0", &["sha256:old"])),
        ]
        .into_iter()
        .collect();
        let after: Pins = [
            ("six".to_string(), pin("1.16.0", &["sha256:a", "sha256:b"])),
            ("idna".to_string(), pin("3.10", &["sha256:j"])),
            ("swapped".to_string(), pin("2.0", &["sha256:new"])),
            ("new".to_string(), pin("0.1", &[])),
        ]
        .into_iter()
        .collect();
        (before, after)
    }

    #[test]
    fn the_diff_names_every_pin_and_every_lost_hash_a_dropped_package_included() {
        let (before, after) = sample();
        assert_eq!(
            pin_diff(&before, &after),
            [
                "- gone 1.0 (not in the compiled lock)",
                "! gone: the original hash sha256:g1 is not in the compiled lock",
                "! gone: the original hash sha256:g2 is not in the compiled lock",
                "~ idna 3.9 -> 3.10",
                "! idna: the original hash sha256:i is not in the compiled lock",
                "= six 1.16.0 (hashes: 1 of 1 kept, 1 added)",
                "= swapped 2.0 (hashes: 0 of 1 kept, 1 added)",
                "! swapped: the original hash sha256:old is not in the compiled lock",
                "+ new 0.1 (added by the resolver)",
            ]
        );
    }

    #[test]
    fn changes_are_moved_or_dropped_pins_and_lost_hashes_never_additions() {
        let (before, after) = sample();
        assert_eq!(
            changes(&before, &after),
            [
                "gone 1.0 is not in the compiled lock",
                "gone: the original hash sha256:g1 is lost",
                "gone: the original hash sha256:g2 is lost",
                "idna 3.9 -> 3.10",
                "idna: the original hash sha256:i is lost",
                "swapped: the original hash sha256:old is lost",
            ]
        );
        // Kept pins with more hashes, and packages the resolver added,
        // change nothing the original pinned.
        let kept: Pins = [("six".to_string(), pin("1.16.0", &["sha256:a"]))]
            .into_iter()
            .collect();
        let grown: Pins = [
            ("six".to_string(), pin("1.16.0", &["sha256:a", "sha256:b"])),
            ("new".to_string(), pin("0.1", &[])),
        ]
        .into_iter()
        .collect();
        assert!(changes(&kept, &grown).is_empty());
    }
}
