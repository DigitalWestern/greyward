//! The `[packages]` policy table (kernel layer): limits on the registry
//! packages a resolution may lock. Today one: `min_age_days`, the youngest a
//! locked version may be when it is resolved (`young-package`).
//!
//! Like the deny list, the table only tightens across the chain. The
//! machine policy sets the floor (any value in range, the default 7 when it
//! says nothing); a project policy, or the file handed to `ward audit
//! --policy`, may only raise it. So a project can never lower the minimum
//! below the machine's, nor below the default.

use super::{Policy, SourceOrigin};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

/// The minimum age, in days, when no policy sets one.
pub const DEFAULT_MIN_AGE_DAYS: u32 = 7;
/// The largest `min_age_days` a file may set: a year. A larger value is a
/// typo, not a policy.
pub const MAX_MIN_AGE_DAYS: u32 = 365;

/// The `[packages]` table as a file spells it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    /// A locked registry version published fewer than this many days before
    /// its resolution is a `young-package` exception. `0` means no minimum
    /// (only the machine policy can set it that low).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_age_days: Option<u32>,
}

impl Policy {
    /// The effective minimum age of a locked version, in days.
    pub fn min_age_days(&self) -> u32 {
        self.packages
            .as_ref()
            .and_then(|packages| packages.min_age_days)
            .unwrap_or(DEFAULT_MIN_AGE_DAYS)
    }
}

/// Refuse a value out of range, naming the file and the range.
pub(super) fn validate(path: &Path, policy: &Policy) -> io::Result<()> {
    match policy.packages.as_ref().and_then(|p| p.min_age_days) {
        Some(days) if days > MAX_MIN_AGE_DAYS => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: [packages] min_age_days = {days} is out of range; use 0 to \
                 {MAX_MIN_AGE_DAYS} (days)",
                path.display()
            ),
        )),
        _ => Ok(()),
    }
}

/// Whether `other` declares a minimum age.
pub(super) fn sets_min_age(other: &Policy) -> bool {
    other
        .packages
        .as_ref()
        .is_some_and(|packages| packages.min_age_days.is_some())
}

/// Merge `other`'s table into the chain. The machine scope sets the floor;
/// every other scope can only raise what is in force.
pub(super) fn merge(policy: &mut Policy, other: &Policy, origin: SourceOrigin) {
    let Some(days) = other.packages.as_ref().and_then(|p| p.min_age_days) else {
        return;
    };
    let effective = match origin {
        SourceOrigin::Machine => days,
        SourceOrigin::Project | SourceOrigin::Flag | SourceOrigin::Env => {
            days.max(policy.min_age_days())
        }
    };
    policy
        .packages
        .get_or_insert_with(Packages::default)
        .min_age_days = Some(effective);
}

#[cfg(test)]
mod tests {
    use super::super::parse_file;
    use super::*;

    fn file(days: u32) -> Policy {
        Policy {
            packages: Some(Packages {
                min_age_days: Some(days),
            }),
            ..Policy::default()
        }
    }

    #[test]
    fn the_default_is_seven_days() {
        assert_eq!(Policy::default().min_age_days(), 7);
        let parsed = parse_file(Path::new("p.toml"), "deny = []\n").unwrap();
        assert_eq!(parsed.min_age_days(), DEFAULT_MIN_AGE_DAYS);
    }

    #[test]
    fn a_project_cannot_lower_the_minimum_and_the_largest_wins() {
        // Alone, a lower project value does not lower the default.
        let mut chain = Policy::default();
        merge(&mut chain, &file(3), SourceOrigin::Project);
        assert_eq!(chain.min_age_days(), 7);
        // Nor the machine's.
        let mut chain = Policy::default();
        merge(&mut chain, &file(14), SourceOrigin::Machine);
        merge(&mut chain, &file(10), SourceOrigin::Project);
        assert_eq!(chain.min_age_days(), 14);
        // A project may raise it, and the largest of several wins.
        merge(&mut chain, &file(30), SourceOrigin::Project);
        merge(&mut chain, &file(21), SourceOrigin::Flag);
        assert_eq!(chain.min_age_days(), 30);
        // The machine policy may set any floor, below the default too.
        let mut chain = Policy::default();
        merge(&mut chain, &file(2), SourceOrigin::Machine);
        assert_eq!(chain.min_age_days(), 2);
        merge(&mut chain, &file(1), SourceOrigin::Project);
        assert_eq!(chain.min_age_days(), 2);
    }

    #[test]
    fn out_of_range_and_unknown_keys_are_refused() {
        let error = parse_file(Path::new("p.toml"), "[packages]\nmin_age_days = 400\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("out of range"), "{error}");
        assert!(error.contains("p.toml"), "{error}");
        for text in [
            "[packages]\nmin_age_days = -1\n",
            "[packages]\nmin_age_days = \"7\"\n",
            "[packages]\nmin_age = 7\n",
        ] {
            assert!(parse_file(Path::new("p.toml"), text).is_err(), "{text}");
        }
        for days in [0, 7, MAX_MIN_AGE_DAYS] {
            let text = format!("[packages]\nmin_age_days = {days}\n");
            assert_eq!(
                parse_file(Path::new("p.toml"), &text)
                    .unwrap()
                    .min_age_days(),
                days
            );
        }
    }
}
