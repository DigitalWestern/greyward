//! `lookalike-name`: is a package name one edit away from a popular
//! package's name without being it? A typosquat (`reqeusts` for
//! `requests`, `crossenv` for `cross-env`) is named to be mistyped into a
//! manifest, so the name alone is the signal.
//!
//! Each tailor embeds its registry's most popular names (`popular.txt`
//! beside it, written by `tools/popular.py`) and its own normalization:
//! the rule by which its registry treats two spellings as one package, so
//! `Django` and `django` are the same name and never a lookalike. One edit
//! is the optimal string alignment distance: one character inserted,
//! removed, replaced, or two adjacent characters swapped.

use std::collections::{BTreeMap, BTreeSet};

/// Names shorter than this are never judged: among short names nearly
/// every one is an edit away from some popular one.
pub const MIN_LEN: usize = 5;

/// One registry's popular names, normalized and indexed by length so a
/// lookup compares only names within one character of its own length.
pub struct Popular {
    normalize: fn(&str) -> String,
    names: BTreeSet<String>,
    by_len: BTreeMap<usize, Vec<String>>,
}

impl Popular {
    /// The list in `text`: one name per line, `#` lines are comments.
    pub fn parse(text: &str, normalize: fn(&str) -> String) -> Popular {
        let mut names = BTreeSet::new();
        let mut by_len: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = normalize(line);
            if names.insert(name.clone()) {
                by_len.entry(name.chars().count()).or_default().push(name);
            }
        }
        Popular {
            normalize,
            names,
            by_len,
        }
    }

    /// How many distinct names the list holds.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The popular name `name` is one edit away from, when it is not
    /// itself popular and is at least [`MIN_LEN`] characters long. The
    /// first in sorted order when several are.
    pub fn lookalike(&self, name: &str) -> Option<&str> {
        let name = (self.normalize)(name);
        let len = name.chars().count();
        if len < MIN_LEN || self.names.contains(&name) {
            return None;
        }
        let name: Vec<char> = name.chars().collect();
        let mut found: Option<&str> = None;
        for candidates in self.by_len.range(len - 1..=len + 1).map(|(_, v)| v) {
            for candidate in candidates {
                if within_one_edit(&name, candidate)
                    && found.is_none_or(|best| candidate.as_str() < best)
                {
                    found = Some(candidate);
                }
            }
        }
        found
    }
}

/// Is the optimal string alignment distance between `a` and `b` exactly
/// one? Equal strings are not.
fn within_one_edit(a: &[char], b: &str) -> bool {
    let b: Vec<char> = b.chars().collect();
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[prefix..], &b[prefix..]);
    let suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (a, b) = (&a[..a.len() - suffix], &b[..b.len() - suffix]);
    match (a.len(), b.len()) {
        // One inserted or removed, or one replaced.
        (0, 1) | (1, 0) | (1, 1) => true,
        // Two adjacent characters swapped.
        (2, 2) => a[0] == b[1] && a[1] == b[0],
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(name: &str) -> String {
        name.to_ascii_lowercase()
    }

    fn list() -> Popular {
        Popular::parse(
            "# a header\nrequests\ncross-env\nDjango\nlodash\nurllib3\nreact\n",
            lower,
        )
    }

    #[test]
    fn one_edit_from_a_popular_name_is_a_lookalike() {
        let popular = list();
        assert_eq!(popular.len(), 6);
        // Swapped, removed, inserted, replaced.
        assert_eq!(popular.lookalike("reqeusts"), Some("requests"));
        assert_eq!(popular.lookalike("crossenv"), Some("cross-env"));
        assert_eq!(popular.lookalike("lodashs"), Some("lodash"));
        assert_eq!(popular.lookalike("urllib4"), Some("urllib3"));
        assert_eq!(popular.lookalike("Djangoo"), Some("django"));
    }

    #[test]
    fn the_popular_name_itself_short_names_and_distant_names_are_not() {
        let popular = list();
        assert_eq!(popular.lookalike("requests"), None);
        assert_eq!(
            popular.lookalike("DJANGO"),
            None,
            "same name once normalized"
        );
        assert_eq!(popular.lookalike("reakt"), Some("react"));
        assert_eq!(popular.lookalike("rect"), None, "shorter than MIN_LEN");
        assert_eq!(popular.lookalike("rqeusets"), None, "two edits");
        assert_eq!(popular.lookalike("numpy"), None);
    }

    #[test]
    fn the_edit_distance_counts_one_adjacent_swap_as_one_edit() {
        let a: Vec<char> = "abcdef".chars().collect();
        assert!(within_one_edit(&a, "abdcef"));
        assert!(within_one_edit(&a, "bacdef"));
        assert!(within_one_edit(&a, "abcdfe"));
        assert!(within_one_edit(&a, "abcde"));
        assert!(within_one_edit(&a, "xabcdef"));
        assert!(!within_one_edit(&a, "abcdef"));
        assert!(!within_one_edit(&a, "acbdfe"));
        assert!(!within_one_edit(&a, "abdecf"), "a rotation is two edits");
    }
}
