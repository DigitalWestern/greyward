//! The hex.pm packages a mix.lock names, for the door's `young-package`
//! check (`kernel::resolve::age`). A line is
//! `"jason": {:hex, :jason, "1.4.4", "<inner>", [:mix], [<deps>], "hexpm", "<outer>"},`
//! and only the public `hexpm` repository counts: an organization's
//! `hexpm:<org>`, git and path dependencies are left out. The repository is
//! the second-to-last element, read from the end, because a dependency in
//! `<deps>` names `repo: "hexpm"` too.

use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::io;
use std::path::Path;

/// The [`LockedList`] of a mix run: its `mix.lock`.
pub(crate) fn locked_list<'a>() -> LockedList<'a> {
    Box::new(
        |staged: &Staged<'_>| match staged.read(Path::new("mix.lock"))? {
            Some(bytes) => hexpm_packages(&String::from_utf8_lossy(&bytes)),
            None => Ok(Vec::new()),
        },
    )
}

/// Every `{:hex, :name, "version", ..., "hexpm", "<outer>"}` entry. Mix
/// writes one entry a line inside `%{` and `}`; any other line, or a
/// `:hex` entry this reader cannot take apart, is `InvalidData`, since a
/// package it skipped would never be judged.
pub(crate) fn hexpm_packages(text: &str) -> io::Result<Vec<LockedPackage>> {
    let mut packages = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if matches!(trimmed, "" | "%{" | "}") {
            continue;
        }
        let unreadable = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("mix.lock line {} is not an entry ward can read", number + 1),
            )
        };
        let (key, entry) = trimmed.split_once("\": {:").ok_or_else(unreadable)?;
        if !key.starts_with('"') {
            return Err(unreadable());
        }
        // `:git`, `:path` and the like name no registry version.
        if !entry.starts_with("hex, :") {
            continue;
        }
        let (name, version, repository) = hex_entry(trimmed).ok_or_else(unreadable)?;
        if repository == "\"hexpm\"" {
            packages.push(LockedPackage::new(name, version));
        }
    }
    Ok(packages)
}

/// A `:hex` entry's package, version, and repository (quoted).
fn hex_entry(line: &str) -> Option<(&str, &str, &str)> {
    let (_, entry) = line.split_once("{:hex, :")?;
    let (name, rest) = entry.split_once(", \"")?;
    let (version, _) = rest.split_once('"')?;
    let tail = line.trim_end_matches(',').strip_suffix('}')?;
    let mut from_end = tail.rsplitn(3, ", ");
    from_end.next()?;
    let repository = from_end.next()?;
    from_end.next()?;
    Some((name, version, repository))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_locks_list_public_hex_packages_only() {
        let lock = "%{\n  \
            \"decimal\": {:hex, :decimal, \"2.3.0\", \"aa\", [:mix], [], \"hexpm\", \"bb\"},\n  \
            \"ecto\": {:hex, :ecto, \"3.12.5\", \"cc\", [:mix], [{:decimal, \"~> 2.0\", \
            [hex: :decimal, repo: \"hexpm\", optional: false]}], \"hexpm\", \"dd\"},\n  \
            \"secret\": {:hex, :secret, \"1.0.0\", \"ee\", [:mix], [{:decimal, \"~> 2.0\", \
            [hex: :decimal, repo: \"hexpm\", optional: false]}], \"hexpm:acme\", \"ff\"},\n  \
            \"forked\": {:git, \"https://github.com/a/b.git\", \"abc\", []},\n\
            }\n";
        assert_eq!(
            hexpm_packages(lock).unwrap(),
            [
                LockedPackage::new("decimal", "2.3.0"),
                LockedPackage::new("ecto", "3.12.5"),
            ]
        );
    }

    #[test]
    fn a_mix_lock_line_the_reader_cannot_take_apart_is_refused() {
        for lock in [
            "%{\n  \"decimal\": {:hex, :decimal, \"2.3.0\", \"aa\", [:mix], [], \"hexpm\", \"bb\"},\n  junk\n}\n",
            "%{\n  \"decimal\": {:hex, :decimal}\n}\n",
            "%{\n  \"decimal\": {:hex, :decimal, \"2.3.0\", \"aa\", [:mix], [],\n}\n",
        ] {
            let error = hexpm_packages(lock).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{lock}");
            assert!(error.to_string().contains("mix.lock line"), "{error}");
        }
        assert!(hexpm_packages("").unwrap().is_empty());
    }
}
