//! The hex.pm packages a mix.lock names, for the door's `young-package`
//! check (`kernel::resolve::age`). A line is
//! `"jason": {:hex, :jason, "1.4.4", "<inner>", [:mix], [<deps>], "hexpm", "<outer>"},`
//! and only the public `hexpm` repository counts: an organization's
//! `hexpm:<org>`, git and path dependencies are left out. The repository is
//! the second-to-last element, read from the end, because a dependency in
//! `<deps>` names `repo: "hexpm"` too.

use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::path::Path;

/// The [`LockedList`] of a mix run: its `mix.lock`.
pub(crate) fn locked_list<'a>() -> LockedList<'a> {
    Box::new(|staged: &Staged<'_>| {
        Ok(match staged.read(Path::new("mix.lock"))? {
            Some(bytes) => hexpm_packages(&String::from_utf8_lossy(&bytes)),
            None => Vec::new(),
        })
    })
}

/// Every `{:hex, :name, "version", ..., "hexpm", "<outer>"}` entry.
pub(crate) fn hexpm_packages(text: &str) -> Vec<LockedPackage> {
    text.lines().filter_map(hexpm_package).collect()
}

fn hexpm_package(line: &str) -> Option<LockedPackage> {
    let (_, entry) = line.split_once("{:hex, :")?;
    let (name, rest) = entry.split_once(", \"")?;
    let (version, _) = rest.split_once('"')?;
    let tail = line.trim().trim_end_matches(',').strip_suffix('}')?;
    let mut from_end = tail.rsplitn(3, ", ");
    from_end.next()?;
    (from_end.next()? == "\"hexpm\"").then(|| LockedPackage::new(name, version))
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
            hexpm_packages(lock),
            [
                LockedPackage::new("decimal", "2.3.0"),
                LockedPackage::new("ecto", "3.12.5"),
            ]
        );
    }
}
