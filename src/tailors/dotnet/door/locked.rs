//! The nuget.org packages a restore's packages.lock.json files pin, for the
//! door's `young-package` check (`kernel::resolve::age`). Every package
//! came through the one source the greyward-written nuget.config names,
//! api.nuget.org, so every Direct and Transitive entry counts.

use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::path::PathBuf;

/// The [`LockedList`] of a restore publishing `outputs`: each of them
/// named `packages.lock.json` that the run left, read as the strict lock
/// reader reads it. Outputs name a lock beside every project file in the
/// tree, and a project restore never reached writes none; the members'
/// locks are required by the run's result check before this reads them.
pub(crate) fn locked_list<'a>(outputs: Vec<PathBuf>) -> LockedList<'a> {
    Box::new(move |staged: &Staged<'_>| {
        let mut found = Vec::new();
        for path in outputs.iter().filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "packages.lock.json")
        }) {
            if let Some(bytes) = staged.read(path)? {
                found.extend(lock_packages(&String::from_utf8_lossy(&bytes))?);
            }
        }
        Ok(found)
    })
}

fn lock_packages(text: &str) -> std::io::Result<Vec<LockedPackage>> {
    Ok(super::super::parse_lock(text)?
        .packages
        .into_iter()
        .map(|package| LockedPackage::new(&package.id, &package.version))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_locks_list_every_pinned_package() {
        let lock = r#"{"version": 1, "dependencies": {"net8.0": {
            "Humanizer.Core": {"type": "Direct", "requested": "[2.14.1, )",
                "resolved": "2.14.1", "contentHash": "abc"},
            "Newtonsoft.Json": {"type": "Transitive", "resolved": "13.0.3",
                "contentHash": "def"}}}}"#;
        assert_eq!(
            lock_packages(lock).unwrap(),
            [
                LockedPackage::new("Humanizer.Core", "2.14.1"),
                LockedPackage::new("Newtonsoft.Json", "13.0.3"),
            ]
        );
    }
}
