//! The rubygems.org gems a Gemfile.lock names, for the door's
//! `young-package` check (`kernel::resolve::age`): every spec of a `GEM`
//! section whose `remote:` is rubygems.org, at its locked version (with its
//! platform, `1.15.0-x86_64-linux`, as the compact index spells it). Git,
//! path and other-remote gems are left out.

use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::path::Path;

/// The [`LockedList`] of a Bundler run: its `Gemfile.lock`.
pub(crate) fn locked_list<'a>() -> LockedList<'a> {
    Box::new(|staged: &Staged<'_>| {
        Ok(match staged.read(Path::new("Gemfile.lock"))? {
            Some(bytes) => rubygems_specs(&String::from_utf8_lossy(&bytes)),
            None => Vec::new(),
        })
    })
}

/// The `name (version)` lines at four spaces under `specs:` in every
/// `GEM` section whose remote is rubygems.org (dependency lines sit at six).
pub(crate) fn rubygems_specs(text: &str) -> Vec<LockedPackage> {
    let mut found = Vec::new();
    let mut in_gem = false;
    let mut public = false;
    let mut in_specs = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            in_gem = line == "GEM";
            public = false;
            in_specs = false;
            continue;
        }
        if !in_gem {
            continue;
        }
        if let Some(remote) = line.strip_prefix("  remote: ") {
            let remote = remote.trim().trim_end_matches('/');
            public = matches!(
                remote,
                "https://rubygems.org" | "https://index.rubygems.org"
            );
            continue;
        }
        if line == "  specs:" {
            in_specs = true;
            continue;
        }
        if !(in_specs && public) {
            continue;
        }
        let Some(spec) = line.strip_prefix("    ") else {
            continue;
        };
        if spec.starts_with(' ') {
            continue;
        }
        let Some((name, rest)) = spec.split_once(" (") else {
            continue;
        };
        let Some(version) = rest.strip_suffix(')') else {
            continue;
        };
        if !name.is_empty() && !version.is_empty() {
            found.push(LockedPackage::new(name, version));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemfile_locks_list_rubygems_specs_only() {
        let lock = "GIT\n  remote: https://github.com/a/b.git\n  revision: abc\n  specs:\n    \
                    forked (0.1.0)\n\n\
                    GEM\n  remote: https://rubygems.org/\n  specs:\n    \
                    nokogiri (1.15.0-x86_64-linux)\n      racc (~> 1.4)\n    \
                    racc (1.7.3)\n    rake (13.4.2)\n\n\
                    GEM\n  remote: https://gems.example.com/\n  specs:\n    private (1.0.0)\n\n\
                    PATH\n  remote: vendor/local\n  specs:\n    local (0.0.1)\n\n\
                    PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n\nBUNDLED WITH\n   2.5.0\n";
        assert_eq!(
            rubygems_specs(lock),
            [
                LockedPackage::new("nokogiri", "1.15.0-x86_64-linux"),
                LockedPackage::new("racc", "1.7.3"),
                LockedPackage::new("rake", "13.4.2"),
            ]
        );
    }
}
