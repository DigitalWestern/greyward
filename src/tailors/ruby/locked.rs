//! The rubygems.org gems a Gemfile.lock names, for the door's
//! `young-package` check (`kernel::resolve::age`): every spec of a `GEM`
//! section whose `remote:` is rubygems.org, at its locked version (with its
//! platform, `1.15.0-x86_64-linux`, as the compact index spells it). Git,
//! path and other-remote gems are left out.

use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::io;
use std::path::Path;

/// The [`LockedList`] of a Bundler run: its `Gemfile.lock`.
pub(crate) fn locked_list<'a>() -> LockedList<'a> {
    Box::new(
        |staged: &Staged<'_>| match staged.read(Path::new("Gemfile.lock"))? {
            Some(bytes) => rubygems_specs(&String::from_utf8_lossy(&bytes)),
            None => Ok(Vec::new()),
        },
    )
}

/// The `name (version)` lines at four spaces under `specs:` in every
/// `GEM` section whose remote is rubygems.org (dependency lines sit at six).
///
/// A `GEM` section line this reader does not know, a second `remote:` in
/// one section (which spec came from which remote is then not written
/// down), or a rubygems.org spec line it cannot take apart is
/// `InvalidData`: a gem it skipped would never be judged.
pub(crate) fn rubygems_specs(text: &str) -> io::Result<Vec<LockedPackage>> {
    let mut found = Vec::new();
    let mut in_gem = false;
    let mut remote: Option<bool> = None;
    let mut in_specs = false;
    for (number, line) in text.lines().enumerate() {
        let unreadable = |what: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Gemfile.lock line {} {what}", number + 1),
            )
        };
        if !line.starts_with(' ') {
            in_gem = line == "GEM";
            remote = None;
            in_specs = false;
            continue;
        }
        if !in_gem {
            continue;
        }
        if let Some(url) = line.strip_prefix("  remote: ") {
            if remote.is_some() {
                return Err(unreadable("is a second remote in one GEM section"));
            }
            let url = url.trim().trim_end_matches('/');
            remote = Some(matches!(
                url,
                "https://rubygems.org" | "https://index.rubygems.org"
            ));
            continue;
        }
        if line == "  specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            return Err(unreadable("is not a GEM section line ward can read"));
        }
        let Some(spec) = line.strip_prefix("    ") else {
            return Err(unreadable("is not a GEM section line ward can read"));
        };
        // A dependency of the spec above, or a spec of another remote.
        if spec.starts_with(' ') || remote != Some(true) {
            continue;
        }
        let parsed = spec
            .split_once(" (")
            .and_then(|(name, rest)| Some((name, rest.strip_suffix(')')?)))
            .filter(|(name, version)| {
                !name.is_empty()
                    && !version.is_empty()
                    && !name.contains(char::is_whitespace)
                    && !version.contains(char::is_whitespace)
            });
        let Some((name, version)) = parsed else {
            return Err(unreadable("is not a `name (version)` spec"));
        };
        found.push(LockedPackage::new(name, version));
    }
    Ok(found)
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
            rubygems_specs(lock).unwrap(),
            [
                LockedPackage::new("nokogiri", "1.15.0-x86_64-linux"),
                LockedPackage::new("racc", "1.7.3"),
                LockedPackage::new("rake", "13.4.2"),
            ]
        );
    }

    #[test]
    fn a_gem_section_the_reader_cannot_take_apart_is_refused() {
        for (lock, why) in [
            (
                "GEM\n  remote: https://rubygems.org/\n  remote: https://gems.example.com/\n  \
                 specs:\n    rake (13.4.2)\n",
                "second remote",
            ),
            (
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake 13.4.2\n",
                "spec",
            ),
            (
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.4.2\n",
                "spec",
            ),
            (
                "GEM\n  remote: https://rubygems.org/\n  mystery: yes\n  specs:\n",
                "GEM section line",
            ),
            (
                "GEM\n  remote: https://rubygems.org/\n  specs:\n   rake (13.4.2)\n",
                "GEM section line",
            ),
        ] {
            let error = rubygems_specs(lock).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{lock}");
            assert!(error.to_string().contains(why), "{error}");
        }
    }
}
