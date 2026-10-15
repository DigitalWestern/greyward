//! What a failed gem build left in the staged GEM_HOME, so the retry
//! against the whole host starts from the state a clean install would.
//!
//! Every gem of a plan installs into one staged GEM_HOME. A hermetic
//! attempt that fails may still have written there, and the retry runs in
//! the same tree. RubyGems' own leftovers from a failed extension build are
//! known (checked with RubyGems 3.6 and a gem whose `extconf.rb` aborts):
//! the gem's directory under `gems/`, its extension directory under
//! `extensions/<platform>/<abi>/` with `gem_make.out` and `mkmf.log`, the
//! platform and ABI directories above that when this was the first
//! extension, and, in an empty GEM_HOME, the standard subdirectories
//! RubyGems creates before it installs anything. Those are removed. Any
//! other change is the build's own doing, and the retry is refused rather
//! than run on top of it.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The subdirectories RubyGems creates in an empty GEM_HOME before its
/// first install (`Gem.ensure_gem_subdirectories`).
const STANDARD_SUBDIRECTORIES: &[&str] = &[
    "build_info",
    "cache",
    "doc",
    "extensions",
    "gems",
    "plugins",
    "specifications",
];

/// One path's state. A directory is compared by kind, mode and inode only:
/// its size and times change whenever an entry under it is added or
/// removed, and every such entry has its own line in the manifest. Anything
/// else also carries its status-change time, which no unprivileged process
/// can set: a rewrite in place that restores the modification time still
/// moves it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    kind: char,
    mode: u32,
    inode: u64,
    size: u64,
    modified_ns: i128,
    changed_ns: i128,
    target: Option<PathBuf>,
}

/// Every path under a GEM_HOME, relative to it, with its state. Symlinks
/// are recorded, never followed.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Manifest(BTreeMap<PathBuf, Entry>);

pub(super) fn manifest(root: &Path) -> io::Result<Manifest> {
    let mut entries = BTreeMap::new();
    walk(root, Path::new(""), &mut entries)?;
    Ok(Manifest(entries))
}

fn walk(root: &Path, relative: &Path, entries: &mut BTreeMap<PathBuf, Entry>) -> io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let path = relative.join(entry.file_name());
        let metadata = fs::symlink_metadata(root.join(&path))?;
        let file_type = metadata.file_type();
        let (kind, target) = if file_type.is_symlink() {
            ('l', Some(fs::read_link(root.join(&path))?))
        } else if file_type.is_dir() {
            ('d', None)
        } else if file_type.is_file() {
            ('f', None)
        } else {
            ('o', None)
        };
        let directory = kind == 'd';
        entries.insert(
            path.clone(),
            Entry {
                kind,
                mode: metadata.mode(),
                inode: metadata.ino(),
                size: if directory { 0 } else { metadata.size() },
                modified_ns: if directory {
                    0
                } else {
                    i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())
                },
                changed_ns: if directory {
                    0
                } else {
                    i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec())
                },
                target,
            },
        );
        if directory {
            walk(root, &path, entries)?;
        }
    }
    Ok(())
}

/// The first path, in path order, that differs between two manifests:
/// added, removed, or changed.
fn first_change(before: &Manifest, after: &Manifest) -> Option<PathBuf> {
    before
        .0
        .keys()
        .chain(after.0.keys())
        .filter(|path| before.0.get(*path) != after.0.get(*path))
        .min()
        .cloned()
}

/// Refuse when a path component of `relative` under `root` that exists is
/// a symlink. The staged GEM_HOME is written by sandboxed builds, and ward
/// writes and deletes there from the host: a build that turned a directory
/// into a symlink would otherwise lead those host operations outside it.
/// A missing component ends the check: nothing below it exists.
pub(super) fn refuse_symlinks(root: &Path, relative: &Path) -> io::Result<()> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::other(format!(
                    "{} is a symlink in the staged gem home; ward does not follow it",
                    path.display()
                )))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Refuse when the git checkout `checkout` in `gem_home` holds git data
/// (`.git`, as a directory, file or symlink), or is reached through a
/// symlink. The helper indexes a checkout in a throwaway repository and
/// removes it; the gems object must hold none.
pub(super) fn refuse_git_data(gem_home: &Path, checkout: &str) -> io::Result<()> {
    let git = Path::new(super::GIT_CHECKOUTS).join(checkout).join(".git");
    let parent = git.parent().expect("has a parent");
    refuse_symlinks(gem_home, parent)?;
    if fs::symlink_metadata(gem_home.join(&git)).is_ok() {
        return Err(io::Error::other(format!(
            "{checkout}: git data was left in the checkout after its install"
        )));
    }
    Ok(())
}

/// Whether `relative` under `gem_home` is a directory reached through no
/// symlink (`refuse_symlinks`).
fn real_dir(gem_home: &Path, relative: &Path) -> io::Result<bool> {
    refuse_symlinks(gem_home, relative)?;
    Ok(fs::symlink_metadata(gem_home.join(relative)).is_ok_and(|m| m.is_dir()))
}

/// The directories one level under `relative` in `gem_home`, as paths
/// relative to `gem_home`; none when it is not a real directory.
fn subdirectories(gem_home: &Path, relative: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !real_dir(gem_home, relative)? {
        return Ok(out);
    }
    for entry in fs::read_dir(gem_home.join(relative))? {
        let child = relative.join(entry?.file_name());
        if real_dir(gem_home, &child)? {
            out.push(child);
        }
    }
    Ok(out)
}

/// Remove what a failed install of `full_name` leaves in `gem_home` (see
/// the module comment), then refuse if anything else differs from
/// `before`, the manifest taken before the attempt.
pub(super) fn discard_failed_attempt(
    gem_home: &Path,
    full_name: &str,
    before: &Manifest,
) -> io::Result<()> {
    let known = |relative: &Path| before.0.contains_key(relative);
    remove_if_new(gem_home, &Path::new("gems").join(full_name), &known)?;
    let mut new_parents = Vec::new();
    for platform in subdirectories(gem_home, Path::new("extensions"))? {
        for abi in subdirectories(gem_home, &platform)? {
            remove_if_new(gem_home, &abi.join(full_name), &known)?;
            new_parents.push(abi);
        }
        new_parents.push(platform);
    }
    new_parents.extend(STANDARD_SUBDIRECTORIES.iter().map(PathBuf::from));
    remove_new_empty(gem_home, new_parents, &known)?;
    compare(gem_home, before, "the gem's own directories")
}

/// Remove what a failed install of the git checkout `checkout` leaves in
/// `gem_home`: the checkout's copy under `bundler/gems/`, its extension
/// directories under `bundler/gems/extensions/<platform>/<abi>/` (Bundler
/// names each `<checkout>` or `<checkout>-<gem directory>`), the
/// executables' wrappers it wrote in `bin/` for the checkout's gems that
/// installed before one failed, and the directories above them the attempt
/// created. Then refuse if anything else differs from `before`, as
/// [`discard_failed_attempt`] does.
pub(super) fn discard_failed_git_attempt(
    gem_home: &Path,
    checkout: &str,
    before: &Manifest,
) -> io::Result<()> {
    let known = |relative: &Path| before.0.contains_key(relative);
    let checkouts = Path::new(super::GIT_CHECKOUTS);
    remove_if_new(gem_home, &checkouts.join(checkout), &known)?;
    let extensions = checkouts.join("extensions");
    let mut new_parents = Vec::new();
    for platform in subdirectories(gem_home, &extensions)? {
        for abi in subdirectories(gem_home, &platform)? {
            for entry in fs::read_dir(gem_home.join(&abi))? {
                let entry = entry?.file_name();
                let name = entry.to_string_lossy();
                if name == checkout || name.starts_with(&format!("{checkout}-")) {
                    remove_if_new(gem_home, &abi.join(&entry), &known)?;
                }
            }
            new_parents.push(abi);
        }
        new_parents.push(platform);
    }
    // Every wrapper new since the attempt began is this attempt's: one
    // install runs at a time.
    let bin = Path::new("bin");
    if real_dir(gem_home, bin)? {
        for entry in fs::read_dir(gem_home.join(bin))? {
            remove_if_new(gem_home, &bin.join(entry?.file_name()), &known)?;
        }
    }
    new_parents.push(extensions);
    new_parents.push(checkouts.to_path_buf());
    new_parents.push(PathBuf::from("bundler"));
    new_parents.push(bin.to_path_buf());
    remove_new_empty(gem_home, new_parents, &known)?;
    compare(gem_home, before, "the checkout's own directories")
}

/// Remove each of `directories` the attempt created, if empty: `remove_dir`
/// fails on anything else, which the comparison then reports.
fn remove_new_empty(
    gem_home: &Path,
    directories: Vec<PathBuf>,
    known: &dyn Fn(&Path) -> bool,
) -> io::Result<()> {
    for directory in directories {
        if known(&directory) {
            continue;
        }
        refuse_symlinks(gem_home, &directory)?;
        let _ = fs::remove_dir(gem_home.join(directory));
    }
    Ok(())
}

/// Refuse the retry when `gem_home` differs from `before` anywhere.
fn compare(gem_home: &Path, before: &Manifest, own: &str) -> io::Result<()> {
    let after = manifest(gem_home)?;
    match first_change(before, &after) {
        None => Ok(()),
        Some(path) => Err(io::Error::other(format!(
            "the failed build changed {} in the gem home, outside {own}; it was not \
             retried against the whole host",
            gem_home.join(path).display()
        ))),
    }
}

/// Remove `relative` under `gem_home` if the attempt created it. A path
/// that was there before is the comparison's to report, not ours to
/// delete. A new symlink is removed as a link, never followed, and no
/// directory above it may be one.
fn remove_if_new(
    gem_home: &Path,
    relative: &Path,
    known: &dyn Fn(&Path) -> bool,
) -> io::Result<()> {
    if let Some(parent) = relative.parent() {
        refuse_symlinks(gem_home, parent)?;
    }
    let path = gem_home.join(relative);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Ok(());
    };
    if known(relative) {
        return Ok(());
    }
    if metadata.is_dir() {
        crate::kernel::store::remove_tree(&path)
    } else {
        fs::remove_file(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// A GEM_HOME with one gem installed and the directories RubyGems
    /// made for it.
    fn gem_home(label: &str) -> TempDir {
        let temp = TempDir::named(&format!("ruby-gem-home-{label}"));
        for directory in STANDARD_SUBDIRECTORIES {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        fs::create_dir_all(temp.0.join("bin")).unwrap();
        fs::create_dir_all(temp.0.join("gems/pure-1.0/lib")).unwrap();
        fs::write(
            temp.0.join("gems/pure-1.0/lib/pure.rb"),
            "module Pure; end\n",
        )
        .unwrap();
        fs::write(temp.0.join("specifications/pure-1.0.gemspec"), "spec\n").unwrap();
        temp
    }

    /// What RubyGems leaves when `failext-1.0`'s extension build aborts.
    fn fail_like_rubygems(root: &Path) {
        let extension = root.join("extensions/x86_64-linux/3.4.0-static/failext-1.0");
        fs::create_dir_all(&extension).unwrap();
        fs::write(extension.join("gem_make.out"), "abort\n").unwrap();
        fs::write(extension.join("mkmf.log"), "have_header: no\n").unwrap();
        fs::create_dir_all(root.join("gems/failext-1.0/ext/failext")).unwrap();
        fs::write(
            root.join("gems/failext-1.0/ext/failext/extconf.rb"),
            "abort\n",
        )
        .unwrap();
    }

    #[test]
    fn manifests_see_additions_removals_and_rewrites() {
        let home = gem_home("diff");
        let before = manifest(&home.0).unwrap();
        assert_eq!(first_change(&before, &manifest(&home.0).unwrap()), None);

        fs::write(home.0.join("bin/marker"), "x").unwrap();
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("bin/marker"))
        );
        fs::remove_file(home.0.join("bin/marker")).unwrap();

        // Same size, new bytes through a new inode: still a change. The
        // replacement is written beside the file and renamed over it, so
        // it really is a new inode: remove-then-create can hand the new
        // file the old inode number, and within one timestamp tick the
        // manifest then has nothing to tell them apart by.
        let file = home.0.join("gems/pure-1.0/lib/pure.rb");
        let replacement = home.0.join("gems/pure-1.0/lib/pure.rb.new");
        fs::write(&replacement, "module Evil; end\n").unwrap();
        fs::rename(&replacement, &file).unwrap();
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("gems/pure-1.0/lib/pure.rb"))
        );

        // Same inode, same size, modification time put back: the change
        // time still moves.
        let home = gem_home("diff-in-place");
        let file = home.0.join("gems/pure-1.0/lib/pure.rb");
        let modified = fs::metadata(&file).unwrap().modified().unwrap();
        let before = manifest(&home.0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        {
            use std::io::Write as _;
            let mut handle = fs::File::options().write(true).open(&file).unwrap();
            handle.write_all(b"module Evil; end").unwrap();
            handle.set_modified(modified).unwrap();
        }
        assert_eq!(fs::read(&file).unwrap(), b"module Evil; end\n");
        assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), modified);
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("gems/pure-1.0/lib/pure.rb"))
        );

        let home = gem_home("diff-link");
        let before = manifest(&home.0).unwrap();
        std::os::unix::fs::symlink("/etc", home.0.join("bin/etc")).unwrap();
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("bin/etc"))
        );
    }

    /// A failed extension build's own leftovers are removed and the retry
    /// may run; the tree is then what it was before the attempt.
    #[test]
    fn rubygems_own_leftovers_are_discarded() {
        let home = gem_home("leftovers");
        let before = manifest(&home.0).unwrap();
        fail_like_rubygems(&home.0);
        discard_failed_attempt(&home.0, "failext-1.0", &before).unwrap();
        assert_eq!(manifest(&home.0).unwrap(), before);

        // In an empty GEM_HOME the first install also creates RubyGems'
        // standard subdirectories.
        let empty = TempDir::named("ruby-gem-home-empty");
        fs::create_dir_all(empty.0.join("bin")).unwrap();
        let before = manifest(&empty.0).unwrap();
        for directory in STANDARD_SUBDIRECTORIES {
            fs::create_dir_all(empty.0.join(directory)).unwrap();
        }
        fail_like_rubygems(&empty.0);
        discard_failed_attempt(&empty.0, "failext-1.0", &before).unwrap();
        assert_eq!(manifest(&empty.0).unwrap(), before);
    }

    /// A build that wrote anywhere else, another gem included, is not
    /// retried, and the refusal names the first changed path.
    #[test]
    fn a_failed_build_that_wrote_elsewhere_refuses_the_retry() {
        let home = gem_home("elsewhere");
        let before = manifest(&home.0).unwrap();
        fail_like_rubygems(&home.0);
        fs::write(
            home.0.join("gems/pure-1.0/lib/pure.rb"),
            "module Evil; end\n",
        )
        .unwrap();
        fs::write(home.0.join("bin/marker"), "x").unwrap();
        let error = discard_failed_attempt(&home.0, "failext-1.0", &before).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("bin/marker"), "{message}");
        assert!(message.contains("not retried"), "{message}");
        // RubyGems' own leftovers went regardless.
        assert!(!home.0.join("gems/failext-1.0").exists());
    }

    /// What a failed build of a git checkout leaves: the copied checkout,
    /// with the build's own files in it, and Bundler's extension directory
    /// for it. Those go, and so do the directories above them the attempt
    /// made; a write anywhere else refuses the retry.
    #[test]
    fn a_failed_git_checkout_build_is_discarded() {
        let home = gem_home("git");
        let before = manifest(&home.0).unwrap();
        let checkout = "gitgem-repo-0123456789ab";
        let copy = home.0.join("bundler/gems").join(checkout);
        fs::create_dir_all(copy.join("ext/gitnative")).unwrap();
        fs::write(copy.join("ext/gitnative/Makefile"), "all:\n").unwrap();
        let extensions = home
            .0
            .join("bundler/gems/extensions/x86_64-linux/3.4.0-static");
        fs::create_dir_all(extensions.join(checkout)).unwrap();
        fs::create_dir_all(extensions.join(format!("{checkout}-sub"))).unwrap();
        fs::write(extensions.join(checkout).join("gem_make.out"), "abort\n").unwrap();
        discard_failed_git_attempt(&home.0, checkout, &before).unwrap();
        assert_eq!(manifest(&home.0).unwrap(), before);

        fs::create_dir_all(&copy).unwrap();
        fs::create_dir_all(extensions.join("other-checkout")).unwrap();
        let error = discard_failed_git_attempt(&home.0, checkout, &before).unwrap_err();
        assert!(error.to_string().contains("not retried"), "{error}");
        assert!(!copy.exists());
        assert!(extensions.join("other-checkout").exists());
    }

    /// A checkout with two gems whose second fails to build: the first
    /// gem's wrapper in `bin/` goes with the attempt, so the retry against
    /// the whole host runs. A wrapper that was there before and the attempt
    /// rewrote is still reported.
    #[test]
    fn a_failed_git_attempt_takes_its_wrappers_with_it() {
        let home = gem_home("git-bin");
        fs::write(home.0.join("bin/rake"), "#!/bin/sh\n").unwrap();
        let before = manifest(&home.0).unwrap();
        let checkout = "pair-repo-0123456789ab";
        fs::create_dir_all(home.0.join("bundler/gems").join(checkout)).unwrap();
        fs::write(home.0.join("bin/first-tool"), "#!/usr/bin/env ruby\n").unwrap();
        discard_failed_git_attempt(&home.0, checkout, &before).unwrap();
        assert_eq!(manifest(&home.0).unwrap(), before);

        fs::remove_file(home.0.join("bin/rake")).unwrap();
        fs::write(home.0.join("bin/rake"), "#!/bin/sh\nrewritten\n").unwrap();
        let error = discard_failed_git_attempt(&home.0, checkout, &before).unwrap_err();
        assert!(error.to_string().contains("bin/rake"), "{error}");
    }

    /// A sandboxed build that turned a directory of the gem home into a
    /// symlink cannot lead the host-side discard outside the gem home.
    #[test]
    fn a_discard_never_follows_a_symlink_out_of_the_gem_home() {
        let outside = TempDir::named("ruby-gem-home-outside");
        let checkout = "gitgem-repo-0123456789ab";
        fs::create_dir_all(outside.0.join(checkout)).unwrap();
        fs::create_dir_all(outside.0.join("x86_64-linux/3.4.0/failext-1.0")).unwrap();

        let home = gem_home("git-link");
        let before = manifest(&home.0).unwrap();
        fs::create_dir_all(home.0.join("bundler")).unwrap();
        std::os::unix::fs::symlink(&outside.0, home.0.join("bundler/gems")).unwrap();
        let error = discard_failed_git_attempt(&home.0, checkout, &before).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(outside.0.join(checkout).is_dir(), "followed the symlink");

        let home = gem_home("ext-link");
        fs::remove_dir(home.0.join("extensions")).unwrap();
        let before = manifest(&home.0).unwrap();
        std::os::unix::fs::symlink(&outside.0, home.0.join("extensions")).unwrap();
        let error = discard_failed_attempt(&home.0, "failext-1.0", &before).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(outside.0.join("x86_64-linux/3.4.0/failext-1.0").is_dir());
    }

    /// Git data in any checkout, in any form, stops the commit: a later
    /// checkout's install could have planted it in an earlier one.
    #[test]
    fn git_data_left_in_a_checkout_is_refused() {
        let home = gem_home("git-data");
        let checkout = "gitgem-repo-0123456789ab";
        let copy = home.0.join("bundler/gems").join(checkout);
        fs::create_dir_all(&copy).unwrap();
        refuse_git_data(&home.0, checkout).unwrap();
        fs::create_dir(copy.join(".git")).unwrap();
        assert!(refuse_git_data(&home.0, checkout).is_err());
        fs::remove_dir(copy.join(".git")).unwrap();
        fs::write(copy.join(".git"), "gitdir: /elsewhere\n").unwrap();
        assert!(refuse_git_data(&home.0, checkout).is_err());
        fs::remove_file(copy.join(".git")).unwrap();
        std::os::unix::fs::symlink("/", copy.join(".git")).unwrap();
        assert!(refuse_git_data(&home.0, checkout).is_err());
    }

    #[test]
    fn refuse_symlinks_checks_every_existing_component() {
        let home = gem_home("refuse");
        refuse_symlinks(&home.0, Path::new("bundler/gems/x")).unwrap();
        fs::create_dir_all(home.0.join("bundler/gems/x")).unwrap();
        refuse_symlinks(&home.0, Path::new("bundler/gems/x")).unwrap();
        std::os::unix::fs::symlink("/", home.0.join("bundler/gems/x/.git")).unwrap();
        assert!(refuse_symlinks(&home.0, Path::new("bundler/gems/x/.git")).is_err());
        assert!(refuse_symlinks(&home.0, Path::new("bundler/gems/x/.git/y")).is_err());
        refuse_symlinks(&home.0, Path::new("bundler/gems/x")).unwrap();
    }
}
