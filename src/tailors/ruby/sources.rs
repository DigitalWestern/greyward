//! Gems a Gemfile.lock takes from somewhere other than rubygems.org.
//!
//! A `PATH` section names gems that live in the project itself: a Gemfile
//! with `gemspec` puts the repository's own gem there, and `gem "x", path:
//! "x"` puts a gem from a subdirectory there. Bundler loads them from the
//! checkout at run time, so there is nothing to download or install: ward
//! checks that each path stays inside the project and records the gem in
//! the closure. A path that leaves the project is refused, as every door
//! refuses one: the gems object and the closure describe the project, and a
//! gem from a sibling directory is in neither.
//!
//! A `GIT` section names gems from a repository at a locked commit. ward
//! fetches that commit with its own git code (`kernel::gitsrc`), records
//! `git-dependency` (and `host-git-transport` for a transport the proxy does
//! not carry) before it fetches, and places the tree where Bundler looks
//! for it at run time, `<GEM_HOME>/bundler/gems/<checkout>`. Bundler's own
//! installer then builds the gems from that tree in the install sandbox,
//! offline, as `bundle install` does once a checkout is in place.

use super::err;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::gitsrc::{self, GitSource};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Component, Path, PathBuf};

/// A gem the lock takes from a `PATH` source inside the project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RubyPathGem {
    pub name: String,
    pub version: String,
    /// The `remote:` the lock names, relative to the project root.
    pub path: String,
}

/// A gem the lock takes from a `GIT` source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RubyGitGem {
    pub name: String,
    pub version: String,
    /// The `remote:` the lock names, as Bundler spells it: the checkout
    /// directory's name is derived from this spelling.
    pub url: String,
    /// The locked commit.
    pub revision: String,
    /// The directory under `<GEM_HOME>/bundler/gems` Bundler reads the
    /// checkout from: `<repository name>-<first 12 hex of the commit>`.
    pub checkout: String,
    /// The lock's `glob:`, empty for Bundler's default.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub glob: String,
}

impl RubyGitGem {
    /// The source ward fetches: the lock's URL normalized for git, at the
    /// locked commit.
    pub fn source(&self) -> GitSource {
        GitSource {
            url: gitsrc::normalize_url(&self.url),
            commit: self.revision.clone(),
            subdirectory: None,
        }
    }
}

/// One checkout and the gems the lock takes from it. Several gems can share
/// one repository at one commit (a monorepo's gems).
pub struct Checkout<'p> {
    pub first: &'p RubyGitGem,
    pub gems: Vec<&'p RubyGitGem>,
}

/// The plan's git gems grouped by checkout, in plan order.
pub fn checkouts(gems: &[RubyGitGem]) -> Vec<Checkout<'_>> {
    let mut out: Vec<Checkout<'_>> = Vec::new();
    for gem in gems {
        match out.iter_mut().find(|c| {
            c.first.url == gem.url && c.first.revision == gem.revision && c.first.glob == gem.glob
        }) {
            Some(checkout) => checkout.gems.push(gem),
            None => out.push(Checkout {
                first: gem,
                gems: vec![gem],
            }),
        }
    }
    out
}

/// A path the lock names, made relative to the project root, or the
/// reason it is refused: it is absolute, or it climbs out with `..`.
fn lexical_inside(path: &str) -> Result<PathBuf, &'static str> {
    if path.is_empty() {
        return Err("is empty");
    }
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                depth += 1;
                out.push(part);
            }
            Component::ParentDir => {
                depth = depth.checked_sub(1).ok_or("is outside the project")?;
                out.pop();
            }
            Component::RootDir | Component::Prefix(_) => return Err("is absolute"),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Ok(out)
}

/// Refuse a path gem whose directory is not inside the project: absolute,
/// climbing out with `..`, absent, or reached through a symlink that
/// leads out of it.
pub fn check_path_gem(project: &ProjectRoot, gem: &RubyPathGem) -> io::Result<()> {
    let refuse = |why: &str| {
        err(format!(
            "{} {}: Gemfile.lock takes it from the path {:?}, which {why}; a path gem must \
             live inside the project (ward reads the project alone). Move it inside the \
             project, or depend on it from rubygems.org or a git repository",
            gem.name, gem.version, gem.path
        ))
    };
    let relative = lexical_inside(&gem.path).map_err(refuse)?;
    if !project.is_input_dir(&relative) {
        return Err(refuse("is not a directory in the project"));
    }
    let root = project.path().canonicalize()?;
    let resolved = project.path().join(&relative).canonicalize()?;
    if !resolved.starts_with(&root) {
        return Err(refuse("is a symlink that leads outside the project"));
    }
    Ok(())
}

/// Refuse a git gem ward cannot fetch safely or place where Bundler reads
/// it: a URL git must not be handed, a revision that is not a full commit,
/// a checkout name that is not one path component ending in the commit's
/// first 12 hex digits, or a glob that leaves the checkout.
pub fn check_git_gem(gem: &RubyGitGem) -> io::Result<()> {
    let refuse = |why: String| {
        err(format!(
            "{} {} from {}: {why}",
            gem.name, gem.version, gem.url
        ))
    };
    if !gitsrc::is_full_commit(&gem.revision) {
        return Err(refuse(format!(
            "the lock's revision {:?} is not a full commit",
            gem.revision
        )));
    }
    gitsrc::validate_source(&gem.source()).map_err(|e| refuse(e.to_string()))?;
    if !gitsrc::is_safe_component(&gem.checkout)
        || gem.checkout.starts_with('.')
        || !gem.checkout.ends_with(&format!("-{}", &gem.revision[..12]))
    {
        return Err(refuse(format!(
            "Bundler would read it from {:?}, which ward cannot place",
            gem.checkout
        )));
    }
    if gem.glob.starts_with('/') || gem.glob.split('/').any(|part| part == "..") {
        return Err(refuse(format!(
            "the lock's glob {:?} leaves the checkout",
            gem.glob
        )));
    }
    Ok(())
}

/// Record `git-dependency` (and `host-git-transport` where it applies) for
/// every git gem of a plan, before anything is fetched: a policy that denies
/// the kind stops the sync here.
pub fn record_git_dependencies(gems: &[RubyGitGem]) -> io::Result<()> {
    for gem in gems {
        gitsrc::record_git_dependency(&gem.name, &gem.source())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_gem(name: &str, url: &str, revision: &str) -> RubyGitGem {
        RubyGitGem {
            name: name.into(),
            version: "1.0.0".into(),
            url: url.into(),
            revision: revision.into(),
            checkout: format!("repo-{}", &revision[..12.min(revision.len())]),
            glob: String::new(),
        }
    }

    #[test]
    fn a_lock_path_is_taken_inside_the_project_only() {
        assert_eq!(lexical_inside(".").unwrap(), PathBuf::from("."));
        assert_eq!(
            lexical_inside("rack-protection").unwrap(),
            PathBuf::from("rack-protection")
        );
        assert_eq!(
            lexical_inside("tools/./releaser").unwrap(),
            PathBuf::from("tools/releaser")
        );
        assert_eq!(lexical_inside("a/../b").unwrap(), PathBuf::from("b"));
        assert_eq!(lexical_inside("a/..").unwrap(), PathBuf::from("."));
        assert!(lexical_inside("..").is_err());
        assert!(lexical_inside("../sibling").is_err());
        assert!(lexical_inside("a/../../sibling").is_err());
        assert!(lexical_inside("/abs/gem").is_err());
        assert!(lexical_inside("").is_err());
    }

    #[test]
    fn a_git_gem_must_name_a_full_commit_and_a_placeable_checkout() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let ok = git_gem("rack", "https://github.com/rack/rack.git", commit);
        check_git_gem(&ok).unwrap();
        // ssh spelling Bundler writes for `git@`: normalized to ssh://.
        check_git_gem(&git_gem("rack", "git@github.com:rack/rack.git", commit)).unwrap();
        assert!(check_git_gem(&git_gem("rack", "https://x/r.git", "main")).is_err());
        assert!(check_git_gem(&git_gem("rack", "-oProxyCommand=x:r", commit)).is_err());
        assert!(check_git_gem(&git_gem("rack", "ftp://x/r.git", commit)).is_err());
        let mut wrong = ok.clone();
        wrong.checkout = "rack-000000000000".into();
        assert!(check_git_gem(&wrong).is_err());
        let mut climbing = ok.clone();
        climbing.checkout = format!("../x-{}", &commit[..12]);
        assert!(check_git_gem(&climbing).is_err());
        let mut glob = ok.clone();
        glob.glob = "../*.gemspec".into();
        assert!(check_git_gem(&glob).is_err());
        glob.glob = "/etc/*.gemspec".into();
        assert!(check_git_gem(&glob).is_err());
        glob.glob = "gems/*/*.gemspec".into();
        check_git_gem(&glob).unwrap();
    }

    #[test]
    fn gems_from_one_repository_at_one_commit_share_a_checkout() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let gems = vec![
            git_gem("one", "https://x/r.git", &a),
            git_gem("two", "https://x/r.git", &a),
            git_gem("three", "https://x/r.git", &b),
        ];
        let grouped = checkouts(&gems);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].gems.len(), 2);
        assert_eq!(grouped[1].first.name, "three");
    }
}
