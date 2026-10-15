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
    /// The source ward fetches: the lock's URL as git takes it, at the
    /// locked commit.
    pub fn source(&self) -> GitSource {
        GitSource {
            url: git_url(&self.url),
            commit: self.revision.clone(),
            subdirectory: None,
        }
    }
}

/// A lock's git `remote:` as ward hands it to git, and as ward names it in
/// identities, the SBOM and messages: an absolute path is a local
/// repository (`file://`), and any other spelling is normalized without
/// its credentials (`gitsrc::normalize_url`). A relative path is refused
/// before this is used (`check_git_gem`).
pub fn git_url(raw: &str) -> String {
    let raw = raw.trim();
    if raw.starts_with('/') {
        return format!("file://{raw}");
    }
    gitsrc::normalize_url(raw)
}

/// Whether a scheme-less remote is the scp-like `host:path` git reads as
/// ssh, rather than a path on this machine.
fn is_scp_like(raw: &str) -> bool {
    match raw.split_once(':') {
        Some((host, _)) => !host.is_empty() && !host.contains('/'),
        None => false,
    }
}

/// One source of a checkout: the lock's `GIT` section, which a repository
/// at one commit can have several of (one per `glob:`, or one per mirror
/// URL), and the gems it names.
pub struct CheckoutSource<'p> {
    /// The `remote:` as the lock spells it, which the helper hands Bundler
    /// so it names the same checkout directory.
    pub url: &'p str,
    pub glob: &'p str,
    pub gems: Vec<&'p RubyGitGem>,
}

/// One directory under `<GEM_HOME>/bundler/gems` and every lock source
/// Bundler reads from it. Bundler names the directory after the
/// repository and the commit only, so all of them share one copy.
pub struct Checkout<'p> {
    /// The directory's name.
    pub name: &'p str,
    /// The gem whose source ward fetches the tree from: every source of a
    /// checkout is at the same commit, so any one names the same tree.
    pub first: &'p RubyGitGem,
    pub sources: Vec<CheckoutSource<'p>>,
}

impl Checkout<'_> {
    /// Every gem installed from this checkout, in plan order per source.
    pub fn gems(&self) -> impl Iterator<Item = &RubyGitGem> + '_ {
        self.sources.iter().flat_map(|s| s.gems.iter().copied())
    }

    /// What the gems object's identity takes from this checkout: the
    /// commit, then each source's URL (as `git_url` names it), glob and
    /// gems, as a JSON array.
    pub fn identity_input(&self) -> String {
        let sources: Vec<serde_json::Value> = self
            .sources
            .iter()
            .map(|s| {
                let gems: Vec<String> = s
                    .gems
                    .iter()
                    .map(|g| format!("{}:{}", g.name, g.version))
                    .collect();
                serde_json::json!([git_url(s.url), s.glob, gems])
            })
            .collect();
        serde_json::json!([self.first.revision, sources]).to_string()
    }
}

/// The plan's git gems grouped by checkout directory, then by source
/// (URL and glob), in plan order. `check_checkouts` has refused two
/// commits under one directory name.
pub fn checkouts(gems: &[RubyGitGem]) -> Vec<Checkout<'_>> {
    let mut out: Vec<Checkout<'_>> = Vec::new();
    for gem in gems {
        let checkout = match out.iter_mut().position(|c| c.name == gem.checkout) {
            Some(index) => &mut out[index],
            None => {
                out.push(Checkout {
                    name: &gem.checkout,
                    first: gem,
                    sources: Vec::new(),
                });
                out.last_mut().expect("just pushed")
            }
        };
        match checkout
            .sources
            .iter_mut()
            .find(|s| s.url == gem.url && s.glob == gem.glob)
        {
            Some(source) => source.gems.push(gem),
            None => checkout.sources.push(CheckoutSource {
                url: &gem.url,
                glob: &gem.glob,
                gems: vec![gem],
            }),
        }
    }
    out
}

/// Refuse two git gems Bundler would read from one directory at different
/// commits: one copy cannot be both.
pub fn check_checkouts(gems: &[RubyGitGem]) -> io::Result<()> {
    for checkout in checkouts(gems) {
        if let Some(other) = checkout
            .gems()
            .find(|g| g.revision != checkout.first.revision)
        {
            return Err(err(format!(
                "{} and {}: Gemfile.lock takes them from {} and {}, which Bundler reads \
                 from one directory, {}; ward cannot place both",
                checkout.first.name,
                other.name,
                git_url(&checkout.first.url),
                git_url(&other.url),
                checkout.name
            )));
        }
    }
    Ok(())
}

/// A path the lock names, made relative to the project root, or the
/// reason it is refused: it is absolute, it starts at a home directory
/// (`~`, which Ruby expands), or it climbs out with `..`.
fn lexical_inside(path: &str) -> Result<PathBuf, &'static str> {
    if path.is_empty() {
        return Err("is empty");
    }
    if path.starts_with('~') {
        return Err("starts at a home directory");
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
/// it: a relative path for a remote, a URL git must not be handed, a
/// revision that is not a full commit, a checkout name that is not one
/// path component ending in the commit's first 12 hex digits, or a glob
/// that could leave the checkout.
pub fn check_git_gem(gem: &RubyGitGem) -> io::Result<()> {
    let refuse = |why: String| {
        err(format!(
            "{} {} from {}: {why}",
            gem.name,
            gem.version,
            git_url(&gem.url)
        ))
    };
    if !gitsrc::is_full_commit(&gem.revision) {
        return Err(refuse(format!(
            "the lock's revision {:?} is not a full commit",
            gem.revision
        )));
    }
    let raw = gem.url.trim();
    if !raw.contains("://") && !raw.starts_with('/') && !is_scp_like(raw) {
        return Err(err(format!(
            "{} {}: Gemfile.lock takes it from the git remote {raw:?}, a relative path, which \
             means a different repository wherever the project is checked out. Use an \
             absolute path or a URL",
            gem.name, gem.version
        )));
    }
    if raw.starts_with("file://") && !raw.starts_with("file:///") {
        return Err(refuse(format!(
            "the remote {raw:?} names a host or a relative path; a file:// remote must \
             be an absolute path"
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
    // Bundler globs relative to the checkout, and nothing it reads may come
    // from outside it. Ruby's `Dir.glob` expands braces before it matches,
    // so `{.}{.}/x` reads as `../x` and `{/abs,y}` as an absolute path: a
    // glob with braces, a character class or an escape is refused rather
    // than expanded here, and what is left must not climb, start at the
    // root, or start at a home directory.
    if gem.glob.starts_with('/')
        || gem.glob.starts_with('~')
        || gem.glob.contains("..")
        || gem.glob.contains(['{', '}', '[', ']', '\\'])
    {
        return Err(refuse(format!(
            "the lock's glob {:?} could leave the checkout",
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
        // Ruby expands a leading `~` to a home directory.
        assert_eq!(lexical_inside("~/gem"), Err("starts at a home directory"));
        assert_eq!(
            lexical_inside("~other/gem"),
            Err("starts at a home directory")
        );
        assert_eq!(lexical_inside("~"), Err("starts at a home directory"));
        assert_eq!(lexical_inside("a/~b").unwrap(), PathBuf::from("a/~b"));
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
    }

    #[test]
    fn a_glob_never_reaches_outside_the_checkout() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let mut gem = git_gem("rack", "https://github.com/rack/rack.git", commit);
        for bad in [
            "../*.gemspec",
            "/etc/*.gemspec",
            "{..,x}/*.gemspec",
            "a/{x,..}/*.gemspec",
            "a..b/*.gemspec",
            "~/*.gemspec",
            // Ruby expands braces before matching: these read as
            // `../*.gemspec` and `/x/*.gemspec`.
            "{.}{.}/*.gemspec",
            "{/x/*.gemspec,y}",
            "{,*,*/*}.gemspec",
            "[.][.]/*.gemspec",
            "\\../*.gemspec",
            "gems/\\x/*.gemspec",
        ] {
            gem.glob = bad.into();
            let error = check_git_gem(&gem).unwrap_err().to_string();
            assert!(error.contains("could leave the checkout"), "{bad}: {error}");
        }
        for good in [
            "gems/*/*.gemspec",
            "*/*.gemspec",
            "a/~b/*.gemspec",
            "g?ms/*.gemspec",
        ] {
            gem.glob = good.into();
            check_git_gem(&gem).unwrap();
        }
    }

    #[test]
    fn an_absolute_remote_is_a_local_repository_and_a_relative_one_is_refused() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let local = git_gem("rack", "/srv/git/rack", commit);
        check_git_gem(&local).unwrap();
        assert_eq!(local.source().url, "file:///srv/git/rack");
        // A local repository records `host-git-transport`, as
        // LIMITATIONS.md says.
        let exception = gitsrc::transport_exception(&local.source()).expect("recorded");
        assert_eq!(exception.kind, "host-git-transport");
        for relative in ["../rack", "rack", "./rack", "vendor/rack.git"] {
            let error = check_git_gem(&git_gem("rack", relative, commit))
                .unwrap_err()
                .to_string();
            assert!(error.contains("a relative path"), "{relative}: {error}");
        }
        for odd in ["file://../rack", "file://host/rack"] {
            let error = check_git_gem(&git_gem("rack", odd, commit))
                .unwrap_err()
                .to_string();
            assert!(error.contains("must be an absolute path"), "{odd}: {error}");
        }
        check_git_gem(&git_gem("rack", "file:///srv/git/rack", commit)).unwrap();
    }

    #[test]
    fn a_remote_is_named_without_its_credentials() {
        assert_eq!(
            git_url("https://user:token@github.com/rack/rack.git"),
            "https://github.com/rack/rack.git"
        );
        assert_eq!(
            git_url("git@github.com:rack/rack.git"),
            "ssh://git@github.com/rack/rack.git"
        );
        assert_eq!(git_url("/srv/rack"), "file:///srv/rack");
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
        assert_eq!(grouped[0].sources.len(), 1);
        assert_eq!(grouped[0].gems().count(), 2);
        assert_eq!(grouped[1].first.name, "three");
    }

    /// Two `GIT` sections of one repository at one commit, with different
    /// globs or from a mirror, name one directory: they are one checkout
    /// with several sources, and the identity input names them all.
    #[test]
    fn sections_bundler_reads_from_one_directory_are_one_checkout() {
        let a = "a".repeat(40);
        let mut globbed = git_gem("two", "https://x/r.git", &a);
        globbed.glob = "sub/*.gemspec".into();
        let gems = vec![
            git_gem("one", "https://x/r.git", &a),
            globbed,
            git_gem("three", "https://mirror.example/r.git", &a),
        ];
        check_checkouts(&gems).unwrap();
        let grouped = checkouts(&gems);
        assert_eq!(grouped.len(), 1, "one directory, one copy");
        let checkout = &grouped[0];
        assert_eq!(checkout.name, format!("repo-{}", &a[..12]));
        assert_eq!(checkout.sources.len(), 3);
        let names: Vec<&str> = checkout.gems().map(|g| g.name.as_str()).collect();
        assert_eq!(names, ["one", "two", "three"]);
        let input: serde_json::Value = serde_json::from_str(&checkout.identity_input()).unwrap();
        assert_eq!(
            input,
            serde_json::json!([
                a,
                [
                    ["https://x/r.git", "", ["one:1.0.0"]],
                    ["https://x/r.git", "sub/*.gemspec", ["two:1.0.0"]],
                    ["https://mirror.example/r.git", "", ["three:1.0.0"]],
                ]
            ])
        );

        // Two commits whose names share the first 12 digits would need one
        // directory to hold two trees.
        let mut clash = git_gem(
            "four",
            "https://x/r.git",
            &format!("{}{}", &a[..12], "b".repeat(28)),
        );
        clash.checkout = format!("repo-{}", &a[..12]);
        let error = check_checkouts(&[gems[0].clone(), clash])
            .unwrap_err()
            .to_string();
        assert!(error.contains("one directory"), "{error}");
    }
}
