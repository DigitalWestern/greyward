//! Elixir git dependencies: each `{:git, url, rev, opts}` mix.lock entry
//! fetched at its locked commit by the kernel's git code
//! (`gitsrc::ensure_git_source`, full commit verified), then laid out the
//! way Mix finds a checked-out git dependency.
//!
//! Mix calls a git dependency checked out when `deps/<app>/.git/HEAD` is a
//! file, and up to date with its lock when `git config remote.origin.url`
//! there is the lock's URL and `git rev-parse --verify HEAD` the lock's
//! revision (`Mix.SCM.Git.lock_status`). The checkout object holds, per
//! app, the source tree and a `.git` of exactly that: HEAD naming the
//! commit, a config naming the origin, and empty object and ref stores. No
//! git history travels; the tree's identity is the commit the kernel
//! checked out and verified. Mix never fetches a dependency whose lock
//! status is up to date, so neither the confined resolver nor a build needs
//! the git host.

use super::err;
use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A `{:git, url, rev, opts}` mix.lock entry. `url` is the lock's string
/// exactly as mix wrote it: mix compares the checkout's
/// `remote.origin.url` to it byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitDep {
    pub app: String,
    pub url: String,
    /// The locked commit, 40 lowercase hex.
    pub rev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sparse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub submodules: bool,
}

impl GitDep {
    /// The source the kernel's git code fetches: the lock's URL normalized,
    /// at the locked commit, the whole repository.
    pub fn source(&self) -> crate::kernel::gitsrc::GitSource {
        crate::kernel::gitsrc::GitSource {
            url: crate::kernel::gitsrc::normalize_url(&self.url),
            commit: self.rev.clone(),
            subdirectory: None,
        }
    }
}

/// A string written verbatim into a checkout's `.git/config` or shown to
/// git: printable ASCII with no space, quote or backslash.
fn git_text_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// The checks the helper makes on a git entry, made again on the plan, and
/// the kernel's own on the source it fetches (scheme, option-looking host,
/// full commit).
pub(super) fn validate_git_dep(g: &GitDep) -> io::Result<()> {
    if !git_text_ok(&g.url, 2048) {
        return Err(err(format!("{}: unsafe git URL {:?}", g.app, g.url)));
    }
    if g.rev.len() != 40
        || !g
            .rev
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err(format!(
            "{}: git revision must be a full commit, got {:?}",
            g.app, g.rev
        )));
    }
    for (key, value) in [
        ("branch", &g.branch),
        ("ref", &g.r#ref),
        ("tag", &g.tag),
        ("sparse", &g.sparse),
        ("subdir", &g.subdir),
    ] {
        if let Some(value) = value {
            if !git_text_ok(value, 1024) {
                return Err(err(format!("{}: unsafe git {key} {value:?}", g.app)));
            }
        }
    }
    crate::kernel::gitsrc::validate_source(&g.source())
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", g.app)))
}

/// The checkout object's kind and schema.
pub(super) const KIND: &str = "mix-git-deps";
pub(super) const SCHEMA: &str = "mix-git-deps/1";

/// The identity input naming one git dependency, shared by the checkout
/// object and the deps object that copies it: the lock's URL and revision,
/// and the kernel source object it was checked out from.
pub(super) fn input(dep: &GitDep) -> (String, String) {
    (
        format!("git:{}", dep.app),
        format!(
            "{} {} {}",
            dep.url,
            dep.rev,
            crate::kernel::gitsrc::object_id(&dep.source())
        ),
    )
}

fn identity(deps: &[GitDep]) -> Identity {
    let mut inputs = BTreeMap::from([("schema".to_string(), SCHEMA.to_string())]);
    inputs.extend(deps.iter().map(input));
    Identity {
        kind: KIND.into(),
        name: "deps".into(),
        version: deps.len().to_string(),
        inputs,
    }
}

/// The `.git/config` Mix reads the origin from. `url` passed
/// `validate_git_dep`: printable ASCII with no quote or backslash, so it
/// needs no escaping inside the quoted value.
fn git_config(url: &str) -> String {
    format!(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\
         [remote \"origin\"]\n\turl = \"{url}\"\n"
    )
}

/// Write the `.git` Mix checks into `checkout`.
fn write_git_marker(checkout: &Path, dep: &GitDep) -> io::Result<()> {
    let git = checkout.join(".git");
    if fs::symlink_metadata(&git).is_ok() {
        return Err(err(format!(
            "{}: the checkout already holds a .git entry",
            dep.app
        )));
    }
    fs::create_dir_all(git.join("objects"))?;
    fs::create_dir_all(git.join("refs/heads"))?;
    fs::create_dir_all(git.join("refs/tags"))?;
    fs::write(git.join("HEAD"), format!("{}\n", dep.rev))?;
    fs::write(git.join("config"), git_config(&dep.url))?;
    Ok(())
}

/// Record `git-dependency` (and the transport, for ssh, git:// or a local
/// path) for every git dependency, then realize each source and the
/// checkout object holding them all. `None` when there are none. The
/// exceptions are recorded on every call, before anything is fetched, so a
/// policy denying either kind stops here and every closure built from the
/// checkouts carries them.
pub(super) fn realize_checkouts(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    deps: &[GitDep],
) -> io::Result<Option<PathBuf>> {
    if deps.is_empty() {
        return Ok(None);
    }
    for dep in deps {
        validate_git_dep(dep)?;
        crate::kernel::gitsrc::record_git_dependency(&dep.app, &dep.source())?;
    }
    let mut sources = Vec::with_capacity(deps.len());
    for dep in deps {
        let source = dep.source();
        let object =
            crate::kernel::gitsrc::ensure_git_source(store, activity, &source).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: git source {} at {}: {e}", dep.app, dep.url, dep.rev),
                )
            })?;
        sources.push(object);
    }
    let identity = identity(deps);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(Some(store.object_path(&id)));
    }
    let staged = store.stage_with_activity(activity)?;
    let built = (|| -> io::Result<()> {
        for (dep, object) in deps.iter().zip(&sources) {
            let checkout = staged.join(&dep.app);
            crate::kernel::store::clone_tree_with_activity(activity, object, &checkout, platform)?;
            write_git_marker(&checkout, dep)?;
        }
        Ok(())
    })();
    if let Err(e) = built {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(e);
    }
    let mut object_deps = crate::kernel::store::ObjectDeps::new();
    for object in &sources {
        object_deps.object_id(&crate::kernel::store::object_id_from_path(object)?)?;
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &object_deps)
        .map(|(path, _)| Some(path))
}

/// The links a confined mix run gets: `deps/<app>` in its deps path to the
/// app's checkout in the object, so Mix finds every git dependency checked
/// out at its locked commit and fetches none of them.
pub(super) fn deps_links(checkouts: Option<&Path>, deps: &[GitDep]) -> Vec<(PathBuf, PathBuf)> {
    let Some(object) = checkouts else {
        return Vec::new();
    };
    deps.iter()
        .map(|dep| (Path::new("deps").join(&dep.app), object.join(&dep.app)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(app: &str, url: &str) -> GitDep {
        GitDep {
            app: app.into(),
            url: url.into(),
            rev: "a".repeat(40),
            branch: None,
            r#ref: None,
            tag: Some("v1.0.0".into()),
            sparse: None,
            subdir: None,
            depth: None,
            submodules: false,
        }
    }

    #[test]
    fn the_marker_names_the_lock_url_and_commit_exactly() {
        let temp = crate::kernel::testutil::TempDir::named("mix-git-marker");
        let d = dep("enacl", "https://github.com/anoma/enacl/");
        write_git_marker(&temp.0, &d).unwrap();
        assert_eq!(
            fs::read_to_string(temp.0.join(".git/HEAD")).unwrap(),
            format!("{}\n", "a".repeat(40))
        );
        let config = fs::read_to_string(temp.0.join(".git/config")).unwrap();
        assert!(
            config.contains("url = \"https://github.com/anoma/enacl/\"\n"),
            "{config}"
        );
        assert!(write_git_marker(&temp.0, &d).is_err());
    }

    /// The git mix runs (`Mix.SCM.Git.get_rev_info`) reads the marker back
    /// as the lock: the origin URL and HEAD's commit, with no objects.
    #[test]
    fn git_reads_the_marker_back_as_the_lock() {
        let temp = crate::kernel::testutil::TempDir::named("mix-git-readback");
        let d = dep("heroicons", "https://github.com/tailwindlabs/heroicons.git");
        write_git_marker(&temp.0, &d).unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&temp.0)
                .env_remove("GIT_DIR")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {out:?}");
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        assert_eq!(
            git(&["--git-dir=.git", "config", "remote.origin.url"]),
            d.url
        );
        assert_eq!(
            git(&["--git-dir=.git", "rev-parse", "--verify", "--quiet", "HEAD"]),
            d.rev
        );
    }

    #[test]
    fn unsafe_git_entries_are_refused() {
        for url in [
            "https://h/x\"y",
            "https://h/x\\y",
            "https://h/x y",
            "-oProxyCommand=x",
            "http://h/x",
            "",
        ] {
            assert!(validate_git_dep(&dep("a", url)).is_err(), "{url}");
        }
        validate_git_dep(&dep("a", "https://github.com/anoma/enacl/")).unwrap();
        validate_git_dep(&dep("a", "git@github.com:a/b.git")).unwrap();
        for rev in ["abc".to_string(), "A".repeat(40), "g".repeat(40)] {
            let mut bad = dep("a", "https://h/x");
            bad.rev = rev;
            assert!(validate_git_dep(&bad).is_err());
        }
        let mut bad = dep("a", "https://h/x");
        bad.branch = Some("main\nevil".into());
        assert!(validate_git_dep(&bad).is_err());
    }

    #[test]
    fn the_identity_counts_and_names_every_dependency() {
        let deps = [
            dep("a", "https://example.com/a.git"),
            dep("b", "https://example.com/b"),
        ];
        let identity = identity(&deps);
        assert_eq!(identity.version, "2");
        assert!(identity.inputs["git:a"].starts_with("https://example.com/a.git "));
        let mut moved = deps.clone();
        moved[1].rev = "b".repeat(40);
        assert_ne!(super::identity(&moved).object_id(), identity.object_id());
    }

    #[test]
    fn links_point_each_deps_entry_at_its_checkout() {
        let deps = [dep(
            "heroicons",
            "https://github.com/tailwindlabs/heroicons.git",
        )];
        assert!(deps_links(None, &deps).is_empty());
        assert_eq!(
            deps_links(Some(Path::new("/store/objects/x")), &deps),
            vec![(
                PathBuf::from("deps/heroicons"),
                PathBuf::from("/store/objects/x/heroicons")
            )]
        );
    }
}
