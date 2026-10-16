//! Conservative input coverage for executable project manifests. The
//! resolver sees only the listed project files and its private scratch.
//!
//! A Gemfile, a mix.exs and a csproj are code that may read any file, so
//! their resolution inputs are every visible project entry ([`walk`]). Each
//! regular file is recorded by the sha256 of its bytes and each symlink by
//! its target text (`record::symlink_digest`), captured during the one walk
//! that also judges where each link leads. The door copies the same entries
//! into its private snapshot, requires them to match what the walk recorded,
//! and then judges every copied link again inside the finished copy
//! (`Snapshot::settle_links`): one that leads out of the copy, or through an
//! entry the copy leaves out, is withheld from it before the tool runs.

use super::record::{self, sha256_hex, symlink_digest};
use super::snapshot::PathGlob;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// How many symlinks one link's resolution may pass through, as the
/// kernel's own limit (`MAXSYMLINKS`) on Linux.
const MAX_LINK_HOPS: usize = 40;

/// How an executable-manifest door treats the symlinks in its project. The
/// walk that lists the inputs and the snapshot the tool runs in apply the
/// same rules, so both make the same decision about each link.
#[derive(Clone, Debug, Default)]
pub struct LinkRules {
    /// Where a ward projection may sit (`**/node_modules`, `**/.venv`). A
    /// symlink there whose target is an absolute path inside one of
    /// `store_roots` is ward's own environment link: neither an input nor
    /// copied. Anything else at such a path, a checked-in directory or an
    /// unrelated link, is an input like any other.
    pub projections: Vec<PathGlob>,
    /// The store's configured and canonical roots.
    pub store_roots: Vec<PathBuf>,
    /// Entries the resolver cannot do without (manifests, locks, tool
    /// configuration): one that is a link out of the project is refused,
    /// never withheld.
    pub required: Vec<PathGlob>,
}

impl LinkRules {
    pub(crate) fn new(
        projections: &[&str],
        required: &[&str],
        store_roots: Vec<PathBuf>,
    ) -> io::Result<LinkRules> {
        let globs = |patterns: &[&str]| -> io::Result<Vec<PathGlob>> {
            patterns
                .iter()
                .map(|pattern| PathGlob::new(pattern))
                .collect()
        };
        Ok(LinkRules {
            projections: globs(projections)?,
            store_roots,
            required: globs(required)?,
        })
    }

    /// Is the symlink at `path`, whose target text is `target`, ward's own
    /// environment link into the store?
    pub(crate) fn is_projection(&self, path: &Path, target: &Path) -> bool {
        target.is_absolute()
            && !target.components().any(|part| part == Component::ParentDir)
            && self
                .projections
                .iter()
                .any(|glob| glob.matches_exactly(path))
            && self.store_roots.iter().any(|root| target.starts_with(root))
    }

    /// Must `path` reach the resolver as it is?
    pub(crate) fn is_required(&self, path: &Path) -> bool {
        self.required.iter().any(|glob| glob.matches_exactly(path))
    }
}

/// What one executable-manifest walk takes into account.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WalkSpec<'a> {
    /// Path patterns neither walked nor copied: `.git`, `.greyward`, the
    /// tool's own state (`vendor/bundle`, `obj`).
    pub excludes: &'a [&'a str],
    /// The files a door writes (the manifest and its lock). They are
    /// recorded by digest but listed as outputs, not inputs.
    pub outputs: &'a [&'a str],
    pub links: &'a LinkRules,
}

/// What a walk found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Walk {
    /// The record digest of every walked input and every present output,
    /// keyed by record path, captured during the walk.
    pub digests: BTreeMap<String, String>,
    /// Every walked input (not the outputs), sorted: regular files and
    /// symlinks, wherever they lead.
    pub inputs: Vec<PathBuf>,
    /// Links that lead out of the project, or through an entry the copy
    /// leaves out, by target text. Each is still an input, named by its
    /// target text; the door withholds it from the resolver's copy and
    /// records an `outward-symlink` exception for it.
    pub outward: BTreeMap<PathBuf, OsString>,
    /// Ward's own environment links the walk verified and skipped.
    pub projections: Vec<PathBuf>,
}

/// Where a symlink leads, judged inside one tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LinkEnd {
    /// It stays inside the tree (or dangles there).
    Inside,
    /// It leads out of the tree, for the reason given.
    Outside(String),
    /// It passes through an entry the copy leaves out, so it would mean
    /// something else there.
    Excluded(PathBuf),
}

impl LinkEnd {
    /// Why a link that does not stay inside is left out or refused.
    pub(crate) fn why(&self) -> String {
        match self {
            LinkEnd::Inside => "stays in the project".into(),
            LinkEnd::Outside(why) => why.clone(),
            LinkEnd::Excluded(through) => format!(
                "passes through {}, which the resolver's copy leaves out",
                through.display()
            ),
        }
    }
}

/// Walk every entry of `project` an executable manifest could read.
///
/// A symlink is an input of its own, never walked through: a link to a
/// directory in the project leaves that directory to be walked where it
/// really is. A link that leads out of the project, or through an entry
/// the copy leaves out, is still an input (its target text is what the
/// receipt binds) and is listed in [`Walk::outward`]; one the resolver
/// cannot do without (an output or a `required` entry) is refused.
pub(crate) fn walk(project: &ProjectRoot, spec: &WalkSpec<'_>) -> io::Result<Walk> {
    let excludes: Vec<PathGlob> = spec
        .excludes
        .iter()
        .map(|pattern| PathGlob::new(pattern))
        .collect::<io::Result<_>>()?;
    let rules = spec.links;
    let is_projection = |path: &Path| -> bool {
        matches!(project.read_link(path), Ok(Some(target)) if rules.is_projection(path, &target))
    };
    let skipped =
        |path: &Path| excludes.iter().any(|glob| glob.matches(path)) || is_projection(path);
    let mut walk = Walk::default();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let dir = if relative.as_os_str().is_empty() {
            project.try_clone()?
        } else {
            project
                .subdir(&relative)?
                .ok_or_else(|| vanished(&relative))?
        };
        for name in dir.read_input_dir(Path::new("."))?.unwrap_or_default() {
            let path = relative.join(&name);
            if excludes.iter().any(|glob| glob.matches(&path)) {
                continue;
            }
            let output = spec.outputs.iter().any(|output| path == Path::new(output));
            let key = record::record_path(&path).ok_or_else(|| {
                io::Error::other(format!(
                    "{} is not a plain UTF-8 project path; a resolution input must be",
                    path.display()
                ))
            })?;
            match dir.entry(Path::new(&name))? {
                Entry::Regular => {
                    let bytes = dir
                        .read_file(Path::new(&name))?
                        .ok_or_else(|| vanished(&path))?;
                    project.observe_input(&path, Some(&bytes))?;
                    walk.digests.insert(key, sha256_hex(&bytes));
                    if !output {
                        walk.inputs.push(path);
                    }
                }
                Entry::Directory => pending.push(path),
                Entry::Symlink => {
                    let target = dir
                        .read_link(Path::new(&name))?
                        .ok_or_else(|| vanished(&path))?;
                    if !output && rules.is_projection(&path, &target) {
                        walk.projections.push(path);
                        continue;
                    }
                    let end = link_end(project, &path, &target, &skipped)?;
                    if end != LinkEnd::Inside {
                        if output || rules.is_required(&path) {
                            return Err(refused_link(&path, &target, &end));
                        }
                        walk.outward
                            .insert(path.clone(), target.clone().into_os_string());
                    }
                    walk.digests
                        .insert(key, symlink_digest(target.as_os_str().as_bytes()));
                    if !output {
                        walk.inputs.push(path);
                    }
                }
                _ => {}
            }
        }
    }
    walk.inputs.sort();
    walk.projections.sort();
    Ok(walk)
}

fn vanished(path: &Path) -> io::Error {
    io::Error::other(format!(
        "{} vanished while listing resolution inputs",
        path.display()
    ))
}

/// The refusal for a link the resolver cannot do without.
pub(crate) fn refused_link(link: &Path, target: &Path, end: &LinkEnd) -> io::Error {
    io::Error::other(format!(
        "{} is a symlink to {}, which {}; it is a manifest, lock or configuration file \
         the resolver needs, and executable-manifest resolution sees only the project. \
         Point the link inside the project or replace it with a regular file",
        link.display(),
        target.display(),
        end.why()
    ))
}

/// Where the symlink at `link` (relative to `tree`) leads when `target`
/// is followed from where the link sits, resolved the way the kernel
/// resolves it: each `..` climbs from where the path really is, so a link
/// that passes through another link is followed through it (a purely
/// textual check would let `d/up -> ..` and `x -> d/up/../out` through).
/// A component `skipped` names is not in the copy, so a link through it is
/// [`LinkEnd::Excluded`]. A component that does not exist ends what the
/// tree can show; the rest is judged by its text alone.
pub(crate) fn link_end(
    tree: &ProjectRoot,
    link: &Path,
    target: &Path,
    skipped: &dyn Fn(&Path) -> bool,
) -> io::Result<LinkEnd> {
    let mut at: Vec<OsString> = link
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect();
    let mut queue: VecDeque<OsString> = VecDeque::new();
    if !push_front(&mut queue, target) {
        return Ok(LinkEnd::Outside("is an absolute path".into()));
    }
    let mut hops = 0usize;
    let mut textual = false;
    while let Some(part) = queue.pop_front() {
        if part == ".." {
            if at.pop().is_none() {
                return Ok(LinkEnd::Outside("climbs out of the project".into()));
            }
            continue;
        }
        at.push(part);
        let here: PathBuf = at.iter().collect();
        if skipped(&here) {
            return Ok(LinkEnd::Excluded(here));
        }
        if textual {
            continue;
        }
        match tree.entry(&here) {
            Ok(Entry::Directory) => {}
            Ok(Entry::Symlink) => {
                hops += 1;
                if hops > MAX_LINK_HOPS {
                    return Ok(LinkEnd::Outside("passes through too many symlinks".into()));
                }
                let Some(next) = tree.read_link(&here)? else {
                    textual = true;
                    continue;
                };
                at.pop();
                if !push_front(&mut queue, &next) {
                    return Ok(LinkEnd::Outside(format!(
                        "reaches {}, a symlink to an absolute path",
                        here.display()
                    )));
                }
            }
            // Absent, a file used as a directory, or unreadable: the kernel
            // stops here too, so nothing past it can be reached.
            _ => textual = true,
        }
    }
    Ok(LinkEnd::Inside)
}

/// Queue `text`'s components ahead of the rest; `false` for an absolute
/// path.
fn push_front(queue: &mut VecDeque<OsString>, text: &Path) -> bool {
    let mut parts = Vec::new();
    for component in text.components() {
        match component {
            Component::Normal(name) => parts.push(name.to_os_string()),
            Component::ParentDir => parts.push(OsString::from("..")),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    for part in parts.into_iter().rev() {
        queue.push_front(part);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn walk_with(
        project: &ProjectRoot,
        excludes: &[&str],
        outputs: &[&str],
        links: &LinkRules,
    ) -> io::Result<Walk> {
        walk(
            project,
            &WalkSpec {
                excludes,
                outputs,
                links,
            },
        )
    }

    #[test]
    fn coverage_includes_nested_code_and_data_but_not_hidden_resolver_state() {
        let temp = TempDir::new();
        for directory in ["apps/web", "config/nested", ".greyward", ".git", "deps"] {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        for file in [
            "mix.exs",
            "mix.lock",
            "apps/web/mix.exs",
            "config/nested/data.json",
            ".greyward/closure.json",
            ".git/config",
            "deps/dep.exs",
        ] {
            fs::write(temp.0.join(file), "input").unwrap();
        }
        let held = ProjectRoot::open(&temp.0).unwrap();
        let walked = walk_with(
            &held,
            &[".greyward", ".git", "deps"],
            &["mix.exs", "mix.lock"],
            &LinkRules::default(),
        )
        .unwrap();
        assert_eq!(
            walked.inputs,
            vec![
                PathBuf::from("apps/web/mix.exs"),
                PathBuf::from("config/nested/data.json")
            ]
        );
        // Outputs are recorded by digest, not listed as inputs.
        assert_eq!(
            walked.digests.keys().collect::<Vec<_>>(),
            [
                "apps/web/mix.exs",
                "config/nested/data.json",
                "mix.exs",
                "mix.lock"
            ]
        );
        assert_eq!(walked.digests["mix.exs"], sha256_hex(b"input"));
    }

    /// An in-project link is an input of its own, listed and not walked
    /// through; the directory it names is walked where it is.
    #[test]
    fn an_in_project_symlink_is_listed_as_itself() {
        let temp = TempDir::new();
        fs::create_dir_all(temp.0.join("test/source/data")).unwrap();
        fs::write(temp.0.join("test/source/data/a.yml"), "a").unwrap();
        symlink("data", temp.0.join("test/source/_data")).unwrap();
        symlink("../../Gemfile", temp.0.join("test/source/gemfile-link")).unwrap();
        symlink("missing/file", temp.0.join("dangling")).unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let walked = walk_with(&held, &[".git"], &[], &LinkRules::default()).unwrap();
        assert_eq!(
            walked.inputs,
            vec![
                PathBuf::from("dangling"),
                PathBuf::from("test/source/_data"),
                PathBuf::from("test/source/data/a.yml"),
                PathBuf::from("test/source/gemfile-link"),
            ]
        );
        assert!(walked.outward.is_empty());
        assert_eq!(walked.digests["test/source/_data"], symlink_digest(b"data"));
    }

    /// A link out of the project that nothing requires is an input named
    /// by its target text and listed as outward; one the resolver needs
    /// (an output, or a required path) is refused.
    #[test]
    fn a_symlink_out_of_the_project_is_outward_unless_required() {
        for (name, target) in [
            ("absolute", "/etc/passwd"),
            ("climbing", "../outside"),
            ("deep/climbing", "../../outside"),
        ] {
            let temp = TempDir::new();
            fs::create_dir_all(temp.0.join("deep")).unwrap();
            symlink(target, temp.0.join(name)).unwrap();
            let held = ProjectRoot::open(&temp.0).unwrap();
            let walked = walk_with(&held, &[], &[], &LinkRules::default()).unwrap();
            assert_eq!(walked.inputs, vec![PathBuf::from(name)], "{name}");
            assert_eq!(
                walked.outward,
                BTreeMap::from([(PathBuf::from(name), OsString::from(target))])
            );
            assert_eq!(walked.digests[name], symlink_digest(target.as_bytes()));
            let required = LinkRules::new(&[], &["**/*"], Vec::new()).unwrap();
            let error = walk_with(&held, &[], &[], &required).unwrap_err();
            assert!(
                error.to_string().contains("is a symlink to"),
                "{name}: {error}"
            );
            assert!(
                walk_with(&held, &[], &[name], &LinkRules::default()).is_err(),
                "{name}"
            );
        }
    }

    /// `d/up -> ..` stays in the project by its text and by where it
    /// lands; `x -> d/up/../out` stays in by its text alone, but the
    /// kernel climbs from where `d/up` really is, the project root, and
    /// lands outside.
    #[test]
    fn a_link_that_escapes_through_another_link_is_judged_where_it_lands() {
        let temp = TempDir::new();
        fs::create_dir_all(temp.0.join("d")).unwrap();
        symlink("..", temp.0.join("d/up")).unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let never = |_: &Path| false;
        assert_eq!(
            link_end(&held, Path::new("d/up"), Path::new(".."), &never).unwrap(),
            LinkEnd::Inside
        );
        let end = link_end(&held, Path::new("x"), Path::new("d/up/../out"), &never).unwrap();
        assert!(
            matches!(end, LinkEnd::Outside(ref why) if why.contains("climbs out")),
            "{end:?}"
        );
        symlink("loop-b", temp.0.join("loop-a")).unwrap();
        symlink("loop-a", temp.0.join("loop-b")).unwrap();
        let end = link_end(&held, Path::new("loop-a"), Path::new("loop-b"), &never).unwrap();
        assert!(
            matches!(end, LinkEnd::Outside(ref why) if why.contains("too many symlinks")),
            "{end:?}"
        );
    }

    /// Only a verified ward link into the store is a projection. A
    /// checked-in `node_modules` directory, or a link there that is not
    /// ward's, is an input like any other.
    #[test]
    fn only_verified_ward_links_are_projections() {
        let temp = TempDir::new();
        let store = temp.0.join("store");
        let project = temp.0.join("project");
        fs::create_dir_all(store.join("forests/abc")).unwrap();
        fs::create_dir_all(project.join("fixtures/node_modules")).unwrap();
        fs::create_dir_all(project.join("packages/web")).unwrap();
        fs::write(project.join("fixtures/node_modules/config.rb"), "x").unwrap();
        symlink(store.join("forests/abc"), project.join("node_modules")).unwrap();
        symlink("/elsewhere", project.join("packages/web/node_modules")).unwrap();
        let held = ProjectRoot::open(&project).unwrap();
        let rules = LinkRules::new(&["**/node_modules"], &[], vec![store]).unwrap();
        let walked = walk_with(&held, &[], &[], &rules).unwrap();
        assert_eq!(walked.projections, vec![PathBuf::from("node_modules")]);
        assert_eq!(
            walked.inputs,
            vec![
                PathBuf::from("fixtures/node_modules/config.rb"),
                PathBuf::from("packages/web/node_modules"),
            ]
        );
        assert_eq!(
            walked.outward.keys().collect::<Vec<_>>(),
            [Path::new("packages/web/node_modules")]
        );
    }

    /// A link whose meaning depends on an entry the copy leaves out (here
    /// ward's `node_modules` link into the store, and `.git`) would mean
    /// something else in the copy: outward.
    #[test]
    fn a_link_through_a_left_out_entry_is_outward() {
        let temp = TempDir::new();
        let store = temp.0.join("store");
        let project = temp.0.join("project");
        fs::create_dir_all(store.join("forest")).unwrap();
        fs::create_dir_all(project.join("data")).unwrap();
        symlink(store.join("forest"), project.join("node_modules")).unwrap();
        symlink("node_modules/../../data", project.join("fixture")).unwrap();
        symlink(".git/config", project.join("git-config")).unwrap();
        let held = ProjectRoot::open(&project).unwrap();
        let rules = LinkRules::new(&["**/node_modules"], &[], vec![store]).unwrap();
        let walked = walk_with(&held, &[".git"], &[], &rules).unwrap();
        assert_eq!(
            walked.outward.keys().collect::<Vec<_>>(),
            [Path::new("fixture"), Path::new("git-config")]
        );
    }
}
