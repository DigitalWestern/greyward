//! npm's workspace member set, read by npm itself. A `workspaces` value is
//! handed to the `@npmcli/map-workspaces` bundled with the npm of the
//! project's selected Node, run by that Node in the network-denied sandbox
//! with the project read-only. Whatever globs, braces, extglobs, negations
//! and symlink rules npm applies are then npm's own, so ward's member set
//! cannot drift from the one `npm ci` builds from.
//!
//! What npm returns passes one rule of ward's own: a member whose real
//! directory is outside the project is left out (a member is read from
//! inside the project only) and reported in [`Found::outside`], so a sync
//! can record it. npm can only return such a member if it can see it, so
//! the directory a symlink below a pattern's literal prefix leads to
//! outside the project is mounted read-only beside the project.
//!
//! Each answer is kept for the rest of the process, keyed by the project's
//! path and the `workspaces` value, so one command runs npm once per list.

use crate::kernel::context::Context;
use crate::kernel::fsroot::{Containment, Entry, ProjectRoot};
use crate::kernel::sandbox::{HostView, Sandbox};
use crate::kernel::toolchain::Selected;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The script the sandboxed Node runs.
const SCRIPT: &str = include_str!("map_workspaces.js");

/// How deep the search for symlinks leading out of the project goes below
/// a pattern's literal prefix.
const MAX_DEPTH: usize = 24;

/// npm's members of one `workspaces` list, after ward's symlink rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Found {
    /// Member directories inside the project, relative to it, sorted.
    pub(crate) members: Vec<String>,
    /// Member directories npm found whose real directory is outside the
    /// project, by the path npm named them with, sorted.
    pub(crate) outside: Vec<String>,
}

/// What a membership run needs from the command: an open store with its
/// lease, and the Node toolchain the project at a directory selects.
pub(crate) type Provider = dyn Fn(&Path) -> io::Result<(Context, Selected)> + Send + Sync;

static PROVIDER: Mutex<Option<Arc<Provider>>> = Mutex::new(None);

type Memo = BTreeMap<(PathBuf, String), Found>;
static MEMO: Mutex<Memo> = Mutex::new(BTreeMap::new());

/// Install the provider for this process. The command layer calls it once,
/// before any verb runs; the first install wins.
pub(crate) fn install(provider: Arc<Provider>) {
    let mut slot = PROVIDER.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_none() {
        *slot = Some(provider);
    }
}

/// npm's members of `workspaces` (a `package.json` `workspaces` value, or
/// the one an npm lock's root entry copies) for the project at `root`. No
/// value, or an empty list, names no members and runs nothing.
pub(crate) fn npm_members(root: &ProjectRoot, workspaces: &Value) -> io::Result<Found> {
    if workspaces.is_null()
        || workspaces.as_array().is_some_and(Vec::is_empty)
        || workspaces
            .get("packages")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Ok(Found::default());
    }
    let key = (root.path().to_path_buf(), workspaces.to_string());
    if let Some(found) = MEMO.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
        return Ok(found.clone());
    }
    let named = npm_named(root, workspaces)?;
    let found = contained(root, named)?;
    MEMO.lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(key, found.clone());
    Ok(found)
}

/// The member directories npm names, relative to the root, before ward's
/// rule: the provider's Node runs map-workspaces in the sandbox.
fn npm_named(root: &ProjectRoot, workspaces: &Value) -> io::Result<Vec<String>> {
    #[cfg(test)]
    if let Some(named) = tests::named_for_test(root, workspaces) {
        return named;
    }
    let provider = PROVIDER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .ok_or_else(|| {
            io::Error::other(
                "npm's workspace members are read by npm itself, and this command has no \
                 Node to run it with",
            )
        })?;
    let (ctx, selected) = provider(root.path())?;
    let node = super::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, &selected)?;
    let scratch = ctx.store.stage_with_activity(&ctx.activity)?;
    let result = run_map_workspaces(&ctx, &node, root, workspaces, &scratch);
    let removed = crate::kernel::store::remove_tree(&scratch);
    let named = result?;
    removed?;
    Ok(named)
}

fn run_map_workspaces(
    ctx: &Context,
    node: &Path,
    root: &ProjectRoot,
    workspaces: &Value,
    scratch: &Path,
) -> io::Result<Vec<String>> {
    let project = std::fs::canonicalize(root.path())?;
    let script = scratch.join("map_workspaces.js");
    let request = scratch.join("workspaces.json");
    let out = scratch.join("members.json");
    std::fs::write(&script, SCRIPT)?;
    std::fs::write(&request, workspaces.to_string())?;
    let outside = outside_targets(root, workspaces)?;
    let modules = node.join("lib/node_modules/npm/node_modules");
    let mut read: Vec<&Path> = vec![node, &project];
    read.extend(outside.iter().map(PathBuf::as_path));
    let sandbox = Sandbox {
        read,
        write: vec![scratch],
        host_view: if ctx.platform.is_macos() {
            HostView::Full
        } else {
            HostView::RuntimeOnly
        },
    };
    let node_bin = node.join("bin/node");
    let argv = [
        node_bin.as_os_str(),
        script.as_os_str(),
        modules.as_os_str(),
        project.as_os_str(),
        request.as_os_str(),
        out.as_os_str(),
    ];
    let argv: Vec<&str> = argv
        .iter()
        .map(|arg| {
            arg.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "a path is not valid UTF-8")
            })
        })
        .collect::<io::Result<_>>()?;
    let path_env = format!("{}:/usr/bin:/bin", node.join("bin").display());
    sandbox
        .run_in_on(
            ctx.platform,
            &argv,
            &path_env,
            scratch,
            &project,
            &[],
            Some(&ctx.activity),
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("npm could not read the package.json workspaces list: {error}"),
            )
        })?;
    let members: BTreeMap<String, String> = serde_json::from_slice(&std::fs::read(&out)?)
        .map_err(|error| io::Error::other(format!("npm's workspace members: {error}")))?;
    Ok(members.into_values().collect())
}

/// ward's rule over the directories npm named: a plain path inside the
/// project with a `package.json` is a member, one a symlink carries out of
/// the project is outside, and one that is not a plain relative path is an
/// error, since a record names files inside the project only.
fn contained(root: &ProjectRoot, named: Vec<String>) -> io::Result<Found> {
    let mut found = Found::default();
    for dir in named {
        if dir.is_empty() || dir == "." {
            continue;
        }
        let path = PathBuf::from(&dir);
        let plain = path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
        if !plain {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "package.json names the workspace member {dir:?}, which is not a plain path \
                     inside the project; a resolution record names files inside the project only"
                ),
            ));
        }
        match root.input_containment(&path)? {
            Containment::Outside => found.outside.push(dir),
            Containment::Dangling => {}
            Containment::Inside if root.is_input_file(&path.join("package.json")) => {
                found.members.push(dir)
            }
            Containment::Inside => {}
        }
    }
    for list in [&mut found.members, &mut found.outside] {
        list.sort();
        list.dedup();
    }
    Ok(found)
}

/// The real directories outside the project that symlinks below the
/// literal prefix of a positive pattern lead to, for the sandbox to mount
/// read-only so npm sees what it would see unconfined.
fn outside_targets(root: &ProjectRoot, workspaces: &Value) -> io::Result<Vec<PathBuf>> {
    let list = workspaces
        .as_array()
        .or_else(|| workspaces.get("packages").and_then(Value::as_array));
    let mut targets = Vec::new();
    for pattern in list.into_iter().flatten().filter_map(Value::as_str) {
        if pattern.starts_with('!') {
            continue;
        }
        let Some(prefix) = literal_prefix(pattern) else {
            continue;
        };
        if prefix.as_os_str().is_empty() {
            walk(root, Path::new("."), 0, &mut targets)?;
            continue;
        }
        match root.input_containment(&prefix)? {
            Containment::Outside => push_target(root, &prefix, &mut targets),
            Containment::Inside if root.is_input_dir(&prefix) => {
                walk(root, &root.contained_input_path(&prefix)?, 0, &mut targets)?
            }
            _ => {}
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

/// The segments of `pattern` before its first one with glob syntax, past a
/// leading `./` or `/`; `None` when one of them is `..`.
fn literal_prefix(pattern: &str) -> Option<PathBuf> {
    const MAGIC: &[char] = &['*', '?', '[', ']', '{', '}', '(', ')', '!', '+', '@', '\\'];
    let undotted = pattern.strip_prefix('.').unwrap_or(pattern);
    let pattern = if undotted.starts_with('/') {
        undotted
    } else {
        pattern
    };
    let mut prefix = PathBuf::new();
    for segment in pattern.trim_start_matches('/').split('/') {
        if segment.contains(MAGIC) {
            break;
        }
        match segment {
            ".." => return None,
            "" | "." => {}
            name => prefix.push(name),
        }
    }
    Some(prefix)
}

fn walk(
    root: &ProjectRoot,
    dir: &Path,
    depth: usize,
    targets: &mut Vec<PathBuf>,
) -> io::Result<()> {
    if depth >= MAX_DEPTH {
        return Ok(());
    }
    let Some(names) = root.read_input_dir(dir)? else {
        return Ok(());
    };
    for name in names {
        if name == "node_modules" || name == ".git" {
            continue;
        }
        let child = if dir == Path::new(".") {
            PathBuf::from(&name)
        } else {
            dir.join(&name)
        };
        match root.entry(&child)? {
            Entry::Directory => walk(root, &child, depth + 1, targets)?,
            Entry::Symlink => match root.input_containment(&child)? {
                // Listed at the real path it resolves to: the strict
                // reader does not list through a link.
                Containment::Inside if root.is_input_dir(&child) => walk(
                    root,
                    &root.contained_input_path(&child)?,
                    depth + 1,
                    targets,
                )?,
                Containment::Outside => push_target(root, &child, targets),
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}

fn push_target(root: &ProjectRoot, relative: &Path, targets: &mut Vec<PathBuf>) {
    if let Ok(real) = std::fs::canonicalize(root.path().join(relative)) {
        if real.is_dir() {
            targets.push(real);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::testutil::TempDir;

    type Fake = dyn Fn(&Value) -> Vec<String> + Send + Sync;

    static FAKE: Mutex<Option<(PathBuf, Arc<Fake>)>> = Mutex::new(None);
    static SERIAL: Mutex<()> = Mutex::new(());

    /// While the returned guard lives, a membership run for the project at
    /// `root` answers with `fake` instead of running npm, and the answers
    /// kept so far are dropped. Tests that read npm's members hold one.
    pub(crate) fn fake_npm(
        root: &Path,
        fake: impl Fn(&Value) -> Vec<String> + Send + Sync + 'static,
    ) -> impl Drop {
        struct Reset(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
        impl Drop for Reset {
            fn drop(&mut self) {
                *FAKE.lock().unwrap_or_else(|p| p.into_inner()) = None;
                MEMO.lock().unwrap_or_else(|p| p.into_inner()).clear();
            }
        }
        let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        MEMO.lock().unwrap_or_else(|p| p.into_inner()).clear();
        *FAKE.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((root.to_path_buf(), Arc::new(fake)));
        Reset(serial)
    }

    pub(super) fn named_for_test(
        root: &ProjectRoot,
        workspaces: &Value,
    ) -> Option<io::Result<Vec<String>>> {
        let slot = FAKE.lock().unwrap_or_else(|p| p.into_inner());
        let (at, fake) = slot.as_ref()?;
        let real = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
        (real(at) == real(root.path())).then(|| Ok(fake(workspaces)))
    }

    /// ward's rule over what npm returned: a member through a symlink
    /// inside the project is kept, one through a symlink out of it is
    /// outside, one with no `package.json` or behind a dangling link is
    /// dropped, and a path above the project is refused (#694).
    #[test]
    fn npm_members_pass_the_containment_rule() {
        let scratch = TempDir::named("npm-members-rule");
        let root = scratch.0.join("project");
        for dir in ["packages/a", "vendor/lib", "packages/bare"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for dir in ["packages/a", "vendor/lib"] {
            std::fs::write(root.join(dir).join("package.json"), "{}").unwrap();
        }
        std::fs::create_dir_all(scratch.0.join("elsewhere")).unwrap();
        std::fs::write(scratch.0.join("elsewhere/package.json"), "{}").unwrap();
        std::os::unix::fs::symlink("../vendor/lib", root.join("packages/lib")).unwrap();
        std::os::unix::fs::symlink("../../elsewhere", root.join("packages/ext")).unwrap();
        std::os::unix::fs::symlink("../missing", root.join("packages/gone")).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let _fake = fake_npm(&root, |_| {
            [
                "packages/a",
                "packages/lib",
                "packages/ext",
                "packages/gone",
                "packages/bare",
            ]
            .map(String::from)
            .to_vec()
        });
        let found = npm_members(&held, &serde_json::json!(["packages/*"])).unwrap();
        assert_eq!(found.members, ["packages/a", "packages/lib"]);
        assert_eq!(found.outside, ["packages/ext"]);
        assert_eq!(
            npm_members(&held, &serde_json::json!([])).unwrap(),
            Found::default()
        );
        drop(_fake);
        let _fake = fake_npm(&root, |_| vec!["../elsewhere".to_string()]);
        let error = npm_members(&held, &serde_json::json!(["../*"])).unwrap_err();
        assert!(error.to_string().contains("not a plain path"), "{error}");
    }

    /// The directories outside the project that the sandbox mounts: a
    /// symlink below a pattern's literal prefix that leads out, and a
    /// literal prefix that is itself one, but nothing below a negation
    /// (#694).
    #[test]
    fn symlinks_leading_out_below_a_pattern_are_mounted() {
        let scratch = TempDir::named("npm-members-mounts");
        let root = scratch.0.join("project");
        for dir in ["packages/a", "tools/deep/x", "skipped"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for dir in ["out/one", "out/two", "out/three"] {
            std::fs::create_dir_all(scratch.0.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink("../../out/one", root.join("packages/one")).unwrap();
        std::os::unix::fs::symlink("../../../out/two", root.join("tools/deep/two")).unwrap();
        std::os::unix::fs::symlink("../out/three", root.join("direct")).unwrap();
        std::os::unix::fs::symlink("../../out/one", root.join("skipped/one")).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let workspaces = serde_json::json!(["./packages/*", "tools/**", "direct", "!skipped/*"]);
        let real = |dir: &str| std::fs::canonicalize(scratch.0.join(dir)).unwrap();
        assert_eq!(
            outside_targets(&held, &workspaces).unwrap(),
            [real("out/one"), real("out/three"), real("out/two")]
        );
        assert_eq!(literal_prefix("a/b/@(c|d)/e"), Some(PathBuf::from("a/b")));
        assert_eq!(literal_prefix("/x/{a,b}"), Some(PathBuf::from("x")));
        assert_eq!(literal_prefix("../x"), None);
    }

    /// The corpus, through the real path: for each case, the member set
    /// npm's map-workspaces found unconfined over the same tree
    /// (`tools/npm_workspace_corpus.js`) is the one ward's sandboxed run
    /// gives (#694).
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn members_match_npm_on_the_corpus() {
        if !crate::kernel::sandbox::linux_ready("members_match_npm_on_the_corpus") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        let corpus: Vec<Value> = serde_json::from_str(include_str!("corpus.json")).unwrap();
        let strings = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .into_iter()
                .flatten()
                .map(|item| item.as_str().unwrap().to_string())
                .collect()
        };
        let mut failures = Vec::new();
        for case in &corpus {
            let name = case["name"].as_str().unwrap();
            let scratch = TempDir::named("npm-ws-corpus");
            let root = scratch.0.join("project");
            std::fs::create_dir_all(&root).unwrap();
            for dir in strings(&case["dirs"]) {
                std::fs::create_dir_all(root.join(&dir)).unwrap();
                let named = format!(
                    "{{\"name\":\"m-{}\"}}",
                    dir.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                );
                std::fs::write(root.join(&dir).join("package.json"), named).unwrap();
            }
            for dir in strings(&case["bare"]) {
                std::fs::create_dir_all(root.join(&dir)).unwrap();
            }
            for link in case["links"].as_array().into_iter().flatten() {
                let at = root.join(link[0].as_str().unwrap());
                std::fs::create_dir_all(at.parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(link[1].as_str().unwrap(), at).unwrap();
            }
            let held = ProjectRoot::open(&root).unwrap();
            let found = npm_members(&held, &case["workspaces"])
                .map(|found| found.members)
                .map_err(|error| error.to_string());
            let expected = Ok(strings(&case["expected"]));
            if found != expected {
                failures.push(format!("{name}: ward {found:?}, npm {expected:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// A member npm reaches through a symlink out of the project is seen
    /// by the sandboxed npm and reported outside; a symlink out of the
    /// project that no pattern names is not (#694).
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_member_symlinked_out_of_the_project_is_reported_and_an_unnamed_one_is_not() {
        if !crate::kernel::sandbox::linux_ready("npm_members_outside") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        let scratch = TempDir::named("npm-ws-outside");
        let root = scratch.0.join("project");
        for dir in ["project/packages/a", "elsewhere/ext", "elsewhere/z"] {
            std::fs::create_dir_all(scratch.0.join(dir)).unwrap();
            let name = dir.rsplit('/').next().unwrap();
            std::fs::write(
                scratch.0.join(dir).join("package.json"),
                format!("{{\"name\":\"{name}\"}}"),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink("../../elsewhere/ext", root.join("packages/ext")).unwrap();
        std::os::unix::fs::symlink("../../elsewhere/z", root.join("packages/z")).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let found = npm_members(&held, &serde_json::json!(["packages/a*", "packages/e*"])).unwrap();
        assert_eq!(found.members, ["packages/a"]);
        assert_eq!(found.outside, ["packages/ext"]);
    }

    /// The provider the ignored tests use: the shipped Node, in the store
    /// `GREYWARD_STORE` names.
    fn install_shipped_node() {
        install(Arc::new(|_dir: &Path| {
            Ok((
                Context::open(Platform::host()?)?,
                super::super::shipped_selection()?,
            ))
        }));
        MEMO.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}
