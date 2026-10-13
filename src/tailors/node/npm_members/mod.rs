//! npm's workspace member set, read by npm itself. A `workspaces` value is
//! handed to the `@npmcli/map-workspaces` bundled with the npm of the
//! project's selected Node, run by that Node in the network-denied sandbox
//! with the whole host read-only (`HostView::WholeHost`) and the project
//! bound from the descriptor ward holds. Whatever globs, braces, extglobs,
//! negations and symlink rules npm applies are then npm's own, and npm sees
//! every directory an unconfined run would, so ward's member set cannot
//! drift from the one `npm ci` builds from.
//!
//! What npm returns passes one rule of ward's own, resolved through the
//! held project descriptor: a member whose real directory is outside the
//! project is left out (a member is read from inside the project only) and
//! reported in [`Found::outside`], so a sync can record it.
//!
//! Nothing is cached: every question runs npm again, so the freshness check
//! and the closure's resolution record each see the tree as it is then.
//! The first answer for each project and list is kept only to compare
//! against: a later answer that differs refuses, since members added or
//! removed while a command ran would leave what it publishes uncovered.

use crate::kernel::context::Context;
use crate::kernel::fsroot::{Containment, ProjectRoot};
use crate::kernel::sandbox::{HostView, Sandbox};
use crate::kernel::toolchain::Selected;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The script the sandboxed Node runs. It is staged as `.cjs` so it runs as
/// CommonJS whatever `"type"` a `package.json` above the store declares.
const SCRIPT: &str = include_str!("map_workspaces.cjs");

/// npm's members of one `workspaces` list, after ward's symlink rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Found {
    /// Member directories inside the project, relative to it, sorted.
    pub(crate) members: Vec<String>,
    /// Member directories npm found whose real directory is outside the
    /// project, by the path npm named them with, sorted.
    pub(crate) outside: Vec<String>,
    /// npm's `[name, directory]` pair for each member in `members`, in
    /// npm's order. The name is the `node_modules/<name>` link an npm lock
    /// records for the member, so a renamed member is a changed member set.
    pub(crate) named: Vec<(String, String)>,
}

/// What a membership run needs from the command: an open store with its
/// lease, and the Node toolchain the project at a directory selects.
pub(crate) type Provider = dyn Fn(&Path) -> io::Result<(Context, Selected)> + Send + Sync;

static PROVIDER: Mutex<Option<Arc<Provider>>> = Mutex::new(None);

/// The first answer for each project path and `workspaces` value in this
/// process, compared against and never served.
type FirstAnswers = BTreeMap<(PathBuf, String), Found>;
static FIRST: Mutex<FirstAnswers> = Mutex::new(BTreeMap::new());

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
/// value, or an empty list, names no members and runs nothing. An answer
/// that differs from this process's first one for the same project and
/// list is refused.
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
    let found = contained(root, npm_named(root, workspaces)?)?;
    let key = (root.path().to_path_buf(), workspaces.to_string());
    let mut first = FIRST.lock().unwrap_or_else(|p| p.into_inner());
    match first.get(&key) {
        Some(earlier) if earlier != &found => Err(changed(root, earlier, &found)),
        Some(_) => Ok(found),
        None => {
            first.insert(key, found.clone());
            Ok(found)
        }
    }
}

/// The refusal for a member set that changed while the command ran.
fn changed(root: &ProjectRoot, earlier: &Found, now: &Found) -> io::Error {
    let all = |found: &Found| -> Vec<String> {
        let mut all: Vec<String> = found
            .members
            .iter()
            .chain(&found.outside)
            .cloned()
            .collect();
        all.sort();
        all
    };
    let (before, after) = (all(earlier), all(now));
    let added: Vec<&String> = after.iter().filter(|dir| !before.contains(dir)).collect();
    let removed: Vec<&String> = before.iter().filter(|dir| !after.contains(dir)).collect();
    let renamed: Vec<&(String, String)> = now
        .named
        .iter()
        .filter(|pair| {
            earlier
                .named
                .iter()
                .any(|(name, dir)| dir == &pair.1 && name != &pair.0)
        })
        .collect();
    let moved: Vec<&String> = now
        .outside
        .iter()
        .filter(|dir| earlier.members.contains(dir))
        .chain(
            now.members
                .iter()
                .filter(|dir| earlier.outside.contains(dir)),
        )
        .collect();
    io::Error::other(format!(
        "{}: the npm workspace members changed while the command ran (added {added:?}, \
         removed {removed:?}, renamed {renamed:?}, moved across the project boundary \
         {moved:?}, or reordered); nothing was published for the changed set, so run the command again",
        root.path().display()
    ))
}

/// The member directories npm names, relative to the root, before ward's
/// rule: the provider's Node runs map-workspaces in the sandbox.
fn npm_named(root: &ProjectRoot, workspaces: &Value) -> io::Result<Vec<(String, String)>> {
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

/// Run the wrapper in the sandbox. The project is named by the path `root`
/// was opened and registered at, never resolved again: the sandbox binds
/// the held descriptor there (`HeldRoots`), so npm reads the directory ward
/// holds even if that path has since been pointed somewhere else.
///
/// Node's stdout and stderr go to `/dev/null`, never to ward's terminal or
/// a CI log: npm sees the whole host read-only, and a member's
/// `package.json` can be a symlink to any file the user can read, which an
/// npm message would quote. The answer is the out file alone.
fn run_map_workspaces(
    ctx: &Context,
    node: &Path,
    root: &ProjectRoot,
    workspaces: &Value,
    scratch: &Path,
) -> io::Result<Vec<(String, String)>> {
    let project = root.path();
    let script = scratch.join("map_workspaces.cjs");
    let request = scratch.join("workspaces.json");
    let out = scratch.join("members.json");
    std::fs::write(&script, SCRIPT)?;
    std::fs::write(&request, workspaces.to_string())?;
    let modules = node.join("lib/node_modules/npm/node_modules");
    let sandbox = Sandbox {
        read: vec![project],
        write: vec![scratch],
        host_view: HostView::WholeHost,
    };
    let node_bin = node.join("bin/node");
    let argv = [
        std::ffi::OsStr::new("/bin/sh"),
        std::ffi::OsStr::new("-c"),
        std::ffi::OsStr::new("exec \"$@\" >/dev/null 2>&1"),
        std::ffi::OsStr::new("sh"),
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
            project,
            &[],
            Some(&ctx.activity),
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("npm could not read the package.json workspaces list: {error}"),
            )
        })?;
    let answer = std::fs::read(&out).map_err(|error| {
        io::Error::new(
            error.kind(),
            "npm could not read the package.json workspaces list: Node exited without an answer",
        )
    })?;
    parse_members(&answer)
}

/// The wrapper's answer: `{"members": [[name, directory], ...]}`, pairs so
/// a member named `__proto__` or `constructor` is a pair like any other, or
/// `{"error": CODE}`. Only a code made of capital letters is shown, so no
/// text from a file npm read reaches the message.
fn parse_members(out: &[u8]) -> io::Result<Vec<(String, String)>> {
    let malformed =
        || io::Error::other("npm's workspace members: the wrapper's answer is malformed");
    let answer: Value = serde_json::from_slice(out).map_err(|_| malformed())?;
    if let Some(code) = answer.get("error") {
        let code = code
            .as_str()
            .filter(|code| (1..=16).contains(&code.len()))
            .filter(|code| code.bytes().all(|byte| byte.is_ascii_uppercase()))
            .unwrap_or("EUNKNOWN");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "npm could not read the package.json workspaces list or a member's package.json \
                 ({code}); ward shows npm's error code only, since npm's message can quote the \
                 file it read"
            ),
        ));
    }
    serde_json::from_value(answer.get("members").cloned().ok_or_else(malformed)?)
        .map_err(|_| malformed())
}

/// ward's rule over the directories npm named: a plain path inside the
/// project with a `package.json` is a member, one a symlink carries out of
/// the project is outside, and one that is not a plain relative path is an
/// error, since a record names files inside the project only. A member
/// inside whose `package.json` is a symlink to a file outside the member's
/// own directory is refused: its manifest is not part of the member.
fn contained(root: &ProjectRoot, named: Vec<(String, String)>) -> io::Result<Found> {
    let mut found = Found::default();
    for (name, dir) in named {
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
            Containment::Inside if own_manifest(root, &path)? => {
                found.members.push(dir.clone());
                found.named.push((name, dir));
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

/// Whether the member directory `dir`, inside the project, has a
/// `package.json`, refusing one that leads outside the directory.
fn own_manifest(root: &ProjectRoot, dir: &Path) -> io::Result<bool> {
    let manifest = dir.join("package.json");
    let refused = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: the workspace member's package.json is a symlink to a file outside the \
                 member's directory; ward reads a member's manifest from the member only",
                manifest.display()
            ),
        )
    };
    match root.input_containment(&manifest)? {
        Containment::Outside => return Err(refused()),
        Containment::Dangling => return Ok(false),
        Containment::Inside => {}
    }
    if !root.is_input_file(&manifest) {
        return Ok(false);
    }
    let real_dir = root.contained_input_path(dir)?;
    let real_manifest = root.contained_input_path(&manifest)?;
    if !real_manifest.starts_with(&real_dir) {
        return Err(refused());
    }
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::testutil::TempDir;

    type Fake = dyn Fn(&Value) -> Vec<(String, String)> + Send + Sync;

    static FAKE: Mutex<Option<(PathBuf, Arc<Fake>)>> = Mutex::new(None);
    static SERIAL: Mutex<()> = Mutex::new(());

    /// While the returned guard lives, a membership run for the project at
    /// `root` answers with `fake`'s directories instead of running npm,
    /// each named by its last component as npm names a member whose
    /// package.json has no name, and the first answers kept so far are
    /// dropped. Tests that read npm's members hold one.
    pub(crate) fn fake_npm(
        root: &Path,
        fake: impl Fn(&Value) -> Vec<String> + Send + Sync + 'static,
    ) -> impl Drop {
        fake_npm_named(root, move |workspaces| {
            fake(workspaces)
                .into_iter()
                .map(|dir| (dir.rsplit('/').next().unwrap_or(&dir).to_string(), dir))
                .collect()
        })
    }

    /// [`fake_npm`] with npm's `[name, directory]` pairs given in full.
    pub(crate) fn fake_npm_named(
        root: &Path,
        fake: impl Fn(&Value) -> Vec<(String, String)> + Send + Sync + 'static,
    ) -> impl Drop {
        struct Reset(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
        impl Drop for Reset {
            fn drop(&mut self) {
                *FAKE.lock().unwrap_or_else(|p| p.into_inner()) = None;
                FIRST.lock().unwrap_or_else(|p| p.into_inner()).clear();
            }
        }
        let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        FIRST.lock().unwrap_or_else(|p| p.into_inner()).clear();
        *FAKE.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((root.to_path_buf(), Arc::new(fake)));
        Reset(serial)
    }

    pub(super) fn named_for_test(
        root: &ProjectRoot,
        workspaces: &Value,
    ) -> Option<io::Result<Vec<(String, String)>>> {
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

    /// A member named `__proto__` is a pair like any other (#694).
    #[test]
    fn a_member_named_like_an_object_property_is_kept() {
        let named = parse_members(
            br#"{"members":[["__proto__","packages/proto"],["constructor","packages/c"]]}"#,
        )
        .unwrap();
        let pair = |name: &str, dir: &str| (name.to_string(), dir.to_string());
        assert_eq!(
            named,
            [
                pair("__proto__", "packages/proto"),
                pair("constructor", "packages/c")
            ]
        );
    }

    /// The wrapper's error is a code, and only a code made of capital
    /// letters is shown: anything else, such as text a confused wrapper
    /// copied from a file, becomes `EUNKNOWN` (#694).
    #[test]
    fn an_npm_error_shows_its_code_only() {
        let error = parse_members(br#"{"error":"EJSONPARSE"}"#).unwrap_err();
        assert!(error.to_string().contains("(EJSONPARSE)"), "{error}");
        for answer in [
            r#"{"error":"token=SECRET-MARKER-123"}"#,
            r#"{"error":{"message":"SECRET-MARKER-123"}}"#,
        ] {
            let error = parse_members(answer.as_bytes()).unwrap_err().to_string();
            assert!(error.contains("(EUNKNOWN)"), "{error}");
            assert!(!error.contains("SECRET"), "{error}");
        }
        let error = parse_members(b"SECRET-MARKER-123").unwrap_err().to_string();
        assert!(!error.contains("SECRET"), "{error}");
    }

    /// A member renamed while the command ran (its package.json `name`
    /// changed, the directory the same) is a changed member set: the lock's
    /// `node_modules/<name>` link would be the old one (#694).
    #[test]
    fn a_member_renamed_while_the_command_runs_is_refused() {
        let scratch = TempDir::named("npm-members-renamed");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(root.join("packages/lib")).unwrap();
        std::fs::write(root.join("packages/lib/package.json"), "{}").unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let _fake = fake_npm_named(&root, move |_| {
            let call = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let name = if call == 0 { "a" } else { "b" };
            vec![(name.to_string(), "packages/lib".to_string())]
        });
        let list = serde_json::json!(["packages/*"]);
        let first = npm_members(&held, &list).unwrap();
        assert_eq!(first.named, [("a".to_string(), "packages/lib".to_string())]);
        let error = npm_members(&held, &list).unwrap_err().to_string();
        assert!(
            error.contains("changed while the command ran") && error.contains("\"b\""),
            "{error}"
        );
    }

    /// A member whose package.json is a symlink out of its own directory is
    /// refused, whether the file is outside the project or elsewhere in it;
    /// one pointing further down its own directory is kept (#694).
    #[test]
    fn a_member_whose_manifest_leads_out_of_it_is_refused() {
        let scratch = TempDir::named("npm-members-manifest");
        let root = scratch.0.join("project");
        for dir in ["packages/out", "packages/side", "packages/down/real"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(scratch.0.join("secret.txt"), "{}").unwrap();
        std::fs::write(root.join("shared.json"), "{}").unwrap();
        std::fs::write(root.join("packages/down/real/package.json"), "{}").unwrap();
        let link = std::os::unix::fs::symlink;
        link(
            "../../../secret.txt",
            root.join("packages/out/package.json"),
        )
        .unwrap();
        link("../../shared.json", root.join("packages/side/package.json")).unwrap();
        link("real/package.json", root.join("packages/down/package.json")).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        for dir in ["packages/out", "packages/side"] {
            let _fake = fake_npm(&root, move |_| vec![dir.to_string()]);
            let error = npm_members(&held, &serde_json::json!(["packages/*"]))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("outside the member's directory"),
                "{dir}: {error}"
            );
        }
        let _fake = fake_npm(&root, |_| vec!["packages/down".to_string()]);
        let found = npm_members(&held, &serde_json::json!(["packages/*"])).unwrap();
        assert_eq!(found.members, ["packages/down"]);
    }

    /// A member added during a sync, after the freshness check read the
    /// members, refuses the resolution record's later question instead of
    /// answering the old set (#694).
    #[test]
    fn a_member_added_while_the_command_runs_is_refused() {
        let scratch = TempDir::named("npm-members-drift");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let member = |dir: &str| {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("package.json"), "{}").unwrap();
        };
        member("packages/a");
        let held = ProjectRoot::open(&root).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let listed = root.clone();
        // npm's answer is the tree as it is: every member directory there.
        let _fake = fake_npm(&root, move |_| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ["packages/a", "packages/b"]
                .into_iter()
                .filter(|dir| listed.join(dir).is_dir())
                .map(String::from)
                .collect()
        });
        // The freshness check reads the members, then the sync downloads.
        let resolve = super::super::resolve::npm_manifest_members;
        assert_eq!(resolve(&held).unwrap(), ["packages/a"]);
        member("packages/b");
        // The closure's resolution record asks again before publishing.
        let error = super::super::resolve::resolution_outputs(&held)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("changed while the command ran") && error.contains("packages/b"),
            "{error}"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "npm ran each time"
        );
        // Another list is another question, with its own first answer.
        assert!(npm_members(&held, &serde_json::json!(["packages/a"])).is_ok());
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
            let first = npm_members(&held, &case["workspaces"]);
            // npm's answer for an unchanged tree is the same pairs in the
            // same order every time: the drift check refuses a reorder.
            let again = npm_members(&held, &case["workspaces"]);
            if let (Ok(first), Ok(again)) = (&first, &again) {
                if first != again {
                    failures.push(format!("{name}: two runs differ: {first:?}, {again:?}"));
                }
            } else if let Err(error) = &again {
                if first.is_ok() {
                    failures.push(format!("{name}: second run refused: {error}"));
                }
            }
            let found = first
                .map(|found| found.members)
                .map_err(|error| error.to_string());
            let expected = Ok(strings(&case["expected"]));
            if found != expected {
                failures.push(format!("{name}: ward {found:?}, npm {expected:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The sandboxed npm sees what unconfined npm sees, with no walk of
    /// ward's own to miss anything (#694): a member through a symlink out
    /// of the project is reported outside, and so is one behind a second
    /// link out of the first target, one 25 directories down, and one a
    /// `!!` pattern names; a symlink out that no pattern matches is not
    /// reported; an unreadable directory npm never needs does not stop it;
    /// and a member named `__proto__` is kept.
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_member_symlinked_out_of_the_project_is_reported_and_an_unnamed_one_is_not() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        if !crate::kernel::sandbox::linux_ready("npm_members_outside") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        let scratch = TempDir::named("npm-ws-outside");
        let root = scratch.0.join("project");
        let deep = format!("packages/{}", ["d"; 25].join("/"));
        let manifest = |dir: &Path, name: &str| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("package.json"), format!("{{\"name\":\"{name}\"}}")).unwrap();
        };
        manifest(&root.join("packages/a"), "a");
        manifest(&root.join("packages/proto"), "__proto__");
        manifest(&root.join("lit"), "lit");
        for name in ["ext", "z", "two", "bang", "far"] {
            manifest(&scratch.0.join("elsewhere").join(name), name);
        }
        std::fs::create_dir_all(scratch.0.join("elsewhere/one")).unwrap();
        symlink("../two", scratch.0.join("elsewhere/one/member")).unwrap();
        symlink("../../elsewhere/ext", root.join("packages/ext")).unwrap();
        symlink("../../elsewhere/z", root.join("packages/z")).unwrap();
        symlink("../../elsewhere/one", root.join("packages/chain")).unwrap();
        symlink("../elsewhere/bang", root.join("bang")).unwrap();
        std::fs::create_dir_all(root.join(&deep)).unwrap();
        symlink(
            scratch.0.join("elsewhere/far"),
            root.join(&deep).join("ext"),
        )
        .unwrap();
        let private = root.join("lit/private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let found = npm_members(
            &held,
            &serde_json::json!([
                "packages/a*",
                "packages/e*",
                "packages/p*",
                "packages/chain/*",
                "packages/**/ext",
                "!!bang",
                "lit"
            ]),
        );
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        let found = found.unwrap();
        assert_eq!(found.members, ["lit", "packages/a", "packages/proto"]);
        let mut outside = vec![
            "bang".to_string(),
            "packages/chain/member".to_string(),
            format!("{deep}/ext"),
            "packages/ext".to_string(),
        ];
        outside.sort();
        assert_eq!(found.outside, outside);
    }

    /// npm never reads a tree other than the one ward holds: a project
    /// renamed after it was opened, with its old path pointed at another
    /// tree, is refused, since the sandbox binds the held directory at the
    /// path it was opened at and will not mount over a symlink (#694).
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_project_whose_path_is_swapped_is_refused_not_read_elsewhere() {
        if !crate::kernel::sandbox::linux_ready("npm_members_swapped") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        let scratch = TempDir::named("npm-ws-swapped");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(root.join("packages/a")).unwrap();
        std::fs::write(root.join("packages/a/package.json"), r#"{"name":"a"}"#).unwrap();
        std::fs::create_dir_all(scratch.0.join("decoy/packages/other")).unwrap();
        std::fs::write(
            scratch.0.join("decoy/packages/other/package.json"),
            r#"{"name":"other"}"#,
        )
        .unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        std::fs::rename(&root, scratch.0.join("moved")).unwrap();
        std::os::unix::fs::symlink("decoy", &root).unwrap();
        let error = npm_members(&held, &serde_json::json!(["packages/*"]))
            .expect_err("npm read the tree the old path now leads to");
        assert!(error.to_string().contains("symlink"), "{error}");
    }

    /// A member's package.json symlinked to a host file is never quoted:
    /// not by npm's parse error, which names the file's text, not in the
    /// error ward returns, and not on ward's stdout or stderr, which this
    /// test points at a file for the run. A host file that parses is
    /// refused by ward's own rule without its contents either (#694).
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_member_manifest_linked_to_a_host_file_is_never_quoted() {
        use std::os::fd::AsRawFd;
        if !crate::kernel::sandbox::linux_ready("npm_members_marker") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        const MARKER: &str = "SECRET-MARKER-5f1c";
        for (secret, expected) in [
            (format!("token={MARKER} not json"), "(EJSONPARSE)"),
            (
                format!("{{\"name\":\"{MARKER}\"}}"),
                "outside the member's directory",
            ),
        ] {
            let scratch = TempDir::named("npm-ws-marker");
            let root = scratch.0.join("project");
            std::fs::create_dir_all(root.join("packages/leak")).unwrap();
            std::fs::create_dir_all(root.join("packages/ok")).unwrap();
            std::fs::write(root.join("packages/ok/package.json"), r#"{"name":"ok"}"#).unwrap();
            std::fs::write(scratch.0.join("secret.txt"), &secret).unwrap();
            std::os::unix::fs::symlink(
                "../../../secret.txt",
                root.join("packages/leak/package.json"),
            )
            .unwrap();
            let held = ProjectRoot::open(&root).unwrap();
            let captured = std::fs::File::create(scratch.0.join("captured")).unwrap();
            // SAFETY: dup and dup2 on this process's own standard
            // descriptors; both are restored before the test reads them.
            let saved = unsafe { [libc::dup(1), libc::dup(2)] };
            unsafe {
                libc::dup2(captured.as_raw_fd(), 1);
                libc::dup2(captured.as_raw_fd(), 2);
            }
            let result = npm_members(&held, &serde_json::json!(["packages/*"]));
            // A probe through the same descriptor shows the capture works.
            unsafe { libc::write(2, b"capture-probe\n".as_ptr().cast(), 14) };
            unsafe {
                libc::dup2(saved[0], 1);
                libc::dup2(saved[1], 2);
                libc::close(saved[0]);
                libc::close(saved[1]);
            }
            let error = result.expect_err("a member's manifest out of it was accepted");
            let error = error.to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains(MARKER), "{error}");
            let printed = std::fs::read_to_string(scratch.0.join("captured")).unwrap();
            assert!(printed.contains("capture-probe"), "nothing was captured");
            assert!(!printed.contains(MARKER), "printed: {printed}");
        }
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
        FIRST.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}
