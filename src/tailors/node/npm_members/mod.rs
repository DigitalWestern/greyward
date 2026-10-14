//! npm's workspace member set, read by npm itself. A `workspaces` value is
//! handed to the `@npmcli/map-workspaces` bundled with the npm of the
//! project's selected Node, run by that Node in the network-denied sandbox
//! with the whole host read-only (`HostView::WholeHost`) and the project
//! bound from the descriptor ward holds. Whatever globs, braces, extglobs,
//! negations and symlink rules npm applies are then npm's own, and npm sees
//! every directory an unconfined run would, so ward's member set cannot
//! drift from the one `npm ci` builds from.
//!
//! npm's answer is untrusted input: npm sees the whole host, so anything it
//! returns can carry host data. ward keeps none of it unchecked. Each
//! directory npm names must be a plain path inside the project, and ward
//! reads that member's `package.json` itself, beneath the member's own
//! directory through the held descriptor
//! ([`ProjectRoot::read_member_manifest`]); the member's name is ward's
//! reading of those bytes, and npm's must agree. Every way this can fail
//! (an npm error of any kind, a malformed answer, a directory or manifest
//! outside the project, a name that disagrees) is one refusal with one
//! fixed message, which names only the project and its own declared
//! patterns, so no failure tells one host file from another. The reason
//! is shown only when [`DEBUG_ENV`] is set, and it can quote host files.
//!
//! Nothing is cached: every question runs npm again, so the freshness check
//! and the closure's resolution record each see the tree as it is then.
//! The first answer for each project and list is kept only to compare
//! against: a later answer that differs refuses, since members added or
//! removed while a command ran would leave what it publishes uncovered.

use crate::kernel::context::Context;
use crate::kernel::fsroot::{MemberManifest, ProjectRoot};
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

/// npm's members of one `workspaces` list, as ward checked them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Found {
    /// Member directories inside the project, relative to it, sorted.
    pub(crate) members: Vec<String>,
    /// Each member's `[name, directory]` pair, in npm's order. The name is
    /// ward's own reading of the member's `package.json` (npm's agrees):
    /// the `node_modules/<name>` link an npm lock records for the member,
    /// so a renamed member is a changed member set.
    pub(crate) named: Vec<(String, String)>,
}

/// Set to show why npm's workspace members could not be determined. The
/// reason can quote what npm read, which can be any host file the user
/// can read through a symlink in the project.
pub(crate) const DEBUG_ENV: &str = "GREYWARD_DEBUG_NPM_MEMBERS";

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
/// ward cannot accept is [`undetermined`]; one that differs from this
/// process's first one for the same project and list is refused.
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
    let debug = std::env::var_os(DEBUG_ENV).is_some_and(|value| !value.is_empty());
    let found = npm_named(root, workspaces)?
        .and_then(|named| contained(root, named))
        .map_err(|why| undetermined(root, workspaces, &why, debug))?;
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

/// The one refusal for every answer of npm's ward cannot accept. It names
/// the project and the `workspaces` patterns it declares, nothing npm
/// found or read, so two failures that differ in what a host file holds
/// print the same bytes. `why` is shown only with `debug` ([`DEBUG_ENV`]).
fn undetermined(root: &ProjectRoot, workspaces: &Value, why: &str, debug: bool) -> io::Error {
    let mut message = format!(
        "workspace members of {}/package.json could not be determined inside the project \
         (workspaces {workspaces}); set {DEBUG_ENV}=1 to see why, which can print host files",
        root.path().display()
    );
    if debug {
        message.push_str(&format!("; {DEBUG_ENV}: {why}"));
    }
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The refusal for a member set that changed while the command ran. It
/// names directories and names ward checked inside the project.
fn changed(root: &ProjectRoot, earlier: &Found, now: &Found) -> io::Error {
    let added: Vec<&String> = now
        .members
        .iter()
        .filter(|dir| !earlier.members.contains(dir))
        .collect();
    let removed: Vec<&String> = earlier
        .members
        .iter()
        .filter(|dir| !now.members.contains(dir))
        .collect();
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
    io::Error::other(format!(
        "{}: the npm workspace members changed while the command ran (added {added:?}, \
         removed {removed:?}, renamed {renamed:?}, or reordered); nothing was published for \
         the changed set, so run the command again",
        root.path().display()
    ))
}

/// npm's `[name, directory]` pairs, relative to the root, before ward's
/// checks: the provider's Node runs map-workspaces in the sandbox. The
/// outer error is ward's own (no Node, the sandbox failed); the inner one
/// is npm's answer refused, with the reason [`undetermined`] keeps back.
type Answer = Result<Vec<(String, String)>, String>;

fn npm_named(root: &ProjectRoot, workspaces: &Value) -> io::Result<Answer> {
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
    let answer = result?;
    removed?;
    Ok(answer)
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
) -> io::Result<Answer> {
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
    Ok(match std::fs::read(&out) {
        Ok(answer) => parse_members(&answer),
        Err(error) => Err(format!("Node exited without an answer ({error})")),
    })
}

/// The wrapper's answer: `{"members": [[name, directory], ...]}`, pairs so
/// a member named `__proto__` or `constructor` is a pair like any other, or
/// `{"error": CODE}`, refused.
fn parse_members(out: &[u8]) -> Answer {
    let answer: Value =
        serde_json::from_slice(out).map_err(|_| "the wrapper's answer is not JSON".to_string())?;
    if let Some(code) = answer.get("error") {
        return Err(format!("npm failed with {code}"));
    }
    serde_json::from_value(answer.get("members").cloned().unwrap_or(Value::Null))
        .map_err(|_| "the wrapper's answer is not a list of [name, directory] pairs".to_string())
}

/// ward's checks over npm's pairs. A directory must be a plain path inside
/// the project; ward reads its `package.json` beneath the member's own
/// directory and takes the member's name from those bytes, and npm's name
/// must be the same. Any directory or manifest outside the project or the
/// member refuses the whole answer: npm read it from the host.
fn contained(root: &ProjectRoot, named: Vec<(String, String)>) -> Result<Found, String> {
    let mut found = Found::default();
    for (npm_name, dir) in named {
        if dir.is_empty() || dir == "." {
            continue;
        }
        let path = PathBuf::from(&dir);
        let plain = path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
        if !plain {
            return Err(format!(
                "npm named {dir:?}, which is not a plain path in the project"
            ));
        }
        let bytes = match root.read_member_manifest(&path) {
            Ok(MemberManifest::Read(bytes)) => bytes,
            Ok(MemberManifest::Missing) => continue,
            Ok(MemberManifest::Refused) => {
                return Err(format!(
                    "{dir}: the member, or its package.json, leads outside the project or the \
                     member's directory"
                ))
            }
            Err(error) => return Err(format!("{dir}/package.json: {error}")),
        };
        let name = manifest_name(root, &dir, &bytes)?;
        if name != npm_name {
            return Err(format!(
                "{dir}: npm named the member {npm_name:?}, and its package.json names {name:?}"
            ));
        }
        found.members.push(dir.clone());
        found.named.push((name, dir));
    }
    found.members.sort();
    found.members.dedup();
    Ok(found)
}

/// The name npm gives the member at `dir` whose `package.json` holds
/// `bytes`, by npm's rule: its `name` when that is set, otherwise its
/// directory's name, under its scope when the directory above starts with
/// `@` (`@npmcli/name-from-folder`).
fn manifest_name(root: &ProjectRoot, dir: &str, bytes: &[u8]) -> Result<String, String> {
    let manifest: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("{dir}/package.json: {error}"))?;
    let unset = match manifest.get("name") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => true,
        Some(Value::String(name)) if name.is_empty() => true,
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => true,
        Some(Value::String(name)) => return Ok(name.clone()),
        Some(_) => return Err(format!("{dir}/package.json: its name is not a string")),
    };
    debug_assert!(unset);
    let mut parts: Vec<String> = dir.split('/').map(String::from).collect();
    let base = parts.pop().unwrap_or_default();
    let parent = match parts.pop() {
        Some(parent) => parent,
        None => root
            .path()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };
    Ok(if parent.starts_with('@') {
        format!("{parent}/{base}")
    } else {
        base
    })
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
    ) -> Option<io::Result<Answer>> {
        let slot = FAKE.lock().unwrap_or_else(|p| p.into_inner());
        let (at, fake) = slot.as_ref()?;
        let real = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.into());
        (real(at) == real(root.path())).then(|| Ok(Ok(fake(workspaces))))
    }

    /// The one refusal every unacceptable answer gets, for the project at
    /// `root` and the patterns `["packages/*"]`.
    fn refusal(root: &Path) -> String {
        format!(
            "workspace members of {}/package.json could not be determined inside the project \
             (workspaces [\"packages/*\"]); set {DEBUG_ENV}=1 to see why, which can print host \
             files",
            root.display()
        )
    }

    /// ward's checks over what npm returned: a member through a symlink
    /// inside the project is kept, one with no `package.json` or behind a
    /// dangling link is dropped, and one through a symlink out of the
    /// project, or a path above it, leaves the members undetermined, with
    /// no path npm found in the message (#694).
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
        let list = serde_json::json!(["packages/*"]);
        let answer = |dirs: &'static [&'static str]| {
            fake_npm(&root, move |_| {
                dirs.iter().map(|dir| dir.to_string()).collect()
            })
        };
        let _fake = answer(&[
            "packages/a",
            "packages/lib",
            "packages/gone",
            "packages/bare",
        ]);
        let found = npm_members(&held, &list).unwrap();
        assert_eq!(found.members, ["packages/a", "packages/lib"]);
        let pair = |name: &str, dir: &str| (name.to_string(), dir.to_string());
        assert_eq!(
            found.named,
            [pair("a", "packages/a"), pair("lib", "packages/lib")]
        );
        assert_eq!(
            npm_members(&held, &serde_json::json!([])).unwrap(),
            Found::default()
        );
        drop(_fake);
        for dirs in [
            &["packages/a", "packages/ext"][..],
            &["../host-projects/secret-alpha"][..],
        ] {
            let _fake = answer(dirs);
            let error = npm_members(&held, &list).unwrap_err().to_string();
            assert_eq!(error, refusal(&root), "{dirs:?}");
        }
    }

    /// The reason is kept back unless asked for, and then it says what
    /// failed (#694, Sol round 6).
    #[test]
    fn the_reason_is_shown_only_when_asked_for() {
        let scratch = TempDir::named("npm-members-debug");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(&root).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let list = serde_json::json!(["packages/*"]);
        let why = parse_members(br#"{"error":"EJSONPARSE"}"#).unwrap_err();
        assert_eq!(
            undetermined(&held, &list, &why, false).to_string(),
            refusal(&root)
        );
        let shown = undetermined(&held, &list, &why, true).to_string();
        assert!(shown.starts_with(&refusal(&root)), "{shown}");
        assert!(shown.contains("EJSONPARSE"), "{shown}");
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

    /// The name is ward's reading of the member's own package.json, by
    /// npm's rule: `name` when set, else the directory's name, under its
    /// scope; a name npm gives that the manifest does not is refused, so a
    /// name npm read from a host file never reaches a message (#694, Sol
    /// round 6).
    #[test]
    fn a_member_is_named_by_its_own_manifest_as_ward_reads_it() {
        let scratch = TempDir::named("npm-members-names");
        let root = scratch.0.join("project");
        let manifest = |dir: &str, text: &str| {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("package.json"), text).unwrap();
        };
        manifest("packages/named", r#"{"name":"alpha"}"#);
        manifest("packages/plain", "{}");
        manifest("packages/@scope/inner", r#"{"name":""}"#);
        let held = ProjectRoot::open(&root).unwrap();
        let list = serde_json::json!(["packages/*"]);
        let pair = |name: &str, dir: &str| (name.to_string(), dir.to_string());
        let expected = vec![
            pair("alpha", "packages/named"),
            pair("plain", "packages/plain"),
            pair("@scope/inner", "packages/@scope/inner"),
        ];
        let answer = expected.clone();
        let _fake = fake_npm_named(&root, move |_| answer.clone());
        assert_eq!(npm_members(&held, &list).unwrap().named, expected);
        drop(_fake);
        let _fake = fake_npm_named(&root, |_| {
            vec![("SECRET-host-name".to_string(), "packages/named".to_string())]
        });
        let error = npm_members(&held, &list).unwrap_err().to_string();
        assert_eq!(error, refusal(&root));
    }

    /// A member renamed while the command ran (its package.json `name`
    /// changed, the directory the same) is a changed member set: the lock's
    /// `node_modules/<name>` link would be the old one (#694).
    #[test]
    fn a_member_renamed_while_the_command_runs_is_refused() {
        let scratch = TempDir::named("npm-members-renamed");
        let root = scratch.0.join("project");
        let manifest = root.join("packages/lib/package.json");
        std::fs::create_dir_all(root.join("packages/lib")).unwrap();
        std::fs::write(&manifest, r#"{"name":"a"}"#).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let read = manifest.clone();
        let _fake = fake_npm_named(&root, move |_| {
            let text = std::fs::read_to_string(&read).unwrap();
            let name = serde_json::from_str::<Value>(&text).unwrap()["name"]
                .as_str()
                .unwrap()
                .to_string();
            vec![(name, "packages/lib".to_string())]
        });
        let list = serde_json::json!(["packages/*"]);
        let first = npm_members(&held, &list).unwrap();
        assert_eq!(first.named, [("a".to_string(), "packages/lib".to_string())]);
        std::fs::write(&manifest, r#"{"name":"b"}"#).unwrap();
        let error = npm_members(&held, &list).unwrap_err().to_string();
        assert!(
            error.contains("changed while the command ran") && error.contains("\"b\""),
            "{error}"
        );
    }

    /// A member whose package.json is a symlink out of its own directory
    /// leaves the members undetermined, whether the file is outside the
    /// project or elsewhere in it; one pointing further down its own
    /// directory is kept (#694).
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
            assert_eq!(error, refusal(&root), "{dir}");
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
    /// ward's own to miss anything (#694): a member 25 directories down, a
    /// member named `__proto__` and a `!!` pattern are npm's; a symlink out
    /// of the project that no pattern matches changes nothing; an
    /// unreadable directory npm never needs does not stop it. A member
    /// through a symlink out of the project, directly, behind a second link
    /// out of the first target, deep down, or named by `!!`, leaves the
    /// members undetermined with the one fixed refusal.
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_member_symlinked_out_of_the_project_leaves_the_members_undetermined() {
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
        manifest(&root.join(&deep).join("in"), "in");
        manifest(&root.join("lit"), "lit");
        manifest(&root.join("bang"), "bang");
        for name in ["ext", "z", "two", "bang", "far"] {
            manifest(&scratch.0.join("elsewhere").join(name), name);
        }
        std::fs::create_dir_all(scratch.0.join("elsewhere/one")).unwrap();
        symlink("../two", scratch.0.join("elsewhere/one/member")).unwrap();
        symlink("../../elsewhere/z", root.join("packages/z")).unwrap();
        let private = root.join("lit/private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let list = serde_json::json!([
            "packages/a*",
            "packages/p*",
            "packages/**/in",
            "!!bang",
            "lit"
        ]);
        let found = npm_members(&held, &list);
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            found.unwrap().members,
            [
                "bang",
                "lit",
                "packages/a",
                &format!("{deep}/in"),
                "packages/proto"
            ]
        );
        let outside: [(&str, std::path::PathBuf, serde_json::Value); 4] = [
            (
                "../../elsewhere/ext",
                root.join("packages/ext"),
                serde_json::json!(["packages/e*"]),
            ),
            (
                "../../elsewhere/one",
                root.join("packages/chain"),
                serde_json::json!(["packages/chain/*"]),
            ),
            (
                "../elsewhere/bang",
                root.join("bang2"),
                serde_json::json!(["!!bang2"]),
            ),
            (
                "far",
                root.join(&deep).join("ext"),
                serde_json::json!(["packages/**/ext"]),
            ),
        ];
        for (text, at, list) in outside {
            let text = if text == "far" {
                scratch.0.join("elsewhere/far")
            } else {
                text.into()
            };
            symlink(&text, &at).unwrap();
            let error = npm_members(&held, &list).unwrap_err().to_string();
            assert_eq!(
                error,
                format!(
                    "workspace members of {}/package.json could not be determined inside the \
                     project (workspaces {list}); set {DEBUG_ENV}=1 to see why, which can print \
                     host files",
                    root.display()
                ),
                "{list}"
            );
            std::fs::remove_file(&at).unwrap();
        }
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

    /// `npm_members` with this process's stdout and stderr pointed at a
    /// file, and what was written there. A probe written through the same
    /// descriptors shows the capture worked.
    fn captured(held: &ProjectRoot, list: &Value, file: &Path) -> (io::Result<Found>, String) {
        use std::os::fd::AsRawFd;
        let capture = std::fs::File::create(file).unwrap();
        // SAFETY: dup and dup2 on this process's own standard descriptors;
        // both are restored before the file is read.
        let saved = unsafe { [libc::dup(1), libc::dup(2)] };
        unsafe {
            libc::dup2(capture.as_raw_fd(), 1);
            libc::dup2(capture.as_raw_fd(), 2);
        }
        let result = npm_members(held, list);
        unsafe {
            libc::write(2, b"capture-probe\n".as_ptr().cast(), 14);
            libc::dup2(saved[0], 1);
            libc::dup2(saved[1], 2);
            libc::close(saved[0]);
            libc::close(saved[1]);
        }
        let printed = std::fs::read_to_string(file).unwrap();
        assert!(printed.contains("capture-probe"), "nothing was captured");
        (result, printed.replace("capture-probe\n", ""))
    }

    /// A member's package.json symlinked to a host file is never quoted, and
    /// what the file holds cannot be told from the outcome (#694, Sol round
    /// 6). Four host files behind the same symlink: one that is not JSON
    /// (npm's parse error), one whose `name` matches another member's
    /// (npm's duplicate-name error), one with another name (ward's own
    /// refusal), and one with no name. Each gives the same bytes: the same
    /// error message and nothing printed.
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_member_manifest_linked_to_a_host_file_is_never_quoted() {
        if !crate::kernel::sandbox::linux_ready("npm_members_marker") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        const MARKER: &str = "SECRET-MARKER-5f1c";
        let scratch = TempDir::named("npm-ws-marker");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(root.join("packages/leak")).unwrap();
        std::fs::create_dir_all(root.join("packages/guess")).unwrap();
        std::fs::write(
            root.join("packages/guess/package.json"),
            format!("{{\"name\":\"{MARKER}\"}}"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../../../secret.json",
            root.join("packages/leak/package.json"),
        )
        .unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let list = serde_json::json!(["packages/*"]);
        let mut outcomes = Vec::new();
        for secret in [
            format!("token={MARKER} not json"),
            format!("{{\"name\":\"{MARKER}\"}}"),
            format!("{{\"name\":\"other-{MARKER}\"}}"),
            "{}".to_string(),
        ] {
            std::fs::write(scratch.0.join("secret.json"), &secret).unwrap();
            let (result, printed) = captured(&held, &list, &scratch.0.join("captured"));
            let error = result.expect_err("a manifest out of the project was accepted");
            outcomes.push((error.to_string(), printed));
        }
        let expected = format!(
            "workspace members of {}/package.json could not be determined inside the project \
             (workspaces [\"packages/*\"]); set {DEBUG_ENV}=1 to see why, which can print host \
             files",
            root.display()
        );
        for (index, (error, printed)) in outcomes.iter().enumerate() {
            assert_eq!(error, &expected, "case {index}");
            assert_eq!(printed, "", "case {index}");
        }
    }

    /// A pattern that climbs out of the project (`../host-projects/*`)
    /// leaves the members undetermined, and the message holds the declared
    /// pattern only, never a directory npm found there (#694, Sol round 6).
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_pattern_out_of_the_project_names_nothing_npm_found() {
        if !crate::kernel::sandbox::linux_ready("npm_members_climb") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        let scratch = TempDir::named("npm-ws-climb");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(&root).unwrap();
        for name in ["secret-alpha", "secret-beta"] {
            let dir = scratch.0.join("host-projects").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("package.json"), format!("{{\"name\":\"{name}\"}}")).unwrap();
        }
        let held = ProjectRoot::open(&root).unwrap();
        let list = serde_json::json!(["../host-projects/*"]);
        let (result, printed) = captured(&held, &list, &scratch.0.join("captured"));
        let error = result.unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "workspace members of {}/package.json could not be determined inside the \
                 project (workspaces [\"../host-projects/*\"]); set {DEBUG_ENV}=1 to see why, \
                 which can print host files",
                root.display()
            )
        );
        assert!(!error.contains("secret"), "{error}");
        assert_eq!(printed, "");
    }

    /// A member whose `name` is an object nested so deep that writing npm's
    /// answer throws gets the same fixed refusal as one nested a level
    /// deep: an exception in the wrapper's success path is a fixed code
    /// too, never Node exiting with an error of its own (#694, Sol round 7).
    #[test]
    #[ignore = "realizes the store Node and runs it in the Linux sandbox"]
    fn a_member_name_too_deep_to_write_gets_the_fixed_refusal() {
        if !crate::kernel::sandbox::linux_ready("npm_members_deep") {
            return;
        }
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        install_shipped_node();
        let scratch = TempDir::named("npm-ws-deep");
        let root = scratch.0.join("project");
        std::fs::create_dir_all(root.join("packages/member")).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let list = serde_json::json!(["packages/*"]);
        let mut errors = Vec::new();
        for depth in [1, 50_000] {
            let name = format!("{}1{}", r#"{"a":"#.repeat(depth), "}".repeat(depth));
            std::fs::write(
                root.join("packages/member/package.json"),
                format!(r#"{{"name":{name}}}"#),
            )
            .unwrap();
            errors.push(npm_members(&held, &list).unwrap_err().to_string());
        }
        assert_eq!(errors[0], refusal(&root));
        assert_eq!(errors[1], refusal(&root));
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
