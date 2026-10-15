//! Git dependencies realized by commit. The fixture repositories are local
//! and served over `file://`. The npm and Python cases also realize the
//! pinned Node or CPython toolchain, which needs the network, so they are
//! ignored by default; the rest run offline on every PR.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use greyward::kernel::gitsrc::{ensure_git_source, normalize_url, GitSource};
use greyward::kernel::platform::Platform;
use greyward::kernel::policy;
use greyward::kernel::store::Store;
use greyward::tailors::node::{self, NpmPackage};
use std::path::Path;
use std::process::Command;

mod common;

use common::TempDir;

fn git(args: &[&str], cwd: &Path) -> String {
    let out = Command::new("/usr/bin/git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository holding one npm package, plus a `prepare` script so the
/// exception path is exercised too.
fn fixture_repo(root: &Path) -> (String, String) {
    let repo = root.join("dep-repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    std::fs::write(
        repo.join("package.json"),
        r#"{"name":"git-dep","version":"1.0.0","main":"index.js","scripts":{"prepare":"exit 1"}}"#,
    )
    .unwrap();
    std::fs::write(repo.join("index.js"), "module.exports = 'from-git';\n").unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "one"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("git+file://{}", repo.display()), commit)
}

fn store_at(root: &Path) -> Store {
    Store::open_at(&root.join("store")).unwrap()
}

/// Runs `realize` with the store's `tmp` read-only. A cache hit answers
/// from the published object and never stages; a rebuild stages under
/// `store/tmp` first, and with it read-only that fails instead of
/// quietly re-publishing the same content-addressed object. (Equal paths
/// or ids cannot tell those two apart.)
fn without_staging<T>(store: &Store, realize: impl FnOnce() -> T) -> T {
    use std::os::unix::fs::PermissionsExt;
    let tmp = store.root.join("tmp");
    let writable = std::fs::metadata(&tmp).unwrap().permissions();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = realize();
    std::fs::set_permissions(&tmp, writable).unwrap();
    result
}

/// One case at a time: policy attribution is process-global, and realizing
/// a source runs the version-control binary under supervision, which takes
/// one child per process and refuses a second rather than queue it.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
#[ignore]
fn npm_git_dependency_is_realized_from_its_commit() {
    let _serial = serial();
    let platform = Platform::host().expect("host platform");
    let root = TempDir::new("gitdep-npm");
    let (url, commit) = fixture_repo(&root.0);
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let attribution = policy::Attribution::open("node").expect("test attribution");

    let lock = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/git-dep":{{"version":"1.0.0","resolved":"{url}#{commit}"}}}}}}"#
    );
    let plan = node::plan_npm(platform, &lock).expect("plan");
    assert_eq!(plan.packages.len(), 1);
    let package: &NpmPackage = &plan.packages[0];
    let source = package
        .git
        .as_ref()
        .expect("git source parsed from the lockfile");
    assert_eq!(source.commit, commit);
    assert_eq!(package.integrity, format!("git:{commit}"));

    let env = node::realize_node_env(&store, activity, platform, &plan, &[]).expect("realize");
    assert_eq!(
        std::fs::read_to_string(env.join("node_modules/git-dep/index.js")).unwrap(),
        "module.exports = 'from-git';\n"
    );
    // The repository's own .git must never reach the environment.
    assert!(!env.join("node_modules/git-dep/.git").exists());

    // The commit is the identity: the same plan hits the cache, which is
    // to say the environment is answered without being staged again.
    let again = without_staging(&store, || {
        node::realize_node_env(&store, activity, platform, &plan, &[])
    })
    .expect("second realize was not a cache hit");
    assert_eq!(env, again);

    let kinds: Vec<String> = attribution
        .recorded()
        .iter()
        .map(|exception| exception.kind.clone())
        .collect();
    assert!(
        kinds.iter().filter(|k| *k == "git-dependency").count() >= 2,
        "expected the source and its unrun prepare script to be recorded: {kinds:?}"
    );
    // No closure is written here, so the frame is discarded, not finished.
    attribution.discard();
}

/// The git fetch happens only on a cold realization, so what it records is
/// stored with the environment and replayed from there: a warm sync never
/// reaches `fetch_plan_sources`, and a stricter policy must still refuse
/// the object. Cold under the default policy, then warm under one denying
/// `git-dependency`: the planner has already run, so only the object's own
/// record can refuse it.
#[test]
#[ignore]
fn a_warm_npm_git_environment_replays_its_fetch_exceptions() {
    let _serial = serial();
    let platform = Platform::host().expect("host platform");
    let root = TempDir::new("gitdep-npm-warm");
    let (url, commit) = fixture_repo(&root.0);
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let lock = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/git-dep":{{"version":"1.0.0","resolved":"{url}#{commit}"}}}}}}"#
    );

    let attribution = policy::Attribution::open("node").expect("test attribution");
    let plan = node::plan_npm(platform, &lock).expect("plan");
    let env = node::realize_node_env(&store, activity, platform, &plan, &[]).expect("cold");
    attribution.discard();

    // The fetch's record is the object's: it is in the store's metadata.
    let id = env.file_name().unwrap().to_str().unwrap();
    let record = greyward::kernel::objmeta::read_store_record(&store, id).unwrap();
    assert!(
        record
            .exceptions
            .iter()
            .any(|e| e.kind == policy::GIT_DEPENDENCY),
        "the cold realization stored no git-dependency: {:?}",
        record.exceptions
    );

    let _deny = policy::PolicyScope::install(policy::Policy {
        deny: [policy::GIT_DEPENDENCY.to_string()].into(),
        ..Default::default()
    });
    let attribution = policy::Attribution::open("node").expect("test attribution");
    let error = without_staging(&store, || {
        node::realize_node_env(&store, activity, platform, &plan, &[])
    })
    .expect_err("a warm environment dropped its git-dependency exception");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    assert!(error.to_string().contains("git-dependency"), "{error}");
    attribution.discard();
}

/// The transport is a fetch-time record like `git-dependency`: a
/// `file://` git dependency realized cold under the default policy stores
/// `host-git-transport` with the environment, and a warm sync under a
/// policy denying only that kind refuses the cached object.
#[test]
#[ignore]
fn a_warm_npm_git_environment_replays_its_host_git_transport() {
    let _serial = serial();
    let platform = Platform::host().expect("host platform");
    let root = TempDir::new("gitdep-npm-warm-transport");
    let (url, commit) = fixture_repo(&root.0);
    assert!(url.starts_with("git+file://"), "{url}");
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let lock = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/git-dep":{{"version":"1.0.0","resolved":"{url}#{commit}"}}}}}}"#
    );

    let attribution = policy::Attribution::open("node").expect("test attribution");
    let plan = node::plan_npm(platform, &lock).expect("plan");
    let env = node::realize_node_env(&store, activity, platform, &plan, &[]).expect("cold");
    attribution.discard();

    let id = env.file_name().unwrap().to_str().unwrap();
    let record = greyward::kernel::objmeta::read_store_record(&store, id).unwrap();
    assert!(
        record
            .exceptions
            .iter()
            .any(|e| e.kind == policy::HOST_GIT_TRANSPORT),
        "the cold realization stored no host-git-transport: {:?}",
        record.exceptions
    );

    let _deny = policy::PolicyScope::install(policy::Policy {
        deny: [policy::HOST_GIT_TRANSPORT.to_string()].into(),
        ..Default::default()
    });
    let attribution = policy::Attribution::open("node").expect("test attribution");
    let error = without_staging(&store, || {
        node::realize_node_env(&store, activity, platform, &plan, &[])
    })
    .expect_err("a warm environment dropped its host-git-transport exception");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    assert!(
        error.to_string().contains(policy::HOST_GIT_TRANSPORT),
        "{error}"
    );
    // The cached environment's own record refused it, not a cold fetch
    // that a cache miss would have run.
    assert!(
        error.to_string().contains(&format!("cached object {id}")),
        "{error}"
    );
    attribution.discard();
}

#[test]
fn an_unpinned_git_reference_is_refused() {
    let platform = Platform::host().expect("host platform");
    let root = TempDir::new("gitdep-unpinned");
    let (url, _) = fixture_repo(&root.0);
    let lock = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/git-dep":{{"version":"1.0.0","resolved":"{url}#main"}}}}}}"#
    );
    let error = node::plan_npm(platform, &lock)
        .expect_err("an unpinned ref must be refused")
        .to_string();
    assert!(
        error.contains("npm_git_dep: git-dep:") && error.contains("commit main;"),
        "an unpinned ref must be refused by name, got: {error:?}"
    );
}

/// Build a parent repository with a relative file submodule. The parent has
/// no usable submodule checkout until the realizing code records `origin`;
/// Git otherwise resolves `../subrepo` relative to its temporary worktree.
fn relative_submodule_fixture(root: &Path, transformed: bool) -> (String, String) {
    let subrepo_name = if transformed {
        "subrepo-transformed"
    } else {
        "subrepo"
    };
    let subrepo = root.join(subrepo_name);
    std::fs::create_dir_all(&subrepo).unwrap();
    git(&["init", "-q", "-b", "main"], &subrepo);
    git(&["config", "user.email", "t@example.invalid"], &subrepo);
    git(&["config", "user.name", "t"], &subrepo);
    if transformed {
        std::fs::write(subrepo.join(".gitattributes"), "*.txt text eol=crlf\n").unwrap();
    }
    std::fs::write(subrepo.join("sub.txt"), "submodule\n").unwrap();
    git(&["add", "-A"], &subrepo);
    git(&["commit", "-qm", "sub"], &subrepo);
    let sub_commit = git(&["rev-parse", "HEAD"], &subrepo);

    let parent = root.join(if transformed {
        "parent-transformed"
    } else {
        "parent"
    });
    std::fs::create_dir_all(&parent).unwrap();
    git(&["init", "-q", "-b", "main"], &parent);
    git(&["config", "user.email", "t@example.invalid"], &parent);
    git(&["config", "user.name", "t"], &parent);
    std::fs::write(
        parent.join(".gitmodules"),
        format!("[submodule \"sub\"]\n\tpath = sub\n\turl = ../{subrepo_name}\n"),
    )
    .unwrap();
    git(&["add", ".gitmodules"], &parent);
    let gitlink = format!("160000,{sub_commit},sub");
    git(&["update-index", "--add", "--cacheinfo", &gitlink], &parent);
    git(&["commit", "-qm", "parent"], &parent);
    let parent_commit = git(&["rev-parse", "HEAD"], &parent);
    (format!("file://{}", parent.display()), parent_commit)
}

#[test]
fn git_relative_submodule_is_pinned_and_raw() {
    let _serial = serial();
    let root = TempDir::new("gitdep-submodule");
    let (url, commit) = relative_submodule_fixture(&root.0, false);
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let source = GitSource {
        url: normalize_url(&url),
        commit,
        subdirectory: None,
    };
    // The file submodule records host-git-transport, into the sync's
    // attribution, before it is fetched.
    let attribution = policy::Attribution::open("node").expect("test attribution");
    let object = ensure_git_source(&store, activity, &source).expect("realize relative submodule");
    let recorded = attribution.recorded();
    attribution.discard();
    assert_eq!(
        std::fs::read_to_string(object.join("sub/sub.txt")).unwrap(),
        "submodule\n"
    );
    assert!(!object.join("sub/.git").exists());
    let subrepo = std::fs::canonicalize(&root.0).unwrap().join("subrepo");
    assert!(
        recorded
            .iter()
            .any(|exception| exception.kind == policy::HOST_GIT_TRANSPORT
                && Path::new(exception.subject.trim_start_matches("file://"))
                    .canonicalize()
                    .ok()
                    .as_deref()
                    == Some(subrepo.as_path())),
        "{recorded:?}"
    );

    let (url, commit) = relative_submodule_fixture(&root.0, true);
    let transformed = GitSource {
        url: normalize_url(&url),
        commit,
        subdirectory: None,
    };
    let attribution = policy::Attribution::open("node").expect("test attribution");
    let error = ensure_git_source(&store, activity, &transformed)
        .expect_err("attribute-transformed submodule must be rejected")
        .to_string();
    attribution.discard();
    assert!(error.contains("transformed"), "{error}");
}

/// A minimal installable Python package in a local repository.
fn python_fixture_repo(root: &Path) -> (String, String) {
    let repo = root.join("py-repo");
    std::fs::create_dir_all(repo.join("gitdep")).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    std::fs::write(
        repo.join("pyproject.toml"),
        "[build-system]\nrequires = [\"setuptools>=40.8.0\", \"wheel\"]\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"gitdep\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("gitdep/__init__.py"),
        "VALUE = 'from-git-python'\n",
    )
    .unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "one"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("git+file://{}", repo.display()), commit)
}

#[test]
#[ignore]
fn python_git_dependency_builds_a_wheel_from_its_commit() {
    let _serial = serial();
    let platform = Platform::host().expect("host platform");
    let root = TempDir::new("gitdep-py");
    let (url, commit) = python_fixture_repo(&root.0);
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let mut attribution = policy::Attribution::open("python").expect("test attribution");

    let requirement = format!("gitdep @ {url}@{commit}");
    let reqs = greyward::tailors::python::pypi::parse_requirements(&requirement).expect("parse");
    let packages = greyward::tailors::python::pypi::lock_requirements(
        platform,
        greyward::tailors::python::pypi::Glibc(0, 0),
        &reqs,
        "cp312",
    )
    .expect("lock");
    assert_eq!(packages.len(), 1);
    assert!(
        packages[0].git.is_some(),
        "the package carries its git source"
    );

    let plan = greyward::kernel::types::Plan {
        ecosystem: "python".into(),
        python_version: "3.12.14".into(),
        packages,
    };
    let env = greyward::tailors::python::env::realize_env(
        &mut greyward::kernel::resolve::ResolutionDoor::open(
            &store,
            activity,
            platform,
            greyward::kernel::resolve::DoorKind::Planner,
            &mut attribution,
        )
        .unwrap(),
        &plan,
    )
    .expect("realize");
    let site = env.join("lib/python3.12/site-packages/gitdep/__init__.py");
    assert_eq!(
        std::fs::read_to_string(&site).unwrap(),
        "VALUE = 'from-git-python'\n"
    );

    // The commit determines the environment: realizing again is a cache
    // hit. Packing the checkout stages on every call, hit or not, so a
    // read-only tmp cannot tell the two apart here; what only a rebuild
    // needs is the built wheel, so an unreadable wheel fails a rebuild and
    // leaves a hit untouched.
    let wheel = std::fs::read_dir(store.root.join("objects"))
        .unwrap()
        .flat_map(|object| std::fs::read_dir(object.unwrap().path()).unwrap())
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("gitdep-"))
                && path.extension().is_some_and(|ext| ext == "whl")
        })
        .expect("the built gitdep wheel in the store");
    {
        use std::os::unix::fs::PermissionsExt;
        let readable = std::fs::metadata(&wheel).unwrap().permissions();
        std::fs::set_permissions(&wheel, std::fs::Permissions::from_mode(0o000)).unwrap();
        let again = greyward::tailors::python::env::realize_env(
            &mut greyward::kernel::resolve::ResolutionDoor::open(
                &store,
                activity,
                platform,
                greyward::kernel::resolve::DoorKind::Planner,
                &mut attribution,
            )
            .unwrap(),
            &plan,
        );
        std::fs::set_permissions(&wheel, readable).unwrap();
        assert_eq!(again.expect("second realize was not a cache hit"), env);
    }
}

/// A local repository holding one small library crate.
fn cargo_fixture_repo(root: &Path) -> (String, String) {
    let repo = root.join("crate-repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"gitdep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 7 }\n").unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "one"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("file://{}", repo.display()), commit)
}

#[test]
fn cargo_git_dependency_is_vendored_from_its_commit() {
    let _serial = serial();
    let root = TempDir::new("gitdep-cargo");
    let (url, commit) = cargo_fixture_repo(&root.0);
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let _attribution = policy::Attribution::open("cargo").expect("test attribution");

    let source = format!("git+{url}?rev={commit}#{commit}");
    let lock = format!(
        "version = 3\n\n[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n"
    );
    let plan = greyward::tailors::cargo::plan_cargo(&lock, "1.96.1").expect("plan");
    assert_eq!(plan.crates.len(), 1);
    assert!(
        plan.crates[0].git.is_some(),
        "the crate carries its git source"
    );

    let vendor = greyward::tailors::cargo::realize_vendor(&store, activity, &plan).expect("vendor");
    let crate_dir = vendor.join("gitdep-1.0.0");
    assert_eq!(
        std::fs::read_to_string(crate_dir.join("src/lib.rs")).unwrap(),
        "pub fn value() -> u32 { 7 }\n"
    );
    // cargo's directory source requires this file; git sources carry no package hash.
    assert_eq!(
        std::fs::read_to_string(crate_dir.join(".cargo-checksum.json")).unwrap(),
        r#"{"files":{},"package":null}"#
    );
    assert!(
        !crate_dir.join(".git").exists(),
        "the .git directory must not be vendored"
    );

    // Realizing again is a cache hit on the same object: answered without
    // staging a second vendor tree.
    let again = without_staging(&store, || {
        greyward::tailors::cargo::realize_vendor(&store, activity, &plan)
    })
    .expect("second vendor was not a cache hit");
    assert_eq!(vendor, again);

    // The file:// source's host-git-transport, recorded cold, stays with
    // the vendor object: a warm sync under a policy denying only that kind
    // refuses the cached object rather than publish without it.
    let id = vendor.file_name().unwrap().to_str().unwrap().to_string();
    let kept: Vec<String> = store
        .exceptions(&id)
        .unwrap()
        .into_iter()
        .map(|exception| exception.kind)
        .collect();
    assert_eq!(
        kept,
        [policy::GIT_DEPENDENCY, policy::HOST_GIT_TRANSPORT].map(String::from)
    );
    let mut deny = policy::Policy::default();
    deny.deny.insert(policy::HOST_GIT_TRANSPORT.to_string());
    let _scope = policy::PolicyScope::install(deny);
    let warm = policy::Attribution::open("cargo").expect("test attribution");
    let error = greyward::tailors::cargo::realize_vendor(&store, activity, &plan)
        .expect_err("a denied kind must refuse the cached vendor object")
        .to_string();
    warm.discard();
    assert!(error.contains(policy::HOST_GIT_TRANSPORT), "{error}");
}

/// Workspace members of a git dependency are vendored with their inherited
/// fields written out, and a link to a file elsewhere in the checkout is
/// copied as that file (#776).
#[test]
fn cargo_git_workspace_members_are_vendored_normalized() {
    let _serial = serial();
    let root = TempDir::new("gitdep-cargo-workspace");
    let (url, commit) = common::cargo_workspace_repo(&root.0);
    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let _attribution = policy::Attribution::open("cargo").expect("test attribution");

    let source = format!("git+{url}?rev={commit}#{commit}");
    let lock = format!(
        "version = 3\n\n\
         [[package]]\nname = \"wsapp\"\nversion = \"0.3.0\"\nsource = \"{source}\"\ndependencies = [\n \"wsshared\",\n]\n\n\
         [[package]]\nname = \"wsshared\"\nversion = \"0.3.0\"\nsource = \"{source}\"\n"
    );
    let plan = greyward::tailors::cargo::plan_cargo(&lock, "1.96.1").expect("plan");
    let vendor = greyward::tailors::cargo::realize_vendor(&store, activity, &plan).expect("vendor");

    let manifest = |dir: &str| -> toml::Table {
        toml::from_str(&std::fs::read_to_string(vendor.join(dir).join("Cargo.toml")).unwrap())
            .unwrap()
    };
    let app = manifest("wsapp-0.3.0");
    let expected: toml::Table = toml::from_str(
        "[package]\nname = \"wsapp\"\nversion = \"0.3.0\"\nedition = \"2021\"\nlicense-file = \"../../LICENSE\"\n\n\
         [dependencies]\nwsshared = { path = \"../shared\", version = \"0.3.0\" }\n",
    )
    .unwrap();
    assert_eq!(app, expected);
    let shared = manifest("wsshared-0.3.0");
    assert_eq!(shared["package"]["version"].as_str(), Some("0.3.0"));
    // A license file from the workspace root is brought into the crate
    // that has none, as `cargo package` does.
    assert_eq!(shared["package"]["license-file"].as_str(), Some("LICENSE"));
    assert_eq!(
        std::fs::read_to_string(vendor.join("wsshared-0.3.0/LICENSE")).unwrap(),
        "shared license\n"
    );
    assert_eq!(
        shared["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid")
    );
    // The original stays beside it, as `cargo package` keeps it.
    assert!(
        std::fs::read_to_string(vendor.join("wsapp-0.3.0/Cargo.toml.orig"))
            .unwrap()
            .contains("version.workspace = true")
    );
    // The link to the repository's LICENSE is the file now.
    let license = vendor.join("wsapp-0.3.0/LICENSE");
    assert!(std::fs::symlink_metadata(&license)
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(
        std::fs::read_to_string(&license).unwrap(),
        "shared license\n"
    );
}

/// A git crate whose links expand past the materialization budget is
/// refused, and the refusal leaves nothing behind: no vendor object and no
/// half-built stage in the store's `tmp` (#776 review).
#[test]
fn a_refused_git_crate_copy_leaves_no_stage() {
    let _serial = serial();
    let root = TempDir::new("gitdep-cargo-budget");
    let repo = root.0.join("fanout-repo");
    std::fs::create_dir_all(repo.join("app/src")).unwrap();
    std::fs::create_dir_all(repo.join("shared/l0")).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    // Ten files, then five levels of ten links each to the level below:
    // the crate's one link to the top expands to over 100,000 entries.
    for i in 0..10 {
        std::fs::write(repo.join(format!("shared/l0/f{i}")), "x").unwrap();
    }
    for level in 1..=5 {
        let dir = repo.join(format!("shared/l{level}"));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..10 {
            std::os::unix::fs::symlink(format!("../l{}", level - 1), dir.join(format!("d{i}")))
                .unwrap();
        }
    }
    std::fs::write(
        repo.join("app/Cargo.toml"),
        "[package]\nname = \"fanout\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("app/src/lib.rs"), "").unwrap();
    std::os::unix::fs::symlink("../shared/l5", repo.join("app/data")).unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "fanout"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    let url = format!("file://{}", repo.display());

    let store = store_at(&root.0);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let attribution = policy::Attribution::open("cargo").expect("test attribution");
    let source = format!("git+{url}?rev={commit}#{commit}");
    let lock = format!(
        "version = 3\n\n[[package]]\nname = \"fanout\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n"
    );
    let plan = greyward::tailors::cargo::plan_cargo(&lock, "1.96.1").expect("plan");
    let error = greyward::tailors::cargo::realize_vendor(&store, activity, &plan)
        .expect_err("a link expansion past the budget must be refused")
        .to_string();
    attribution.discard();
    assert!(error.contains("past 100000 entries"), "{error}");

    let names = |dir: &str| -> Vec<String> {
        match std::fs::read_dir(store.root.join(dir)) {
            Ok(entries) => entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    };
    let stages: Vec<String> = names("tmp")
        .into_iter()
        .filter(|name| name.starts_with("stage-"))
        .collect();
    assert!(stages.is_empty(), "stages left behind: {stages:?}");
    let vendors: Vec<String> = names("objects")
        .into_iter()
        .filter(|name| name.contains("-vendor-"))
        .collect();
    assert!(vendors.is_empty(), "vendor objects published: {vendors:?}");
}
