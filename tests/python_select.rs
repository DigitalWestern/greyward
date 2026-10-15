//! E2e for interpreter selection, warm lock/plan caches, and `ward run`'s
//! refusal of a runtime the synced environment lost (network tests are
//! ignored; the preflight refusal runs offline).

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::os::unix::fs::PermissionsExt;
use std::process::Output;

use greyward::kernel::platform::Platform;

mod common;

use common::{
    assert_frozen_never_writes_the_lock, assert_ok, command, copy_tree, fixture, snapshot, text,
    ward, ward_at, warm_store, TempDir,
};

#[test]
#[ignore]
fn pyproject_requires_python_selects_311_and_warm_sync_is_cached() {
    if !cfg!(target_os = "linux") {
        eprintln!("python_select: skipped on non-Linux host");
        return;
    }
    if Platform::host().unwrap() != Platform::X86_64UnknownLinuxGnu {
        eprintln!("skip python_select: host is not x86_64-unknown-linux-gnu");
        return;
    }

    let temp = TempDir::new("python-select");
    let project = temp.0.join("proj-py311");
    copy_tree(&fixture("proj-py311"), &project);
    let store = warm_store(&temp);
    // The sync signs its closure with a key made here, and a machine policy
    // in a scratch HOME trusts it: the gate then passes the real record.
    let key = temp.0.join("signing.key");
    let public = greyward::kernel::signing::generate(&key).unwrap();
    let home = temp.0.join("home");
    std::fs::create_dir_all(home.join(".greyward")).unwrap();
    std::fs::write(
        home.join(".greyward/policy.toml"),
        format!("[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let signed = |args: &[&str]| -> Output {
        command(&project, &home, &store)
            .env("GREYWARD_SIGNING_KEY", &key)
            .args(args)
            .output()
            .unwrap()
    };

    let first = signed(&["sync"]);
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(first.status.success(), "first sync failed: {first_stderr}");
    assert!(
        first_stderr.contains("python 3.11.17 selected"),
        "{first_stderr}"
    );
    assert!(
        !first_stderr.contains("written unsigned"),
        "a signed sync must not warn about unsigned closures: {first_stderr}"
    );
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".greyward/closures/python.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(closure["signature"]["alg"], "ed25519");
    assert_eq!(closure["signature"]["key"], public.hex());
    assert_eq!(
        greyward::kernel::signing::verify(&closure),
        greyward::kernel::signing::Verification::Valid(public)
    );
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert!(
        audit.status.success()
            && report["passed"] == true
            && report["closures"][0]["verdict"] == "clean"
            && report["closures"][0]["signature"]["state"] == "trusted",
        "audit did not pass the signed sync record\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );
    // Editing the committed record is caught: no exception is judged. The
    // edit adds an exception the sync did not record, so the value changes
    // whatever the real sync recorded.
    let path = project.join(".greyward/closures/python.json");
    let mut edited = closure.clone();
    edited["body"]["exceptions"] = serde_json::json!([
        {"kind": "git-dependency", "subject": "left-pad", "detail": "hand-added"}
    ]);
    std::fs::write(&path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert_eq!(audit.status.code(), Some(1));
    assert_eq!(report["closures"][0]["verdict"], "bad-signature");
    std::fs::write(&path, serde_json::to_vec_pretty(&closure).unwrap()).unwrap();
    // An unsigned sync says so and its record is outdated.
    let unsigned = ward_at(&project, &home, &store, &["sync", "--fresh"]);
    assert!(
        unsigned.status.success(),
        "{}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unsigned.stderr).contains("written unsigned"),
        "{}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert_eq!(audit.status.code(), Some(1));
    assert_eq!(report["closures"][0]["verdict"], "outdated");
    assert_eq!(report["closures"][0]["signature"]["state"], "unsigned");
    let resigned = signed(&["sync"]);
    assert!(
        resigned.status.success(),
        "{}",
        String::from_utf8_lossy(&resigned.stderr)
    );
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert!(
        audit.status.success() && report["closures"][0]["verdict"] == "clean",
        "re-syncing under the key did not restore a clean audit\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );
    assert_eq!(closure["body"]["python"]["version"], "3.11.17");
    assert_eq!(closure["body"]["python"]["constraint"], ">=3.9,<3.12");
    assert_eq!(
        closure["body"]["python"]["constraint_source"],
        "pyproject.toml"
    );

    let run = assert_ok(
        ward_at(
            &project,
            &home,
            &store,
            &[
                "run",
                "python",
                "-c",
                "import sys,six; print(sys.version_info[:2])",
            ],
        ),
        "ward run python",
    );
    assert_eq!(run.trim(), "(3, 11)");

    let plan_path = project.join(".greyward/plan.json");
    let lock_path = project.join("requirements.lock.txt");
    // The lock names what it was compiled from in uv's header (#673).
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.lines()
            .nth(1)
            .is_some_and(|line| line.starts_with("#    ward # lock-source/1 platform=")),
        "{lock}"
    );
    let plan_mtime = std::fs::metadata(&plan_path).unwrap().modified().unwrap();
    let lock_mtime = std::fs::metadata(&lock_path).unwrap().modified().unwrap();

    let second = signed(&["sync"]);
    assert_ok(second, "warm sync");
    assert_eq!(
        std::fs::metadata(&plan_path).unwrap().modified().unwrap(),
        plan_mtime,
        "warm sync replanned"
    );
    assert_eq!(
        std::fs::metadata(&lock_path).unwrap().modified().unwrap(),
        lock_mtime,
        "warm sync re-locked"
    );
}

/// Offline and fast: the refusal happens before any download, so this runs
/// in the default suite and guards the preflight-before-store ordering.
#[test]
fn unpinned_patch_request_fails_closed_before_opening_store() {
    let temp = TempDir::new("python-select");
    let project = temp.0.join("proj-unpinned-patch");
    std::fs::create_dir_all(&project).unwrap();
    // 3.11.2 is a real CPython release python-build-standalone never
    // published a checksummed build of, so no catalog can carry it.
    std::fs::write(project.join(".python-version"), "3.11.2\n").unwrap();
    std::fs::write(project.join("requirements.txt"), "").unwrap();
    let store = temp.0.join("store");

    let output = ward(&project, &temp.0, &["sync"]);
    assert_eq!(
        output.status.code(),
        Some(5),
        "unexpected status: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("3.11.2"), "{stderr}");
    assert!(stderr.contains(".python-version"), "{stderr}");
    assert!(stderr.contains("3.11.1, 3.11.3"), "{stderr}");
    assert!(
        stderr.contains("pin 3.11 to accept the pinned patch"),
        "{stderr}"
    );
    assert!(stderr.contains("request one of:"), "{stderr}");
    assert!(!store.exists(), "store was opened: {store:?}");
}

/// The committed files of `project` (its top-level files: no `.greyward`,
/// no `.venv`), copied into a new directory `clone`, as a fresh checkout on
/// another machine has them.
fn fresh_checkout(project: &std::path::Path, clone: &std::path::Path) {
    std::fs::create_dir_all(clone).unwrap();
    for entry in std::fs::read_dir(project).unwrap() {
        let path = entry.unwrap().path();
        if path.symlink_metadata().unwrap().is_file() {
            std::fs::copy(&path, clone.join(path.file_name().unwrap())).unwrap();
        }
    }
}

/// `--frozen` only reads the requirements lock (#673): after an edit to
/// `requirements.txt` the committed lock names other inputs in its header,
/// and the frozen sync is refused as stale (exit 4) with every project file
/// left byte for byte as it was, rather than re-locked over the network.
/// The header is the evidence, so a fresh checkout with no local state, at
/// another path, reads the same lock and is refused the same way. Without
/// the lock it is refused by name, and a plain plan compiles it again.
/// Ignored: the first sync downloads CPython and resolves against PyPI.
#[test]
#[ignore]
fn frozen_python_sync_never_relocks_an_edited_requirements_file() {
    let temp = TempDir::new("python-frozen");
    let project = temp.0.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("requirements.txt"), "six>=1.16\n").unwrap();
    assert_ok(ward(&project, &temp.0, &[]), "first sync");
    let lock = std::fs::read(project.join("requirements.lock.txt")).unwrap();

    // A fresh checkout of the unedited project syncs frozen from the lock.
    let clone = temp.0.join("checkout/proj");
    fresh_checkout(&project, &clone);
    assert_ok(
        ward(&clone, &temp.0, &["--frozen"]),
        "frozen fresh checkout",
    );
    assert_eq!(
        std::fs::read(clone.join("requirements.lock.txt")).unwrap(),
        lock
    );
    // An edited one is refused, and nothing in it changes.
    let clone = temp.0.join("edited/proj");
    fresh_checkout(&project, &clone);
    std::fs::write(clone.join("requirements.txt"), "six>=1.15\n").unwrap();
    let before = snapshot(&clone);
    let frozen = ward(&clone, &temp.0, &["--frozen"]);
    let stderr = text(&frozen.stderr);
    assert_eq!(frozen.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains(
            "was not compiled from requirements.txt as it is now: the requirements changed"
        ),
        "{stderr}"
    );
    assert_eq!(snapshot(&clone), before, "--frozen changed the checkout");

    std::fs::write(project.join("requirements.txt"), "six>=1.15\n").unwrap();
    let before = snapshot(&project);
    let frozen = ward(&project, &temp.0, &["--frozen"]);
    let stderr = text(&frozen.stderr);
    assert_eq!(frozen.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains("was not compiled from requirements.txt as it is now"),
        "{stderr}"
    );
    assert_eq!(snapshot(&project), before, "--frozen changed the project");
    assert_eq!(
        std::fs::read(project.join("requirements.lock.txt")).unwrap(),
        lock
    );
    assert_frozen_never_writes_the_lock(&project, &temp.0, "requirements.lock.txt");
}

/// `ward run` itself refuses a runtime its project's environment does not
/// provide, rather than letting the host's PATH supply one (#564, #581):
/// the unit tests of `unprovided_runtime` do not show that `run` calls it.
/// Ignored: the sync downloads CPython. The environment is then broken in
/// this case's own store (never a shared `GREYWARD_STORE`), by making the
/// interpreter `.venv/bin` points at non-executable, so `python` and
/// `python3` are named but not provided. A host python3 (every CI runner
/// has one) would answer `--version` if `run` fell through.
#[test]
#[ignore]
fn run_refuses_a_runtime_its_synced_environment_lost() {
    let home = TempDir::boundary("cli-run-runtime");
    let project = TempDir::boundary("cli-run-runtime-project");
    std::fs::write(
        project.0.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let out = ward(&project.0, &home.0, &["run", "python3", "--version"]);
    let stdout = text(&out.stdout);
    assert!(
        out.status.success() && stdout.starts_with("Python 3."),
        "stdout: {stdout}\nstderr: {}",
        text(&out.stderr)
    );
    let interpreter = std::fs::canonicalize(project.0.join(".venv/bin/python3")).unwrap();
    assert!(
        interpreter.starts_with(std::fs::canonicalize(home.0.join("store")).unwrap()),
        "{} is not in this case's store",
        interpreter.display()
    );
    let mode = std::fs::metadata(&interpreter).unwrap().permissions();
    std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o644)).unwrap();
    for program in ["python3", "python"] {
        let out = ward(&project.0, &home.0, &["run", program, "--version"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{program}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "'{program}' is the python runtime, but the project's environment does not \
                 provide it"
            )),
            "{program}: {stderr}"
        );
        assert!(
            text(&out.stdout).is_empty(),
            "{program} ran: {}",
            text(&out.stdout)
        );
    }
    std::fs::set_permissions(&interpreter, mode).unwrap();
}
