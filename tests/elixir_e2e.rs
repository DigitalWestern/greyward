//! End-to-end Elixir tailor test. Heavy: downloads OTP + Elixir + Hex +
//! rebar3 and the dep closure (telemetry exercises the rebar3 manager).
//!
//! The single ignored gate proves, from the COMMITTED BEAM object only
//! (staging gone, host Erlang/Elixir off the effective PATH): OTP release
//! 29 / 29.0.5, Elixir 1.20.4, `:code.root_dir()` inside the object,
//! crypto (sha256 compared against Rust), ssl startup, the sandboxed
//! `ward build`, a `mix run --no-compile` application probe, a rebuild
//! after deleting the qualified build output, and object immutability.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;

use common::{
    assert_frozen_never_writes_the_lock, assert_ok, assert_private_run_home, copy_tree, fixture,
    home_store, temp_entries, ward, ward_offline, TempDir,
};

const DARWIN_FINGERPRINT: &str = "c35290f692496d51";

/// Run a binary from the committed object with a cleared environment:
/// PATH holds only the object's own bin dirs plus the system dirs, so no
/// host Erlang/Elixir can be found by name.
fn run_store_bin(bin: &Path, beam: &Path, home: &Path, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        beam.join("elixir/bin").display(),
        beam.join("otp/bin").display()
    );
    Command::new(bin)
        .args(args)
        .current_dir(home)
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("LANG", "C.UTF-8")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap()
}

/// The tailor-owned `body` of the closure envelope ward wrote
/// (`.greyward/closures/elixir.json`, schema closure/1).
fn closure_body(project: &Path) -> serde_json::Value {
    let mut envelope: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".greyward/closures/elixir.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(envelope["schema"], "closure/1");
    assert_eq!(envelope["ecosystem"], "elixir");
    envelope["body"].take()
}

fn remove_tree(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) {
        if let Ok(md) = std::fs::symlink_metadata(p) {
            if md.file_type().is_symlink() {
                return;
            }
            let mut perms = md.permissions();
            perms.set_mode(perms.mode() | 0o200);
            let _ = std::fs::set_permissions(p, perms);
            if md.is_dir() {
                for entry in std::fs::read_dir(p).unwrap() {
                    unlock(&entry.unwrap().path());
                }
            }
        }
    }
    unlock(path);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore]
fn elixir_sync_sandboxed_build_and_run() {
    let temp = TempDir::new("elixir-e2e");
    let project = temp.0.join("elixir-hello");
    copy_tree(&fixture("elixir-hello"), &project);
    let store = temp.0.join("store");
    let home = temp.0.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let temp_before = temp_entries("greyward-mix-run-");

    // Realize the composite BEAM object; everything below uses only its
    // committed path (read from the closure ward wrote).
    assert_ok(ward(&project, &temp.0, &["sync"]), "sync");
    // The child's HOME is the project's private run home, and every
    // directory the forced environment names exists before it starts.
    let run_home =
        assert_private_run_home(&project, &temp.0, &store, "elixir", "greyward-mix-run-");
    for sub in ["mix", "hex", "xdg", "xdg-cache"] {
        assert!(
            run_home.join(sub).is_dir(),
            "{sub} missing under the run home"
        );
    }
    let closure = closure_body(&project);
    let beam = PathBuf::from(closure["beam_object"]["path"].as_str().unwrap());
    let fingerprint = closure["beam_fingerprint"].as_str().unwrap().to_string();
    let store_canon = store.canonicalize().unwrap();
    assert!(
        beam.starts_with(store_canon.join("objects")),
        "beam object {} is not under the store",
        beam.display()
    );
    let otp = beam.join("otp");
    assert!(otp.join("bin/erl").is_file());

    // An unchanged project re-syncs with the network cut: the consistency
    // check passed for these exact inputs, so no live Hex query is needed.
    // Each resolution run owns its private Hex home. No shared executable
    // client configuration or cache survives for another project to inherit.
    assert!(!store.join("planner-hexhome").exists());
    assert_ok(
        ward_offline(&project, &temp.0, &["sync"]),
        "offline re-sync of the unchanged project",
    );
    let offline = closure_body(&project);
    for key in ["beam_object", "deps_object"] {
        assert_eq!(
            offline[key], closure[key],
            "the offline re-sync projected a different {key}"
        );
    }
    // Staging is cleaned up: no `stage-` directories left under <store>/tmp.
    let leftovers: Vec<_> = std::fs::read_dir(store_canon.join("tmp"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("stage-"))
        .collect();
    assert!(leftovers.is_empty(), "staging left behind: {leftovers:?}");

    // OTP-side probes from the committed object.
    let otp_version = std::fs::read_to_string(otp.join("releases/29/OTP_VERSION")).unwrap();
    assert_eq!(otp_version.trim(), "29.0.5");
    let expected_hash = hex::encode(Sha256::digest(b"ward"));
    let erl = assert_ok(
        run_store_bin(
            &otp.join("bin/erl"),
            &beam,
            &home,
            &[
                "-noshell",
                "-eval",
                "ok = crypto:start(), \
                 io:format(\"release=~s~n\", [erlang:system_info(otp_release)]), \
                 io:format(\"root=~s~n\", [code:root_dir()]), \
                 io:format(\"sha256=~s~n\", [string:lowercase(binary:encode_hex(crypto:hash(sha256, <<\"ward\">>)))]), \
                 {ok, _} = application:ensure_all_started(ssl), \
                 {supported, Supported} = lists:keyfind(supported, 1, ssl:versions()), \
                 true = length(Supported) > 0, \
                 io:format(\"ssl=~p~n\", [Supported]), \
                 halt(0).",
            ],
        ),
        "erl probe",
    );
    assert!(erl.contains("release=29\n"), "{erl}");
    assert!(
        erl.contains(&format!("root={}\n", otp.canonicalize().unwrap().display())),
        "{erl}"
    );
    assert!(erl.contains(&format!("sha256={expected_hash}\n")), "{erl}");
    assert!(erl.contains("ssl=["), "{erl}");

    // Elixir side, through `ward run` (its PATH puts the object first).
    let ex = assert_ok(
        ward(&project, &temp.0,
            &[
                "run",
                "elixir",
                "-e",
                "IO.puts(\"elixir=\" <> System.version()); \
                 IO.puts(\"otp=\" <> System.otp_release()); \
                 IO.puts(\"root=\" <> List.to_string(:code.root_dir())); \
                 IO.puts(\"sha256=\" <> Base.encode16(:crypto.hash(:sha256, \"ward\"), case: :lower)); \
                 {:ok, _} = Application.ensure_all_started(:ssl); \
                 IO.puts(\"ssl=\" <> inspect(:ssl.versions()[:supported]))",
            ],
        ),
        "elixir probe",
    );
    assert!(ex.contains("elixir=1.20.4\n"), "{ex}");
    assert!(ex.contains("otp=29\n"), "{ex}");
    assert!(
        ex.contains(&format!("root={}\n", otp.canonicalize().unwrap().display())),
        "{ex}"
    );
    assert!(ex.contains(&format!("sha256={expected_hash}\n")), "{ex}");
    assert!(ex.contains("ssl=[:"), "{ex}");

    // Sandboxed compile of the locked closure (telemetry via the pinned
    // rebar3, jason via mix), network denied; then the app probe WITHOUT
    // compiling, so a failed sandboxed build cannot be repaired by this
    // unsandboxed run.
    assert_ok(ward(&project, &temp.0, &["build"]), "build");
    let build_dir = project.join(format!("_build/greyward-{fingerprint}"));
    assert!(
        build_dir.join("dev/lib/ex_real/ebin").is_dir(),
        "{}",
        build_dir.display()
    );
    assert!(build_dir.join("dev/lib/telemetry/ebin").is_dir());
    assert!(build_dir.join("dev/lib/jason/ebin").is_dir());
    let probe = [
        "run",
        "mix",
        "run",
        "--no-compile",
        "--no-deps-check",
        "-e",
        "IO.puts(\"e2e: \" <> ExReal.hello())",
    ];
    let out = assert_ok(ward(&project, &temp.0, &probe), "run");
    assert!(out.contains("e2e: {\"beam\":\"ok\"}"), "{out}");

    // Drop the qualified build output and refresh the projection (removes
    // compiled residue in dep source trees), rebuild from the same realized
    // objects, rerun.
    remove_tree(&build_dir);
    assert!(!build_dir.exists());
    assert_ok(
        ward(&project, &temp.0, &["sync", "--fresh"]),
        "sync --fresh",
    );
    let closure_again = closure_body(&project);
    assert_eq!(
        closure_again["beam_object"]["path"],
        closure["beam_object"]["path"]
    );
    assert_eq!(
        closure_again["deps_object"]["path"],
        closure["deps_object"]["path"]
    );
    assert_ok(ward(&project, &temp.0, &["build"]), "rebuild");
    let out = assert_ok(ward(&project, &temp.0, &probe), "rerun");
    assert!(out.contains("e2e: {\"beam\":\"ok\"}"), "{out}");
    let vsn = assert_ok(
        ward(&project, &temp.0, &["run", "elixir", "--version"]),
        "elixir version",
    );
    assert!(vsn.contains("1.20.4"), "{vsn}");

    // Fingerprint/build dir are platform-specific; the object is immutable.
    if cfg!(target_os = "linux") {
        assert_ne!(fingerprint, DARWIN_FINGERPRINT);
        assert_ne!(
            build_dir,
            project.join(format!("_build/greyward-{DARWIN_FINGERPRINT}"))
        );
    } else {
        assert_eq!(fingerprint, DARWIN_FINGERPRINT);
    }
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [beam.clone(), otp.clone(), otp.join("bin/erl")] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o222,
                0,
                "{} is writable (mode {mode:o})",
                p.display()
            );
        }
    }
    assert!(std::fs::write(beam.join("tamper"), b"x").is_err());
    assert!(std::fs::write(otp.join("bin/tamper"), b"x").is_err());
    // Without its lock the project is refused under --frozen and left
    // alone; a plan regenerates the lock with the store mix.
    assert_frozen_never_writes_the_lock(&project, &temp.0, "mix.lock");
    let left: Vec<_> = temp_entries("greyward-mix-run-")
        .difference(&temp_before)
        .cloned()
        .collect();
    assert!(left.is_empty(), "runs left {left:?} under the temp root");
}

/// A mix.lock git dependency outlives `ward gc` while the project uses it:
/// the deps object holds the checkout object, which holds the git source,
/// so a frozen sync with the repository gone and no network finds all of
/// it in the store.
#[test]
#[ignore]
fn elixir_git_dependency_survives_gc_for_an_offline_frozen_sync() {
    let temp = TempDir::new("elixir-git-gc");
    let repo = temp.0.join("lib");
    std::fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    std::fs::write(
        repo.join("mix.exs"),
        "defmodule Lib.MixProject do\n  use Mix.Project\n  \
         def project, do: [app: :lib, version: \"0.1.0\"]\nend\n",
    )
    .unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "one"]);
    let rev = git(&["rev-parse", "HEAD"]);
    let url = format!("file://{}", repo.canonicalize().unwrap().display());

    let project = temp.0.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("mix.exs"),
        format!(
            "defmodule Demo.MixProject do\n  use Mix.Project\n  \
             def project, do: [app: :demo, version: \"0.1.0\", deps: [{{:lib, git: {url:?}}}]]\n\
             end\n"
        ),
    )
    .unwrap();
    std::fs::write(
        project.join("mix.lock"),
        format!("%{{\n  \"lib\": {{:git, {url:?}, {rev:?}, []}},\n}}\n"),
    )
    .unwrap();
    assert_ok(ward(&project, &temp.0, &["sync"]), "sync");
    let deps = PathBuf::from(
        closure_body(&project)["deps_object"]["path"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        std::fs::read_to_string(deps.join("lib/.git/HEAD"))
            .unwrap()
            .trim(),
        rev
    );

    // Collection keeps whatever was touched in the last ten minutes; age
    // every object past that so only reachability keeps one.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(11 * 60);
    let store = home_store(&project, &temp.0);
    for entry in std::fs::read_dir(store.join("objects")).unwrap() {
        std::fs::File::open(entry.unwrap().path())
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    assert_ok(ward(&project, &temp.0, &["gc", "--keep-days", "0"]), "gc");
    remove_tree(&repo);
    assert_ok(
        ward_offline(&project, &temp.0, &["--frozen"]),
        "frozen sync after gc, the repository gone",
    );
}
