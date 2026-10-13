//! `ward update --self` and the `version` row of `ward doctor`, exercised
//! through the real binary against a release laid out the way GitHub
//! serves one: a manifest naming the assets, a tarball holding `ward`, and
//! the `.sha256` file beside it. Everything is served from `file://` URLs
//! (`GREYWARD_RELEASE_MANIFEST`), so nothing here touches the network, and the
//! binary being replaced is always a copy in a throwaway HOME, never the
//! one cargo built.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;

use common::{command_for, tar_create, text, TempDir};

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn triple() -> &'static str {
    greyward::kernel::platform::Platform::host()
        .unwrap()
        .triple()
}

/// A shell script that answers `--version` the way a ward binary does, so
/// the update's smoke test accepts it and the test can tell the new file
/// from the old one by what it prints.
fn fake_ward(version_line: &str) -> String {
    format!("#!/bin/sh\nprintf '%s\\n' '{version_line}'\n")
}

/// The pieces of a release the manifest can point at. Each knob breaks one
/// rule on purpose so the test can watch the refusal.
struct Release<'a> {
    tag: &'a str,
    /// The `ward` member of the tarball; `None` ships a tarball without one.
    binary: Option<&'a str>,
    /// The digest the `.sha256` file claims; `None` uses the real one.
    claimed_sha256: Option<&'a str>,
    /// Leave the platform's assets out of the manifest entirely.
    no_assets: bool,
    /// The `.sig` file next to the archive.
    signature: Signature,
}

/// What the release's `.sig` holds.
#[derive(Clone, Copy)]
enum Signature {
    /// The test release key's signature over the archive.
    Good,
    /// No `.sig` asset at all.
    Missing,
    /// A signature over the archive by a key that is not the release key.
    OtherKey,
    /// The release key's signature over other bytes: an archive swapped
    /// after signing, with its `.sha256` rewritten to match.
    OtherBytes,
}

/// The release key the tests sign with: the binary under test is a debug
/// build, which honors `GREYWARD_RELEASE_PUBLIC_KEY` (a release build does
/// not, and trusts only the compiled-in key).
const RELEASE_SEED: [u8; 32] = [5; 32];

fn key_pair(seed: &[u8; 32]) -> ring::signature::Ed25519KeyPair {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap()
}

fn release_public_key() -> String {
    use ring::signature::KeyPair;
    format!(
        "ed25519:{}",
        hex::encode(key_pair(&RELEASE_SEED).public_key().as_ref())
    )
}

impl Release<'_> {
    fn newer() -> Self {
        Release {
            tag: "v99.0.0",
            binary: Some("ward 99.0.0 (test)"),
            claimed_sha256: None,
            no_assets: false,
            signature: Signature::Good,
        }
    }
}

/// Lay the release out under `home/release` and return the manifest URL.
fn publish(home: &Path, release: &Release<'_>) -> String {
    let dir = home.join("release");
    let stage = home.join("stage");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(&stage).unwrap();
    let asset = format!("greyward-{}.tar.gz", triple());
    let member = match release.binary {
        Some(version_line) => {
            fs::write(stage.join("ward"), fake_ward(version_line)).unwrap();
            fs::set_permissions(stage.join("ward"), fs::Permissions::from_mode(0o755)).unwrap();
            "ward"
        }
        None => {
            fs::write(stage.join("README"), "no binary here\n").unwrap();
            "README"
        }
    };
    let status = tar_create()
        .args(["-C"])
        .arg(&stage)
        .arg("-czf")
        .arg(dir.join(&asset))
        .arg(member)
        .status()
        .unwrap();
    assert!(status.success());
    let digest = match release.claimed_sha256 {
        Some(claimed) => claimed.to_string(),
        None => sha256_hex(&fs::read(dir.join(&asset)).unwrap()),
    };
    fs::write(
        dir.join(format!("{asset}.sha256")),
        format!("{digest}  {asset}\n"),
    )
    .unwrap();
    let archive = fs::read(dir.join(&asset)).unwrap();
    let signed = match release.signature {
        Signature::Good | Signature::Missing => key_pair(&RELEASE_SEED).sign(&archive),
        Signature::OtherKey => key_pair(&[6; 32]).sign(&archive),
        Signature::OtherBytes => key_pair(&RELEASE_SEED).sign(b"the archive that was signed"),
    };
    let sig_name = format!("{asset}.sig");
    let _ = fs::remove_file(dir.join(&sig_name));
    let mut assets = vec![
        serde_json::json!({
            "name": asset,
            "browser_download_url": format!("file://{}", dir.join(&asset).display()),
        }),
        serde_json::json!({
            "name": format!("{asset}.sha256"),
            "browser_download_url": format!("file://{}", dir.join(format!("{asset}.sha256")).display()),
        }),
    ];
    if !matches!(release.signature, Signature::Missing) {
        // One line of base64, as tools/release-sign.sh writes it.
        let line = base64_line(signed.as_ref());
        fs::write(dir.join(&sig_name), format!("{line}\n")).unwrap();
        assets.push(serde_json::json!({
            "name": sig_name,
            "browser_download_url": format!("file://{}", dir.join(&sig_name).display()),
        }));
    }
    let assets = if release.no_assets {
        serde_json::json!([])
    } else {
        serde_json::Value::Array(assets)
    };
    let manifest = dir.join("latest.json");
    fs::write(
        &manifest,
        serde_json::to_string_pretty(&serde_json::json!({
            "tag_name": release.tag,
            "assets": assets,
        }))
        .unwrap(),
    )
    .unwrap();
    format!("file://{}", manifest.display())
}

/// A copy of the built binary at `home/bin/ward`: the one the test runs and
/// the one the update is allowed to replace.
fn install_copy(home: &Path) -> PathBuf {
    let bin = home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let target = bin.join("ward");
    fs::copy(env!("CARGO_BIN_EXE_ward"), &target).unwrap();
    target
}

fn run(binary: &Path, home: &Path, manifest: &str, args: &[&str]) -> Output {
    let mut command = command_for(binary, home, home, &home.join("store"));
    command
        .args(args)
        .env("GREYWARD_RELEASE_MANIFEST", manifest)
        .env("GREYWARD_RELEASE_PUBLIC_KEY", release_public_key());
    output_of(&mut command)
}

/// Standard base64 with padding: the crate's own codec is not public.
fn base64_line(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> shift) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Run a binary this test just wrote. Another test thread that forks
/// while our copy is still open for writing holds that descriptor until
/// its child execs, and exec of a file open for writing fails with
/// ETXTBSY; the window is short, so wait it out.
fn output_of(command: &mut Command) -> Output {
    for _ in 0..50 {
        match command.output() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            result => return result.expect("spawn ward"),
        }
    }
    command.output().expect("spawn ward")
}

fn version_of(binary: &Path, home: &Path) -> String {
    text(&output_of(command_for(binary, home, home, &home.join("store")).arg("--version")).stdout)
        .trim()
        .to_string()
}

/// Nothing named `.greyward.update.*` may survive next to the binary, whatever
/// happened.
fn no_leftovers(dir: &Path) {
    let stray: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".greyward.update."))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

fn running_line() -> String {
    greyward::cli::version_line()
}

#[test]
fn a_newer_release_replaces_the_binary_in_place() {
    let home = TempDir::boundary("selfupdate-newer");
    let binary = install_copy(&home.0);
    let before = version_of(&binary, &home.0);
    assert_eq!(before, running_line());
    let manifest = publish(&home.0, &Release::newer());

    let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("downloading v99.0.0"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "updated {before} -> ward 99.0.0 (test) at {}",
            binary.canonicalize().unwrap().display()
        )),
        "{stderr}"
    );
    assert_eq!(version_of(&binary, &home.0), "ward 99.0.0 (test)");
    assert_eq!(
        fs::metadata(&binary).unwrap().permissions().mode() & 0o777,
        0o755
    );
    no_leftovers(binary.parent().unwrap());
}

#[test]
fn the_same_or_an_older_release_leaves_the_binary_alone() {
    let home = TempDir::boundary("selfupdate-current");
    let binary = install_copy(&home.0);
    let bytes = fs::read(&binary).unwrap();
    for (tag, word) in [
        (
            format!("v{}", env!("CARGO_PKG_VERSION")),
            "is at the latest release's version",
        ),
        ("v0.0.1".to_string(), "is newer than the latest release"),
    ] {
        let manifest = publish(
            &home.0,
            &Release {
                tag: &tag,
                ..Release::newer()
            },
        );
        let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        assert!(
            stderr.contains(&format!("{} {word} ({tag}); nothing to do", running_line())),
            "{stderr}"
        );
        assert!(!stderr.contains("downloading"), "{stderr}");
        assert_eq!(fs::read(&binary).unwrap(), bytes);
    }
    // Quiet silences the narration and still exits 0.
    let manifest = publish(
        &home.0,
        &Release {
            tag: "v0.0.1",
            ..Release::newer()
        },
    );
    let out = run(&binary, &home.0, &manifest, &["-q", "update", "--self"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
}

#[test]
fn a_bad_download_never_touches_the_binary() {
    let home = TempDir::boundary("selfupdate-refused");
    let binary = install_copy(&home.0);
    let bytes = fs::read(&binary).unwrap();
    let wrong = "0".repeat(64);
    for (release, expected) in [
        (
            Release {
                claimed_sha256: Some(&wrong),
                ..Release::newer()
            },
            "hash mismatch",
        ),
        (
            Release {
                claimed_sha256: Some("not-a-digest"),
                ..Release::newer()
            },
            "does not hold a sha256",
        ),
        (
            Release {
                binary: None,
                ..Release::newer()
            },
            "did not contain a 'ward' binary",
        ),
        (
            Release {
                binary: Some("something else"),
                ..Release::newer()
            },
            "does not identify itself",
        ),
        (
            Release {
                binary: Some("ward 1.0.0 (wrong asset)"),
                ..Release::newer()
            },
            "says it is 1.0.0, not 99.0.0",
        ),
        (
            Release {
                no_assets: true,
                ..Release::newer()
            },
            &format!("release v99.0.0 has no greyward-{}.tar.gz", triple()),
        ),
        // #698: the .sha256 comes from the same release, so only the
        // release key's signature over these exact bytes is trusted.
        (
            Release {
                signature: Signature::Missing,
                ..Release::newer()
            },
            &format!("greyward-{}.tar.gz.sig for this machine", triple()),
        ),
        (
            Release {
                signature: Signature::OtherKey,
                ..Release::newer()
            },
            "is not signed by ward's release key",
        ),
        (
            Release {
                signature: Signature::OtherBytes,
                ..Release::newer()
            },
            "is not signed by ward's release key",
        ),
    ] {
        let manifest = publish(&home.0, &release);
        let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("ward: error: "), "{stderr}");
        assert!(stderr.contains(expected), "{expected}: {stderr}");
        assert_eq!(fs::read(&binary).unwrap(), bytes, "{expected}");
        no_leftovers(binary.parent().unwrap());
    }
    // A manifest that cannot be read names the releases page.
    let out = run(
        &binary,
        &home.0,
        &format!("file://{}", home.0.join("missing.json").display()),
        &["update", "--self"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("cannot read the latest release (")
            && stderr.contains("https://github.com/DigitalWestern/greyward/releases"),
        "{stderr}"
    );
    assert_eq!(fs::read(&binary).unwrap(), bytes);
}

#[test]
fn an_unwritable_directory_is_refused_before_anything_is_downloaded() {
    let home = TempDir::boundary("selfupdate-readonly");
    let binary = install_copy(&home.0);
    let bin = binary.parent().unwrap().to_path_buf();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::File::create(bin.join(".probe")).is_ok() {
        // root, or a filesystem that ignores the mode: nothing to prove.
        let _ = fs::remove_file(bin.join(".probe"));
        return;
    }
    let manifest = publish(&home.0, &Release::newer());
    let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
    let stderr = text(&out.stderr);
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "cannot write to {} (",
            bin.canonicalize().unwrap().display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("install.sh"), "{stderr}");
    assert!(!stderr.contains("downloading"), "{stderr}");
    assert_eq!(version_of(&binary, &home.0), running_line());
    no_leftovers(&bin);
}

#[test]
fn a_symlinked_binary_updates_its_target_and_names_it() {
    let home = TempDir::boundary("selfupdate-symlink");
    let target = install_copy(&home.0);
    let link_dir = home.0.join("link");
    fs::create_dir_all(&link_dir).unwrap();
    let link = link_dir.join("ward");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let manifest = publish(&home.0, &Release::newer());

    let out = run(&link, &home.0, &manifest, &["update", "--self"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!("at {}", target.canonicalize().unwrap().display())),
        "{stderr}"
    );
    assert!(!stderr.contains(&link.display().to_string()), "{stderr}");
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(version_of(&target, &home.0), "ward 99.0.0 (test)");
    assert_eq!(version_of(&link, &home.0), "ward 99.0.0 (test)");
    no_leftovers(target.parent().unwrap());
    no_leftovers(&link_dir);
}

#[test]
fn self_takes_nothing_else_and_needs_no_project_or_store() {
    let home = TempDir::boundary("selfupdate-usage");
    let binary = install_copy(&home.0);
    let manifest = publish(&home.0, &Release::newer());
    for args in [
        &["update", "--self", "serde"][..],
        &["update", "--self", "--toolchain"],
        &["update", "--self", "--no-sync"],
    ] {
        let out = run(&binary, &home.0, &manifest, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            text(&out.stderr).contains("update --self replaces the ward binary"),
            "{}",
            text(&out.stderr)
        );
    }
    // A successful update from an empty directory never created a store.
    let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!home.0.join("store").exists());
}

#[test]
fn doctor_reports_the_build_and_whether_a_release_is_newer() {
    let home = TempDir::boundary("selfupdate-doctor");
    let binary = install_copy(&home.0);
    let running = running_line();

    let manifest = publish(&home.0, &Release::newer());
    let out = run(&binary, &home.0, &manifest, &["doctor"]);
    let stdout = text(&out.stdout);
    let first = stdout.lines().next().unwrap();
    assert_eq!(
        first,
        format!("warn  version      {running}; v99.0.0 is out (run 'ward update --self')"),
        "{stdout}"
    );
    // A stale binary is a warning, not a failure. Other rows may fail on
    // the host running this (no bubblewrap, no C toolchain), so only
    // the version row is judged.
    assert!(
        !stdout.lines().any(|line| line.starts_with("fail  version")),
        "{stdout}"
    );
    let out = run(&binary, &home.0, &manifest, &["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["checks"][0]["name"], "version");
    assert_eq!(value["checks"][0]["level"], "warn");
    assert!(value["checks"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("ward update --self"));

    // Issue #403. A newer release with no build for this machine is news,
    // not a warning: `update --self` would refuse it.
    let manifest = publish(
        &home.0,
        &Release {
            no_assets: true,
            ..Release::newer()
        },
    );
    let out = run(&binary, &home.0, &manifest, &["doctor"]);
    let stdout = text(&out.stdout);
    assert_eq!(
        stdout.lines().next().unwrap(),
        format!(
            "ok    version      {running}; v99.0.0 is out, with no build for this machine ({})",
            triple()
        ),
        "{stdout}"
    );

    let manifest = publish(
        &home.0,
        &Release {
            tag: &format!("v{}", env!("CARGO_PKG_VERSION")),
            ..Release::newer()
        },
    );
    let out = run(&binary, &home.0, &manifest, &["doctor"]);
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with(&format!(
            "ok    version      {running}; the latest release is v{} (same version; releases are compared by version, not by commit)\n",
            env!("CARGO_PKG_VERSION")
        )),
        "{stdout}"
    );

    let out = run(
        &binary,
        &home.0,
        &format!("file://{}", home.0.join("missing.json").display()),
        &["doctor"],
    );
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with(&format!(
            "ok    version      {running}; newer release not checked ("
        )),
        "{stdout}"
    );
}
