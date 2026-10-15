//! The Elixir resolution doors: the store mix confined through the proxy
//! session's Hex mirror for a missing lock, the planner's
//! `--check-locked` gate and `ward attest`, and the helper's mix.lock parse
//! confined with no route at all. Every run that evaluates mix.exs finds
//! the lock's git dependencies already checked out (`Checkouts`).

use super::check_locked::{check_locked_inputs, check_locked_passed, record_check_locked};
use super::door::{elixir_tool, run_mix, run_mix_checked, MixPublish, MixRun, OUTPUTS, SCRATCH};
use super::{err, read_mix_lock, require_lock, validate_plan, ElixirPlan, GitDep, HexDep, HELPER};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::record;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Executable mix manifests can load app manifests, nested configuration,
/// and arbitrary data. Cover every visible regular project file.
pub(crate) fn resolution_inputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    crate::kernel::resolve::inputs::project_files(project, &super::door::EXCLUDE, &OUTPUTS)
}

/// mix.exs, mix.lock and the config files, by digest: a closure's
/// `resolution_basis`.
pub(crate) fn resolution_basis(
    project: &ProjectRoot,
) -> io::Result<crate::comforter::join::Digests> {
    let mut listed: Vec<PathBuf> = OUTPUTS.iter().map(PathBuf::from).collect();
    listed.extend(resolution_inputs(project)?);
    record::file_digests(project, &listed)
}

/// `--no-archives-check` on every mix dependency command ward runs. A
/// project's `archives:` (nerves' `nerves_bootstrap`) names Mix archives a
/// developer installs for their own tasks; the confined mix has only Hex,
/// and fetching or locking dependencies never uses them.
pub(super) const NO_ARCHIVES_CHECK: &str = "--no-archives-check";

/// The words Mix raises with (`Mix.Dep.Lock.write`) when `mix deps.get
/// --check-locked` would rewrite the lock: the one failure that means mix.exs
/// has moved past mix.lock.
const STALE_LOCK: &str = "is out of date and must be updated without the --check-locked flag";

/// `prepare`: mix.lock, resolved by the store mix when there is none. The
/// one place the Elixir tailor writes project inputs. `mix deps.get`
/// runs confined through `door` (a missing-lock door), and mix.lock and the
/// signed resolution record are published together through its
/// transaction.
pub fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    ui::note("no mix.lock; resolving with the store mix...");
    deps_get(door, project, beam_obj, selected, &Checkouts::default())
}

/// The lock's git dependencies, checked out for a confined mix run:
/// `deps/<app>` in the run's deps path linked into the checkout object
/// (`git::realize_checkouts`), which the run reads. Mix finds each one at
/// its lock and fetches none, so no run needs the git host.
#[derive(Debug, Default)]
struct Checkouts {
    links: Vec<(PathBuf, PathBuf)>,
    reads: Vec<PathBuf>,
}

impl Checkouts {
    /// Realize `git`'s checkouts (recording `git-dependency` for each).
    fn of(door: &ResolutionDoor<'_>, git: &[GitDep]) -> io::Result<Self> {
        let object =
            super::git::realize_checkouts(door.store(), door.lease(), door.platform(), git)?;
        Ok(Checkouts {
            links: super::git::deps_links(object.as_deref(), git),
            reads: object.into_iter().collect(),
        })
    }

    /// The checkouts of the project's mix.lock, parsed offline first.
    fn of_lock(
        door: &mut ResolutionDoor<'_>,
        project: &ProjectRoot,
        beam_obj: &Path,
        basis: &crate::comforter::join::Digests,
    ) -> io::Result<Self> {
        let lock = read_mix_lock(project)?;
        let (_, git) = parse_lock(
            &mut door.reopen(DoorKind::Planner),
            project,
            beam_obj,
            &lock,
            basis,
        )?;
        Checkouts::of(door, &git)
    }
}

/// `prepare` for a project that has a mix.lock: the `--check-locked` gate,
/// and when mix says mix.exs has moved past the lock, `mix deps.get`
/// confined through `door`, the way Go's tailor runs `go mod tidy` for an
/// untidy go.mod. Mix keeps every locked version it can, so only what
/// mix.exs changed moves. The committed lock disagreed with its manifest,
/// so `lock-disagreement` is recorded before it is rewritten: a policy
/// denying the kind stops here with the lock untouched.
pub fn relock_if_stale(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    let observed = project.observing_inputs()?;
    let basis = resolution_basis(&observed)?;
    let lock = read_mix_lock(&observed)?;
    let checkouts = Checkouts::of_lock(door, &observed, beam_obj, &basis)?;
    let verdict = gate(
        &mut door.reopen(DoorKind::Planner),
        &observed,
        beam_obj,
        &lock,
        &basis,
        &checkouts,
    )?;
    let Gate::Stale(why) = verdict else {
        return Ok(());
    };
    crate::kernel::policy::record(
        crate::kernel::policy::LOCK_DISAGREEMENT,
        "mix.lock",
        &format!(
            "mix deps.get --check-locked: {}; re-resolved with the store mix deps.get",
            why.lines().last().unwrap_or("").trim()
        ),
    )?;
    ui::note("mix.lock is out of date with mix.exs; resolving with the store mix...");
    deps_get(door, project, beam_obj, selected, &checkouts)
}

/// `mix deps.get` confined through `door`, publishing mix.lock with its
/// resolution record.
fn deps_get(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
    checkouts: &Checkouts,
) -> io::Result<()> {
    let basis = resolution_basis(project)?;
    let args = ["mix", "deps.get", NO_ARCHIVES_CHECK];
    let spec = crate::tailors::record_spec(
        &super::tailor::Elixir,
        project,
        elixir_tool(selected)?,
        &args[1..],
    )?;
    run_mix_checked(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &args,
            online: true,
            inputs: Some(&basis),
            files: Vec::new(),
            links: checkouts.links.clone(),
            reads: checkouts.reads.clone(),
            publish: MixPublish::Project {
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(())
}

/// `ward update` for Elixir: `mix deps.update` through the edit door, which
/// publishes mix.lock with its record.
pub(crate) fn update(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
    args: &[&str],
) -> io::Result<()> {
    let basis = resolution_basis(project)?;
    let checkouts = if require_lock(project).is_ok() {
        Checkouts::of_lock(door, project, beam_obj, &basis)?
    } else {
        Checkouts::default()
    };
    let mut args = args.to_vec();
    args.push(NO_ARCHIVES_CHECK);
    let args = &args[..];
    let spec = crate::tailors::record_spec(
        &super::tailor::Elixir,
        project,
        elixir_tool(selected)?,
        &args[1..],
    )?;
    run_mix_checked(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args,
            online: true,
            inputs: Some(&basis),
            files: Vec::new(),
            links: checkouts.links,
            reads: checkouts.reads,
            publish: MixPublish::Project {
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(())
}

/// What the consistency gate found.
#[derive(Debug)]
pub(super) enum Gate {
    /// mix.exs and mix.lock agree.
    InSync,
    /// mix would rewrite the lock; mix's own report.
    Stale(String),
}

/// The consistency gate: `mix deps.get --check-locked`, exit status only
/// (it evaluates mix.exs, delegated trust and never artifact authority).
/// It needs the Hex registry, so it reaches the mirror. Its Hex home is
/// private scratch: project code must never seed configuration or code for
/// another run. Registry reuse belongs to the proxy cache. Nothing in the
/// project may change.
fn check_locked(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    basis: &crate::comforter::join::Digests,
    checkouts: &Checkouts,
) -> io::Result<Gate> {
    let out = run_mix(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &["mix", "deps.get", "--check-locked", NO_ARCHIVES_CHECK],
            online: true,
            inputs: Some(basis),
            files: Vec::new(),
            links: checkouts.links.clone(),
            reads: checkouts.reads.clone(),
            publish: MixPublish::Detached,
        },
    )?;
    classify_check(out.status.success(), &String::from_utf8_lossy(&out.stderr))
}

/// [`check_locked`]'s reading of mix's exit status and stderr. Only Mix's
/// own stale-lock words make the lock stale. Any other failure (a manifest
/// that does not evaluate, a dependency mix cannot fetch) is mix failing to
/// check, and says so with mix's report: it is no verdict on the lock.
fn classify_check(success: bool, stderr: &str) -> io::Result<Gate> {
    if success {
        return Ok(Gate::InSync);
    }
    let stderr = stderr.trim();
    if stderr.contains(STALE_LOCK) {
        return Ok(Gate::Stale(stderr.to_string()));
    }
    Err(err(format!(
        "mix could not check mix.lock against mix.exs: `mix deps.get --check-locked` \
         failed before comparing them\n{stderr}"
    )))
}

/// The gate, skipped when its inputs are unchanged since it last passed
/// (equal input hashes give the same answer). A pass is recorded only when
/// the inputs still hash the same after the check, so the record names the
/// bytes the check actually read.
fn gate(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    lock: &str,
    basis: &crate::comforter::join::Digests,
    checkouts: &Checkouts,
) -> io::Result<Gate> {
    let bind = |input: String, basis: &crate::comforter::join::Digests| {
        format!(
            "canonical-project-v1:{input}:{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(basis).expect("string map")
            ))
        )
    };
    let inputs = check_locked_inputs(project, beam_obj, lock)?.map(|input| bind(input, basis));
    if let Some(inputs) = &inputs {
        if check_locked_passed(door.store(), project, inputs)? {
            ui::trace("mix.exs and mix.lock unchanged since their last passing check");
            return Ok(Gate::InSync);
        }
    }
    let verdict = check_locked(door, project, beam_obj, basis, checkouts)?;
    if matches!(verdict, Gate::InSync) {
        let after_basis = resolution_basis(project)?;
        let after = check_locked_inputs(project, beam_obj, &read_mix_lock(project)?)?
            .map(|input| bind(input, &after_basis));
        if let (Some(before), Some(after)) = (&inputs, &after) {
            if before == after {
                record_check_locked(door.store(), door.lease(), project, before);
            }
        }
    }
    Ok(verdict)
}

/// The refusal for a lock the gate finds stale at planning time: `prepare`
/// would have re-resolved it, and the command layer skips `prepare` under
/// `--frozen`.
fn stale_lock(project: &ProjectRoot, why: &str) -> io::Error {
    crate::kernel::error::stale(
        io::ErrorKind::InvalidData,
        format!(
            "mix.lock in {} is out of date with mix.exs and --frozen never updates it; run \
             `ward` once without --frozen and commit the result\n{why}",
            project.path().display()
        ),
    )
}

/// The helper's strict parse of `lock`, confined with no route: the helper
/// and a copy of the bytes read through the held descriptor are handed to
/// the run, so what it parses is exactly what the plan hashes.
fn parse_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    lock: &str,
    basis: &crate::comforter::join::Digests,
) -> io::Result<(Vec<HexDep>, Vec<GitDep>)> {
    let helper = format!("{SCRATCH}/helper.exs");
    let lock_copy = format!("{SCRATCH}/mix.lock");
    let out = run_mix(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &["elixir", &helper, "lock", &lock_copy],
            online: false,
            inputs: Some(basis),
            files: vec![
                (PathBuf::from("helper.exs"), HELPER.as_bytes().to_vec()),
                (PathBuf::from("mix.lock"), lock.as_bytes().to_vec()),
            ],
            links: Vec::new(),
            reads: Vec::new(),
            publish: MixPublish::Detached,
        },
    )?;
    if !out.status.success() {
        return Err(err(format!(
            "mix.lock analysis failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    #[derive(Deserialize)]
    struct HelperOut {
        entries: Vec<HexDep>,
        #[serde(default)]
        git: Vec<GitDep>,
    }
    let parsed: HelperOut =
        serde_json::from_slice(&out.stdout).map_err(|e| err(format!("helper output: {e}")))?;
    Ok((parsed.entries, parsed.git))
}

/// Plan: AST-parse mix.lock under the pinned toolchain (lock-only, no
/// eval), then the `--check-locked` gate unless its inputs are unchanged
/// since it last passed. The project is read through the held descriptor.
/// Returns the plan, the lock's sha256, and the resolution basis.
pub fn plan_elixir(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<(ElixirPlan, String, crate::comforter::join::Digests)> {
    let observed = project.observing_inputs()?;
    let project = &observed;
    let basis = resolution_basis(project)?;
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    require_lock(project)?;
    let lock = read_mix_lock(project)?;
    // The lock is read first, offline: an entry ward cannot realize is
    // refused by name before mix evaluates anything.
    let (mut deps, mut git) = parse_lock(door, project, beam_obj, &lock, &basis)?;
    let checkouts = Checkouts::of(door, &git)?;
    if let Gate::Stale(why) = gate(door, project, beam_obj, &lock, &basis, &checkouts)? {
        return Err(stale_lock(project, &why));
    }
    deps.sort_by(|a, b| a.app.cmp(&b.app));
    git.sort_by(|a, b| a.app.cmp(&b.app));
    let plan = ElixirPlan {
        // The toolchain this plan was made under is the selected one, so
        // the plan records the selection's versions, never the shipped pins.
        otp_version: selected.version("otp")?.to_string(),
        elixir_version: selected.version("elixir")?.to_string(),
        deps,
        git,
    };
    validate_plan(&plan)?;
    if read_mix_lock(project)? != lock {
        return Err(err("mix.lock changed while planning; re-run 'ward'"));
    }
    // The resolution files this plan was built from, so the resolution
    // join binds a record to this generation of mix.exs and its lock.
    project.verify_observed_inputs()?;
    if resolution_basis(project)? != basis {
        return Err(err(
            "Elixir resolution inputs changed while planning; run `ward` again",
        ));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes())), basis))
}

/// `ward attest` for Elixir: `mix deps.get --check-locked` in the project
/// through `door`'s transaction with the record's producer. A mix.exs the
/// lock no longer matches fails the check; a lock it would rewrite anyway
/// is refused by the record. Nothing is published here.
pub fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    require_lock(project)?;
    let basis = resolution_basis(project)?;
    let checkouts = Checkouts::of_lock(door, project, beam_obj, &basis)?;
    let args = ["mix", "deps.get", "--check-locked", NO_ARCHIVES_CHECK];
    let mut spec = crate::tailors::record_spec(
        &super::tailor::Elixir,
        project,
        elixir_tool(selected)?,
        &args[1..],
    )?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = run_mix(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &args,
            online: true,
            inputs: Some(&basis),
            files: Vec::new(),
            links: checkouts.links,
            reads: checkouts.reads,
            publish: MixPublish::Project {
                receipt: Some(record::producer(spec, slot.clone())),
            },
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "mix.lock in {} is not what mix deps.get would write, so it is not attested; \
             run `ward` to bring it up to date and commit the result\n{}",
            project.path().display(),
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("mix's lock check published no record"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::ledger::{self, Entry, LedgerObjects};
    use crate::kernel::resolve::testing::{relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC};
    use crate::kernel::resolve::DoorKind;
    use crate::kernel::testutil::TempDir;
    use crate::tailors::elixir::registry::{self, REPO_HOST};
    use std::fs;

    #[test]
    fn basis_refuses_a_lock_or_manifest_replaced_after_consumption() {
        let temp = TempDir::named("elixir-basis-race");
        fs::write(temp.0.join("mix.exs"), "manifest A").unwrap();
        fs::write(temp.0.join("mix.lock"), "lock A").unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let observed = held.observing_inputs().unwrap();
        resolution_basis(&observed).unwrap();
        fs::write(temp.0.join("mix.lock"), "lock B").unwrap();
        assert!(resolution_basis(&observed).is_err());
        let observed = held.observing_inputs().unwrap();
        resolution_basis(&observed).unwrap();
        fs::write(temp.0.join("mix.exs"), "manifest B").unwrap();
        assert!(resolution_basis(&observed).is_err());
    }

    #[test]
    fn an_included_manifest_change_or_new_file_invalidates_the_basis() {
        let temp = TempDir::named("elixir-included-input");
        fs::create_dir_all(temp.0.join("apps/web/mix.exs").parent().unwrap()).unwrap();
        fs::write(temp.0.join("mix.exs"), "manifest").unwrap();
        fs::write(temp.0.join("mix.lock"), "lock").unwrap();
        fs::write(temp.0.join("apps/web/mix.exs"), "included manifest A").unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let basis = resolution_basis(&held).unwrap();
        assert!(basis.contains_key("apps/web/mix.exs"));
        fs::write(temp.0.join("apps/web/mix.exs"), "included manifest B").unwrap();
        let files = crate::tailors::resolution_files(&super::super::tailor::Elixir, &held)
            .unwrap()
            .unwrap();
        assert!(
            crate::comforter::join::check_basis_for_test(&held, "elixir", &files, &basis).is_err()
        );
        let basis = resolution_basis(&held).unwrap();
        fs::write(temp.0.join("new-data.txt"), "new input").unwrap();
        let files = crate::tailors::resolution_files(&super::super::tailor::Elixir, &held)
            .unwrap()
            .unwrap();
        assert!(
            crate::comforter::join::check_basis_for_test(&held, "elixir", &files, &basis).is_err()
        );
    }

    /// A harness whose upstream answers repo.hex.pm from the recorded Hex
    /// rows, and whose proxy every door in this thread uses while it
    /// lives. builds.hex.pm is not served: no route permits it.
    fn hex_harness(label: &str, corrupt: bool) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(20);
        let rows = stored_rows("elixir", label);
        if corrupt {
            use std::io::{Read, Write};
            let body_path = rows.0.join("repo.hex.pm/packages/jason.body");
            let body = fs::read(&body_path).unwrap();
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(body.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            *decoded.last_mut().unwrap() ^= 1;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&decoded).unwrap();
            let corrupt = encoder.finish().unwrap();
            fs::write(body_path, &corrupt).unwrap();
            let index_path = rows.0.join("index.json");
            let mut index: Vec<serde_json::Value> =
                serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
            for row in &mut index {
                if row["url"] == "https://repo.hex.pm/packages/jason" {
                    row["sha256"] = hex::encode(Sha256::digest(&corrupt)).into();
                    row["size"] = corrupt.len().into();
                }
            }
            fs::write(index_path, serde_json::to_vec(&index).unwrap()).unwrap();
        }

        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            &[REPO_HOST, registry::API_HOST],
            &rows.0.to_string_lossy(),
        )));
        std::mem::forget(rows);
        PROXY_FOR_TEST.with(|slot| slot.set(Some(&harness.proxy)));
        Some(harness)
    }

    fn done() {
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        PROXY_FOR_TEST.with(|slot| slot.set(None));
    }

    fn through_door<T>(
        harness: &Harness,
        kind: DoorKind,
        job: impl FnOnce(&mut ResolutionDoor<'_>) -> T,
    ) -> (T, Vec<Exception>) {
        let mut attribution = Attribution::open("elixir").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            kind,
            &mut attribution,
        )
        .unwrap();
        let out = job(&mut door);
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        (out, recorded)
    }

    fn entries(harness: &Harness, objects: &LedgerObjects) -> Vec<Entry> {
        let portable = ledger::PortableLedger::parse(
            &ledger::read_portable(&harness.store, &objects.ledger).unwrap(),
        )
        .unwrap();
        portable.entries().cloned().collect()
    }

    fn manifest(deps: &str) -> String {
        format!(
            "defmodule Demo.MixProject do\n  use Mix.Project\n\n  def project do\n    \
             [app: :demo, version: \"0.1.0\", deps: [{deps}]]\n  end\nend\n"
        )
    }

    /// The whole Elixir door against the recorded repo.hex.pm: a missing
    /// lock resolved by `mix deps.get` through the Hex mirror, the
    /// planner's `--check-locked` gate through it and the helper's lock
    /// parse with no route at all, and `ward attest`'s check: an unchanged
    /// lock signed, a drifted mix.exs refused.
    #[test]
    #[ignore = "realizes the store BEAM over the network"]
    fn mix_resolves_through_the_hex_mirror() {
        let _env = policy::test_env_lock();
        let _serial = policy::attribution_test_lock();
        let label = "mix_resolves_through_the_hex_mirror";
        let Some(harness) = hex_harness(label, false) else {
            return;
        };
        let selected = super::super::shipped_selection().unwrap();
        let beam = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        let temp = TempDir::named("elixir-mirror");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("mix.exs"),
            manifest(
                "(if File.dir?(\"feature\"), do: {:telemetry, \"1.4.2\"}, else: {:jason, \"1.4.5\"})",
            ),
        )
        .unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();

        let (generated, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &held, &beam, &selected)
        });
        generated.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join("mix.lock")).unwrap();
        assert!(
            lock.contains("\"jason\": {:hex, :jason, \"1.4.5\""),
            "{lock}"
        );
        assert!(dir.join(".greyward/resolution/elixir.json").is_file());

        let direct = temp.0.join("direct");
        let direct_home = temp.0.join("direct-home");
        fs::create_dir_all(&direct).unwrap();
        fs::create_dir_all(&direct_home).unwrap();
        fs::copy(dir.join("mix.exs"), direct.join("mix.exs")).unwrap();
        let ca = temp.0.join("fixture-ca.pem");
        fs::write(&ca, harness.upstream_ca_pem()).unwrap();
        let forwarder =
            crate::kernel::resolve::testing::blind_forwarder(harness.upstream.address());
        let direct_result = std::process::Command::new(beam.join("elixir/bin/mix"))
            .args(["deps.get"])
            .current_dir(&direct)
            .env_clear()
            .envs(super::super::forced_env(
                &beam,
                &direct_home.join("deps"),
                &direct_home,
            ))
            .env_remove("HEX_OFFLINE")
            .env("https_proxy", format!("http://{forwarder}"))
            .env("HEX_CACERTS_PATH", &ca)
            .env("HOME", &direct_home)
            .env("PATH", super::super::beam_path(&beam))
            .output()
            .unwrap();
        assert!(
            direct_result.status.success(),
            "{}",
            String::from_utf8_lossy(&direct_result.stderr)
        );
        assert_eq!(fs::read(direct.join("mix.lock")).unwrap(), lock.as_bytes());

        assert!(
            !dir.join("deps").exists(),
            "deps were fetched into the project"
        );

        // A prior project's writable Hex home must never enter this run.
        let shared = harness.store.root.join("planner-hexhome");
        fs::create_dir_all(&shared).unwrap();
        let marker = dir.join("cross-project-code-ran");
        fs::write(
            shared.join("hex.config"),
            format!(
                "File.write!({:?}, \"injected\"); []",
                marker.to_str().unwrap()
            ),
        )
        .unwrap();
        let ((planned, ledgers), recorded) = through_door(harness, DoorKind::Planner, |door| {
            let planned = plan_elixir(door, &held, &beam, &selected);
            (planned, door.take_kept_ledgers())
        });
        let (plan, _, basis) = planned.unwrap();
        assert!(
            !marker.exists(),
            "a previous project injected Hex config code"
        );
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(plan.deps.len(), 1, "{:?}", plan.deps);
        assert_eq!(plan.deps[0].version, "1.4.5");
        assert!(basis.contains_key("mix.lock"), "{basis:?}");
        assert_eq!(
            ledgers.len(),
            2,
            "the parse and the gate each leave a ledger"
        );
        assert!(entries(harness, &ledgers[0]).is_empty());
        let gate = entries(harness, &ledgers[1]);
        assert!(
            gate.iter()
                .any(|e| e.url == "https://repo.hex.pm/packages/jason"),
            "{gate:?}"
        );

        let (attested, recorded) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &beam, &selected)
        });
        let (record, _) = attested.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(record.outputs.len(), 2, "{:?}", record.outputs);

        // Empty directory presence and host permissions must never change
        // executable-manifest semantics in the canonical project view.
        fs::create_dir(dir.join("feature")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("mix.exs"), fs::Permissions::from_mode(0o700)).unwrap();
        let (replanned, _) = through_door(harness, DoorKind::Planner, |door| {
            plan_elixir(door, &held, &beam, &selected)
        });
        assert_eq!(replanned.unwrap().0.deps[0].package, "jason");
        let (reattested, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &beam, &selected)
        });
        reattested.unwrap();
        assert!(dir.join("feature").is_dir());
        assert_eq!(
            fs::metadata(dir.join("mix.exs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let (updated, recorded) = through_door(harness, DoorKind::Edit, |door| {
            update(
                door,
                &held,
                &beam,
                &selected,
                &["mix", "deps.update", "jason"],
            )
        });
        updated.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(fs::read(dir.join("mix.lock")).unwrap(), lock.as_bytes());
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(dir.join(".greyward/resolution/elixir.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receipt["command"],
            serde_json::json!(["mix", "deps.update", "jason", "--no-archives-check"])
        );

        fs::write(
            dir.join("mix.exs"),
            manifest("{:jason, \"1.4.5\"}, {:telemetry, \"1.4.2\"}"),
        )
        .unwrap();
        let before = fs::read(dir.join("mix.lock")).unwrap();
        let (drifted, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &beam, &selected)
        });
        let why = drifted.unwrap_err().to_string();
        assert!(why.contains("not attested"), "{why}");
        assert_eq!(fs::read(dir.join("mix.lock")).unwrap(), before);

        // The planner names a stale lock as stale (what --frozen sees),
        // and `prepare` re-resolves it, recording the disagreement.
        let (stale, _) = through_door(harness, DoorKind::Planner, |door| {
            plan_elixir(door, &held, &beam, &selected)
        });
        let why = stale.unwrap_err().to_string();
        assert!(why.contains("out of date with mix.exs"), "{why}");
        let (relocked, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            relock_if_stale(door, &held, &beam, &selected)
        });
        relocked.unwrap();
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].kind, policy::LOCK_DISAGREEMENT);
        let lock = fs::read_to_string(dir.join("mix.lock")).unwrap();
        assert!(
            lock.contains("\"telemetry\": {:hex, :telemetry, \"1.4.2\""),
            "{lock}"
        );
        let (replanned, _) = through_door(harness, DoorKind::Planner, |door| {
            plan_elixir(door, &held, &beam, &selected)
        });
        assert_eq!(replanned.unwrap().0.deps.len(), 2);
        // An in-sync lock is left alone and records nothing.
        let (again, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            relock_if_stale(door, &held, &beam, &selected)
        });
        again.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(fs::read_to_string(dir.join("mix.lock")).unwrap(), lock);
        done();
    }

    #[test]
    fn only_mixs_stale_lock_words_make_a_lock_stale() {
        assert!(matches!(classify_check(true, ""), Ok(Gate::InSync)));
        let stale = "Resolving Hex dependencies...\n** (Mix) Your mix.lock is out of date \
                     and must be updated without the --check-locked flag\n";
        assert!(matches!(classify_check(false, stale), Ok(Gate::Stale(_))));
        // A fetch mix could not make is no verdict on the lock.
        let why = classify_check(
            false,
            "** (Mix) Command \"git --git-dir=.git fetch --force --quiet\" failed",
        )
        .unwrap_err()
        .to_string();
        assert!(why.contains("could not check"), "{why}");
        assert!(!why.contains("out of sync"), "{why}");
        assert!(why.contains("git --git-dir"), "{why}");
    }

    #[test]
    #[ignore = "realizes the store BEAM over the network"]
    fn mix_refuses_a_corrupted_registry_signature() {
        let _env = policy::test_env_lock();
        let _serial = policy::attribution_test_lock();
        let Some(harness) = hex_harness("hex-corrupt-signature", true) else {
            return;
        };
        let selected = super::super::shipped_selection().unwrap();
        let beam = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        let temp = TempDir::named("hex-corrupt-project");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("mix.exs"), manifest("{:jason, \"1.4.5\"}")).unwrap();
        let held = ProjectRoot::open(&dir).unwrap();
        let (result, _) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &held, &beam, &selected)
        });
        let why = result.unwrap_err().to_string();
        assert!(why.to_ascii_lowercase().contains("signature"), "{why}");
        assert!(!dir.join("mix.lock").exists());
        assert!(!dir.join(".greyward/resolution/elixir.json").exists());
        done();
    }
}
