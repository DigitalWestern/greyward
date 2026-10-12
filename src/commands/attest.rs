//! `ward attest [<ecosystem>...]`: give existing locks a signed resolution
//! record, and move a record's ledger between machines.
//!
//! Attesting runs in two phases. First, each ecosystem's own lock check
//! runs through a verification door (its `Tailor::attester`), publishing
//! nothing: a check that leaves the lock and manifest byte-unchanged yields
//! a record signed with the process key. Only when every check passed does
//! the second phase write them: as the project's receipts
//! (`.greyward/resolution/<ecosystem>.json`, through `record::publish_receipts`,
//! all or nothing, under the project lock, and only while each lock still
//! reads as its record signed it), or with `--record-out` outside the
//! checkout, which is then left unchanged. A failed check therefore leaves
//! no receipt behind, whichever ecosystem it was, and a failed publication
//! puts back the receipts it already wrote. A process killed between two
//! publications can leave a partial set; each receipt in it still attests
//! its own lock, and rerunning `ward attest` completes it.
//!
//! The ledger transfers never run a tool. `--ledger-export` writes the
//! portable bytes of the ledger the committed record names, from the local
//! store. `--ledger-import` stores portable bytes only when an attesting
//! record in this project names exactly those bytes, then roots the object
//! under the project so the next closure write retains it.

use crate::cli::{Command, LedgerTransfer};
use crate::comforter::join;
use crate::comforter::toolchain::Mode;
use crate::commands::shared::no_inputs;
use crate::commands::sync::{preflight_sync, Scope};
use crate::kernel::context::{self, Context};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::record::{self, Judgment, ResolutionRecord};
use crate::kernel::resolve::{transaction, DoorKind, ResolutionDoor};
use crate::kernel::ui;
use crate::tailors::{self, Attester, Tailor};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Run `ward attest` as parsed. It validates the host, preflights the
/// project, and loads the signing key itself, before it opens the store.
pub fn run(command: Command) -> io::Result<i32> {
    let Command::Attest {
        ecosystems,
        record_out,
        ledger,
    } = command
    else {
        unreachable!("dispatch hands attest only its own command");
    };
    let platform = Platform::host()?;
    let project = ProjectRoot::open(&context::project_dir()?)?;
    let _policy = policy::init_in(&project)?;
    match ledger {
        Some(LedgerTransfer::Export { ecosystem, file }) => {
            export_ledger(platform, &project, &ecosystem, &file)
        }
        Some(LedgerTransfer::Import { file }) => import_ledger(platform, &project, &file),
        None => attest(platform, &project, &ecosystems, record_out.as_deref()),
    }?;
    Ok(0)
}

/// One ecosystem to attest, with the lock check that attests it.
struct Target {
    tailor: &'static dyn Tailor,
    attester: &'static dyn Attester,
}

/// Why `tailor` cannot be attested in `project`, or its lock check: it
/// needs both an attester and a lock that a resolution door produces.
fn attestable(
    tailor: &'static dyn Tailor,
    project: &ProjectRoot,
) -> io::Result<Result<Target, String>> {
    let Some(attester) = tailor.attester() else {
        return Ok(Err(
            "it has no lock check that runs through a resolution door".into(),
        ));
    };
    if tailors::resolution_files(tailor, project)?.is_none() {
        return Ok(Err(
            "it has no lock that a resolution door produces, so there is nothing to sign".into(),
        ));
    }
    Ok(Ok(Target { tailor, attester }))
}

/// The tailors to attest: the named ones, or every detected ecosystem that
/// can be attested. A named ecosystem that is not here, or cannot be
/// attested, is refused before any work.
fn targets(
    project: &ProjectRoot,
    present: &[&'static dyn Tailor],
    named: &[String],
) -> io::Result<Vec<Target>> {
    let mut targets = Vec::new();
    if named.is_empty() {
        for tailor in present {
            if let Ok(target) = attestable(*tailor, project)? {
                targets.push(target);
            }
        }
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "nothing to attest in {}: no ecosystem found here has a lock that a \
                     resolution door produces and checks",
                    project.path().display()
                ),
            ));
        }
        return Ok(targets);
    }
    for id in named {
        let Some(tailor) = present.iter().copied().find(|tailor| tailor.id() == id) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no {id} project in {}", project.path().display()),
            ));
        };
        match attestable(tailor, project)? {
            Ok(target) => targets.push(target),
            Err(why) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("ward attest does not support {id}: {why}"),
                ))
            }
        }
    }
    Ok(targets)
}

/// The front of `ward attest`, in order: choose the targets, then
/// `preflight` the scope they name, then `open` the store. A refused
/// selection returns before either runs.
fn select_then_open<T, C>(
    project: &ProjectRoot,
    present: &[&'static dyn Tailor],
    named: &[String],
    preflight: impl FnOnce(Scope<'_>) -> io::Result<T>,
    open: impl FnOnce() -> io::Result<C>,
) -> io::Result<(Vec<Target>, T, C)> {
    let targets = targets(project, present, named)?;
    let ids: Vec<&str> = targets.iter().map(|target| target.tailor.id()).collect();
    let toolchain = preflight(Scope::Selected(&ids))?;
    let ctx = open()?;
    Ok((targets, toolchain, ctx))
}

fn attest(
    platform: Platform,
    project: &ProjectRoot,
    named: &[String],
    record_out: Option<&Path>,
) -> io::Result<()> {
    let _signing = crate::comforter::init_signing()?;
    if record_out.is_some() && crate::comforter::signing_key().is_none() {
        // The CI flow hands this file to a later sync, which attests only a
        // signed record: an unsigned one would be written, uploaded, and
        // then never count.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--record-out writes a record for another machine's sync, which attests only a \
             signed one, and GREYWARD_SIGNING_KEY is not set; export GREYWARD_SIGNING_KEY=<key file the \
             sync's machine policy trusts>",
        ));
    }
    let present = tailors::detected_in(project)?;
    if present.is_empty() {
        return Err(no_inputs());
    }
    let (targets, toolchain, ctx) = select_then_open(
        project,
        &present,
        named,
        // The committed toolchain lock names the tool; attesting never
        // writes one, so the lock is read the way `--frozen` reads it.
        |scope| preflight_sync(platform, project, Mode::Frozen, scope).map(|(_, lock)| lock),
        || Context::open(platform),
    )?;
    // An interrupted publication is finished or undone before any check
    // reads the lock it was replacing.
    transaction::recover_project(&ctx.store, &ctx.activity, project.path())?;
    project.check_still_named()?;
    if crate::comforter::signing_key().is_none() {
        ui::warning(
            "resolution records written unsigned: GREYWARD_SIGNING_KEY is not set, so no sync \
             will attest them",
            "export GREYWARD_SIGNING_KEY=<key file your machine policy trusts>",
        );
    }
    let ids: Vec<&str> = targets.iter().map(|target| target.tailor.id()).collect();
    let host = crate::commands::shared::CommandHost { platform };
    check_then_publish(
        &ids,
        |id| {
            let Target { tailor, attester } = targets
                .iter()
                .find(|target| target.tailor.id() == id)
                .expect("the ids are the targets'");
            let selected = toolchain.get(tailor.lock_ecosystem())?;
            // The door records its run's exceptions (a tier's
            // `unconfined-resolution`) into this scope, and the record
            // carries them; attesting publishes no closure, so the scope is
            // discarded.
            let mut attribution = policy::Attribution::open(tailor.id())?;
            let checked = ResolutionDoor::open(
                &ctx.store,
                &ctx.activity,
                platform,
                DoorKind::Attest,
                &mut attribution,
            )
            .and_then(|mut door| attester.attest_lock(&ctx, project, selected, &host, &mut door));
            attribution.discard();
            checked
        },
        |records| match record_out {
            Some(out) => {
                for (record, bytes) in records {
                    let written = write_record(record, bytes, out, named.len() == 1)?;
                    written_note(record, &written);
                }
                Ok(())
            }
            None => {
                record::publish_receipts(&ctx.store, &ctx.activity, project, records)?;
                for (record, _) in records {
                    written_note(
                        record,
                        &project.path().join(record::receipt_path(&record.ecosystem)),
                    );
                }
                Ok(())
            }
        },
    )
}

/// The two phases of attesting `ids`, in order: `check` each one, which
/// publishes nothing, then `publish` every record only once all passed. A
/// failed check stops before anything is written, so no ecosystem's
/// receipt or `--record-out` file is left behind for a partial set.
fn check_then_publish(
    ids: &[&str],
    mut check: impl FnMut(&str) -> io::Result<(ResolutionRecord, Vec<u8>)>,
    publish: impl FnOnce(&[(ResolutionRecord, Vec<u8>)]) -> io::Result<()>,
) -> io::Result<()> {
    let mut records = Vec::new();
    for id in ids {
        let (record, bytes) = check(id)?;
        if record.ecosystem != *id {
            return Err(io::Error::other(format!(
                "the {id} lock check returned a {} record",
                record.ecosystem
            )));
        }
        records.push((record, bytes));
    }
    publish(&records)
}

fn written_note(record: &ResolutionRecord, to: &Path) {
    ui::note(&format!(
        "attest: {} {} record ({} {}) written to {}",
        record.ecosystem,
        record.door,
        record.tool.name,
        record.tool.version,
        to.display()
    ));
}

/// Write one signed record for `--record-out`: to `out` itself when
/// exactly one ecosystem was named, else to `<out>/<ecosystem>.json`.
/// Returns where it went.
fn write_record(
    record: &ResolutionRecord,
    bytes: &[u8],
    out: &Path,
    one_named: bool,
) -> io::Result<PathBuf> {
    let path = if one_named {
        out.to_path_buf()
    } else {
        fs::create_dir_all(out).map_err(|error| {
            io::Error::new(error.kind(), format!("create {}: {error}", out.display()))
        })?;
        out.join(format!("{}.json", record.ecosystem))
    };
    fs::write(&path, bytes).map_err(|error| {
        io::Error::new(error.kind(), format!("write {}: {error}", path.display()))
    })?;
    Ok(path)
}

fn export_ledger(
    platform: Platform,
    project: &ProjectRoot,
    ecosystem: &str,
    file: &Path,
) -> io::Result<()> {
    let receipt = project.path().join(record::receipt_path(ecosystem));
    let bytes = record::read_receipt(project, ecosystem)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} does not exist, so no ledger is named; run 'ward attest {ecosystem}' first",
                receipt.display()
            ),
        )
    })?;
    let record = record::parse_unverified(&bytes, ecosystem).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not a resolution record: {reason}", receipt.display()),
        )
    })?;
    let ctx = Context::open(platform)?;
    let portable = record::read_ledger(&ctx.store, &ctx.activity, &record)?;
    fs::write(file, &portable).map_err(|error| {
        io::Error::new(error.kind(), format!("write {}: {error}", file.display()))
    })?;
    ui::note(&format!(
        "attest: wrote the {ecosystem} ledger {} ({} bytes) to {}",
        record.ledger.object,
        portable.len(),
        file.display()
    ));
    Ok(())
}

/// The attesting committed record in `project` whose ledger is exactly
/// `portable`, judged as the sync's join judges it.
fn attesting_record_for(
    project: &ProjectRoot,
    portable: &[u8],
) -> io::Result<Option<ResolutionRecord>> {
    let trusted = join::trusted_keys(&policy::effective());
    for tailor in tailors::detected_in(project)? {
        let Some(files) = tailors::resolution_files(tailor, project)? else {
            continue;
        };
        let Some(bytes) = record::read_receipt(project, tailor.id())? else {
            continue;
        };
        let origin = project
            .path()
            .join(record::receipt_path(tailor.id()))
            .display()
            .to_string();
        if let Judgment::Attests(attested) =
            record::judge(&origin, &bytes, tailor.id(), &trusted, &files, project)?
        {
            if record::describes_ledger(&attested.record, portable) {
                return Ok(Some(attested.record));
            }
        }
    }
    Ok(None)
}

fn import_ledger(platform: Platform, project: &ProjectRoot, file: &Path) -> io::Result<()> {
    let portable = fs::read(file).map_err(|error| {
        io::Error::new(error.kind(), format!("read {}: {error}", file.display()))
    })?;
    let Some(record) = attesting_record_for(project, &portable)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is not the ledger of any attesting resolution record in {} (its sha256 is \
                 {}); import the ledger the committed record names, on a machine whose policy \
                 trusts the record's key",
                file.display(),
                project.path().display(),
                record::portable_sha256(&portable)
            ),
        ));
    };
    let ctx = Context::open(platform)?;
    let objects = record::commit_ledger(&ctx.store, &ctx.activity, &record, &portable)?;
    // Root it under the project now; the next closure write retains it
    // through the closure's references.
    crate::kernel::resolve::ledger::root(&ctx.store, &ctx.activity, project, &objects)?;
    let id = objects.ledger;
    ui::note(&format!(
        "attest: stored the {} ledger {id} and rooted it under {}",
        record.ecosystem,
        project.path().display()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::resolve::ledger::{Entry, PortableLedger};
    use crate::kernel::resolve::record::{
        file_digests, Isolation, LedgerSummary, RecordDoor, RecordFacts, Tool,
        FAIL_PUBLISH_FOR_TEST,
    };
    use crate::kernel::store::Store;
    use crate::kernel::testutil::TempDir;
    use std::sync::Mutex;

    /// `FAIL_PUBLISH_FOR_TEST` is process-global: the tests that publish
    /// run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        _temp: TempDir,
        store: Store,
        dir: PathBuf,
    }

    /// A store, and a project with one lock file per fake ecosystem.
    fn fixture(label: &str) -> Fixture {
        let temp = TempDir::named(&format!("attest-{label}"));
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp", "roots", "root-locks", "forests"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        for ecosystem in ["alpha", "beta"] {
            fs::write(dir.join(format!("{ecosystem}.lock")), "pinned 1.0.0\n").unwrap();
        }
        Fixture {
            store: Store::for_test(root.canonicalize().unwrap()),
            dir: dir.canonicalize().unwrap(),
            _temp: temp,
        }
    }

    /// What a passing check of `ecosystem` returns: a record over its lock
    /// as it is now.
    fn checked(dir: &Path, ecosystem: &str) -> (ResolutionRecord, Vec<u8>) {
        let project = ProjectRoot::open(dir).unwrap();
        let mut ledger = PortableLedger::new(ecosystem, "attest").unwrap();
        ledger.insert(Entry {
            class: "metadata".into(),
            method: "GET".into(),
            url: "https://registry.example/pinned".into(),
            status: 200,
            sha256: None,
            claimed: None,
            verified: false,
            freshness: None,
            redirected_to: None,
        });
        let record = ResolutionRecord::new(RecordFacts {
            ecosystem: ecosystem.into(),
            door: RecordDoor::Attest,
            tool: Tool {
                name: format!("{ecosystem}pm"),
                version: "1.0.0".into(),
            },
            command: vec!["check".into()],
            outputs: file_digests(&project, &[PathBuf::from(format!("{ecosystem}.lock"))]).unwrap(),
            inputs: Default::default(),
            ledger: LedgerSummary::of(&ledger.identity().object_id(), &ledger),
            isolation: Isolation::Confined,
            exceptions: Vec::new(),
        })
        .unwrap();
        let bytes = record::envelope_bytes(&record.envelope(None).unwrap()).unwrap();
        (record, bytes)
    }

    fn receipt(dir: &Path, ecosystem: &str) -> Option<Vec<u8>> {
        fs::read(dir.join(record::receipt_path(ecosystem))).ok()
    }

    /// Attest `alpha` then `beta` through the real two phases, publishing
    /// into the project; `beta_check` decides the second check.
    fn attest_both(
        fx: &Fixture,
        beta_check: impl Fn(&Path) -> io::Result<(ResolutionRecord, Vec<u8>)>,
    ) -> io::Result<()> {
        let activity = fx.store.activity(ActivityMode::Exclusive).unwrap();
        let project = ProjectRoot::open(&fx.dir).unwrap();
        check_then_publish(
            &["alpha", "beta"],
            |id| match id {
                "alpha" => Ok(checked(&fx.dir, "alpha")),
                _ => beta_check(&fx.dir),
            },
            |records| record::publish_receipts(&fx.store, &activity, &project, records),
        )
    }

    #[test]
    fn a_failed_later_check_leaves_no_receipt_for_an_earlier_one() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("second-fails");
        let error =
            attest_both(&fx, |_| Err(io::Error::other("beta's lock check failed"))).unwrap_err();
        assert!(error.to_string().contains("beta's lock check failed"));
        assert_eq!(receipt(&fx.dir, "alpha"), None);
        assert_eq!(receipt(&fx.dir, "beta"), None);
        assert!(!fx.dir.join(record::RESOLUTION_DIR).exists());
        // With both passing, both are published.
        attest_both(&fx, |dir| Ok(checked(dir, "beta"))).unwrap();
        assert_eq!(receipt(&fx.dir, "alpha"), Some(checked(&fx.dir, "alpha").1));
        assert_eq!(receipt(&fx.dir, "beta"), Some(checked(&fx.dir, "beta").1));
        assert!(!fx.dir.join(".greyward/journal/alpha.json").exists());
    }

    #[test]
    fn a_check_returning_another_ecosystems_record_publishes_nothing() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("wrong-record");
        let error = attest_both(&fx, |dir| Ok(checked(dir, "alpha"))).unwrap_err();
        assert!(
            error.to_string().contains("returned a alpha record"),
            "{error}"
        );
        assert_eq!(receipt(&fx.dir, "alpha"), None);
    }

    /// Publishing the second receipt fails after the first was published:
    /// the first is put back as it was. With no prior receipt the new one
    /// is removed, and so are the directories this run created.
    #[test]
    fn a_failed_publication_removes_a_new_receipt_and_its_directories() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("rollback-absent");
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = Some("beta".into());
        let result = attest_both(&fx, |dir| Ok(checked(dir, "beta")));
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = None;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("simulated failure"), "{error}");
        assert!(error.contains("no receipt was published"), "{error}");
        assert_eq!(receipt(&fx.dir, "alpha"), None);
        assert!(!fx.dir.join(record::RESOLUTION_DIR).exists());
        assert!(!fx.dir.join(".greyward").exists());
    }

    /// With a prior receipt, the first is restored byte for byte and with
    /// its own mode.
    #[test]
    fn a_failed_publication_restores_a_prior_receipt_and_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("rollback-prior");
        let prior = fx.dir.join(record::receipt_path("alpha"));
        fs::create_dir_all(fx.dir.join(record::RESOLUTION_DIR)).unwrap();
        fs::write(&prior, b"the prior receipt").unwrap();
        fs::set_permissions(&prior, fs::Permissions::from_mode(0o640)).unwrap();
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = Some("beta".into());
        let result = attest_both(&fx, |dir| Ok(checked(dir, "beta")));
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = None;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("no receipt was published"), "{error}");
        assert_eq!(
            receipt(&fx.dir, "alpha").as_deref(),
            Some(&b"the prior receipt"[..])
        );
        assert_eq!(
            fs::metadata(&prior).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(receipt(&fx.dir, "beta"), None);
        assert!(fx.dir.join(record::RESOLUTION_DIR).is_dir());
        assert!(!fx.dir.join(".greyward/journal/alpha.json").exists());
        assert!(!fx.dir.join(".greyward/journal/beta.json").exists());
    }

    /// A lock that changed after its check passed is not given the record
    /// the check signed.
    #[test]
    fn a_lock_changed_after_its_check_is_not_published() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("changed");
        let error = attest_both(&fx, |dir| {
            let checked = checked(dir, "beta");
            fs::write(dir.join("alpha.lock"), "pinned 2.0.0\n").unwrap();
            Ok(checked)
        })
        .unwrap_err();
        assert!(error.to_string().contains("alpha.lock changed"), "{error}");
        assert_eq!(receipt(&fx.dir, "alpha"), None);
        assert_eq!(receipt(&fx.dir, "beta"), None);
    }

    /// A tailor from a future ecosystem, as `ward attest` sees it: an id,
    /// the lock it declares if any, and whether it has a lock check. Every
    /// other method panics, and so does the check: choosing targets must
    /// not reach a toolchain, a sync, a closure, or a tool.
    struct Future {
        id: &'static str,
        lock: Option<&'static str>,
        checks: bool,
    }

    /// Declares `alpha.lock` and checks it: attestable.
    static ALPHA: Future = Future {
        id: "alpha",
        lock: Some("alpha.lock"),
        checks: true,
    };
    static BETA: Future = Future {
        id: "beta",
        lock: Some("beta.lock"),
        checks: true,
    };
    /// Has a lock check but declares no lock a resolution door produces.
    static BARE: Future = Future {
        id: "bare",
        lock: None,
        checks: true,
    };
    /// Declares a lock but has no lock check of its own.
    static DOORLESS: Future = Future {
        id: "doorless",
        lock: Some("doorless.lock"),
        checks: false,
    };

    impl Attester for Future {
        fn attest_lock(
            &self,
            _ctx: &Context,
            _project: &ProjectRoot,
            _toolchain: &crate::kernel::toolchain::Selected,
            _host: &dyn tailors::EditHost,
            _door: &mut ResolutionDoor<'_>,
        ) -> io::Result<(ResolutionRecord, Vec<u8>)> {
            unreachable!("attest target selection runs no lock check")
        }
    }

    impl Tailor for Future {
        fn id(&self) -> &'static str {
            self.id
        }
        fn resolution_outputs(&self, _project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
            Ok(self.lock.map(PathBuf::from).into_iter().collect())
        }
        fn attester(&self) -> Option<&dyn Attester> {
            self.checks.then_some(self)
        }
        fn toolchain_sources(&self) -> crate::kernel::toolchain::input::Sources {
            unreachable!("attest target selection reads no toolchain source")
        }
        fn detect(&self, _project: &ProjectRoot) -> io::Result<bool> {
            unreachable!("attest target selection takes the detected tailors")
        }
        fn input_files(&self) -> &'static str {
            unreachable!("attest target selection names no input files")
        }
        fn preflight(&self, _platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
            unreachable!("attest target selection runs no preflight")
        }
        fn plan(
            &self,
            _ctx: &Context,
            _project: &ProjectRoot,
            _toolchain: &crate::kernel::toolchain::Selected,
            _door: &mut ResolutionDoor<'_>,
        ) -> io::Result<Option<String>> {
            unreachable!("ward attest plans nothing")
        }
        fn sync(
            &self,
            _ctx: &Context,
            _project: &ProjectRoot,
            _request: &tailors::SyncRequest,
            _attribution: &mut policy::Attribution,
        ) -> io::Result<bool> {
            unreachable!("ward attest syncs nothing")
        }
        fn listing(&self, _ecosystem: &str, _body: &serde_json::Value) -> tailors::ClosureListing {
            unreachable!("ward attest lists no closure")
        }
        fn closure_state(
            &self,
            _platform: Platform,
            _project: &ProjectRoot,
            _ecosystem: &str,
            _body: &serde_json::Value,
        ) -> io::Result<crate::comforter::status::State> {
            unreachable!("ward attest reads no closure")
        }
        fn sbom_components(
            &self,
            _ecosystem: &str,
            _body: &serde_json::Value,
            _out: &mut Vec<serde_json::Value>,
        ) -> io::Result<()> {
            unreachable!("ward attest writes no SBOM")
        }
        fn toolchain_catalog(&self) -> io::Result<crate::kernel::toolchain::Catalog> {
            unreachable!("attest target selection reads no toolchain catalog")
        }
    }

    /// Run the front of `ward attest` over `present` with observable
    /// stand-ins for preflight and the store: the ids it chose, or its
    /// refusal, and the steps that ran, in order.
    fn front(
        present: &[&'static dyn Tailor],
        named: &[&str],
    ) -> (Result<Vec<&'static str>, io::Error>, Vec<String>) {
        let temp = TempDir::named("attest-front");
        let project = ProjectRoot::open(&temp.0).unwrap();
        let named: Vec<String> = named.iter().map(|id| id.to_string()).collect();
        let steps = std::cell::RefCell::new(Vec::new());
        let result = select_then_open(
            &project,
            present,
            &named,
            |scope| {
                let ids: Vec<&str> = present
                    .iter()
                    .filter(|tailor| scope.covers(**tailor))
                    .map(|tailor| tailor.id())
                    .collect();
                steps.borrow_mut().push(format!("preflight {ids:?}"));
                Ok(())
            },
            || {
                steps.borrow_mut().push("open store".to_string());
                Ok(())
            },
        )
        .map(|(targets, (), ())| targets.iter().map(|target| target.tailor.id()).collect());
        (result, steps.into_inner())
    }

    /// No ecosystem shipped today lacks a lock check, so no CLI fixture
    /// reaches these refusals; a future tailor would. Each one returns
    /// before preflight or the store opens.
    #[test]
    fn an_unattestable_selection_refuses_before_preflight_or_the_store() {
        let all: [&'static dyn Tailor; 3] = [&ALPHA, &BARE, &DOORLESS];
        for (named, refusal) in [
            (
                &["doorless"][..],
                "ward attest does not support doorless: it has no lock check that runs \
                 through a resolution door",
            ),
            (
                &["bare"][..],
                "ward attest does not support bare: it has no lock that a resolution door \
                 produces, so there is nothing to sign",
            ),
            // Named beside a supported one, either way round, it refuses
            // the whole run: alpha is not attested alone in its place.
            (
                &["alpha", "doorless"][..],
                "ward attest does not support doorless: ",
            ),
            (
                &["doorless", "alpha"][..],
                "ward attest does not support doorless: ",
            ),
            (
                &["alpha", "bare"][..],
                "ward attest does not support bare: ",
            ),
            (&["gamma"][..], "no gamma project in "),
        ] {
            let (result, steps) = front(&all, named);
            let error = result.unwrap_err();
            assert!(error.to_string().starts_with(refusal), "{named:?}: {error}");
            assert!(steps.is_empty(), "{named:?} ran {steps:?}");
        }
        // Unnamed, with nothing attestable present.
        let (result, steps) = front(&[&BARE, &DOORLESS], &[]);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error.to_string().starts_with("nothing to attest in "),
            "{error}"
        );
        assert!(steps.is_empty(), "{steps:?}");
    }

    /// Unnamed, the unattestable tailors are skipped and the attestable one
    /// kept; named, it is scoped alone. Preflight runs before the store
    /// opens.
    #[test]
    fn an_attestable_selection_preflights_then_opens_the_store() {
        let all: [&'static dyn Tailor; 3] = [&BARE, &ALPHA, &DOORLESS];
        let (result, steps) = front(&all, &[]);
        assert_eq!(result.unwrap(), ["alpha"]);
        assert_eq!(steps, [r#"preflight ["alpha"]"#, "open store"]);
        let (result, steps) = front(&all, &["alpha"]);
        assert_eq!(result.unwrap(), ["alpha"]);
        assert_eq!(steps, [r#"preflight ["alpha"]"#, "open store"]);
        let all: [&'static dyn Tailor; 4] = [&BARE, &ALPHA, &DOORLESS, &BETA];
        let (result, steps) = front(&all, &["beta", "alpha"]);
        assert_eq!(result.unwrap(), ["beta", "alpha"]);
        assert_eq!(steps, [r#"preflight ["alpha", "beta"]"#, "open store"]);
    }
}
