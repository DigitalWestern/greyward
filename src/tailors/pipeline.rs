//! A test-only bench that drives one tailor's real planner and closure
//! publication end to end, with stand-in store objects in place of the
//! realized toolchain and environment, and pause points
//! (`kernel::resolve::pause`) where a concurrent writer acts at an exact
//! stage.
//!
//! Everything between the stand-ins and the closure file is the code a
//! sync runs: the planner reading the project through its held root (a
//! confined planner's doors staging an immutable snapshot and checking it
//! against the consumed basis), the planner's final checks of the live
//! project, the publication lock, the resolution join, any projection
//! switch, and the closure writer. A concurrent writer is a resolution transaction (what a
//! door publishes) on a thread and store lease of its own, or a second
//! complete sync. The scenarios are generic over [`Pipeline`]; each
//! ecosystem implements it and instantiates them with
//! [`pipeline_scenarios!`].

#![cfg(test)]

use crate::comforter::join::{self, Digests, BASIS_FIELD};
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{self, Attribution, Policy, Signing, StrictSource};
use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
use crate::kernel::resolve::ledger::{self, Entry, LedgerObjects, PortableLedger};
use crate::kernel::resolve::pause::{PausePoint, PausePoints};
use crate::kernel::resolve::record::{
    self, Isolation, LedgerSummary, RecordDoor, RecordFacts, ResolutionRecord, Tool,
};
use crate::kernel::resolve::testing::{idle_proxy, publish_through_transaction, relay};
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::signing::{self, SigningKey};
use crate::kernel::store::Store;
use crate::kernel::testutil::TempDir;
use crate::kernel::toolchain::Selected;
use crate::tailors::Tailor;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// One of the two generations of the project's resolution files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gen {
    A,
    B,
}

/// What one ecosystem supplies: its stand-in toolchain, its two project
/// generations, and its real planner and producer.
pub(crate) trait Pipeline: 'static {
    const ECOSYSTEM: &'static str;
    /// The lock file among the resolution outputs.
    const LOCK: &'static str;
    /// The closure body field holding the planned lock's sha256, when the
    /// producer records one.
    const LOCK_SHA_FIELD: Option<&'static str>;
    /// Whether the planner runs the tool through confined doors, so a sync
    /// reaches `Staged` and `Ran`. A planner that parses the lock itself
    /// reaches neither.
    const CONFINED: bool;
    /// The link the producer switches in the project to publish its
    /// environment (`.venv`, `node_modules`), if any, and the closure body
    /// field naming the target it must point at.
    const LINK: Option<(&'static str, &'static str)>;
    type Plan;
    fn tailor() -> &'static dyn Tailor;
    fn selected() -> Selected;
    /// Every project file of `generation`: the resolution outputs and the
    /// inputs the record must cover.
    fn files(generation: Gen) -> Vec<(&'static str, String)>;
    /// Publish the stand-in toolchain object and the stand-in environment
    /// objects (gems, deps, packages) into `store`; the toolchain's id and
    /// the environment each generation realizes to. Two generations may
    /// share one environment, as a lock change that moves no package
    /// does; a producer must then keep the active one intact by itself.
    fn objects(store: &Store) -> (String, [String; 2]);
    fn plan(
        door: &mut ResolutionDoor<'_>,
        project: &ProjectRoot,
        runtime: &Path,
        selected: &Selected,
    ) -> io::Result<(Self::Plan, String, Digests)>;
    #[allow(clippy::too_many_arguments)]
    fn publish(
        activity: &StoreActivity,
        project: &ProjectRoot,
        runtime: &Path,
        env: &Path,
        plan: &Self::Plan,
        lock_sha256: &str,
        basis: &Digests,
        selected: &Selected,
        ledgers: &[LedgerObjects],
        attribution: &mut Attribution,
    ) -> io::Result<()>;
    /// What the plan in a closure body says it read: a lock digest the
    /// stand-in planner reported, or a locked package version.
    fn planned(body: &Value) -> String;
    /// `planned` for a plan read from `generation`. By default the sha256
    /// of its lock, which the confined stand-in planners report.
    fn planned_as(generation: Gen) -> String {
        Self::files(generation)
            .into_iter()
            .find(|(path, _)| *path == Self::LOCK)
            .map(|(_, text)| record::sha256_hex(text.as_bytes()))
            .unwrap()
    }
    /// The writable tree the producer projects into the store for `env`,
    /// if any.
    fn forest(store: &Store, project: &Path, env: &Path) -> Option<PathBuf>;
}

/// What a rejected sync must leave exactly as it was.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Active {
    closure: Option<Vec<u8>>,
    link: Option<PathBuf>,
    forest: Option<BTreeMap<PathBuf, Vec<u8>>>,
}

/// The file `Bench::seed` writes into the active forest. A sync that
/// rebuilt or replaced the forest leaves it out.
const MARKER: &str = "active-marker";

/// The test's hold on process-wide state: the locks every closure-writing
/// test takes, and the door's thread-local wiring. Dropping it resets the
/// wiring and the join's lookup while the locks are still held.
pub(crate) struct Held {
    _env: std::sync::MutexGuard<'static, ()>,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Held {
    fn drop(&mut self) {
        join::set_resolution_files_for_test(None);
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        PROXY_FOR_TEST.with(|slot| slot.set(None));
    }
}

/// A project, a store with the stand-in objects, and a trusted signing
/// key. Shared (`Arc`) so a hook can run a second sync of the same
/// project inside the first one's window.
pub(crate) struct Bench<P: Pipeline> {
    dir: PathBuf,
    store: Store,
    activity: StoreActivity,
    runtime: PathBuf,
    envs: [PathBuf; 2],
    key: SigningKey,
    selected: Selected,
    _temp: TempDir,
    _store_temp: TempDir,
    _pipeline: PhantomData<fn() -> P>,
}

/// How long a competing door may take to publish once the project lock is
/// free before the test calls it hung. It decides no outcome: the lock is
/// probed, not waited on.
const HUNG_AFTER: Duration = Duration::from_secs(120);

/// A door started by a hook: the receiver signals once it has published,
/// and its thread returns how.
type CompetingDoor = (mpsc::Receiver<()>, std::thread::JoinHandle<io::Result<()>>);

impl<P: Pipeline> Bench<P> {
    /// `None` (after the skip message) when this host cannot run a
    /// confined door.
    fn new(label: &str) -> Option<(Held, Arc<Self>)> {
        let relay = relay(label)?;
        let held = Held {
            _env: policy::test_env_lock(),
            _serial: policy::attribution_test_lock(),
        };
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        PROXY_FOR_TEST.with(|slot| slot.set(Some(idle_proxy())));
        join::set_resolution_files_for_test(Some(Arc::new(|ecosystem: &str, project| {
            if ecosystem == P::ECOSYSTEM {
                crate::tailors::resolution_files(P::tailor(), project)
            } else {
                Ok(None)
            }
        })));
        let (store_temp, store, activity) =
            crate::kernel::resolve::testing::scratch_store(&format!("{label}-store"));
        let (runtime, envs) = P::objects(&store);
        let temp = TempDir::named(label);
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        let dir = dir.canonicalize().unwrap();
        let key_path = temp.0.join("key");
        signing::generate(&key_path).unwrap();
        let key = SigningKey::load(&key_path).unwrap();
        fs::remove_file(&key_path).unwrap();
        let bench = Self {
            dir,
            runtime: store.object_path(&runtime),
            envs: envs.map(|env| store.object_path(&env)),
            store,
            activity,
            key,
            selected: P::selected(),
            _temp: temp,
            _store_temp: store_temp,
            _pipeline: PhantomData,
        };
        Some((held, Arc::new(bench)))
    }

    /// A policy that trusts this bench's key and nothing else.
    fn trusting(&self) -> Policy {
        Policy {
            signing: Some(Signing {
                trusted: [self.key.public_key()].into_iter().collect(),
            }),
            ..Policy::default()
        }
    }

    /// `trusting`, under `ward --strict`.
    fn strict(&self) -> Policy {
        let mut policy = self.trusting();
        policy.strict = true;
        policy.strict_source = Some(StrictSource::Flag);
        policy
    }

    /// `trusting`, with a deny list naming `unrecorded-resolution`.
    fn denying(&self) -> Policy {
        let mut policy = self.trusting();
        policy.deny = [policy::UNRECORDED_RESOLUTION.to_string()].into();
        policy
    }

    fn generation(generation: Gen) -> Vec<(PathBuf, Vec<u8>)> {
        P::files(generation)
            .into_iter()
            .map(|(path, text)| (PathBuf::from(path), text.into_bytes()))
            .collect()
    }

    /// The digests a record of `generation` names, split into the
    /// tailor's outputs and inputs.
    fn digests(&self, generation: Gen) -> (Digests, Digests) {
        let project = ProjectRoot::open(&self.dir).unwrap();
        let outputs = P::tailor().resolution_outputs(&project).unwrap();
        let (mut out, mut inputs) = (Digests::new(), Digests::new());
        for (path, bytes) in Self::generation(generation) {
            let name = path.to_string_lossy().into_owned();
            let digest = record::sha256_hex(&bytes);
            if outputs.contains(&path) {
                out.insert(name, digest);
            } else {
                inputs.insert(name, digest);
            }
        }
        (out, inputs)
    }

    /// The basis a plan of `generation` binds its closure to.
    fn basis(&self, generation: Gen) -> Digests {
        let (mut all, inputs) = self.digests(generation);
        all.extend(inputs);
        all
    }

    fn lock_sha256(generation: Gen) -> String {
        Self::generation(generation)
            .into_iter()
            .find(|(path, _)| path == Path::new(P::LOCK))
            .map(|(_, bytes)| record::sha256_hex(&bytes))
            .unwrap()
    }

    /// The generation whose lock has this digest.
    fn generation_of(lock_sha256: &str) -> Gen {
        [Gen::A, Gen::B]
            .into_iter()
            .find(|generation| Self::lock_sha256(*generation) == lock_sha256)
            .expect("a lock of neither generation")
    }

    /// The environment object a plan of `generation` realizes to.
    fn env(&self, generation: Gen) -> &Path {
        &self.envs[match generation {
            Gen::A => 0,
            Gen::B => 1,
        }]
    }

    /// Whether the project lock is held right now, by anyone.
    fn contended(&self) -> bool {
        let project = ProjectRoot::open(&self.dir).unwrap();
        self.store.project_lock_contended(&project).unwrap()
    }

    /// The signed receipt a door resolving `generation` would publish.
    fn receipt(&self, generation: Gen) -> Vec<u8> {
        let mut ledger = PortableLedger::new(P::ECOSYSTEM, "edit").unwrap();
        ledger.insert(Entry {
            class: "metadata".into(),
            method: "GET".into(),
            url: "https://registry.example/standin".into(),
            status: 200,
            sha256: Some(record::sha256_hex(b"index")),
            claimed: None,
            verified: false,
            freshness: None,
            redirected_to: None,
        });
        let (outputs, inputs) = self.digests(generation);
        let record = ResolutionRecord::new(RecordFacts {
            ecosystem: P::ECOSYSTEM.into(),
            door: RecordDoor::Edit,
            tool: Tool {
                name: "standin".into(),
                version: "1.0.0".into(),
            },
            command: vec!["lock".into()],
            outputs,
            inputs,
            ledger: LedgerSummary::of(&ledger.identity().object_id(), &ledger),
            isolation: Isolation::Confined,
            exceptions: Vec::new(),
        })
        .unwrap();
        record::envelope_bytes(&record.envelope(Some(&self.key)).unwrap()).unwrap()
    }

    /// Write `generation`'s files straight into the project, as an editor
    /// would: no receipt, no lock.
    fn write(&self, generation: Gen) {
        for (path, bytes) in Self::generation(generation) {
            let at = self.dir.join(path);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::write(at, bytes).unwrap();
        }
    }

    /// The project as a door that resolved `generation` left it: the
    /// files and their receipt.
    fn commit(&self, generation: Gen) {
        self.write(generation);
        let receipt = self.dir.join(record::receipt_path(P::ECOSYSTEM));
        fs::create_dir_all(receipt.parent().unwrap()).unwrap();
        fs::write(receipt, self.receipt(generation)).unwrap();
    }

    /// A concurrent door publishing `generation` and its receipt through
    /// a transaction of its own, on a thread and store lease of its own,
    /// prepared now and started when called. It publishes once it gets the
    /// project lock.
    fn door(&self, generation: Gen) -> impl FnOnce() -> CompetingDoor + Send {
        let (store_root, dir) = (self.store.root.clone(), self.dir.clone());
        let receipt = self.receipt(generation);
        move || {
            let (done, finished) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let published = publish_through_transaction(
                    &store_root,
                    &dir,
                    P::ECOSYSTEM,
                    &Self::generation(generation),
                    &receipt,
                );
                let _ = done.send(());
                published
            });
            (finished, handle)
        }
    }

    /// `door`, run to completion when called.
    fn published_door(&self, generation: Gen) -> impl FnOnce() + Send {
        let door = self.door(generation);
        move || door().1.join().unwrap().unwrap()
    }

    /// One complete sync on this thread, as one command runs it: open the
    /// project, plan through a planner door, root its ledgers, publish
    /// through the producer. `pauses` are this invocation's alone.
    fn sync(&self, policy: Policy, pauses: Option<Arc<PausePoints>>) -> io::Result<()> {
        let _scope = policy::PolicyScope::install(policy);
        let mut attribution = Attribution::open(P::ECOSYSTEM)?;
        if let Some(pauses) = pauses {
            attribution = attribution.with_pauses(pauses);
        }
        match self.plan_and_publish(&mut attribution) {
            Ok(()) => attribution.finish(true),
            Err(error) => {
                attribution.discard();
                Err(error)
            }
        }
    }

    fn plan_and_publish(&self, attribution: &mut Attribution) -> io::Result<()> {
        let project = ProjectRoot::open(&self.dir)?;
        let mut door = ResolutionDoor::open(
            &self.store,
            &self.activity,
            Platform::host()?,
            DoorKind::Planner,
            attribution,
        )?;
        let (plan, lock_sha256, basis) =
            P::plan(&mut door, &project, &self.runtime, &self.selected)?;
        let ledgers = door.take_kept_ledgers();
        drop(door);
        for objects in &ledgers {
            ledger::root(&self.store, &self.activity, &project, objects)?;
        }
        // Realization: the environment of the generation the plan read.
        let planned = basis.get(P::LOCK).expect("the basis names the lock");
        let env = self.env(Self::generation_of(planned));
        P::publish(
            &self.activity,
            &project,
            &self.runtime,
            env,
            &plan,
            &lock_sha256,
            &basis,
            &self.selected,
            &ledgers,
            attribution,
        )
    }

    fn closure(&self) -> Option<Vec<u8>> {
        fs::read(
            self.dir
                .join(format!(".greyward/closures/{}.json", P::ECOSYSTEM)),
        )
        .ok()
    }

    fn body(&self) -> Value {
        let closure: Value = serde_json::from_slice(&self.closure().expect("a closure")).unwrap();
        closure["body"].clone()
    }

    /// The generation the published closure was planned from, if any.
    fn published_generation(&self) -> Option<Gen> {
        self.closure()?;
        let basis: Digests = serde_json::from_value(self.body()[BASIS_FIELD].clone()).unwrap();
        Some(Self::generation_of(basis.get(P::LOCK)?))
    }

    /// The forest of the published environment, if the producer has one.
    fn active_forest(&self) -> Option<PathBuf> {
        let generation = self.published_generation().unwrap_or(Gen::A);
        P::forest(&self.store, &self.dir, self.env(generation))
    }

    /// Mark the published forest as built by the active environment, as a
    /// compile into it would: a sync that rebuilds or replaces the forest
    /// loses the mark. Done once, before the operation under test.
    fn seed(&self) {
        if let Some(forest) = self.active_forest() {
            fs::write(forest.join(MARKER), "compiled by the active environment").unwrap();
        }
    }

    /// The published environment as it is now: the closure, the link the
    /// producer switched, and the forest. Only reads.
    fn active(&self) -> Active {
        Active {
            closure: self.closure(),
            link: P::LINK.and_then(|(link, _)| fs::read_link(self.dir.join(link)).ok()),
            forest: self.active_forest().map(|forest| tree(&forest)),
        }
    }

    fn receipt_on_disk(&self) -> Option<Vec<u8>> {
        fs::read(self.dir.join(record::receipt_path(P::ECOSYSTEM))).ok()
    }

    /// The published closure agrees with itself: its plan, its basis, its
    /// lock digest and any record it joined all name one generation.
    fn assert_coherent(&self) {
        if self.closure().is_none() {
            return;
        }
        let body = self.body();
        let basis: Digests = serde_json::from_value(body[BASIS_FIELD].clone()).unwrap();
        let lock = basis.get(P::LOCK).expect("the basis names the lock");
        if let Some(field) = P::LOCK_SHA_FIELD {
            assert_eq!(body[field].as_str(), Some(lock.as_str()));
        }
        let generation = Self::generation_of(lock);
        assert_eq!(
            P::planned(&body),
            P::planned_as(generation),
            "the plan read another lock"
        );
        if let Some((link, field)) = P::LINK {
            let target = fs::read_link(self.dir.join(link)).ok();
            assert_eq!(
                target.as_deref().and_then(Path::to_str),
                body[field].as_str(),
                "{link} serves another environment than the closure names"
            );
        }
        if let Some(envelope) = body.get("resolution") {
            let mut named: Digests = serde_json::from_value(envelope["outputs"].clone()).unwrap();
            named.extend(serde_json::from_value::<Digests>(envelope["inputs"].clone()).unwrap());
            assert_eq!(
                named, basis,
                "the joined record describes another generation"
            );
        }
    }

    /// The closure was planned from `generation`, and joined its receipt
    /// when `joined`.
    fn assert_published(&self, generation: Gen, joined: bool) {
        self.assert_coherent();
        let body = self.body();
        assert_eq!(
            body[BASIS_FIELD],
            join::basis_value(&self.basis(generation))
        );
        assert_eq!(self.published_generation(), Some(generation));
        match body.get("resolution") {
            Some(envelope) => {
                assert!(joined, "an unexpected record was joined: {envelope}");
                let receipt: Value = serde_json::from_slice(&self.receipt(generation)).unwrap();
                assert_eq!(envelope, &receipt);
            }
            None => assert!(!joined, "no record was joined: {body}"),
        }
    }
}

/// Every file under `dir` with its bytes.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path.strip_prefix(dir).unwrap().to_path_buf();
                files.insert(relative, fs::read(&path).unwrap());
            }
        }
    }
    files
}

fn reached(points: &PausePoints, point: PausePoint) {
    assert!(points.hits(point) >= 1, "the sync never reached {point:?}");
}

/// Run `hook` once, at the first arrival at `point`.
fn once(points: &PausePoints, point: PausePoint, hook: impl FnOnce() + Send + 'static) {
    points.at(point, 1, hook);
}

/// Every point a sync of `P` passes, in order: `Staged` and `Ran` only
/// when its planner runs confined doors.
fn stages<P: Pipeline>() -> Vec<PausePoint> {
    let mut stages = vec![PausePoint::Captured];
    if P::CONFINED {
        stages.extend([PausePoint::Staged, PausePoint::Ran]);
    }
    stages.extend([
        PausePoint::Planned,
        PausePoint::Publishing,
        PausePoint::Joining,
        PausePoint::Published,
    ]);
    stages
}

/// A bench with generation A resolved, receipted and synced, its forest
/// marked: the active environment every rejection must leave in place.
fn active_bench<P: Pipeline>(label: &str) -> Option<(Held, Arc<Bench<P>>)> {
    let (held, bench) = Bench::<P>::new(label)?;
    bench.commit(Gen::A);
    bench.sync(bench.strict(), None).unwrap();
    bench.assert_published(Gen::A, true);
    bench.seed();
    Some((held, bench))
}

/// A rejected sync left the active environment and published nothing
/// mismatched.
fn assert_rejected<P: Pipeline>(bench: &Bench<P>, result: io::Result<()>, before: &Active) {
    let error = result.expect_err("a sync that read a replaced generation was published");
    assert_eq!(
        &bench.active(),
        before,
        "a rejected sync changed the environment: {error}"
    );
    bench.assert_coherent();
}

/// Plan and publish with nothing in the way, under `--strict`: the closure
/// joins the receipt of the generation the plan read, and every stage
/// between capture and publication was reached.
pub(crate) fn publishes_a_closure_joined_to_its_plan<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = Bench::<P>::new(label) else {
        return;
    };
    bench.commit(Gen::A);
    let points = PausePoints::new();
    bench.sync(bench.strict(), Some(points.clone())).unwrap();
    for point in stages::<P>() {
        reached(&points, point);
    }
    if !P::CONFINED {
        assert_eq!(points.hits(PausePoint::Staged), 0);
        assert_eq!(points.hits(PausePoint::Ran), 0);
    }
    assert_eq!(points.hits(PausePoint::Published), 1);
    bench.assert_published(Gen::A, true);
}

/// A concurrent door publishes generation B after the planner captured A
/// and before it finished: before a confined run staged the project, or
/// while a lock-parsing planner checks what it read. The planner refuses
/// before taking the publication lock, and the A environment stays. The
/// next sync plans B.
pub(crate) fn a_generation_replaced_after_capture_is_refused<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let before = bench.active();
    let points = PausePoints::new();
    once(&points, PausePoint::Captured, bench.published_door(Gen::B));
    let result = bench.sync(bench.strict(), Some(points.clone()));
    reached(&points, PausePoint::Captured);
    assert_eq!(points.hits(PausePoint::Planned), 0);
    assert_eq!(points.hits(PausePoint::Publishing), 0);
    assert_rejected(&bench, result, &before);
    bench.sync(bench.strict(), None).unwrap();
    bench.assert_published(Gen::B, true);
}

/// A-to-B-to-A inside one planner run: B is published after capture, the
/// confined run stages B, and A (with its receipt) is restored before the
/// stage is compared. The live files read as A again, but the run read B,
/// so the plan is refused and the A environment stays.
pub(crate) fn an_aba_replacement_inside_the_stage_is_refused<P: Pipeline>(label: &str) {
    assert!(P::CONFINED, "only a confined planner stages the project");
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let before = bench.active();
    let receipt = bench.receipt_on_disk();
    let points = PausePoints::new();
    once(&points, PausePoint::Captured, bench.published_door(Gen::B));
    once(&points, PausePoint::Staged, bench.published_door(Gen::A));
    let result = bench.sync(bench.strict(), Some(points.clone()));
    reached(&points, PausePoint::Staged);
    assert_eq!(points.hits(PausePoint::Publishing), 0);
    assert_rejected(&bench, result, &before);
    assert_eq!(bench.receipt_on_disk(), receipt);
    bench.sync(bench.strict(), None).unwrap();
    bench.assert_published(Gen::A, true);
}

/// A concurrent door publishes B after the planner's last confined run
/// succeeded against A, and before the planner returns. Nothing the doors
/// checked changed while they ran, so only the planner's own final checks
/// of the live project (the lock, the observed inputs, the basis) stand
/// between this plan and publication: it must refuse before taking the
/// publication lock, and the A environment stays.
pub(crate) fn a_generation_published_after_the_last_confined_run_is_refused<P: Pipeline>(
    label: &str,
) {
    assert!(P::CONFINED, "only a confined planner runs doors");
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    // How many confined runs a sync of the unchanged project makes now: a
    // planner may skip a run whose result the store already recorded.
    let measured = PausePoints::new();
    bench.sync(bench.strict(), Some(measured.clone())).unwrap();
    bench.seed();
    let runs = measured.hits(PausePoint::Ran);
    assert!(runs >= 1, "the planner ran no confined door");
    let before = bench.active();
    let points = PausePoints::new();
    points.at(PausePoint::Ran, runs, bench.published_door(Gen::B));
    let result = bench.sync(bench.strict(), Some(points.clone()));
    assert_eq!(points.hits(PausePoint::Ran), runs);
    assert_eq!(
        points.hits(PausePoint::Planned),
        0,
        "the planner finished a plan of a replaced generation"
    );
    assert_eq!(points.hits(PausePoint::Publishing), 0);
    assert_rejected(&bench, result, &before);
    bench.sync(bench.strict(), None).unwrap();
    bench.assert_published(Gen::B, true);
}

/// A concurrent door publishes B and its receipt after the plan of A is
/// complete. The receipt on disk attests B, never the A plan, so the join
/// refuses and the A environment stays.
pub(crate) fn a_generation_published_after_planning_is_refused<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let before = bench.active();
    let points = PausePoints::new();
    once(&points, PausePoint::Planned, bench.published_door(Gen::B));
    let result = bench.sync(bench.strict(), Some(points.clone()));
    reached(&points, PausePoint::Joining);
    assert_eq!(points.hits(PausePoint::Published), 0);
    assert_rejected(&bench, result, &before);
    bench.sync(bench.strict(), None).unwrap();
    bench.assert_published(Gen::B, true);
}

/// A-to-B-to-A after planning, with A's receipt restored too: the files,
/// the receipt and the plan all name A again, so publishing is correct,
/// and the closure is A's, joined to A's receipt.
pub(crate) fn an_aba_replacement_after_planning_publishes_coherently<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let points = PausePoints::new();
    let (to_b, back_to_a) = (bench.published_door(Gen::B), bench.published_door(Gen::A));
    once(&points, PausePoint::Planned, move || {
        to_b();
        back_to_a();
    });
    bench.sync(bench.strict(), Some(points.clone())).unwrap();
    reached(&points, PausePoint::Planned);
    bench.assert_published(Gen::A, true);
}

/// Two syncs publish concurrently. While the A sync is about to take the
/// publication lock, a door publishes B and a second complete sync plans
/// and publishes B's closure. The A sync must then be refused, and B's
/// environment must stay byte for byte: a stale plan never overwrites it.
/// The second sync runs on this thread, inside the first one's window,
/// because the attribution stack nests per thread.
pub(crate) fn a_stale_sync_never_overwrites_a_concurrent_closure<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let points = PausePoints::new();
    let published: Arc<Mutex<Option<Active>>> = Arc::default();
    let (second, seen, to_b) = (
        bench.clone(),
        published.clone(),
        bench.published_door(Gen::B),
    );
    once(&points, PausePoint::Publishing, move || {
        to_b();
        second.sync(second.strict(), None).unwrap();
        second.assert_published(Gen::B, true);
        second.seed();
        *seen.lock().unwrap() = Some(second.active());
    });
    let result = bench.sync(bench.strict(), Some(points.clone()));
    reached(&points, PausePoint::Publishing);
    assert_eq!(points.hits(PausePoint::Published), 0);
    let after_second = published
        .lock()
        .unwrap()
        .take()
        .expect("the second sync ran");
    assert_rejected(&bench, result, &after_second);
    bench.assert_published(Gen::B, true);
}

/// The join and the closure write run under the project lock, so a
/// concurrent door publishing the resolution files cannot interleave with
/// them. At every `Joining` and at `Published` the lock is probed without
/// waiting and must be held. A door started at the first join has not
/// published when the closure is, and publishes once the sync lets go.
pub(crate) fn a_door_waits_for_the_join_and_the_closure<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let points = PausePoints::new();
    let started: Arc<Mutex<Option<CompetingDoor>>> = Arc::default();
    let (probe, start, door) = (bench.clone(), started.clone(), bench.door(Gen::B));
    points.on(PausePoint::Joining, move |_| {
        assert!(probe.contended(), "the join ran without the project lock");
    });
    once(&points, PausePoint::Joining, move || {
        *start.lock().unwrap() = Some(door());
    });
    let (probe, check) = (bench.clone(), started.clone());
    points.on(PausePoint::Published, move |_| {
        assert!(
            probe.contended(),
            "the closure was published without the project lock"
        );
        let guard = check.lock().unwrap();
        let door = guard.as_ref().expect("the door started at the join");
        assert!(
            door.0.try_recv().is_err(),
            "a door published before the closure was"
        );
    });
    bench.sync(bench.strict(), Some(points.clone())).unwrap();
    assert_eq!(points.hits(PausePoint::Published), 1);
    bench.assert_published(Gen::A, true);
    let door = started.lock().unwrap().take().unwrap();
    door.0
        .recv_timeout(HUNG_AFTER)
        .expect("the door never published after the sync let go of the lock");
    door.1.join().unwrap().unwrap();
    assert!(!bench.contended());
    assert_eq!(bench.receipt_on_disk(), Some(bench.receipt(Gen::B)));
    bench.assert_published(Gen::A, true);
    bench.sync(bench.strict(), None).unwrap();
    bench.assert_published(Gen::B, true);
}

/// Strict and deny-list refusals of evidence: B written by hand, with A's
/// receipt still committed, is unrecorded. Both policies refuse it, and the
/// A closure, its receipt and its environment stay. The permissive policy
/// then publishes B unjoined, recording the exception.
pub(crate) fn a_denied_unrecorded_generation_keeps_the_environment<P: Pipeline>(label: &str) {
    let Some((_held, bench)) = active_bench::<P>(label) else {
        return;
    };
    let before = bench.active();
    let receipt = bench.receipt_on_disk();
    bench.write(Gen::B);
    for policy in [bench.strict(), bench.denying()] {
        let points = PausePoints::new();
        let result = bench.sync(policy, Some(points.clone()));
        reached(&points, PausePoint::Joining);
        assert_eq!(points.hits(PausePoint::Published), 0);
        let error = result.as_ref().map_err(ToString::to_string).unwrap_err();
        assert!(error.contains("unrecorded-resolution"), "{error}");
        assert_rejected(&bench, result, &before);
        assert_eq!(bench.receipt_on_disk(), receipt);
    }
    bench.sync(bench.trusting(), None).unwrap();
    bench.assert_published(Gen::B, false);
    let body = bench.body();
    assert_eq!(
        body["exceptions"][0]["kind"],
        policy::UNRECORDED_RESOLUTION,
        "{body}"
    );
}

/// One `#[test]` per scenario for the pipeline `$pipeline`, each with its
/// own bench labelled from `$prefix`. `confined` adds the scenarios that
/// act inside a confined planner run.
macro_rules! pipeline_scenarios {
    (@each $pipeline:ty, $prefix:literal, $($scenario:ident),+) => {
        $(
            #[test]
            fn $scenario() {
                $crate::tailors::pipeline::$scenario::<$pipeline>(concat!(
                    $prefix,
                    "-",
                    stringify!($scenario)
                ));
            }
        )+
    };
    ($pipeline:ty, $prefix:literal, confined) => {
        $crate::tailors::pipeline::pipeline_scenarios!($pipeline, $prefix);
        $crate::tailors::pipeline::pipeline_scenarios!(@each $pipeline, $prefix,
            an_aba_replacement_inside_the_stage_is_refused,
            a_generation_published_after_the_last_confined_run_is_refused
        );
    };
    ($pipeline:ty, $prefix:literal) => {
        $crate::tailors::pipeline::pipeline_scenarios!(@each $pipeline, $prefix,
            publishes_a_closure_joined_to_its_plan,
            a_generation_replaced_after_capture_is_refused,
            a_generation_published_after_planning_is_refused,
            an_aba_replacement_after_planning_publishes_coherently,
            a_stale_sync_never_overwrites_a_concurrent_closure,
            a_door_waits_for_the_join_and_the_closure,
            a_denied_unrecorded_generation_keeps_the_environment
        );
    };
}

pub(crate) use pipeline_scenarios;
