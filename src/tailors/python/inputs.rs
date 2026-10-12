//! From project inputs to a Python `Plan`: manifest discovery, interpreter
//! selection, `uv` locking of unpinned requirements, the PyPI planner, and
//! the project-local plan cache.

use crate::comforter;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use crate::kernel::types;
use crate::kernel::ui;
use crate::tailors::python;
use crate::tailors::python::door::{Builds, Index, Uv, UvRun, UvTarget};
use crate::tailors::python::manifest;
use crate::tailors::python::pypi;
use crate::tailors::python::pyselect;
use crate::tailors::python::resolve;
use std::io;
use std::path::{Path, PathBuf};

pub const PLANNER_SCHEMA: &str = "python-planner/3";
const PLAN_CACHE: &str = ".greyward/plan.json";
const MANIFEST_REQUIREMENTS: &str = ".greyward/manifest-requirements.txt";
const MANIFEST_CONSTRAINTS: &str = ".greyward/manifest-constraints.txt";
/// How the generated requirements name the constraints beside them: uv reads
/// a `-c` path relative to the file that names it, so it is the held
/// project's file (#499).
const MANIFEST_CONSTRAINTS_NAME: &str = "manifest-constraints.txt";
const LOCK_STAMP: &str = ".greyward/lock-source.hash";
/// The requirements lock uv compiles and planning reads.
const LOCK: &str = "requirements.lock.txt";

pub fn planner_input_hash(
    platform: Platform,
    python_version: &str,
    text: &str,
    glibc: pypi::Glibc,
) -> String {
    use sha2::{Digest, Sha256};
    let glibc_input = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        format!("\0{}.{}", glibc.0, glibc.1)
    } else {
        String::new()
    };
    hex::encode(Sha256::digest(
        format!(
            "{PLANNER_SCHEMA}\x00{python_version}\x00{text}\x00{}{glibc_input}",
            platform.triple(),
        )
        .as_bytes(),
    ))
}

pub fn has_python_input(project: &ProjectRoot) -> io::Result<bool> {
    manifest::has_manifest(project)
}

/// The Python plan, the interpreter selection it was made with, and the
/// project files it was computed from (recorded in the closure for status).
pub type PythonPlan = (
    types::Plan,
    pyselect::PythonSelection,
    Vec<comforter::InputRecord>,
);

/// Candidate input files for the status record: the manifest that won, the
/// interpreter request, and every lock ward reads or writes, hashed through
/// the held project descriptor by `comforter::input_records`.
pub fn python_input_records(
    project: &ProjectRoot,
    manifest: &manifest::Manifest,
) -> io::Result<Vec<comforter::InputRecord>> {
    let dir = project.path();
    let mut candidates: Vec<PathBuf> = Vec::new();
    match &manifest.source_path {
        Some(path) => candidates.push(path.clone()),
        None => candidates.push(dir.join(&manifest.input)),
    }
    for extra in [
        ".python-version",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "requirements.lock.txt",
        "uv.lock",
        "poetry.lock",
        "pdm.lock",
    ] {
        candidates.push(dir.join(extra));
    }
    comforter::input_records(project, &candidates)
}

/// The text uv resolves, and whether uv may be handed the manifest's own
/// file instead (it names the same requirements). A file outside the
/// project never is, and nor is one whose includes reach outside it: uv
/// would read the external file again by path, and by then the path may
/// name another file (#501). uv compiles the flattened text ward read
/// instead, written under `.greyward` by `read_plan`.
fn resolver_input(project: &ProjectRoot, manifest: &manifest::Manifest) -> (String, bool) {
    let external = manifest
        .source_path
        .as_deref()
        .is_some_and(|path| manifest::held_relative(project, path).is_none())
        || manifest.has_external_includes();
    if external {
        return (manifest.flattened_text(), false);
    }
    let text = manifest.resolver_text();
    let as_is = text == manifest.requirements_text();
    (text, as_is)
}

/// What planning reads from a project before it plans: the manifest, the
/// interpreter selection checked against it, and the requirements text in
/// the forms planning and uv need. Discovering it writes no project input:
/// `read_plan` and `ensure_lock` both start here.
struct Inputs {
    manifest: manifest::Manifest,
    selection: pyselect::PythonSelection,
    /// The manifest's file name, for messages and uv's compile input.
    input: String,
    /// The requirements text as the manifest states it.
    source: String,
    /// The text uv compiles, and whether uv may read the manifest's own
    /// file for it ([`resolver_input`]).
    resolver_source: String,
    as_is: bool,
}

/// Where a plan's pinned requirements come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pins {
    /// The manifest pins nothing (an empty one), or its own lock (`uv.lock`,
    /// `poetry.lock`, `pdm.lock`) already gave every package.
    Manifest,
    /// A hash-pinned requirements file the planner reads as it is.
    AsWritten,
    /// `requirements.lock.txt`, compiled by uv from the manifest.
    /// `repinned` when the manifest was hash-pinned already but not in a
    /// form the planner reads (markers, extras).
    Lock { repinned: bool },
}

impl Inputs {
    /// Discover the manifest and check the interpreter against it. The
    /// interpreter is decided: it is the one this project's toolchain
    /// selection names. Nothing here reselects, so a `setup.py` probe cannot
    /// move the version out from under the lock. `announce` says what was
    /// read (the setup.py fallback warning, the inputs note); `prepare`
    /// reads quietly, so a sync says it once.
    fn discover(
        project: &ProjectRoot,
        selected: &Selected,
        door: &mut ResolutionDoor<'_>,
        announce: bool,
    ) -> io::Result<Self> {
        let platform = door.platform();
        let version = selected.version("cpython")?;
        let mut manifest = manifest::discover(platform, project, version)?;
        let mut selection = pyselect::locked(platform, version, &manifest.python)?;
        if manifest.requires_setup() {
            let dynamic_dependencies = manifest.dynamic_dependencies;
            if let Err(error) = manifest.prepare_setup(project, selected, door) {
                // Every ordinary failure in here is already `InvalidData`
                // (`unreadable` in the manifest layer hardcodes it, and it
                // wraps the sandboxed egg_info probe), so the kind cannot
                // tell a descriptor refusal from a probe that did not work.
                // Fall back on both: a symlinked `.greyward` is still
                // refused at the first write through the project descriptor.
                if !dynamic_dependencies {
                    return Err(error);
                }
                let Some(mut fallback) = manifest::dynamic_requirements_fallback(project)? else {
                    return Err(error);
                };
                if announce {
                    warn_setup_fallback(&error);
                }
                fallback.python = manifest.python.clone();
                manifest = fallback;
            }
            // The probe may have added a `requires-python` the lock never
            // reads. It cannot change the interpreter, so it is checked
            // against the locked one instead: the probe loop this replaces
            // existed only to let selection chase its own metadata.
            selection = pyselect::locked(platform, version, &manifest.python)?;
        }
        if manifest.is_empty() && !manifest.provenance.contains("empty manifest") {
            manifest.provenance.push_str(" (empty manifest)");
        }
        if announce {
            ui::note(&format!("python inputs: {}", manifest.provenance));
        }
        let input = manifest.input.clone();
        let source = manifest.requirements_text();
        let (resolver_source, as_is) = resolver_input(project, &manifest);
        Ok(Self {
            manifest,
            selection,
            input,
            source,
            resolver_source,
            as_is,
        })
    }

    /// Where the pins come from.
    fn pins(&self) -> io::Result<Pins> {
        if self.manifest.is_empty() || self.manifest.locked_packages.is_some() {
            return Ok(Pins::Manifest);
        }
        if !is_fully_pinned(&self.source) {
            return Ok(Pins::Lock { repinned: false });
        }
        match pypi::parse_requirements(&self.source) {
            Ok(_) => Ok(Pins::AsWritten),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(e),
            Err(_) => Ok(Pins::Lock { repinned: true }),
        }
    }

    /// The file uv compiles the lock from, as planning names it: the
    /// generated text under `.greyward` when uv may not read the manifest's
    /// own file, that file otherwise. Naming it writes nothing.
    fn compile_path(&self, project: &ProjectRoot) -> Option<PathBuf> {
        if needs_generated_input(&self.input, &self.source, self.as_is) {
            Some(project.path().join(MANIFEST_REQUIREMENTS))
        } else {
            self.manifest.source_path.clone()
        }
    }

    /// The stamp `requirements.lock.txt` is compiled under: the interpreter,
    /// the text uv compiles, and, when uv reads a project file by path,
    /// every file of its include tree.
    fn lock_stamp(&self, project: &ProjectRoot, selected: &Selected) -> io::Result<String> {
        let pyver = selected.version("cpython")?;
        match self.compile_path(project) {
            Some(path)
                if !path
                    .components()
                    .any(|component| component.as_os_str() == ".greyward") =>
            {
                let tree_hash = manifest::requirements_tree_hash(project, &path)?;
                Ok(lock_source_hash(
                    pyver,
                    &format!("{}\0{tree_hash}", self.resolver_source),
                ))
            }
            _ => Ok(lock_source_hash(pyver, &self.resolver_source)),
        }
    }
}

/// The setup.py probe failed and planning fell back on the requirements
/// directory convention: say why, once.
fn warn_setup_fallback(error: &io::Error) {
    // The probe's error carries the sandbox log's last lines after a
    // marker; those go out as progress lines first, so the warning and its
    // next line stay a pair.
    let text = error.to_string();
    let (reason, tail) = match text.split_once("last 20 lines:\n") {
        Some((reason, tail)) => (reason.trim_end_matches("; ").to_string(), Some(tail)),
        None => (text.clone(), None),
    };
    if let Some(tail) = tail {
        ui::note("setup.py probe output, last 20 lines:");
        for line in tail.lines() {
            ui::note(&format!("  {line}"));
        }
    }
    // `next:`, not `fix:`: re-running the probe by hand shows why it
    // failed; it does not make it pass.
    ui::warning_next(
        &format!(
            "setup.py metadata probe failed; using the requirements directory \
             convention: {reason}"
        ),
        "ward run python setup.py egg_info",
    );
}

/// `Tailor::prepare` for Python: compile `requirements.lock.txt` when the
/// manifest needs one and the lock on disk was not compiled from it. This
/// is the only step that writes a Python dependency lock, and the command
/// layer skips it under `--frozen`, so a frozen sync only ever reads one.
pub fn ensure_lock(
    project: &ProjectRoot,
    selected: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<()> {
    let inputs = Inputs::discover(project, selected, door, false)?;
    let Pins::Lock { repinned } = inputs.pins()? else {
        return Ok(());
    };
    let stamp = inputs.lock_stamp(project, selected)?;
    // The stamp is ward's own state (strict no-follow read); the lock is a
    // project input. Anything unreadable is a miss, and compiles afresh.
    if let (Ok(Some(found)), Ok(Some(lock))) = (
        project.read_file(Path::new(LOCK_STAMP)),
        project.read_input_string(Path::new(LOCK)),
    ) {
        if cached_lock_matches(&String::from_utf8_lossy(&found), &lock, &stamp) {
            return Ok(());
        }
    }
    if repinned {
        ui::note(&format!(
            "{} is pinned but not directly consumable; re-locking for this platform \
             with uv into {LOCK}",
            inputs.input
        ));
    } else {
        ui::note(&format!(
            "{} is not hash-pinned; resolving with the store uv...",
            inputs.input
        ));
    }
    let compile_path = match generated_compile_input(
        project,
        &inputs.manifest,
        &inputs.input,
        &inputs.source,
        &inputs.resolver_source,
        inputs.as_is,
    )? {
        Some(generated) => Some(generated),
        None => inputs.manifest.source_path.clone(),
    };
    compile_lock(
        door,
        project,
        &inputs.input,
        selected,
        compile_path.as_deref(),
    )?;
    // The stamp is the only file ward writes here, and it goes through the
    // held project descriptor, so a `.greyward` swapped for a symlink is
    // refused rather than followed. The lock beside it is the door's
    // publication.
    project.write_file(Path::new(LOCK_STAMP), stamp.as_bytes())?;
    if repinned {
        // Said once the lock exists, with its full path: an automatic sync
        // can run from a subdirectory of the project.
        let lock = project.path().join(LOCK);
        ui::warning(
            &format!(
                "{} holds the pins this platform can consume; commit it so every \
                 sync reads the same lock",
                lock.display()
            ),
            &ui::shell_line(&["git", "add", &lock.display().to_string()]),
        );
    }
    Ok(())
}

/// Plan from project inputs, returning the interpreter selection that was
/// used. The manifest layer may only learn the constraint after a sandboxed
/// `setup.py egg_info`, so the selection is made here and handed back to the
/// caller: planning, realization and the closure all use this one value.
///
/// Planning only reads the dependency lock. `ensure_lock` (`prepare`)
/// writes it, and under `--frozen` nothing does, so a lock that is missing
/// or was compiled from other inputs is refused as stale. Planning hits
/// PyPI, so successful plans are cached in `.greyward/plan.json` keyed by a
/// hash of the inputs; an unchanged lock replans offline.
///
/// The project is read, and `.greyward` written, through the held descriptor.
pub fn read_plan(
    project: &ProjectRoot,
    selected: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<PythonPlan> {
    let platform = door.platform();
    let version = selected.version("cpython")?;
    let inputs = Inputs::discover(project, selected, door, true)?;
    if !inputs.input.starts_with("requirements") {
        record_skippable_specs(&inputs.source)?;
    }
    inputs.selection.emit_warnings();
    let pins = inputs.pins()?;
    let records = python_input_records(project, &inputs.manifest)?;
    let text = match pins {
        // A found manifest may intentionally declare no dependencies: the
        // interpreter-only plan stays on the normal realization and
        // projection path, and uv is never asked to compile it.
        Pins::Manifest => {
            let packages = match &inputs.manifest.locked_packages {
                Some(packages) if !inputs.manifest.is_empty() => packages.clone(),
                _ => Vec::new(),
            };
            let plan = types::Plan {
                ecosystem: "python".into(),
                python_version: version.into(),
                packages,
            };
            return Ok((plan, inputs.selection, records));
        }
        Pins::AsWritten => inputs.source,
        Pins::Lock { .. } => read_lock(
            project,
            &inputs.input,
            &inputs.lock_stamp(project, selected)?,
        )?,
    };

    // These are project-local .greyward caches, not store identities; one
    // re-plan after moving a project between platforms is acceptable.
    let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        pypi::host_glibc()?
    } else {
        pypi::Glibc(0, 0)
    };
    let input_hash = planner_input_hash(platform, version, &text, glibc);
    // A symlinked or non-regular cache is a refusal; an unreadable regular
    // file is a miss that the write below replaces.
    let cached = match project.read_file(Path::new(PLAN_CACHE)) {
        Ok(cached) => cached,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
        Err(_) => None,
    };
    if let Some(cached) = cached {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash.as_str() {
                if let Ok(plan) = serde_json::from_value::<types::Plan>(v["plan"].clone()) {
                    return Ok((plan, inputs.selection, records));
                }
            }
        }
    }

    let plan = pypi::plan_python(platform, &text, version)?;
    project.write_file(
        Path::new(PLAN_CACHE),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "input_hash": input_hash,
            "plan": plan,
        }))?,
    )?;
    Ok((plan, inputs.selection, records))
}

pub fn record_skippable_specs(source: &str) -> io::Result<()> {
    record_skippable_specs_with(source, policy::record)
}

pub fn record_skippable_specs_with<F>(source: &str, mut record: F) -> io::Result<()>
where
    F: FnMut(&str, &str, &str) -> io::Result<()>,
{
    let specs: Vec<String> = pypi::skippable_specs(source);
    for spec in specs {
        record(
            policy::REQUIREMENT_SKIPPED,
            &spec,
            "project-local or direct reference is not a locked registry package",
        )?;
    }
    for option in pypi::unattested_index_options(source) {
        record(
            policy::UNATTESTED_INDEX,
            &option,
            "requirements index/find-links options are recorded but never followed",
        )?;
    }
    Ok(())
}

/// Most non-comment logical lines (after backslash continuations) carry a
/// --hash= option. That is the shape `uv pip compile --generate-hashes`
/// emits and the only shape the planner accepts directly.
pub fn is_fully_pinned(text: &str) -> bool {
    let mut logical = String::new();
    let mut any = false;
    for raw in text.lines().chain(std::iter::once("")) {
        if let Some(stripped) = raw.strip_suffix('\\') {
            logical.push_str(stripped);
            continue;
        }
        logical.push_str(raw);
        let line = logical.trim();
        let line = match line.find(" #") {
            Some(i) => line[..i].trim(),
            None => line,
        };
        if !line.is_empty() && !line.starts_with('#') {
            any = true;
            let spec = line
                .split_whitespace()
                .filter(|token| !token.starts_with("--hash="))
                .collect::<Vec<_>>()
                .join(" ");
            if pypi::is_skippable_spec(&spec) {
                logical.clear();
                continue;
            }
            if !line.contains("--hash=") {
                return false;
            }
        }
        logical.clear();
    }
    any
}

/// Whether uv compiles a requirements text ward writes under `.greyward`
/// rather than the manifest's own file: a pyproject or setup.cfg, or a
/// requirements file uv may not reopen by path (an external include).
fn needs_generated_input(input: &str, source: &str, as_is: bool) -> bool {
    !(as_is && (input.starts_with("requirements") || is_fully_pinned(source)))
}

/// The requirements text ward writes under `.greyward` for uv to compile, when
/// [`needs_generated_input`]: its path, or `None` when uv compiles the
/// manifest's own file.
fn generated_compile_input(
    project: &ProjectRoot,
    manifest: &manifest::Manifest,
    input: &str,
    source: &str,
    resolver_source: &str,
    as_is: bool,
) -> io::Result<Option<PathBuf>> {
    if !needs_generated_input(input, source, as_is) {
        return Ok(None);
    }
    // The compile input is named to uv by pathname, but ward writes it
    // through the held project descriptor so a symlinked `.greyward` is
    // refused rather than followed.
    let mut text = if manifest.has_constraints() {
        project.write_file(
            Path::new(MANIFEST_CONSTRAINTS),
            manifest.constraints_text().as_bytes(),
        )?;
        format!(
            "{}-c {MANIFEST_CONSTRAINTS_NAME}\n",
            manifest.normalized_requirements_text(),
        )
    } else {
        resolver_source.to_string()
    };
    if text.is_empty() {
        text.push('\n');
    }
    project.write_file(Path::new(MANIFEST_REQUIREMENTS), text.as_bytes())?;
    Ok(Some(project.path().join(MANIFEST_REQUIREMENTS)))
}

/// The file uv compiles a project's `requirements.lock.txt` from, relative
/// to the project, as planning names it: `ward attest` reruns that compile.
/// A generated input is written afresh, as planning would.
pub(crate) fn lock_compile_input(
    project: &ProjectRoot,
    selected: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<String> {
    let version = selected.version("cpython")?;
    let mut manifest = manifest::discover(door.platform(), project, version)?;
    if manifest.requires_setup() {
        manifest.prepare_setup(project, selected, door)?;
    }
    let input = manifest.input.clone();
    let source = manifest.requirements_text();
    let (resolver_source, as_is) = resolver_input(project, &manifest);
    let generated =
        generated_compile_input(project, &manifest, &input, &source, &resolver_source, as_is)?;
    let path = generated.or_else(|| manifest.source_path.clone());
    Ok(compile_name(project, path.as_deref(), &input))
}

/// How uv, started in the held project directory, is told the compile
/// input: relative to the project, so a directory swapped in at the
/// project's path is never the one read (#499). An external requirements
/// file never reaches here: planning hands uv the flattened text under
/// `.greyward` instead (#501).
fn compile_name(project: &ProjectRoot, path: Option<&Path>, input: &str) -> String {
    path.map(|path| path.strip_prefix(project.path()).unwrap_or(path))
        .and_then(Path::to_str)
        .unwrap_or(input)
        .to_string()
}

/// The lock a requirements manifest is planned from, or the refusal that
/// names it: `prepare` compiles it, and the command layer skips `prepare`
/// under `--frozen`.
pub fn require_lock(project: &ProjectRoot) -> io::Result<String> {
    project
        .read_input_string(Path::new(LOCK))?
        .ok_or_else(|| crate::tailors::missing_lock(project, LOCK))
}

/// The committed `requirements.lock.txt`, read and never written. A lock
/// this machine compiled from other inputs than `stamp` names (the stamp
/// beside it disagrees), or an empty one, is stale: `ensure_lock` would
/// have compiled it afresh, and under `--frozen` nothing does. A lock with
/// no stamp at all is a fresh checkout's committed lock, read as it is.
fn read_lock(project: &ProjectRoot, input: &str, stamp: &str) -> io::Result<String> {
    let lock = require_lock(project)?;
    let found = project.read_file(Path::new(LOCK_STAMP))?;
    let compiled_elsewhere = found
        .is_some_and(|found| !cached_lock_matches(&String::from_utf8_lossy(&found), &lock, stamp));
    if lock.is_empty() || compiled_elsewhere {
        return Err(crate::kernel::error::stale(
            io::ErrorKind::InvalidData,
            format!(
                "{} was not compiled from {input} as it is now, and --frozen never \
                 re-locks; run `ward` once without --frozen and commit the file",
                project.path().join(LOCK).display()
            ),
        ));
    }
    Ok(lock)
}

/// Compile `requirements.lock.txt` with uv from `compile_path` (the
/// manifest's own file when `None`). uv runs in the project by path, through
/// a missing-lock door on `door`'s scope; the lock it writes is the door's
/// publication.
fn compile_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    input: &str,
    selected: &Selected,
    compile_path: Option<&Path>,
) -> io::Result<()> {
    let pyver = selected.version("cpython")?;
    // Store-pinned uv, not host uv: a bare machine needs only ward. It runs
    // confined through a missing-lock door, and the lock is published with
    // its signed record (none when an include lies outside the project).
    let compile_input = compile_name(project, compile_path, input);
    let uv = Uv::for_door(door, selected)?;
    let args = resolve::compile_args(&compile_input, LOCK, pyver);
    let record = if resolve::has_external_includes(project)? {
        None
    } else {
        let shown: Vec<String> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let refs: Vec<&str> = shown.iter().map(String::as_str).collect();
        Some(crate::tailors::record_spec(
            &python::tailor::Python,
            project,
            uv.tool(),
            &refs,
        )?)
    };
    let mut missing_lock = door.reopen(DoorKind::MissingLock);
    python::door::run_uv_checked(
        &mut missing_lock,
        UvRun {
            uv: &uv,
            lock_root: project.path(),
            cwd: None,
            args,
            index: Index::PipCompile,
            outputs: resolve::resolution_outputs(project)?,
            target: UvTarget::Project {
                record,
                slot: Default::default(),
            },
            builds: Builds::Probe,
            // Quiet on success; on failure its words go into ward's error.
            capture: !ui::verbose(),
            policy: None,
        },
        "uv pip compile failed",
    )?;
    drop(missing_lock);
    project.regenerated_input(Path::new(LOCK));
    match project.read_input_string(Path::new(LOCK))? {
        Some(_) => Ok(()),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: uv wrote no lock", project.path().join(LOCK).display()),
        )),
    }
}

pub fn cached_lock_matches(stamp: &str, lock: &str, source_hash: &str) -> bool {
    !lock.is_empty() && stamp.trim() == source_hash
}

/// Stamp deciding whether `uv pip compile` must re-run. Deliberately NOT
/// platform-qualified: `.greyward/lock-source.hash` is per-machine state and
/// the format is byte-identical to the pre-port one, so existing darwin
/// stamps stay valid after the Linux port (platform lives in
/// `planner_input_hash`, which keys the plan cache).
pub fn lock_source_hash(pyver: &str, source: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{pyver}\x00{source}").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::StoreActivity;
    use crate::kernel::store;

    /// A lease on `store` itself, for the case that runs a child against it.
    /// The other cases use a store that is absent or not a directory on
    /// purpose, so they borrow `testutil::detached_lease` instead.
    fn test_activity(store: &store::Store) -> StoreActivity {
        store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap()
    }

    /// The selection these tests plan with: the shipped release for the
    /// interpreter the fixtures expect. Choosing it is the kernel's job.
    fn selected() -> crate::kernel::toolchain::Selected {
        python::shipped_selection(pyselect::DEFAULT_VERSION).expect("shipped CPython release")
    }

    #[test]
    fn cache_key_builders_track_independent_inputs() {
        let source = "six==1.17.0\n";
        let darwin_plan = planner_input_hash(
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            source,
            pypi::Glibc(0, 0),
        );
        let linux_plan = planner_input_hash(
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            source,
            pypi::Glibc(2, 43),
        );
        let linux_changed_glibc = planner_input_hash(
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            source,
            pypi::Glibc(2, 42),
        );
        let changed_plan = planner_input_hash(
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            "six==1.17.0\n# changed",
            pypi::Glibc(0, 0),
        );
        assert_ne!(darwin_plan, changed_plan); // source only
        assert_ne!(darwin_plan, linux_plan); // platform only
        assert_ne!(linux_plan, linux_changed_glibc); // host glibc only
        assert_eq!(
            darwin_plan,
            planner_input_hash(
                Platform::Aarch64AppleDarwin,
                "3.12.14",
                source,
                pypi::Glibc(2, 43),
            )
        ); // neither
        assert_eq!(
            darwin_plan,
            "dc181496c6681389a89b3191dba44abdfe8efef8044e540777e7b62c91166411"
        );

        // The lock-source stamp is platform-free on purpose (see its doc):
        // this is main's exact format, so pre-port darwin stamps stay valid.
        let lock = lock_source_hash("3.12", source);
        let changed_lock = lock_source_hash("3.12", "six==1.17.0\n# changed");
        assert_ne!(lock, changed_lock); // source only
        assert_eq!(lock, lock_source_hash("3.12", source)); // same input
                                                            // The default pin's full version is part of existing stamps.
        assert_eq!(
            lock_source_hash("3.12.14", "six==1.17.0\n"),
            "2036e745694799536bfd9bee5ce7f4fbf3a1f621d96e8d54e632e4d0c2334c67"
        );
        assert!(cached_lock_matches(&lock, "six==1.17.0\n", &lock));
        assert!(!cached_lock_matches(&changed_lock, "six==1.17.0\n", &lock));
        assert!(!cached_lock_matches(&lock, "", &lock));
        {
            use sha2::{Digest, Sha256};
            assert_eq!(
                lock,
                hex::encode(Sha256::digest(format!("3.12\x00{source}").as_bytes()))
            );
        }
    }

    #[test]
    fn plan_cache_behind_a_symlinked_ward_is_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project = temp.0.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        // Hash-pinned, so planning never needs uv and the cache read is the
        // first store-free step that can refuse.
        std::fs::write(
            project.join("requirements.txt"),
            format!("six==1.17.0 --hash=sha256:{}\n", "a".repeat(64)),
        )
        .unwrap();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(outside.join(".greyward")).unwrap();
        std::os::unix::fs::symlink(outside.join(".greyward"), project.join(".greyward")).unwrap();
        let store = store::Store::for_test(temp.0.join("absent-store"));
        let root = ProjectRoot::open(&project).unwrap();
        let e = read_plan(
            &root,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not a real directory"), "{e}");
        assert!(!store.root.exists(), "a refused cache touched the store");
        assert!(
            std::fs::read_dir(outside.join(".greyward"))
                .unwrap()
                .next()
                .is_none(),
            "wrote through the symlinked .greyward"
        );
    }

    /// Plant the pinned uv as a script that writes the lock uv would have
    /// produced, headed by the arguments it ran with (`# args:`) and the
    /// input it read (`# input:`), the lock being the one file a confined
    /// run may write; and an empty stand-in for the CPython uv is given as
    /// `--python`. Realization returns store objects it already has, so
    /// `locked_requirements` reaches its stamp write with no network.
    fn store_with_stub_uv(root: &Path) -> store::Store {
        use std::os::unix::fs::PermissionsExt as _;
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = store::Store::for_test(root.canonicalize().unwrap());
        crate::tailors::install_kinds();
        let host = Platform::host().unwrap();
        let pin = python::uv_pins()
            .unwrap()
            .iter()
            .find(|pin| pin.platform == host)
            .unwrap();
        let staged = store.stage().unwrap();
        let uv = staged.join("uv");
        std::fs::write(
            &uv,
            "#!/bin/sh\n{ echo \"# args: $*\"; sed 's/^/# input: /' \"$3\"; \
             echo 'six==1.17.0 --hash=sha256:aaaa'; } > requirements.lock.txt\n",
        )
        .unwrap();
        std::fs::set_permissions(&uv, std::fs::Permissions::from_mode(0o755)).unwrap();
        store
            .commit_with_deps(
                &python::uv_identity(pin),
                &staged,
                &[],
                &store::ObjectDeps::new(),
            )
            .unwrap();
        let cpython = python::pythons()
            .unwrap()
            .iter()
            .find(|pin| pin.platform == host && pin.version == pyselect::DEFAULT_VERSION)
            .unwrap();
        let staged = store.stage().unwrap();
        std::fs::create_dir_all(staged.join("bin")).unwrap();
        store
            .commit_with_deps(
                &python::cpython_identity(cpython),
                &staged,
                &[],
                &store::ObjectDeps::new(),
            )
            .unwrap();
        store
    }

    /// The confined door's relay for a stub-uv test, cleared when the guard
    /// drops; `None` (after a skip) when the host cannot confine a door.
    fn stub_relay(test: &str) -> Option<RelayGuard> {
        let relay = crate::kernel::resolve::testing::relay(test)?;
        crate::kernel::resolve::door::RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        Some(RelayGuard)
    }

    struct RelayGuard;

    impl Drop for RelayGuard {
        fn drop(&mut self) {
            crate::kernel::resolve::door::RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// What the stub uv recorded in the lock it wrote in `dir`: its
    /// arguments, and the input it read.
    fn stub_args(dir: &Path) -> String {
        stub_lines(dir, "# args: ").trim_end().to_string()
    }

    fn stub_input(dir: &Path) -> String {
        stub_lines(dir, "# input: ")
    }

    fn stub_lines(dir: &Path, prefix: &str) -> String {
        std::fs::read_to_string(dir.join("requirements.lock.txt"))
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix(prefix))
            .map(|line| format!("{line}\n"))
            .collect()
    }

    #[test]
    fn lock_stamp_behind_a_symlinked_ward_is_refused() {
        let Some(_relay) = stub_relay("lock_stamp_behind_a_symlinked_ward_is_refused") else {
            return;
        };
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        // Unpinned, so preparing has to compile and reach the stamp write.
        std::fs::write(project_dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project_dir.join(".greyward")).unwrap();
        let store = store_with_stub_uv(&temp.0.join("store"));

        let project = ProjectRoot::open(&project_dir).unwrap();
        let error = ensure_lock(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &test_activity(&store),
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a real directory"), "{error}");
        // The door's transaction journals under `.greyward`, so it refuses the
        // whole publication: not even uv's lock lands.
        assert!(!project_dir.join("requirements.lock.txt").exists());
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "wrote the lock stamp through the symlinked .greyward"
        );
    }

    /// uv starts inside the held project directory and is handed the
    /// requirements relative to it, so a directory swapped in at the
    /// project's path is never the one compiled (#499).
    #[test]
    fn uv_compiles_the_held_project_inputs_after_a_swap() {
        let Some(_relay) = stub_relay("uv_compiles_the_held_project_inputs_after_a_swap") else {
            return;
        };
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let store = store_with_stub_uv(&temp.0.join("store"));
        let project = ProjectRoot::open(&project_dir).unwrap();
        let held = temp.0.join("held");
        std::fs::rename(&project_dir, &held).unwrap();
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("requirements.txt"), "decoy==1.0\n").unwrap();

        let result = ensure_lock(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &test_activity(&store),
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        );
        drop(result);
        let args = stub_args(&held);
        assert!(args.starts_with("pip compile requirements.txt "), "{args}");
        // uv builds any sdist on ward's CPython, named explicitly by the
        // forced row: `uv pip compile` ignores UV_PYTHON (#210). The probe
        // forbids every build, and the index is PyPI's.
        let python = store
            .object_path(
                &python::cpython_object_id(&selected(), Platform::host().unwrap()).unwrap(),
            )
            .join("bin/python3");
        assert!(
            args.contains(&format!("--python {}", python.display())),
            "{args}"
        );
        assert!(args.contains("--no-build"), "{args}");
        assert!(args.contains("--no-config"), "{args}");
        assert!(
            args.contains("--index-url https://pypi.org/simple"),
            "{args}"
        );
        assert_eq!(stub_input(&held), "six==1.17.0\n");
        assert!(!project_dir.join("requirements.lock.txt").exists());
    }

    /// A project whose `greyward.toml` names a requirements file outside it.
    fn external_requirements_project(temp: &Path) -> (PathBuf, PathBuf) {
        let project_dir = temp.join("proj");
        std::fs::create_dir_all(project_dir.join("requirements")).unwrap();
        let external = temp.join("shared/requirements.txt");
        std::fs::create_dir_all(external.parent().unwrap()).unwrap();
        std::fs::write(&external, "six==1.17.0\n").unwrap();
        std::fs::write(
            project_dir.join("greyward.toml"),
            format!("[python]\nrequirements = \"{}\"\n", external.display()),
        )
        .unwrap();
        (project_dir, external)
    }

    /// An external requirements file replaced between planning and the
    /// input record: the record is of the bytes the plan was made from,
    /// and the same command's status check agrees, while the next command
    /// sees the change (#501).
    #[test]
    fn an_external_requirements_file_is_read_once_per_command() {
        use sha2::{Digest, Sha256};
        let temp = crate::kernel::testutil::TempDir::new();
        let (project_dir, external) = external_requirements_project(&temp.0);
        let project = ProjectRoot::open(&project_dir).unwrap();
        let manifest = manifest::discover(
            Platform::host().unwrap(),
            &project,
            pyselect::DEFAULT_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.source, "six==1.17.0\n");
        std::fs::write(&external, "decoy==1.0\n").unwrap();
        let records = python_input_records(&project, &manifest).unwrap();
        let record = records
            .iter()
            .find(|record| Path::new(&record.path) == external)
            .expect("the external file is recorded");
        assert_eq!(record.sha256, hex::encode(Sha256::digest(b"six==1.17.0\n")));
        let body = serde_json::json!({ "inputs": records });
        assert_eq!(
            comforter::status::recorded_inputs_state(&project, &body).unwrap(),
            comforter::status::State::Synced
        );
        assert!(matches!(
            comforter::status::recorded_inputs_state(
                &ProjectRoot::open(&project_dir).unwrap(),
                &body
            )
            .unwrap(),
            comforter::status::State::Changed(_)
        ));
    }

    /// uv is never handed the external path, which it would reopen: it
    /// compiles the text ward read, written under `.greyward` (#501).
    #[test]
    fn uv_compiles_the_external_requirements_ward_read() {
        let Some(_relay) = stub_relay("uv_compiles_the_external_requirements_ward_read") else {
            return;
        };
        let temp = crate::kernel::testutil::TempDir::new();
        let (project_dir, external) = external_requirements_project(&temp.0);
        let store = store_with_stub_uv(&temp.0.join("store"));
        let project = ProjectRoot::open(&project_dir).unwrap();
        // The first read happens here; the replacement after it is not seen.
        assert!(project.read_external(&external).unwrap().is_some());
        std::fs::write(&external, "decoy==1.0\n").unwrap();
        let _ = ensure_lock(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &test_activity(&store),
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        );
        let args = stub_args(&project_dir);
        assert!(
            args.starts_with(&format!("pip compile {MANIFEST_REQUIREMENTS} ")),
            "{args}"
        );
        assert_eq!(stub_input(&project_dir), "six==1.17.0\n");
    }

    /// An in-project requirements file whose include lies beside the
    /// project: uv is not handed the file, which names the include by a
    /// path uv would reopen. It compiles the flattened text of the first
    /// read, so the include replaced after that read is not seen (#501).
    #[test]
    fn uv_compiles_the_flattened_text_when_an_include_is_external() {
        let Some(_relay) = stub_relay("uv_compiles_the_flattened_text_when_an_include_is_external")
        else {
            return;
        };
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(
            project_dir.join("requirements.txt"),
            "-r ../shared/base.txt\n",
        )
        .unwrap();
        let external = temp.0.join("shared/base.txt");
        std::fs::create_dir_all(external.parent().unwrap()).unwrap();
        std::fs::write(&external, "six==1.17.0\n").unwrap();
        let store = store_with_stub_uv(&temp.0.join("store"));
        let project = ProjectRoot::open(&project_dir).unwrap();
        // The first read happens here, by the spelling the include uses.
        assert!(project
            .read_external(&project_dir.join("../shared/base.txt"))
            .unwrap()
            .is_some());
        std::fs::write(&external, "decoy==1.0\n").unwrap();
        let _ = ensure_lock(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &test_activity(&store),
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        );
        let args = stub_args(&project_dir);
        assert!(
            args.starts_with(&format!("pip compile {MANIFEST_REQUIREMENTS} ")),
            "{args}"
        );
        assert_eq!(stub_input(&project_dir), "six==1.17.0\n");
    }

    /// A `setup.py egg_info` probe that cannot run must not abort planning:
    /// a PEP 621 `dynamic = ["dependencies"]` project falls back to the
    /// requirements-directory convention. Everything `prepare_setup` can
    /// fail with is already `InvalidData` (`unreadable` in the manifest
    /// layer hardcodes it), so the fallback cannot be gated on the kind.
    #[test]
    fn a_probe_failure_falls_back_to_the_requirements_directory() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(project_dir.join("requirements")).unwrap();
        std::fs::write(
            project_dir.join("pyproject.toml"),
            "[project]\nname = \"p\"\nversion = \"0\"\ndynamic = [\"dependencies\"]\n",
        )
        .unwrap();
        std::fs::write(
            project_dir.join("setup.py"),
            "from setuptools import setup\nsetup()\n",
        )
        .unwrap();
        let pinned = format!("six==1.17.0 --hash=sha256:{}\n", "a".repeat(64));
        std::fs::write(project_dir.join("requirements/common.txt"), &pinned).unwrap();
        // A store root that is a regular file: the probe's first store
        // access fails offline and immediately, which is the cheapest
        // stand-in for "egg_info cannot run here".
        let store_root = temp.0.join("not-a-store");
        std::fs::write(&store_root, b"").unwrap();
        let store = store::Store::for_test(store_root);

        // Prime the plan cache under the key the fallback text produces, so
        // planning finishes offline. A cache hit is itself the assertion:
        // if the probe failure had aborted, or the fallback had read
        // anything but requirements/common.txt, this key would not match.
        let platform = Platform::host().unwrap();
        let version = pyselect::select_python(platform, &[]).unwrap().pin.version;
        let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            pypi::host_glibc().unwrap()
        } else {
            pypi::Glibc(0, 0)
        };
        let plan = types::Plan {
            ecosystem: "python".into(),
            python_version: version.into(),
            packages: Vec::new(),
        };
        let project = ProjectRoot::open(&project_dir).unwrap();
        project
            .write_file(
                Path::new(PLAN_CACHE),
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "input_hash": planner_input_hash(platform, version, &pinned, glibc),
                    "plan": plan,
                }))
                .unwrap(),
            )
            .unwrap();

        let (planned, selection, inputs) = read_plan(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                platform,
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap();
        assert_eq!(planned.python_version, version);
        assert_eq!(selection.pin.version, version);
        assert!(
            inputs
                .iter()
                .any(|record| record.path == "requirements/common.txt"),
            "planning did not read the requirements directory: {:?}",
            inputs.iter().map(|r| &r.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn manifest_snapshots_behind_a_symlinked_ward_are_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        // A pyproject manifest needs a generated uv compile input, so the
        // manifest snapshot is written before uv or the store is reached.
        std::fs::write(
            project_dir.join("pyproject.toml"),
            "[project]\nname = \"p\"\nversion = \"0\"\ndependencies = [\"six\"]\n",
        )
        .unwrap();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project_dir.join(".greyward")).unwrap();
        let store = store::Store::for_test(temp.0.join("absent-store"));

        let project = ProjectRoot::open(&project_dir).unwrap();
        let error = ensure_lock(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a real directory"), "{error}");
        assert!(!store.root.exists(), "a refused snapshot touched the store");
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "wrote a manifest snapshot through the symlinked .greyward"
        );
    }

    /// Every file under `dir`, by relative path, with its bytes.
    fn tree(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(next) = pending.pop() {
            for entry in std::fs::read_dir(&next).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    files.insert(path.strip_prefix(dir).unwrap().to_path_buf(), bytes);
                }
            }
        }
        files
    }

    /// Planning an unpinned project with no lock is the missing-lock
    /// refusal, exit 4, and it writes nothing: compiling the lock is
    /// `prepare`'s, which `--frozen` skips (#673).
    #[test]
    fn planning_with_no_lock_is_stale_and_writes_nothing() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("requirements.txt"), "six>=1\n").unwrap();
        let before = tree(&project_dir);
        let store = store::Store::for_test(temp.0.join("absent-store"));
        let project = ProjectRoot::open(&project_dir).unwrap();
        let error = read_plan(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err();
        assert_eq!(
            crate::kernel::error::class_of(&error),
            Some(crate::kernel::error::Class::Stale),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("requirements.lock.txt is missing and --frozen never creates it"),
            "{error}"
        );
        assert_eq!(tree(&project_dir), before);
        assert!(!store.root.exists(), "planning touched the store");
    }

    /// A lock this machine compiled from other requirements is stale when
    /// planned without `prepare`, as `--frozen` plans: the refusal is exit 4
    /// and every project file, `.greyward` included, stays byte for byte
    /// what it was (#673). `prepare` compiles it afresh.
    #[test]
    fn planning_reads_the_lock_and_refuses_one_compiled_from_other_inputs() {
        let Some(_relay) =
            stub_relay("planning_reads_the_lock_and_refuses_one_compiled_from_other_inputs")
        else {
            return;
        };
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("requirements.txt"), "six>=1\n").unwrap();
        let store = store_with_stub_uv(&temp.0.join("store"));
        let project = ProjectRoot::open(&project_dir).unwrap();
        let mut scope = crate::kernel::testutil::DoorScope::new();
        let activity = test_activity(&store);
        let platform = Platform::host().unwrap();
        ensure_lock(
            &project,
            &selected(),
            &mut scope.door(&store, &activity, platform, DoorKind::MissingLock),
        )
        .unwrap();
        assert_eq!(stub_input(&project_dir), "six>=1\n");
        assert!(project_dir.join(LOCK_STAMP).is_file());

        std::fs::write(project_dir.join("requirements.txt"), "six>=1.16\n").unwrap();
        let before = tree(&project_dir);
        let error = read_plan(
            &project,
            &selected(),
            &mut scope.door(&store, &activity, platform, DoorKind::Planner),
        )
        .unwrap_err();
        assert_eq!(
            crate::kernel::error::class_of(&error),
            Some(crate::kernel::error::Class::Stale),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("was not compiled from requirements.txt as it is now"),
            "{error}"
        );
        assert_eq!(tree(&project_dir), before, "a stale plan wrote a file");

        ensure_lock(
            &project,
            &selected(),
            &mut scope.door(&store, &activity, platform, DoorKind::MissingLock),
        )
        .unwrap();
        assert_eq!(stub_input(&project_dir), "six>=1.16\n");
    }

    /// A committed lock with no stamp beside it (a fresh checkout: the
    /// stamp is machine-local) is read as it is, and an empty one is stale.
    #[test]
    fn a_committed_lock_without_a_stamp_is_read_and_an_empty_one_is_stale() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        std::fs::write(temp.0.join(LOCK), "six==1.17.0 --hash=sha256:aa\n").unwrap();
        assert_eq!(
            read_lock(&project, "requirements.txt", "stamp").unwrap(),
            "six==1.17.0 --hash=sha256:aa\n"
        );
        std::fs::write(temp.0.join(LOCK), "").unwrap();
        let error = read_lock(&project, "requirements.txt", "stamp").unwrap_err();
        assert_eq!(
            crate::kernel::error::class_of(&error),
            Some(crate::kernel::error::Class::Stale),
            "{error}"
        );
    }

    #[test]
    fn plan_skipped_requirement_is_strict_or_recorded_once() {
        let _attribution_lock = policy::exception_guard();
        let attribution = policy::Attribution::open("python").unwrap();
        let source = ".\n";
        let strict = policy::Policy {
            strict: true,
            ..policy::Policy::default()
        };
        let error = record_skippable_specs_with(source, |kind, subject, detail| {
            policy::record_with(&strict, kind, subject, detail)
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut recorded = Vec::new();
        record_skippable_specs_with(source, |kind, subject, detail| {
            recorded.push((kind.to_string(), subject.to_string(), detail.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(pypi::parse_requirements(source).unwrap().is_empty());
        attribution.discard();
    }
}
