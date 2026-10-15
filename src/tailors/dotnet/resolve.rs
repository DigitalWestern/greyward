//! The .NET resolution doors: the store SDK's restore confined through the
//! proxy session's NuGet mirror, for a missing lock and for `ward attest`.

use super::door::{dotnet_tool, run_restore, DotnetRun};
use super::solution::{self, lock_beside, Layout};
use super::{err, require_lock, ParsedLock, LOCK_FILE};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::record;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use sha2::{Digest as _, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Only the validated project's files and locks are restore outputs.
/// A computed reference that escapes the checked graph cannot publish an
/// unexpected lock beside an unselected project.
pub(super) fn outputs_of(layout: &Layout) -> Vec<PathBuf> {
    let mut outputs = layout.members.clone();
    outputs.extend(layout.member_locks());
    outputs
}

/// The layout, its resolution outputs and its inputs (every other regular
/// file restore can see).
fn files(project: &ProjectRoot) -> io::Result<(Layout, Vec<PathBuf>, Vec<PathBuf>)> {
    let layout = solution::discover(project)?;
    let all = crate::kernel::resolve::inputs::project_files(project, &super::door::EXCLUDE, &[])?;
    let outputs = outputs_of(&layout);
    let inputs = all
        .into_iter()
        .filter(|path| !outputs.contains(path))
        .collect();
    Ok((layout, outputs, inputs))
}

/// The project files and packages.lock.json files: what restore resolves
/// from and writes.
pub(crate) fn resolution_outputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    Ok(files(project)?.1)
}

/// MSBuild property functions and imported targets can read arbitrary project
/// data. Bind every regular file visible to its snapshot until precise input
/// declarations have a reviewed design.
pub(crate) fn resolution_inputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    Ok(files(project)?.2)
}

/// Every resolution file of `project` that exists, by digest: a closure's
/// `resolution_basis`.
pub(crate) fn resolution_basis(
    project: &ProjectRoot,
) -> io::Result<crate::comforter::join::Digests> {
    let (_, mut listed, inputs) = files(project)?;
    listed.extend(inputs);
    record::file_digests(project, &listed)
}

fn is_lock_path(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|name| name == LOCK_FILE)
}

/// Command-line global properties hold the lock contract unless imported
/// MSBuild opts them back into local reassignment. Every file MSBuild can
/// import is scanned, whatever its extension: any file holding a
/// `<Project` element, in every encoding XML allows (UTF-16/32's
/// NUL-padded ASCII names included). A README or a data file holds none,
/// so a solution's whole tree is not refused for mentioning a name. This
/// is a conservative refusal.
fn reject_lock_controls(
    project: &ProjectRoot,
    basis: &crate::comforter::join::Digests,
) -> io::Result<()> {
    for path in basis.keys().filter(|path| !is_lock_path(path)) {
        let bytes = project
            .read_input(Path::new(path))?
            .ok_or_else(|| err("MSBuild input vanished"))?;
        let ascii: Vec<u8> = bytes
            .into_iter()
            .filter(|byte| *byte != 0)
            .map(|byte| byte.to_ascii_lowercase())
            .collect();
        let holds = |name: &str| {
            ascii
                .windows(name.len())
                .any(|part| part == name.as_bytes())
        };
        if !holds("<project") {
            continue;
        }
        for control in ["treataslocalproperty", "nugetlockfilepath"] {
            if holds(control) {
                return Err(err(format!("{path}: unsupported MSBuild lock control {control}; restore must check packages.lock.json with ward's global settings")));
            }
        }
    }
    Ok(())
}

/// One member's packages.lock.json as preflight read it.
#[derive(Debug)]
pub(super) struct MemberLock {
    pub path: PathBuf,
    pub text: String,
    pub parsed: ParsedLock,
}

/// What preflight checked: the layout (the single project, or the
/// solution's members and skips), each member lock's text and parse when
/// it exists (it may not until delegated planning writes it), and the
/// resolution basis. Planning and realization take it as proof.
#[derive(Debug)]
pub struct Preflight {
    pub(super) layout: Layout,
    pub(super) locks: Vec<MemberLock>,
    pub(super) basis: crate::comforter::join::Digests,
    pub(super) references: std::collections::BTreeMap<PathBuf, Vec<PathBuf>>,
    /// Does any member target Windows: a lock framework such as
    /// `net8.0-windows`, or project text that names one or WPF or
    /// Windows Forms? Its restore then needs `EnableWindowsTargeting`,
    /// which every other project is better without: it makes restore
    /// fetch the Windows Desktop targeting pack, which no lock pins.
    pub(super) windows: bool,
}

/// Does a lock target (`net8.0-windows7.0/win-x64`) build for Windows?
fn windows_target(target: &str) -> bool {
    super::target_framework(target).is_ok_and(|tfm| tfm.contains("-windows"))
}

/// Does project text (lowercase) ask for Windows targeting?
fn windows_text(text: &str) -> bool {
    [
        "-windows",
        "<usewpf",
        "<usewindowsforms",
        "<enablewindowstargeting",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

impl Preflight {
    /// The members whose lock targets Windows: `ward build` leaves them
    /// out, because their build needs a Windows targeting pack no lock
    /// pins and the build has no network to fetch it.
    pub(super) fn windows_members(&self) -> Vec<PathBuf> {
        self.layout
            .members
            .iter()
            .filter(|member| {
                let lock = lock_beside(member);
                self.locks.iter().any(|read| {
                    read.path == lock
                        && read
                            .parsed
                            .targets
                            .iter()
                            .any(|target| windows_target(target))
                })
            })
            .cloned()
            .collect()
    }

    /// For a solution, each member lock's path and sha256, which its
    /// closure records; empty for a single project.
    pub(super) fn lock_inputs(&self) -> Vec<(String, String)> {
        if self.layout.solution.is_none() && self.layout.members.len() == 1 {
            return Vec::new();
        }
        self.locks
            .iter()
            .map(|read| {
                (
                    read.path.to_string_lossy().into_owned(),
                    hex::encode(Sha256::digest(read.text.as_bytes())),
                )
            })
            .collect()
    }

    /// Record each listed project the solution's restore skips that may
    /// carry dependencies: a `requirement-skipped` exception per project.
    pub(super) fn record_skips(&self) -> io::Result<()> {
        for skip in self.layout.skipped.iter().filter(|skip| skip.record) {
            crate::kernel::policy::record_plan_time(
                crate::kernel::policy::REQUIREMENT_SKIPPED,
                &skip.path,
                &format!("not restored: {}", skip.why),
            )?;
        }
        Ok(())
    }
}

/// All captured MSBuild documents receive the project restrictions, even
/// when an import has a custom filename or an XML encoding other than UTF-8.
/// This deliberately scans the visible tree conservatively, because import
/// paths may be computed by project code.
fn validate_msbuild_inputs(
    project: &ProjectRoot,
    basis: &crate::comforter::join::Digests,
    layout: &Layout,
) -> io::Result<()> {
    for path in basis.keys().filter(|path| !is_lock_path(path)) {
        let rel = Path::new(path);
        // A .slnx contains <Project> entries under <Solution>. Discovery
        // already validated it as a solution, not an importable MSBuild
        // document. Keep it in the input basis without treating those
        // entries as the root of an MSBuild project.
        if layout.solution.as_deref() == Some(rel) {
            continue;
        }
        let bytes = project
            .read_input(rel)?
            .ok_or_else(|| err("MSBuild input vanished"))?;
        let ascii: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .map(|byte| byte.to_ascii_lowercase())
            .collect();
        if !ascii.windows(8).any(|part| part == b"<project") {
            continue;
        }
        super::validate_csproj(project, rel)?;
        let markup = super::strip_comments_and_cdata(&super::decode_msbuild(&bytes)?, rel)?
            .to_ascii_lowercase();
        if !layout.members.contains(&rel.to_path_buf()) {
            if super::opens_element(&markup, "projectreference") {
                return Err(err(format!("{path}: ProjectReference in an imported or unselected file is unsupported; declare literal references in the member project so every reached project can be validated")));
            }
            if super::OUTPUT_PROPERTIES
                .iter()
                .any(|name| super::opens_element(&markup, &name.to_ascii_lowercase()))
                && rel
                    .file_name()
                    .is_none_or(|name| name != "Directory.Build.props")
            {
                return Err(err(format!("{path}: output properties in an imported file can run after ward's output hook; move them to the SDK-style project or Directory.Build.props")));
            }
        }
    }
    Ok(())
}

/// Central v0 trust-boundary validation.
///
/// Project files are read through the held descriptor (a held root is a
/// directory by construction); the returned paths are for messages and
/// child-process arguments. Ancestors lie outside the project and are
/// still inspected by path.
pub fn preflight(project: &ProjectRoot, sdk_version: &str) -> io::Result<Preflight> {
    let observed = project.observing_inputs()?;
    let project = &observed;
    let basis = resolution_basis(project)?;
    reject_lock_controls(project, &basis)?;
    let layout = solution::discover(project)?;
    for member in &layout.members {
        if !super::regular_file_if_present(project, member, "project file")? {
            return Err(err(format!(
                "project file is missing: {}",
                project.path().join(member).display()
            )));
        }
        super::validate_csproj(project, member)?;
    }
    validate_msbuild_inputs(project, &basis, &layout)?;
    for lock in layout.member_locks() {
        super::regular_file_if_present(project, &lock, "packages.lock.json")?;
    }
    super::regular_file_if_present(project, Path::new("global.json"), "global.json")?;
    super::check_global_json(project, sdk_version)?;

    // Each directory above is reached from the held project, not its path.
    for (depth, ancestor) in project.ancestors().enumerate() {
        let ancestor = ancestor?;
        let present = |name: &str| {
            ancestor
                .entry(Path::new(name))
                .map(|entry| entry != crate::kernel::fsroot::Entry::Absent)
        };
        // Directory.Build.rsp adds arguments to every command line ward
        // runs; above the project, every file is one restore cannot see.
        let mut refused = vec!["Directory.Build.rsp"];
        if depth > 0 {
            refused.push("Directory.Packages.props");
        }
        if depth > 0 || layout.solution.is_none() {
            refused.push("packages.config");
        }
        for name in refused {
            if present(name)? {
                return Err(err(format!(
                    "{name} is not supported in the project or an SDK ancestor: {}",
                    ancestor.path().join(name).display()
                )));
            }
        }
        if depth > 0 && present("global.json")? {
            return Err(err(format!(
                "ancestor global.json is not supported; SDK discovery would see {}",
                ancestor.path().join("global.json").display()
            )));
        }
    }
    let mut locks = Vec::new();
    for path in layout.member_locks() {
        if project.is_input_file(&path) {
            let text = super::read_input_text(project, &path)?;
            let parsed =
                super::parse_lock(&text).map_err(|e| err(format!("{}: {e}", path.display())))?;
            locks.push(MemberLock { path, text, parsed });
        }
    }
    let mut windows = locks.iter().any(|read| {
        read.parsed
            .targets
            .iter()
            .any(|target| windows_target(target))
    });
    // Every MSBuild file of the tree, imported .props included: the
    // framework is often set in one a project imports by path.
    for path in basis.keys().filter(|path| !is_lock_path(path)) {
        if windows {
            break;
        }
        let bytes = project
            .read_input(Path::new(path))?
            .ok_or_else(|| err("MSBuild input vanished"))?;
        let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        windows = text.contains("<project") && windows_text(&text);
    }
    let references = layout
        .members
        .iter()
        .map(|member| Ok((member.clone(), solution::references(project, member)?)))
        .collect::<io::Result<_>>()?;
    project.verify_observed_inputs()?;
    if resolution_basis(project)? != basis {
        return Err(err(
            ".NET resolution inputs changed during preflight; run `ward` again",
        ));
    }
    Ok(Preflight {
        layout,
        locks,
        basis,
        references,
        windows,
    })
}

/// Build receipt filenames from the already validated generation. Re-listing
/// the live project here could omit a temporarily removed input that is
/// restored before staging (an ABA race).
fn receipt_spec(
    checked: &Preflight,
    selected: &Selected,
    args: &[String],
) -> io::Result<record::RecordSpec> {
    let outputs = outputs_of(&checked.layout);
    let inputs = checked
        .basis
        .keys()
        .map(PathBuf::from)
        .filter(|path| !outputs.contains(path))
        .collect();
    let tool = dotnet_tool(selected)?;
    let mut command = vec![tool.name.clone(), "restore".to_string()];
    command.extend(args.iter().cloned());
    let spec = record::RecordSpec {
        tool,
        command,
        files: record::ResolutionFiles { outputs, inputs },
        key: crate::comforter::signing_key(),
        require_unchanged: false,
        publish_receipt: true,
    };
    #[cfg(test)]
    after_receipt_spec_for_test();
    Ok(spec)
}

/// The arguments after `dotnet restore` for `checked`'s layout: the
/// generated solution and the user solution's properties for a solution,
/// nothing for a single project (restore finds it in the project
/// directory), then `mode`, and Windows targeting when a member needs it,
/// so a project for `net8.0-windows` restores on any host.
fn restore_args(
    project: &ProjectRoot,
    checked: &Preflight,
    mode: &str,
) -> io::Result<(Vec<String>, Option<String>)> {
    let mut args = Vec::new();
    let mut generated = None;
    if let Some(solution) = &checked.layout.solution {
        args.push(format!("@SCRATCH@/{}", super::door::SOLUTION_FILE));
        generated = Some(solution::generated_sln(
            project.path(),
            &checked.layout.members,
            &[],
        )?);
        args.extend(solution::solution_properties(project.path(), solution)?);
    }
    args.push(mode.to_string());
    // A project in MSBuild's artifacts mode would put its obj in an
    // `artifacts/` the snapshot diff sees; restore writes it beside each
    // project instead, where the diff ignores it. The locks are the same.
    args.push("-p:UseArtifactsOutput=false".to_string());
    if checked.windows {
        args.push("-p:EnableWindowsTargeting=true".to_string());
    }
    Ok((args, generated))
}

/// `prepare`: a packages.lock.json for every member, written by the store
/// SDK's `restore --use-lock-file` when one is missing. The one place the
/// .NET tailor writes project inputs. Restore runs confined through `door`
/// (a missing-lock door), and the locks and the signed resolution record
/// are published together through its transaction. A member's committed
/// lock is not an output of the run: restore may leave it as it is, and a
/// run that would change it is refused.
pub fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    sdk_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    let checked = preflight(project, selected.version("dotnet-sdk")?)?;
    let basis = &checked.basis;
    #[cfg(test)]
    after_preflight_for_test();
    let missing: Vec<PathBuf> = checked
        .layout
        .member_locks()
        .into_iter()
        .filter(|lock| !basis.contains_key(&*lock.to_string_lossy()))
        .collect();
    ui::note(&format!(
        "no {}; resolving with the store SDK...",
        missing
            .iter()
            .map(|lock| lock.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let (args, generated) = restore_args(project, &checked, "--use-lock-file")?;
    let spec = receipt_spec(&checked, selected, &args)?;
    let outputs = spec
        .files
        .outputs
        .iter()
        .filter(|path| {
            !(is_lock_path(&path.to_string_lossy()) && basis.contains_key(&*path.to_string_lossy()))
        })
        .cloned()
        .collect();
    let report = run_restore(
        door,
        DotnetRun {
            sdk_obj,
            lock_root: project.path(),
            args,
            solution: generated,
            required: checked.layout.member_locks(),
            outputs,
            inputs: Some(basis),
            receipt: Some(record::producer(spec, Default::default())),
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "store dotnet restore --use-lock-file failed: {}",
            restore_failure(&report)
        )));
    }
    Ok(())
}

/// `ward attest` for .NET: `restore --locked-mode` in the project, through
/// `door`'s transaction with the record's producer. A project file the
/// lock no longer matches fails locked mode (NU1004); a lock it would
/// rewrite anyway is refused by the record. Nothing is published here.
pub fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    sdk_obj: &Path,
    selected: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    let checked = preflight(project, selected.version("dotnet-sdk")?)?;
    let basis = &checked.basis;
    #[cfg(test)]
    after_preflight_for_test();
    require_lock(project)?;
    let (args, generated) = restore_args(project, &checked, "--locked-mode")?;
    let mut spec = receipt_spec(&checked, selected, &args)?;
    let outputs = spec.files.outputs.clone();
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = run_restore(
        door,
        DotnetRun {
            sdk_obj,
            lock_root: project.path(),
            args,
            solution: generated,
            required: checked.layout.member_locks(),
            outputs,
            inputs: Some(basis),
            receipt: Some(record::producer(spec, slot.clone())),
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "the packages.lock.json files in {} are not what restore would write, so they are \
             not attested; run `ward` to bring them up to date and commit the result\n{}",
            project.path().display(),
            restore_failure(&report)
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("restore's lock check published no record"))
}

/// What a failed restore said: MSBuild writes its errors to stdout.
fn restore_failure(report: &crate::kernel::resolve::DelegateReport) -> String {
    let mut text = String::from_utf8_lossy(&report.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&report.stdout);
    for line in stdout.lines().filter(|line| line.contains("error")) {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(line.trim());
    }
    text
}

#[cfg(test)]
thread_local! {
    static AFTER_RECEIPT_SPEC_FOR_TEST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_PREFLIGHT_FOR_TEST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn after_preflight_for_test() {
    let hook = AFTER_PREFLIGHT_FOR_TEST.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn after_receipt_spec_for_test() {
    let hook = AFTER_RECEIPT_SPEC_FOR_TEST.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::testing::{relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC};
    use crate::kernel::resolve::DoorKind;
    use crate::kernel::testutil::TempDir;
    use crate::tailors::dotnet::registry::HOST;
    use std::fs;
    use std::io::Write as _;

    fn write_project(root: &Path, file: &str, text: &str) {
        let path = root.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn unlisted_references_contribute_private_packages_and_lock_inputs() {
        let temp = TempDir::named("dotnet-reference-graph");
        write_project(
            &temp.0,
            "App.slnx",
            "<Solution><Project Path=\"App/App.csproj\" /></Solution>",
        );
        write_project(
            &temp.0,
            "App/App.csproj",
            &csproj("<ProjectReference Include=\"../Hidden/Hidden.csproj\" />"),
        );
        write_project(&temp.0, "Hidden/Hidden.csproj", &csproj("<PackageReference Include=\"Example.Private\" Version=\"1.0.0\" PrivateAssets=\"all\" />"));
        write_project(
            &temp.0,
            "App/packages.lock.json",
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        );
        let hash = crate::kernel::base64::encode(&[7; 64]);
        write_project(
            &temp.0,
            "Hidden/packages.lock.json",
            &format!(
                r#"{{"version":1,"dependencies":{{"net9.0":{{"Example.Private":{{"type":"Direct","resolved":"1.0.0","contentHash":"{hash}"}}}}}}}}"#
            ),
        );
        let project = ProjectRoot::open(&temp.0).unwrap();
        let selected = super::super::shipped_selection().unwrap();
        let checked = preflight(&project, selected.version("dotnet-sdk").unwrap()).unwrap();
        assert_eq!(
            checked.layout.members,
            [
                PathBuf::from("App/App.csproj"),
                PathBuf::from("Hidden/Hidden.csproj")
            ]
        );
        assert_eq!(checked.lock_inputs().len(), 2);
        let (plan, _) = super::super::plan_dotnet(&project, &selected, &checked).unwrap();
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].id, "Example.Private");
        // A single root project follows exactly the same reference graph.
        fs::remove_file(temp.0.join("App.slnx")).unwrap();
        write_project(
            &temp.0,
            "Root.csproj",
            &csproj("<ProjectReference Include=\"Hidden/Hidden.csproj\" />"),
        );
        write_project(
            &temp.0,
            "packages.lock.json",
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        );
        // Unselected projects are still visible inputs, so remove the old
        // referencing member from this single-project fixture.
        fs::remove_file(temp.0.join("App/App.csproj")).unwrap();
        let checked = preflight(&project, selected.version("dotnet-sdk").unwrap()).unwrap();
        assert_eq!(checked.lock_inputs().len(), 2);
        let (plan, _) = super::super::plan_dotnet(&project, &selected, &checked).unwrap();
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.members.len(), 2);
    }

    #[test]
    fn references_cannot_reintroduce_skipped_projects_or_hide_collisions() {
        let temp = TempDir::named("dotnet-reference-refusals");
        write_project(
            &temp.0,
            "App.slnx",
            "<Solution><Project Path=\"App/App.csproj\" /></Solution>",
        );
        let project = ProjectRoot::open(&temp.0).unwrap();
        for (reference, target, body, expected) in [
            (
                "../Hidden/Hidden.csproj",
                "Hidden/Hidden.csproj",
                "<Project Sdk=\"Other.Sdk/1.0\" />",
                "cannot be validated",
            ),
            (
                "../App/Other.csproj",
                "App/Other.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />",
                "share a directory",
            ),
            (
                "$(Hidden)/Hidden.csproj",
                "Hidden/Hidden.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />",
                "dynamic ProjectReference",
            ),
            (
                "../../Outside.csproj",
                "Hidden/Hidden.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\" />",
                "leaves the restore input tree",
            ),
        ] {
            write_project(
                &temp.0,
                "App/App.csproj",
                &csproj(&format!("<ProjectReference Include=\"{reference}\" />")),
            );
            write_project(&temp.0, target, body);
            let why = preflight(&project, "9.0.317").unwrap_err().to_string();
            assert!(why.contains(expected), "{why}");
        }
    }

    #[test]
    fn imported_features_are_checked_in_every_xml_encoding() {
        let temp = TempDir::named("dotnet-import-validation");
        write_project(
            &temp.0,
            "App.csproj",
            &csproj("").replace("</Project>", "<Import Project=\"custom.data\" /></Project>"),
        );
        let project = ProjectRoot::open(&temp.0).unwrap();
        for feature in [
            "<ItemGroup><PackageDownload Include=\"Example.Hidden\" Version=\"[1.0.0]\" />",
            "<UsingTask TaskName=\"Hidden\" AssemblyFile=\"hidden.dll\" />",
            "<PropertyGroup><RestoreSources>https://example.test</RestoreSources></PropertyGroup>",
            "<Sdk Name=\"Other.Sdk\" Version=\"1.0.0\" />",
            "<ProjectReference Include=\"Hidden.csproj\" />",
        ] {
            let text = format!("<Project>{feature}</Project>");
            let encodings = [
                text.as_bytes().to_vec(),
                std::iter::once(0xfeffu16)
                    .chain(text.encode_utf16())
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                std::iter::once(0xfeffu16)
                    .chain(text.encode_utf16())
                    .flat_map(u16::to_be_bytes)
                    .collect(),
                std::iter::once('\u{feff}')
                    .chain(text.chars())
                    .flat_map(|c| (c as u32).to_le_bytes())
                    .collect(),
                std::iter::once('\u{feff}')
                    .chain(text.chars())
                    .flat_map(|c| (c as u32).to_be_bytes())
                    .collect(),
            ];
            for bytes in encodings {
                fs::write(temp.0.join("custom.data"), bytes).unwrap();
                let why = preflight(&project, "9.0.317").unwrap_err().to_string();
                assert!(why.contains("custom.data"), "{feature}: {why}");
            }
        }
        fs::write(
            temp.0.join("custom.data"),
            "<Project><PropertyGroup><Version>1.0</Version></PropertyGroup></Project>",
        )
        .unwrap();
        preflight(&project, "9.0.317").unwrap();
    }

    #[test]
    fn imported_sdk_projects_are_members_and_late_outputs_are_refused() {
        let temp = TempDir::named("dotnet-imported-sdk");
        write_project(
            &temp.0,
            "App.slnx",
            "<Solution><Project Path=\"App/App.csproj\" /></Solution>",
        );
        write_project(
            &temp.0,
            "App/App.csproj",
            "<Project><Import Project=\"../sdk.props\" /></Project>",
        );
        write_project(&temp.0, "sdk.props", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>");
        let project = ProjectRoot::open(&temp.0).unwrap();
        let checked = preflight(&project, "9.0.317").unwrap();
        assert_eq!(checked.layout.members, [PathBuf::from("App/App.csproj")]);
        assert!(checked.layout.skipped.is_empty());
        for file in ["Directory.Build.targets", "late.props", "late.custom"] {
            write_project(&temp.0, file, "<Project><PropertyGroup><OutDir>$(MSBuildProjectDirectory)/LateOutput/</OutDir></PropertyGroup></Project>");
            let why = preflight(&project, "9.0.317").unwrap_err().to_string();
            assert!(why.contains("output properties"), "{why}");
            fs::remove_file(temp.0.join(file)).unwrap();
        }
    }

    #[test]
    fn a_retained_member_cannot_build_a_skipped_windows_reference() {
        let temp = TempDir::named("dotnet-reference-windows");
        write_project(
            &temp.0,
            "App.slnx",
            "<Solution><Project Path=\"App/App.csproj\" /></Solution>",
        );
        write_project(
            &temp.0,
            "App/App.csproj",
            &csproj("<ProjectReference Include=\"../Windows/Windows.csproj\" />"),
        );
        write_project(&temp.0, "Windows/Windows.csproj", &csproj(""));
        write_project(
            &temp.0,
            "App/packages.lock.json",
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        );
        write_project(
            &temp.0,
            "Windows/packages.lock.json",
            r#"{"version":1,"dependencies":{"net9.0-windows7.0":{}}}"#,
        );
        let checked = preflight(&ProjectRoot::open(&temp.0).unwrap(), "9.0.317").unwrap();
        let why = super::super::build::buildable(&checked)
            .unwrap_err()
            .to_string();
        assert!(
            why.contains("App/App.csproj references Windows project Windows/Windows.csproj"),
            "{why}"
        );
    }

    #[test]
    fn msbuild_data_and_nested_imports_are_resolution_inputs() {
        let temp = TempDir::named("dotnet-inputs");
        for directory in ["config/nested", "obj", "bin", ".git", ".greyward"] {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        fs::write(temp.0.join("app.csproj"), csproj("")).unwrap();
        fs::write(temp.0.join("config/nested/version.txt"), "1.0.0").unwrap();
        for file in [
            "obj/ignored",
            "bin/ignored",
            ".git/config",
            ".greyward/closure.json",
        ] {
            fs::write(temp.0.join(file), "excluded").unwrap();
        }
        let project = ProjectRoot::open(&temp.0).unwrap();
        assert_eq!(
            resolution_inputs(&project).unwrap(),
            vec![PathBuf::from("config/nested/version.txt")]
        );
        let before = resolution_basis(&project).unwrap();
        fs::write(temp.0.join("config/nested/version.txt"), "2.0.0").unwrap();
        assert_ne!(resolution_basis(&project).unwrap(), before);
        std::os::unix::fs::symlink("config", temp.0.join("linked")).unwrap();
        assert!(resolution_inputs(&project).is_err());
    }

    #[test]
    fn a_cached_preflight_cannot_label_a_changed_project_generation() {
        let temp = TempDir::named("dotnet-captured-plan");
        fs::write(temp.0.join("app.csproj"), csproj("")).unwrap();
        fs::write(
            temp.0.join(LOCK_FILE),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        fs::write(temp.0.join("version.txt"), "A").unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let selected = super::super::shipped_selection().unwrap();
        let checked = preflight(&project, selected.version("dotnet-sdk").unwrap()).unwrap();
        super::super::plan_dotnet(&project, &selected, &checked).unwrap();
        fs::write(temp.0.join("version.txt"), "B").unwrap();
        let why = super::super::plan_dotnet(&project, &selected, &checked)
            .unwrap_err()
            .to_string();
        assert!(why.contains("resolution inputs changed"), "{why}");
        fs::write(temp.0.join("version.txt"), "A").unwrap();
        fs::write(temp.0.join("new.props"), "new input").unwrap();
        assert!(super::super::plan_dotnet(&project, &selected, &checked).is_err());
        fs::remove_file(temp.0.join("new.props")).unwrap();
        fs::write(temp.0.join("app.csproj"), csproj("<!-- changed -->")).unwrap();
        assert!(super::super::plan_dotnet(&project, &selected, &checked).is_err());
    }

    #[test]
    fn alternate_lock_controls_are_refused_in_main_and_imported_files() {
        let temp = TempDir::named("dotnet-lock-control");
        let plain = csproj("");
        fs::write(temp.0.join("app.csproj"), &plain).unwrap();
        fs::write(
            temp.0.join(LOCK_FILE),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        fs::write(
            temp.0.join("alternate.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{}}}}"#,
        )
        .unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let sdk_version = super::super::shipped_selection()
            .unwrap()
            .version("dotnet-sdk")
            .unwrap()
            .to_owned();
        fs::write(temp.0.join("app.csproj"), plain.replace("</Project>", "<PropertyGroup><NuGetLockFilePath>alternate.lock.json</NuGetLockFilePath></PropertyGroup></Project>")).unwrap();
        let why = preflight(&project, &sdk_version).unwrap_err().to_string();
        assert!(why.contains("nugetlockfilepath"), "{why}");
        fs::write(temp.0.join("app.csproj"), &plain).unwrap();
        for control in [
            "<Project TreatAsLocalProperty=\"NuGetLockFilePath;RestoreLockedMode\" />",
            "<Project><PropertyGroup><NuGetLockFilePath>alternate.lock.json</NuGetLockFilePath></PropertyGroup></Project>",
        ] {
            fs::write(temp.0.join("Directory.Build.props"), control).unwrap();
            assert!(preflight(&project, &sdk_version).is_err());
            let utf16: Vec<_> = std::iter::once(0xfeffu16).chain(control.encode_utf16()).flat_map(u16::to_le_bytes).collect();
            fs::write(temp.0.join("Directory.Build.props"), utf16).unwrap();
            assert!(preflight(&project, &sdk_version).is_err());
        }
    }

    /// An unsigned package with one netstandard2.0 asset, so the fixture
    /// restore has a real `.nupkg` to install (the recorded rows kept
    /// Humanizer.Core's index but not its 500 KB body).
    fn fixture_nupkg() -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("Greyward.Fixture.nuspec", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<package \
              xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n  \
              <metadata>\n    <id>Greyward.Fixture</id>\n    <version>1.0.0</version>\n    \
              <authors>ward</authors>\n    <description>ward test fixture</description>\n  \
              </metadata>\n</package>\n",
        )
        .unwrap();
        zip.start_file("lib/netstandard2.0/_._", options).unwrap();
        zip.finish().unwrap().into_inner()
    }

    /// A harness whose upstream answers api.nuget.org from the recorded
    /// NuGet rows plus a served Greyward.Fixture 1.0.0 (with its
    /// registration leaf) and an empty
    /// vulnerability base (the recording kept neither body), and whose
    /// proxy every door in this thread uses while it lives.
    fn nuget_harness(label: &str) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(20);
        let rows = stored_rows("dotnet", label);
        let mut kept: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(rows.0.join("index.json")).unwrap()).unwrap();
        let stamp = "2026.09.23.05.36.38";
        for (path, body) in [
            (
                "/v3-flatcontainer/greyward.fixture/index.json".to_string(),
                br#"{"versions":["1.0.0"]}"#.to_vec(),
            ),
            (
                "/v3-flatcontainer/greyward.fixture/1.0.0/greyward.fixture.1.0.0.nupkg".to_string(),
                fixture_nupkg(),
            ),
            (
                format!("/v3-vulnerabilities/{stamp}/vulnerability.base.json"),
                b"{}".to_vec(),
            ),
            // The registration leaf the door's `young-package` lookup
            // reads the publish time from.
            (
                "/v3/registration5-gz-semver2/greyward.fixture/1.0.0.json".to_string(),
                br#"{"published":"2020-01-01T00:00:00Z"}"#.to_vec(),
            ),
        ] {
            let file = format!("served{path}.body");
            fs::create_dir_all(rows.0.join(&file).parent().unwrap()).unwrap();
            fs::write(rows.0.join(&file), &body).unwrap();
            kept.retain(|row| row["url"] != format!("https://{HOST}{path}"));
            kept.push(serde_json::json!({
                "method": "GET",
                "url": format!("https://{HOST}{path}"),
                "file": file,
                "sha256": hex::encode(Sha256::digest(&body)),
                "size": body.len(),
                "status": 200,
                "headers": {"content-type": "application/octet-stream"},
            }));
        }
        fs::write(
            rows.0.join("index.json"),
            serde_json::to_vec(&kept).unwrap(),
        )
        .unwrap();
        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            &[HOST],
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
        let mut attribution = Attribution::open("dotnet").unwrap();
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

    fn csproj(references: &str) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
             <TargetFramework>net9.0</TargetFramework>\n  </PropertyGroup>\n  \
             <ItemGroup>\n{references}  </ItemGroup>\n</Project>\n"
        )
    }

    /// The .NET door against the recorded api.nuget.org: a missing lock
    /// restored through the NuGet mirror (the rewritten service index, the
    /// flat container, NuGetAudit's files), published with its record and
    /// no `obj/`, then `ward attest`'s locked-mode check: an unchanged lock
    /// signed, a drifted csproj refused.
    #[test]
    #[ignore = "realizes the store .NET SDK over the network"]
    fn dotnet_restore_attest_without_unix_sockets_through_nuget_mirror() {
        let _env = policy::test_env_lock();
        let _serial = policy::attribution_test_lock();
        let label = "dotnet_restore_attest_without_unix_sockets_through_nuget_mirror";
        let Some(harness) = nuget_harness(label) else {
            return;
        };
        let selected = super::super::shipped_selection().unwrap();
        let sdk = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        let temp = TempDir::named("dotnet-mirror");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        let reference =
            "    <PackageReference Include=\"Greyward.Fixture\" Version=\"$(FixtureVersion)\" Condition=\"!Exists('empty-switch') And Exists('feature.flag')\" />\n";
        fs::write(dir.join("app.csproj"), csproj(reference)).unwrap();
        fs::write(dir.join("feature.flag"), "enabled").unwrap();
        fs::create_dir_all(dir.join("config")).unwrap();
        fs::write(dir.join("config/version.txt"), "1.0.0").unwrap();
        fs::write(dir.join("config/package.props"), r#"<Project><PropertyGroup>
          <FixtureVersion>$([System.IO.File]::ReadAllText('$(MSBuildThisFileDirectory)version.txt').Trim())</FixtureVersion>
        </PropertyGroup></Project>"#).unwrap();
        fs::write(dir.join("Directory.Build.props"), r#"<Project>
          <Import Project="config/package.props" />
          <PropertyGroup>
            <GreywardDiagnostics>$([System.Environment]::GetEnvironmentVariable('DOTNET_EnableDiagnostics'))</GreywardDiagnostics>
            <GreywardNodeReuse>$([System.Environment]::GetEnvironmentVariable('MSBUILDDISABLENODEREUSE'))</GreywardNodeReuse>
          </PropertyGroup>
          <Target Name="GreywardNoUnixSettings" BeforeTargets="Restore">
            <Error Condition="'$(GreywardDiagnostics)' != '0'" Text="diagnostic IPC not disabled" />
            <Error Condition="'$(GreywardNodeReuse)' != '1'" Text="MSBuild node reuse not disabled" />
            <Error Condition="'$(MSBuildNodeCount)' != '1'" Text="parallel MSBuild workers not disabled" />
          </Target>
        </Project>"#).unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();

        let (generated, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &held, &sdk, &selected)
        });
        generated.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join(LOCK_FILE)).unwrap();
        assert!(lock.contains("\"Greyward.Fixture\""), "{lock}");
        assert!(lock.contains("\"resolved\": \"1.0.0\""), "{lock}");
        assert!(dir.join(".greyward/resolution/dotnet.json").is_file());
        assert!(
            !dir.join("obj").exists(),
            "restore output reached the project"
        );

        let (attested, recorded) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        let (record, _) = attested.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(record.outputs.len(), 2, "{:?}", record.outputs);
        for input in [
            "Directory.Build.props",
            "config/package.props",
            "config/version.txt",
        ] {
            assert!(record.inputs.contains_key(input), "{record:?}");
        }
        // Changing data read by an imported props file invalidates the receipt,
        // even though the main project and its lock remain byte-identical.
        let before_basis = resolution_basis(&held).unwrap();
        fs::write(dir.join("config/version.txt"), "2.0.0").unwrap();
        assert_ne!(resolution_basis(&held).unwrap(), before_basis);
        let before_lock = fs::read(dir.join(LOCK_FILE)).unwrap();
        let (changed_data, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        assert!(changed_data.is_err());
        assert_eq!(fs::read(dir.join(LOCK_FILE)).unwrap(), before_lock);
        fs::write(dir.join("config/version.txt"), "1.0.0").unwrap();

        // Deterministically replace validated input before staging. A fresh
        // basis here would bypass the lock-control refusal scan.
        let props = dir.join("Directory.Build.props");
        let original_props = fs::read(&props).unwrap();
        let replacement = props.clone();
        AFTER_PREFLIGHT_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(Box::new(move || {
            fs::write(replacement, "<Project TreatAsLocalProperty=\"NuGetLockFilePath\"><PropertyGroup><NuGetLockFilePath>alternate.lock.json</NuGetLockFilePath></PropertyGroup></Project>").unwrap();
        })));
        let receipt_before = fs::read(dir.join(".greyward/resolution/dotnet.json")).unwrap();
        let (replaced, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        let why = replaced.unwrap_err().to_string();
        assert!(why.contains("changed while planning"), "{why}");
        assert_eq!(fs::read(dir.join(LOCK_FILE)).unwrap(), before_lock);
        assert_eq!(
            fs::read(dir.join(".greyward/resolution/dotnet.json")).unwrap(),
            receipt_before
        );
        fs::write(&props, original_props).unwrap();

        let missing = temp.0.join("replaced-missing-lock");
        fs::create_dir(&missing).unwrap();
        fs::write(missing.join("app.csproj"), csproj("")).unwrap();
        let inserted = missing.join("Directory.Build.props");
        AFTER_PREFLIGHT_FOR_TEST.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::write(
                    inserted,
                    "<Project TreatAsLocalProperty=\"RestoreLockedMode\" />",
                )
                .unwrap();
            }))
        });
        let missing_held = ProjectRoot::open(&missing).unwrap();
        let (replaced_missing, _) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &missing_held, &sdk, &selected)
        });
        let why = replaced_missing.unwrap_err().to_string();
        assert!(why.contains("changed while planning"), "{why}");
        assert!(!missing.join(LOCK_FILE).exists());
        assert!(!missing.join(".greyward/resolution/dotnet.json").exists());

        // Remove an input during receipt-spec creation, then restore it before
        // staging. Receipt filenames must come from the captured generation.
        let flag = dir.join("feature.flag");
        let removed = flag.clone();
        AFTER_PREFLIGHT_FOR_TEST.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(removed).unwrap();
            }))
        });
        let restored = flag.clone();
        AFTER_RECEIPT_SPEC_FOR_TEST.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::write(restored, "enabled").unwrap();
            }))
        });
        let (aba, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        let (aba_record, _) = aba.unwrap();
        assert!(
            aba_record.inputs.contains_key("feature.flag"),
            "{aba_record:?}"
        );
        let key_path = temp.0.join("receipt-test.key");
        let public = crate::kernel::signing::generate(&key_path).unwrap();
        let key = crate::kernel::signing::SigningKey::load(&key_path).unwrap();
        let envelope = serde_json::to_vec(&aba_record.envelope(Some(&key)).unwrap()).unwrap();
        let trusted = [public].into_iter().collect();
        let judge = || {
            record::judge(
                "test",
                &envelope,
                "dotnet",
                &trusted,
                &crate::tailors::resolution_files(&super::super::tailor::Dotnet, &held)
                    .unwrap()
                    .unwrap(),
                &held,
            )
            .unwrap()
        };
        assert!(matches!(judge(), record::Judgment::Attests(_)));
        fs::remove_file(&flag).unwrap();
        assert!(matches!(judge(), record::Judgment::Unrecorded(_)));
        fs::write(flag, "enabled").unwrap();

        // Empty directories and host execute bits cannot select a different
        // dependency set in the canonical resolver view. The checkout stays intact.
        use std::os::unix::fs::PermissionsExt as _;
        fs::create_dir(dir.join("empty-switch")).unwrap();
        fs::set_permissions(
            dir.join("config/version.txt"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let (canonical, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        canonical.unwrap();
        assert!(dir.join("empty-switch").is_dir());
        assert_eq!(
            fs::metadata(dir.join("config/version.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        fs::write(dir.join("app.csproj"), csproj("")).unwrap();
        let before = fs::read(dir.join(LOCK_FILE)).unwrap();
        let (drifted, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &sdk, &selected)
        });
        let why = drifted.unwrap_err().to_string();
        assert!(why.contains("not attested"), "{why}");
        assert_eq!(fs::read(dir.join(LOCK_FILE)).unwrap(), before);
        done();
    }
}
