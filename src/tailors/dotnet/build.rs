//! `ward build` for .NET: a fresh offline locked restore into scratch, the
//! `--no-restore` build, and the output published into the project.

use super::{
    add_dotnet_tmp_write_root, ensure_dotnet_tmp, err, forced_env, opens_element, preflight,
    prepare_scratch, read_input_text, sdk_fingerprint_of, sdk_spec, solution,
    strip_comments_and_cdata, Preflight,
};
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The paths a sandboxed project restore and build run over. The project
/// and the package object are read-only: each phase writes only its own
/// scratch directories and the selected CoreCLR tmp root.
pub(super) struct ProjectPhase<'a> {
    pub(super) project_dir: &'a Path,
    pub(super) sdk_obj: &'a Path,
    pub(super) packages_obj: &'a Path,
    pub(super) scratch: &'a Path,
    pub(super) objdir: &'a Path,
    pub(super) output_scratch: &'a Path,
}

impl ProjectPhase<'_> {
    /// The offline locked restore writes the scratch obj/ only; the
    /// `--no-restore` build (`build`) writes the scratch output too.
    pub(super) fn spec(
        &self,
        build: bool,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        dotnet_tmp: PathBuf,
    ) -> BuildSpec {
        let mut write = Vec::new();
        // In artifacts mode one tree holds both, written by both phases.
        if build && self.output_scratch != self.objdir {
            write.push(self.output_scratch.to_path_buf());
        }
        write.push(self.objdir.to_path_buf());
        BuildSpec {
            argv,
            cwd: self.project_dir.to_path_buf(),
            env,
            read: vec![
                self.project_dir.to_path_buf(),
                self.sdk_obj.to_path_buf(),
                self.packages_obj.to_path_buf(),
            ],
            write: add_dotnet_tmp_write_root(write, dotnet_tmp),
            scratch: self.scratch.to_path_buf(),
            path: format!("{}:/usr/bin:/bin", self.sdk_obj.display()),
            host_view: crate::kernel::sandbox::HostView::Full,
        }
    }
}

pub(super) fn validate_build_args(args: &[String]) -> io::Result<()> {
    let mut i = 0;
    while i < args.len() {
        let lower = args[i].to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-c" | "--configuration" | "-v" | "--verbosity" | "-f" | "--framework"
        ) {
            if i + 1 == args.len() || args[i + 1].starts_with('-') || args[i + 1].starts_with('@') {
                return Err(err(format!("{}: missing option value", args[i])));
            }
            i += 2;
            continue;
        }
        if matches!(lower.as_str(), "--no-incremental" | "-warnaserror")
            || lower.starts_with("-p:configuration=")
            || lower.starts_with("-p:treatwarningsaserrors=")
        {
            i += 1;
            continue;
        }
        return Err(err(format!(
            "{}: not allowed for sandboxed dotnet build",
            args[i]
        )));
    }
    Ok(())
}

/// The configurations validated build `args` name (`-c X`,
/// `--configuration X`, `-p:Configuration=X`).
pub(super) fn named_configurations(args: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        let lower = arg.to_ascii_lowercase();
        if matches!(lower.as_str(), "-c" | "--configuration") {
            if let Some(value) = args.get(index + 1) {
                found.push(value.clone());
            }
        } else if lower.starts_with("-p:configuration=") {
            found.push(arg["-p:configuration=".len()..].to_string());
        }
    }
    found
}

/// The output directory `bin/greyward-<fingerprint>` under the project's held
/// path, with `bin` created. Neither may be a symlink, and both must
/// resolve under the held path: the path is not canonicalized first, so a
/// symlink swapped in at the project path since ward opened it is refused
/// as escaping the project rather than published into (#497).
pub(super) fn checked_output_dir(project: &ProjectRoot, fingerprint: &str) -> io::Result<PathBuf> {
    let project_dir = project.path();
    let bin = project_dir.join("bin");
    if let Ok(md) = fs::symlink_metadata(&bin) {
        if md.file_type().is_symlink() {
            return Err(err(format!("{} must not be a symlink", bin.display())));
        }
        if !md.is_dir() {
            return Err(err(format!("{} must be a directory", bin.display())));
        }
    }
    let output = bin.join(format!("greyward-{fingerprint}"));
    if let Ok(md) = fs::symlink_metadata(&output) {
        if md.file_type().is_symlink() {
            return Err(err(format!("{} must not be a symlink", output.display())));
        }
        if !md.is_dir() {
            return Err(err(format!("{} must be a directory", output.display())));
        }
    }
    // Created from the held descriptor, so nothing is made where a
    // symlink at the project path or at `bin` points.
    project.create_dir_all(Path::new("bin"))?;
    let canonical_bin = bin.canonicalize()?;
    if !canonical_bin.starts_with(project_dir) {
        return Err(err(format!("{} escapes the project", bin.display())));
    }
    if output.exists() && !output.canonicalize()?.starts_with(project_dir) {
        return Err(err(format!("{} escapes the project", output.display())));
    }
    Ok(output)
}

pub(super) fn publish_output(
    staged: &Path,
    project: &ProjectRoot,
    platform: Platform,
    fingerprint: &str,
    activity: Option<&StoreActivity>,
) -> io::Result<PathBuf> {
    let output = checked_output_dir(project, fingerprint)?;
    let bin = output
        .parent()
        .ok_or_else(|| err("output directory has no bin parent"))?;
    let suffix = crate::kernel::fsroot::random_suffix()?;
    let new = bin.join(format!(".greyward-{fingerprint}.new.{suffix}"));
    let old = bin.join(format!(".greyward-{fingerprint}.old.{suffix}"));
    for path in [&new, &old] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(err(format!(
                "temporary output already exists: {}",
                path.display()
            )));
        }
    }
    match fs::rename(staged, &new) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            let cloned = match activity {
                Some(activity) => {
                    crate::kernel::store::clone_tree_with_activity(activity, staged, &new, platform)
                }
                None => crate::comforter::clone_tree_for(staged, &new, platform),
            };
            if let Err(clone_error) = cloned {
                let _ = crate::kernel::store::remove_tree(&new);
                return Err(io::Error::new(
                    clone_error.kind(),
                    format!("publish {}: {clone_error}", output.display()),
                ));
            }
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("publish {}: {e}", output.display()),
            ))
        }
    }

    let had_old = output.exists();
    if had_old {
        if let Err(e) = fs::rename(&output, &old) {
            let _ = crate::kernel::store::remove_tree(&new);
            return Err(io::Error::new(
                e.kind(),
                format!("publish {}: {e}", output.display()),
            ));
        }
    }
    if let Err(e) = fs::rename(&new, &output) {
        let _ = crate::kernel::store::remove_tree(&new);
        let restore = if had_old {
            fs::rename(&old, &output)
        } else {
            Ok(())
        };
        return Err(match restore {
            Ok(()) => io::Error::new(e.kind(), format!("publish {}: {e}", output.display())),
            Err(restore_error) => io::Error::new(
                e.kind(),
                format!(
                    "publish {}: {e}; restoring previous output failed: {restore_error}",
                    output.display()
                ),
            ),
        });
    }
    if had_old {
        if let Err(e) = crate::kernel::store::remove_tree(&old) {
            // The publish itself succeeded; rolling back here could lose
            // BOTH versions (the old tree may be partially deleted). Keep
            // the new output and report the leftover.
            ui::warning(
                &format!("previous output left at {} ({e})", old.display()),
                &ui::shell_line(&["rm", "-rf", &old.display().to_string()]),
            );
        }
    }
    Ok(output)
}

/// Sandboxed build: fresh offline locked restore into scratch obj, attest
/// assets, then build --no-restore. Project obj/ is never authority.
pub fn build_sandboxed(
    platform: Platform,
    activity: &StoreActivity,
    project: &ProjectRoot,
    sdk_obj: &Path,
    packages_obj: &Path,
    args: &[String],
    selected: &Selected,
) -> io::Result<()> {
    validate_build_args(args)?;
    let sdk_spec = sdk_spec(platform, selected)?;
    let checked = preflight(project, &sdk_spec.version)?;
    let layout = buildable(&checked)?;
    let project_dir = project.path().to_path_buf();
    let sdk_obj = sdk_obj.canonicalize()?;
    let packages_obj = packages_obj.canonicalize()?;
    let store = Store::open()?;
    store.require_activity(activity, "dotnet build")?;
    let scratch = store.stage_with_activity(activity)?;
    let built = build_in(
        platform,
        activity,
        project,
        &layout,
        &BuildPaths {
            project_dir: &project_dir,
            sdk_obj: &sdk_obj,
            packages_obj: &packages_obj,
            scratch: &scratch,
        },
        args,
        &sdk_fingerprint_of(&sdk_spec),
    );
    let _ = crate::kernel::store::remove_tree(&scratch);
    let output = built?;
    ui::note(&format!("built into {}", output.display()));
    Ok(())
}

/// The layout `ward build` builds: every member but those whose lock
/// targets Windows. Building those needs a Windows targeting pack
/// (`Microsoft.WindowsDesktop.App.Ref` and the like), which restore
/// fetches beside the lock and no lock pins, and the build has no
/// network; each is named as it is left out. Refused when none is left.
pub(super) fn buildable(checked: &Preflight) -> io::Result<solution::Layout> {
    let windows = checked.windows_members();
    let mut layout = checked.layout.clone();
    if windows.is_empty() {
        return Ok(layout);
    }
    layout.members.retain(|member| !windows.contains(member));
    let names = windows
        .iter()
        .map(|member| member.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if layout.members.is_empty() {
        return Err(err(format!(
            "{names} target Windows; building for Windows needs its targeting pack, which \
             no packages.lock.json pins, so `ward build` cannot build it offline"
        )));
    }
    ui::note(&format!(
        "not built: {names} (targets Windows; its targeting pack is not in any lock)"
    ));
    Ok(layout)
}

struct BuildPaths<'a> {
    project_dir: &'a Path,
    sdk_obj: &'a Path,
    packages_obj: &'a Path,
    scratch: &'a Path,
}

/// Every `project.assets.json` under `dir` with its sha256, by path.
fn assets_digests(dir: &Path) -> io::Result<BTreeMap<PathBuf, String>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name() == "project.assets.json" {
                let bytes = fs::read(entry.path())?;
                found.insert(entry.path(), hex::encode(Sha256::digest(&bytes)));
            }
        }
    }
    Ok(found)
}

/// The targets file every build imports as
/// `CustomBeforeMicrosoftCommonTargets`, which
/// Microsoft.Common.CurrentVersion.targets imports after the project, its
/// Directory.Build.props and the SDK's default output paths, and before
/// `OutDir`, `TargetDir` and the paths derived from them. It puts every project's output in
/// scratch whatever `OutputPath`, `BaseOutputPath` or `OutDir` the project
/// set: in artifacts mode the path the SDK would pick had the project set
/// none, otherwise the global `OutputPath`.
pub(super) const OUTPUT_TARGETS: &str = "greyward-output.targets";
pub(super) const OUTPUT_TARGETS_TEXT: &str = "<Project>\n  \
     <PropertyGroup Condition=\"'$(UseArtifactsOutput)' == 'true'\">\n    \
     <OutputPath>$(ArtifactsPath)/bin/$(ArtifactsProjectName)/$(ArtifactsPivots)/</OutputPath>\n  \
     </PropertyGroup>\n  \
     <PropertyGroup>\n    <OutDir>$(OutputPath)</OutDir>\n  </PropertyGroup>\n</Project>\n";

/// Artifacts mode names each project's obj and bin by its file name, so
/// two members with one name would build into one directory.
pub(super) fn same_named_members(members: &[PathBuf]) -> io::Result<()> {
    let mut seen: BTreeMap<String, &PathBuf> = BTreeMap::new();
    for member in members {
        let name = member
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        if let Some(first) = seen.insert(name, member) {
            return Err(err(format!(
                "{} and {} have one project name, and a solution build gives each \
                 project name one output directory; rename one",
                first.display(),
                member.display()
            )));
        }
    }
    Ok(())
}

/// The offline locked restore and the `--no-restore` build in scratch, then
/// the output published into the project.
///
/// A single project with no project references keeps its obj and output
/// in two scratch directories (`MSBuildProjectExtensionsPath`,
/// `OutputPath`) and publishes its output as it is. A solution, or a
/// project referencing others, builds in artifacts mode
/// (`UseArtifactsOutput`): every project gets its own obj and bin under
/// one scratch `artifacts/`, and `artifacts/bin` (for a single project,
/// its own configuration directory) is published.
fn build_in(
    platform: Platform,
    activity: &StoreActivity,
    project: &ProjectRoot,
    layout: &solution::Layout,
    paths: &BuildPaths<'_>,
    args: &[String],
    fingerprint: &str,
) -> io::Result<PathBuf> {
    let BuildPaths {
        project_dir,
        sdk_obj,
        packages_obj,
        scratch,
    } = *paths;
    let root_project = &layout.members[0];
    let references = layout.solution.is_none() && {
        let text = read_input_text(project, root_project)?;
        opens_element(
            &strip_comments_and_cdata(&text, root_project)?.to_ascii_lowercase(),
            "projectreference",
        )
    };
    let artifacts_mode = layout.solution.is_some() || references;
    if artifacts_mode {
        same_named_members(&layout.members)?;
    }
    prepare_scratch(scratch)?;
    // Empty source list: everything must come from the projected packages.
    fs::write(
        scratch.join("nuget.config"),
        "<configuration><packageSources><clear /></packageSources><config>\
         <add key=\"updatePackageLastAccessTime\" value=\"false\" /></config></configuration>",
    )?;
    let (objdir, output_scratch) = if artifacts_mode {
        let artifacts = scratch.join("artifacts");
        (artifacts.clone(), artifacts)
    } else {
        (scratch.join("obj"), scratch.join("output"))
    };
    fs::create_dir_all(&objdir)?;
    fs::create_dir_all(&output_scratch)?;
    let target = match &layout.solution {
        Some(_) => {
            let sln = scratch.join("greyward.sln");
            fs::write(
                &sln,
                solution::generated_sln(project_dir, &layout.members, &named_configurations(args))?,
            )?;
            sln
        }
        None => project_dir.join(root_project),
    };
    let output_targets = scratch.join(OUTPUT_TARGETS);
    fs::write(&output_targets, OUTPUT_TARGETS_TEXT)?;
    let shared = shared_properties(
        project_dir,
        layout,
        &output_targets,
        &objdir,
        artifacts_mode,
    )?;
    let common = |verb: &str| -> Vec<String> {
        vec![
            sdk_obj.join("dotnet").display().to_string(),
            verb.to_string(),
            target.display().to_string(),
        ]
    };
    // CoreCLR named mutexes use the platform-selected local write root.
    let env: Vec<(String, String)> = forced_env(sdk_obj, packages_obj, scratch);
    let mut restore = common("restore");
    restore.extend([
        "--locked-mode".to_string(),
        "--no-cache".to_string(),
        "--configfile".to_string(),
        scratch.join("nuget.config").display().to_string(),
    ]);
    restore.extend(shared.iter().cloned());
    let phase = ProjectPhase {
        project_dir,
        sdk_obj,
        packages_obj,
        scratch,
        objdir: &objdir,
        output_scratch: &output_scratch,
    };
    let spec = phase.spec(false, restore, env.clone(), ensure_dotnet_tmp(platform)?);
    crate::kernel::sandbox::run_build_spec_on(platform, &spec, Some(activity)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "offline locked restore failed: {e}; network is denied — \
                     packages outside the lock, framework packs, or workloads \
                     are unsupported in v0"
            ),
        )
    })?;
    let assets = assets_digests(&objdir)?;
    let expected = if artifacts_mode {
        layout
            .members
            .iter()
            .map(|member| {
                let name = member.file_stem().unwrap_or_default();
                objdir.join("obj").join(name).join("project.assets.json")
            })
            .collect()
    } else {
        vec![objdir.join("project.assets.json")]
    };
    if let Some(missing) = expected.iter().find(|path| !assets.contains_key(*path)) {
        return Err(err(format!(
            "restore produced no {}",
            missing.strip_prefix(scratch).unwrap_or(missing).display()
        )));
    }
    let mut build = common("build");
    build.extend(args.iter().cloned());
    build.push("--no-restore".to_string());
    if !artifacts_mode {
        build.push(format!("-p:OutputPath={}/", output_scratch.display()));
    }
    build.extend(shared);
    let spec = phase.spec(true, build, env, ensure_dotnet_tmp(platform)?);
    crate::kernel::sandbox::run_build_spec_on(platform, &spec, Some(activity)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("dotnet build failed: {e}\n(network is denied during builds)"),
        )
    })?;
    if assets_digests(&objdir)? != assets {
        return Err(err(
            "project.assets.json changed during build; refusing to publish output",
        ));
    }
    let published = if artifacts_mode {
        published_artifacts(layout, &objdir)?
    } else {
        output_scratch
    };
    publish_output(&published, project, platform, fingerprint, Some(activity))
}

/// The artifacts-mode tree `ward build` publishes: a solution's whole
/// `bin`, a single project's one configuration directory.
fn published_artifacts(layout: &solution::Layout, objdir: &Path) -> io::Result<PathBuf> {
    if layout.solution.is_some() {
        return Ok(objdir.join("bin"));
    }
    let own = objdir
        .join("bin")
        .join(layout.members[0].file_stem().unwrap_or_default());
    let configurations: Vec<PathBuf> = fs::read_dir(&own)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<_>>()?;
    Ok(match configurations.as_slice() {
        [only] => only.clone(),
        _ => own,
    })
}

/// The properties both the restore and the build pass: the output targets
/// file, no build servers, and the obj and output layout.
fn shared_properties(
    project_dir: &Path,
    layout: &solution::Layout,
    output_targets: &Path,
    objdir: &Path,
    artifacts_mode: bool,
) -> io::Result<Vec<String>> {
    let mut shared = vec![
        "-noAutoResponse".to_string(),
        format!(
            "-p:CustomBeforeMicrosoftCommonTargets={}",
            output_targets.display()
        ),
        "-p:UseSharedCompilation=false".to_string(),
        "-nodeReuse:false".to_string(),
        "--disable-build-servers".to_string(),
    ];
    if artifacts_mode {
        shared.extend([
            "-p:UseArtifactsOutput=true".to_string(),
            format!("-p:ArtifactsPath={}/", objdir.display()),
        ]);
    } else {
        shared.extend([
            "-p:UseArtifactsOutput=false".to_string(),
            format!("-p:MSBuildProjectExtensionsPath={}/", objdir.display()),
            format!("-p:BaseIntermediateOutputPath={}/", objdir.display()),
        ]);
    }
    if let Some(solution) = &layout.solution {
        shared.extend(solution::solution_properties(project_dir, solution)?);
    }
    Ok(shared)
}
