//! The .NET tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a NuGet-locked project.

use crate::comforter;
use crate::comforter::status::{
    object_liveness_state, recorded_inputs_state, standard_state, string, State,
};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_property, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::sandbox;
use crate::kernel::toolchain::input::{InputRow, Sources};
use crate::kernel::toolchain::Request;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::dotnet;
use crate::tailors::{
    Attester, ClosureListing, FileRunner, PackageRow, SourceFile, SyncRequest, Tailor,
};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Dotnet;

/// What `sync` and `build` share: realize the SDK and the restored
/// packages, then project the closure through the descriptor the command
/// holds. Returns the SDK object and the packages object.
/// Realize and project from one preflight: `checked`, or a fresh one.
fn realize_and_project(
    ctx: &Context,
    project: &ProjectRoot,
    toolchain: &Selected,
    checked: Option<dotnet::Preflight>,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<(PathBuf, PathBuf)> {
    let (activity, platform, store) = (&ctx.activity, ctx.platform, &ctx.store);
    let checked = match checked {
        Some(checked) => checked,
        None => dotnet::preflight(project, toolchain.version("dotnet-sdk")?)?,
    };
    // A solution's skipped projects are this closure's exceptions.
    checked.record_skips()?;
    let sdk = dotnet::realize_runtime(store, activity, platform, toolchain)?;
    let (plan, lock_sha256) = dotnet::plan_dotnet(project, toolchain, &checked)?;
    // The resolution files this plan was built from, so the resolution
    // join binds a record to this generation of the csproj and its lock.
    let basis = &checked.basis;
    let packages =
        dotnet::realize_packages(store, activity, platform, &plan, &sdk, toolchain, &checked)?;
    dotnet::project_dotnet_env(
        activity,
        project,
        &sdk,
        &packages,
        &plan,
        &lock_sha256,
        &checked.lock_inputs(),
        basis,
        toolchain,
        attribution,
    )?;
    Ok((sdk, packages))
}

impl Attester for Dotnet {
    fn attest_lock(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _host: &dyn crate::tailors::EditHost,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        let sdk = dotnet::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        dotnet::attest_project(door, project, &sdk, toolchain)
    }
}

impl Tailor for Dotnet {
    fn package_registry(&self) -> Option<crate::tailors::PackageRegistry> {
        Some(super::edit::REGISTRY)
    }

    fn registry_exists(&self, name: &str) -> io::Result<Option<String>> {
        super::edit::registry_exists(name)
    }

    fn claims_package_name(&self, name: &str) -> bool {
        super::edit::claims_package_name(name)
    }

    fn edit_manifest(
        &self,
        _ctx: &crate::kernel::context::Context,
        edit: &crate::tailors::ManifestEdit<'_>,
        _door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<crate::tailors::EditOutcome> {
        super::edit::edit_manifest(edit)
    }

    fn id(&self) -> &'static str {
        "dotnet"
    }

    /// The csproj and packages.lock.json: what restore resolves from and
    /// writes.
    fn resolution_outputs(&self, project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        super::resolve::resolution_outputs(project)
    }

    /// Every project file visible to executable MSBuild resolution.
    fn resolution_inputs(&self, project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        super::resolve::resolution_inputs(project)
    }

    fn attester(&self) -> Option<&dyn Attester> {
        Some(self)
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        // A held root is a directory by construction.
        dotnet::has_marker(project)
    }

    fn toolchain_sources(&self) -> Sources {
        Sources {
            discover: toolchain_rows,
            request: toolchain_request,
        }
    }

    fn input_files(&self) -> &'static str {
        "*.csproj, *.sln, *.slnx, packages.lock.json"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        &[SourceFile {
            extension: "cs",
            runner: FileRunner::Built(
                "a C# source file is built as part of its project, and a file-based app's \
                 '#:package' lines would restore packages outside the lock: 'ward build' builds \
                 the project in the sandbox",
            ),
        }]
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        dotnet::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        if dotnet::require_lock(project).is_ok() {
            return Ok(());
        }
        let sdk = dotnet::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        dotnet::generate_lock(door, project, &sdk, toolchain)
    }

    fn plan(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        // The plan is read from the lock alone: no SDK is realized.
        let checked = dotnet::preflight(project, toolchain.version("dotnet-sdk")?)?;
        let (plan, _) = dotnet::plan_dotnet(project, toolchain, &checked)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let toolchain = request.toolchain;
        let checked = dotnet::preflight(project, toolchain.version("dotnet-sdk")?)?;
        dotnet::require_lock(project)?;
        let (_, packages) =
            realize_and_project(ctx, project, toolchain, Some(checked), attribution)?;
        ui::synced("nuget packages", &packages);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        dotnet::has_marker(&ProjectRoot::open(cwd)?)
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd.to_path_buf())
    }

    fn build(
        &self,
        ctx: &Context,
        _root: &Path,
        cwd: &Path,
        args: &[String],
        toolchain: &Selected,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        let project = ProjectRoot::open(cwd)?;
        // build_sandboxed checks the project again right before the build.
        let (sdk, packages) = realize_and_project(ctx, &project, toolchain, None, attribution)?;
        dotnet::build_sandboxed(
            ctx.platform,
            &ctx.activity,
            &project,
            &sdk,
            &packages,
            args,
            toolchain,
        )
    }

    fn refused_package_script(&self, dir: &Path) -> Option<String> {
        std::fs::symlink_metadata(dir.join(".greyward/closures/dotnet.json"))
            .is_ok()
            .then(|| {
                "package.json scripts are not run under a .NET projection (MSBuild belongs in \
                 the sandbox: use `ward build dotnet`)"
                    .to_string()
            })
    }

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["dotnet"]
    }

    fn run_env(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        _cwd: &Path,
        cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let dir = project.path();
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        if comforter::has_closure(project, "dotnet")? {
            // This prevents accidental unsandboxed builds, not deliberate bypasses
            // through wrappers such as `sh -c`; during realization and build,
            // ward never evaluates project code outside its sandbox. Missing-lock
            // lock generation is the explicit host-side exception.
            if let Some(reason) = dotnet::refused_run_command(cmd) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
            }
            let closure = comforter::read_closure_in(project, "dotnet")?;
            let sdk =
                comforter::closure_object(&ctx.store, activity, &closure, "sdk_object", "dotnet")?;
            let packages =
                comforter::closure_object(&ctx.store, activity, &closure, "packages_object", "")?;
            prefix.push(sdk.to_string_lossy().into_owned());
            // A private per-project home inside the store, laid out like
            // the sync path's scratch: a home under the shared temp root
            // lets another user plant files the SDK reads as this user,
            // and a per-process one would make `ward env` print different
            // bytes on every call.
            let scratch = ctx.store.run_home(dir, "dotnet")?;
            dotnet::prepare_scratch(&scratch)?;
            let (prefixes, remove, set) = dotnet::run_env(&sdk, &packages, &scratch);
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        dotnet::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("dotnet-sdk".into(), string(&plan["sdk_version"])));
        for package in plan["packages"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["id"]),
                version: string(&package["version"]),
                detail: string(&package["content_hash"]),
            });
        }
        out
    }

    fn closure_state(
        &self,
        _platform: Platform,
        project: &ProjectRoot,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        // A solution's closure records each member lock.
        if body["inputs"]
            .as_array()
            .is_some_and(|inputs| !inputs.is_empty())
        {
            if let Some(state) = object_liveness_state(body, &["sdk_object", "packages_object"]) {
                return Ok(state);
            }
            return recorded_inputs_state(project, body);
        }
        standard_state(
            project,
            body,
            &["sdk_object", "packages_object"],
            "packages.lock.json",
            "packages_lock_sha256",
        )
    }

    /// NuGet package ids are case-insensitive.
    fn popular(&self) -> Option<&'static crate::kernel::lookalike::Popular> {
        static POPULAR: std::sync::OnceLock<crate::kernel::lookalike::Popular> =
            std::sync::OnceLock::new();
        Some(POPULAR.get_or_init(|| {
            crate::kernel::lookalike::Popular::parse(include_str!("popular.txt"), |name| {
                name.to_lowercase()
            })
        }))
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "packages")? {
            let (id, ver) = (required(eco, &p, "id")?, required(eco, &p, "version")?);
            let mut c = component(
                &id,
                &ver,
                format!("pkg:nuget/{}@{}", purl_encode(&id), purl_encode(&ver)),
                eco,
            );
            // contentHash is NuGet's semantic (signature-stripped)
            // sha512, base64 — not a raw file digest.
            push_property(
                &mut c,
                "greyward:nuget:contentHash",
                &required(eco, &p, "content_hash")?,
            );
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "sdk_object",
            "dotnet-sdk",
            &version_of(eco, plan, "sdk_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["dotnet-sdk"]
    }
}

/// The files this ecosystem's toolchain version is read from, in its own
/// tools' precedence order ([`Tailor::toolchain_sources`]).
fn toolchain_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    use crate::kernel::toolchain::input::{
        checked_row_for, read_global_json, read_global_json_roll_forward,
    };
    let mut rows = vec![
        checked_row_for(root, "global.json", "sdk.version", read_global_json)?,
        checked_row_for(
            root,
            "global.json",
            "sdk.rollForward",
            read_global_json_roll_forward,
        )?,
    ];
    rows.extend(target_row(root)?);
    Ok(rows)
}

/// The field of the row naming the layout's newest target framework.
const TARGET_FIELD: &str = "TargetFramework.newest";

/// The newest `netN.0` the layout targets
/// ([`dotnet::targets::newest_target_major`]), as one row on the root
/// solution (or the single project). Written only when that framework is
/// newer than the catalog default SDK builds: the default already serves
/// every older one, so a project that synced before this row existed keeps
/// its toolchain lock fresh, and only a project the default cannot build
/// (which could not sync before) records one. A layout ward cannot read
/// (no project, several without a solution) has no row: sync refuses it
/// with its own message.
fn target_row(root: &ProjectRoot) -> io::Result<Option<InputRow>> {
    let Ok(layout) = dotnet::solution::discover(root) else {
        return Ok(None);
    };
    let targets = dotnet::targets::newest_target_major(root, &layout)?;
    // A global.json constraint chooses the SDK. Otherwise an unresolved
    // conditional declaration above the default cannot silently demand a
    // framework that is inactive in this project.
    let global = root.read_file(Path::new("global.json"))?;
    let global_selects = global
        .as_deref()
        .map(crate::kernel::toolchain::input::read_global_json)
        .transpose()?
        .flatten()
        .is_some_and(|version| {
            super::rollforward::sdk_request(Some(&version), None)
                .ok()
                .flatten()
                .is_some()
        });
    if let Some((major, file)) = targets.unsure {
        if !global_selects && default_sdk_major().is_none_or(|default| major > default) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: target framework net{major}.0 depends on an unevaluated MSBuild condition; choose the SDK with global.json or use an unconditional effective target framework", file.display())));
        }
    }
    let Some(major) = targets.newest else {
        return Ok(None);
    };
    if default_sdk_major().is_some_and(|default| major <= default) {
        return Ok(None);
    }
    let path = match &layout.solution {
        Some(solution) => solution.clone(),
        None => layout.members[0].clone(),
    };
    let bytes = root.read_file(&path)?.unwrap_or_default();
    Ok(Some(InputRow {
        path,
        field: TARGET_FIELD.to_string(),
        value: Some(format!("net{major}.0")),
        absent: false,
        sha256: Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes))),
    }))
}

/// The major of the shipped catalog's default SDK.
fn default_sdk_major() -> Option<u64> {
    let catalog = dotnet::toolchain_catalog().ok()?;
    let bundle = catalog.default_release()?;
    let sdk = bundle
        .components
        .iter()
        .find(|component| component.name == "dotnet-sdk")?;
    sdk.version.split('.').next()?.parse().ok()
}

/// The selection request [`toolchain_rows`] state: `sdk.version` and
/// `sdk.rollForward` as one range, read the way the .NET host reads them
/// (`super::rollforward`). When they state none, the newest target
/// framework does: `netN.0` needs SDK N.0.100 or later.
fn toolchain_request(rows: &[InputRow]) -> io::Result<Request> {
    use crate::kernel::toolchain::resolve::{value, UPDATE_HINT};
    let invalid =
        |error: io::Error| crate::kernel::toolchain::invalid(format!("{error}; {UPDATE_HINT}"));
    let request = super::rollforward::sdk_request(
        value(rows, "global.json", "sdk.version"),
        value(rows, "global.json", "sdk.rollForward"),
    )
    .map_err(invalid)?;
    let request = match request {
        Some(request) => Some(request),
        None => rows
            .iter()
            .find(|row| row.field == TARGET_FIELD)
            .and_then(|row| row.value.as_deref())
            .and_then(|value| value.strip_prefix("net")?.strip_suffix(".0")?.parse().ok())
            .map(super::rollforward::target_request)
            .transpose()
            .map_err(invalid)?,
    };
    Ok(match request {
        Some(request) => Request::newest().with("dotnet-sdk", request),
        None => Request::newest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// The run guard is wired into the tailor's `ward run` environment: under
    /// a .NET projection a build verb is refused before any closure object
    /// is read; without one, the tailor adds nothing and refuses nothing.
    #[test]
    fn ward_run_under_a_dotnet_projection_refuses_build_verbs() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let scratch = TempDir::named("dotnet-run-guard");
        let previous_store = std::env::var_os("GREYWARD_STORE");
        std::env::set_var("GREYWARD_STORE", scratch.0.join("store"));
        let ctx = Context::open(Platform::host().unwrap());
        match previous_store {
            Some(value) => std::env::set_var("GREYWARD_STORE", value),
            None => std::env::remove_var("GREYWARD_STORE"),
        }
        let ctx = ctx.unwrap();
        let project = scratch.0.join("project");
        std::fs::create_dir_all(project.join(".greyward/closures")).unwrap();
        let cmd = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let build = cmd(&["dotnet", "build"]);

        let prefix = Dotnet
            .run_env(
                &ctx,
                &ProjectRoot::open(&project).unwrap(),
                &project,
                &build,
                &mut Command::new("dotnet"),
            )
            .unwrap();
        assert!(prefix.is_empty());

        // A closure that names no objects: reaching it would fail on the
        // missing `sdk_object`, not with the guard's refusal.
        std::fs::write(project.join(".greyward/closures/dotnet.json"), "{}").unwrap();
        let error = Dotnet
            .run_env(
                &ctx,
                &ProjectRoot::open(&project).unwrap(),
                &project,
                &build,
                &mut Command::new("dotnet"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
        assert_eq!(
            error.to_string(),
            dotnet::refused_run_command(&build).unwrap()
        );
        let error = Dotnet
            .run_env(
                &ctx,
                &ProjectRoot::open(&project).unwrap(),
                &project,
                &cmd(&["dotnet", "exec", "app.dll"]),
                &mut Command::new("dotnet"),
            )
            .unwrap_err();
        assert!(!error.to_string().contains("must run sandboxed"), "{error}");
    }

    #[test]
    fn inactive_targets_do_not_request_unavailable_sdks() {
        let temp = TempDir::named("dotnet-inactive-sdk");
        std::fs::write(temp.0.join("Directory.Build.props"), "<Project><PropertyGroup><TargetFramework>net11.0</TargetFramework></PropertyGroup></Project>").unwrap();
        std::fs::write(temp.0.join("app.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework><TargetFramework Condition=\"false\">net11.0</TargetFramework></PropertyGroup></Project>").unwrap();
        let root = ProjectRoot::open(&temp.0).unwrap();
        assert!(!toolchain_rows(&root)
            .unwrap()
            .iter()
            .any(|row| row.field == TARGET_FIELD));
        std::fs::write(temp.0.join("app.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework><TargetFramework Condition=\"'$(Optional)' == 'true'\">net11.0</TargetFramework></PropertyGroup></Project>").unwrap();
        let why = toolchain_rows(&root).unwrap_err().to_string();
        assert!(why.contains("unevaluated MSBuild condition"), "{why}");
        for prefix in ["", "\u{feff}"] {
            std::fs::write(
                temp.0.join("global.json"),
                format!(
                    "{prefix}{}",
                    r#"{"sdk":{"version":"9.0.317","rollForward":"disable"}}"#
                ),
            )
            .unwrap();
            toolchain_rows(&root).unwrap();
        }
    }

    /// Without a global.json version, the newest target framework picks
    /// the SDK line; a global.json version overrides it.
    #[test]
    fn target_framework_requests_its_sdk_without_global_json() {
        let temp = TempDir::named("dotnet-target-sdk");
        std::fs::write(
            temp.0.join("app.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
             <TargetFrameworks>net8.0;net10.0</TargetFrameworks></PropertyGroup></Project>",
        )
        .unwrap();
        let root = ProjectRoot::open(&temp.0).unwrap();
        let rows = toolchain_rows(&root).unwrap();
        let row = rows.iter().find(|row| row.field == TARGET_FIELD).unwrap();
        assert_eq!(row.path, PathBuf::from("app.csproj"));
        assert_eq!(row.value.as_deref(), Some("net10.0"));
        let target = Request::newest().with(
            "dotnet-sdk",
            super::super::rollforward::target_request(10).unwrap(),
        );
        assert_eq!(toolchain_request(&rows).unwrap(), target);

        std::fs::write(
            temp.0.join("global.json"),
            r#"{"sdk":{"version":"9.0.300"}}"#,
        )
        .unwrap();
        let rows = toolchain_rows(&root).unwrap();
        assert_ne!(toolchain_request(&rows).unwrap(), target);

        // No target newer than the default SDK builds: no row (a lock
        // minted before the row existed stays fresh), and the default is
        // asked for.
        std::fs::remove_file(temp.0.join("global.json")).unwrap();
        std::fs::write(
            temp.0.join("app.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
             <TargetFrameworks>netstandard2.0;net9.0</TargetFrameworks></PropertyGroup></Project>",
        )
        .unwrap();
        let rows = toolchain_rows(&root).unwrap();
        assert!(rows.iter().all(|row| row.field != TARGET_FIELD));
        assert_eq!(toolchain_request(&rows).unwrap(), Request::newest());
    }
}
