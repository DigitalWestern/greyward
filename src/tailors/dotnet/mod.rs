//! The .NET tailor: NuGet packages.lock.json (v1, greyward-mandatory),
//! materialization delegated to the pinned NuGet, per-build fresh offline
//! restore, sandboxed builds only.
//!
//! Signed nupkgs' contentHash is a SEMANTIC hash over transformed bytes, so
//! ward never compares lock hashes to raw
//! downloads — the pinned NuGet verifies contentHash while installing into
//! the global-packages layout (locked mode), the same delegated-extractor
//! pattern as Go, with the full SDK object id in the object identity. The
//! lock (not project obj/) is the only durable authority: every sandboxed
//! build re-restores offline into scratch and builds --no-restore.

mod build;
mod door;
pub mod edit;
pub mod objects;
pub(crate) mod registry;
mod resolve;
mod rollforward;
mod solution;
pub mod tailor;
mod targets;
mod unpack;
mod verifier;

pub use build::build_sandboxed;
#[cfg(test)]
use build::{
    buildable, checked_output_dir, publish_output, same_named_members, validate_build_args,
    ProjectPhase,
};
pub use resolve::{attest_project, generate_lock};
use verifier::{rewrite_metadata_source, verifier_projects, write_verifier};
#[cfg(test)]
use verifier::{synthetic_csproj, synthetic_lock, VerifierProject};

#[cfg(test)]
use unpack::extract_sdk_archive;
use unpack::extract_sdk_archive_for;

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{cache_insert, download_toolchain_artifact_held, Digest};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::Platform;
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{ArtifactRow, Catalog, Selected};
use crate::kernel::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The shipped .NET catalog: every SDK of the .NET channels Microsoft still
/// supports, with its default, generated and verified by
/// `tools/catalog.py dotnet` from Microsoft's release metadata (sha512,
/// published over HTTPS, not signed).
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// The default SDK's archive for a platform: what a project with no
/// `global.json` pin realizes there.
fn sdk_pin(platform: Platform) -> io::Result<&'static ArtifactRow> {
    CATALOG.default_row(platform, "dotnet-sdk")
}

/// The shipped .NET catalog: one release bundle per SDK, keeping the sha512
/// Microsoft publishes, and the default.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, ".NET SDK")?;
    sdk_pin(platform).map(|_| ())
}

/// The recipe this tailor knows how to build an SDK object from. A lock
/// naming any other recipe was written by a ward that installs the SDK some
/// other way, and this one must not guess.
const SDK_RECIPE: &str = "dotnet-sdk/1";

/// One SDK realization's bytes, read from the selected toolchain rather
/// than from the compiled pin table: the same fields a pin carries, owned,
/// so a project's lock can supply them.
#[derive(Debug)]
struct SdkSpec {
    platform: Platform,
    version: String,
    provider: String,
    url: String,
    sha512: String,
}

/// The selected SDK's row for `platform`, refused unless this ward knows the
/// recipe that produced it. Microsoft publishes sha512, so the row must
/// carry one: a sha256 row is a different provenance channel.
fn sdk_spec(platform: Platform, selected: &Selected) -> io::Result<SdkSpec> {
    selected.require("dotnet", "dotnet-sdk")?;
    let row = selected.checked_artifact(platform, "dotnet-sdk", SDK_RECIPE, "sha512")?;
    Ok(SdkSpec {
        platform,
        version: row.version,
        provider: row.provider,
        url: row.url,
        sha512: row.digest.hex().to_string(),
    })
}

#[cfg(test)]
/// The shipped catalog's SDK, for callers with no project selection to
/// honor. Inside a project every caller realizes from the lock instead.
fn shipped_selection() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

fn sdk_identity(spec: &SdkSpec) -> Identity {
    Identity {
        kind: "dotnet-sdk".into(),
        name: "dotnet-sdk".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "dotnet-sdk/1".to_string()),
            ("artifact_sha512".to_string(), spec.sha512.clone()),
            ("platform".to_string(), spec.platform.triple().to_string()),
        ]),
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A short fingerprint of the SDK an output tree was built with: published
/// build directories must not be shared across SDK upgrades.
fn sdk_fingerprint_of(spec: &SdkSpec) -> String {
    hex::encode(&Sha256::digest(spec.sha512.as_bytes())[..8])
}

/// The global-packages object's identity: the restoring SDK and each
/// package's lock contentHash, all known before any download, so a stored
/// object syncs offline and a nuget.org re-sign (new raw sha256, same
/// contentHash) keeps it. Raw sha256s are evidence only (cache_digest).
/// `nuget-packages/1` keyed on them and checked the store only after every
/// download; its objects are not reused (one restore each, then GC).
fn nuget_identity(plan: &DotnetPlan, sdk_id: &str) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "nuget-packages/2".to_string()),
        ("extractor".to_string(), sdk_id.to_string()),
    ]);
    for p in &plan.packages {
        let key = format!("{}@{}", p.id.to_ascii_lowercase(), p.version);
        inputs.insert(format!("pkg:{key}"), p.content_hash.clone());
    }
    Identity {
        kind: "nuget-packages".into(),
        name: "packages".into(),
        version: plan.packages.len().to_string(),
        inputs,
    }
}

/// A spec straight from the compiled pin table: the catalog's own rows, and
/// the fixture the identity goldens are written against.
#[cfg(test)]
fn pin_spec(platform: Platform) -> SdkSpec {
    let pin = sdk_pin(platform).expect("pinned SDK for test platform");
    SdkSpec {
        platform: pin.platform,
        version: SDK_VERSION.to_string(),
        provider: pin.provider.clone(),
        url: pin.url.to_string(),
        sha512: pin.digest.hex().to_string(),
    }
}

/// The shipped default SDK, the object-id golden the identity tests hold:
/// adding a newer SDK to the catalog must not move it.
#[cfg(test)]
const SDK_VERSION: &str = "9.0.317";

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let sdk = sdk_identity(&pin_spec(platform));
    let empty_plan = DotnetPlan {
        members: Vec::new(),
        sdk_version: SDK_VERSION.into(),
        project: "app.csproj".into(),
        targets: vec!["net9.0".into()],
        packages: Vec::new(),
    };
    let package = NugetPackage {
        id: "Newtonsoft.Json".into(),
        version: "13.0.3".into(),
        content_hash: "content-hash".into(),
    };
    let package_plan = DotnetPlan {
        packages: vec![package],
        ..empty_plan.clone()
    };
    let nuget_empty = nuget_identity(&empty_plan, &sdk.object_id());
    let nuget_package = nuget_identity(&package_plan, &sdk.object_id());
    vec![sdk, nuget_empty, nuget_package]
}

/// Realize the SDK the selection names: its bytes, its version, its digest.
/// A catalog refresh cannot move a project's SDK, because nothing here
/// reads the pin table.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, ".NET SDK")?;
    let spec = sdk_spec(platform, selected)?;
    let identity = sdk_identity(&spec);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let digest = Digest::sha512(&spec.sha512)?;
    let tarball =
        download_toolchain_artifact_held(store, activity, &spec.provider, &spec.url, &digest)?;
    let staged = store.stage_with_activity(activity)?;
    extract_sdk_archive_for(activity, &tarball, &staged)?;
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(digest);
            deps
        })
        .map(|(path, _)| path)
}

/// global.json gate: the SELECTED SDK must be one the .NET host would
/// accept under the file's `sdk.version` and `sdk.rollForward`
/// (`rollforward::sdk_request`, the same reading that selected it), and
/// nothing may redirect SDK discovery. Comparing against the shipped
/// constant would let a catalog refresh start failing locked projects. The
/// project is read through the held descriptor.
pub fn check_global_json(project: &ProjectRoot, sdk_version: &str) -> io::Result<()> {
    let rel = Path::new("global.json");
    if !regular_file_if_present(project, rel, "global.json")? {
        return Ok(());
    }
    let text = read_input_text(project, rel)?;
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| err(format!("global.json: {e}")))?;
    reject_global_redirects(&v, "global.json")?;
    // A global.json with no sdk object states nothing about the SDK.
    let Some(sdk) = v.get("sdk") else {
        return Ok(());
    };
    let sdk = sdk
        .as_object()
        .ok_or_else(|| err("global.json sdk must be an object"))?;
    let field = |name: &str| -> io::Result<Option<&str>> {
        match sdk.get(name) {
            None => Ok(None),
            Some(serde_json::Value::String(text)) => Ok(Some(text.as_str())),
            Some(_) => Err(err(format!("global.json sdk.{name} must be a string"))),
        }
    };
    let Some(request) = rollforward::sdk_request(field("version")?, field("rollForward")?)? else {
        return Ok(());
    };
    let selected = crate::kernel::toolchain::Version::parse(sdk_version)?;
    if !request.matches(&selected) {
        return Err(err(format!(
            "global.json admits SDK {request}; locked: {sdk_version}; \
             run `ward update --toolchain dotnet`"
        )));
    }
    Ok(())
}

fn reject_global_redirects(value: &serde_json::Value, path: &str) -> io::Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "paths" || key == "msbuild-sdks" {
                    return Err(err(format!(
                        "{path}: {key} is not supported (SDK redirection)"
                    )));
                }
                reject_global_redirects(value, path)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_global_redirects(value, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A project-relative name inspected from the held descriptor without
/// following a symlink (what `symlink_metadata` on its path did).
fn regular_file_if_present(project: &ProjectRoot, rel: &Path, label: &str) -> io::Result<bool> {
    let path = project.path().join(rel);
    match project.entry(rel)? {
        Entry::Symlink => Err(err(format!(
            "{label} must be a regular file, not a symlink: {}",
            path.display()
        ))),
        Entry::Directory | Entry::Other => Err(err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ))),
        Entry::Regular => Ok(true),
        Entry::Absent => Ok(false),
    }
}

/// A project input's text, read through the held descriptor. A file that
/// vanished after its entry was checked reads as NotFound, as
/// `fs::read_to_string` reported it.
fn read_input_text(project: &ProjectRoot, rel: &Path) -> io::Result<String> {
    project.read_input_string(rel)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", project.path().join(rel).display()),
        )
    })
}

const ENV_REMOVE_PREFIXES: &[&str] = &["DOTNET_", "NUGET_", "MSBUILD", "MSBuild", "Msbuild"];
const ENV_REMOVE: &[&str] = &[
    "MSBuildSDKsPath",
    "MSBuildExtensionsPath",
    "RestoreSources",
    "RestoreConfigFile",
    "RestorePackagesPath",
];

fn forced_env(sdk_obj: &Path, packages: &Path, scratch: &Path) -> Vec<(String, String)> {
    vec![
        ("DOTNET_ROOT".to_string(), sdk_obj.display().to_string()),
        ("NUGET_PACKAGES".to_string(), packages.display().to_string()),
        ("DOTNET_CLI_TELEMETRY_OPTOUT".to_string(), "1".to_string()),
        ("DOTNET_NOLOGO".to_string(), "1".to_string()),
        ("DOTNET_CLI_HOME".to_string(), scratch.display().to_string()),
        (
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE".to_string(),
            "1".to_string(),
        ),
        (
            "HOME".to_string(),
            scratch.join("home").display().to_string(),
        ),
        (
            "XDG_CONFIG_HOME".to_string(),
            scratch.join("xdg").display().to_string(),
        ),
        (
            "XDG_CACHE_HOME".to_string(),
            scratch.join("xdg-cache").display().to_string(),
        ),
        (
            "XDG_DATA_HOME".to_string(),
            xdg_data_home(scratch).display().to_string(),
        ),
    ]
}

fn xdg_data_home(scratch: &Path) -> PathBuf {
    scratch.join("xdg-data")
}

/// Create the scratch layout every store-SDK invocation runs against.
///
/// The NuGet migration sentinel is the load-bearing part. NuGet guards its
/// first-run migration with a machine-global named mutex ("NuGet-Migrations"),
/// and ward hands every invocation a fresh home, so without the sentinel
/// every invocation re-runs that migration and contends for that single
/// mutex; concurrent syncs then die inside `Mutex.ReleaseMutex`. A home
/// already marked migrated never takes the mutex, and a directory ward
/// just created has nothing to migrate.
pub(crate) fn prepare_scratch(scratch: &Path) -> io::Result<()> {
    fs::create_dir_all(scratch.join("home"))?;
    let migrations = xdg_data_home(scratch).join("NuGet").join("Migrations");
    fs::create_dir_all(&migrations)?;
    fs::write(migrations.join("1"), "")
}

/// Env for `ward run`. Build-capable verbs are REJECTED at run: they
/// execute arbitrary MSBuild code and are sandbox-only. This env is for
/// `dotnet <app.dll>`, --version/--info, and compiled-app execution.
pub fn run_env(
    sdk_obj: &Path,
    packages: &Path,
    scratch: &Path,
) -> (Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>) {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        forced_env(sdk_obj, packages, scratch),
    )
}

pub const BUILD_VERBS: &[&str] = &[
    "build", "run", "test", "publish", "pack", "msbuild", "restore", "clean", "watch",
];

/// `ward run`'s guard is advisory: wrappers can bypass it. During
/// realization and build, ward never evaluates project code outside the
/// build sandbox. Missing-lock generation and attestation evaluate MSBuild
/// in the confined resolution sandbox through the NuGet mirror.
pub fn refused_run_command(cmd: &[String]) -> Option<String> {
    if cmd.first().map(String::as_str) != Some("dotnet") {
        return None;
    }
    let (verb_index, verb) = cmd[1..]
        .iter()
        .enumerate()
        .find(|(_, arg)| !arg.starts_with('-'))
        .map(|(i, arg)| (i + 1, arg.as_str()))?;
    if BUILD_VERBS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(verb))
    {
        return Some(format!(
            "`dotnet {verb}` compiles/executes MSBuild code and must run sandboxed: use `ward build dotnet ...`"
        ));
    }
    if verb.eq_ignore_ascii_case("exec")
        && cmd[verb_index + 1..].iter().any(|arg| {
            Path::new(arg)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case("MSBuild.dll"))
                .unwrap_or(false)
        })
    {
        return Some(
            "`dotnet exec .../MSBuild.dll` executes MSBuild code and must run sandboxed: use `ward build dotnet ...`"
                .to_string(),
        );
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NugetPackage {
    pub id: String,
    pub version: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetPlan {
    pub sdk_version: String,
    /// The project file, or the solution when one is restored.
    pub project: String,
    /// Full lock target matrix retained for provenance (TFM and TFM/RID),
    /// across every member's lock.
    pub targets: Vec<String>,
    pub packages: Vec<NugetPackage>,
    /// A solution's restored projects, project-relative; empty for a single
    /// project, so its plan and closure keep their shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        && !s.starts_with('.')
        && !s.contains("..")
}

/// The framework of a lock target (`net8.0`, `net8.0/linux-x64`), as a
/// TargetFramework MSBuild reads. NuGet writes the frameworks before .NET 5
/// by full name (`.NETFramework,Version=v4.7.2`), which maps to its short
/// name (`net472`); a short name passes as written.
fn target_framework(target: &str) -> io::Result<String> {
    let key = target.split('/').next().unwrap_or("");
    let bad = || err(format!("invalid lock target framework: {target}"));
    if let Some(rest) = key.strip_prefix('.') {
        let (name, version) = rest.split_once(",Version=v").ok_or_else(bad)?;
        if version.is_empty()
            || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || version.starts_with('.')
        {
            return Err(bad());
        }
        return match name {
            "NETFramework" => Ok(format!("net{}", version.replace('.', ""))),
            "NETStandard" => Ok(format!("netstandard{version}")),
            "NETCoreApp" => Ok(format!("netcoreapp{version}")),
            _ => Err(bad()),
        };
    }
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return Err(bad());
    }
    Ok(key.to_string())
}

fn validate_plan(plan: &DotnetPlan, sdk_version: &str) -> io::Result<()> {
    if plan.sdk_version != sdk_version {
        return Err(err(format!(
            "plan requires SDK {}; pinned: {sdk_version}",
            plan.sdk_version
        )));
    }
    if plan.targets.is_empty() {
        return Err(err("packages.lock.json has no target frameworks"));
    }
    for target in &plan.targets {
        target_framework(target)?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in &plan.packages {
        if !valid_id(&p.id) || !valid_id(&p.version) {
            return Err(err(format!("invalid package coordinates: {p:?}")));
        }
        // contentHash: base64 sha512, 88 characters with padding. It is
        // the packages object's identity input, so nothing else will do.
        if p.content_hash.len() != 88
            || crate::kernel::base64::decode(&p.content_hash).map(|bytes| bytes.len()) != Some(64)
        {
            return Err(err(format!("{}: invalid contentHash", p.id)));
        }
        if !seen.insert((p.id.to_ascii_lowercase(), p.version.clone())) {
            return Err(err(format!("duplicate package {}@{}", p.id, p.version)));
        }
    }
    Ok(())
}

/// The names in the project root, listed through the held descriptor. A
/// root that went away reads as NotFound, as `fs::read_dir` reported it.
fn root_names(project: &ProjectRoot) -> io::Result<Vec<std::ffi::OsString>> {
    project.read_input_dir(Path::new("."))?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", project.path().display()),
        )
    })
}

/// Directory-read failures propagate: guessing "no dotnet here" would hide
/// them, and guessing "dotnet present" would trigger SDK realization first.
/// The project is read through the held descriptor.
pub fn has_marker(project: &ProjectRoot) -> io::Result<bool> {
    for name in root_names(project)? {
        let lower = name.to_string_lossy().to_ascii_lowercase();
        if lower.ends_with(".sln")
            || lower.ends_with(".slnx")
            || solution::is_project_file(Path::new(&lower))
        {
            return Ok(true);
        }
    }
    let present = |rel: &str| {
        matches!(
            project.entry(Path::new(rel)),
            Ok(Entry::Regular | Entry::Directory | Entry::Symlink | Entry::Other)
        )
    };
    Ok(present(LOCK_FILE) || present(".greyward/closures/dotnet.json"))
}

/// MSBuild elements a project file or a `Directory.*` file may not
/// contain, each because it changes restore: the lock is the only package
/// authority, and restore output lands in scratch.
const BLOCKED_ELEMENTS: &[(&str, &str)] = &[
    ("UsingTask", "loads task assemblies outside the SDK"),
    (
        "PackageDownload",
        "downloads packages the lock does not name",
    ),
    (
        "RestoreSources",
        "points restore at feeds other than the projected packages",
    ),
    (
        "RestoreAdditionalProjectSources",
        "points restore at feeds other than the projected packages",
    ),
    (
        "RestorePackagesPath",
        "moves the package folder away from the projected packages",
    ),
    (
        "MSBuildProjectExtensionsPath",
        "moves restore output away from scratch obj",
    ),
    ("BaseIntermediateOutputPath", "moves obj away from scratch"),
    ("IntermediateOutputPath", "moves obj away from scratch"),
];

/// Properties that only say where build output goes. A project may set
/// them to a path inside the checkout: relative, no `..` that climbs out
/// of it, and starting from nothing or from one of its own directories.
/// `ward build` never writes there: [`OUTPUT_TARGETS`] moves every
/// project's output to scratch.
const OUTPUT_PROPERTIES: &[&str] = &["OutputPath", "OutDir", "BaseOutputPath", "PublishDir"];

/// The MSBuild properties an output path may start from: each names a
/// directory inside the checkout.
const OUTPUT_ANCHORS: &[&str] = &[
    "$(msbuildprojectdirectory)",
    "$(msbuildthisfiledirectory)",
    "$(solutiondir)",
    "$(projectdir)",
];

/// Does `value` (lowercase), set in a file `depth` directories below the
/// project root, name a place inside the project? A relative path starts
/// from the evaluated project's directory, which is the file's or below
/// it, so `depth` levels of `..` stay inside; `$(SolutionDir)` is the
/// root. Properties other than the anchors may follow
/// (`bin\$(Configuration)\`), not lead.
fn output_inside(value: &str, depth: usize) -> bool {
    let value = value.trim();
    let (rest, mut depth) = match OUTPUT_ANCHORS
        .iter()
        .find_map(|anchor| value.strip_prefix(anchor).map(|rest| (*anchor, rest)))
    {
        Some((anchor, rest)) => (
            rest.trim_start_matches(['/', '\\']),
            if anchor == "$(solutiondir)" { 0 } else { depth },
        ),
        None => (value, depth),
    };
    if rest.starts_with(['/', '\\', '~', '$']) || rest.as_bytes().get(1) == Some(&b':') {
        return false;
    }
    for part in rest.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return false,
            },
            _ => depth += 1,
        }
    }
    true
}

/// The text of every `<name>` element in `markup` (lowercase, comments
/// stripped): empty for `<name/>`.
fn element_values<'a>(markup: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let close = format!("</{name}");
    let mut values = Vec::new();
    for (at, _) in markup.match_indices(&open) {
        let after = &markup[at + open.len()..];
        if !after.starts_with(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/') {
            continue;
        }
        let Some(end) = after.find('>') else {
            continue;
        };
        if after[..end].ends_with('/') {
            values.push("");
            continue;
        }
        let body = &after[end + 1..];
        values.push(body.find(&close).map(|end| &body[..end]).unwrap_or(body));
    }
    values
}

/// The csproj text with every comment and CDATA section replaced by a
/// space. Both hold character data, never markup, so what remains is what
/// MSBuild reads as elements and attributes. An unterminated section is a
/// refusal: MSBuild would reject the file, and the rest cannot be scanned.
fn strip_comments_and_cdata(text: &str, path: &Path) -> io::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let comment = rest.find("<!--");
        let cdata = rest.find("<![CDATA[");
        let (at, open, close, what) = match (comment, cdata) {
            (Some(c), Some(d)) if d < c => (d, "<![CDATA[".len(), "]]>", "CDATA section"),
            (Some(c), _) => (c, "<!--".len(), "-->", "XML comment"),
            (None, Some(d)) => (d, "<![CDATA[".len(), "]]>", "CDATA section"),
            (None, None) => break,
        };
        out.push_str(&rest[..at]);
        out.push(' ');
        let body = &rest[at + open..];
        let end = body
            .find(close)
            .ok_or_else(|| err(format!("{}: unterminated {what}", path.display())))?;
        rest = &body[end + close.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Does `markup` (lowercase, comments stripped) open an element named
/// `name` (lowercase)? The name must end at whitespace, `>` or `/`, so
/// `<OutputPath` matches `<OutputPath>`, `<OutputPath Condition=...>` and
/// `<OutputPath/>` but not `<AppendTargetFrameworkToOutputPath>`.
fn opens_element(markup: &str, name: &str) -> bool {
    let tag = format!("<{name}");
    markup.match_indices(&tag).any(|(at, _)| {
        markup
            .as_bytes()
            .get(at + tag.len())
            .map(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
            .unwrap_or(false)
    })
}

/// The quoted values of every `attribute=` in `markup` (lowercase, comments
/// stripped), where `attribute` is a whole name. An unquoted value is an
/// error: well-formed XML always quotes, and the scan must not guess.
fn attribute_values<'a>(markup: &'a str, attribute: &str, path: &Path) -> io::Result<Vec<&'a str>> {
    let bytes = markup.as_bytes();
    let mut values = Vec::new();
    let mut at = 0;
    while let Some(found) = markup[at..].find(attribute) {
        let start = at + found;
        let before_ok = start == 0 || !is_name_byte(bytes[start - 1]);
        let mut i = start + attribute.len();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if !before_ok || i >= bytes.len() || bytes[i] != b'=' {
            at = start + attribute.len();
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || !matches!(bytes[i], b'"' | b'\'') {
            return Err(err(format!(
                "{}: {attribute} attribute must be quoted",
                path.display()
            )));
        }
        let quote = bytes[i];
        let value_start = i + 1;
        let end = bytes[value_start..]
            .iter()
            .position(|b| *b == quote)
            .map(|offset| value_start + offset)
            .ok_or_else(|| {
                err(format!(
                    "{}: unterminated {attribute} attribute",
                    path.display()
                ))
            })?;
        values.push(&markup[value_start..end]);
        at = end + 1;
    }
    Ok(values)
}

/// Does `b` join the name before an attribute? The boundary keeps `sdk=`
/// from matching inside `MySdk=`; punctuation such as `-`, `.` and `:`
/// counts as a boundary so that anything resembling the name is checked.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// XML can encode element names as UTF-8, UTF-16 or UTF-32. Decode before
/// applying the same restrictions to every MSBuild input.
fn decode_msbuild(bytes: &[u8]) -> io::Result<String> {
    let utf32 = if bytes.starts_with(&[0xff, 0xfe, 0, 0]) {
        Some((true, &bytes[4..]))
    } else if bytes.starts_with(&[0, 0, 0xfe, 0xff]) {
        Some((false, &bytes[4..]))
    } else if bytes.starts_with(&[b'<', 0, 0, 0]) {
        Some((true, bytes))
    } else if bytes.starts_with(&[0, 0, 0, b'<']) {
        Some((false, bytes))
    } else {
        None
    };
    if let Some((little, bytes)) = utf32 {
        if !bytes.len().is_multiple_of(4) {
            return Err(err("invalid UTF-32 MSBuild input"));
        }
        return bytes
            .chunks_exact(4)
            .map(|chunk| {
                let chunk: [u8; 4] = chunk.try_into().expect("four-byte chunk");
                char::from_u32(if little {
                    u32::from_le_bytes(chunk)
                } else {
                    u32::from_be_bytes(chunk)
                })
                .ok_or_else(|| err("invalid UTF-32 MSBuild input"))
            })
            .collect();
    }
    let utf16 = if bytes.starts_with(&[0xff, 0xfe]) {
        Some((true, &bytes[2..]))
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Some((false, &bytes[2..]))
    } else if bytes.starts_with(&[b'<', 0]) {
        Some((true, bytes))
    } else if bytes.starts_with(&[0, b'<']) {
        Some((false, bytes))
    } else {
        None
    };
    if let Some((little, bytes)) = utf16 {
        if !bytes.len().is_multiple_of(2) {
            return Err(err("invalid UTF-16 MSBuild input"));
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| {
                let chunk = [chunk[0], chunk[1]];
                if little {
                    u16::from_le_bytes(chunk)
                } else {
                    u16::from_be_bytes(chunk)
                }
            })
            .collect();
        return String::from_utf16(&units).map_err(|_| err("invalid UTF-16 MSBuild input"));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| err("MSBuild input must use UTF-8, UTF-16 or UTF-32"))
}

/// Validate a project-relative project file or `Directory.*` MSBuild file,
/// read through the held descriptor.
///
/// Matching is on whole element and attribute names, case-insensitively,
/// with comments and CDATA removed first; entity references cannot encode
/// names, so a well-formed file cannot hide one. The scan is an early,
/// named refusal: the sandbox (network denied, writes confined to scratch)
/// is what holds the boundary when a build step does something the scan
/// does not model.
fn validate_csproj(project: &ProjectRoot, rel: &Path) -> io::Result<()> {
    let bytes = project
        .read_input(rel)?
        .ok_or_else(|| err("MSBuild input vanished"))?;
    let text = decode_msbuild(&bytes)?;
    let path = project.path().join(rel);
    let path = path.as_path();
    let markup = strip_comments_and_cdata(&text, path)?.to_ascii_lowercase();
    let mut document = markup
        .strip_prefix('\u{feff}')
        .unwrap_or(&markup)
        .trim_start();
    if document.starts_with("<?xml")
        && document
            .as_bytes()
            .get(5)
            .map(|b| b.is_ascii_whitespace())
            .unwrap_or(false)
    {
        let end = document
            .find("?>")
            .ok_or_else(|| err(format!("{}: unterminated XML declaration", path.display())))?;
        document = document[end + 2..].trim_start();
    }
    // The root must be exactly <Project (word-bounded: <Projector/> is not).
    let root_ok = document.starts_with("<project")
        && document
            .as_bytes()
            .get(8)
            .map(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
            .unwrap_or(false);
    if !root_ok {
        return Err(err(format!(
            "{}: not a supported project file (expected <Project root)",
            path.display()
        )));
    }
    for (name, why) in BLOCKED_ELEMENTS {
        if opens_element(&markup, &name.to_ascii_lowercase()) {
            return Err(err(format!(
                "{}: unsupported MSBuild/project feature <{name}>: it {why}",
                path.display()
            )));
        }
    }
    // ward overrides the output and intermediate paths as global properties
    // on the command line, which a project cannot reassign unless it names
    // them in TreatAsLocalProperty.
    if !attribute_values(&markup, "treataslocalproperty", path)?.is_empty() {
        return Err(err(format!(
            "{}: unsupported MSBuild/project feature TreatAsLocalProperty: it lets the \
             project override the paths ward sets on the command line",
            path.display()
        )));
    }
    // A task's <Output> creates items and properties by name, the same as
    // the blocked elements would.
    for attribute in ["itemname", "propertyname"] {
        for value in attribute_values(&markup, attribute, path)? {
            let value = value.trim();
            if value.eq_ignore_ascii_case("ProjectReference")
                || OUTPUT_PROPERTIES
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(value))
            {
                return Err(err(format!("{}: task-created {value} is not supported; its project graph or output path cannot be checked before execution", path.display())));
            }
            if let Some((name, why)) = BLOCKED_ELEMENTS
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(value))
            {
                return Err(err(format!(
                    "{}: unsupported MSBuild/project feature {name} created by a task: it {why}",
                    path.display()
                )));
            }
        }
    }
    let has_output = OUTPUT_PROPERTIES
        .iter()
        .any(|name| opens_element(&markup, &name.to_ascii_lowercase()));
    let early_output_file = solution::is_project_file(rel)
        || rel
            .file_name()
            .is_some_and(|name| name == "Directory.Build.props");
    if has_output
        && (!early_output_file
            || opens_element(&markup, "target")
            || opens_element(&markup, "import"))
    {
        return Err(err(format!(
            "{}: output properties in imported files, targets or projects with explicit imports may override ward's output hook; move them to an SDK-style project or Directory.Build.props without explicit imports",
            path.display()
        )));
    }
    for property in OUTPUT_PROPERTIES {
        for value in element_values(&markup, &property.to_ascii_lowercase()) {
            let depth = rel.parent().map_or(0, |parent| parent.components().count());
            if !output_inside(value, depth) {
                return Err(err(format!(
                    "{}: <{property}>{}</{property}> puts build output outside the project; \
                     use a path inside it",
                    path.display(),
                    value.trim()
                )));
            }
        }
    }
    for name in solution::sdk_names(&markup, path)? {
        if !solution::bundled_sdk(&name) {
            return Err(err(format!(
                "{}: the MSBuild SDK {name} is fetched from NuGet when MSBuild evaluates the \
                 project, and no lock pins it; only the Microsoft.NET.Sdk family the .NET SDK \
                 carries is supported",
                path.display()
            )));
        }
    }
    Ok(())
}

/// What a packages.lock.json pins: its targets in lock order, one package
/// per case-insensitive id and version, sorted by that key, and each
/// target's own packages (what the verifier restores per framework).
#[derive(Debug, Clone)]
struct ParsedLock {
    targets: Vec<String>,
    packages: Vec<NugetPackage>,
    by_target: Vec<(String, Vec<NugetPackage>)>,
}

/// The one reader of packages.lock.json. Preflight calls it once and hands
/// planning what it read, so every refusal of a lock has one text and the
/// lock preflight accepts is the one planning uses.
///
/// Version 1 and version 2 (Central Package Management) locks are read.
/// `Direct`, `Transitive` and `CentralTransitive` entries are packages;
/// `Project` entries name another project of the restore and pin nothing.
fn parse_lock(text: &str) -> io::Result<ParsedLock> {
    let v: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map_err(|e| err(format!("packages.lock.json: {e}")))?;
    if v["version"] != 1 && v["version"] != 2 {
        return Err(err(format!(
            "packages.lock.json version {} unsupported (versions 1 and 2 are read)",
            v["version"]
        )));
    }
    let deps = v["dependencies"]
        .as_object()
        .ok_or_else(|| err("packages.lock.json has no dependencies"))?;
    let mut targets = Vec::new();
    let mut by_target = Vec::new();
    let mut packages: BTreeMap<(String, String), NugetPackage> = BTreeMap::new();
    for (target, entries) in deps {
        targets.push(target.clone());
        let entries = entries
            .as_object()
            .ok_or_else(|| err(format!("bad lock target {target}")))?;
        let mut in_target = Vec::new();
        for (id, e) in entries {
            match e["type"].as_str() {
                Some("Direct") | Some("Transitive") | Some("CentralTransitive") => {}
                Some("Project") => continue,
                Some(kind) => {
                    return Err(err(format!(
                        "{id}: unsupported lock dependency type {kind}; expected Direct, \
                         Transitive, CentralTransitive or Project"
                    )))
                }
                None => {
                    return Err(err(format!(
                        "{id}: unsupported lock dependency type {}; expected Direct, \
                         Transitive, CentralTransitive or Project",
                        e["type"]
                    )))
                }
            }
            let version = e["resolved"]
                .as_str()
                .ok_or_else(|| err(format!("{id}: no resolved version")))?;
            let hash = e["contentHash"]
                .as_str()
                .ok_or_else(|| err(format!("{id}: no contentHash")))?;
            let key = (id.to_ascii_lowercase(), version.to_string());
            let pkg = NugetPackage {
                id: id.clone(),
                version: version.to_string(),
                content_hash: hash.to_string(),
            };
            if let Some(prev) = packages.get(&key) {
                if prev.content_hash != pkg.content_hash {
                    return Err(err(format!(
                        "{id}@{version}: conflicting contentHash across lock targets"
                    )));
                }
            } else {
                packages.insert(key, pkg.clone());
            }
            in_target.push(pkg);
        }
        by_target.push((target.clone(), in_target));
    }
    Ok(ParsedLock {
        targets,
        packages: packages.into_values().collect(),
        by_target,
    })
}

pub use resolve::{preflight, Preflight};

const LOCK_FILE: &str = "packages.lock.json";

/// The locks every plan reads, or the refusal that names the first missing
/// one: `prepare` generates them, and the command layer skips `prepare`
/// under `--frozen`. Checked before any toolchain is realized, so a frozen
/// sync of an unlocked project fails without a download.
pub fn require_lock(project: &ProjectRoot) -> io::Result<()> {
    let layout = solution::discover(project)?;
    for lock in layout.member_locks() {
        if !project.is_input_file(&lock) {
            return Err(crate::tailors::missing_lock(
                project,
                &lock.to_string_lossy(),
            ));
        }
    }
    Ok(())
}

/// Plan from the members' packages.lock.json files, as `checked` read and
/// parsed them: every package any member pins, once. The project is read
/// through the held descriptor. The second value is the lock's sha256, or
/// for a solution the sha256 of every member lock's path and sha256.
pub fn plan_dotnet(
    project: &ProjectRoot,
    selected: &Selected,
    checked: &Preflight,
) -> io::Result<(DotnetPlan, String)> {
    let sdk_version = selected.version("dotnet-sdk")?.to_string();
    let Preflight { layout, locks, .. } = checked;
    for lock in layout.member_locks() {
        if !locks.iter().any(|read| read.path == lock) {
            return Err(crate::tailors::missing_lock(
                project,
                &lock.to_string_lossy(),
            ));
        }
    }
    let mut targets: Vec<String> = Vec::new();
    let mut packages: BTreeMap<(String, String), NugetPackage> = BTreeMap::new();
    for read in locks {
        for target in &read.parsed.targets {
            if !targets.contains(target) {
                targets.push(target.clone());
            }
        }
        for package in &read.parsed.packages {
            let key = (package.id.to_ascii_lowercase(), package.version.clone());
            match packages.get(&key) {
                Some(prev) if prev.content_hash != package.content_hash => {
                    return Err(err(format!(
                        "{}@{}: conflicting contentHash across the solution's locks ({})",
                        package.id,
                        package.version,
                        read.path.display()
                    )));
                }
                Some(_) => {}
                None => {
                    packages.insert(key, package.clone());
                }
            }
        }
    }
    let named = layout
        .solution
        .as_ref()
        .unwrap_or(&layout.members[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();
    let plan = DotnetPlan {
        // The SDK this plan was restored under is the selected one.
        sdk_version: sdk_version.clone(),
        project: named,
        targets,
        packages: packages.into_values().collect(),
        members: match (&layout.solution, layout.members.len()) {
            (Some(_), _) | (_, 2..) => layout
                .members
                .iter()
                .map(|member| member.to_string_lossy().into_owned())
                .collect(),
            _ => Vec::new(),
        },
    };
    validate_plan(&plan, &sdk_version)?;
    for read in locks {
        if read_input_text(project, &read.path)? != read.text {
            return Err(err(format!(
                "{} changed while planning; re-run 'ward'",
                read.path.display()
            )));
        }
    }
    if resolve::resolution_basis(project)? != checked.basis {
        return Err(err(
            ".NET resolution inputs changed while planning; run `ward` again",
        ));
    }
    let digest = match (&layout.solution, locks.as_slice()) {
        (None, [only]) => hex::encode(Sha256::digest(only.text.as_bytes())),
        _ => {
            let mut all = Sha256::new();
            for (path, sha256) in checked.lock_inputs() {
                all.update(format!("{path}\0{sha256}\n").as_bytes());
            }
            hex::encode(all.finalize())
        }
    };
    Ok((plan, digest))
}

/// Realize the global-packages object: ward fetches every nupkg into a
/// local folder feed (raw bytes cached by sha256), then the PINNED NuGet
/// installs from that feed in LOCKED mode — it verifies each package's
/// semantic contentHash against the lock and writes the exact
/// global-packages layout (.nupkg.sha512/.nupkg.metadata/nuspec). The SDK
/// is the extractor, so its full store object id is an identity input (Go
/// precedent). Network denied at install: the feed is local.
pub fn realize_packages(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &DotnetPlan,
    sdk_obj: &Path,
    selected: &Selected,
    checked: &Preflight,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, ".NET packages")?;
    let spec = sdk_spec(platform, selected)?;
    validate_plan(plan, &spec.version)?;
    let sdk_obj = sdk_obj.canonicalize()?;
    let sdk_id = sdk_obj
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| err("pinned SDK object has no UTF-8 store id"))?
        .to_string();
    // The store check comes before any download: the identity is the
    // lock's contentHashes and the SDK, so a project whose packages are
    // already restored syncs and builds with the network cut.
    let identity = nuget_identity(plan, &sdk_id);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    // Fetch every nupkg (nuget.org flatcontainer only in v0). No upfront
    // per-file hash exists (contentHash is semantic): download to tmp,
    // record raw sha256 via cache_insert, verify semantically below.
    let scratch = store.stage_with_activity(activity)?;
    let feed = scratch.join("feed");
    fs::create_dir_all(&feed)?;
    let mut raw_hashes = Vec::new();
    for p in &plan.packages {
        let idl = p.id.to_ascii_lowercase();
        let verl = p.version.to_ascii_lowercase();
        let url = format!("https://api.nuget.org/v3-flatcontainer/{idl}/{verl}/{idl}.{verl}.nupkg");
        let tmp = scratch.join(format!("{idl}.{verl}.nupkg"));
        let fetched = crate::kernel::fetch::download_unpinned(&url, &tmp, 1 << 30)
            .map_err(|e| err(format!("{}: {e}", p.id)))
            .and_then(|_| cache_insert(store, activity, &tmp))
            .and_then(|(raw_sha256, _)| {
                fs::rename(&tmp, feed.join(format!("{idl}.{verl}.nupkg")))?;
                Ok(raw_sha256)
            });
        match fetched {
            Ok(raw_sha256) => raw_hashes.push(raw_sha256),
            Err(e) => {
                let _ = crate::kernel::store::remove_tree(&scratch);
                return Err(e);
            }
        }
    }

    // Locked-mode restore of synthetic projects into the staged folder: the
    // user's projects and global.json are never evaluated in realization.
    let staged = store.stage_with_activity(activity)?;
    let verifier = scratch.join("verifier");
    fs::create_dir_all(&verifier)?;
    prepare_scratch(&scratch)?;
    let parsed: Vec<&ParsedLock> = checked.locks.iter().map(|read| &read.parsed).collect();
    let projects = verifier_projects(&parsed);
    let sdk_major = spec
        .version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u64>().ok())
        .ok_or_else(|| err(format!("SDK version {} has no major", spec.version)))?;
    let objs = match write_verifier(&verifier, &feed, &projects, sdk_major) {
        Ok(objs) => objs,
        Err(e) => {
            let _ = crate::kernel::store::remove_tree(&scratch);
            let _ = crate::kernel::store::remove_tree(&staged);
            return Err(e);
        }
    };
    let config = verifier.join("nuget.config").canonicalize()?;
    // Nothing locked, nothing to verify: the object is the empty folder.
    let result = if projects.is_empty() {
        Ok(())
    } else {
        crate::kernel::sandbox::run_build_spec_on(
            platform,
            &verify_spec(
                &sdk_obj,
                &feed,
                &verifier,
                &config,
                &staged,
                &scratch,
                objs,
                ensure_dotnet_tmp(platform)?,
            ),
            Some(activity),
        )
    };
    if let Err(e) = result {
        let _ = crate::kernel::store::remove_tree(&scratch);
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(io::Error::new(
            e.kind(),
            format!("locked-mode package verification failed: {e}"),
        ));
    }
    // Every locked package must have materialized with its completion
    // marker; anything missing means the lock and feed disagree.
    for p in &plan.packages {
        let dir = staged
            .join(p.id.to_ascii_lowercase())
            .join(p.version.to_ascii_lowercase());
        if !dir.join(".nupkg.metadata").is_file() {
            let _ = crate::kernel::store::remove_tree(&scratch);
            let _ = crate::kernel::store::remove_tree(&staged);
            return Err(err(format!(
                "{}@{}: not materialized by locked restore",
                p.id, p.version
            )));
        }
        if let Err(e) = rewrite_metadata_source(&dir.join(".nupkg.metadata")) {
            let _ = crate::kernel::store::remove_tree(&scratch);
            let _ = crate::kernel::store::remove_tree(&staged);
            return Err(e);
        }
    }
    let _ = crate::kernel::store::remove_tree(&scratch);
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(&sdk_obj)?)?;
    for raw_sha256 in &raw_hashes {
        deps.cache_digest(Digest::sha256(raw_sha256)?);
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
        .map(|(path, _)| path)
}

pub fn project_dotnet_env(
    activity: &StoreActivity,
    project: &ProjectRoot,
    sdk_obj: &Path,
    packages_obj: &Path,
    plan: &DotnetPlan,
    lock_sha256: &str,
    lock_inputs: &[(String, String)],
    resolution_basis: &crate::comforter::join::Digests,
    selected: &Selected,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let sdk_obj = sdk_obj.canonicalize()?;
    let packages_obj = packages_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&sdk_obj)
        .ok_or_else(|| err(".NET SDK object is not in a Greyward store"))?;
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, activity, &sdk_obj)?;
    refs.object_path(&store, activity, &packages_obj)?;
    let mut body = closure_body(&sdk_obj, &packages_obj, plan, lock_sha256, selected)?;
    // A solution's closure records each member lock, which `ward status`
    // compares one by one; a single project's keeps its one lock hash.
    if !lock_inputs.is_empty() {
        body["inputs"] = lock_inputs
            .iter()
            .map(|(path, sha256)| serde_json::json!({"path": path, "sha256": sha256}))
            .collect();
    }
    body[crate::comforter::join::BASIS_FIELD] =
        crate::comforter::join::basis_value(resolution_basis);
    crate::comforter::write_closure(project, "dotnet", body, &store, activity, refs, attribution)
}

/// The .NET closure body: the projection's objects and plan, plus the
/// toolchain record that says which selection realized them. The SDK object
/// is this ecosystem's runtime, and `project_dotnet_env` already holds it as
/// a direct ref, so GC keeps it alive by the recorded id.
fn closure_body(
    sdk_obj: &Path,
    packages_obj: &Path,
    plan: &DotnetPlan,
    lock_sha256: &str,
    selected: &Selected,
) -> io::Result<serde_json::Value> {
    let mut body = serde_json::json!({
        "sdk_object": crate::comforter::object_ref(sdk_obj)?,
        "packages_object": crate::comforter::object_ref(packages_obj)?,
        "packages_lock_sha256": lock_sha256,
        "plan": plan,
    });
    let record = crate::comforter::toolchain::closure_record(selected, sdk_obj);
    crate::comforter::merge_record(&mut body, record);
    Ok(body)
}

fn dotnet_tmp_path(platform: Platform) -> PathBuf {
    if platform.is_macos() {
        PathBuf::from("/private/tmp/.dotnet")
    } else {
        PathBuf::from("/tmp/.dotnet")
    }
}

// Reviewed site (tests/architecture.rs): host probe (`id -u`); no store.
#[allow(clippy::disallowed_methods)]
fn invoking_uid() -> io::Result<u32> {
    let uid = Command::new("/usr/bin/id").arg("-u").output()?.stdout;
    String::from_utf8(uid)
        .map_err(|_| err("could not determine current uid"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| err("could not determine current uid"))
}

fn ensure_dotnet_tmp_at(
    path: &Path,
    expected_uid: u32,
    precreate_shm: bool,
) -> io::Result<PathBuf> {
    let created = match fs::symlink_metadata(path) {
        Ok(md) => {
            if md.file_type().is_symlink() || !md.is_dir() {
                return Err(err(format!(
                    "{} must be a real directory, not a symlink or non-directory",
                    path.display()
                )));
            }
            false
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Two ward processes may race here (concurrent syncs share
            // this directory by design); losing the race is fine, the
            // validation below still applies to whatever now exists.
            match fs::create_dir(path) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };
    if created {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(err(format!(
            "{} must be a real directory, not a symlink or non-directory",
            path.display()
        )));
    }
    if md.uid() != expected_uid {
        return Err(err(format!(
            "{} is owned by uid {}, current uid is {expected_uid}",
            path.display(),
            md.uid(),
        )));
    }
    if path.canonicalize()? != path {
        return Err(err(format!(
            "{} does not canonicalize to the required path",
            path.display()
        )));
    }
    if precreate_shm {
        // Both platforms and both sandbox backends: CoreCLR creates `shm` by
        // mkdtemp()-ing `/tmp/.coreclr.XXXXXX`
        // and rename()-ing it into place. Inside the bwrap sandbox /tmp is
        // a private tmpfs and this directory a separate bind mount, so the
        // rename fails with EXDEV; under Seatbelt only this directory is
        // writable, not /tmp itself, so the mkdtemp fails with EPERM. Either
        // way every NuGet/MSBuild named mutex ("NuGet-Migrations") errors
        // out. macOS periodically purges /private/tmp, so `shm` cannot be
        // assumed to survive from an earlier run. Creating it here, owned by
        // us with the runtime's expected 0700, lets CoreCLR skip that path.
        let shm = path.join("shm");
        match fs::symlink_metadata(&shm) {
            Ok(md) if md.file_type().is_symlink() || !md.is_dir() => {
                return Err(err(format!(
                    "{} must be a real directory, not a symlink or non-directory",
                    shm.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&shm) {
                Ok(()) => fs::set_permissions(&shm, fs::Permissions::from_mode(0o700))?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
    Ok(path.to_path_buf())
}

fn ensure_dotnet_tmp(platform: Platform) -> io::Result<PathBuf> {
    let path = dotnet_tmp_path(platform);
    ensure_dotnet_tmp_at(&path, invoking_uid()?, true)
}

fn add_dotnet_tmp_write_root(mut roots: Vec<PathBuf>, dotnet_tmp: PathBuf) -> Vec<PathBuf> {
    roots.push(dotnet_tmp);
    roots
}

/// The locked-mode package verification: `dotnet restore` of the synthetic
/// verifier projects (their generated solution) against the local feed. It
/// writes only the staged package tree, each verifier project's `obj/` and
/// the CoreCLR tmp root (#680).
#[allow(clippy::too_many_arguments)]
fn verify_spec(
    sdk_obj: &Path,
    feed: &Path,
    verifier: &Path,
    config: &Path,
    staged: &Path,
    scratch: &Path,
    objs: Vec<PathBuf>,
    dotnet_tmp: PathBuf,
) -> BuildSpec {
    let mut write = vec![staged.to_path_buf()];
    write.extend(objs);
    BuildSpec {
        argv: vec![
            sdk_obj.join("dotnet").display().to_string(),
            "restore".to_string(),
            verifier.join("greyward-verifier.sln").display().to_string(),
            "--locked-mode".to_string(),
            "--no-cache".to_string(),
            "--disable-build-servers".to_string(),
            "--configfile".to_string(),
            config.display().to_string(),
            "-noAutoResponse".to_string(),
        ],
        cwd: verifier.to_path_buf(),
        env: forced_env(sdk_obj, staged, scratch),
        read: vec![
            sdk_obj.to_path_buf(),
            feed.to_path_buf(),
            verifier.to_path_buf(),
        ],
        write: add_dotnet_tmp_write_root(write, dotnet_tmp),
        scratch: scratch.to_path_buf(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
        host_view: crate::kernel::sandbox::HostView::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn sdk_pins_cover_each_supported_platform() {
        let catalog = toolchain_catalog().unwrap();
        assert!(
            catalog.bundles().len() > 1,
            "the catalog holds more than the default"
        );
        for bundle in catalog.bundles() {
            for &platform in Platform::ALL {
                let row = bundle.artifact(platform, "dotnet-sdk").unwrap();
                assert_eq!(row.digest.algo(), "sha512");
                assert!(row
                    .url
                    .starts_with("https://builds.dotnet.microsoft.com/dotnet/Sdk/"));
            }
        }
        assert_eq!(
            shipped_selection().unwrap().version("dotnet-sdk").unwrap(),
            SDK_VERSION
        );

        let linux = sdk_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(
            linux.url,
            "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/dotnet-sdk-9.0.317-linux-x64.tar.gz"
        );
        assert_eq!(linux.digest.hex().len(), 128);
        assert!(linux
            .digest
            .hex()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn sdk_identities_and_fingerprints_are_platform_specific() {
        let darwin = pin_spec(Platform::Aarch64AppleDarwin);
        let linux = pin_spec(Platform::X86_64UnknownLinuxGnu);
        assert_ne!(
            sdk_identity(&darwin).object_id(),
            sdk_identity(&linux).object_id()
        );
        assert_ne!(sdk_fingerprint_of(&darwin), sdk_fingerprint_of(&linux));
    }

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let pin = sdk_pin(platform).unwrap();
        assert_eq!(
            pin.url,
            "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/dotnet-sdk-9.0.317-osx-arm64.tar.gz"
        );
        assert_eq!(
            pin.digest.hex(),
            "f707a1c73e84c6d009baab2a274270bd11bbb58cd8244cf59594fe1662f50225d1665878d3af4e4b9649b6feccd95b693cf9cf28e127742b7a4e6287caa3eb2a"
        );
        let spec = pin_spec(platform);
        let identity = sdk_identity(&spec);
        assert_eq!(
            identity.object_id(),
            "aebf0bc6741c81b414dfe7825ed9115ccc60f085-dotnet-sdk-9.0.317"
        );
        assert_eq!(sdk_fingerprint_of(&spec), "3a532efac27c3140");
    }

    /// The selection is the only authority on the sync path, so the object
    /// it realizes must have the id the pin table realized before selection
    /// existed, on both platforms: that is the id every cached SDK already
    /// has. If this drifts, every cached SDK is orphaned.
    #[test]
    fn a_selected_row_and_the_pin_build_the_same_identity() {
        let selected = shipped_selection().unwrap();
        for platform in Platform::ALL {
            let from_lock = sdk_spec(*platform, &selected).unwrap();
            let from_pin = pin_spec(*platform);
            assert_eq!(from_lock.version, from_pin.version);
            assert_eq!(from_lock.url, from_pin.url);
            assert_eq!(from_lock.sha512, from_pin.sha512);
            assert_eq!(
                sdk_identity(&from_lock).object_id(),
                sdk_identity(&from_pin).object_id(),
                "{}",
                platform.triple()
            );
            assert_eq!(
                sdk_fingerprint_of(&from_lock),
                sdk_fingerprint_of(&from_pin)
            );
        }
    }

    #[test]
    fn an_unknown_recipe_and_a_foreign_selection_are_both_refused() {
        let mut selected = shipped_selection().unwrap();
        for row in &mut selected.bundle.artifacts {
            row.recipe = "dotnet-sdk/99".into();
        }
        let error = sdk_spec(Platform::X86_64UnknownLinuxGnu, &selected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("dotnet-sdk/99"), "{error}");
        assert!(error.contains("upgrade ward"), "{error}");

        let mut foreign = shipped_selection().unwrap();
        foreign.ecosystem = "go".into();
        let error = sdk_spec(Platform::X86_64UnknownLinuxGnu, &foreign)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not dotnet"), "{error}");

        // Microsoft publishes sha512; a sha256 row is another provenance
        // channel and this tailor does not accept one.
        let mut wrong_algo = shipped_selection().unwrap();
        for row in &mut wrong_algo.bundle.artifacts {
            row.digest = Digest::sha256(&"a".repeat(64)).unwrap();
        }
        let error = sdk_spec(Platform::X86_64UnknownLinuxGnu, &wrong_algo)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be sha512"), "{error}");
    }

    /// The global.json gate answers to the selection, so a project locked to
    /// an older SDK keeps passing after the shipped catalog moves on, and it
    /// reads rollForward as the range the host reads.
    #[test]
    fn the_global_json_gate_compares_against_the_selected_sdk() {
        let scratch = TempDir::named("dotnet-globaljson");
        let temp = scratch.0.clone();
        let gate = |text: &str, selected: &str| {
            fs::write(temp.join("global.json"), text).unwrap();
            check_global_json(&ProjectRoot::open(&temp).unwrap(), selected)
        };
        let exact = r#"{"sdk":{"version":"9.0.100","rollForward":"disable"}}"#;
        gate(exact, "9.0.100").unwrap();
        let error = gate(exact, SDK_VERSION).unwrap_err().to_string();
        assert!(error.contains("admits SDK ==9.0.100"), "{error}");
        assert!(error.contains(SDK_VERSION), "{error}");
        // A roll-forward policy admits its range, and only its range.
        let feature =
            "\u{feff}{\"sdk\":{\"version\":\"9.0.100\",\"rollForward\":\"latestFeature\"}}";
        gate(feature, SDK_VERSION).unwrap();
        let error = gate(feature, "10.0.100").unwrap_err().to_string();
        assert!(error.contains(">=9.0.100,<9.1"), "{error}");
        // No rollForward is the host's patch policy: the same feature band.
        gate(r#"{"sdk":{"version":"9.0.300"}}"#, SDK_VERSION).unwrap();
        assert!(gate(r#"{"sdk":{"version":"9.0.100"}}"#, SDK_VERSION).is_err());
        // What the host ignores constrains nothing.
        gate(r#"{"sdk":{"version":"9.0.*"}}"#, SDK_VERSION).unwrap();
        gate(r#"{"sdk":{"allowPrerelease":false}}"#, SDK_VERSION).unwrap();
        gate(r#"{"tools":{}}"#, SDK_VERSION).unwrap();
        // Redirection and an unknown policy are refused.
        for (text, refusal) in [
            (
                format!(
                    r#"{{"sdk":{{"version":"{SDK_VERSION}","rollForward":"disable"}},"msbuild-sdks":{{"X":"1.0"}}}}"#
                ),
                "SDK redirection",
            ),
            (
                format!(r#"{{"sdk":{{"version":"{SDK_VERSION}","paths":[".dotnet"]}}}}"#),
                "SDK redirection",
            ),
            (
                format!(r#"{{"sdk":{{"version":"{SDK_VERSION}","rollForward":"newest"}}}}"#),
                "roll-forward policy",
            ),
        ] {
            let error = gate(&text, SDK_VERSION).unwrap_err().to_string();
            assert!(error.contains(refusal), "{text}: {error}");
        }
        // No global.json at all is no constraint.
        fs::remove_file(temp.join("global.json")).unwrap();
        check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION).unwrap();
    }

    /// Every closure this tailor writes carries which bundle realized it and
    /// which store object that bundle became: `ward status` compares the one,
    /// `ward run` resolves the other.
    #[test]
    fn the_closure_body_records_the_bundle_and_the_runtime_object() {
        let selected = shipped_selection().unwrap();
        let sdk_obj = Path::new("/store/objects/abc-dotnet-sdk-9.0.317");
        let plan = DotnetPlan {
            members: Vec::new(),
            sdk_version: SDK_VERSION.into(),
            project: "app.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: Vec::new(),
        };
        let body = closure_body(
            sdk_obj,
            Path::new("/store/objects/def-packages-0"),
            &plan,
            &"c".repeat(64),
            &selected,
        )
        .unwrap();
        assert_eq!(body["toolchain"]["ecosystem"], "dotnet");
        assert_eq!(body["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(body["toolchain"]["versions"]["dotnet-sdk"], SDK_VERSION);
        assert_eq!(body["runtime_object"]["id"], "abc-dotnet-sdk-9.0.317");
        assert_eq!(
            body["runtime_object"]["path"],
            sdk_obj.display().to_string()
        );
        // The runtime object is the SDK the projection already records, and
        // every pre-existing key survives beside the record.
        assert_eq!(body["sdk_object"]["id"], body["runtime_object"]["id"]);
        assert_eq!(body["packages_object"]["id"], "def-packages-0");
        assert_eq!(body["packages_lock_sha256"], "c".repeat(64));
        assert_eq!(body["plan"]["project"], "app.csproj");
    }

    /// The durable root/2 record `project_dotnet_env` publishes names
    /// exactly the SDK object and the packages object it was handed:
    /// nothing inferred from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("dotnet").unwrap();
        let scratch = TempDir::named("dotnet-closure-refs");
        let temp = scratch.0.clone();
        let store_root = temp.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store::for_test(store_root.canonicalize().unwrap());
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        let sdk_id = store.publish_bare_test("dotnet-sdk", SDK_VERSION);
        let packages_id = store.publish_bare_test("packages", "0");
        let project = temp.join("project");
        fs::create_dir_all(&project).unwrap();
        let plan = DotnetPlan {
            members: Vec::new(),
            sdk_version: SDK_VERSION.into(),
            project: "app.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: Vec::new(),
        };
        project_dotnet_env(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &store.object_path(&sdk_id),
            &store.object_path(&packages_id),
            &plan,
            &"c".repeat(64),
            &[],
            &Default::default(),
            &shipped_selection().unwrap(),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([sdk_id, packages_id])
        );
        assert!(record.projections.is_empty(), "{:?}", record.projections);

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
    }

    /// `ward run`'s dotnet guard: a build verb is found past leading options,
    /// `dotnet exec` of MSBuild.dll is refused by file name, and running a
    /// built app is allowed.
    #[test]
    fn dotnet_run_guard_handles_options_and_msbuild_dll() {
        let refused = |words: &[&str]| {
            refused_run_command(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(
            refused(&["dotnet", "-d", "build"]).as_deref(),
            Some(
                "`dotnet build` compiles/executes MSBuild code and must run sandboxed: \
                 use `ward build dotnet ...`"
            )
        );
        assert_eq!(
            refused(&["dotnet", "MSBuild"]).as_deref(),
            Some(
                "`dotnet MSBuild` compiles/executes MSBuild code and must run sandboxed: \
                 use `ward build dotnet ...`"
            )
        );
        assert_eq!(
            refused(&["dotnet", "exec", "/tmp/tools/msbuild.DLL"]).as_deref(),
            Some(
                "`dotnet exec .../MSBuild.dll` executes MSBuild code and must run sandboxed: \
                 use `ward build dotnet ...`"
            )
        );
        assert_eq!(refused(&["dotnet", "exec", "app.dll"]), None);
        assert_eq!(refused(&["dotnet", "--info"]), None);
        assert_eq!(refused(&["/usr/bin/env", "dotnet", "build"]), None);
    }

    #[test]
    fn dotnet_tmp_validation_is_path_specific_and_testable() {
        // The validator requires canonical paths, and a TempDir path is one.
        // On macOS `/tmp` is a symlink, so the real path names `/private`.
        assert_eq!(
            dotnet_tmp_path(Platform::Aarch64AppleDarwin),
            PathBuf::from("/private/tmp/.dotnet")
        );
        assert_eq!(
            dotnet_tmp_path(Platform::X86_64UnknownLinuxGnu),
            PathBuf::from("/tmp/.dotnet")
        );
        let scratch = TempDir::named("dn-tmp");
        let base = scratch.0.clone();
        let uid = invoking_uid().unwrap();

        let safe = base.join("safe");
        fs::create_dir(&safe).unwrap();
        assert_eq!(ensure_dotnet_tmp_at(&safe, uid, false).unwrap(), safe);

        let created = base.join("created");
        assert_eq!(ensure_dotnet_tmp_at(&created, uid, false).unwrap(), created);
        assert_eq!(
            fs::metadata(&created).unwrap().permissions().mode() & 0o7777,
            0o700
        );

        let file = base.join("file");
        fs::write(&file, b"not a directory").unwrap();
        assert!(ensure_dotnet_tmp_at(&file, uid, false).is_err());

        let link = base.join("link");
        symlink(&safe, &link).unwrap();
        assert!(ensure_dotnet_tmp_at(&link, uid, false).is_err());

        let mismatch = base.join("mismatch");
        fs::create_dir(&mismatch).unwrap();
        let error = ensure_dotnet_tmp_at(&mismatch, uid ^ 1, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is owned by uid"), "{error}");
    }

    #[test]
    fn precreates_shm_under_the_dotnet_tmp_dir_on_every_platform() {
        let scratch = TempDir::named("dotnet-shm");
        let temp = scratch.0.join("tmp");
        let uid = invoking_uid().unwrap();
        let dir = ensure_dotnet_tmp_at(&temp, uid, true).unwrap();
        let shm = dir.join("shm");
        assert!(shm.is_dir());
        assert_eq!(
            fs::metadata(&shm).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // idempotent, and a symlinked shm is refused
        ensure_dotnet_tmp_at(&temp, uid, true).unwrap();
        fs::remove_dir(&shm).unwrap();
        std::os::unix::fs::symlink(&temp, &shm).unwrap();
        assert!(ensure_dotnet_tmp_at(&temp, uid, true).is_err());
    }

    #[test]
    fn every_prepared_scratch_is_already_marked_nuget_migrated() {
        let scratch = TempDir::named("dn-mig");
        let base = scratch.0.clone();
        prepare_scratch(&base).unwrap();
        assert!(base.join("home").is_dir());
        let data_home = forced_env(&base, &base, &base)
            .into_iter()
            .find(|(k, _)| k == "XDG_DATA_HOME")
            .map(|(_, v)| PathBuf::from(v))
            .expect("dotnet forces XDG_DATA_HOME");
        assert!(
            data_home
                .join("NuGet")
                .join("Migrations")
                .join("1")
                .is_file(),
            "NuGet reads migrations under XDG_DATA_HOME; the sentinel must land there"
        );
        prepare_scratch(&base).unwrap();
    }

    /// Every sandboxed dotnet phase (package verification, restore, build)
    /// writes exactly its own scratch directories plus the selected CoreCLR
    /// tmp root: never the project, the SDK, the package object, or the
    /// feed it reads. Built through the same spec constructors the phases
    /// run, so a write root added to any of them fails here.
    #[test]
    fn every_dotnet_sandbox_phase_writes_only_its_scratch_and_the_selected_tmp_root() {
        let base = PathBuf::from("/fixture");
        let project_dir = base.join("project");
        let sdk_obj = base.join("store/objects/sdk");
        let packages_obj = base.join("store/objects/packages");
        let scratch = base.join("store/tmp/stage-1");
        let objdir = scratch.join("obj");
        let output_scratch = scratch.join("output");
        let staged = base.join("store/tmp/stage-2");
        let feed = scratch.join("feed");
        let verifier = scratch.join("verifier");
        let dotnet_tmp = base.join("tmp/.dotnet");
        let phase = ProjectPhase {
            project_dir: &project_dir,
            sdk_obj: &sdk_obj,
            packages_obj: &packages_obj,
            scratch: &scratch,
            objdir: &objdir,
            output_scratch: &output_scratch,
        };
        let verify = verify_spec(
            &sdk_obj,
            &feed,
            &verifier,
            &verifier.join("nuget.config"),
            &staged,
            &scratch,
            vec![verifier.join("v0/obj"), verifier.join("v1/obj")],
            dotnet_tmp.clone(),
        );
        let restore = phase.spec(false, Vec::new(), Vec::new(), dotnet_tmp.clone());
        let build = phase.spec(true, Vec::new(), Vec::new(), dotnet_tmp.clone());
        assert_eq!(
            verify.write,
            [
                staged.clone(),
                verifier.join("v0/obj"),
                verifier.join("v1/obj"),
                dotnet_tmp.clone()
            ]
        );
        // Artifacts mode: one scratch tree both phases write.
        let artifacts = scratch.join("artifacts");
        let artifacts_phase = ProjectPhase {
            objdir: &artifacts,
            output_scratch: &artifacts,
            ..phase
        };
        assert_eq!(
            artifacts_phase
                .spec(true, Vec::new(), Vec::new(), dotnet_tmp.clone())
                .write,
            [artifacts.clone(), dotnet_tmp.clone()]
        );
        assert_eq!(restore.write, [objdir.clone(), dotnet_tmp.clone()]);
        assert_eq!(
            build.write,
            [output_scratch.clone(), objdir.clone(), dotnet_tmp.clone()]
        );
        // What each phase reads stays read-only.
        assert_eq!(verify.read, [sdk_obj.clone(), feed, verifier]);
        for spec in [&restore, &build] {
            assert_eq!(
                spec.read,
                [project_dir.clone(), sdk_obj.clone(), packages_obj.clone()]
            );
        }
    }

    fn minimal_csproj() -> &'static str {
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>"
    }

    /// A member locked for Windows turns on Windows targeting for restore
    /// and is left out of `ward build`; a portable project gets neither.
    #[test]
    fn windows_members_restore_with_windows_targeting_and_are_not_built() {
        let scratch = TempDir::named("dn-windows");
        let root = scratch.0.clone();
        for (path, text) in [
            (
                "s.sln",
                "Project(\"{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}\") = \"a\", \"a\\a.csproj\", \"{1}\"\nEndProject\n\
                 Project(\"{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}\") = \"w\", \"w\\w.csproj\", \"{2}\"\nEndProject\n",
            ),
            ("a/a.csproj", minimal_csproj()),
            ("w/w.csproj", minimal_csproj()),
            (
                "a/packages.lock.json",
                r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
            ),
            (
                "w/packages.lock.json",
                r#"{"version":1,"dependencies":{"net9.0-windows7.0":{}}}"#,
            ),
        ] {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        }
        let checked = preflight(&ProjectRoot::open(&root).unwrap(), SDK_VERSION).unwrap();
        assert!(checked.windows);
        assert_eq!(checked.windows_members(), [PathBuf::from("w/w.csproj")]);
        assert_eq!(
            buildable(&checked).unwrap().members,
            [PathBuf::from("a/a.csproj")]
        );

        fs::write(
            root.join("w/packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        let checked = preflight(&ProjectRoot::open(&root).unwrap(), SDK_VERSION).unwrap();
        assert!(!checked.windows);
        assert_eq!(buildable(&checked).unwrap().members.len(), 2);

        // With no lock yet, project text decides.
        fs::remove_file(root.join("w/packages.lock.json")).unwrap();
        fs::write(root.join("w/w.csproj"), in_project("<UseWPF>true</UseWPF>")).unwrap();
        let checked = preflight(&ProjectRoot::open(&root).unwrap(), SDK_VERSION).unwrap();
        assert!(checked.windows);
    }

    #[test]
    fn solution_builds_refuse_two_members_of_one_name() {
        let members = |paths: &[&str]| paths.iter().map(PathBuf::from).collect::<Vec<_>>();
        same_named_members(&members(&["a/App.csproj", "b/Lib.csproj"])).unwrap();
        let why = same_named_members(&members(&["a/App.csproj", "b/app.fsproj"]))
            .unwrap_err()
            .to_string();
        assert!(why.contains("a/App.csproj and b/app.fsproj"), "{why}");
    }

    /// A file deeper in the checkout may climb as far as the root.
    #[test]
    fn output_paths_may_climb_to_the_root() {
        assert!(output_inside("..\\output\\release\\", 1));
        assert!(output_inside("$(msbuildthisfiledirectory)../../bin", 2));
        assert!(!output_inside("..\\..\\output", 1));
        assert!(!output_inside("$(solutiondir)..\\bin", 3));
        assert!(output_inside("$(solutiondir)bin\\$(configuration)", 0));
        let scratch = TempDir::named("dn-output-depth");
        fs::create_dir_all(scratch.0.join("src/app")).unwrap();
        let project = "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><OutputPath>../../Output/Release/</OutputPath></PropertyGroup></Project>";
        fs::write(scratch.0.join("src/app/app.csproj"), project).unwrap();
        fs::write(scratch.0.join("app.csproj"), project).unwrap();
        let root = ProjectRoot::open(&scratch.0).unwrap();
        validate_csproj(&root, Path::new("src/app/app.csproj")).unwrap();
        assert!(validate_csproj(&root, Path::new("app.csproj")).is_err());
    }

    #[test]
    fn lock_targets_name_their_framework() {
        for (target, tfm) in [
            ("net9.0", "net9.0"),
            ("net9.0/linux-x64", "net9.0"),
            ("net11.0-windows7.0", "net11.0-windows7.0"),
            (".NETStandard,Version=v2.0", "netstandard2.0"),
            (".NETFramework,Version=v4.7.2", "net472"),
            (".NETCoreApp,Version=v3.1/win-x64", "netcoreapp3.1"),
        ] {
            assert_eq!(target_framework(target).unwrap(), tfm, "{target}");
        }
        for bad in [
            "",
            "net9.0;evil",
            ".NETFramework,Version=v",
            ".NETFramework,Version=v4'",
            ".Other,Version=v1.0",
            ".NETStandard",
            "net$(X)",
        ] {
            assert!(target_framework(bad).is_err(), "{bad}");
        }
    }

    /// Every lock's packages are restored under the framework they were
    /// locked for; one id at two versions for one framework goes to a
    /// second verifier project.
    #[test]
    fn verifier_projects_keep_each_framework_at_one_version() {
        let package = |id: &str, version: &str, kind: &str| {
            format!(
                r#""{id}":{{"type":"{kind}","resolved":"{version}","contentHash":"{CONTENT_HASH}"}}"#
            )
        };
        let a = parse_lock(&format!(
            r#"{{"version":1,"dependencies":{{
                "net8.0":{{{},{}}},
                ".NETStandard,Version=v2.0":{{{}}},
                "net8.0/linux-x64":{{{}}}}}}}"#,
            package("Json", "13.0.1", "Direct"),
            package("Core", "1.0.0", "Transitive"),
            package("Json", "12.0.0", "Direct"),
            package("Native", "2.0.0", "Transitive"),
        ))
        .unwrap();
        let b = parse_lock(&format!(
            r#"{{"version":2,"dependencies":{{"net8.0":{{{},{}}}}}}}"#,
            package("Json", "13.0.3", "CentralTransitive"),
            package("Other", "1.0.0", "Project"),
        ))
        .unwrap();
        let projects = verifier_projects(&[&a, &b]);
        assert_eq!(projects.len(), 2);
        let ids = |project: &VerifierProject, key: &str| -> Vec<String> {
            project[key]
                .values()
                .map(|p| format!("{}@{}", p.id, p.version))
                .collect()
        };
        assert_eq!(
            ids(&projects[0], "net8.0"),
            ["Core@1.0.0", "Json@13.0.1", "Native@2.0.0"]
        );
        assert_eq!(
            ids(&projects[0], ".NETStandard,Version=v2.0"),
            ["Json@12.0.0"]
        );
        assert_eq!(ids(&projects[1], "net8.0"), ["Json@13.0.3"]);

        let csproj = synthetic_csproj(&projects[0], 8).unwrap();
        assert!(
            csproj.contains("<TargetFrameworks>netstandard2.0;net8.0</TargetFrameworks>"),
            "{csproj}"
        );
        // The SDK's own framework prunes like the user's restore did; any
        // other restores with no framework reference to download.
        assert!(
            csproj.contains(
                "<FrameworkReference Include=\"Microsoft.AspNetCore.App\" />\n  </ItemGroup>"
            ),
            "{csproj}"
        );
        assert!(
            csproj.contains(
                "<PropertyGroup Condition=\"'$(TargetFramework)' == 'netstandard2.0'\">\n    \
                 <DisableImplicitFrameworkReferences>true</DisableImplicitFrameworkReferences>\n"
            ),
            "{csproj}"
        );
        assert!(!csproj.contains("'net8.0'\">\n    <Disable"), "{csproj}");
        let older = synthetic_csproj(&projects[0], 9).unwrap();
        assert!(!older.contains("<FrameworkReference"), "{older}");
        assert!(
            csproj.contains(
                "<ItemGroup Condition=\"'$(TargetFramework)' == 'netstandard2.0'\">\n    \
                 <PackageReference Include=\"Json\" Version=\"[12.0.0]\" />"
            ),
            "{csproj}"
        );
        let lock = synthetic_lock(&projects[0]);
        assert_eq!(
            lock["dependencies"][".NETStandard,Version=v2.0"]["Json"]["requested"],
            "[12.0.0]"
        );
        assert_eq!(lock["dependencies"]["net8.0"]["Core"]["type"], "Direct");
    }

    #[test]
    fn lock_parsing_and_validation() {
        let base = NugetPackage {
            id: "Newtonsoft.Json".into(),
            version: "13.0.4".into(),
            content_hash: CONTENT_HASH.into(),
        };
        let ok = DotnetPlan {
            members: Vec::new(),
            sdk_version: SDK_VERSION.into(),
            project: "p.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: vec![base.clone()],
        };
        assert!(validate_plan(&ok, SDK_VERSION).is_ok());
        // Multi-targeted locks, long framework names included, are read.
        assert!(validate_plan(
            &DotnetPlan {
                targets: vec![
                    "net9.0".into(),
                    "net8.0".into(),
                    ".NETStandard,Version=v2.0".into(),
                ],
                ..ok.clone()
            },
            SDK_VERSION,
        )
        .is_ok());
        let error = validate_plan(
            &DotnetPlan {
                targets: vec!["net9.0".into(), "net8.0;evil".into()],
                ..ok.clone()
            },
            SDK_VERSION,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid lock target framework"), "{error}");
        let same_tfm_rids = DotnetPlan {
            targets: vec![
                "net9.0".into(),
                "net9.0/osx-arm64".into(),
                "net9.0/linux-x64".into(),
            ],
            ..ok.clone()
        };
        assert!(validate_plan(&same_tfm_rids, SDK_VERSION).is_ok());
        let mut evil = base.clone();
        evil.id = "../escape".into();
        assert!(validate_plan(
            &DotnetPlan {
                packages: vec![evil],
                ..ok.clone()
            },
            SDK_VERSION
        )
        .is_err());
        // contentHash is the packages object's identity input, so only a
        // base64 sha512 passes: 88 characters that decode to 64 bytes. An
        // empty value, a truncated one, 88 characters of something longer,
        // and anything not base64 are refused.
        for content_hash in [
            String::new(),
            "not/base64\n".to_string(),
            CONTENT_HASH[..87].to_string(),
            "A".repeat(88),
            format!("{}A=", &CONTENT_HASH[..86]),
            CONTENT_HASH.replace('/', "_"),
        ] {
            let mut bad = base.clone();
            bad.content_hash = content_hash.clone();
            let error = validate_plan(
                &DotnetPlan {
                    packages: vec![bad],
                    ..ok.clone()
                },
                SDK_VERSION,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("invalid contentHash"),
                "{content_hash:?}: {error}"
            );
        }
    }

    /// The real contentHash of Newtonsoft.Json 13.0.3 (the dotnet-hello
    /// fixture's lock).
    const CONTENT_HASH: &str =
        "pdgNNMai3zv51W5aq268sujXUyx7SNdE2bj1wZcWjAQrKMFZV260lbqYop1d2GM67JI1huLRwxo9ZqnfF/lC6A==";

    /// Issue #696. The packages object's identity is known before any
    /// download: the SDK object and each package's lock contentHash, and
    /// nothing a download produces. So the store check can run first, and a
    /// re-signed nupkg (new raw bytes, same contentHash) keeps its object.
    /// The golden pins `nuget-packages/2`; a change to it orphans every
    /// restored packages object.
    #[test]
    fn the_packages_identity_is_the_lock_and_the_sdk() {
        crate::tailors::install_kinds();
        let plan = |content_hash: &str| DotnetPlan {
            members: Vec::new(),
            sdk_version: SDK_VERSION.into(),
            project: "app.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: vec![NugetPackage {
                id: "Newtonsoft.Json".into(),
                version: "13.0.3".into(),
                content_hash: content_hash.into(),
            }],
        };
        let sdk = sdk_identity(&pin_spec(Platform::X86_64UnknownLinuxGnu)).object_id();
        let identity = nuget_identity(&plan(CONTENT_HASH), &sdk);
        assert_eq!(
            identity.inputs.keys().collect::<Vec<_>>(),
            ["extractor", "pkg:newtonsoft.json@13.0.3", "schema"]
        );
        assert_eq!(identity.inputs["schema"], "nuget-packages/2");
        assert_eq!(identity.inputs["extractor"], sdk);
        assert_eq!(identity.inputs["pkg:newtonsoft.json@13.0.3"], CONTENT_HASH);
        assert_eq!(identity.version, "1");
        assert_eq!(
            crate::kernel::objmeta::check_identity_grammar(&identity),
            Ok(())
        );
        assert_eq!(
            identity.object_id(),
            "e21a9a1f5cc45a98c9030a867aba71d317ecfb3e-packages-1"
        );
        // Another contentHash or another SDK is another object.
        let other = format!("{}Q==", &CONTENT_HASH[..85]);
        assert_ne!(other, CONTENT_HASH);
        assert_ne!(
            nuget_identity(&plan(&other), &sdk).object_id(),
            identity.object_id()
        );
        assert_ne!(
            nuget_identity(&plan(CONTENT_HASH), "other-sdk").object_id(),
            identity.object_id()
        );
    }

    #[test]
    fn build_argument_allowlist() {
        for bad in [
            "-p:RestoreSources=https://evil",
            "--output",
            "project.csproj",
            "@resp.rsp",
            "-r",
        ] {
            assert!(validate_build_args(&[bad.to_string()]).is_err(), "{bad}");
        }
        for good in [
            vec!["-c", "Release"],
            vec!["--verbosity", "minimal"],
            vec!["-f", "net9.0"],
            vec!["--no-incremental"],
            vec!["-warnaserror"],
            vec!["-p:Configuration=Release"],
            vec!["-p:treatwarningsaserrors=true"],
        ] {
            assert!(
                validate_build_args(&good.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
                    .is_ok(),
                "{good:?}"
            );
        }
        for v in ["build", "test", "publish", "msbuild", "restore"] {
            assert!(BUILD_VERBS.contains(&v));
        }
    }

    /// An SDK file in a search-only (0111) ancestor is still seen: the walk
    /// checks it by name through the held ancestor (#480).
    #[test]
    fn preflight_sees_an_sdk_file_in_a_search_only_ancestor() {
        let scratch = TempDir::named("dn-search-only");
        let parent = scratch.0.join("parent");
        let project = parent.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(parent.join("Directory.Build.rsp"), "-p:X=1\n").unwrap();
        let _search_only = match crate::kernel::testutil::SearchOnly::new(&parent) {
            Ok(held) => held,
            Err(skip) => return eprintln!("{skip}"),
        };
        let error = preflight(&ProjectRoot::open(&project).unwrap(), SDK_VERSION).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Directory.Build.rsp is not supported"),
            "{error}"
        );
    }

    #[test]
    fn preflight_rejects_unsafe_project_shapes() {
        let scratch = TempDir::named("dn-preflight");
        let base = scratch.0.clone();

        let minimal = base.join("minimal.csproj");
        fs::write(&minimal, minimal_csproj()).unwrap();
        assert!(validate_csproj(
            &ProjectRoot::open(&base).unwrap(),
            Path::new("minimal.csproj")
        )
        .is_ok());
        let sdk_element = base.join("sdk-element.csproj");
        fs::write(
            &sdk_element,
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Sdk Name=\"X\" /></Project>",
        )
        .unwrap();
        let error = validate_csproj(
            &ProjectRoot::open(&base).unwrap(),
            Path::new("sdk-element.csproj"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the MSBuild SDK x is fetched from NuGet"),
            "{error}"
        );
        let garbage = base.join("garbage.csproj");
        fs::write(&garbage, "not XML").unwrap();
        let error = validate_csproj(
            &ProjectRoot::open(&base).unwrap(),
            Path::new("garbage.csproj"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not a supported project file (expected <Project root)"),
            "{error}"
        );

        let symlinked = base.join("symlinked");
        fs::create_dir(&symlinked).unwrap();
        fs::write(symlinked.join("project.xml"), minimal_csproj()).unwrap();
        symlink(
            symlinked.join("project.xml"),
            symlinked.join("project.csproj"),
        )
        .unwrap();
        let error = preflight(&ProjectRoot::open(&symlinked).unwrap(), SDK_VERSION).unwrap_err();
        assert!(
            error.to_string().contains("project.csproj is a symlink"),
            "{error}"
        );

        let project_lock = base.join("project-lock");
        fs::create_dir(&project_lock).unwrap();
        fs::write(project_lock.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(
            project_lock.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"Project","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        // A Project entry names another project of the tree, which the
        // solution restores itself: nothing to fetch.
        let checked = preflight(&ProjectRoot::open(&project_lock).unwrap(), SDK_VERSION).unwrap();
        assert!(checked.locks[0].parsed.packages.is_empty());

        let central_transitive = base.join("central-transitive");
        fs::create_dir(&central_transitive).unwrap();
        fs::write(central_transitive.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(
            central_transitive.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"CentralTransitive","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        let checked = preflight(
            &ProjectRoot::open(&central_transitive).unwrap(),
            SDK_VERSION,
        )
        .unwrap();
        assert_eq!(checked.locks[0].parsed.packages[0].id, "Other");

        // An import is evaluated in the sandbox like the project itself.
        let import = base.join("import");
        fs::create_dir(&import).unwrap();
        fs::write(
            import.join("project.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Import Project=\"shared.targets\" /></Project>",
        )
        .unwrap();
        preflight(&ProjectRoot::open(&import).unwrap(), SDK_VERSION).unwrap();

        let bad_global = base.join("bad-global");
        fs::create_dir(&bad_global).unwrap();
        fs::write(bad_global.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(bad_global.join("global.json"), r#"{"sdk":"9.0.100"}"#).unwrap();
        let error = preflight(&ProjectRoot::open(&bad_global).unwrap(), SDK_VERSION).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("global.json sdk must be an object"),
            "{error}"
        );

        let ancestor = base.join("ancestor");
        fs::create_dir(&ancestor).unwrap();
        fs::write(ancestor.join("global.json"), "{}").unwrap();
        let child = ancestor.join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("project.csproj"), minimal_csproj()).unwrap();
        let held = ProjectRoot::open(&child).unwrap();
        let error = preflight(&held, SDK_VERSION).unwrap_err().to_string();
        assert!(error.contains("ancestor global.json"), "{error}");
        // The ancestor is the directory holding the project: moved away
        // after the open, with a clean one at its path, it still refuses.
        fs::rename(&ancestor, base.join("ancestor-moved")).unwrap();
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("project.csproj"), minimal_csproj()).unwrap();
        let error = preflight(&held, SDK_VERSION).unwrap_err().to_string();
        assert!(error.contains("ancestor global.json"), "{error}");

        let solution_only = base.join("solution-only");
        fs::create_dir(&solution_only).unwrap();
        fs::write(solution_only.join("x.sln"), "solution").unwrap();
        assert!(has_marker(&ProjectRoot::open(&solution_only).unwrap()).unwrap());
        // An unreadable/missing dir propagates instead of guessing.
        assert!(ProjectRoot::open(&base.join("missing")).is_err());

        let bypass = base.join("bypass");
        fs::create_dir(&bypass).unwrap();
        let cr_sdk = bypass.join("cr.csproj");
        fs::write(
            &cr_sdk,
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Sdk\rName=\"X\"/></Project>",
        )
        .unwrap();
        let error = validate_csproj(&ProjectRoot::open(&bypass).unwrap(), Path::new("cr.csproj"))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the MSBuild SDK x is fetched from NuGet"),
            "{error}"
        );
        let projector = bypass.join("projector.csproj");
        fs::write(&projector, "<Projector/>").unwrap();
        let error = validate_csproj(
            &ProjectRoot::open(&bypass).unwrap(),
            Path::new("projector.csproj"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not a supported project file (expected <Project root)"),
            "{error}"
        );
    }

    /// Preflight and planning read the lock through one parser, so a lock
    /// preflight accepts is one planning can use, and each refusal has one
    /// text.
    #[test]
    fn preflight_and_planning_share_one_lock_parser() {
        let scratch = TempDir::named("dn-lock");
        let refusal = |name: &str, lock: &str| -> String {
            let dir = scratch.0.join(name);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("p.csproj"), minimal_csproj()).unwrap();
            fs::write(dir.join("packages.lock.json"), lock).unwrap();
            preflight(&ProjectRoot::open(&dir).unwrap(), SDK_VERSION)
                .map(|_| String::new())
                .unwrap_err()
                .to_string()
        };
        let entry = |fields: &str| {
            format!(
                r#"{{"version":1,"dependencies":{{"net9.0":{{"Newtonsoft.Json":{{{fields}}}}}}}}}"#
            )
        };
        let error = refusal("v3", r#"{"version":3,"dependencies":{}}"#);
        assert!(
            error.contains("packages.lock.json version 3 unsupported (versions 1 and 2 are read)"),
            "{error}"
        );
        // Version 2 (Central Package Management) is read like version 1.
        let v2 = parse_lock("\u{feff}{\"version\":2,\"dependencies\":{\"net9.0\":{}}}").unwrap();
        assert_eq!(v2.targets, ["net9.0"]);
        let error = refusal(
            "kind",
            &entry(r#""type":"Weird","resolved":"1.0.0","contentHash":"A""#),
        );
        assert!(
            error.contains("Newtonsoft.Json: unsupported lock dependency type Weird; expected Direct, Transitive, CentralTransitive or Project"),
            "{error}"
        );
        let error = refusal("untyped", &entry(r#""resolved":"1.0.0","contentHash":"A""#));
        assert!(
            error.contains("Newtonsoft.Json: unsupported lock dependency type null; expected Direct, Transitive, CentralTransitive or Project"),
            "{error}"
        );
        let error = refusal("unresolved", &entry(r#""type":"Direct","contentHash":"A""#));
        assert!(
            error.contains("Newtonsoft.Json: no resolved version"),
            "{error}"
        );
        let error = refusal("unhashed", &entry(r#""type":"Direct","resolved":"1.0.0""#));
        assert!(error.contains("Newtonsoft.Json: no contentHash"), "{error}");
        let error = refusal(
            "conflict",
            r#"{"version":1,"dependencies":{
                "net9.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"1.0.0","contentHash":"A"}},
                "net9.0/linux-x64":{"newtonsoft.json":{"type":"Transitive","resolved":"1.0.0","contentHash":"B"}}}}"#,
        );
        assert!(
            error.contains("newtonsoft.json@1.0.0: conflicting contentHash across lock targets"),
            "{error}"
        );

        let lock = parse_lock(
            r#"{"version":1,"dependencies":{
                "net9.0":{
                    "Zeta":{"type":"Direct","resolved":"2.0.0","contentHash":"Z"},
                    "Alpha":{"type":"Transitive","resolved":"1.0.0","contentHash":"A"}},
                "net9.0/linux-x64":{
                    "alpha":{"type":"Transitive","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        assert_eq!(lock.targets, ["net9.0", "net9.0/linux-x64"]);
        let packages: Vec<_> = lock
            .packages
            .iter()
            .map(|p| (p.id.as_str(), p.version.as_str(), p.content_hash.as_str()))
            .collect();
        assert_eq!(packages, [("Alpha", "1.0.0", "A"), ("Zeta", "2.0.0", "Z")]);
    }

    /// Validate one csproj body in a fresh project directory.
    fn csproj_verdict(body: &str) -> io::Result<()> {
        let scratch = TempDir::named("dn-csproj");
        fs::write(scratch.0.join("p.csproj"), body).unwrap();
        validate_csproj(
            &ProjectRoot::open(&scratch.0).unwrap(),
            Path::new("p.csproj"),
        )
    }

    fn in_project(inner: &str) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>{inner}</PropertyGroup></Project>"
        )
    }

    /// Blocked names match whole element names outside comments, so a
    /// longer property that merely contains one is a valid project.
    #[test]
    fn csproj_markers_match_whole_element_names() {
        for accepted in [
            in_project(
                "<AppendTargetFrameworkToOutputPath>false</AppendTargetFrameworkToOutputPath>",
            ),
            in_project(
                "<AppendRuntimeIdentifierToOutputPath>false</AppendRuntimeIdentifierToOutputPath>",
            ),
            in_project("<!-- <OutputPath>bin/elsewhere</OutputPath> -->"),
            in_project("<!-- an Import, a ProjectReference and a UsingTask -->"),
            in_project("<Description>$(OutputPath) is where it lands</Description>"),
            in_project("<OutDirSuffix>x</OutDirSuffix>"),
            in_project("<PublishDirName>x</PublishDirName>"),
            "<!-- lead --><Project Sdk=\"Microsoft.NET.Sdk\"><!-- Sdk=\"Other\" --></Project>"
                .into(),
            in_project("<![CDATA[<OutputPath>]]>"),
            // Output-only properties that stay inside the project.
            in_project("<OutputPath>bin/elsewhere</OutputPath>"),
            in_project("<OutputPath Condition=\"'$(Configuration)' == 'Release'\">x</OutputPath>"),
            in_project("<OutputPath\n>x</OutputPath>"),
            in_project("<OutputPath/>"),
            in_project("<outputpath>x</outputpath>"),
            in_project("<OUTPUTPATH>out\\x</OUTPUTPATH>"),
            in_project("<BaseOutputPath>x/../y</BaseOutputPath>"),
            in_project("<OutDir>$(MSBuildProjectDirectory)/out</OutDir>"),
            in_project("<PublishDir Condition=\"true\">$(SolutionDir)publish/</PublishDir>"),
            // Imports, project references and the bundled SDK family.
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../o/o.csproj\" /></ItemGroup></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><import Project=\"shared.targets\" /></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>".into(),
            "<Project><Sdk Name=\"Microsoft.NET.Sdk.Razor\" /></Project>".into(),
        ] {
            assert!(csproj_verdict(&accepted).is_ok(), "{accepted}");
        }
        for refused in [
            in_project("<OutputPath>/elsewhere</OutputPath>"),
            in_project("<OutputPath>../elsewhere</OutputPath>"),
            in_project("<OutDir>x/../../elsewhere</OutDir>"),
            in_project("<BaseOutputPath>C:\\out</BaseOutputPath>"),
            in_project("<PublishDir>~/out</PublishDir>"),
            in_project("<PublishDir>$(Home)/out</PublishDir>"),
            in_project("<OutDir>$(MSBuildProjectDirectory)/../out</OutDir>"),
            in_project("<IntermediateOutputPath>x</IntermediateOutputPath>"),
            in_project("<BaseIntermediateOutputPath>x</BaseIntermediateOutputPath>"),
            in_project("<MSBuildProjectExtensionsPath>x</MSBuildProjectExtensionsPath>"),
            in_project("<RestoreSources>https://evil</RestoreSources>"),
            in_project("<RestorePackagesPath>x</RestorePackagesPath>"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><PackageDownload Include=\"X\" Version=\"[1.0.0]\" /></ItemGroup></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><UsingTask TaskName=\"T\" AssemblyFile=\"t.dll\" /></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk;Other.Sdk/1.0\"></Project>".into(),
            "<Project><Sdk Name=\"Other.Sdk\" Version=\"1.0\" /></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Import Project=\"x.props\" Sdk=\"Other.Sdk\" /></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\" TreatAsLocalProperty=\"OutputPath\"></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Target Name=\"T\"><CreateItem Include=\"X\"><Output TaskParameter=\"Include\" ItemName=\"PackageDownload\" /></CreateItem></Target></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Target Name=\"T\"><CreateProperty Value=\"x\"><Output TaskParameter=\"Value\" PropertyName=\"RestoreSources\" /></CreateProperty></Target></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><!-- open".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><![CDATA[ open</Project>".into(),
            "<Project Sdk=\"Other.Sdk\"></Project>".into(),
        ] {
            assert!(csproj_verdict(&refused).is_err(), "{refused}");
        }
    }

    /// A project read through a held root keeps reading the original
    /// directory after it is renamed and another project takes its path.
    #[test]
    fn preflight_reads_the_held_project_after_a_rename() {
        let scratch = TempDir::named("dn-held");
        let base = scratch.0.clone();
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("original.csproj"), minimal_csproj()).unwrap();
        fs::write(
            project.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        let root = ProjectRoot::open(&project).unwrap();

        fs::rename(&project, base.join("moved")).unwrap();
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("replacement.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><UsingTask TaskName=\"Evil\" /></Project>",
        )
        .unwrap();
        fs::write(
            project.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"Project","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();

        assert_eq!(
            solution::discover(&root).unwrap().members,
            [PathBuf::from("original.csproj")]
        );
        let members = preflight(&root, SDK_VERSION).unwrap().layout.members;
        assert_eq!(members, [PathBuf::from("original.csproj")]);
        // The replacement at the old path is what a path read would see.
        assert!(preflight(&ProjectRoot::open(&project).unwrap(), SDK_VERSION).is_err());
    }

    #[test]
    fn sdk_extraction_requires_muxer_at_object_root() {
        let scratch = TempDir::named("dn-extract");
        let base = scratch.0.clone();

        let root = base.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("dotnet"), b"muxer").unwrap();
        let archive = base.join("root.tar.gz");
        assert!(Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&root)
            .arg("dotnet")
            .status()
            .unwrap()
            .success());
        let stage = base.join("stage");
        fs::create_dir(&stage).unwrap();
        extract_sdk_archive(&archive, &stage).unwrap();
        assert!(stage.join("dotnet").is_file());

        let nested_root = base.join("nested-root");
        fs::create_dir_all(nested_root.join("nested")).unwrap();
        fs::write(nested_root.join("nested/dotnet"), b"muxer").unwrap();
        let nested_archive = base.join("nested.tar.gz");
        assert!(Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&nested_archive)
            .args(["-C"])
            .arg(&nested_root)
            .arg("nested")
            .status()
            .unwrap()
            .success());
        let nested_stage = base.join("nested-stage");
        fs::create_dir(&nested_stage).unwrap();
        let error = extract_sdk_archive(&nested_archive, &nested_stage)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unexpected layout"), "{error}");
    }

    #[test]
    fn output_roots_reject_symlinks_and_metadata_source_is_fixed() {
        let scratch = TempDir::named("dn-output");
        let base = scratch.0.clone();
        let outside = base.join("outside");
        fs::create_dir(&outside).unwrap();
        let project = base.join("project");
        fs::create_dir(&project).unwrap();
        symlink(&outside, project.join("bin")).unwrap();
        assert!(checked_output_dir(&ProjectRoot::open(&project).unwrap(), "fp").is_err());

        let project = base.join("project2");
        fs::create_dir_all(project.join("bin")).unwrap();
        symlink(&outside, project.join("bin/greyward-fp")).unwrap();
        assert!(checked_output_dir(&ProjectRoot::open(&project).unwrap(), "fp").is_err());

        // The project renamed away and a symlink to another directory put
        // at its path after the root was opened (#497): the output would
        // land outside the held path, so it is refused, and the directory
        // the symlink points at gets no `bin`.
        let project = base.join("project3");
        fs::create_dir_all(project.join("bin")).unwrap();
        let project = project.canonicalize().unwrap();
        let held = ProjectRoot::open(&project).unwrap();
        fs::rename(&project, base.join("project3-moved")).unwrap();
        let swapped = base.join("swapped");
        fs::create_dir(&swapped).unwrap();
        symlink(&swapped, &project).unwrap();
        assert!(checked_output_dir(&held, "fp").is_err());
        assert!(fs::read_dir(&swapped).unwrap().next().is_none());

        let metadata = base.join(".nupkg.metadata");
        fs::write(&metadata, r#"{"source":"/tmp/feed","version":2}"#).unwrap();
        rewrite_metadata_source(&metadata).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(metadata).unwrap()).unwrap();
        assert_eq!(value["source"], "greyward-feed");

        let publish_project = base.join("publish-project");
        fs::create_dir_all(publish_project.join("bin")).unwrap();
        let publish_project = ProjectRoot::open(&publish_project).unwrap();
        let staged_old = base.join("staged-old");
        fs::create_dir(&staged_old).unwrap();
        fs::write(staged_old.join("artifact"), "old").unwrap();
        let output = publish_output(
            &staged_old,
            &publish_project,
            Platform::Aarch64AppleDarwin,
            "fp",
            None,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(output.join("artifact")).unwrap(), "old");

        let staged_new = base.join("staged-new");
        fs::create_dir(&staged_new).unwrap();
        fs::write(staged_new.join("artifact"), "new").unwrap();
        publish_output(
            &staged_new,
            &publish_project,
            Platform::Aarch64AppleDarwin,
            "fp",
            None,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(output.join("artifact")).unwrap(), "new");
        let leftovers: Vec<_> = fs::read_dir(output.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".greyward-fp."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
