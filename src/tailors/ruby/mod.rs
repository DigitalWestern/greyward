//! The Ruby tailor: Bundler-delegated planning, greyward-verified gems,
//! immutable GEM_HOME objects, sandboxed native-extension installs.
//!
//! Platform selection and lock parsing are DELEGATED to the pinned Ruby's
//! own Bundler/RubyGems (a helper script —
//! Gem::Platform matching has wildcards and specificity scores no hand
//! parser should reimplement), while every artifact byte is still pinned
//! and verified by ward. Bundler's local .bundle/config outranks plain
//! env vars, so every greyward-controlled invocation scrubs BUNDLE_*/RUBY*
//! preload vars and sets BUNDLE_IGNORE_CONFIG=1.

mod bundler;
mod door;
pub mod edit;
mod gem_home;
mod helper;
mod locked;
mod native;
mod native_libs;
pub mod objects;
pub(crate) mod registry;
mod resolve;
mod sources;
pub mod tailor;
mod unpack;
pub use bundler::RubyBundler;
pub use sources::{RubyGitGem, RubyPathGem};

use helper::HELPER;

pub(crate) use door::ruby_tool;
pub use resolve::{attest_project, generate_lock};

use unpack::extract_ruby_bottle;
#[cfg(test)]
use unpack::extract_ruby_bottle_for_test;

use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Algo;
use crate::kernel::fetch::{
    download_toolchain_artifact_held, download_verified_held, hash_file, CacheLease, Digest,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DelegateSpec, ResolutionDoor};
use crate::kernel::sandbox::{BuildSpec, HostView};
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{ArtifactRow, Catalog, Selected};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use native::{
    cached_gems_object, record_host_fallback, ruby_gems_fallback_identity, same_host_state,
    GemInstall, RUNTIME_ONLY_VIEW,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// Homebrew portable-ruby: relocatable, bundler included; the ruby Homebrew
// itself ships on. The catalog holds every portable build of the ruby-lang
// lines still maintained (ruby-lang source may be newer; documented gap
// until a newer portable build exists).
//
// Both 3.4.6 bottles were inspected: root `portable-ruby/3.4.6/`,
// no symlinks, `#!/bin/sh` wrappers that `exec "$bindir/ruby"` relative to
// $0, `--enable-load-relative` (RbConfig prefix follows the object path) and
// `--with-static-linked-ext` (openssl/zlib/yaml/ffi compiled into
// `bin/ruby`). The Linux binary's NEEDED set is glibc only; its RUNPATH still
// lists `/home/linuxbrew/...` build directories but nothing NEEDED lives
// there, so it is inert provenance (like `configure_args`) and is NOT
// rewritten: no staging repair, hence no relocation-recipe identity input.
// RubyGems reports `Gem::Platform.local` = `x86_64-linux` for that bottle,
// which is neither the bottle tag (`x86_64_linux`) nor the Rust triple; the
// plan records whatever the pinned interpreter says. The generator checks
// every bottle it adds for the same layout (one `portable-ruby/<tag>/` root,
// no link leaving it, the entries `validate_ruby_layout` requires).
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// The default Ruby's bottle for a platform: what a project with no Ruby
/// pin realizes there.
fn ruby_pin(platform: Platform) -> io::Result<&'static ArtifactRow> {
    CATALOG.default_row(platform, "ruby")
}

/// The shipped Ruby catalog: one release bundle per portable-ruby build,
/// generated and verified by `tools/catalog.py ruby`, and its default.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Ruby")?;
    ruby_pin(platform).map(|_| ())
}

/// The recipe this tailor knows how to build a Ruby object from. A lock
/// naming any other recipe was written by a ward that builds Ruby some other
/// way, and this one must not guess.
const RUBY_RECIPE: &str = "ruby-toolchain/1";

/// One Ruby realization's bytes, read from the selected toolchain rather
/// than from the compiled pin table: the same fields a pin carries, owned,
/// so a project's lock can supply them.
#[derive(Debug)]
struct RubySpec {
    platform: Platform,
    version: String,
    provider: String,
    url: String,
    sha256: String,
}

/// The selected Ruby's row for `platform`, refused unless this ward knows
/// the recipe that produced it.
fn ruby_spec(platform: Platform, selected: &Selected) -> io::Result<RubySpec> {
    selected.require("ruby", "ruby")?;
    let row = selected.checked_artifact(platform, "ruby", RUBY_RECIPE, "sha256")?;
    Ok(RubySpec {
        platform,
        version: row.version,
        provider: row.provider,
        url: row.url,
        sha256: row.digest.hex().to_string(),
    })
}

#[cfg(test)]
/// The shipped catalog's Ruby, for callers with no project selection to
/// honor. Inside a project every caller realizes from the lock instead.
fn shipped_selection() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

fn ruby_identity(spec: &RubySpec) -> Identity {
    Identity {
        kind: "ruby".into(),
        name: "ruby".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "ruby-toolchain/1".to_string()),
            ("artifact_sha256".to_string(), spec.sha256.clone()),
            ("platform".to_string(), spec.platform.triple().to_string()),
        ]),
    }
}

/// `native_libs_id` is the pinned native library set the plan's native
/// gems build with (`native_libs::identity_id`): Linux only.
fn ruby_gems_identity(spec: &RubySpec, plan: &RubyPlan, native_libs_id: Option<&str>) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "ruby-gems/1".to_string()),
        // Installer recipe AND wrapper-byte provenance: generated binstubs
        // embed interpreter paths.
        (
            "installer".to_string(),
            format!("ruby{}:{}", spec.version, spec.sha256),
        ),
        ("ruby_platform".to_string(), plan.ruby_platform.clone()),
    ]);
    // On Linux, native extensions compile against the host's C runtime
    // alone (`HostView::RuntimeOnly`; pure-Ruby gems compile nothing and
    // install against the full view), so the headers and libraries a build
    // sees are the same on every host with the same C runtime. A gem that
    // needs more falls back to the whole host, records `host-build-inputs`,
    // and the object is committed under `ruby_gems_fallback_identity`
    // instead, never under this id. Darwin builds see the whole SDK, and
    // their ids are pinned.
    //
    // Linux native gems also build with ward's pinned native library set
    // mounted (`native_libs`, #329). `native` spells out that decision
    // either way, so a dropped `native_libs` input cannot pass for a plan
    // with no native gem.
    if !spec.platform.is_macos() {
        inputs.insert("build_view".to_string(), RUNTIME_ONLY_VIEW.to_string());
        let native = match native_libs_id {
            Some(id) => {
                inputs.insert("native_libs".to_string(), id.to_string());
                native_libs::NATIVE_LIBS_MOUNTED
            }
            None => native_libs::NATIVE_NONE,
        };
        inputs.insert("native".to_string(), native.to_string());
    }
    for g in &plan.gems {
        inputs.insert(format!("gem:{}", g.full_name), g.sha256.clone());
    }
    // A git gem's tree is installed into the object, so its source and
    // commit are inputs. A plan with none keeps the id it always had.
    // Keyed by checkout directory, the name a host fallback records it
    // under; the value names every lock source read from that directory.
    for checkout in sources::checkouts(&plan.git_gems) {
        inputs.insert(format!("git:{}", checkout.name), checkout.identity_input());
    }
    // A provisioned Bundler (`bundler`); a plan on the store Ruby's own
    // keeps the id it always had.
    if let Some(bundler) = &plan.bundler {
        inputs.insert("bundler".to_string(), bundler.identity_input());
    }
    Identity {
        kind: "ruby-gems".into(),
        name: "gems".into(),
        version: plan.gems.len().to_string(),
        inputs,
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn required_entry(root: &Path, relative: &str) -> io::Result<()> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("portable-ruby is missing {relative}: {e}"),
        )
    })?;
    if !metadata.is_file() && !metadata.file_type().is_symlink() {
        return Err(err(format!(
            "portable-ruby path is not a file: {}",
            path.display()
        )));
    }
    if metadata.file_type().is_symlink() {
        let root = root.canonicalize()?;
        let resolved = path.canonicalize().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("portable-ruby has dangling symlink {}: {e}", path.display()),
            )
        })?;
        if !resolved.starts_with(&root) {
            return Err(err(format!(
                "portable-ruby symlink escapes the object: {} -> {}",
                path.display(),
                resolved.display()
            )));
        }
        if !resolved.is_file() {
            return Err(err(format!(
                "portable-ruby symlink does not resolve to a file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn find_file(root: &Path, wanted: &dyn Fn(&Path) -> bool) -> io::Result<Option<PathBuf>> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Ok(None);
    }
    if metadata.is_file() {
        return Ok(wanted(root).then(|| root.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Ok(None);
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if let Some(found) = find_file(&path, wanted)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn validate_ruby_layout(root: &Path) -> io::Result<()> {
    required_entry(root, "bin/ruby")?;
    required_entry(root, "bin/gem")?;

    let bin = root.join("bin");
    let bundle = find_file(&bin, &|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "bundle" || name == "bundler" || name.starts_with("bundle"))
    })?;
    if bundle.is_none() {
        return Err(err(format!(
            "portable-ruby is missing a Bundler launcher under {}",
            bin.display()
        )));
    }

    let library = find_file(&root.join("lib"), &|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("libruby"))
    })?;
    if library.is_none() {
        return Err(err("portable-ruby is missing its Ruby runtime library"));
    }

    let header = find_file(&root.join("include"), &|path| {
        path.file_name().and_then(|name| name.to_str()) == Some("ruby.h")
    })?;
    if header.is_none() {
        return Err(err("portable-ruby is missing interpreter headers"));
    }
    Ok(())
}

/// Realize the Ruby the selection names: its bytes, its version, its
/// digest. A catalog refresh cannot move a project's interpreter, because
/// nothing here reads the pin table.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Ruby")?;
    let spec = ruby_spec(platform, selected)?;
    let identity = ruby_identity(&spec);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_toolchain_artifact_held(
        store,
        activity,
        &spec.provider,
        &spec.url,
        &Digest::sha256(&spec.sha256)?,
    )?;
    let staged = store.stage_with_activity(activity)?;
    if let Err(error) = extract_ruby_bottle(activity, &tarball, &staged) {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(&spec.sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

/// The forced environment for EVERY greyward-controlled ruby/bundler run.
/// Removal lists close the .bundle/config and preload side doors; they live
/// with the host-local tripwire, which checks the `spec` read by them.
const ENV_REMOVE_PREFIXES: &[&str] = crate::kernel::resolve::tripwire::RUBY_ENV_REMOVE_PREFIXES;
const ENV_REMOVE: &[&str] = crate::kernel::resolve::tripwire::RUBY_ENV_REMOVE;

/// The Gemfile and its lock as ward's delegates name them: relative to the
/// held project directory they start in.
const GEMFILE: &str = "Gemfile";
const GEMFILE_LOCK: &str = "Gemfile.lock";

/// Where Bundler reads git checkouts from, under GEM_HOME.
const GIT_CHECKOUTS: &str = "bundler/gems";

/// The gem environment every store Ruby run shares: `gem_home` is the one
/// gem path, so neither the host's `~/.gem` nor its `GEM_PATH` is searched.
fn gem_env(gem_home: &Path) -> Vec<(String, String)> {
    vec![
        ("GEM_HOME".to_string(), gem_home.display().to_string()),
        ("GEM_PATH".to_string(), gem_home.display().to_string()),
        // Unsetting GEMRC would re-enable ~/.gemrc; point it at an empty
        // config instead (system /etc/gemrc remains a documented impurity).
        ("GEMRC".to_string(), "/dev/null".to_string()),
    ]
}

/// The environment every store Ruby tool runs with. `gemfile` is what
/// Bundler reads: ward's own delegates start inside the held project
/// directory and name it relatively, so a directory swapped in at the
/// project's path is never the one evaluated (#499).
fn forced_env(gemfile: &str, gem_home: &Path) -> Vec<(String, String)> {
    let mut env = gem_env(gem_home);
    env.extend([
        ("BUNDLE_IGNORE_CONFIG".to_string(), "1".to_string()),
        ("BUNDLE_GEMFILE".to_string(), gemfile.to_string()),
        ("BUNDLE_FROZEN".to_string(), "true".to_string()),
        ("BUNDLE_DISABLE_SHARED_GEMS".to_string(), "true".to_string()),
        ("BUNDLE_AUTO_INSTALL".to_string(), "false".to_string()),
        (
            "BUNDLE_DISABLE_VERSION_CHECK".to_string(),
            "true".to_string(),
        ),
    ]);
    env
}

/// Env for a lone script (`ward app.rb` with no Ruby project): the same
/// scrub as [`run_env`], with an empty `gem_home` in place of a gems
/// object, so the script sees the interpreter and its default gems only.
pub fn lone_env(gem_home: &Path) -> crate::tailors::EnvScrub {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        gem_env(gem_home),
    )
}

/// Env applied by `ward run` for a projected ruby environment. The user's
/// command may start in a subdirectory and still needs the root Gemfile,
/// so here it is named by its full path.
pub fn run_env(
    project_dir: &Path,
    gems_obj: &Path,
) -> (Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>) {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        forced_env(&project_dir.join(GEMFILE).display().to_string(), gems_obj),
    )
}

/// The helper's `spec` mode over a `.gem` ward already verified: it reads
/// the embedded gemspec and needs no network, so it runs as a host-local
/// helper rather than through the door.
fn read_gem_spec(
    activity: &StoreActivity,
    ruby_obj: &Path,
    cwd: &Path,
    gem_home: &Path,
    args: &[&str],
) -> io::Result<std::process::Output> {
    let mut cmd = gem_spec_command(ruby_obj, cwd, gem_home, args);
    crate::kernel::supervise::local_output(&mut cmd, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store ruby {args:?}: {e}")))
}

/// The command `read_gem_spec` starts: the forced environment, with `HOME`
/// in `cwd` so no user `.gemrc` or `.gem` directory is read.
fn gem_spec_command(
    ruby_obj: &Path,
    cwd: &Path,
    gem_home: &Path,
    args: &[&str],
) -> std::process::Command {
    let mut spec = ruby_tool_spec(ruby_obj, cwd, args, &forced_env(GEMFILE, gem_home));
    spec.env("HOME", cwd);
    spec.command()
}

/// The store Ruby tool `args[0]` with ward's forced environment, its output
/// captured.
fn ruby_tool_spec(
    ruby_obj: &Path,
    cwd: &Path,
    args: &[&str],
    environment: &[(String, String)],
) -> DelegateSpec {
    let mut spec = DelegateSpec::new(ruby_obj.join(format!("bin/{}", args[0])));
    spec.args(&args[1..]).lock_root(cwd);
    // Ruby FIRST on PATH: a gem executable named ruby/gem must never shadow.
    // A store path holds no ':' (`Store::open` refuses one), so the join
    // cannot fail; an unset host PATH adds no current-directory entry.
    let path = crate::kernel::platform::child_path(&[ruby_obj.join("bin")])
        .expect("a store path holds no ':'");
    spec.env("PATH", path);
    spec.force_env(ENV_REMOVE_PREFIXES, ENV_REMOVE, environment);
    spec.capture();
    spec
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RubyGem {
    pub name: String,
    pub version: String,
    pub platform: String,
    pub full_name: String,
    pub sha256: String,
    /// The digest came from the rubygems.org API on this plan, so once the
    /// downloaded bytes match it, it is worth recording in the store.
    /// Planning state only: never serialized, so closures and object
    /// identities are unchanged by it.
    #[serde(skip)]
    pub digest_from_api: bool,
    /// The lock's CHECKSUMS section pinned `sha256`. Without one the digest
    /// is rubygems.org's answer (now, or as the store recorded it), and the
    /// sync records `unpinned-digest` for the gem. Planning state only,
    /// like `digest_from_api`.
    #[serde(skip)]
    pub digest_in_lock: bool,
}

/// Record `unpinned-digest` for each gem in `plan` whose digest the lock
/// did not pin, through `record` (the sync's attribution). A policy that
/// denies the kind refuses the sync until the lock carries a CHECKSUMS
/// section (`bundle lock --add-checksums`).
pub(crate) fn record_unpinned_digests(
    plan: &RubyPlan,
    record: impl Fn(&str, &str, &str) -> io::Result<()>,
) -> io::Result<()> {
    for gem in plan.gems.iter().filter(|gem| !gem.digest_in_lock) {
        record(
            crate::kernel::policy::UNPINNED_DIGEST,
            &gem.full_name,
            "Gemfile.lock has no CHECKSUMS entry for it, so its sha256 is the one rubygems.org \
             served; `bundle lock --add-checksums` pins it in the lock",
        )?;
    }
    Ok(())
}

/// Record `git-dependency` for each git gem in `plan`, and
/// `host-git-transport` for one fetched over ssh, git:// or a local path,
/// into the sync's attribution, before anything is fetched.
pub(crate) fn record_git_dependencies(plan: &RubyPlan) -> io::Result<()> {
    sources::record_git_dependencies(&plan.git_gems)
}

/// The store record kind holding rubygems.org's sha256 for one gem
/// coordinate.
const GEM_DIGESTS: &str = "rubygems-sha256";

/// A gem coordinate as a store record key: a JSON array, so no name,
/// version or platform spelling can run into the next field.
fn gem_digest_key(name: &str, version: &str, platform: &str) -> String {
    serde_json::json!([name, version, platform]).to_string()
}

/// The sha256 rubygems.org serves for this (name, version, platform), as an
/// earlier sync recorded it, or `None` when none has.
///
/// This is store data, not project data, which is why it may stand in for
/// the API where a plan cache in the project may not. A file in the project
/// ships with the repository, so a cache there says whatever the repo's
/// author wrote, and its predictable key makes it forgeable authority over
/// which bytes get installed. The store is written only by ward on this
/// machine, and a record exists only because ward asked rubygems.org for
/// exactly this coordinate's digest, downloaded
/// `rubygems.org/downloads/<full_name>.gem`, and found that the bytes hash
/// to that digest and their embedded gemspec names this coordinate.
/// rubygems.org never republishes a version, so the answer does not go
/// stale. A digest from a lock's CHECKSUMS section is never recorded: that
/// is the repository's claim, not rubygems.org's.
fn recorded_gem_digest(
    store: &Store,
    name: &str,
    version: &str,
    platform: &str,
) -> io::Result<Option<String>> {
    let value = store.read_record(GEM_DIGESTS, &gem_digest_key(name, version, platform))?;
    Ok(value
        .and_then(|value| value["sha256"].as_str().map(str::to_string))
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Record a digest the API gave for `gem` once its bytes have been checked
/// against it. A failed write costs the next sync one API call and nothing
/// else, so it is reported and the sync goes on.
fn record_gem_digest(store: &Store, activity: &StoreActivity, gem: &RubyGem) {
    let key = gem_digest_key(&gem.name, &gem.version, &gem.platform);
    let value = serde_json::json!({"sha256": gem.sha256});
    if let Err(error) = store.write_record(activity, GEM_DIGESTS, &key, &value) {
        ui::note(&format!(
            "{}: rubygems.org digest not recorded in the store ({error}); \
             the next sync asks rubygems.org again",
            gem.full_name
        ));
    }
}

/// Where a planned gem's `.gem` is fetched from. rubygems.org is the only
/// source the plan validator admits, so this is the single spelling of that
/// URL rather than a per-gem field.
fn gem_url(gem: &RubyGem) -> String {
    format!("https://rubygems.org/downloads/{}.gem", gem.full_name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RubyPlan {
    pub ruby_version: String,
    pub ruby_platform: String,
    pub bundler_version: String,
    pub gems: Vec<RubyGem>,
    /// Gems the lock takes from a `PATH` source inside the project. Bundler
    /// loads them from the project at run time, so they add nothing to the
    /// gems object and are not part of its identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_gems: Vec<RubyPathGem>,
    /// Gems the lock takes from a `GIT` source at a locked commit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_gems: Vec<RubyGitGem>,
    /// The Bundler `BUNDLED WITH` names, when it is newer than the store
    /// Ruby's own and ward provisioned it (`bundler`). `bundler_version` is
    /// then this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundler: Option<RubyBundler>,
}

fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !s.starts_with('.')
}

/// A gem's name, version, platform and full name, each one safe to place in
/// a URL path or query and in a store path.
fn valid_coordinates(name: &str, version: &str, platform: &str, full_name: &str) -> bool {
    valid_component(name)
        && valid_component(version)
        && (platform == "ruby" || valid_component(platform))
        && valid_component(full_name)
}

fn validate_plan(plan: &RubyPlan) -> io::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for g in &plan.gems {
        if !valid_coordinates(&g.name, &g.version, &g.platform, &g.full_name) {
            return Err(err(format!("invalid gem coordinates in plan: {g:?}")));
        }
        if g.sha256.len() != 64 || !g.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err(format!("{}: invalid sha256 in plan", g.full_name)));
        }
        if !seen.insert(g.name.clone()) {
            return Err(err(format!("duplicate gem {} in plan", g.name)));
        }
    }
    let others = plan
        .path_gems
        .iter()
        .map(|g| (&g.name, &g.version))
        .chain(plan.git_gems.iter().map(|g| (&g.name, &g.version)));
    for (name, version) in others {
        if !valid_component(name) || !valid_component(version) {
            return Err(err(format!(
                "invalid gem coordinates in plan: {name} {version}"
            )));
        }
        if !seen.insert(name.clone()) {
            return Err(err(format!("duplicate gem {name} in plan")));
        }
    }
    for g in &plan.git_gems {
        sources::check_git_gem(g)?;
    }
    sources::check_checkouts(&plan.git_gems)
}

/// The project's Gemfile.lock text, read through the held descriptor so a
/// project directory renamed or replaced mid-sync cannot substitute another
/// project's lock. Absent reads as NotFound, as the path read reported it.
fn read_gemfile_lock(project: &ProjectRoot) -> io::Result<String> {
    project
        .read_input_string(Path::new("Gemfile.lock"))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{}: not found",
                    project.path().join("Gemfile.lock").display()
                ),
            )
        })
}

/// The lock every plan reads, or the refusal that names it: `prepare`
/// generates it, and the command layer skips `prepare` under `--frozen`.
/// Checked before any toolchain is realized, so a frozen sync of an
/// unlocked project fails without a download.
pub fn require_lock(project: &ProjectRoot) -> io::Result<()> {
    if project.is_input_file(Path::new("Gemfile.lock")) {
        Ok(())
    } else {
        Err(crate::tailors::missing_lock(project, "Gemfile.lock"))
    }
}

/// Plan the gem closure: Bundler-delegated lock parsing + platform
/// selection, greyward-pinned hashes (lock CHECKSUMS section when present, else
/// the digest an earlier sync verified and recorded in the store, else the
/// rubygems.org v2 API). The plan itself is never cached: every sync
/// re-derives it from the lock. The project is read through the held
/// descriptor; its path is only the store Ruby's working directory and
/// arguments.
pub fn plan_ruby(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<(RubyPlan, String, crate::comforter::join::Digests)> {
    if !project.is_input_file(Path::new("Gemfile")) {
        return Err(err("Gemfile not found"));
    }
    let observed = project.observing_inputs()?;
    let project = &observed;
    require_lock(project)?;
    let basis = resolve::resolution_basis(project)?;
    let lock = read_gemfile_lock(project)?;
    // No plan cache in the project: an editable cache with a predictable
    // key is forgeable authority. Planning re-derives from the lock every
    // sync; the store's digest records keep an unchanged lock off the
    // network, and its object cache makes realizes instant.

    // The Bundler the lock was written with, when the store Ruby's own is
    // older: both gates read the lock with it.
    let bundler = bundler::locked_bundler(door, ruby_obj, selected, &lock)?;
    // Both gates run confined with no route: full network denial.
    let mut gate = |mode| {
        resolve::helper(
            door,
            project,
            ruby_obj,
            mode,
            Some(&basis),
            bundler.as_ref(),
        )
    };
    // Gate 1: Gemfile/lock equivalence + ruby directive. EVALS THE GEMFILE
    // (delegated resolver trust) — exit status only, stdout untrusted.
    let out = gate("check")?;
    if !out.status.success() {
        return Err(err(format!(
            "Gemfile/Gemfile.lock validation failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    // Gate 2: LOCK-ONLY closure derivation (never evaluates the Gemfile).
    let out = gate("plan")?;
    if !out.status.success() {
        return Err(err(format!(
            "bundler lock analysis failed: {}{}",
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        )));
    }
    #[derive(Deserialize)]
    struct HelperGem {
        name: String,
        version: String,
        platform: String,
        full_name: String,
        checksum: Option<String>,
    }
    #[derive(Deserialize)]
    struct HelperOut {
        ruby_platform: String,
        bundler: String,
        gems: Vec<HelperGem>,
        #[serde(default)]
        path_gems: Vec<RubyPathGem>,
        #[serde(default)]
        git_gems: Vec<RubyGitGem>,
    }
    let parsed: HelperOut =
        serde_json::from_slice(&out.stdout).map_err(|e| err(format!("helper output: {e}")))?;
    for gem in &parsed.path_gems {
        sources::check_path_gem(project, gem)?;
    }

    let store = door.store();
    let mut gems = Vec::new();
    for g in parsed.gems {
        // Checked before any of them is placed in a rubygems.org URL: a
        // lock entry such as `x?platform=java` would otherwise choose the
        // query the digest is asked with.
        if !valid_coordinates(&g.name, &g.version, &g.platform, &g.full_name) {
            return Err(err(format!(
                "invalid gem coordinates in Gemfile.lock: {} {} {}",
                g.name, g.version, g.platform
            )));
        }
        let mut digest_from_api = false;
        let digest_in_lock = g.checksum.is_some();
        let recorded = match g.checksum {
            Some(_) => None,
            None => recorded_gem_digest(store, &g.name, &g.version, &g.platform)?,
        };
        let sha256 = match (g.checksum, recorded) {
            (Some(c), _) => c,
            (None, Some(recorded)) => recorded,
            (None, None) => {
                digest_from_api = true;
                // ALWAYS platform-qualified: the bare endpoint returns the
                // latest-PUSHED variant (racc 1.8.1 returns the java gem's
                // sha!). Validate the reply's platform too.
                let url = format!(
                    "https://rubygems.org/api/v2/rubygems/{}/versions/{}.json?platform={}",
                    g.name, g.version, g.platform
                );
                let body = crate::kernel::fetch::fetch_text(&url)
                    .map_err(|e| err(format!("{}: {e}", g.full_name)))?;
                digest_from_api_reply(&g.full_name, &g.version, &g.platform, &body)?
            }
        };
        gems.push(RubyGem {
            name: g.name,
            version: g.version,
            platform: g.platform,
            full_name: g.full_name,
            sha256,
            digest_from_api,
            digest_in_lock,
        });
    }
    bundler::check_reader(bundler.as_ref(), &parsed.bundler)?;
    let plan = RubyPlan {
        // The interpreter this plan was made under is the selected one, so
        // the plan records the selection's version, never the shipped pin.
        ruby_version: selected.version("ruby")?.to_string(),
        ruby_platform: parsed.ruby_platform,
        bundler_version: parsed.bundler,
        gems,
        path_gems: parsed.path_gems,
        git_gems: parsed.git_gems,
        bundler: bundler.map(|bundler| bundler.pin),
    };
    validate_plan(&plan)?;
    // Snapshot guard: the lock this plan derives from is the lock whose
    // digest provenance will record (Go precedent).
    let now = read_gemfile_lock(project)?;
    if now != lock {
        return Err(err("Gemfile.lock changed while planning; re-run 'ward'"));
    }
    // The resolution files this plan was built from, so the resolution
    // join binds a record to this generation of the Gemfile and its lock.
    project.verify_observed_inputs()?;
    if resolve::resolution_basis(project)? != basis {
        return Err(err(
            "Ruby resolution inputs changed while planning; run `ward` again",
        ));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes())), basis))
}

/// The sha256 in one rubygems.org version reply, once the reply is shown to
/// describe the coordinate that was asked for. The bare endpoint answers
/// with whichever variant was pushed last, so a reply naming another
/// version or platform is refused rather than trusted for its digest.
fn digest_from_api_reply(
    full_name: &str,
    version: &str,
    platform: &str,
    body: &str,
) -> io::Result<String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| err(format!("{full_name}: api json: {e}")))?;
    if v["number"].as_str() != Some(version) || v["platform"].as_str() != Some(platform) {
        return Err(err(format!(
            "{}: api returned {}-{} instead",
            full_name, v["number"], v["platform"]
        )));
    }
    Ok(v["sha"]
        .as_str()
        .ok_or_else(|| err(format!("{full_name}: api has no sha")))?
        .to_string())
}

/// Check that the gemspec the helper read out of a downloaded `.gem` names
/// exactly the planned coordinate, and that the plan's `full_name` is the
/// canonical spelling of that coordinate (the download URL is built from
/// it). Returns the gem's executables and whether it declares native
/// extensions.
fn spec_matches_plan(g: &RubyGem, spec_json: &[u8]) -> io::Result<(Vec<String>, bool)> {
    let spec: serde_json::Value = serde_json::from_slice(spec_json)
        .map_err(|e| err(format!("{}: spec json: {e}", g.full_name)))?;
    let canonical = if g.platform == "ruby" {
        format!("{}-{}", g.name, g.version)
    } else {
        format!("{}-{}-{}", g.name, g.version, g.platform)
    };
    if spec["name"].as_str() != Some(g.name.as_str())
        || spec["version"].as_str() != Some(g.version.as_str())
        || spec["platform"].as_str() != Some(g.platform.as_str())
        || g.full_name != canonical
    {
        return Err(err(format!(
            "{}: embedded gemspec disagrees with the plan ({} {} {})",
            g.full_name, spec["name"], spec["version"], spec["platform"]
        )));
    }
    let executables = spec["executables"]
        .as_array()
        .map(|exes| {
            exes.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // A spec that does not say is treated as native: the hermetic build is
    // the safe side of the choice `install_gem` makes.
    let native = spec["extensions"]
        .as_array()
        .is_none_or(|extensions| !extensions.is_empty());
    Ok((executables, native))
}

/// Fetch one planned gem into the artifact cache, or find it there, verified
/// against the plan's sha256, then check that its embedded gemspec names
/// exactly the planned coordinate. Returns the cache lease, which keeps the
/// `.gem` from being swept while it is held, the gem's executables, and
/// whether its gemspec declares native extensions.
fn verify_gem(
    store: &Store,
    activity: &StoreActivity,
    ruby_obj: &Path,
    scratch: &Path,
    helper: &Path,
    g: &RubyGem,
) -> io::Result<(CacheLease, Vec<String>, bool)> {
    let url = gem_url(g);
    let lease = download_verified_held(store, activity, &url, &g.sha256)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", g.full_name)))?;
    let (executables, native) =
        read_gem_spec_checked(activity, ruby_obj, scratch, helper, g, &lease)?;
    Ok((lease, executables, native))
}

/// Read the gemspec embedded in the verified `.gem` at `gem_file` and check
/// it names exactly `g` (`spec_matches_plan`): its executables, and
/// whether it declares native extensions.
fn read_gem_spec_checked(
    activity: &StoreActivity,
    ruby_obj: &Path,
    scratch: &Path,
    helper: &Path,
    g: &RubyGem,
    gem_file: &Path,
) -> io::Result<(Vec<String>, bool)> {
    let out = read_gem_spec(
        activity,
        ruby_obj,
        scratch,
        scratch,
        &[
            "ruby",
            helper
                .to_str()
                .ok_or_else(|| err("helper path not UTF-8"))?,
            "spec",
            gem_file.to_str().ok_or_else(|| err("gem path not UTF-8"))?,
        ],
    )?;
    if !out.status.success() {
        return Err(err(format!(
            "{}: gemspec read failed: {}",
            g.full_name,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    spec_matches_plan(g, &out.stdout)
}

/// On an object hit, record the API digests this plan used. The object
/// shows that some earlier build checked these gems, but a record is only
/// ever written on a check made now: each gem is verified again from the
/// artifact cache (or downloaded, when the cache was swept) before its
/// digest is recorded. Best effort, like every record write.
fn record_api_digests_on_hit(
    store: &Store,
    activity: &StoreActivity,
    plan: &RubyPlan,
    ruby_obj: &Path,
) {
    let pending: Vec<&RubyGem> = plan.gems.iter().filter(|g| g.digest_from_api).collect();
    if pending.is_empty() {
        return;
    }
    let result = (|| -> io::Result<()> {
        let scratch = store.stage_with_activity(activity)?;
        let helper = scratch.join("helper.rb");
        let outcome = fs::write(&helper, HELPER).map(|()| {
            for g in pending {
                match verify_gem(store, activity, ruby_obj, &scratch, &helper, g) {
                    Ok(_) => record_gem_digest(store, activity, g),
                    Err(error) => ui::note(&format!(
                        "{}: rubygems.org digest not recorded in the store ({error}); \
                         the next sync asks rubygems.org again",
                        g.full_name
                    )),
                }
            }
        });
        let _ = crate::kernel::store::remove_tree(&scratch);
        outcome
    })();
    if let Err(error) = result {
        ui::note(&format!(
            "rubygems.org digests not recorded in the store ({error}); \
             the next sync asks rubygems.org again"
        ));
    }
}

/// Realize the immutable GEM_HOME object: dependency-first sandboxed
/// installs (native extensions compile here, network denied).
pub fn realize_gems(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &RubyPlan,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Ruby gems")?;
    let spec = ruby_spec(platform, selected)?;
    validate_plan(plan)?;
    // Fetch + post-download spec verification (all-or-nothing). It runs
    // before the cache lookup only when a gem's native classification is
    // not in the store yet: the identity names the native library set
    // exactly when the plan has a native gem (`native_libs`).
    let scratch = store.stage_with_activity(activity)?;
    let result = (|| {
        let helper = scratch.join("helper.rb");
        fs::write(&helper, HELPER)?;
        let mut verified = None;
        let has_native = match native_libs::persisted_classification(store, plan)? {
            Some(has_native) => has_native,
            None => {
                let gems = verify_plan(store, activity, ruby_obj, &scratch, &helper, plan)?;
                let has_native = gems.artifacts.iter().any(|(_, _, native)| *native);
                verified = Some(gems);
                has_native
            }
        };
        // A git checkout is built as a native gem is (`GemInstall::install_git`),
        // so a plan with one mounts the native library set too.
        let builds_native = |has_native: bool| has_native || !plan.git_gems.is_empty();
        let mut native_libs_id =
            native_libs::identity_id(store, platform, builds_native(has_native))?;
        let mut identity = ruby_gems_identity(&spec, plan, native_libs_id.as_deref());
        let cached = |identity: &Identity| -> io::Result<Option<PathBuf>> {
            let lookup_inputs = crate::kernel::hostview::host_build_inputs;
            match cached_gems_object(store, activity, identity, lookup_inputs)? {
                // An `object-meta/2` record a stricter policy cannot judge
                // is installed again under the same id.
                Some(id) if crate::kernel::policy::check_cached_reusable(store, activity, &id)? => {
                    Ok(Some(store.object_path(&id)))
                }
                _ => Ok(None),
            }
        };
        if let Some(path) = cached(&identity)? {
            record_api_digests_on_hit(store, activity, plan, ruby_obj);
            return Ok(path);
        }
        let verified = match verified {
            Some(verified) => verified,
            None => {
                let verified = verify_plan(store, activity, ruby_obj, &scratch, &helper, plan)?;
                // The identity above came from the store's records; the
                // gemspecs just read are the authority. When they disagree,
                // the records were wrong (`verify_plan` has rewritten them),
                // and the object is built and named by the gemspecs.
                if let Some(fresh) = stale_native_classification(has_native, &verified) {
                    ui::note(&format!(
                        "the store recorded that this plan {} a native gem, but its gemspecs \
                         say it {}; the record is corrected and the gemspecs decide",
                        if has_native { "has" } else { "has no" },
                        if fresh { "has" } else { "has not" },
                    ));
                    native_libs_id =
                        native_libs::identity_id(store, platform, builds_native(fresh))?;
                    identity = ruby_gems_identity(&spec, plan, native_libs_id.as_deref());
                    // `verify_plan` recorded this plan's API digests already.
                    if let Some(path) = cached(&identity)? {
                        return Ok(path);
                    }
                }
                verified
            }
        };
        let native_libs = match native_libs_id {
            Some(_) => Some(crate::kernel::provider::nativelibs::ensure_native_libs(
                store, activity, platform,
            )?),
            None => None,
        };
        install_gems(
            store,
            activity,
            platform,
            plan,
            ruby_obj,
            &identity,
            &GemsWork {
                scratch: &scratch,
                helper: &helper,
                verified,
                native_libs: native_libs.as_ref(),
            },
        )
    })();
    let _ = crate::kernel::store::remove_tree(&scratch);
    result
}

/// The verified `.gem` of every planned gem, with whether its gemspec
/// declares native extensions, and the cache leases that keep them.
struct VerifiedGems<'p> {
    artifacts: Vec<(&'p RubyGem, PathBuf, bool)>,
    _leases: Vec<CacheLease>,
    /// Each executable the gems provide, and the gem providing it: a git
    /// gem's executables are checked against these once it is installed.
    executables: BTreeMap<String, String>,
}

/// Claim the executables `gem` provides, refusing one another gem of the
/// plan already provides: two would write one wrapper in the bin dir.
fn claim_executables(
    claimed: &mut BTreeMap<String, String>,
    gem: &str,
    executables: impl IntoIterator<Item = String>,
) -> io::Result<()> {
    for e in executables {
        if let Some(prev) = claimed.insert(e.clone(), gem.to_string()) {
            return Err(err(format!(
                "executable {e:?} provided by both {prev} and {gem}; refusing \
                 ambiguous bin dir"
            )));
        }
    }
    Ok(())
}

/// Whether `verified`'s gemspecs say the plan has a native gem, when that
/// differs from `recorded`, the answer the store's classification records
/// gave; `None` when they agree.
fn stale_native_classification(recorded: bool, verified: &VerifiedGems<'_>) -> Option<bool> {
    let fresh = verified.artifacts.iter().any(|(_, _, native)| *native);
    (fresh != recorded).then_some(fresh)
}

/// Download and verify every gem of `plan`, refusing two gems that provide
/// one executable, and record each gem's native classification.
fn verify_plan<'p>(
    store: &Store,
    activity: &StoreActivity,
    ruby_obj: &Path,
    scratch: &Path,
    helper: &Path,
    plan: &'p RubyPlan,
) -> io::Result<VerifiedGems<'p>> {
    let mut artifacts: Vec<(&RubyGem, PathBuf, bool)> = Vec::new();
    // One download per gem, and the lease from that download is held through
    // the sandboxed installs below, so no sweep can drop a `.gem` between
    // verification and use. That is all the lease closes: a same-user
    // replacement of a cache entry is still possible, so the install loop
    // digests every artifact again immediately before it copies it.
    let mut leases = Vec::new();
    let mut executables: BTreeMap<String, String> = BTreeMap::new();
    for g in &plan.gems {
        let (lease, exes, native) = verify_gem(store, activity, ruby_obj, scratch, helper, g)?;
        let file_path = lease.to_path_buf();
        leases.push(lease);
        // The bytes rubygems.org serves match the digest its API gave and
        // name this coordinate: that is what a digest record vouches for.
        if g.digest_from_api {
            record_gem_digest(store, activity, g);
        }
        native_libs::record_classification(store, activity, &g.sha256, native);
        claim_executables(&mut executables, &g.name, exes)?;
        artifacts.push((g, file_path, native));
    }
    Ok(VerifiedGems {
        artifacts,
        _leases: leases,
        executables,
    })
}

/// What the installs of one gems object work from: the scratch directory
/// and the helper in it, the verified gems, and the native library set
/// their native gems build with.
struct GemsWork<'a, 'p> {
    scratch: &'a Path,
    helper: &'a Path,
    verified: VerifiedGems<'p>,
    native_libs: Option<&'a crate::kernel::provider::nativelibs::NativeLibSet>,
}

/// Install every verified gem into a staged GEM_HOME, dependency-first, and
/// commit it under `identity` (or its host-fallback identity).
fn install_gems(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &RubyPlan,
    ruby_obj: &Path,
    identity: &Identity,
    work: &GemsWork,
) -> io::Result<PathBuf> {
    let (scratch, helper, artifacts) = (work.scratch, work.helper, &work.verified.artifacts);
    let staged = store.stage_with_activity(activity)?;
    let bin = staged.join("bin");
    fs::create_dir_all(&bin)?;
    let sandboxed = GemInstall {
        platform,
        activity,
        ruby_obj,
        helper,
        scratch,
        staged: &staged,
        native_libs: work.native_libs.map(|set| set.path.as_path()),
        bundler: plan
            .bundler
            .as_ref()
            .map(|bundler| bundler.version.as_str()),
    };
    // The Bundler the lock was written with, first: the git checkouts'
    // installs below read their gemspecs with it, and at run time it is the
    // `bundle` RubyGems activates for this lock.
    let _bundler_lease = match &plan.bundler {
        Some(bundler) => Some(bundler::install(bundler, scratch, &sandboxed, |gem| {
            verify_gem(store, activity, ruby_obj, scratch, helper, gem).map(|(lease, ..)| lease)
        })?),
        None => None,
    };
    let mut fell_back = Vec::new();
    // The host state every fallback was built against (`same_host_state`).
    let mut host_inputs = None;
    for (g, file, native) in artifacts {
        // Re-verify immediately before use. The lease held since the download
        // stops a sweep, not a same-user replacement of the cache entry, so
        // the bytes about to be installed are digested again here.
        let hex = hash_file(file, Algo::Sha256)?;
        if hex != g.sha256 {
            return Err(err(format!(
                "{}: cached gem {} no longer matches the plan digest (expected {}, found {hex})",
                g.full_name,
                file.display(),
                g.sha256
            )));
        }
        // gem install only treats .gem-named arguments as local files (the
        // same lesson as pip and sdists); COPY from the cache, never link.
        let named = scratch.join(format!("{}.gem", g.full_name));
        fs::copy(file, &named)?;
        // Dependency-first order comes from the plan (helper topo-sort):
        // extconf.rb may require already-installed dependency gems.
        if let Some(built_against) = sandboxed.install(g, &named, *native)? {
            same_host_state(&mut host_inputs, &g.full_name, built_against)?;
            fell_back.push(g.full_name.clone());
        }
    }
    // Git checkouts last: their gemspecs and extension builds may require
    // the rubygems.org gems above. `git-dependency` was recorded before
    // the sync fetched anything (`sources::record_git_dependencies`).
    // A git gem's executables are known once Bundler has evaluated its
    // gemspec, so they are checked against the others here.
    let mut executables = work.verified.executables.clone();
    for checkout in sources::checkouts(&plan.git_gems) {
        let source = checkout.first.source();
        let tree =
            crate::kernel::gitsrc::ensure_git_source(store, activity, &source).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{} from {}: {e}", checkout.first.name, source.url),
                )
            })?;
        let installed = sandboxed.install_git(&checkout, &tree)?;
        // The report names exactly this checkout's gems
        // (`read_git_install_report`).
        for gem in checkout.gems() {
            let exes = installed.executables.get(&gem.name).into_iter().flatten();
            claim_executables(&mut executables, &gem.name, exes.cloned())?;
        }
        if let Some(built_against) = installed.built_against {
            same_host_state(&mut host_inputs, checkout.name, built_against)?;
            fell_back.push(checkout.name.to_string());
        }
    }
    // Each install checked its own checkout, but a later checkout's
    // sandboxed install can write to an earlier one: every checkout is
    // checked again once all have installed, before the commit.
    for checkout in sources::checkouts(&plan.git_gems) {
        gem_home::refuse_git_data(&staged, checkout.name)?;
    }
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(ruby_obj)?)?;
    if let Some(set) = work.native_libs {
        deps.object_id(&set.id)?;
    }
    for gem in &plan.gems {
        deps.cache_digest(Digest::sha256(&gem.sha256)?);
    }
    if let Some(bundler) = &plan.bundler {
        deps.cache_digest(Digest::sha256(&bundler.sha256)?);
    }
    // A gem rebuilt against the whole host recorded `host-build-inputs`:
    // the object carries it, so a later cache hit replays it through
    // `check_cached_with_activity` above and a policy that denies the kind
    // refuses the cached object too. Such an object is committed under its
    // own identity, keyed by the host build inputs its fallbacks were built
    // against, and a record under the runtime-only id and those inputs
    // points a later sync on a host in the same state at it.
    let commit_identity = match &host_inputs {
        None => identity.clone(),
        Some(host_inputs) => ruby_gems_fallback_identity(identity, &fell_back, host_inputs),
    };
    let candidate = crate::kernel::policy::object_exceptions();
    let (object, applied) = store
        .commit_with_activity_and_deps(activity, &commit_identity, &staged, &candidate, &deps)
        .map_err(|e| io::Error::new(e.kind(), format!("commit gems: {e}")))?;
    if let Some(host_inputs) = &host_inputs {
        record_host_fallback(store, activity, identity, host_inputs, &fell_back);
    }
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// Project provenance (closure envelope); enforcement is env, set at run.
/// The closure writer still takes the project path: it publishes through
/// the descriptor the sync's toolchain guard holds and refuses a renamed
/// project before publication.
pub fn project_ruby_env(
    activity: &StoreActivity,
    project: &ProjectRoot,
    ruby_obj: &Path,
    gems_obj: &Path,
    plan: &RubyPlan,
    lock_sha256: &str,
    resolution_basis: &crate::comforter::join::Digests,
    selected: &Selected,
    ledgers: &[crate::kernel::resolve::ledger::LedgerObjects],
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let ruby_obj = ruby_obj.canonicalize()?;
    let gems_obj = gems_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&ruby_obj)
        .ok_or_else(|| err("Ruby object is not in a Greyward store"))?;
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, activity, &ruby_obj)?;
    refs.object_path(&store, activity, &gems_obj)?;
    // Native extensions load the set's libraries at run time, through the
    // rpath they were linked with, so the project keeps it live too.
    let native_reference = crate::kernel::provider::nativelibs::env_reference(&gems_obj)?;
    if let Some(id) = native_reference.as_ref().and_then(|r| r["id"].as_str()) {
        refs.object_id(&store, activity, id)?;
    }
    // The planner doors' ledgers: evidence of what planning ran, kept as
    // long as this closure is, and named in the body so a root rebuilt
    // from the closure alone keeps them.
    let mut ledger_refs = Vec::new();
    for objects in ledgers {
        for id in [&objects.ledger, &objects.diagnostics] {
            refs.object_id(&store, activity, id)?;
            ledger_refs.push(crate::comforter::object_ref(&store.object_path(id))?);
        }
    }
    let mut body = closure_body(&ruby_obj, &gems_obj, plan, lock_sha256, selected)?;
    if let Some(reference) = native_reference {
        body["native_libs"] = reference;
    }
    body["resolution_ledgers"] = ledger_refs.into();
    body[crate::comforter::join::BASIS_FIELD] =
        crate::comforter::join::basis_value(resolution_basis);
    crate::comforter::write_closure(project, "ruby", body, &store, activity, refs, attribution)
}

/// The Ruby closure body: the projection's objects and plan, plus the
/// toolchain record that says which selection realized them. The
/// interpreter object is this ecosystem's runtime, and `project_ruby_env`
/// already holds it as a direct ref, so GC keeps it alive by the recorded
/// id.
fn closure_body(
    ruby_obj: &Path,
    gems_obj: &Path,
    plan: &RubyPlan,
    lock_sha256: &str,
    selected: &Selected,
) -> io::Result<serde_json::Value> {
    let mut body = serde_json::json!({
        "ruby_object": crate::comforter::object_ref(ruby_obj)?,
        "gems_object": crate::comforter::object_ref(gems_obj)?,
        "gemfile_lock_sha256": lock_sha256,
        "plan": plan,
    });
    let record = crate::comforter::toolchain::closure_record(selected, ruby_obj);
    crate::comforter::merge_record(&mut body, record);
    Ok(body)
}

/// A spec straight from the compiled pin table: the catalog's own rows, and
/// the fixture the identity goldens are written against.
#[cfg(test)]
fn pin_spec(platform: Platform) -> RubySpec {
    let pin = ruby_pin(platform).expect("pinned Ruby toolchain for test platform");
    RubySpec {
        platform: pin.platform,
        version: RUBY_VERSION.to_string(),
        provider: pin.provider.clone(),
        url: pin.url.to_string(),
        sha256: pin.digest.hex().to_string(),
    }
}

/// The shipped default Ruby, the object-id golden the identity tests hold:
/// adding a newer portable build to the catalog must not move it.
#[cfg(test)]
const RUBY_VERSION: &str = "3.4.6";

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let spec = pin_spec(platform);
    let ruby = ruby_identity(&spec);
    let empty_plan = RubyPlan {
        ruby_version: RUBY_VERSION.into(),
        ruby_platform: if platform.is_macos() {
            "arm64-darwin20".into()
        } else {
            "x86_64-linux".into()
        },
        bundler_version: "2.6.9".into(),
        path_gems: Vec::new(),
        git_gems: Vec::new(),
        bundler: None,
        gems: Vec::new(),
    };
    let gem_plan = RubyPlan {
        gems: vec![RubyGem {
            name: "rake".into(),
            version: "13.2.1".into(),
            platform: "ruby".into(),
            full_name: "rake-13.2.1".into(),
            sha256: "a".repeat(64),
            digest_from_api: false,
            digest_in_lock: false,
        }],
        ..empty_plan.clone()
    };
    let gems = ruby_gems_identity(&spec, &gem_plan, None);
    let mut cases = vec![
        ruby,
        ruby_gems_identity(&spec, &empty_plan, None),
        gems.clone(),
    ];
    // Path and git gems: only a git checkout is an input, and a plan with
    // one builds as a native plan does on Linux.
    let git_plan = sources_test_plan(&empty_plan);
    let native_libs_id = format!("{}-libset-3", "c".repeat(40));
    let linux_libs = (!platform.is_macos()).then_some(native_libs_id.as_str());
    let git = ruby_gems_identity(&spec, &git_plan, linux_libs);
    cases.push(git.clone());
    // A lock written by a newer Bundler: its own object, and the gems
    // object it is installed into first.
    let provisioned = RubyBundler {
        version: "4.0.3".into(),
        sha256: "f06623d5edf4183e5fac847a953c1f1bd95e27aa766471525d3a9c70bdee9394".into(),
        digest_in_lock: false,
        digest_from_api: false,
    };
    cases.push(bundler::identity(&spec, &provisioned));
    cases.push(ruby_gems_identity(
        &spec,
        &RubyPlan {
            bundler_version: provisioned.version.clone(),
            bundler: Some(provisioned),
            ..gem_plan.clone()
        },
        None,
    ));
    if !platform.is_macos() {
        cases.push(ruby_gems_identity(&spec, &gem_plan, Some(&native_libs_id)));
        cases.push(ruby_gems_fallback_identity(
            &gems,
            &["rake-13.2.1".into()],
            &"f".repeat(64),
        ));
        cases.push(ruby_gems_fallback_identity(
            &git,
            &["gitgem-repo-0123456789ab".into()],
            &"f".repeat(64),
        ));
    }
    cases
}

/// `base` with one path gem and one git gem, and no rubygems.org gem.
#[cfg(test)]
fn sources_test_plan(base: &RubyPlan) -> RubyPlan {
    RubyPlan {
        path_gems: vec![RubyPathGem {
            name: "app".into(),
            version: "1.0.0".into(),
            path: ".".into(),
        }],
        git_gems: vec![RubyGitGem {
            name: "gitgem".into(),
            version: "0.1.0".into(),
            url: "https://example.invalid/gitgem-repo.git".into(),
            revision: "0123456789abcdef0123456789abcdef01234567".into(),
            checkout: "gitgem-repo-0123456789ab".into(),
            glob: String::new(),
        }],
        ..base.clone()
    }
}

#[cfg(test)]
mod tests {

    /// The host-local tripwire admits this helper by content: the digest
    /// it holds is the digest of the text written here, so an edit to the
    /// helper is also an edit to the reviewed table.
    #[test]
    fn the_tripwire_pins_this_helper() {
        use sha2::Digest as _;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(HELPER.as_bytes())),
            crate::kernel::resolve::tripwire::RUBY_HELPER_SHA256
        );
    }

    /// The real `spec` call site passes the tripwire, and an interpreter
    /// option variable added to it is refused.
    #[test]
    fn the_gem_spec_read_passes_the_tripwire_only_as_built() {
        use crate::kernel::resolve::tripwire::refusal;
        use crate::kernel::testutil::{loosened, store_program};
        let store = TempDir::named("ruby-tripwire");
        let refused = |command: &Command| refusal(command, &store.0);
        store_program(&store.0, "objects/ruby/bin/ruby");
        let ruby = store.0.join("objects/ruby");
        let scratch = store.0.join("tmp/stage-scratch");
        fs::create_dir_all(&scratch).unwrap();
        let helper = scratch.join("helper.rb");
        fs::write(&helper, HELPER).unwrap();
        let gem = store.0.join("cache/sha256/x.gem");
        let spec_args = |gem: &Path| {
            [
                "ruby",
                helper.to_str().unwrap(),
                "spec",
                gem.to_str().unwrap(),
            ]
            .map(str::to_string)
        };
        let build_at = |ruby: &Path, gem: &Path| {
            let args = spec_args(gem);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            gem_spec_command(ruby, &scratch, &scratch, &args)
        };
        let build = || build_at(&ruby, &gem);
        assert!(refused(&build()).is_none(), "{:?}", refused(&build()));
        for (key, value) in [
            ("RUBYOPT", "-r/tmp/evil"),
            ("RUBYLIB", "/tmp"),
            ("RUBYGEMS_GEMDEPS", "-"),
            ("BUNDLE_PATH", "/tmp"),
            ("GEM_PATH", "/tmp/gems"),
            ("GEM_HOME", "/tmp/gems"),
            ("GEMRC", "/home/someone/.gemrc"),
            ("HOME", "/home/someone"),
            ("PATH", "/home/someone/.rbenv/shims"),
        ] {
            let mut command = build();
            command.env(key, value);
            assert!(refused(&command).is_some(), "{key}");
        }
        // Another mode, or another script at the helper's path, each in
        // the environment as built.
        let (helper_arg, gem_arg) = (helper.to_str().unwrap(), gem.to_str().unwrap());
        for argv in [
            ["ruby", helper_arg, "check", gem_arg],
            ["ruby", helper_arg, "-rx", gem_arg],
        ] {
            let command = gem_spec_command(&ruby, &scratch, &scratch, &argv);
            assert!(refused(&command).is_some(), "{argv:?}");
        }
        fs::write(&helper, "puts 'not the helper'\n").unwrap();
        assert!(refused(&build()).is_some(), "an impostor helper.rb");
        fs::write(&helper, HELPER).unwrap();
        assert!(refused(&build()).is_none());
        let mut appended = build();
        appended.env("GEM_PATH", format!("{}:/tmp/gems", scratch.display()));
        assert!(refused(&appended).is_some(), "GEM_PATH with a second entry");
        let loosened_spec = loosened(build);
        let keys: Vec<&str> = loosened_spec.iter().map(|(key, _)| key.as_str()).collect();
        for key in [
            "GEM_HOME",
            "GEM_PATH",
            "GEMRC",
            "HOME",
            "PATH",
            "BUNDLE_GEMFILE",
        ] {
            assert!(keys.contains(&key), "{key} is not forced: {keys:?}");
        }
        for (key, command) in &loosened_spec {
            assert!(refused(command).is_some(), "loosened {key}");
        }
        assert!(
            refused(&build_at(&ruby, Path::new("/tmp/x.gem"))).is_some(),
            "a .gem outside the store"
        );
        let host = TempDir::named("ruby-tripwire-host");
        store_program(&host.0, "ruby/bin/ruby");
        assert!(
            refused(&build_at(&host.0.join("ruby"), &gem)).is_some(),
            "a ruby outside the store"
        );
    }
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;

    #[test]
    fn ruby_pins_cover_supported_platforms() {
        let catalog = toolchain_catalog().unwrap();
        assert!(
            catalog.bundles().len() > 1,
            "the catalog holds more than the default"
        );
        for bundle in catalog.bundles() {
            for platform in Platform::ALL {
                let row = bundle.artifact(*platform, "ruby").unwrap();
                assert!(
                    row.url.starts_with(&format!(
                        "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/{}/portable-ruby-{}.",
                        row.build, row.build
                    )),
                    "{}",
                    row.url
                );
            }
        }
        // The default is unchanged by the newer rows around it.
        for platform in Platform::ALL {
            assert_eq!(ruby_pin(*platform).unwrap().platform, *platform);
            assert_eq!(ruby_pin(*platform).unwrap().build, RUBY_VERSION);
        }
        assert_eq!(
            shipped_selection().unwrap().version("ruby").unwrap(),
            RUBY_VERSION
        );
        let linux = ruby_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(linux.url, "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/portable-ruby-3.4.6.x86_64_linux.bottle.tar.gz");
        assert_eq!(
            linux.digest.hex(),
            "40932a3950ccc8bf9d13d98e692e5518427cc66b4f9520956cec349629d25259"
        );
    }

    pub(super) fn linux_test_plan() -> RubyPlan {
        RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "x86_64-linux".into(),
            bundler_version: "2.6.9".into(),
            path_gems: Vec::new(),
            git_gems: Vec::new(),
            bundler: None,
            gems: vec![RubyGem {
                name: "rake".into(),
                version: "13.2.1".into(),
                platform: "ruby".into(),
                full_name: "rake-13.2.1".into(),
                sha256: "a".repeat(64),
                digest_from_api: false,
                digest_in_lock: false,
            }],
        }
    }

    /// A classification record that disagrees with the gemspecs read on a
    /// cache miss is caught, and the identity is decided by the gemspecs:
    /// a gem recorded as pure Ruby that is native names the set.
    #[test]
    fn a_stale_native_record_is_overruled_by_the_gemspecs() {
        let plan = linux_test_plan();
        let spec = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let verified = |native: bool| VerifiedGems {
            artifacts: vec![(&plan.gems[0], PathBuf::from("/cache/rake.gem"), native)],
            _leases: Vec::new(),
            executables: BTreeMap::new(),
        };
        assert_eq!(stale_native_classification(false, &verified(false)), None);
        assert_eq!(stale_native_classification(true, &verified(true)), None);
        assert_eq!(
            stale_native_classification(false, &verified(true)),
            Some(true)
        );
        assert_eq!(
            stale_native_classification(true, &verified(false)),
            Some(false)
        );

        let set = format!("{}-libset-3", "c".repeat(40));
        let recorded = ruby_gems_identity(&spec, &plan, None);
        let corrected = ruby_gems_identity(&spec, &plan, Some(&set));
        assert_eq!(recorded.inputs["native"], native_libs::NATIVE_NONE);
        assert_eq!(corrected.inputs["native"], native_libs::NATIVE_LIBS_MOUNTED);
        assert_ne!(recorded.object_id(), corrected.object_id());
    }

    #[test]
    fn linux_and_darwin_identities_are_distinct_rows_of_one_schema() {
        let darwin_pin = pin_spec(Platform::Aarch64AppleDarwin);
        let linux_pin = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let darwin = ruby_identity(&darwin_pin);
        let linux = ruby_identity(&linux_pin);
        assert_ne!(darwin.object_id(), linux.object_id());
        // Same input keys: the Linux pin is a row, not a second recipe.
        assert_eq!(
            darwin.inputs.keys().collect::<Vec<_>>(),
            linux.inputs.keys().collect::<Vec<_>>()
        );
        assert_eq!(linux.inputs["platform"], "x86_64-unknown-linux-gnu");
        assert_eq!(linux.inputs["artifact_sha256"], linux_pin.sha256);

        let plan = linux_test_plan();
        let darwin_gems = ruby_gems_identity(&darwin_pin, &plan, None);
        let linux_gems = ruby_gems_identity(&linux_pin, &plan, None);
        assert_ne!(darwin_gems.object_id(), linux_gems.object_id());
        assert!(linux_gems.inputs["installer"].contains(&linux_pin.sha256));
    }

    #[test]
    fn linux_identities_pinned() {
        // Goldens for the shared-store check: a Mac
        // and a Linux box realizing the same pin must not collide, and the
        // Linux ids must not drift without a deliberate identity change.
        let spec = pin_spec(Platform::X86_64UnknownLinuxGnu);
        assert_eq!(
            (
                ruby_identity(&spec).object_id(),
                ruby_gems_identity(&spec, &linux_test_plan(), None).object_id(),
            ),
            (
                "192a4c7b501dd09eb3c76a3ebd427e8077fbda6e-ruby-3.4.6".to_string(),
                // runtime-only/3: native extensions see the C runtime alone;
                // native none: the plan names no native library set.
                "0aeb9ec439b4e6a0cb5ce2b150a4ab7d4d15541f-gems-1".to_string(),
            )
        );
    }

    /// Linux gem objects name the host view their extensions built
    /// against; Darwin's inputs are what they were, so its ids stand.
    #[test]
    fn linux_gem_identity_names_the_runtime_only_view() {
        let plan = linux_test_plan();
        let linux = ruby_gems_identity(&pin_spec(Platform::X86_64UnknownLinuxGnu), &plan, None);
        assert_eq!(linux.inputs["build_view"], "runtime-only/3");
        let darwin = ruby_gems_identity(&pin_spec(Platform::Aarch64AppleDarwin), &plan, None);
        assert!(!darwin.inputs.contains_key("build_view"), "{darwin:?}");
    }

    /// A Linux gems identity spells out its native decision, names the
    /// native library set exactly when it says so, and a macOS one names
    /// neither (#329).
    #[test]
    fn the_native_decision_and_the_library_set_agree() {
        let plan = linux_test_plan();
        let linux = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let set = format!("{}-libset-3", "c".repeat(40));
        let none = ruby_gems_identity(&linux, &plan, None);
        let mounted = ruby_gems_identity(&linux, &plan, Some(&set));
        assert_eq!(none.inputs["native"], native_libs::NATIVE_NONE);
        assert_eq!(mounted.inputs["native"], native_libs::NATIVE_LIBS_MOUNTED);
        assert_eq!(mounted.inputs["native_libs"], set);
        assert_ne!(none.object_id(), mounted.object_id());
        let grammar = crate::kernel::objmeta::check_identity_grammar;
        assert_eq!(grammar(&none), Ok(()));
        assert_eq!(grammar(&mounted), Ok(()));
        let mut dropped = mounted.clone();
        dropped.inputs.remove("native_libs");
        assert!(grammar(&dropped).unwrap_err().contains("native decision"));
        let mut no_decision = none.clone();
        no_decision.inputs.remove("native");
        assert!(grammar(&no_decision).is_err());
        let mut empty = mounted.clone();
        empty.inputs.retain(|key, _| !key.starts_with("gem:"));
        empty.version = "0".into();
        assert!(grammar(&empty).unwrap_err().contains("requires a gem:"));
        let darwin_spec = pin_spec(Platform::Aarch64AppleDarwin);
        let darwin = ruby_gems_identity(&darwin_spec, &plan, Some(&set));
        assert!(!darwin.inputs.contains_key("native"), "{darwin:?}");
        assert!(!darwin.inputs.contains_key("native_libs"), "{darwin:?}");
        let mut foreign = darwin.clone();
        foreign
            .inputs
            .insert("native".into(), native_libs::NATIVE_NONE.into());
        assert!(grammar(&foreign).unwrap_err().contains("Linux-only"));
    }

    /// Native classifications kept in the store answer for a plan only
    /// when every gem has one.
    #[test]
    fn a_plan_is_classified_only_when_every_gem_is() {
        let temp = TempDir::named("ruby-native-records");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let mut plan = linux_test_plan();
        let mut second = plan.gems[0].clone();
        second.sha256 = "b".repeat(64);
        plan.gems.push(second);
        let persisted =
            |plan: &RubyPlan| native_libs::persisted_classification(&store, plan).unwrap();
        assert_eq!(persisted(&plan), None);
        native_libs::record_classification(&store, &activity, &plan.gems[0].sha256, false);
        assert_eq!(persisted(&plan), None);
        native_libs::record_classification(&store, &activity, &plan.gems[1].sha256, true);
        assert_eq!(persisted(&plan), Some(true));
        assert_eq!(
            native_libs::identity_id(&store, Platform::Aarch64AppleDarwin, true).unwrap(),
            None
        );
    }

    #[test]
    fn synthetic_bottle_uses_two_root_components_and_validates_layout() {
        let temp = TempDir::new();
        let source = temp.0.join("source with spaces");
        let tree = source.join("portable-ruby/3.4.6");
        fs::create_dir_all(tree.join("bin")).unwrap();
        fs::create_dir_all(tree.join("lib")).unwrap();
        fs::create_dir_all(tree.join("include/ruby-3.4.0")).unwrap();
        fs::write(tree.join("bin/ruby"), b"#!/bin/sh\n").unwrap();
        fs::write(tree.join("bin/gem-real"), b"#!/bin/sh\n").unwrap();
        symlink("gem-real", tree.join("bin/gem")).unwrap();
        fs::write(tree.join("bin/bundle"), b"#!/bin/sh\n").unwrap();
        fs::write(tree.join("lib/libruby-3.4.so"), b"ELF\0not text").unwrap();
        fs::write(
            tree.join("include/ruby-3.4.0/ruby.h"),
            b"#define RUBY_H 1\n",
        )
        .unwrap();
        fs::set_permissions(tree.join("bin/ruby"), fs::Permissions::from_mode(0o755)).unwrap();

        let archive = temp.0.join("portable ruby.tar.gz");
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg("portable-ruby")
            .status()
            .unwrap();
        assert!(status.success());

        let staged = temp.0.join("staged");
        fs::create_dir(&staged).unwrap();
        extract_ruby_bottle_for_test(&archive, &staged).unwrap();
        assert!(staged.join("bin/ruby").is_file());
        assert!(staged.join("bin/gem").is_symlink());
        assert!(!staged.join("portable-ruby").exists());
        assert_eq!(
            fs::metadata(staged.join("bin/ruby"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        fs::remove_file(staged.join("bin/bundle")).unwrap();
        let error = validate_ruby_layout(&staged).unwrap_err();
        assert!(error.to_string().contains("Bundler launcher"));
    }

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let identity = ruby_identity(&pin_spec(platform));
        assert_eq!(
            identity.object_id(),
            "c4c2411b7540521f48dcdd8cff25786e261ed1ee-ruby-3.4.6"
        );
    }

    #[test]
    fn darwin_ruby_gems_identity_unchanged() {
        let spec = pin_spec(Platform::Aarch64AppleDarwin);
        let plan = RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "arm64-darwin20".into(),
            bundler_version: "2.6.9".into(),
            path_gems: Vec::new(),
            git_gems: Vec::new(),
            bundler: None,
            gems: vec![RubyGem {
                name: "rake".into(),
                version: "13.2.1".into(),
                platform: "ruby".into(),
                full_name: "rake-13.2.1".into(),
                sha256: "a".repeat(64),
                digest_from_api: false,
                digest_in_lock: false,
            }],
        };
        let identity = ruby_gems_identity(&spec, &plan, None);
        assert_eq!(
            identity.object_id(),
            "c017bc4da37483c7d35d1997df4c541d35e4a751-gems-1"
        );
    }

    #[test]
    fn plan_validation_rejects_hostile_fields() {
        let base = RubyGem {
            name: "rake".into(),
            version: "13.2.1".into(),
            platform: "ruby".into(),
            full_name: "rake-13.2.1".into(),
            sha256: "a".repeat(64),
            digest_from_api: false,
            digest_in_lock: false,
        };
        let ok = RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "arm64-darwin20".into(),
            bundler_version: "2.6.9".into(),
            path_gems: Vec::new(),
            git_gems: Vec::new(),
            bundler: None,
            gems: vec![base.clone()],
        };
        assert!(validate_plan(&ok).is_ok());
        let mut evil = base.clone();
        evil.full_name = "../escape".into();
        assert!(validate_plan(&RubyPlan {
            gems: vec![evil],
            ..ok.clone()
        })
        .is_err());
        let mut bad = base.clone();
        bad.sha256 = "zz".into();
        assert!(validate_plan(&RubyPlan {
            gems: vec![bad],
            ..ok.clone()
        })
        .is_err());
        let dup = RubyPlan {
            gems: vec![base.clone(), base.clone()],
            ..ok.clone()
        };
        assert!(validate_plan(&dup).is_err());
    }

    #[test]
    fn linux_plan_accepts_source_and_platform_qualified_gems() {
        let plan = RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "x86_64-linux".into(),
            bundler_version: "2.6.9".into(),
            path_gems: Vec::new(),
            git_gems: Vec::new(),
            bundler: None,
            gems: vec![
                RubyGem {
                    name: "mini_portile2".into(),
                    version: "2.8.9".into(),
                    platform: "ruby".into(),
                    full_name: "mini_portile2-2.8.9".into(),
                    sha256: "a".repeat(64),
                    digest_from_api: false,
                    digest_in_lock: false,
                },
                RubyGem {
                    name: "nokogiri".into(),
                    version: "1.18.10".into(),
                    platform: "x86_64-linux".into(),
                    full_name: "nokogiri-1.18.10-x86_64-linux".into(),
                    sha256: "b".repeat(64),
                    digest_from_api: false,
                    digest_in_lock: false,
                },
            ],
        };
        assert!(validate_plan(&plan).is_ok());
    }

    /// The selection is the only authority on the sync path, so the object
    /// it realizes must have the id the pin table realized before selection
    /// existed, on both platforms: that is the id every cached Ruby already
    /// has. If this drifts, every cached Ruby is orphaned.
    #[test]
    fn a_selected_row_and_the_pin_build_the_same_identity() {
        let selected = shipped_selection().unwrap();
        for platform in Platform::ALL {
            let from_lock = ruby_spec(*platform, &selected).unwrap();
            let from_pin = pin_spec(*platform);
            assert_eq!(from_lock.version, from_pin.version);
            assert_eq!(from_lock.url, from_pin.url);
            assert_eq!(from_lock.sha256, from_pin.sha256);
            assert_eq!(
                ruby_identity(&from_lock).object_id(),
                ruby_identity(&from_pin).object_id(),
                "{}",
                platform.triple()
            );
            let plan = linux_test_plan();
            assert_eq!(
                ruby_gems_identity(&from_lock, &plan, None).object_id(),
                ruby_gems_identity(&from_pin, &plan, None).object_id()
            );
        }
    }

    #[test]
    fn an_unknown_recipe_and_a_foreign_selection_are_both_refused() {
        let mut selected = shipped_selection().unwrap();
        for row in &mut selected.bundle.artifacts {
            row.recipe = "ruby-toolchain/99".into();
        }
        let error = ruby_spec(Platform::X86_64UnknownLinuxGnu, &selected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ruby-toolchain/99"), "{error}");
        assert!(error.contains("upgrade ward"), "{error}");

        let mut foreign = shipped_selection().unwrap();
        foreign.ecosystem = "python".into();
        let error = ruby_spec(Platform::X86_64UnknownLinuxGnu, &foreign)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not ruby"), "{error}");

        // A selection of the right ecosystem with no row for this host is a
        // refusal too, and it names what it could not find.
        let mut empty = shipped_selection().unwrap();
        empty.bundle.artifacts.clear();
        let error = ruby_spec(Platform::X86_64UnknownLinuxGnu, &empty)
            .unwrap_err()
            .to_string();
        assert!(error.contains("x86_64-unknown-linux-gnu"), "{error}");
    }

    /// Every closure this tailor writes carries which bundle realized it and
    /// which store object that bundle became: `ward status` compares the one,
    /// `ward run` resolves the other.
    #[test]
    fn the_closure_body_records_the_bundle_and_the_runtime_object() {
        let selected = shipped_selection().unwrap();
        let ruby_obj = Path::new("/store/objects/abc-ruby-3.4.6");
        let body = closure_body(
            ruby_obj,
            Path::new("/store/objects/def-gems-1"),
            &linux_test_plan(),
            &"c".repeat(64),
            &selected,
        )
        .unwrap();
        assert_eq!(body["toolchain"]["ecosystem"], "ruby");
        assert_eq!(body["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(body["toolchain"]["versions"]["ruby"], RUBY_VERSION);
        assert_eq!(body["runtime_object"]["id"], "abc-ruby-3.4.6");
        assert_eq!(
            body["runtime_object"]["path"],
            ruby_obj.display().to_string()
        );
        // The runtime object is the interpreter the projection already
        // records, and every pre-existing key survives beside the record.
        assert_eq!(body["ruby_object"]["id"], body["runtime_object"]["id"]);
        assert_eq!(body["gems_object"]["id"], "def-gems-1");
        assert_eq!(body["gemfile_lock_sha256"], "c".repeat(64));
        assert_eq!(body["plan"]["ruby_platform"], "x86_64-linux");
    }

    /// The durable root/2 record `project_ruby_env` publishes names exactly
    /// the Ruby interpreter object and the gems object it was handed:
    /// nothing inferred from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("ruby").unwrap();
        let temp = TempDir::new();
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store::for_test(store_root.canonicalize().unwrap());
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        let ruby_id = store.publish_bare_test("ruby", RUBY_VERSION);
        let gems_id = store.publish_bare_test("gems", "1");
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        project_ruby_env(
            activity,
            &ProjectRoot::open(&project).unwrap(),
            &store.object_path(&ruby_id),
            &store.object_path(&gems_id),
            &linux_test_plan(),
            &"c".repeat(64),
            &Default::default(),
            &shipped_selection().unwrap(),
            &[],
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([ruby_id, gems_id])
        );
        assert!(record.projections.is_empty(), "{:?}", record.projections);

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
    }

    /// A project renamed mid-sync with another project put at its old path:
    /// detection and the lock reader keep reading the directory the sync
    /// opened, never the replacement.
    #[test]
    fn a_held_root_keeps_reading_the_original_project_after_a_rename() {
        use crate::tailors::Tailor as _;
        let temp = TempDir::new();
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Gemfile"), "source \"https://rubygems.org\"\n").unwrap();
        fs::write(project.join("Gemfile.lock"), "ORIGINAL\n").unwrap();
        let root = ProjectRoot::open(&project).unwrap();

        fs::rename(&project, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Gemfile.lock"), "REPLACEMENT\n").unwrap();

        assert!(tailor::Ruby.detect(&root).unwrap());
        assert_eq!(read_gemfile_lock(&root).unwrap(), "ORIGINAL\n");
        let fresh = ProjectRoot::open(&project).unwrap();
        assert!(!tailor::Ruby.detect(&fresh).unwrap());
        assert_eq!(read_gemfile_lock(&fresh).unwrap(), "REPLACEMENT\n");
    }

    /// A recorded digest is found only by its exact (name, version,
    /// platform), and a record that is not a sha256 is no record.
    #[test]
    fn gem_digest_records_are_keyed_by_the_whole_coordinate() {
        let temp = TempDir::named("ruby-gem-digests");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let gem = RubyGem {
            name: "racc".into(),
            version: "1.8.1".into(),
            platform: "ruby".into(),
            full_name: "racc-1.8.1".into(),
            sha256: "c".repeat(64),
            digest_from_api: true,
            digest_in_lock: false,
        };
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.1", "ruby").unwrap(),
            None
        );
        record_gem_digest(&store, &activity, &gem);
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.1", "ruby").unwrap(),
            Some("c".repeat(64))
        );
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.1", "java").unwrap(),
            None
        );
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.2", "ruby").unwrap(),
            None
        );
        // Name and version never run together: "a-1" at "2" is not "a" at
        // "1-2".
        let key = gem_digest_key("a-1", "2", "ruby");
        assert_ne!(key, gem_digest_key("a", "1-2", "ruby"));
        store
            .write_record(
                &activity,
                GEM_DIGESTS,
                &key,
                &serde_json::json!({"sha256": "zz"}),
            )
            .unwrap();
        assert_eq!(
            recorded_gem_digest(&store, "a-1", "2", "ruby").unwrap(),
            None
        );
        // The digest is planning state: it never reaches a serialized plan.
        let json = serde_json::to_value(&gem).unwrap();
        assert!(json.get("digest_from_api").is_none(), "{json}");
        assert!(json.get("digest_in_lock").is_none(), "{json}");
    }

    /// A gem whose digest the lock's CHECKSUMS section pinned records
    /// nothing; one whose digest came from rubygems.org, now or through the
    /// store's record, records `unpinned-digest` under its full name.
    #[test]
    fn a_digest_the_lock_did_not_pin_is_recorded() {
        let gem = |name: &str, in_lock: bool, from_api: bool| RubyGem {
            name: name.into(),
            version: "1.0.0".into(),
            platform: "ruby".into(),
            full_name: format!("{name}-1.0.0"),
            sha256: "c".repeat(64),
            digest_from_api: from_api,
            digest_in_lock: in_lock,
        };
        let plan = RubyPlan {
            ruby_version: "3.4.6".into(),
            ruby_platform: "x86_64-linux".into(),
            bundler_version: "2.6.9".into(),
            path_gems: Vec::new(),
            git_gems: Vec::new(),
            bundler: None,
            gems: vec![
                gem("pinned", true, false),
                gem("asked", false, true),
                gem("remembered", false, false),
            ],
        };
        let recorded = std::cell::RefCell::new(Vec::new());
        record_unpinned_digests(&plan, |kind, subject, _| {
            recorded
                .borrow_mut()
                .push((kind.to_string(), subject.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            recorded.into_inner(),
            [
                ("unpinned-digest".to_string(), "asked-1.0.0".to_string()),
                (
                    "unpinned-digest".to_string(),
                    "remembered-1.0.0".to_string()
                ),
            ]
        );
        let denied = record_unpinned_digests(&plan, |_, subject, _| {
            Err(io::Error::other(format!("denied {subject}")))
        })
        .unwrap_err();
        assert_eq!(denied.to_string(), "denied asked-1.0.0");
    }

    /// ward's own Bundler runs start inside the held project directory and
    /// name the Gemfile relative to it (#499). `ward run` may start in a
    /// subdirectory, so it keeps the root Gemfile's full path.
    #[test]
    fn delegates_name_the_gemfile_relative_to_the_held_project() {
        let gemfile = |env: &[(String, String)]| {
            env.iter()
                .find(|(key, _)| key == "BUNDLE_GEMFILE")
                .map(|(_, value)| value.clone())
        };
        let spec = ruby_tool_spec(
            Path::new("/ruby"),
            Path::new("/p"),
            &["bundle", "lock"],
            &forced_env(GEMFILE, Path::new("/g")),
        );
        assert!(format!("{:?}", spec.command()).contains("BUNDLE_GEMFILE=\"Gemfile\""));
        assert_eq!(
            gemfile(&forced_env(GEMFILE, Path::new("/g"))).as_deref(),
            Some("Gemfile")
        );
        let (_, _, run) = run_env(Path::new("/p"), Path::new("/g"));
        assert_eq!(gemfile(&run).as_deref(), Some("/p/Gemfile"));
    }

    #[test]
    fn forced_env_covers_bundler_side_doors() {
        let env = forced_env(GEMFILE, Path::new("/g"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for required in [
            "BUNDLE_IGNORE_CONFIG",
            "BUNDLE_GEMFILE",
            "BUNDLE_FROZEN",
            "GEM_HOME",
            "GEM_PATH",
        ] {
            assert!(keys.contains(&required), "{required}");
        }
        assert!(ENV_REMOVE.contains(&"RUBYOPT"));
        assert!(ENV_REMOVE.contains(&"RUBYLIB"));
        assert!(ENV_REMOVE_PREFIXES.contains(&"BUNDLE_"));
        // The host-local tripwire checks the spec read against its own copy
        // of the forced list.
        let env = forced_env(GEMFILE, Path::new("/g"));
        let mut keys: Vec<&str> = env.iter().map(|(key, _)| key.as_str()).collect();
        let mut checked = crate::kernel::resolve::tripwire::RUBY_FORCED.to_vec();
        keys.sort_unstable();
        checked.sort_unstable();
        assert_eq!(keys, checked);
    }

    /// A plan with no path or git gem serializes as it always did, so
    /// closures written before #771 and after it read the same; one with
    /// them round-trips.
    #[test]
    fn path_and_git_gems_are_absent_from_a_plan_without_them() {
        let plan = linux_test_plan();
        let value = serde_json::to_value(&plan).unwrap();
        assert!(value.get("path_gems").is_none(), "{value}");
        assert!(value.get("git_gems").is_none(), "{value}");
        let back: RubyPlan = serde_json::from_value(value).unwrap();
        assert!(back.path_gems.is_empty() && back.git_gems.is_empty());
        let with = sources_test_plan(&plan);
        let value = serde_json::to_value(&with).unwrap();
        assert_eq!(value["path_gems"][0]["path"], ".");
        assert_eq!(value["git_gems"][0]["checkout"], "gitgem-repo-0123456789ab");
        // An empty glob is Bundler's default and is not written.
        assert!(value["git_gems"][0].get("glob").is_none(), "{value}");
        let back: RubyPlan = serde_json::from_value(value).unwrap();
        assert_eq!(back.path_gems, with.path_gems);
        assert_eq!(back.git_gems, with.git_gems);
    }

    /// A path gem adds nothing to the gems object, so it leaves the id
    /// alone; a git checkout is installed into it, so its source and commit
    /// move the id.
    #[test]
    fn only_a_git_gem_moves_the_gems_identity() {
        let spec = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let plan = linux_test_plan();
        let base = ruby_gems_identity(&spec, &plan, None).object_id();
        let mut with_path = sources_test_plan(&plan);
        with_path.git_gems.clear();
        assert_eq!(
            ruby_gems_identity(&spec, &with_path, None).object_id(),
            base
        );
        let with_git = sources_test_plan(&plan);
        let git = ruby_gems_identity(&spec, &with_git, None);
        assert_ne!(git.object_id(), base);
        assert!(git.inputs.contains_key("git:gitgem-repo-0123456789ab"));
        let mut moved = with_git.clone();
        moved.git_gems[0].revision = "f".repeat(40);
        moved.git_gems[0].checkout = format!("gitgem-repo-{}", "f".repeat(12));
        assert_ne!(
            ruby_gems_identity(&spec, &moved, None).object_id(),
            git.object_id()
        );
    }

    /// Every lock source Bundler reads from one checkout directory is part
    /// of that checkout's one identity input, a JSON array; the URL in it
    /// carries no credentials.
    #[test]
    fn a_checkout_identity_names_every_source_it_serves() {
        let spec = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let mut plan = sources_test_plan(&linux_test_plan());
        let mut second = plan.git_gems[0].clone();
        second.name = "subgem".into();
        second.glob = "sub/*.gemspec".into();
        plan.git_gems.push(second);
        validate_plan(&plan).unwrap();
        let identity = ruby_gems_identity(&spec, &plan, None);
        let git_inputs: Vec<&String> = identity
            .inputs
            .keys()
            .filter(|k| k.starts_with("git:"))
            .collect();
        assert_eq!(git_inputs, ["git:gitgem-repo-0123456789ab"]);
        let input: serde_json::Value =
            serde_json::from_str(&identity.inputs["git:gitgem-repo-0123456789ab"]).unwrap();
        assert_eq!(
            input,
            serde_json::json!([
                "0123456789abcdef0123456789abcdef01234567",
                [
                    [
                        "https://example.invalid/gitgem-repo.git",
                        "",
                        ["gitgem:0.1.0"]
                    ],
                    [
                        "https://example.invalid/gitgem-repo.git",
                        "sub/*.gemspec",
                        ["subgem:0.1.0"]
                    ],
                ]
            ])
        );
        // The second source's glob is in the id, not only the first's.
        let mut reglobbed = plan.clone();
        reglobbed.git_gems[1].glob = "other/*.gemspec".into();
        assert_ne!(
            ruby_gems_identity(&spec, &reglobbed, None).object_id(),
            identity.object_id()
        );
        // Credentials in the lock's remote never reach the identity.
        let mut credentialed = plan.clone();
        for gem in &mut credentialed.git_gems {
            gem.url = "https://user:secret@example.invalid/gitgem-repo.git".into();
        }
        let with_credentials = ruby_gems_identity(&spec, &credentialed, None);
        assert!(!format!("{:?}", with_credentials.inputs).contains("secret"));
        assert_eq!(with_credentials.object_id(), identity.object_id());
    }

    /// A git gem's executables are claimed as a rubygems.org gem's are:
    /// two gems providing one name are refused.
    #[test]
    fn two_gems_providing_one_executable_are_refused() {
        let mut claimed = BTreeMap::new();
        claim_executables(&mut claimed, "rake", ["rake".to_string()]).unwrap();
        claim_executables(&mut claimed, "gitgem", ["gitgem".to_string()]).unwrap();
        let error = claim_executables(&mut claimed, "fakerake", ["rake".to_string()])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("executable \"rake\" provided by both rake and fakerake"),
            "{error}"
        );
    }

    /// One name from two sources, or a git gem ward cannot place, is
    /// refused before anything is fetched.
    #[test]
    fn validate_plan_judges_path_and_git_gems() {
        let plan = sources_test_plan(&linux_test_plan());
        validate_plan(&plan).unwrap();
        let mut twice = plan.clone();
        twice.path_gems[0].name = "rake".into();
        assert!(validate_plan(&twice).is_err());
        let mut twice = plan.clone();
        twice.git_gems[0].name = "app".into();
        assert!(validate_plan(&twice).is_err());
        let mut bad = plan.clone();
        bad.path_gems[0].version = "../1".into();
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan.clone();
        bad.git_gems[0].revision = "main".into();
        assert!(validate_plan(&bad).is_err());
        let mut bad = plan.clone();
        bad.git_gems[0].checkout = "elsewhere".into();
        assert!(validate_plan(&bad).is_err());
    }

    /// A path gem must be a directory inside the project: not absent, not
    /// above it, and not a symlink that leads out of it.
    #[test]
    fn a_path_gem_outside_the_project_is_refused() {
        let temp = TempDir::named("ruby-path-gem");
        let project = temp.0.join("project");
        fs::create_dir_all(project.join("gems/inside")).unwrap();
        fs::create_dir_all(temp.0.join("outside")).unwrap();
        symlink(temp.0.join("outside"), project.join("escape")).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let gem = |path: &str| RubyPathGem {
            name: "x".into(),
            version: "1.0.0".into(),
            path: path.into(),
        };
        sources::check_path_gem(&root, &gem(".")).unwrap();
        sources::check_path_gem(&root, &gem("gems/inside")).unwrap();
        sources::check_path_gem(&root, &gem("gems/../gems/inside")).unwrap();
        for (path, why) in [
            ("../outside", "outside the project"),
            ("/etc", "is absolute"),
            ("gems/missing", "not a directory in the project"),
            ("escape", "symlink that leads outside the project"),
        ] {
            let error = sources::check_path_gem(&root, &gem(path)).unwrap_err();
            assert!(error.to_string().contains(why), "{path}: {error}");
        }
    }
}

/// Offline tests for the two rubygems.org checks (#348): the version reply
/// that supplies a digest, and the embedded gemspec that must name the
/// planned coordinate before a downloaded `.gem` is installed.
#[cfg(test)]
mod rubygems_check_tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A rubygems.org version reply for one coordinate, with the fields
    /// ward reads and the ones it ignores, all consistent with each other.
    fn api_reply(name: &str, number: &str, platform: &str, sha: &str) -> String {
        let full_name = if platform == "ruby" {
            format!("{name}-{number}")
        } else {
            format!("{name}-{number}-{platform}")
        };
        serde_json::json!({
            "name": name, "number": number, "platform": platform, "sha": sha,
            "gem_uri": format!("https://rubygems.org/gems/{full_name}.gem"),
        })
        .to_string()
    }

    #[test]
    fn an_api_reply_for_another_version_is_refused() {
        let body = api_reply("racc", "1.8.0", "ruby", SHA);
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "racc-1.8.1: api returned \"1.8.0\"-\"ruby\" instead");
    }

    #[test]
    fn an_api_reply_for_another_platform_is_refused() {
        // The racc 1.8.1 case that motivated the platform query: the bare
        // endpoint answers with the java gem, whose sha is not the ruby one.
        let body = api_reply("racc", "1.8.1", "java", SHA);
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "racc-1.8.1: api returned \"1.8.1\"-\"java\" instead");
    }

    #[test]
    fn an_api_reply_with_no_version_or_platform_field_is_refused() {
        // One field at a time: the other is correct, so only the missing or
        // mistyped one can be what refuses the reply.
        for (body, shown) in [
            (r#"{"platform": "ruby", "sha": "aa"}"#, "null-\"ruby\""),
            (
                r#"{"number": null, "platform": "ruby", "sha": "aa"}"#,
                "null-\"ruby\"",
            ),
            (
                r#"{"number": 1.81, "platform": "ruby", "sha": "aa"}"#,
                "1.81-\"ruby\"",
            ),
            (r#"{"number": "1.8.1", "sha": "aa"}"#, "\"1.8.1\"-null"),
            (
                r#"{"number": "1.8.1", "platform": null, "sha": "aa"}"#,
                "\"1.8.1\"-null",
            ),
            (
                r#"{"number": "1.8.1", "platform": ["ruby"], "sha": "aa"}"#,
                "\"1.8.1\"-[\"ruby\"]",
            ),
            (r#"[]"#, "null-null"),
        ] {
            let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", body)
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!("racc-1.8.1: api returned {shown} instead"),
                "{body}"
            );
        }
    }

    #[test]
    fn an_api_reply_without_a_string_sha_is_refused() {
        for sha in ["null", "123", "[]", "{}"] {
            let body = format!(r#"{{"number": "1.8.1", "platform": "ruby", "sha": {sha}}}"#);
            let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "racc-1.8.1: api has no sha", "{sha}");
        }
        let body = r#"{"number": "1.8.1", "platform": "ruby"}"#;
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", body)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "racc-1.8.1: api has no sha");
    }

    #[test]
    fn an_api_reply_that_is_not_json_is_refused() {
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", "<html>")
            .unwrap_err()
            .to_string();
        let serde = serde_json::from_str::<serde_json::Value>("<html>").unwrap_err();
        assert_eq!(error, format!("racc-1.8.1: api json: {serde}"));
    }

    #[test]
    fn control_a_matching_api_reply_yields_its_sha() {
        // Two replies with different digests: the value must come from the
        // reply, not from anywhere else.
        let body = api_reply("racc", "1.8.1", "ruby", SHA);
        let sha = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body).unwrap();
        assert_eq!(sha, SHA);
        // A platform-qualified coordinate matches its own variant.
        let body = api_reply("nokogiri", "1.18.10", "x86_64-linux", OTHER_SHA);
        let sha = digest_from_api_reply(
            "nokogiri-1.18.10-x86_64-linux",
            "1.18.10",
            "x86_64-linux",
            &body,
        )
        .unwrap();
        assert_eq!(sha, OTHER_SHA);
    }

    fn gem(name: &str, version: &str, platform: &str, full_name: &str) -> RubyGem {
        RubyGem {
            name: name.into(),
            version: version.into(),
            platform: platform.into(),
            full_name: full_name.into(),
            sha256: SHA.into(),
            digest_from_api: false,
            digest_in_lock: false,
        }
    }

    fn spec(name: &str, version: &str, platform: &str) -> Vec<u8> {
        serde_json::json!({
            "name": name, "version": version, "platform": platform,
            "executables": ["rake"], "extensions": [],
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_gemspec_naming_another_gem_version_or_platform_is_refused() {
        let planned = gem("rake", "13.2.1", "ruby", "rake-13.2.1");
        for (name, version, platform, shown) in [
            ("rack", "13.2.1", "ruby", "\"rack\" \"13.2.1\" \"ruby\""),
            ("rake", "13.2.0", "ruby", "\"rake\" \"13.2.0\" \"ruby\""),
            ("rake", "13.2.1", "java", "\"rake\" \"13.2.1\" \"java\""),
            ("Rake", "13.2.1", "ruby", "\"Rake\" \"13.2.1\" \"ruby\""),
        ] {
            let error = spec_matches_plan(&planned, &spec(name, version, platform))
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!("rake-13.2.1: embedded gemspec disagrees with the plan ({shown})"),
            );
        }
        // A field missing from the spec reads as null and disagrees too,
        // one at a time with the other two correct.
        for (body, shown) in [
            (
                r#"{"version": "13.2.1", "platform": "ruby"}"#,
                "null \"13.2.1\" \"ruby\"",
            ),
            (
                r#"{"name": "rake", "platform": "ruby"}"#,
                "\"rake\" null \"ruby\"",
            ),
            (
                r#"{"name": "rake", "version": "13.2.1"}"#,
                "\"rake\" \"13.2.1\" null",
            ),
        ] {
            let error = spec_matches_plan(&planned, body.as_bytes())
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!("rake-13.2.1: embedded gemspec disagrees with the plan ({shown})"),
                "{body}"
            );
        }
    }

    #[test]
    fn a_plan_full_name_that_is_not_the_canonical_spelling_is_refused() {
        // The gemspec agrees with name/version/platform, but the download
        // URL is built from full_name, so it must be the canonical spelling.
        for (platform, full_name) in [
            ("ruby", "rake-13.2.1-ruby"),
            ("ruby", "rake-13.2.0"),
            ("ruby", "rack-13.2.1"),
            ("x86_64-linux", "rake-13.2.1"),
            ("x86_64-linux", "rake-13.2.1-java"),
        ] {
            let planned = gem("rake", "13.2.1", platform, full_name);
            let error = spec_matches_plan(&planned, &spec("rake", "13.2.1", platform))
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!(
                    "{full_name}: embedded gemspec disagrees with the plan \
                     (\"rake\" \"13.2.1\" \"{platform}\")"
                ),
                "{full_name}"
            );
        }
    }

    #[test]
    fn a_gemspec_that_is_not_json_is_refused() {
        let planned = gem("rake", "13.2.1", "ruby", "rake-13.2.1");
        let error = spec_matches_plan(&planned, b"not json")
            .unwrap_err()
            .to_string();
        let serde = serde_json::from_slice::<serde_json::Value>(b"not json").unwrap_err();
        assert_eq!(error, format!("rake-13.2.1: spec json: {serde}"));
    }

    #[test]
    fn control_a_matching_gemspec_yields_executables_and_the_native_flag() {
        let planned = gem("rake", "13.2.1", "ruby", "rake-13.2.1");
        let (executables, native) =
            spec_matches_plan(&planned, &spec("rake", "13.2.1", "ruby")).unwrap();
        assert_eq!(executables, ["rake"]);
        assert!(!native, "an empty extensions list is pure ruby");

        let qualified = gem(
            "nokogiri",
            "1.18.10",
            "x86_64-linux",
            "nokogiri-1.18.10-x86_64-linux",
        );
        let body = serde_json::json!({
            "name": "nokogiri", "version": "1.18.10", "platform": "x86_64-linux",
            "executables": ["nokogiri", 7], "extensions": ["ext/nokogiri/extconf.rb"],
        })
        .to_string();
        let (executables, native) = spec_matches_plan(&qualified, body.as_bytes()).unwrap();
        assert_eq!(
            executables,
            ["nokogiri"],
            "a non-string executable is dropped"
        );
        assert!(native);

        // A spec that does not list extensions at all is treated as native.
        let body = br#"{"name": "rake", "version": "13.2.1", "platform": "ruby"}"#;
        let (executables, native) = spec_matches_plan(&planned, body).unwrap();
        assert!(executables.is_empty());
        assert!(native);
    }
}
