//! The Ruby tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for a Bundler project.

use crate::comforter;
use crate::comforter::status::{standard_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, push_property, required, toolchain_component,
    version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::sandbox;
use crate::kernel::toolchain::input::{InputRow, Sources};
use crate::kernel::toolchain::Request;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::ruby;
use crate::tailors::{
    Attester, ClosureListing, FileRunner, LoneFile, PackageRow, SourceFile, SyncRequest, Tailor,
};
use serde_json::Value;
use std::io;
use std::path::Path;
use std::process::Command;

pub struct Ruby;

impl Attester for Ruby {
    fn attest_lock(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &crate::kernel::toolchain::Selected,
        _host: &dyn crate::tailors::EditHost,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        let ruby_obj = ruby::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        ruby::attest_project(door, project, &ruby_obj, toolchain)
    }
}

impl Tailor for Ruby {
    fn package_registry(&self) -> Option<crate::tailors::PackageRegistry> {
        Some(super::edit::REGISTRY)
    }

    fn registry_exists(&self, name: &str) -> io::Result<Option<String>> {
        super::edit::registry_exists(name)
    }

    fn edit_manifest(
        &self,
        _ctx: &crate::kernel::context::Context,
        edit: &crate::tailors::ManifestEdit<'_>,
        door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<crate::tailors::EditOutcome> {
        super::edit::edit_manifest(edit, door)
    }

    fn id(&self) -> &'static str {
        "ruby"
    }

    /// Manifest and lock outputs, plus every visible regular project input
    /// because Gemfiles can load other files while evaluating dependencies.
    fn resolution_outputs(&self, _project: &ProjectRoot) -> io::Result<Vec<std::path::PathBuf>> {
        Ok(vec!["Gemfile".into(), "Gemfile.lock".into()])
    }

    fn resolution_inputs(&self, project: &ProjectRoot) -> io::Result<Vec<std::path::PathBuf>> {
        super::resolve::resolution_inputs(project)
    }

    fn attester(&self) -> Option<&dyn Attester> {
        Some(self)
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(project.is_input_file(Path::new("Gemfile")))
    }

    fn toolchain_sources(&self) -> Sources {
        Sources {
            discover: toolchain_rows,
            request: toolchain_request,
        }
    }

    fn input_files(&self) -> &'static str {
        "Gemfile"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        &[SourceFile {
            extension: "rb",
            runner: FileRunner::Command(&["ruby"]),
        }]
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        ruby::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        if ruby::require_lock(project).is_ok() {
            return Ok(());
        }
        let ruby_obj = ruby::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        ruby::generate_lock(door, project, &ruby_obj, toolchain)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let activity = &ctx.activity;
        ruby::require_lock(project)?;
        let ruby_obj = ruby::realize_runtime(&ctx.store, activity, ctx.platform, toolchain)?;
        let (plan, _, _) = ruby::plan_ruby(door, project, &ruby_obj, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let activity = &ctx.activity;
        let toolchain = request.toolchain;
        let platform = ctx.platform;
        let store = &ctx.store;
        ruby::require_lock(project)?;
        let ruby_obj = ruby::realize_runtime(store, activity, platform, toolchain)?;
        let mut door =
            ResolutionDoor::open(store, activity, platform, DoorKind::Planner, attribution)?;
        let (plan, lock_sha256, basis) = ruby::plan_ruby(&mut door, project, &ruby_obj, toolchain)?;
        // The planner checks ran detached; their ledgers are evidence of
        // this sync's planning, rooted here so GC keeps them.
        let ledgers = door.take_kept_ledgers();
        drop(door);
        for objects in &ledgers {
            crate::kernel::resolve::ledger::root(store, activity, project, objects)?;
        }
        // Before any gem is fetched: a policy that requires lock-pinned
        // digests stops here.
        ruby::record_unpinned_digests(&plan, |kind, subject, detail| {
            attribution.record(kind, subject, detail)
        })?;
        // Before any git source is fetched: a policy that denies
        // `git-dependency` stops here.
        ruby::record_git_dependencies(&plan)?;
        let gems = ruby::realize_gems(store, activity, platform, &plan, &ruby_obj, toolchain)?;
        ruby::project_ruby_env(
            activity,
            project,
            &ruby_obj,
            &gems,
            &plan,
            &lock_sha256,
            &basis,
            toolchain,
            &ledgers,
            attribution,
        )?;
        ui::synced("gems", &gems);
        Ok(true)
    }

    /// A lone script runs on the interpreter alone, with no gems: an
    /// empty gem home in the store's run home for this directory, and the
    /// host's RUBYOPT, GEM_PATH and Bundler settings removed as `ward run`
    /// removes them.
    fn lone_file(
        &self,
        ctx: &Context,
        toolchain: &Selected,
        _extension: &str,
    ) -> io::Result<Option<LoneFile>> {
        let runtime = ruby::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        let gem_home = ctx
            .store
            .run_home(&ctx.project_dir()?, "ruby")?
            .join("gems");
        std::fs::create_dir_all(&gem_home)?;
        Ok(Some(
            LoneFile::in_bin(&runtime, "ruby").scrubbed(ruby::lone_env(&gem_home)),
        ))
    }

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["ruby", "gem", "bundle"]
    }

    fn run_env(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let dir = project.path();
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        if let Some(closure) = comforter::read_closure_if_present(project, "ruby")? {
            let ruby_obj = comforter::closure_object(
                &ctx.store,
                activity,
                &closure,
                "ruby_object",
                "bin/ruby",
            )?;
            let gems_obj =
                comforter::closure_object(&ctx.store, activity, &closure, "gems_object", "")?;
            // Ruby FIRST, then gem binstubs (a gem exe must never shadow ruby).
            prefix.push(ruby_obj.join("bin").to_string_lossy().into_owned());
            prefix.push(gems_obj.join("bin").to_string_lossy().into_owned());
            let (prefixes, remove, set) = ruby::run_env(dir, &gems_obj);
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        ruby::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("ruby".into(), string(&plan["ruby_version"])));
        out.toolchain
            .push(("bundler".into(), string(&plan["bundler_version"])));
        for package in plan["gems"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["name"]),
                version: string(&package["version"]),
                detail: string(&package["full_name"]),
            });
        }
        for package in plan["path_gems"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["name"]),
                version: string(&package["version"]),
                detail: format!("path: {}", string(&package["path"])),
            });
        }
        for package in plan["git_gems"].as_array().unwrap_or(&empty) {
            let revision = string(&package["revision"]);
            out.packages.push(PackageRow {
                name: string(&package["name"]),
                version: string(&package["version"]),
                detail: format!(
                    "git: {} at {}",
                    super::sources::git_url(&string(&package["url"])),
                    revision.get(..12).unwrap_or(&revision)
                ),
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
        standard_state(
            project,
            body,
            &["ruby_object", "gems_object"],
            "Gemfile.lock",
            "gemfile_lock_sha256",
        )
    }

    /// RubyGems refuses a name that differs from a taken one by case only.
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
        for p in list(eco, plan, "gems")? {
            let (name, ver, platform) = (
                required(eco, &p, "name")?,
                required(eco, &p, "version")?,
                required(eco, &p, "platform")?,
            );
            let qualifier = if platform.is_empty() || platform == "ruby" {
                String::new()
            } else {
                format!("?platform={}", purl_encode(&platform))
            };
            let mut c = component(
                &name,
                &ver,
                format!(
                    "pkg:gem/{}@{}{}",
                    purl_encode(&name),
                    purl_encode(&ver),
                    qualifier
                ),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "sha256")?);
            out.push(c);
        }
        let optional = |key: &str| -> io::Result<Vec<Value>> {
            match plan.get(key) {
                None => Ok(Vec::new()),
                Some(_) => list(eco, plan, key),
            }
        };
        // A path gem is the project's own code, not the registry's: a
        // registry purl would name a package that may exist there with
        // other contents. Its identity is its directory, as a Node `file:`
        // package's is.
        for p in optional("path_gems")? {
            let (name, ver) = (required(eco, &p, "name")?, required(eco, &p, "version")?);
            let mut c = component(&name, &ver, String::new(), eco);
            c.as_object_mut().unwrap().remove("purl");
            push_property(&mut c, "greyward:local", &required(eco, &p, "path")?);
            out.push(c);
        }
        // A git gem's purl says which repository and commit it is
        // (`vcs_url`, per the purl spec).
        for p in optional("git_gems")? {
            let (name, ver) = (required(eco, &p, "name")?, required(eco, &p, "version")?);
            // Named as ward fetched it, without credentials the lock's
            // remote may carry.
            let vcs = format!(
                "git+{}@{}",
                super::sources::git_url(&required(eco, &p, "url")?),
                required(eco, &p, "revision")?
            );
            out.push(component(
                &name,
                &ver,
                format!(
                    "pkg:gem/{}@{}?vcs_url={}",
                    purl_encode(&name),
                    purl_encode(&ver),
                    purl_encode(&vcs)
                ),
                eco,
            ));
        }
        out.push(toolchain_component(
            body,
            "ruby_object",
            "ruby",
            &version_of(eco, plan, "ruby_version")?,
        )?);
        // The Bundler the lock was written with, when ward provisioned it:
        // a rubygems.org gem installed into the gems object.
        if let Some(bundler) = plan.get("bundler").filter(|value| !value.is_null()) {
            let version = required(eco, bundler, "version")?;
            let mut c = component(
                super::bundler::NAME,
                &version,
                format!("pkg:gem/bundler@{}", purl_encode(&version)),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, bundler, "sha256")?);
            out.push(c);
        }
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["ruby"]
    }
}

/// The files this ecosystem's toolchain version is read from, in its own
/// tools' precedence order ([`Tailor::toolchain_sources`]).
fn toolchain_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    use crate::kernel::toolchain::input::{read_ruby_version, read_tool_versions, row_for};
    Ok(vec![
        row_for(root, ".ruby-version", "version", read_ruby_version)?,
        row_for(root, ".tool-versions", "ruby", |bytes| {
            read_tool_versions(bytes, "ruby")
        })?,
    ])
}

/// The selection request [`toolchain_rows`] state.
fn toolchain_request(rows: &[InputRow]) -> io::Result<Request> {
    use crate::kernel::toolchain::invalid;
    use crate::kernel::toolchain::resolve::{exact_or_prefix, parse_version, value, UPDATE_HINT};
    let mut request = Request::newest();
    let pinned = value(rows, ".ruby-version", "version");
    let tools = value(rows, ".tool-versions", "ruby");
    if let (Some(a), Some(b)) = (pinned, tools) {
        if a != b {
            return Err(invalid(format!(
                ".ruby-version says {a} and .tool-versions says {b}; make them agree, then {UPDATE_HINT}"
            )));
        }
    }
    if let Some(text) = pinned.or(tools) {
        request = request.with(
            "ruby",
            exact_or_prefix(parse_version(".ruby-version", text)?),
        );
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body() -> Value {
        json!({
            "ruby_object": "/store/objects/abc123-ruby-3.4.6",
            "plan": {
                "ruby_version": "3.4.6",
                "bundler_version": "2.6.9",
                "gems": [{"name": "rake", "version": "13.2.1", "platform": "ruby",
                          "full_name": "rake-13.2.1", "sha256": "a".repeat(64)}],
                "path_gems": [{"name": "app", "version": "1.0.0", "path": "."}],
                "git_gems": [{"name": "rack", "version": "3.2.0",
                              "url": "https://user:token@github.com/rack/rack.git",
                              "revision": "0123456789abcdef0123456789abcdef01234567",
                              "checkout": "rack-0123456789ab"}],
            },
        })
    }

    /// A path gem is the project's own code: no registry purl, its
    /// directory instead. A git gem names its repository and commit, never
    /// the credentials its lock remote carries.
    #[test]
    fn sbom_components_name_where_path_and_git_gems_come_from() {
        let mut out = Vec::new();
        Ruby.sbom_components("ruby", &body(), &mut out).unwrap();
        let named = |name: &str| out.iter().find(|c| c["name"] == name).unwrap().clone();
        assert_eq!(named("rake")["purl"], "pkg:gem/rake@13.2.1");
        let app = named("app");
        assert!(app.get("purl").is_none(), "{app}");
        assert!(app["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "greyward:local" && p["value"] == "."));
        assert_eq!(
            named("rack")["purl"],
            "pkg:gem/rack@3.2.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Frack%2Frack.git%400123456789abcdef0123456789abcdef01234567"
        );
        // A closure written before #771 has neither list.
        let mut old = body();
        let plan = old["plan"].as_object_mut().unwrap();
        plan.remove("path_gems");
        plan.remove("git_gems");
        let mut out = Vec::new();
        Ruby.sbom_components("ruby", &old, &mut out).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn the_listing_shows_path_and_git_gems() {
        let listing = Ruby.listing("ruby", &body());
        let details: Vec<&str> = listing.packages.iter().map(|p| p.detail.as_str()).collect();
        assert_eq!(
            details,
            [
                "rake-13.2.1",
                "path: .",
                "git: https://github.com/rack/rack.git at 0123456789ab"
            ]
        );
    }
}
