//! The Elixir tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a Mix project.

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
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::toolchain::{Request, Version, VersionRequest};
use crate::kernel::ui;
use crate::tailors::elixir;
use crate::tailors::{
    Attester, ClosureListing, FileRunner, LoneFile, PackageRow, SourceFile, SyncRequest, Tailor,
};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Elixir;

/// What `sync` and `build` share: realize the BEAM pair and the Hex deps,
/// then project them. Projection writes only the store forest and the
/// closure, which is published through the descriptor the command holds.
/// Returns the BEAM object and the projection.
fn realize_and_project(
    ctx: &Context,
    project: &ProjectRoot,
    toolchain: &Selected,
    fresh: bool,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<(PathBuf, PathBuf)> {
    let (activity, platform, store) = (&ctx.activity, ctx.platform, &ctx.store);
    let beam = elixir::realize_runtime(store, activity, platform, toolchain)?;
    let mut door = ResolutionDoor::open(store, activity, platform, DoorKind::Planner, attribution)?;
    let (plan, lock_sha256, basis) = elixir::plan_elixir(&mut door, project, &beam, toolchain)?;
    // The planner checks ran detached; their ledgers are evidence of this
    // sync's planning, rooted here so GC keeps them.
    let ledgers = door.take_kept_ledgers();
    drop(door);
    for objects in &ledgers {
        crate::kernel::resolve::ledger::root(store, activity, project, objects)?;
    }
    let deps = elixir::realize_deps(store, activity, platform, &plan, &beam, toolchain)?;
    let projection = elixir::project_elixir_env(
        activity,
        platform,
        project,
        &beam,
        &deps,
        &plan,
        &lock_sha256,
        &basis,
        fresh,
        toolchain,
        &ledgers,
        attribution,
    )?;
    Ok((beam, projection))
}

impl Attester for Elixir {
    fn attest_lock(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _host: &dyn crate::tailors::EditHost,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        let beam = elixir::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        elixir::attest_project(door, project, &beam, toolchain)
    }
}

impl Tailor for Elixir {
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
        "elixir"
    }

    /// mix.exs and mix.lock: what `mix deps.get` resolves from and
    /// writes. Hex's own configuration is the run's scratch, never the
    /// host's.
    fn resolution_outputs(&self, _project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        Ok(vec!["mix.exs".into(), "mix.lock".into()])
    }

    /// The `config/*.exs` files mix evaluates before it reads the deps.
    fn resolution_inputs(&self, project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        super::resolve::resolution_inputs(project)
    }

    fn attester(&self) -> Option<&dyn Attester> {
        Some(self)
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(project.is_input_file(Path::new("mix.exs")))
    }

    fn toolchain_sources(&self) -> Sources {
        Sources {
            discover: toolchain_rows,
            request: toolchain_request,
        }
    }

    fn input_files(&self) -> &'static str {
        "mix.exs"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        // .exs is a script; .ex is a compiled module of a Mix project and
        // has no meaning on its own. `mix run` rather than `elixir`: a bare
        // `elixir` loads none of the project's deps, and the projection
        // only reaches the script through Mix.
        &[SourceFile {
            extension: "exs",
            runner: FileRunner::Command(&["mix", "run"]),
        }]
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        elixir::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        let beam = elixir::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        if elixir::require_lock(project).is_ok() {
            return elixir::relock_if_stale(door, project, &beam, toolchain);
        }
        elixir::generate_lock(door, project, &beam, toolchain)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let activity = &ctx.activity;
        elixir::require_lock(project)?;
        let beam = elixir::realize_runtime(&ctx.store, activity, ctx.platform, toolchain)?;
        let (plan, _, _) = elixir::plan_elixir(door, project, &beam, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        elixir::require_lock(project)?;
        let (_, projection) =
            realize_and_project(ctx, project, request.toolchain, request.fresh, attribution)?;
        ui::synced("hex deps", &projection);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        Ok(cwd.ancestors().any(|d| d.join("mix.exs").is_file()))
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd
            .ancestors()
            .find(|dir| dir.join("mix.exs").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no mix.exs found from here upward")
            })?
            .to_path_buf())
    }

    fn build(
        &self,
        ctx: &Context,
        root: &Path,
        _cwd: &Path,
        args: &[String],
        toolchain: &Selected,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        let project = ProjectRoot::open(root)?;
        let (beam, projection) = realize_and_project(ctx, &project, toolchain, false, attribution)?;
        elixir::build_sandboxed(
            ctx.platform,
            &ctx.activity,
            &project,
            &beam,
            &projection,
            args,
            toolchain,
        )
    }

    /// A lone script runs with `elixir`, not `mix run`, which needs a
    /// project: no deps, OTP on PATH beside it, and the same scrubbed
    /// environment and private home as `ward run` gives a project.
    fn lone_file(
        &self,
        ctx: &Context,
        toolchain: &Selected,
        _extension: &str,
    ) -> io::Result<Option<LoneFile>> {
        let beam = elixir::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        let scratch = ctx.store.run_home(&ctx.project_dir()?, "elixir")?;
        elixir::prepare_run_home(&scratch)?;
        let (remove_prefixes, remove, env) = elixir::lone_env(&beam, &scratch);
        Ok(Some(LoneFile {
            program: vec![beam
                .join("elixir/bin/elixir")
                .to_string_lossy()
                .into_owned()],
            path: vec![beam.join("elixir/bin"), beam.join("otp/bin")],
            remove_prefixes,
            remove,
            env,
        }))
    }

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["mix", "elixir", "iex", "erl"]
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
        if let Some(closure) = comforter::read_closure_if_present(project, "elixir")? {
            let store = &ctx.store;
            let beam = comforter::closure_object(
                store,
                activity,
                &closure,
                "beam_object",
                "elixir/bin/mix",
            )?;
            // The deps projection is a writable clone OUTSIDE the store; verify
            // it lives under the ward home and matches the recorded deps id.
            let deps_obj = comforter::closure_object(store, activity, &closure, "deps_object", "")?;
            // Never trust the recorded projection path: reconstruct the ONE
            // expected forest path from canonical project + deps id and require
            // exact canonical equality — lexical checks admit foreign forests,
            // dot-dot tricks, and symlinked dirs.
            let projection = elixir::expected_projection(store, dir, &deps_obj)?;
            let recorded = closure["deps_projection"].as_str().map(PathBuf::from);
            if recorded.as_deref().and_then(|p| p.canonicalize().ok()) != Some(projection.clone())
                || !projection.is_dir()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "elixir closure projection is not the expected forest path; \
                     run `ward` first",
                ));
            }
            prefix.push(beam.join("elixir/bin").to_string_lossy().into_owned());
            prefix.push(beam.join("otp/bin").to_string_lossy().into_owned());
            // A private per-project home inside the store: a HOME under
            // the shared temp root lets another user plant `.erlang` or
            // `.iex.exs` that Erlang and Elixir run at startup as this
            // user, and a per-process one would make `ward env` print
            // different bytes on every call.
            let scratch = ctx.store.run_home(dir, "elixir")?;
            elixir::prepare_run_home(&scratch)?;
            // The build root belongs to the toolchain this closure was
            // synced with, not to whatever the catalog offers now.
            let fingerprint = closure["beam_fingerprint"].as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "elixir closure records no toolchain fingerprint; run `ward`",
                )
            })?;
            let (prefixes, remove, set) = elixir::run_env(
                &beam,
                &projection,
                &elixir::build_root_at(dir, fingerprint),
                &scratch,
            )?;
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        elixir::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("elixir".into(), string(&plan["elixir_version"])));
        out.toolchain
            .push(("otp".into(), string(&plan["otp_version"])));
        for package in plan["deps"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["package"]),
                version: string(&package["version"]),
                detail: string(&package["app"]),
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
            &["beam_object", "deps_object"],
            "mix.lock",
            "mix_lock_sha256",
        )
    }

    /// Hex names are lowercase already and compared as they are.
    fn popular(&self) -> Option<&'static crate::kernel::lookalike::Popular> {
        static POPULAR: std::sync::OnceLock<crate::kernel::lookalike::Popular> =
            std::sync::OnceLock::new();
        Some(POPULAR.get_or_init(|| {
            crate::kernel::lookalike::Popular::parse(include_str!("popular.txt"), str::to_string)
        }))
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "deps")? {
            let (name, ver) = (required(eco, &p, "package")?, required(eco, &p, "version")?);
            let mut c = component(
                &name,
                &ver,
                format!(
                    "pkg:hex/{}@{}",
                    purl_encode(&name.to_ascii_lowercase()),
                    purl_encode(&ver)
                ),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "outer_sha256")?);
            push_property(
                &mut c,
                "greyward:hex:inner-checksum",
                &required(eco, &p, "inner_sha256")?,
            );
            out.push(c);
        }
        let beam_version = format!(
            "otp-{}-elixir-{}",
            version_of(eco, plan, "otp_version")?,
            version_of(eco, plan, "elixir_version")?,
        );
        out.push(toolchain_component(
            body,
            "beam_object",
            "beam",
            &beam_version,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["beam"]
    }
}

/// The files this ecosystem's toolchain version is read from, in its own
/// tools' precedence order ([`Tailor::toolchain_sources`]).
fn toolchain_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    use crate::kernel::toolchain::input::{read_tool_versions, row_for};
    Ok(vec![
        row_for(root, ".tool-versions", "erlang", |bytes| {
            read_tool_versions(bytes, "erlang")
        })?,
        row_for(root, ".tool-versions", "elixir", |bytes| {
            read_tool_versions(bytes, "elixir")
        })?,
    ])
}

/// The selection request [`toolchain_rows`] state.
///
/// asdf and mise accept a `v` before either version (`elixir v1.19.4`) and
/// an Elixir build tag naming the OTP major it was compiled for
/// (`1.19.4-otp-27`). The tag constrains the OTP major: with no `erlang`
/// line it selects the newest OTP of that major, and an `erlang` line on
/// another major is refused, since no build pairs the two.
fn toolchain_request(rows: &[InputRow]) -> io::Result<Request> {
    use crate::kernel::toolchain::resolve::{exact_or_prefix, parse_version, value, UPDATE_HINT};
    let erlang = value(rows, ".tool-versions", "erlang")
        .map(|text| parse_version(".tool-versions erlang", strip_v(text)))
        .transpose()?;
    let elixir = value(rows, ".tool-versions", "elixir")
        .map(parse_elixir_tool_version)
        .transpose()?;
    let otp_major = elixir.as_ref().and_then(|(_, major)| major.clone());
    let mut request = Request::newest();
    match (erlang, otp_major) {
        (Some(erlang), Some(major)) if erlang.parts().first() != major.parts().first() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    ".tool-versions: elixir is built for OTP {major} (-otp-{major}) but \
                     erlang asks for {erlang}; make the two agree, then {UPDATE_HINT}"
                ),
            ));
        }
        (Some(erlang), _) => request = request.with("otp", exact_or_prefix(erlang)),
        (None, Some(major)) => request = request.with("otp", VersionRequest::Prefix(major)),
        (None, None) => {}
    }
    if let Some((elixir, _)) = elixir {
        request = request.with("elixir", exact_or_prefix(elixir));
    }
    Ok(request)
}

/// asdf's and mise's optional `v` before a version number.
fn strip_v(text: &str) -> &str {
    text.strip_prefix('v')
        .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(text)
}

/// An Elixir `.tool-versions` value (`1.19.4`, `v1.19.4`, `1.19.4-otp-27`,
/// `1.19-otp-28`): the Elixir version, and the OTP major its build tag
/// names. The tag is one number, as in Elixir's release asset names.
fn parse_elixir_tool_version(text: &str) -> io::Result<(Version, Option<Version>)> {
    use crate::kernel::toolchain::resolve::parse_version;
    let stripped = strip_v(text);
    let Some((version, tag)) = stripped.split_once("-otp-") else {
        return Ok((parse_version(".tool-versions elixir", stripped)?, None));
    };
    let major = parse_version(".tool-versions elixir OTP tag", tag)?;
    if major.parts().len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                ".tool-versions elixir: {text:?}: the -otp- tag names an OTP major (`-otp-27`), \
                 not {tag:?}; run `ward update --toolchain`"
            ),
        ));
    }
    Ok((
        parse_version(".tool-versions elixir", version)?,
        Some(major),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(erlang: Option<&str>, elixir: Option<&str>) -> Vec<InputRow> {
        let row = |field: &str, value: Option<&str>| InputRow {
            path: PathBuf::from(".tool-versions"),
            field: field.into(),
            value: value.map(str::to_string),
            absent: value.is_none(),
            sha256: Some("0".repeat(64)),
        };
        vec![row("erlang", erlang), row("elixir", elixir)]
    }

    fn request(erlang: Option<&str>, elixir: Option<&str>) -> io::Result<String> {
        toolchain_request(&rows(erlang, elixir)).map(|request| request.to_string())
    }

    #[test]
    fn a_v_prefix_is_accepted_on_either_line() {
        assert_eq!(
            request(Some("v27.3.4"), Some("v1.19.4")).unwrap(),
            request(Some("27.3.4"), Some("1.19.4")).unwrap()
        );
        assert!(request(None, Some("vx1.19")).is_err());
        assert!(request(None, Some("v")).is_err());
    }

    #[test]
    fn an_otp_tag_constrains_the_otp_major() {
        let tagged = toolchain_request(&rows(None, Some("1.19.4-otp-27"))).unwrap();
        let otp = &tagged
            .components
            .iter()
            .find(|(c, _)| c == "otp")
            .unwrap()
            .1;
        assert_eq!(*otp, VersionRequest::Prefix(Version::parse("27").unwrap()));
        assert!(otp.matches(&Version::parse("27.3.4.1").unwrap()));
        assert!(!otp.matches(&Version::parse("28.0").unwrap()));
        assert_eq!(
            request(None, Some("v1.19.4-otp-27")).unwrap(),
            tagged.to_string()
        );
        // An erlang line on the same major is the narrower request.
        let both = request(Some("27.3.4"), Some("1.19.4-otp-27")).unwrap();
        assert_eq!(both, request(Some("27.3.4"), Some("1.19.4")).unwrap());
    }

    #[test]
    fn an_otp_tag_on_another_major_than_erlang_is_refused() {
        let why = request(Some("28.1"), Some("1.19.4-otp-27"))
            .unwrap_err()
            .to_string();
        assert!(why.contains("OTP 27") && why.contains("28.1"), "{why}");
    }

    #[test]
    fn a_malformed_otp_tag_is_refused() {
        assert!(request(None, Some("1.19.4-otp-")).is_err());
        assert!(request(None, Some("1.19.4-otp-27.1")).is_err());
        assert!(request(None, Some("1.19.4-otp-x")).is_err());
    }
}
