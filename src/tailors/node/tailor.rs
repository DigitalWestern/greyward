//! The Node tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for an npm/pnpm/Yarn project.

use crate::comforter;
use crate::comforter::status::{recorded_inputs_state, string, State};
use crate::kernel::activity::StoreActivity;
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, purl_encode_path, push_property, required, toolchain_component,
    version_of,
};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::input::{InputRow, Sources};
use crate::kernel::toolchain::Request;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::node::{self as node, inputs};
use crate::tailors::{
    Attester, ClosureListing, FileRunner, LoneFile, PackageRow, RegistryTool, ScriptRun,
    SourceFile, SyncRequest, Tailor,
};
use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const NODE_INPUTS: &[&str] = &[
    "package.json",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

pub struct Node;

/// The package.json `ward run` reads scripts from, as (canonical path,
/// text): only under a `node_modules` projection whose closure reads back,
/// and only when `dir` has a package.json.
fn projected_package_json(dir: &Path, cwd: &Path) -> io::Result<Option<(PathBuf, String)>> {
    let (node_projected, _) = projected_node_modules(dir, cwd);
    if !node_projected {
        return Ok(None);
    }
    comforter::read_closure(dir, "node")?;
    let path = dir.join("package.json");
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    Ok(Some((path.canonicalize()?, std::fs::read_to_string(path)?)))
}

/// Is `dir/node_modules` a ward projection, and which `node_modules`
/// between `cwd` and `dir` should lead PATH? `ward run` works from
/// workspace subdirectories like npm run does: the nearest projected
/// `node_modules` inside the same forest wins, falling back to the root's.
pub fn projected_node_modules(dir: &Path, cwd: &Path) -> (bool, PathBuf) {
    let nm = dir.join("node_modules");
    let node_projected = std::fs::symlink_metadata(&nm)
        .map(|md| md.file_type().is_symlink())
        .unwrap_or(false)
        && std::fs::symlink_metadata(dir.join(".greyward/closures/node.json")).is_ok();
    let nearest_nm = if node_projected {
        let forest_root = nm
            .canonicalize()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        cwd.ancestors()
            .take_while(|path| path.starts_with(dir))
            .map(|path| path.join("node_modules"))
            .find(|path| {
                std::fs::symlink_metadata(path)
                    .map(|md| md.file_type().is_symlink())
                    .unwrap_or(false)
                    && forest_root
                        .as_ref()
                        .and_then(|root| {
                            path.canonicalize().ok().map(|path| path.starts_with(root))
                        })
                        .unwrap_or(false)
            })
            .unwrap_or_else(|| nm.clone())
    } else {
        nm.clone()
    };
    (node_projected, nearest_nm)
}

fn projected_node_modules_in(project: &ProjectRoot, cwd: &Path) -> io::Result<(bool, PathBuf)> {
    let root = project.current_name()?;
    let nm = root.join("node_modules");
    let node_projected = project.entry(Path::new("node_modules"))? == Entry::Symlink
        && comforter::has_closure(project, "node")?;
    if node_projected {
        let forest = held_link_target(project, Path::new("node_modules"))
            .and_then(|path| path.parent().map(Path::to_path_buf));
        if let Some(relative) = project.relative(cwd) {
            for dir in relative.ancestors() {
                let relative_nm = dir.join("node_modules");
                if project.entry(&relative_nm)? == Entry::Symlink
                    && forest.as_ref().is_some_and(|forest| {
                        held_link_target(project, &relative_nm)
                            .is_some_and(|target| target.starts_with(forest))
                    })
                {
                    return Ok((true, root.join(relative_nm)));
                }
            }
        }
    }
    Ok((node_projected, nm))
}

impl Attester for Node {
    /// npm's lock-only install with the lock unchanged, or pnpm's frozen
    /// lock-only install, at the lock root, on the Node the selection
    /// names.
    fn attest_lock(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        host: &dyn crate::tailors::EditHost,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        super::resolve::attest_project(door, project, host, toolchain)
    }
}

impl Tailor for Node {
    fn package_registry(&self) -> Option<crate::tailors::PackageRegistry> {
        Some(super::edit::REGISTRY)
    }

    fn registry_exists(&self, name: &str) -> io::Result<Option<String>> {
        super::edit::registry_exists(name)
    }

    fn claims_package_name(&self, name: &str) -> bool {
        super::edit::claims_package_name(name)
    }

    fn edit_root(&self, project: &Path) -> io::Result<std::path::PathBuf> {
        super::edit::edit_root(project)
    }

    fn edit_manifest(
        &self,
        _ctx: &crate::kernel::context::Context,
        edit: &crate::tailors::ManifestEdit<'_>,
        door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<crate::tailors::EditOutcome> {
        super::edit::edit_manifest(edit, door)
    }

    fn resolution_outputs(&self, project: &ProjectRoot) -> io::Result<Vec<std::path::PathBuf>> {
        super::resolve::resolution_outputs(project)
    }

    fn resolution_inputs(&self, project: &ProjectRoot) -> io::Result<Vec<std::path::PathBuf>> {
        super::resolve::resolution_inputs(project)
    }

    fn attester(&self) -> Option<&dyn Attester> {
        Some(self)
    }

    fn id(&self) -> &'static str {
        "node"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(NODE_INPUTS
            .iter()
            .any(|name| project.is_input_file(Path::new(name))))
    }

    fn toolchain_sources(&self) -> Sources {
        Sources {
            discover: toolchain_rows,
            request: toolchain_request,
        }
    }

    fn input_files(&self) -> &'static str {
        "package.json, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        // Node runs TypeScript itself by stripping the types, so which
        // command runs a .ts file depends on the project's Node.
        const NODE: FileRunner = FileRunner::Command(&["node"]);
        const TYPESCRIPT: FileRunner = FileRunner::ByVersion(typescript_runner);
        &[
            SourceFile {
                extension: "js",
                runner: NODE,
            },
            SourceFile {
                extension: "mjs",
                runner: NODE,
            },
            SourceFile {
                extension: "cjs",
                runner: NODE,
            },
            SourceFile {
                extension: "ts",
                runner: TYPESCRIPT,
            },
            SourceFile {
                extension: "mts",
                runner: TYPESCRIPT,
            },
            SourceFile {
                extension: "cts",
                runner: TYPESCRIPT,
            },
        ]
    }

    /// `ward x` resolves from the public registry and projects into its own
    /// cache directory (`registry_tool.rs`).
    fn registry_tool(&self) -> io::Result<&'static dyn RegistryTool> {
        Ok(&node::registry_tool::NodeTool)
    }

    /// node-gyp runs on a Python.
    fn helpers(&self) -> &'static [&'static str] {
        &["python"]
    }

    /// A project without Python gets the shipped 3.12 line for node-gyp.
    fn default_helper(&self, helper: &str) -> io::Result<Option<Selected>> {
        match helper {
            "python" => node::shipped_gyp_python().map(Some),
            _ => Ok(None),
        }
    }

    fn preflight(&self, platform: Platform, project: &ProjectRoot) -> io::Result<()> {
        node::preflight(platform)?;
        // A workspace member with no lock of its own is sent to the root
        // here, before the sync writes anything into it.
        if inputs::needs_lock(project) {
            inputs::refuse_member_lock_generation(project)?;
        }
        // A workspace whose members ward cannot name refuses here, before
        // anything is realized: the closure writer would refuse it later.
        super::resolve::check_members_readable(project)
    }

    fn prepare(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        // A missing lock is generated by the npm bundled in the Node this
        // project's toolchain selection names.
        inputs::ensure_npm_lock(project, toolchain, door)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let Some(plan) = inputs::load_npm_plan(ctx.platform, project, toolchain)? else {
            inputs::require_lock(project)?;
            return Ok(None);
        };
        node::freshness::check_lock_freshness(project, &plan)?;
        let v: Vec<_> = plan
            .packages
            .iter()
            .map(|p| {
                json!({"path": p.path, "version": p.version,
                                   "url": p.url, "integrity": p.integrity})
            })
            .collect();
        Ok(Some(serde_json::to_string_pretty(&json!({
            "ecosystem": "node", "node_version": plan.node_version,
            "lock_source": plan.lock_source, "packages": v
        }))?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let activity = &ctx.activity;
        let fresh = request.fresh;

        let platform = ctx.platform;
        let store = &ctx.store;
        // The Node this sync plans with and realizes is the row the
        // project's toolchain selection names, not the pin table.
        let selected = request.toolchain;
        // The plan and the closure's resolution basis come from one read of
        // the lock: a lock swapped in while this sync realizes is not what
        // the closure was planned from, and the join refuses it.
        let Some(inputs::Planned { plan, basis }) =
            inputs::load_npm_plan_with_basis(platform, project, selected)?
        else {
            inputs::require_lock(project)?;
            return Ok(false);
        };
        node::freshness::check_lock_freshness(project, &plan)?;
        // package.json is read through the held descriptor; a lock-only
        // project has no "greyward" config to read.
        let package_json = project.read_input_string(Path::new("package.json"))?;
        let config = match &package_json {
            Some(pkg) => node::parse_greyward_config(pkg)?,
            None => node::GreywardConfig::default(),
        };
        record_skipped_project_scripts(project, &plan, package_json.as_deref(), attribution)?;
        let runtime = node::realize_runtime(store, activity, platform, selected)?;
        // node-gyp runs on the helper Python selection when the project has
        // one; a Node-only project gets the shipped default.
        let helpers = request.helpers(self)?;
        let gyp_python = match helpers.get("python") {
            Some(python) => python.clone(),
            None => node::shipped_gyp_python()?,
        };
        // A `file:` directory package is packed from the project into the
        // cache, where the environment extracts it like a registry tarball.
        node::local_package::stage(store, activity, project, &plan.packages)?;
        let env = node::realize_node_env_for(
            store,
            activity,
            platform,
            &plan,
            &config.artifacts,
            selected,
            &gyp_python,
        )?;
        let inputs = inputs::input_records(project, &["package.json", &plan.lock_source])?;
        node::project_node_env_recorded(
            activity,
            project,
            &env,
            platform,
            &plan,
            &config.mutable_packages,
            fresh,
            &inputs,
            &basis,
            Some((selected, runtime.as_path())),
            &crate::tailors::helper_record(self, &helpers),
            attribution,
        )?;
        ui::synced("node_modules", &env);
        Ok(true)
    }

    fn refused_command(&self, cmd: &[String]) -> Option<String> {
        super::run_refusal::refused_command(cmd)
    }

    fn project_script(
        &self,
        root: &Path,
        name: &str,
        args: &[std::ffi::OsString],
    ) -> io::Result<Option<Vec<(String, std::ffi::OsString)>>> {
        let package_json = root.join("package.json");
        if !package_json.is_file() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(&package_json)?;
        node::script_commands_from_package(&json, name, args)
    }

    fn projected_script(
        &self,
        dir: &Path,
        cwd: &Path,
        cmd: &[std::ffi::OsString],
    ) -> io::Result<Option<ScriptRun>> {
        // A script's name is a package.json key, so text; its arguments
        // are the script's, whatever their bytes.
        let Some((name, args)) = cmd.split_first() else {
            return Ok(None);
        };
        let Some(name) = name.to_str() else {
            return Ok(None);
        };
        let Some((path, json)) = projected_package_json(dir, cwd)? else {
            return Ok(None);
        };
        let Some(steps) = node::script_commands_from_package(&json, name, args)? else {
            return Ok(None);
        };
        // The npm lifecycle protocol: each step sees which event it is,
        // the package it belongs to, and where `npm run` was started.
        let package: Value = serde_json::from_str(&json).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("package.json: {e}"))
        })?;
        let mut env = Vec::new();
        for (var, key) in [
            ("npm_package_name", "name"),
            ("npm_package_version", "version"),
        ] {
            if let Some(value) = package[key].as_str() {
                env.push((var.to_string(), value.into()));
            }
        }
        env.push(("npm_package_json".to_string(), path.into_os_string()));
        env.push(("INIT_CWD".to_string(), cwd.as_os_str().to_owned()));
        Ok(Some(ScriptRun {
            steps,
            scrubbed_prefix: "npm_",
            step_label_var: Some("npm_lifecycle_event"),
            env,
            noun: "npm script",
        }))
    }

    /// A lone file runs on the Node alone, with no node_modules, and a
    /// TypeScript one by the rule a project's would.
    fn lone_file(
        &self,
        ctx: &Context,
        toolchain: &Selected,
        extension: &str,
    ) -> io::Result<Option<LoneFile>> {
        let flags: &[&str] = match extension {
            "ts" | "mts" | "cts" => &typescript_runner(&toolchain.primary_version())
                .map_err(|why| io::Error::new(io::ErrorKind::Unsupported, why))?[1..],
            _ => &[],
        };
        let runtime = node::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        let mut lone = LoneFile::in_bin(&runtime, "node");
        lone.program
            .extend(flags.iter().map(|flag| flag.to_string()));
        Ok(Some(lone))
    }

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["node", "npm", "npx"]
    }

    fn run_env(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        cwd: &Path,
        _cmd: &[String],
        _command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        let nm = project.current_name()?.join("node_modules");
        let (_, nearest_nm) = projected_node_modules_in(project, cwd)?;
        if project.input_entry(Path::new("node_modules"))? != Entry::Absent {
            prefix.push(nearest_nm.join(".bin").to_string_lossy().into_owned());
            if nearest_nm != nm {
                prefix.push(nm.join(".bin").to_string_lossy().into_owned());
            }
            // The Node this run uses is the object the closure recorded, so
            // a catalog refresh between sync and run cannot change it.
            let node = closure_runtime(&ctx.store, activity, project)?;
            prefix.push(node.join("bin").to_string_lossy().into_owned());
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        node::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("node".into(), string(&body["node_version"])));
        for package in body["packages"].as_array().unwrap_or(&empty) {
            let path = string(&package["path"]);
            // A closure written before rows named the package has only the
            // path, which is the name except under an npm alias.
            let name = package["name"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| npm_name_from_path(&path).to_string());
            out.packages.push(PackageRow {
                name,
                version: string(&package["version"]),
                detail: path,
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
        let projection = node_projection_state(project, body);
        Ok(
            if matches!(&projection, State::Synced | State::Unchecked(_)) {
                let packages = body["packages"].as_array().map_or(&[][..], Vec::as_slice);
                let local = node::local_package::changed(project, packages);
                match recorded_inputs_state(project, body)? {
                    State::Synced if !local.is_empty() => State::Changed(local),
                    State::Changed(mut changed) => {
                        changed.extend(local);
                        State::Changed(changed)
                    }
                    State::Synced if matches!(projection, State::Unchecked(_)) => projection,
                    State::Synced => State::Synced,
                    other => other,
                }
            } else {
                projection
            },
        )
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "packages")? {
            let path = required(eco, &p, "path")?;
            // The row's `name` is the package the bytes are; a closure
            // written before rows carried it has only the install path.
            let name = match p.get("name") {
                Some(_) => required(eco, &p, "name")?,
                None => npm_name_from_path(&path).to_string(),
            };
            let ver = required(eco, &p, "version")?;
            // Scoped names: '@scope/x' -> '%40scope/x' per the purl spec.
            let purl_name = match name.strip_prefix('@') {
                Some(rest) => match rest.split_once('/') {
                    Some((scope, n)) => {
                        format!("%40{}/{}", purl_encode(scope), purl_encode(n))
                    }
                    None => purl_encode(&name),
                },
                None => purl_encode(&name),
            };
            let mut purl = format!("pkg:npm/{}@{}", purl_name, purl_encode(&ver));
            // A git package is not the registry's: the purl says which
            // repository and commit it is (`vcs_url`, per the purl spec).
            if let Some(git) = p.get("git").filter(|git| !git.is_null()) {
                let git: crate::kernel::gitsrc::GitSource = serde_json::from_value(git.clone())
                    .map_err(|e| {
                        crate::kernel::cyclonedx::err(format!("{eco} closure: {path}: git: {e}"))
                    })?;
                purl.push_str(&format!(
                    "?vcs_url={}",
                    purl_encode(&format!("git+{}@{}", git.url, git.commit))
                ));
                if let Some(subdirectory) = &git.subdirectory {
                    purl.push_str(&format!("#{}", purl_encode_path(subdirectory)));
                }
            }
            let mut c = component(&name, &ver, purl, eco);
            if npm_name_from_path(&path) != name {
                push_property(&mut c, "greyward:path", &path);
            }
            let integrity = required(eco, &p, "integrity")?;
            // An SRI is base64 of the digest: each candidate is the same
            // digest a CycloneDX hash carries in hex. A git package's
            // `git:<commit>` is not a digest of a file; its commit is in the
            // purl. An empty integrity names no digest at all.
            if !integrity.is_empty() && !integrity.starts_with("git:") {
                push_sri_hashes(&mut c, &integrity, &p["matched_digest"]).map_err(|e| {
                    crate::kernel::cyclonedx::err(format!("{eco} closure: {path}: integrity: {e}"))
                })?;
            }
            push_property(&mut c, "greyward:integrity", &integrity);
            // A `file:` directory package is packed from the project, not
            // fetched from the registry: a registry purl would name a
            // package that may exist there with other contents. Its
            // identity is its directory, and the integrity of the pack.
            if let Some(dir) = p["local"].as_str() {
                c.as_object_mut().unwrap().remove("purl");
                push_property(&mut c, "greyward:local", dir);
            }
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "env_object",
            "node-env",
            &version_of(eco, body, "node_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["nodejs"]
    }
}

/// The lifecycle scripts `npm install` (and `npm ci`) without package
/// arguments runs for the project root after the tree is reified, in
/// npm's order: the explicit list in npm 11's `lib/commands/install.js`
/// and `ci.js` (docs.npmjs.com/cli/v11/using-npm/scripts, "npm install").
const ROOT_LIFECYCLE_PHASES: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

/// What arborist runs for each linked package, workspace members
/// included, in its order: `preinstall`, then `prepare` (links alone run
/// it, before their bins are linked), then `install` and `postinstall`
/// (`@npmcli/arborist` `rebuild.js`, `#build` for `type === 'links'`).
/// Hooks around `prepare` are not run for a link.
const MEMBER_LIFECYCLE_PHASES: &[&str] = &["preinstall", "prepare", "install", "postinstall"];

/// The `install` command npm supplies for a package with a `binding.gyp`
/// and neither an `install` nor a `preinstall` script, unless
/// `"gypfile": false` (`@npmcli/node-gyp`, used by `@npmcli/run-script`
/// for the root and by arborist for links).
const DEFAULT_GYP_INSTALL: &str = "node-gyp rebuild";

/// The project's and its workspace members' own lifecycle scripts, each
/// recorded as the exception it is: npm runs them on install and ward does
/// not, since they write the project's source rather than an environment
/// (#693). The root is `.`, then every workspace importer and `link: true`
/// target the plan names, once each. A directory without a package.json has
/// nothing to run.
fn record_skipped_project_scripts(
    project: &ProjectRoot,
    plan: &node::NpmPlan,
    root_package_json: Option<&str>,
    attribution: &crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let has_binding_gyp = |dir: &str| project.is_input_file(&Path::new(dir).join("binding.gyp"));
    let mut skipped = match root_package_json {
        Some(text) => {
            skipped_project_scripts(".", text, ROOT_LIFECYCLE_PHASES, has_binding_gyp("."))?
        }
        None => Vec::new(),
    };
    let members: std::collections::BTreeSet<&str> = plan
        .workspaces
        .iter()
        .map(String::as_str)
        .chain(plan.links.iter().map(|link| link.target.as_str()))
        .filter(|dir| !dir.is_empty() && *dir != ".")
        .collect();
    for member in members {
        let manifest = Path::new(member).join("package.json");
        if let Some(text) = project.read_input_string(&manifest)? {
            skipped.extend(skipped_project_scripts(
                member,
                &text,
                MEMBER_LIFECYCLE_PHASES,
                has_binding_gyp(member),
            )?);
        }
    }
    for (subject, detail) in skipped {
        attribution.record(
            crate::kernel::policy::PROJECT_SCRIPT_SKIPPED,
            &subject,
            &detail,
        )?;
    }
    Ok(())
}

/// The lifecycle scripts in one package.json that npm would run on install,
/// `phases` in order, as (subject, detail) pairs: the subject is `dir`, the
/// detail names the phase and its command. `binding_gyp`: `dir` has a
/// `binding.gyp`, so `install` may be npm's default node-gyp build.
fn skipped_project_scripts(
    dir: &str,
    package_json: &str,
    phases: &[&str],
    binding_gyp: bool,
) -> io::Result<Vec<(String, String)>> {
    let manifest: Value = serde_json::from_str(package_json).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {e}", Path::new(dir).join("package.json").display()),
        )
    })?;
    let scripts = &manifest["scripts"];
    let default_gyp = binding_gyp
        && manifest["gypfile"] != Value::Bool(false)
        && scripts["install"].as_str().is_none()
        && scripts["preinstall"].as_str().is_none();
    Ok(phases
        .iter()
        .filter_map(|phase| {
            let command = match scripts[*phase].as_str() {
                Some(command) => command,
                None if *phase == "install" && default_gyp => DEFAULT_GYP_INSTALL,
                None => return None,
            };
            Some((
                dir.to_string(),
                format!(
                    "`{phase}` script ({command}) was not run: ward runs the lifecycle scripts of dependencies, not the project's own"
                ),
            ))
        })
        .collect())
}

/// The Node object this project's closure recorded. A closure written
/// before the toolchain lock has no such reference: it names no bytes to
/// resolve, so the run stops rather than silently picking today's default.
fn closure_runtime(
    store: &crate::kernel::store::Store,
    activity: &StoreActivity,
    project: &ProjectRoot,
) -> io::Result<PathBuf> {
    let closure = comforter::read_closure_in(project, "node")?;
    if closure["runtime_object"]["id"].as_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "node closure predates runtime recording; run `ward`",
        ));
    }
    comforter::toolchain::runtime_object(store, activity, &closure, "bin/node")
}

/// The digest the installed bytes matched as a CycloneDX hash: the
/// algorithm by its CycloneDX name and the digest in hex, the same digest
/// the SRI spells in base64. `matched` is the closure row's
/// `matched_digest`, which must be one of the integrity's candidates. A
/// closure written before rows named it lists every candidate instead and
/// says so in a `greyward:hash-match` property, since only one of them is
/// known to be the bytes'.
fn push_sri_hashes(c: &mut Value, integrity: &str, matched: &Value) -> io::Result<()> {
    let candidates = crate::kernel::digest::sri_candidates(integrity)?;
    let digests = if matched.is_null() {
        push_property(
            c,
            "greyward:hash-match",
            "unrecorded: this closure predates the matched digest, so every integrity \
             candidate is listed and only one is the installed bytes'; run `ward` to record it",
        );
        candidates
    } else {
        let algo = matched["algo"].as_str().unwrap_or_default();
        let hex = matched["hex"].as_str().unwrap_or_default();
        let digest = crate::kernel::digest::Digest::from_parts(algo, hex).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("matched_digest: {e}"))
        })?;
        if !candidates.contains(&digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("matched_digest {algo}:{hex} is not one of the integrity's digests"),
            ));
        }
        vec![digest]
    };
    let hashes = digests
        .iter()
        .map(|digest| {
            let alg = match digest.algo() {
                "sha1" => "SHA-1",
                "sha256" => "SHA-256",
                _ => "SHA-512",
            };
            json!({"alg": alg, "content": digest.hex()})
        })
        .collect();
    c["hashes"] = Value::Array(hashes);
    Ok(())
}

/// npm lockfile path ("node_modules/a/node_modules/@s/b") -> package name.
fn npm_name_from_path(path: &str) -> &str {
    match path.rfind("node_modules/") {
        Some(i) => &path[i + "node_modules/".len()..],
        None => path,
    }
}

fn store_home_from_object(path: &Path) -> Option<PathBuf> {
    let objects = path.parent()?;
    if objects.file_name()?.to_str()? != "objects" {
        return None;
    }
    Some(objects.parent()?.parent()?.to_path_buf())
}

pub(super) fn encoded_workspace(workspace: &str) -> Option<String> {
    if workspace.is_empty()
        || workspace
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(workspace.replace('%', "%25").replace('/', "%2F"))
}

/// A `node_modules` that exists but is not a symlink. ward only ever
/// projects a symlink, so a real directory here means an install tool
/// (`npm install`, `yarn`, `pnpm`) ran and replaced the projection — the
/// single most common way a synced project silently stops being synced.
/// Named as its own detail so `ward status` says what happened rather than
/// the generic "not the synced projection".
fn replaced_by_a_real_directory(project: &ProjectRoot, node_modules: &Path) -> bool {
    project
        .entry(node_modules)
        .is_ok_and(|entry| entry == Entry::Directory)
}

/// The canonical target of a project symlink, read through the held
/// descriptor (`canonical_symlink_target` for a held project).
fn held_link_target(project: &ProjectRoot, link: &Path) -> Option<PathBuf> {
    project.read_link(link).ok()??;
    project.input_subdir(link).ok()??.current_name().ok()
}

/// The `State` detail for that case. Reads as one sentence inside the
/// status line's "{what} is not the synced projection; run 'ward'".
pub(crate) fn replaced_projection_detail(name: &str) -> String {
    format!("{name} (a real directory an install tool wrote over the projection)")
}

fn node_projection_state(project: &ProjectRoot, body: &Value) -> State {
    let node_modules = Path::new("node_modules");
    if replaced_by_a_real_directory(project, node_modules) {
        return State::ProjectionMissing(replaced_projection_detail("node_modules"));
    }
    let Some(env_text) = body["env_object"].as_str() else {
        return if held_link_target(project, node_modules).is_some()
            && project.is_input_dir(node_modules)
        {
            State::Unchecked("node projection provenance was not recorded".into())
        } else {
            State::ProjectionMissing("node_modules".into())
        };
    };
    let Some(projection_id) = body["projection_id"].as_str() else {
        return State::ProjectionMissing("node_modules".into());
    };
    let expected_root = if let Some(path) = body["forest_path"].as_str() {
        let path = PathBuf::from(path);
        if path.file_name().and_then(|name| name.to_str()) != Some("node_modules") {
            return State::ProjectionMissing("node_modules".into());
        }
        let Some(root) = path.parent().map(Path::to_path_buf) else {
            return State::ProjectionMissing("node_modules".into());
        };
        root
    } else {
        let Some(home) = store_home_from_object(Path::new(env_text)) else {
            return State::ProjectionMissing("node_modules".into());
        };
        let project_key = crate::kernel::store::Store::forest_project_key(project.path());
        home.join("forests").join(project_key).join(projection_id)
    };
    let Some(expected) = expected_root.join("node_modules").canonicalize().ok() else {
        return State::ProjectionMissing("node_modules".into());
    };
    if held_link_target(project, node_modules) != Some(expected) {
        return State::ProjectionMissing("node_modules".into());
    }
    if !Path::new(env_text).is_dir() {
        return State::ProjectionMissing("env object".into());
    }
    if let Some(workspaces) = body["workspaces"].as_array() {
        for workspace in workspaces {
            let Some(workspace) = workspace.as_str() else {
                return State::ProjectionMissing("workspace node_modules".into());
            };
            let Some(encoded) = encoded_workspace(workspace) else {
                return State::ProjectionMissing("workspace node_modules".into());
            };
            // A member whose node_modules git tracks was left unprojected
            // on purpose (#174): its own directory is what belongs there.
            if body["unprojected_workspaces"]
                .as_array()
                .is_some_and(|kept| kept.iter().any(|kept| kept == workspace))
            {
                if replaced_by_a_real_directory(project, &Path::new(workspace).join("node_modules"))
                {
                    continue;
                }
                return State::ProjectionMissing("workspace node_modules".into());
            }
            let Some(expected) = expected_root
                .join("workspaces")
                .join(encoded)
                .join("node_modules")
                .canonicalize()
                .ok()
            else {
                return State::ProjectionMissing("workspace node_modules".into());
            };
            if held_link_target(project, &Path::new(workspace).join("node_modules"))
                != Some(expected)
            {
                return State::ProjectionMissing("workspace node_modules".into());
            }
        }
    }
    State::Synced
}

/// The command that runs a TypeScript file on Node `version`. Node strips
/// types on its own from 23.6 and 22.18, behind `--experimental-strip-types`
/// from 22.6 (23.0 to 23.5 included), and not at all before.
fn typescript_runner(version: &str) -> Result<&'static [&'static str], String> {
    let mut parts = version.split('.').map(|part| part.parse::<u64>().ok());
    let major = parts.next().flatten();
    let minor = parts.next().flatten().unwrap_or(0);
    match major {
        Some(major) if major >= 24 => Ok(&["node"]),
        Some(23) if minor >= 6 => Ok(&["node"]),
        Some(22) if minor >= 18 => Ok(&["node"]),
        Some(23) => Ok(&["node", "--experimental-strip-types"]),
        Some(22) if minor >= 6 => Ok(&["node", "--experimental-strip-types"]),
        _ => Err(format!(
            "the project's Node is {version}, which cannot run TypeScript (Node strips types \
             from 22.6 on); raise the Node version the project asks for (its .node-version, \
             package.json engines or similar), and if greyward-toolchain.toml pins Node, run 'ward \
             update --toolchain node' to move that pin"
        )),
    }
}

/// The files this ecosystem's toolchain version is read from, in its own
/// tools' precedence order ([`Tailor::toolchain_sources`]).
fn toolchain_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    use crate::kernel::toolchain::input::{
        checked_row_for, read_node_version, read_package_json_engines_node, row_for,
    };
    Ok(vec![
        row_for(root, ".node-version", "version", read_node_version)?,
        checked_row_for(
            root,
            "package.json",
            "engines.node",
            read_package_json_engines_node,
        )?,
    ])
}

/// The selection request [`toolchain_rows`] state.
fn toolchain_request(rows: &[InputRow]) -> io::Result<Request> {
    use crate::kernel::toolchain::resolve::{engines_node, exact_or_prefix, parse_version, value};
    let mut request = Request::newest();
    if let Some(text) = value(rows, ".node-version", "version") {
        request = request.with(
            "node",
            exact_or_prefix(parse_version(".node-version", text)?),
        );
    }
    if let Some(text) = value(rows, "package.json", "engines.node") {
        for term in engines_node(text)? {
            request = request.with("node", term);
        }
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::store::Store;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    /// TypeScript runs as-is where Node strips types itself, behind the
    /// flag where it needs one, and is refused before 22.6.
    #[test]
    fn typescript_runs_on_every_node_that_can_strip_types() {
        for version in ["22.18.0", "22.20.1", "23.6.0", "24.0.0", "26.10.0"] {
            assert_eq!(typescript_runner(version).unwrap(), ["node"], "{version}");
        }
        for version in ["22.6.0", "22.17.1", "23.0.0", "23.5.0"] {
            assert_eq!(
                typescript_runner(version).unwrap(),
                ["node", "--experimental-strip-types"],
                "{version}"
            );
        }
        for version in ["22.5.1", "21.7.3", "20.19.0", "garbage"] {
            let why = typescript_runner(version).unwrap_err();
            assert!(why.contains(&format!("Node is {version}")), "{why}");
            assert!(why.contains(".node-version"), "{why}");
            assert!(why.contains("ward update --toolchain node"), "{why}");
        }
    }

    struct StoreEnv(Option<std::ffi::OsString>);

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("GREYWARD_STORE", value),
                None => std::env::remove_var("GREYWARD_STORE"),
            }
        }
    }

    fn write_closure(dir: &Path, body: Value) {
        let closures = dir.join(".greyward/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join("node.json"),
            serde_json::to_string(&json!({
                "schema": "closure/1",
                "ecosystem": "node",
                "platform": Platform::host().unwrap().triple(),
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A script in a projected project runs as npm runs it: pre, main and
    /// post steps, the lifecycle variables, and `INIT_CWD` where it started.
    #[test]
    fn projected_script_gives_each_step_npms_environment() {
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        let cwd = dir.join("packages/app");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(temp.0.join("forest/node_modules")).unwrap();
        std::os::unix::fs::symlink(temp.0.join("forest/node_modules"), dir.join("node_modules"))
            .unwrap();
        write_closure(&dir, json!({}));
        fs::write(
            dir.join("package.json"),
            r#"{"name": "app", "version": "1.2.3",
                "scripts": {"pretest": "echo pre", "test": "vitest", "posttest": "echo post"}}"#,
        )
        .unwrap();
        let cmd = ["test".into(), "--run".into()];
        let run = Node.projected_script(&dir, &cwd, &cmd).unwrap().unwrap();
        let labels: Vec<&str> = run.steps.iter().map(|(label, _)| label.as_str()).collect();
        assert_eq!(labels, ["pretest", "test", "posttest"]);
        let text = |step: usize| run.steps[step].1.to_str().unwrap().to_string();
        assert!(text(1).starts_with("vitest"), "{:?}", run.steps[1]);
        assert!(text(1).contains("--run"), "{:?}", run.steps[1]);
        assert!(!text(0).contains("--run"), "{:?}", run.steps[0]);
        assert_eq!(run.scrubbed_prefix, "npm_");
        assert_eq!(run.step_label_var, Some("npm_lifecycle_event"));
        let env: std::collections::BTreeMap<String, std::ffi::OsString> =
            run.env.into_iter().collect();
        assert_eq!(env["npm_package_name"], "app");
        assert_eq!(env["npm_package_version"], "1.2.3");
        assert_eq!(
            Path::new(&env["npm_package_json"]),
            dir.join("package.json").canonicalize().unwrap()
        );
        assert_eq!(Path::new(&env["INIT_CWD"]), cwd);

        // A name with no script, and a project ward has not projected, run
        // nothing here.
        let missing = ["lint".into()];
        assert!(Node
            .projected_script(&dir, &cwd, &missing)
            .unwrap()
            .is_none());
        fs::remove_file(dir.join("node_modules")).unwrap();
        assert!(Node.projected_script(&dir, &cwd, &cmd).unwrap().is_none());
    }

    #[test]
    fn a_relative_projection_link_cannot_resolve_through_a_replaced_project() {
        let temp = TempDir::new();
        let project = temp.0.join("project");
        let original = project.join("env/node_modules");
        fs::create_dir_all(&original).unwrap();
        std::os::unix::fs::symlink("env/node_modules", project.join("node_modules")).unwrap();
        let held = ProjectRoot::open(&project).unwrap();
        let moved = temp.0.join("moved");
        fs::rename(&project, &moved).unwrap();
        let replacement = project.join("env/node_modules");
        fs::create_dir_all(&replacement).unwrap();
        let found = held_link_target(&held, Path::new("node_modules"));
        assert_eq!(
            found,
            Some(moved.join("env/node_modules").canonicalize().unwrap())
        );
    }

    #[test]
    fn absolute_projection_stays_synced_when_its_project_name_is_replaced() {
        let temp = TempDir::new();
        let project = temp.0.join("project");
        let forest = temp.0.join("forest/node_modules");
        let env = temp.0.join("env");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&forest).unwrap();
        fs::create_dir_all(&env).unwrap();
        std::os::unix::fs::symlink(&forest, project.join("node_modules")).unwrap();
        let body = json!({"env_object": env, "projection_id": "p", "forest_path": forest});
        let held = ProjectRoot::open(&project).unwrap();
        assert_eq!(node_projection_state(&held, &body), State::Synced);
        fs::rename(&project, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&project).unwrap();
        assert_eq!(node_projection_state(&held, &body), State::Synced);
    }

    #[test]
    fn workspace_bin_selection_uses_the_held_project() {
        let temp = TempDir::new();
        let project = temp.0.join("project");
        let moved = temp.0.join("moved");
        let forest = temp.0.join("forest");
        let outside = temp.0.join("outside/node_modules");
        fs::create_dir_all(project.join("packages/member")).unwrap();
        fs::create_dir_all(project.join(".greyward/closures")).unwrap();
        fs::write(project.join(".greyward/closures/node.json"), "{}").unwrap();
        fs::create_dir_all(forest.join("node_modules")).unwrap();
        fs::create_dir_all(forest.join("workspaces/member/node_modules")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(forest.join("node_modules"), project.join("node_modules"))
            .unwrap();
        std::os::unix::fs::symlink(
            forest.join("workspaces/member/node_modules"),
            project.join("packages/member/node_modules"),
        )
        .unwrap();
        let held = ProjectRoot::open(&project).unwrap();
        fs::rename(&project, &moved).unwrap();
        fs::create_dir_all(project.join("packages/member")).unwrap();
        std::os::unix::fs::symlink(forest.join("node_modules"), project.join("node_modules"))
            .unwrap();
        std::os::unix::fs::symlink(outside, project.join("packages/member/node_modules")).unwrap();
        let (_, nearest) =
            projected_node_modules_in(&held, &project.join("packages/member")).unwrap();
        assert_eq!(nearest, moved.join("packages/member/node_modules"));
    }

    #[test]
    fn run_env_refuses_symlinked_state_parents_for_every_closure_tailor() {
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::new();
        let old = std::env::var_os("GREYWARD_STORE");
        std::env::set_var("GREYWARD_STORE", temp.0.join("store"));
        let _guard = StoreEnv(old);
        let ctx = Context::open(Platform::host().unwrap()).unwrap();
        for parent in [".greyward", ".greyward/closures"] {
            let dir = temp.0.join(parent.replace('/', "-"));
            let outside = temp.0.join(format!("outside-{}", parent.replace('/', "-")));
            fs::create_dir_all(&outside).unwrap();
            fs::create_dir_all(dir.join(Path::new(parent).parent().unwrap())).unwrap();
            std::os::unix::fs::symlink(outside, dir.join(parent)).unwrap();
            let project = ProjectRoot::open(&dir).unwrap();
            for ecosystem in ["go", "ruby", "elixir", "dotnet"] {
                let tailor = crate::tailors::by_id(ecosystem).unwrap();
                let mut command = Command::new("unused");
                assert!(
                    tailor
                        .run_env(&ctx, &project, project.path(), &[], &mut command)
                        .is_err(),
                    "{ecosystem} silently ignored {parent}"
                );
            }
        }
    }

    #[test]
    fn optional_run_env_callers_propagate_damaged_held_closures() {
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::new();
        let old = std::env::var_os("GREYWARD_STORE");
        std::env::set_var("GREYWARD_STORE", temp.0.join("store"));
        let _guard = StoreEnv(old);
        let ctx = Context::open(Platform::host().unwrap()).unwrap();
        for ecosystem in ["go", "ruby", "elixir"] {
            let dir = temp.0.join(ecosystem);
            fs::create_dir_all(dir.join(".greyward/closures")).unwrap();
            let project = ProjectRoot::open(&dir).unwrap();
            let tailor = crate::tailors::by_id(ecosystem).unwrap();
            let mut command = Command::new("unused");
            assert!(tailor
                .run_env(&ctx, &project, project.path(), &[], &mut command)
                .unwrap()
                .is_empty());
            assert_eq!(command.get_envs().count(), 0);
            for bytes in [b"{not JSON".as_slice(), b"\xff\xfe".as_slice()] {
                fs::write(
                    dir.join(format!(".greyward/closures/{ecosystem}.json")),
                    bytes,
                )
                .unwrap();
                let mut command = Command::new("unused");
                assert_eq!(
                    tailor
                        .run_env(&ctx, &project, project.path(), &[], &mut command)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidData,
                    "{ecosystem}"
                );
                assert_eq!(command.get_envs().count(), 0);
            }
            let moved = temp.0.join(format!("moved-{ecosystem}"));
            fs::rename(&dir, &moved).unwrap();
            fs::create_dir(&dir).unwrap();
            let mut command = Command::new("unused");
            assert!(
                tailor
                    .run_env(&ctx, &project, project.path(), &[], &mut command)
                    .is_err(),
                "{ecosystem} reopened the replacement project"
            );
        }
    }

    #[test]
    fn cargo_environment_uses_the_held_home_after_detachment_and_replacement() {
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::new();
        let old = std::env::var_os("GREYWARD_STORE");
        std::env::set_var("GREYWARD_STORE", temp.0.join("store"));
        let _guard = StoreEnv(old);
        let ctx = Context::open(Platform::host().unwrap()).unwrap();
        let id = format!("{}-rust-1.96.1", "b".repeat(40));
        let object = ctx.store.object_path(&id);
        fs::create_dir_all(object.join("bin")).unwrap();
        fs::write(object.join("bin/rustc"), "rust").unwrap();
        fs::write(ctx.store.root.join(format!("meta/{id}.json")), "{}").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
        let dir = temp.0.join("project");
        fs::create_dir_all(dir.join(".greyward/cargo-home/bin")).unwrap();
        fs::create_dir_all(dir.join(".greyward/closures")).unwrap();
        fs::write(
            dir.join(".greyward/closures/cargo.json"),
            serde_json::to_vec(&json!({
                "schema": "closure/1", "ecosystem": "cargo", "platform": ctx.platform.triple(),
                "body": {"rust_object": {"id": id, "path": object}},
            }))
            .unwrap(),
        )
        .unwrap();
        let project = ProjectRoot::open(&dir).unwrap();
        let moved = temp.0.join("moved");
        fs::rename(&dir, &moved).unwrap();
        for replacement in [false, true] {
            if replacement {
                fs::create_dir_all(dir.join(".greyward/cargo-home")).unwrap();
            }
            let mut command = Command::new("unused");
            let prefix = crate::tailors::by_id("cargo")
                .unwrap()
                .run_env(&ctx, &project, project.path(), &[], &mut command)
                .unwrap();
            assert_eq!(
                prefix[0],
                moved.join(".greyward/cargo-home/bin").to_string_lossy()
            );
            let home = command
                .get_envs()
                .find(|(key, _)| *key == "CARGO_HOME")
                .unwrap()
                .1
                .unwrap();
            assert_eq!(Path::new(home), moved.join(".greyward/cargo-home"));
        }
    }

    /// A member whose node_modules git tracks keeps its own directory
    /// (#174). `status` takes that directory as the member's projection,
    /// and still reports the member missing once the directory is gone.
    #[test]
    fn an_unprojected_member_keeps_its_own_directory_and_is_synced() {
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        let root = temp.0.join("forest");
        let env = temp.0.join("env");
        for path in [
            root.join("node_modules"),
            root.join("workspaces/packages%2Fbuilt/node_modules"),
            dir.join("packages/fixture/node_modules"),
            dir.join("packages/built"),
            env.clone(),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        std::os::unix::fs::symlink(root.join("node_modules"), dir.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            root.join("workspaces/packages%2Fbuilt/node_modules"),
            dir.join("packages/built/node_modules"),
        )
        .unwrap();
        let body = |kept: Value| {
            json!({
                "env_object": env,
                "projection_id": "p",
                "forest_path": root.join("node_modules"),
                "workspaces": ["packages/built", "packages/fixture"],
                "unprojected_workspaces": kept,
            })
        };
        assert_eq!(
            node_projection_state(
                &ProjectRoot::open(&dir).unwrap(),
                &body(json!(["packages/fixture"]))
            ),
            State::Synced
        );
        let outside = temp.0.join("outside");
        fs::create_dir_all(outside.join("node_modules")).unwrap();
        for workspace in [
            "../outside".to_string(),
            outside.to_string_lossy().into_owned(),
        ] {
            let mut invalid = body(json!([workspace]));
            invalid["workspaces"] = json!([workspace]);
            assert!(matches!(
                node_projection_state(&ProjectRoot::open(&dir).unwrap(), &invalid),
                State::ProjectionMissing(_)
            ));
        }
        assert!(matches!(
            node_projection_state(&ProjectRoot::open(&dir).unwrap(), &body(Value::Null)),
            State::ProjectionMissing(_)
        ));
        fs::remove_dir(dir.join("packages/fixture/node_modules")).unwrap();
        assert!(matches!(
            node_projection_state(
                &ProjectRoot::open(&dir).unwrap(),
                &body(json!(["packages/fixture"]))
            ),
            State::ProjectionMissing(_)
        ));
    }

    /// A sync holds the project open: once the directory is renamed and a
    /// different project put at its old path, the plan and the recorded
    /// inputs still come from the original directory's lock.
    #[test]
    fn plan_reads_the_held_project_after_it_is_renamed_and_replaced() {
        let lock = |name: &str| {
            format!(
                r#"{{"name":"x","lockfileVersion":3,"packages":{{"":{{"name":"x"}},
                   "node_modules/{name}":{{"version":"1.0.0","resolved":"https://r/{name}.tgz",
                   "integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}}}}}}"#
            )
        };
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("package.json"), r#"{"name":"x"}"#).unwrap();
        fs::write(dir.join("package-lock.json"), lock("original")).unwrap();
        let project = ProjectRoot::open(&dir).unwrap();

        fs::rename(&dir, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("package.json"), r#"{"name":"replacement"}"#).unwrap();
        fs::write(dir.join("package-lock.json"), lock("replacement")).unwrap();

        assert!(Node.detect(&project).unwrap());
        let selected = node::shipped_selection().unwrap();
        let plan = inputs::load_npm_plan(Platform::host().unwrap(), &project, &selected)
            .unwrap()
            .unwrap();
        let names: Vec<&str> = plan.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["original"]);
        let records =
            inputs::input_records(&project, &["package.json", "package-lock.json"]).unwrap();
        assert_eq!(
            records[1].sha256,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                lock("original").as_bytes()
            ))
        );
    }

    /// A run takes its Node from the object the closure named, and a closure
    /// written before that reference existed stops the run instead of
    /// falling back to whatever the catalog would pick today.
    #[test]
    fn run_resolves_node_through_the_closure() {
        let _store_lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let temp = TempDir::new();
        let old_store = std::env::var_os("GREYWARD_STORE");
        std::env::set_var("GREYWARD_STORE", temp.0.join("store"));
        let _store_env = StoreEnv(old_store);
        let store = Store::open().unwrap();
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();

        let id = format!("{}-node-24.20.0", "b".repeat(40));
        let object = store.object_path(&id);
        fs::create_dir_all(object.join("bin")).unwrap();
        fs::write(object.join("bin/node"), b"#!/bin/sh\n").unwrap();
        // A published object is a read-only directory with a metadata file;
        // anything less reads as a crashed publication.
        fs::write(store.root.join(format!("meta/{id}.json")), "{}").unwrap();
        let mut mode = fs::metadata(&object).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o555);
        fs::set_permissions(&object, mode).unwrap();

        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        write_closure(
            &dir,
            json!({
                "node_version": "24.20.0",
                "runtime_object": {"id": id, "path": object},
            }),
        );
        assert_eq!(
            closure_runtime(&store, activity, &ProjectRoot::open(&dir).unwrap()).unwrap(),
            object
        );

        write_closure(&dir, json!({"node_version": "24.20.0"}));
        let error =
            closure_runtime(&store, activity, &ProjectRoot::open(&dir).unwrap()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "node closure predates runtime recording; run `ward`"
        );

        // Leave the fixture removable.
        let mut mode = fs::metadata(&object).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        fs::set_permissions(&object, mode).unwrap();
    }

    /// A `file:` directory package is a copy of a project directory, not a
    /// registry package: its SBOM component names the directory and
    /// carries no registry purl, which would claim a package that may
    /// exist on the registry with other contents.
    #[test]
    fn a_file_directory_package_is_not_given_a_registry_purl() {
        let body = json!({
            "env_object": "/store/objects/abc123",
            "node_version": "22.0.0",
            "packages": [
                {"path": "node_modules/b", "version": "1.0.0", "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="},
                {
                    "path": "node_modules/local",
                    "version": "2.1.0",
                    "integrity": "sha256-rKyGwOYJypBvYysOLazMsrd9IrBiHyDr7OGkg1uT9vA=",
                    "local": "vendor/local",
                },
            ],
        });
        let mut out = Vec::new();
        Node.sbom_components("node", &body, &mut out).unwrap();
        let property = |c: &Value, name: &str| -> Option<String> {
            c["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .map(|p| p["value"].as_str().unwrap().to_string())
        };
        let registry = out.iter().find(|c| c["name"] == "b").unwrap();
        assert_eq!(registry["purl"], "pkg:npm/b@1.0.0");
        assert_eq!(property(registry, "greyward:local"), None);
        let local = out.iter().find(|c| c["name"] == "local").unwrap();
        assert!(local.get("purl").is_none(), "{local}");
        assert_eq!(local["version"], "2.1.0");
        assert_eq!(
            property(local, "greyward:local").as_deref(),
            Some("vendor/local")
        );
        assert_eq!(
            property(local, "greyward:integrity").as_deref(),
            Some("sha256-rKyGwOYJypBvYysOLazMsrd9IrBiHyDr7OGkg1uT9vA=")
        );
    }

    /// A component names the package its bytes are, and says where they
    /// came from (#688). An alias is the real package, with its install
    /// path kept as a property; a git package's purl carries its repository
    /// and commit, and its `git:` integrity is no file hash; an SRI becomes
    /// CycloneDX hashes in hex, one per candidate. A row written before
    /// rows named the package still reads its name from the path.
    #[test]
    fn sbom_components_name_the_real_package_and_its_source() {
        let body = json!({
            "env_object": "/store/objects/abc123",
            "node_version": "22.0.0",
            "packages": [
                {"path": "node_modules/@s/alias", "name": "@t/real", "version": "2.0.0",
                 "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ== sha512-AAAAktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ==",
                 "matched_digest": {"algo": "sha512", "hex": "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"}},
                {"path": "node_modules/gitdep", "name": "gitdep", "version": "1.0.0",
                 "integrity": "git:0123456789abcdef0123456789abcdef01234567",
                 "git": {"url": "https://github.com/o/gitdep.git",
                         "commit": "0123456789abcdef0123456789abcdef01234567",
                         "subdirectory": "packages/core"}},
                {"path": "node_modules/a/node_modules/old", "version": "1.0.0",
                 "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="},
                {"path": "node_modules/unmatched", "name": "unmatched", "version": "1.0.0",
                 "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ== sha512-AAAAktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="},
            ],
        });
        let mut out = Vec::new();
        Node.sbom_components("node", &body, &mut out).unwrap();
        let property = |c: &Value, name: &str| -> Option<String> {
            c["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .map(|p| p["value"].as_str().unwrap().to_string())
        };
        let alias = &out[0];
        assert_eq!(alias["name"], "@t/real");
        assert_eq!(alias["purl"], "pkg:npm/%40t/real@2.0.0");
        assert_eq!(
            property(alias, "greyward:path").as_deref(),
            Some("node_modules/@s/alias")
        );
        // Two candidates, and the bytes matched the first: only it is a
        // hash of the component.
        let hashes = alias["hashes"].as_array().unwrap();
        assert_eq!(hashes.len(), 1, "{hashes:?}");
        assert_eq!(hashes[0]["alg"], "SHA-512");
        assert_eq!(hashes[0]["content"], "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
        assert_eq!(property(alias, "greyward:hash-match"), None);

        let git = &out[1];
        assert_eq!(
            git["purl"],
            "pkg:npm/gitdep@1.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fgitdep.git%400123456789abcdef0123456789abcdef01234567#packages/core"
        );
        assert!(git.get("hashes").is_none(), "{git}");
        assert_eq!(property(git, "greyward:path"), None);

        let old = &out[2];
        assert_eq!(old["name"], "old");
        assert_eq!(old["purl"], "pkg:npm/old@1.0.0");
        assert_eq!(old["hashes"][0]["content"], "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");

        // A row from a closure written before the matched digest: every
        // candidate, and a property that says only one is the bytes'.
        let unmatched = &out[3];
        let hashes = unmatched["hashes"].as_array().unwrap();
        assert_eq!(hashes.len(), 2, "{hashes:?}");
        assert!(property(unmatched, "greyward:hash-match")
            .unwrap()
            .starts_with("unrecorded: this closure predates the matched digest"));
        assert!(property(old, "greyward:hash-match").is_some());

        // A matched digest that is none of the row's candidates is a
        // damaged closure.
        let mut out = Vec::new();
        let stray = json!({
            "env_object": "/store/objects/abc123",
            "node_version": "22.0.0",
            "packages": [{"path": "node_modules/x", "version": "1.0.0",
                          "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ== sha512-AAAAktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ==",
                          "matched_digest": {"algo": "sha512", "hex": "abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab"}}],
        });
        let error = Node
            .sbom_components("node", &stray, &mut out)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("is not one of the integrity's digests"),
            "{error}"
        );

        let mut out = Vec::new();
        let malformed = json!({
            "env_object": "/store/objects/abc123",
            "node_version": "22.0.0",
            "packages": [{"path": "node_modules/x", "version": "1.0.0", "integrity": "sha512-xyz"}],
        });
        let error = Node
            .sbom_components("node", &malformed, &mut out)
            .unwrap_err()
            .to_string();
        assert!(error.contains("node_modules/x: integrity"), "{error}");
    }

    /// npm runs the root's and each workspace member's install lifecycle
    /// scripts; ward does not, so each one is recorded where policy and
    /// `ward audit` see it (#693). Other scripts, and a member directory
    /// without a package.json, record nothing; a directory named both as a
    /// workspace and as a link target is read once.
    #[test]
    fn the_projects_own_lifecycle_scripts_are_recorded_as_skipped() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let scratch = TempDir::named("node-project-scripts");
        let project = scratch.0.clone();
        let root = r#"{"name":"app","scripts":{"postinstall":"patch-package","test":"jest","prepare":"husky","postprepare":"echo done","prepublish":"build","preprepare":"gen"}}"#;
        fs::write(project.join("package.json"), root).unwrap();
        fs::create_dir_all(project.join("packages/lib")).unwrap();
        fs::write(
            project.join("packages/lib/package.json"),
            r#"{"name":"lib","scripts":{"postinstall":"cp","prepare":"tsc","preprepare":"x","postprepare":"y","build":"tsc"}}"#,
        )
        .unwrap();
        // A member with a `binding.gyp` and no install script gets npm's
        // default node-gyp build; one that opts out with `gypfile: false`
        // does not.
        fs::create_dir_all(project.join("packages/addon")).unwrap();
        fs::write(project.join("packages/addon/binding.gyp"), "{}").unwrap();
        fs::write(
            project.join("packages/addon/package.json"),
            r#"{"name":"addon"}"#,
        )
        .unwrap();
        fs::create_dir_all(project.join("packages/optout")).unwrap();
        fs::write(project.join("packages/optout/binding.gyp"), "{}").unwrap();
        fs::write(
            project.join("packages/optout/package.json"),
            r#"{"name":"optout","gypfile":false}"#,
        )
        .unwrap();
        fs::create_dir_all(project.join("packages/empty")).unwrap();
        let plan = node::NpmPlan {
            node_version: "24.20.0".into(),
            packages: Vec::new(),
            links: vec![node::NpmLink {
                path: "node_modules/lib".into(),
                target: "packages/lib".into(),
            }],
            workspaces: vec![
                "packages/lib".into(),
                "packages/empty".into(),
                "packages/addon".into(),
                "packages/optout".into(),
            ],
            lock_source: "package-lock.json".into(),
        };
        let held = ProjectRoot::open(&project).unwrap();
        let attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        record_skipped_project_scripts(&held, &plan, Some(root), &attribution).unwrap();
        let recorded: Vec<(String, String)> = attribution
            .recorded()
            .into_iter()
            .map(|exception| {
                assert_eq!(
                    exception.kind,
                    crate::kernel::policy::PROJECT_SCRIPT_SKIPPED
                );
                (exception.subject, exception.detail)
            })
            .collect();
        attribution.discard();
        let not_run =
            "was not run: ward runs the lifecycle scripts of dependencies, not the project's own";
        assert_eq!(
            recorded,
            [
                (
                    ".".to_string(),
                    format!("`postinstall` script (patch-package) {not_run}")
                ),
                (
                    ".".to_string(),
                    format!("`prepublish` script (build) {not_run}")
                ),
                (
                    ".".to_string(),
                    format!("`preprepare` script (gen) {not_run}")
                ),
                (
                    ".".to_string(),
                    format!("`prepare` script (husky) {not_run}")
                ),
                (
                    ".".to_string(),
                    format!("`postprepare` script (echo done) {not_run}")
                ),
                (
                    "packages/addon".to_string(),
                    format!("`install` script (node-gyp rebuild) {not_run}")
                ),
                // A link runs `prepare` before `install`, and no hooks
                // around it.
                (
                    "packages/lib".to_string(),
                    format!("`prepare` script (tsc) {not_run}")
                ),
                (
                    "packages/lib".to_string(),
                    format!("`postinstall` script (cp) {not_run}")
                ),
            ]
        );

        let denying = crate::kernel::policy::PolicyScope::install(crate::kernel::policy::Policy {
            deny: [crate::kernel::policy::PROJECT_SCRIPT_SKIPPED.to_string()].into(),
            ..Default::default()
        });
        let attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let error = record_skipped_project_scripts(&held, &plan, Some(root), &attribution)
            .unwrap_err()
            .to_string();
        attribution.discard();
        drop(denying);
        assert!(error.contains("project-script-skipped"), "{error}");
    }
}
