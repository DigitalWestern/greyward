//! Running the store SDK's restore as a resolver: confined through the
//! door, reaching api.nuget.org only through the proxy session's NuGet
//! mirror, named by a `nuget.config` the wiring writes.

use super::{registry, ENV_REMOVE, ENV_REMOVE_PREFIXES};
use crate::kernel::resolve::door::{
    ConfinedSpec, Publish, ReceiptProducer, ResultCheck, Staged, Wire, Wiring,
};
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

mod locked;

/// Why restore runs isolated, for the missing-capability message.
const WHY: &str = "evaluates the project's MSBuild files and fetches packages from the network";

/// Restore and build output in the project, at any depth (every project
/// of a solution has its own): never copied into the snapshot, never
/// diffed. A confined restore writes `obj/` in its stage, and it is
/// discarded. A file under a directory named `bin` or `obj` is invisible to
/// restore too, so leaving it out of the receipt leaves out nothing
/// restore read.
pub(super) const EXCLUDE: [&str; 4] = ["**/obj", "**/bin", ".git", ".greyward"];

/// Stands for the run's scratch directory in an argument.
const SCRATCH: &str = "@SCRATCH@";

/// The greyward-written config every run names: the mirror alone.
const CONFIG_FILE: &str = "nuget.config";

/// The generated solution a solution's restore runs over, in scratch.
pub(super) const SOLUTION_FILE: &str = "greyward.sln";

/// One confined restore. Its outputs (project files and packages.lock.json
/// files) are published through the transaction with the receipt the
/// producer makes.
pub(crate) struct DotnetRun<'a> {
    pub sdk_obj: &'a Path,
    pub lock_root: &'a Path,
    /// The arguments after `dotnet restore`.
    pub args: Vec<String>,
    /// The generated solution's text, written to [`SOLUTION_FILE`] in
    /// scratch; `None` for a single project.
    pub solution: Option<String>,
    /// The locks the run must leave: one per member.
    pub required: Vec<PathBuf>,
    pub outputs: Vec<PathBuf>,
    /// The input generation captured before restore.
    pub inputs: Option<&'a crate::comforter::join::Digests>,
    pub receipt: Option<ReceiptProducer<'a>>,
}

/// The tool a resolution record names: the selected SDK, whose NuGet
/// resolved.
pub(crate) fn dotnet_tool(selected: &Selected) -> io::Result<crate::kernel::resolve::record::Tool> {
    Ok(crate::kernel::resolve::record::Tool {
        name: "dotnet".to_string(),
        version: selected.version("dotnet-sdk")?.to_string(),
    })
}

/// The arguments one restore runs: `restore`, `args`, and the mirror's
/// config.
fn restore_args(args: &[String]) -> Vec<String> {
    let mut all = vec!["restore".to_string()];
    all.extend(args.iter().cloned());
    all.extend(
        [
            "--configfile",
            "@SCRATCH@/nuget.config",
            "--lock-file-path",
            "packages.lock.json",
        ]
        .map(String::from),
    );
    all
}

/// The store `dotnet` with ward's forced environment, its output captured.
/// The package folder and the homes are the run's scratch, set by the
/// wiring.
fn spec(run: &DotnetRun<'_>) -> DelegateSpec {
    let mut spec = DelegateSpec::new(run.sdk_obj.join("dotnet"));
    spec.args(restore_args(&run.args)).lock_root(run.lock_root);
    spec.env("PATH", format!("{}:/usr/bin:/bin", run.sdk_obj.display()));
    let set: Vec<(String, String)> = vec![
        ("DOTNET_ROOT".into(), run.sdk_obj.display().to_string()),
        ("DOTNET_CLI_TELEMETRY_OPTOUT".into(), "1".into()),
        ("DOTNET_NOLOGO".into(), "1".into()),
        ("DOTNET_SKIP_FIRST_TIME_EXPERIENCE".into(), "1".into()),
    ];
    spec.force_env(ENV_REMOVE_PREFIXES, ENV_REMOVE, &set);
    spec.capture();
    spec
}

/// `arg` with [`SCRATCH`] replaced by `scratch`.
fn in_scratch(arg: &OsString, scratch: &Path) -> OsString {
    match arg.to_str() {
        Some(text) if text.contains(SCRATCH) => {
            text.replace(SCRATCH, &scratch.display().to_string()).into()
        }
        _ => arg.clone(),
    }
}

/// Every member's lock must come out of the run: a member restore skipped
/// would otherwise publish a solution with a hole in it.
fn every_lock_written<'a>(required: Vec<PathBuf>) -> ResultCheck<'a> {
    Box::new(move |staged: &Staged<'_>| {
        for lock in &required {
            if staged.read(lock)?.is_none() {
                return Err(super::err(format!(
                    "restore wrote no {}; nothing is published",
                    lock.display()
                )));
            }
        }
        Ok(Vec::new())
    })
}

fn dotnet_confined<'a>(run: &mut DotnetRun<'a>) -> io::Result<ConfinedSpec<'a>> {
    let mut confined = ConfinedSpec::new("dotnet", "dotnet", WHY);
    confined.name = "dotnet restore";
    confined.expected_inputs = run.inputs.cloned().unwrap_or_default();
    confined.complete_inputs = true;
    confined.store_reads = vec![run.sdk_obj.to_path_buf()];
    confined.exclude = EXCLUDE
        .iter()
        .map(|pattern| PathGlob::new(pattern))
        .collect::<io::Result<_>>()?;
    confined.routes = vec![registry::route()?];
    let solution = run.solution.take();
    confined.wire = Some(Box::new(move |wire: &Wire<'_>| {
        let at = |sub: &str| OsString::from(wire.scratch.join(sub));
        let mut env: Vec<(OsString, OsString)> = vec![
            ("NUGET_PACKAGES".into(), at("pkgs")),
            (
                "DOTNET_CLI_HOME".into(),
                wire.scratch.as_os_str().to_owned(),
            ),
            ("XDG_CONFIG_HOME".into(), at("xdg")),
            ("XDG_DATA_HOME".into(), at("xdg-data")),
        ];
        env.extend(
            registry::proxy_env(wire.address)
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        let args = wire
            .args
            .iter()
            .map(|arg| in_scratch(arg, wire.scratch))
            .chain(wire.forced_args.iter().cloned())
            .collect();
        let mut files = vec![
            (
                PathBuf::from(CONFIG_FILE),
                registry::nuget_config(wire.address).into_bytes(),
            ),
            // NuGet's first-run migration takes a machine-global mutex
            // unless the home is marked migrated (`prepare_scratch`).
            (PathBuf::from("xdg-data/NuGet/Migrations/1"), Vec::new()),
        ];
        if let Some(text) = &solution {
            files.push((PathBuf::from(SOLUTION_FILE), text.clone().into_bytes()));
        }
        Ok(Wiring {
            args,
            env,
            files,
            ..Wiring::default()
        })
    }));
    confined.check = Some(every_lock_written(std::mem::take(&mut run.required)));
    confined.locked = Some(locked::locked_list(run.outputs.clone()));
    confined.publish(Publish::Project {
        outputs: std::mem::take(&mut run.outputs),
        receipt: run.receipt.take(),
    });
    Ok(confined)
}

/// Run the store restore confined through `door`.
pub(crate) fn run_restore(
    door: &mut ResolutionDoor<'_>,
    mut run: DotnetRun<'_>,
) -> io::Result<DelegateReport> {
    let spec = spec(&run);
    let confined = dotnet_confined(&mut run)?;
    door.run_confined(spec, confined).map_err(|e| {
        crate::kernel::error::context(
            e,
            format_args!("store dotnet restore {}", run.args.join(" ")),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_restore_names_the_mirror_config_in_its_scratch() {
        assert_eq!(
            restore_args(&["--use-lock-file".to_string()]),
            [
                "restore",
                "--use-lock-file",
                "--configfile",
                "@SCRATCH@/nuget.config",
                "--lock-file-path",
                "packages.lock.json"
            ]
        );
        assert_eq!(
            in_scratch(&"@SCRATCH@/nuget.config".into(), Path::new("/s")),
            OsString::from("/s/nuget.config")
        );
    }

    #[test]
    fn the_spec_runs_the_store_sdk_alone() {
        let run = DotnetRun {
            sdk_obj: Path::new("/store/obj/sdk"),
            lock_root: Path::new("/work/p"),
            args: vec!["--locked-mode".to_string()],
            solution: None,
            required: Vec::new(),
            outputs: Vec::new(),
            inputs: None,
            receipt: None,
        };
        let command = format!("{:?}", spec(&run).command());
        assert!(
            command.contains("DOTNET_ROOT=\"/store/obj/sdk\""),
            "{command}"
        );
        assert!(
            command.contains("PATH=\"/store/obj/sdk:/usr/bin:/bin\""),
            "{command}"
        );
        assert!(!command.contains("NUGET_PACKAGES"), "{command}");
    }

    #[test]
    fn a_member_lock_restore_left_unwritten_refuses_the_run() {
        let temp = crate::kernel::testutil::TempDir::named("dotnet-locks-written");
        std::fs::create_dir(temp.0.join("a")).unwrap();
        std::fs::write(temp.0.join("a/packages.lock.json"), "{}").unwrap();
        let staged = Staged::in_dir(&temp.0);
        every_lock_written(vec!["a/packages.lock.json".into()])(&staged).unwrap();
        let why = every_lock_written(vec![
            "a/packages.lock.json".into(),
            "b/packages.lock.json".into(),
        ])(&staged)
        .unwrap_err()
        .to_string();
        assert!(why.contains("b/packages.lock.json"), "{why}");
    }
}
