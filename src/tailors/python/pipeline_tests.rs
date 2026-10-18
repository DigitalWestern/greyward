//! The Python planner-to-closure pipeline under concurrent writers
//! (`tailors::pipeline`): the real `plan_sync` (the manifest and uv.lock
//! read through an observing root, the basis, the observed-input check),
//! and the real `project_env_with_inputs`, which joins before it switches
//! `.venv`. Realization is a stand-in: each generation's environment is a
//! store object of its own.

use crate::comforter::join::Digests;
use crate::comforter::InputRecord;
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy::Attribution;
use crate::kernel::resolve::ledger::LedgerObjects;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::types::{Identity, Plan};
use crate::tailors::pipeline::{Gen, Pipeline};
use crate::tailors::python::pyselect::PythonSelection;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

struct PythonPipeline;

/// The one locked package's version in `generation`.
fn version(generation: Gen) -> &'static str {
    match generation {
        Gen::A => "1.16.0",
        Gen::B => "1.17.0",
    }
}

fn standin(store: &Store, name: &str, fill: impl FnOnce(&Path)) -> String {
    store.publish_bare_with(
        &Identity {
            kind: "test".into(),
            name: name.into(),
            version: "0".into(),
            inputs: Default::default(),
        },
        fill,
    )
}

/// The environment a plan of `generation` realizes to.
fn environment(store: &Store, generation: Gen) -> String {
    standin(store, &format!("python-env-{generation:?}"), |dir| {
        let site = dir.join("lib/python3.12/site-packages");
        fs::create_dir_all(&site).unwrap();
        fs::write(
            site.join("six.py"),
            format!("# six {}\n", version(generation)),
        )
        .unwrap();
    })
}

impl Pipeline for PythonPipeline {
    const ECOSYSTEM: &'static str = "python";
    const LOCK: &'static str = "uv.lock";
    const LOCK_SHA_FIELD: Option<&'static str> = None;
    const CONFINED: bool = false;
    const LINK: Option<(&'static str, &'static str)> = Some((".venv", "env_object"));
    type Plan = (Plan, PythonSelection, Vec<InputRecord>);

    fn tailor() -> &'static dyn crate::tailors::Tailor {
        &crate::tailors::python::tailor::Python
    }

    fn selected() -> Selected {
        crate::kernel::provider::cpython::shipped_selection("3.12").unwrap()
    }

    fn files(generation: Gen) -> Vec<(&'static str, String)> {
        let version = version(generation);
        let digest = "0".repeat(64);
        vec![
            (
                "pyproject.toml",
                "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n\
                 requires-python = \">=3.12\"\ndependencies = [\"six\"]\n"
                    .into(),
            ),
            (
                "uv.lock",
                format!(
                    "version = 1\nrequires-python = \">=3.12\"\n\n\
                     [[package]]\nname = \"demo\"\nversion = \"0.1.0\"\n\
                     source = {{ editable = \".\" }}\ndependencies = [{{ name = \"six\" }}]\n\n\
                     [[package]]\nname = \"six\"\nversion = \"{version}\"\n\
                     source = {{ registry = \"https://pypi.org/simple\" }}\n\
                     wheels = [{{ url = \"https://files.pythonhosted.org/six-{version}-py2.py3-none-any.whl\", \
                     hash = \"sha256:{digest}\" }}]\n"
                ),
            ),
        ]
    }

    fn objects(store: &Store) -> (String, [String; 2]) {
        let runtime = standin(store, "cpython", |dir| {
            fs::create_dir_all(dir.join("bin")).unwrap();
        });
        (
            runtime,
            [environment(store, Gen::A), environment(store, Gen::B)],
        )
    }

    fn plan(
        door: &mut ResolutionDoor<'_>,
        project: &ProjectRoot,
        _runtime: &Path,
        selected: &Selected,
    ) -> io::Result<(Self::Plan, String, Digests)> {
        let (plan, selection, inputs, basis) =
            crate::tailors::python::tailor::plan_sync(project, selected, door)?;
        let lock = basis[Self::LOCK].clone();
        Ok(((plan, selection, inputs), lock, basis))
    }

    fn publish(
        activity: &StoreActivity,
        project: &ProjectRoot,
        _runtime: &Path,
        env: &Path,
        (plan, selection, inputs): &Self::Plan,
        _lock_sha256: &str,
        basis: &Digests,
        _selected: &Selected,
        ledgers: &[LedgerObjects],
        attribution: &mut Attribution,
    ) -> io::Result<()> {
        crate::tailors::python::env::project_env_with_inputs(
            activity,
            project,
            env,
            plan,
            selection,
            inputs,
            None,
            &Value::Null,
            ledgers,
            basis,
            attribution,
        )
    }

    fn planned(body: &Value) -> String {
        body["plan"]["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|package| package["name"] == "six")
            .and_then(|package| package["version"].as_str())
            .unwrap_or_default()
            .to_string()
    }

    fn planned_as(generation: Gen) -> String {
        version(generation).into()
    }

    fn forest(_: &Store, _: &Path, _: &Path) -> Option<PathBuf> {
        None
    }
}

crate::tailors::pipeline::pipeline_scenarios!(PythonPipeline, "python");
