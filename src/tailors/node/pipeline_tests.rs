//! The Node planner-to-closure pipeline under concurrent writers
//! (`tailors::pipeline`): the real `plan_sync` (one read of
//! package-lock.json, the freshness check, the observed-input check), and
//! the real `project_node_env_recorded`, which rebuilds the forest and
//! switches `node_modules` to it. Realization is a stand-in: each
//! generation's package set is a store object of its own.

use crate::comforter::join::Digests;
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy::Attribution;
use crate::kernel::resolve::ledger::LedgerObjects;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::types::Identity;
use crate::tailors::node::{self, inputs, NpmPlan};
use crate::tailors::pipeline::{Gen, Pipeline};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

struct NodePipeline;

/// The one locked package's version in `generation`.
fn version(generation: Gen) -> &'static str {
    match generation {
        Gen::A => "1.0.0",
        Gen::B => "1.0.1",
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

/// The packages a plan of `generation` realizes to.
fn packages(store: &Store, generation: Gen) -> String {
    standin(store, &format!("node-env-{generation:?}"), |dir| {
        let package = dir.join("node_modules/c");
        fs::create_dir_all(&package).unwrap();
        fs::write(
            package.join("package.json"),
            format!("{{\"name\":\"c\",\"version\":\"{}\"}}", version(generation)),
        )
        .unwrap();
    })
}

impl Pipeline for NodePipeline {
    const ECOSYSTEM: &'static str = "node";
    const LOCK: &'static str = "package-lock.json";
    const LOCK_SHA_FIELD: Option<&'static str> = None;
    const CONFINED: bool = false;
    const LINK: Option<(&'static str, &'static str)> = Some(("node_modules", "forest_path"));
    type Plan = NpmPlan;

    fn tailor() -> &'static dyn crate::tailors::Tailor {
        &node::tailor::Node
    }

    fn selected() -> Selected {
        node::shipped_selection().unwrap()
    }

    fn files(generation: Gen) -> Vec<(&'static str, String)> {
        let version = version(generation);
        vec![
            (
                "package.json",
                r#"{"name":"demo","version":"1.0.0","dependencies":{"c":"^1.0.0"}}"#.into(),
            ),
            (
                "package-lock.json",
                format!(
                    r#"{{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"demo","version":"1.0.0","dependencies":{{"c":"^1.0.0"}}}},"node_modules/c":{{"version":"{version}","resolved":"https://registry.npmjs.org/c/-/c-{version}.tgz","integrity":"{}"}}}}}}"#,
                    node::tests::TEST_SRI
                ),
            ),
            (".npmrc", format!("# generation {generation:?}\n")),
        ]
    }

    fn objects(store: &Store) -> (String, [String; 2]) {
        let runtime = standin(store, "node", |dir| {
            fs::create_dir_all(dir.join("bin")).unwrap();
        });
        (runtime, [packages(store, Gen::A), packages(store, Gen::B)])
    }

    fn plan(
        door: &mut ResolutionDoor<'_>,
        project: &ProjectRoot,
        _runtime: &Path,
        selected: &Selected,
    ) -> io::Result<(NpmPlan, String, Digests)> {
        let planned =
            node::tailor::plan_sync(Platform::host()?, project, selected, door.attribution())?
                .expect("a package-lock.json project plans");
        let lock = planned.basis[Self::LOCK].clone();
        Ok((planned.plan, lock, planned.basis))
    }

    fn publish(
        activity: &StoreActivity,
        project: &ProjectRoot,
        _runtime: &Path,
        env: &Path,
        plan: &NpmPlan,
        _lock_sha256: &str,
        basis: &Digests,
        _selected: &Selected,
        _ledgers: &[LedgerObjects],
        attribution: &mut Attribution,
    ) -> io::Result<()> {
        let records = inputs::input_records(project, &["package.json", &plan.lock_source])?;
        // `fresh`: every sync rebuilds the forest, so a refused one would
        // destroy the active environment if it got that far.
        node::project_node_env_recorded(
            activity,
            project,
            env,
            Platform::host()?,
            plan,
            &[],
            true,
            &records,
            basis,
            None,
            &Value::Null,
            attribution,
        )
    }

    fn planned(body: &Value) -> String {
        body["packages"][0]["version"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn planned_as(generation: Gen) -> String {
        version(generation).into()
    }

    /// The forest `node_modules` links to: the producer derives its path
    /// from the plan, so the link is where to find it.
    fn forest(_: &Store, project: &Path, _: &Path) -> Option<PathBuf> {
        fs::read_link(project.join("node_modules"))
            .ok()
            .filter(|forest| forest.is_dir())
    }
}

crate::tailors::pipeline::pipeline_scenarios!(NodePipeline, "node");
