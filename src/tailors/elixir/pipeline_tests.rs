//! The Elixir planner-to-closure pipeline under concurrent writers
//! (`tailors::pipeline`): the real `plan_elixir` through a planner door
//! (the `--check-locked` gate and the helper's lock parse), with a
//! stand-in store BEAM whose gate passes and whose parse names the digest
//! of the mix.lock it was handed, and the real `project_elixir_env`, which
//! replaces the deps forest on every sync.

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
use crate::tailors::elixir::{self, ElixirPlan};
use crate::tailors::pipeline::{Gen, Pipeline};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

struct ElixirPipeline;

/// The stand-in `mix`: `deps.get --check-locked` passes.
const MIX: &str = r#"#!/usr/bin/bash
set -eu
[ "$1 $2" = "deps.get --check-locked" ] || exit 64
"#;

/// The stand-in `elixir`: `helper.exs lock <copy>` prints one dependency
/// whose checksums are the sha256 of the lock copy it parsed, so a closure
/// shows which lock its plan read.
const ELIXIR: &str = r#"#!/usr/bin/bash
set -eu
[ "$2" = "lock" ] || exit 64
digest=$(sha256sum "$3")
digest=${digest%% *}
printf '{"entries":[{"app":"standin","package":"standin","version":"1.0.0","inner_sha256":"%s","outer_sha256":"%s","managers":["mix"]}]}' "$digest" "$digest"
"#;

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

impl Pipeline for ElixirPipeline {
    const ECOSYSTEM: &'static str = "elixir";
    const LOCK: &'static str = "mix.lock";
    const LOCK_SHA_FIELD: Option<&'static str> = Some("mix_lock_sha256");
    const CONFINED: bool = true;
    const LINK: Option<(&'static str, &'static str)> = None;
    type Plan = ElixirPlan;

    fn tailor() -> &'static dyn crate::tailors::Tailor {
        &elixir::tailor::Elixir
    }

    fn selected() -> Selected {
        elixir::shipped_selection().unwrap()
    }

    fn files(generation: Gen) -> Vec<(&'static str, String)> {
        let (version, extra) = match generation {
            Gen::A => ("1.4.4", "A"),
            Gen::B => ("1.4.5", "B"),
        };
        vec![
            (
                "mix.exs",
                "defmodule Demo.MixProject do\n  use Mix.Project\n  def project, do: \
                 [app: :demo, version: \"0.1.0\", deps: [{:jason, \"~> 1.4\"}]]\nend\n"
                    .into(),
            ),
            (
                "config/config.exs",
                format!("import Config\n# generation {extra}\n"),
            ),
            (
                "mix.lock",
                format!("%{{\"jason\": {{:hex, :jason, \"{version}\", \"\", [:mix], [], \"hexpm\", \"\"}}}}\n"),
            ),
        ]
    }

    fn objects(store: &Store) -> (String, [String; 2]) {
        let beam = standin(store, "beam", |dir| {
            use std::os::unix::fs::PermissionsExt;
            let bin = dir.join("elixir/bin");
            fs::create_dir_all(&bin).unwrap();
            for (name, script) in [("mix", MIX), ("elixir", ELIXIR)] {
                fs::write(bin.join(name), script).unwrap();
                fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o555)).unwrap();
            }
        });
        let deps = standin(store, "deps", |dir| {
            fs::create_dir_all(dir.join("jason")).unwrap();
            fs::write(dir.join("jason/mix.exs"), "").unwrap();
        });
        // Both generations realize to one deps object, so a sync of
        // either projects into the same forest: a stale sync that reached
        // the forest would rebuild the active one.
        (beam, [deps.clone(), deps])
    }

    fn plan(
        door: &mut ResolutionDoor<'_>,
        project: &ProjectRoot,
        runtime: &Path,
        selected: &Selected,
    ) -> io::Result<(ElixirPlan, String, Digests)> {
        elixir::plan_elixir(door, project, runtime, selected)
    }

    fn publish(
        activity: &StoreActivity,
        project: &ProjectRoot,
        runtime: &Path,
        env: &Path,
        plan: &ElixirPlan,
        lock_sha256: &str,
        basis: &Digests,
        selected: &Selected,
        ledgers: &[LedgerObjects],
        attribution: &mut Attribution,
    ) -> io::Result<()> {
        // `fresh`: every sync replaces the forest, so a refused one would
        // destroy the active environment if it got that far.
        elixir::project_elixir_env(
            activity,
            Platform::host()?,
            project,
            runtime,
            env,
            plan,
            lock_sha256,
            basis,
            true,
            selected,
            ledgers,
            attribution,
        )
        .map(|_| ())
    }

    fn planned(body: &Value) -> String {
        body["plan"]["deps"][0]["inner_sha256"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn forest(store: &Store, project: &Path, env: &Path) -> Option<PathBuf> {
        let forest = elixir::expected_projection(store, project, env).unwrap();
        forest.is_dir().then_some(forest)
    }
}

crate::tailors::pipeline::pipeline_scenarios!(ElixirPipeline, "elixir", confined);
