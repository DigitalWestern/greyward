//! The Ruby planner-to-closure pipeline under concurrent writers
//! (`tailors::pipeline`): the real `plan_ruby` through a planner door, with
//! a stand-in store Ruby whose helper checks pass and whose lock-only plan
//! names the digest of the Gemfile.lock it read in the stage, and the real
//! `project_ruby_env`.

use super::*;
use crate::comforter::join::Digests;
use crate::kernel::activity::StoreActivity;
use crate::kernel::policy::Attribution;
use crate::kernel::resolve::ledger::LedgerObjects;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::types::Identity;
use crate::tailors::pipeline::{Gen, Pipeline};
use serde_json::Value;

struct RubyPipeline;

/// The stand-in `ruby`: `helper.rb check` passes, `helper.rb plan` prints a
/// lock-only plan whose Bundler version is the sha256 of the staged
/// Gemfile.lock, so a closure shows which lock its plan read.
const RUBY: &str = r#"#!/usr/bin/bash
set -eu
case "$2" in
check) exit 0 ;;
plan)
    digest=$(sha256sum Gemfile.lock)
    printf '{"ruby_platform":"x86_64-linux","bundler":"%s","gems":[]}' "${digest%% *}"
    ;;
*) exit 64 ;;
esac
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

impl Pipeline for RubyPipeline {
    const ECOSYSTEM: &'static str = "ruby";
    const LOCK: &'static str = "Gemfile.lock";
    const LOCK_SHA_FIELD: &'static str = "gemfile_lock_sha256";
    type Plan = RubyPlan;

    fn tailor() -> &'static dyn crate::tailors::Tailor {
        &tailor::Ruby
    }

    fn selected() -> Selected {
        shipped_selection().unwrap()
    }

    fn files(generation: Gen) -> Vec<(&'static str, String)> {
        let (version, extra) = match generation {
            Gen::A => ("13.2.1", "A"),
            Gen::B => ("13.3.0", "B"),
        };
        vec![
            (
                "Gemfile",
                "source \"https://rubygems.org\"\neval_gemfile \"gems.rb\"\n".into(),
            ),
            ("gems.rb", format!("gem \"rake\" # generation {extra}\n")),
            (
                "Gemfile.lock",
                format!("GEM\n  remote: https://rubygems.org/\n  specs:\n    rake ({version})\n"),
            ),
        ]
    }

    fn objects(store: &Store) -> (String, String) {
        let ruby = standin(store, "ruby", |dir| {
            use std::os::unix::fs::PermissionsExt;
            fs::create_dir_all(dir.join("bin")).unwrap();
            fs::write(dir.join("bin/ruby"), RUBY).unwrap();
            fs::set_permissions(dir.join("bin/ruby"), fs::Permissions::from_mode(0o555)).unwrap();
        });
        let gems = standin(store, "gems", |dir| {
            fs::create_dir_all(dir.join("gems")).unwrap();
        });
        (ruby, gems)
    }

    fn plan(
        door: &mut ResolutionDoor<'_>,
        project: &ProjectRoot,
        runtime: &Path,
        selected: &Selected,
    ) -> io::Result<(RubyPlan, String, Digests)> {
        plan_ruby(door, project, runtime, selected)
    }

    fn publish(
        activity: &StoreActivity,
        project: &ProjectRoot,
        runtime: &Path,
        env: &Path,
        plan: &RubyPlan,
        lock_sha256: &str,
        basis: &Digests,
        selected: &Selected,
        ledgers: &[LedgerObjects],
        attribution: &mut Attribution,
    ) -> io::Result<()> {
        project_ruby_env(
            activity,
            project,
            runtime,
            env,
            plan,
            lock_sha256,
            basis,
            selected,
            ledgers,
            attribution,
        )
    }

    fn planned_lock(body: &Value) -> String {
        body["plan"]["bundler_version"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn forest(_: &Store, _: &Path, _: &Path) -> Option<PathBuf> {
        None
    }
}

crate::tailors::pipeline::pipeline_scenarios!(RubyPipeline, "ruby");
