//! `ward plan`: print each detected ecosystem's plan as JSON without
//! realizing anything, through the tailor registry.

use crate::comforter::toolchain::{self as project_toolchain, Mode};
use crate::commands::shared::{ecosystem_inputs, no_inputs};
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy;
use crate::kernel::resolve::{ledger, DoorKind, ResolutionDoor};
use crate::kernel::ui;
use crate::tailors;
use std::io;

/// Plan every ecosystem here and print the plans: one JSON document per
/// ecosystem, or under `json` one array of them, which any JSON parser
/// reads in one call. Nothing reaches stdout until every plan is made, so
/// stdout holds the plans and nothing else, whatever a tool printed.
pub fn run(ctx: &Context, frozen: bool, json: bool) -> io::Result<()> {
    // `prepare` runs the ecosystem's own tool (npm prints "up to date in
    // 1s"), and stdout is the plan: point it at stderr while planning, as
    // `env` does before it prints.
    let plans = ui::with_stdout_on_stderr(|| plans(ctx, frozen))?;
    if plans.is_empty() {
        return Err(no_inputs());
    }
    print!("{}", render(&plans, json));
    Ok(())
}

/// The printed form: each document on its own line, or one array of them.
fn render(plans: &[String], json: bool) -> String {
    if json {
        format!(
            "[
{}
]
",
            plans.join(
                ",
"
            )
        )
    } else {
        plans
            .iter()
            .map(|plan| {
                format!(
                    "{plan}
"
                )
            })
            .collect()
    }
}

/// Each detected ecosystem's plan, in registry order.
fn plans(ctx: &Context, frozen: bool) -> io::Result<Vec<String>> {
    let dir = ctx.project_dir();
    // One descriptor for the whole plan, as sync holds one.
    let root = ProjectRoot::open(&dir)?;
    let _policy = policy::init_in(&root)?;
    let present = tailors::detected_in(&root)?;
    // The toolchain lock is read, never written: a project without one
    // plans against the shipped selection. A missing dependency lock is
    // another matter: unless frozen, `prepare` below generates it.
    let toolchain = project_toolchain::resolve(
        &root,
        ctx.platform,
        ecosystem_inputs(&present)?,
        Mode::ReadOnly,
        false,
    )?;
    let mut plans = Vec::new();
    for tailor in &present {
        let selected = toolchain.get(tailor.lock_ecosystem())?;
        let mut attribution = policy::Attribution::open("plan")?;
        // `prepare` is missing-lock generation: it runs the ecosystem's own
        // tool in the project and writes a dependency lock. Frozen promises
        // not to modify project inputs, so it never reaches that call at
        // all; a project with no dependency lock fails inside the tailor,
        // which is the one place that knows which file is missing.
        if !frozen {
            let mut door = ResolutionDoor::open(
                &ctx.store,
                &ctx.activity,
                ctx.platform,
                DoorKind::MissingLock,
                &mut attribution,
            )?;
            tailor.prepare(ctx, &root, selected, &mut door)?;
        }
        let mut door = ResolutionDoor::open(
            &ctx.store,
            &ctx.activity,
            ctx.platform,
            DoorKind::Planner,
            &mut attribution,
        )?;
        let text = tailor.plan(ctx, &root, selected, &mut door)?;
        // A plan that generated an sdist's Cargo.lock ran it through a
        // Detached door: its ledger is the lock's evidence, rooted under
        // this project while the plan still holds its lease, as sync does.
        for objects in door.take_kept_ledgers() {
            ledger::root(&ctx.store, &ctx.activity, &root, &objects)?;
        }
        plans.extend(text);
        attribution.discard();
    }
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::render;

    /// Under --json several plans are one document a JSON parser reads in
    /// one call, never documents back to back; one plan is a one-item
    /// array, so the shape never depends on how many ecosystems there are.
    #[test]
    fn json_plans_are_one_array() {
        let plans = ["{\n  \"a\": 1\n}".to_string(), "{\"b\": 2}".to_string()];
        let value: serde_json::Value = serde_json::from_str(&render(&plans, true)).unwrap();
        assert_eq!(value, serde_json::json!([{"a": 1}, {"b": 2}]));
        let one: serde_json::Value = serde_json::from_str(&render(&plans[..1], true)).unwrap();
        assert_eq!(one, serde_json::json!([{"a": 1}]));
        assert_eq!(render(&plans, false), "{\n  \"a\": 1\n}\n{\"b\": 2}\n");
    }
}
