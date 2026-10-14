//! `lookalike-name` at closure publication: every registry package a
//! closure about to be published names is judged against its registry's
//! popular names (`kernel::lookalike`), and each lookalike is recorded as
//! a plan-time exception of the project. The judgment reads the lock's
//! names, not built bytes, so every sync records it again, like the
//! resolution join's facts.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy::{self, LOOKALIKE_NAME};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

/// From a closure's ecosystem and body to the lookalikes among its
/// registry packages: each package name mapped to the popular name it is
/// one edit from. The tailors install it; a process that never installs
/// one judges nothing.
pub type LookalikeTable =
    dyn Fn(&str, &Value) -> io::Result<BTreeMap<String, String>> + Send + Sync;

static TABLE: Mutex<Option<Arc<LookalikeTable>>> = Mutex::new(None);

/// Install the table for this process. The first install wins.
pub fn install(table: Arc<LookalikeTable>) {
    let mut slot = TABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(table);
    }
}

fn table() -> Option<Arc<LookalikeTable>> {
    TABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Replace the table. Tests that set one hold `attribution_test_lock`
/// across the set, the judgment and the reset.
#[cfg(test)]
pub(crate) fn set_for_test(table: Option<Arc<LookalikeTable>>) {
    *TABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = table;
}

/// The detail a `lookalike-name` exception carries.
pub fn detail(popular: &str) -> String {
    format!("one edit from popular package {popular}")
}

/// Record a `lookalike-name` exception for each lookalike among the
/// closure's packages. A `ward x` cache root is not a project and records
/// none, as the join records nothing for one.
pub(crate) fn record_for_closure(
    project: &ProjectRoot,
    ecosystem: &str,
    body: &Value,
) -> io::Result<()> {
    if crate::comforter::is_cache_root(project.path()) {
        return Ok(());
    }
    let Some(table) = table() else {
        return Ok(());
    };
    let policy = policy::effective();
    for (name, popular) in table(ecosystem, body)? {
        policy::record_plan_time_with(&policy, LOOKALIKE_NAME, &name, &detail(&popular))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::{Attribution, Exception};
    use crate::kernel::testutil::TempDir;

    /// Each lookalike the table finds is a plan-time exception of the
    /// project, named by the package with the popular name in the detail.
    #[test]
    fn each_lookalike_is_recorded_against_the_project() {
        let _serial = policy::attribution_test_lock();
        let temp = TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        set_for_test(Some(Arc::new(|ecosystem: &str, body: &Value| {
            assert_eq!(ecosystem, "node");
            Ok(body["found"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, popular)| (name.clone(), popular.as_str().unwrap().to_string()))
                .collect())
        })));
        let attribution = Attribution::open("node").unwrap();
        let body = serde_json::json!({"found": {"lodahs": "lodash", "expres": "express"}});
        let result = record_for_closure(&project, "node", &body);
        set_for_test(None);
        result.unwrap();
        let exception = |subject: &str, popular: &str| Exception {
            kind: LOOKALIKE_NAME.to_string(),
            subject: subject.to_string(),
            detail: format!("one edit from popular package {popular}"),
        };
        assert_eq!(
            attribution.recorded(),
            [
                exception("expres", "express"),
                exception("lodahs", "lodash")
            ]
        );
        attribution.discard();
    }
}
