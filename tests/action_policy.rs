//! The GitHub Action's `Policy` step (`action.yml`), run here with bash as
//! the runner would run it: which `policy` inputs it turns into
//! `GREYWARD_POLICY`, and which it refuses. Offline, no ward binary needed.

// Tests spawn fixtures freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::TempDir;

/// The `run: |` block of the step named `name` in action.yml, de-indented.
fn step_script(name: &str) -> String {
    let action =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("action.yml")).unwrap();
    let mut lines = action.lines();
    lines
        .by_ref()
        .find(|line| line.trim() == format!("- name: {name}"))
        .unwrap_or_else(|| panic!("no step named {name}"));
    lines
        .by_ref()
        .find(|line| line.trim() == "run: |")
        .expect("the step has a run block");
    let mut body: Vec<&str> = Vec::new();
    let mut indent = None;
    for line in lines {
        if line.trim().is_empty() {
            body.push("");
            continue;
        }
        let width = line.len() - line.trim_start().len();
        let indent = *indent.get_or_insert(width);
        if width < indent {
            break;
        }
        body.push(&line[indent..]);
    }
    body.join("\n")
}

/// Run the Policy step with `input` as the `policy` input on `event`.
/// Returns whether it passed, what it wrote to `$GITHUB_ENV`, and its output.
fn policy_step(root: &Path, input: &str, event: &str) -> (bool, String, String) {
    let env_file = root.join("github_env");
    std::fs::write(&env_file, "").unwrap();
    let output = Command::new("bash")
        .arg("-c")
        .arg(step_script("Policy"))
        .env("GREYWARD_ACTION_POLICY", input)
        .env("GITHUB_EVENT_NAME", event)
        .env("GITHUB_WORKSPACE", root.join("workspace"))
        .env("GITHUB_ACTION_PATH", root.join("action"))
        .env("GITHUB_ENV", &env_file)
        .output()
        .unwrap();
    let written = std::fs::read_to_string(&env_file).unwrap();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), written, printed)
}

/// On a pull_request event a policy file from the workspace is the pull
/// request's own to edit, so the step refuses it, by relative or absolute
/// path, and still takes the shipped default or a file outside the
/// workspace. On any other event the workspace file is the trusted ref's.
#[test]
fn a_pull_request_cannot_supply_the_policy_that_judges_it() {
    let temp = TempDir::new("action-policy");
    let root = temp.0.canonicalize().unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("ci")).unwrap();
    std::fs::write(workspace.join("ci/policy.toml"), "deny = []\n").unwrap();
    let shipped = root.join("action/docs/human/policy-company.toml");
    std::fs::create_dir_all(shipped.parent().unwrap()).unwrap();
    std::fs::write(&shipped, "deny = []\n").unwrap();
    let outside: PathBuf = root.join("runner-temp-policy.toml");
    std::fs::write(&outside, "deny = []\n").unwrap();
    let absolute = workspace.join("ci/policy.toml");
    let absolute = absolute.to_str().unwrap();

    for input in ["ci/policy.toml", "./ci/../ci/policy.toml", absolute] {
        let (passed, written, printed) = policy_step(&root, input, "pull_request");
        assert!(!passed, "{input}: {printed}");
        assert_eq!(written, "", "{input}");
        assert!(
            printed.contains("the pull request can edit the policy that judges it"),
            "{input}: {printed}"
        );
        let (passed, written, printed) = policy_step(&root, input, "push");
        assert!(passed, "{input}: {printed}");
        assert_eq!(
            written,
            format!(
                "GREYWARD_POLICY={}\n",
                workspace.join("ci/policy.toml").display()
            )
        );
    }
    let (passed, written, printed) = policy_step(&root, "", "pull_request");
    assert!(passed, "{printed}");
    assert_eq!(written, format!("GREYWARD_POLICY={}\n", shipped.display()));
    let (passed, written, printed) = policy_step(&root, outside.to_str().unwrap(), "pull_request");
    assert!(passed, "{printed}");
    assert_eq!(written, format!("GREYWARD_POLICY={}\n", outside.display()));
    let (passed, written, _) = policy_step(&root, "none", "pull_request");
    assert!(passed);
    assert_eq!(written, "");
}
