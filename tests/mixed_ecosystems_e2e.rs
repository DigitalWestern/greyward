//! End-to-end: one project, two ecosystems. Heavy: downloads the pinned
//! Node and Ruby and one gem.
//!
//! The node tailor syncs first and leaves its `node_modules` link in the
//! project; the Ruby tailor's executable-manifest resolution must treat
//! that link as ward's own output, not as a Gemfile input. A symlink
//! checked into the repository that stays inside the project is recorded
//! as a link and copied into the resolver's snapshot. Incidental outward
//! links are omitted with an explicit exception. Required ones are refused.

// Tests spawn fixtures freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::Path;

mod common;

use common::{assert_ok, ward, TempDir};

fn project_files(project: &Path) {
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"mixed","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        project.join("package-lock.json"),
        r#"{"name":"mixed","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"mixed","version":"1.0.0"}}}"#,
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rake\", \"13.4.2\"\n",
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    rake (13.4.2)

PLATFORMS
  ruby

DEPENDENCIES
  rake (= 13.4.2)

BUNDLED WITH
   2.6.9
"#,
    )
    .unwrap();
    // A checked-in fixture link, the shape jekyll's test site has.
    std::fs::create_dir_all(project.join("test/source/data")).unwrap();
    std::fs::write(project.join("test/source/data/site.yml"), "title: x\n").unwrap();
    std::os::unix::fs::symlink("data", project.join("test/source/_data")).unwrap();
}

#[test]
#[ignore]
fn gemfile_and_package_json_sync_together_with_an_in_project_link() {
    let temp = TempDir::new("mixed-ecosystems");
    // Beside HOME, not under it: a resolution door refuses to mount a root
    // the default signing-key path lies under.
    let project = temp.0.join("project");
    std::fs::create_dir_all(&project).unwrap();
    project_files(&project);

    assert_ok(ward(&project, &temp.0, &["sync"]), "sync");
    assert!(
        std::fs::symlink_metadata(project.join("node_modules"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "node synced its link"
    );
    for closure in ["node", "ruby"] {
        assert!(
            project
                .join(format!(".greyward/closures/{closure}.json"))
                .is_file(),
            "{closure} closure written"
        );
    }
    // A second sync sees the node link from the first one and the same
    // checked-in link, and agrees with what it recorded.
    assert_ok(ward(&project, &temp.0, &["sync"]), "second sync");

    // A Jekyll-style fixture and a repository's linked assistant notes
    // must be absent from the resolver's copy, even though /etc and /usr
    // exist there. The original links remain in the checkout.
    std::os::unix::fs::symlink("/etc/passwd", project.join("test/escape")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/env", project.join("CLAUDE.md")).unwrap();
    std::fs::create_dir_all(project.join("fixtures/node_modules")).unwrap();
    std::fs::write(
        project.join("fixtures/node_modules/config.rb"),
        "$fixture_loaded = true\n",
    )
    .unwrap();
    let gemfile = std::fs::read_to_string(project.join("Gemfile")).unwrap();
    std::fs::write(project.join("Gemfile"), format!(
        "raise 'outward fixture copied' if File.exist?('test/escape') || File.symlink?('CLAUDE.md')\n\
         require_relative 'fixtures/node_modules/config'\n\
         raise 'fixture missing' unless $fixture_loaded\n\
         raise 'inward link missing' unless File.read('test/source/_data/site.yml').include?('title:')\n{gemfile}"
    )).unwrap();
    let key = temp.0.join("resolution.key");
    let trust = assert_ok(
        ward(&temp.0, &temp.0, &["keygen", key.to_str().unwrap()]),
        "keygen",
    );
    std::fs::create_dir_all(temp.0.join(".greyward")).unwrap();
    std::fs::write(temp.0.join(".greyward/policy.toml"), trust).unwrap();
    let env = [("GREYWARD_SIGNING_KEY", key.as_path())];
    assert_ok(
        common::ward_env(&project, &temp.0, &["attest", "ruby"], &env),
        "attest with omitted outward links",
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".greyward/resolution/ruby.json")).unwrap(),
    )
    .unwrap();
    for name in ["test/escape", "CLAUDE.md"] {
        assert!(
            receipt["exceptions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|exception| exception["kind"] == "outward-symlink"
                    && exception["subject"] == name),
            "{receipt}"
        );
        assert!(receipt["inputs"][name]
            .as_str()
            .unwrap()
            .starts_with("symlink:"));
        assert!(std::fs::symlink_metadata(project.join(name))
            .unwrap()
            .file_type()
            .is_symlink());
    }
    assert_ok(
        common::ward_env(&project, &temp.0, &["sync"], &env),
        "sync with signed symlink receipt",
    );
    std::fs::write(
        project.join("test/source/data/site.yml"),
        "title: changed\n",
    )
    .unwrap();
    assert_ok(
        common::ward_env(&project, &temp.0, &["sync"], &env),
        "sync after inward target edit",
    );
    let closure: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".greyward/closures/ruby.json")).unwrap(),
    )
    .unwrap();
    assert!(
        closure["body"]["exceptions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|exception| exception["kind"] == "unrecorded-resolution"
                && exception["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("stale-inputs")),
        "{closure}"
    );

    // A policy can refuse every omission before executing project code.
    std::fs::write(
        temp.0.join(".greyward/policy.toml"),
        "deny = [\"outward-symlink\"]\n",
    )
    .unwrap();
    let refused = ward(&project, &temp.0, &["sync"]);
    assert!(!refused.status.success());
    assert!(
        common::text(&refused.stderr).contains("policy denies outward-symlink"),
        "{}",
        common::text(&refused.stderr)
    );
    std::fs::write(temp.0.join(".greyward/policy.toml"), "").unwrap();
    std::fs::remove_file(project.join("Gemfile")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", project.join("Gemfile")).unwrap();
    let refused = ward(&project, &temp.0, &["sync"]);
    assert!(!refused.status.success(), "outward manifest accepted");
    assert!(
        common::text(&refused.stderr).contains("Gemfile is a symlink"),
        "{}",
        common::text(&refused.stderr)
    );
}

#[test]
#[ignore]
fn python_and_ruby_share_a_project_with_a_ward_venv() {
    let temp = TempDir::new("mixed-python-ruby");
    let project = temp.0.join("project");
    std::fs::create_dir_all(&project).unwrap();
    project_files(&project);
    std::fs::remove_file(project.join("package.json")).unwrap();
    std::fs::remove_file(project.join("package-lock.json")).unwrap();
    std::fs::write(project.join("pyproject.toml"), "[project]\nname = \"mixed\"\nversion = \"1.0.0\"\nrequires-python = \"~=3.11.0\"\ndependencies = []\n").unwrap();
    assert_ok(ward(&project, &temp.0, &["sync"]), "Python and Ruby sync");
    assert!(std::fs::symlink_metadata(project.join(".venv"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_ok(
        ward(&project, &temp.0, &["sync"]),
        "Ruby accepts Python's existing venv",
    );
    for ecosystem in ["python", "ruby"] {
        assert!(project
            .join(format!(".greyward/closures/{ecosystem}.json"))
            .is_file());
    }
}
