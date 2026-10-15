//! End-to-end: one project, two ecosystems. Heavy: downloads the pinned
//! Node and Ruby and one gem.
//!
//! The node tailor syncs first and leaves its `node_modules` link in the
//! project; the Ruby tailor's executable-manifest resolution must treat
//! that link as ward's own output, not as a Gemfile input. A symlink
//! checked into the repository that stays inside the project is recorded
//! as a link and copied into the resolver's snapshot; one that leaves the
//! project is refused.

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

    // A link out of the project is refused by name, before any resolver
    // runs.
    std::os::unix::fs::symlink("../../outside", project.join("test/escape")).unwrap();
    let refused = ward(&project, &temp.0, &["sync"]);
    assert!(!refused.status.success(), "escaping link accepted");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("test/escape is a symlink to ../../outside"),
        "{stderr}"
    );
}
