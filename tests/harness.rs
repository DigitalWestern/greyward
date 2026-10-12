//! The shared harness's own checks: which `HOME` it refuses for a run in a
//! given directory (#560, #656). Containment is physical, so every spelling
//! of one directory gets one answer.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

mod common;

use common::{child_home, command_for, home_inside_cwd, TempDir};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A scratch root with `project/` and `home/` side by side.
fn layout(label: &str) -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new(label);
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    (temp, project, home)
}

#[test]
fn nested_home_is_refused() {
    let (_temp, project, _) = layout("harness-nested");
    let nested = project.join("home");
    std::fs::create_dir_all(&nested).unwrap();
    assert!(home_inside_cwd(&project, &nested));
    // Below a HOME that does not exist yet, too.
    assert!(home_inside_cwd(&project, &project.join("later/home")));
}

#[test]
fn home_equal_to_cwd_is_allowed() {
    let (temp, _, _) = layout("harness-equal");
    assert!(!home_inside_cwd(temp.path(), temp.path()));
    // Equal in another spelling is still equal.
    let spelled = temp.path().join("project/..");
    assert!(!home_inside_cwd(temp.path(), &spelled));
    let slash = PathBuf::from(format!("{}/", temp.path().display()));
    assert!(!home_inside_cwd(&slash, temp.path()));
}

#[test]
fn sibling_home_is_allowed() {
    let (_temp, project, home) = layout("harness-sibling");
    assert!(!home_inside_cwd(&project, &home));
    // A sibling whose name extends the project's is not inside it.
    let longer = project.with_file_name("project-home");
    std::fs::create_dir_all(&longer).unwrap();
    assert!(!home_inside_cwd(&project, &longer));
    // HOME above the project is not inside it either.
    assert!(!home_inside_cwd(&project, project.parent().unwrap()));
}

#[test]
fn root_cwd_is_allowed() {
    let (_temp, _, home) = layout("harness-root");
    assert!(!home_inside_cwd(Path::new("/"), &home));
    assert!(!home_inside_cwd(Path::new("/."), &home));
    assert!(!home_inside_cwd(Path::new("/.."), &home));
    assert!(!home_inside_cwd(Path::new("//"), &home));
}

#[cfg(unix)]
#[test]
fn root_cwd_through_a_symlink_is_allowed() {
    let (temp, _, home) = layout("harness-root-link");
    let root = temp.path().join("root-link");
    std::os::unix::fs::symlink("/", &root).unwrap();
    assert!(!home_inside_cwd(&root, &home));
}

#[test]
fn relative_cwd_resolves_against_the_process_cwd() {
    let here = std::env::current_dir().unwrap();
    let project = Path::new("target/harness-656/project");
    assert!(home_inside_cwd(project, &here.join(project).join("home")));
    assert!(home_inside_cwd(
        &here.join(project),
        &here.join(project).join("x/home")
    ));
    assert!(!home_inside_cwd(
        project,
        &here.join("target/harness-656/home")
    ));
    assert!(!home_inside_cwd(project, &here.join(project)));
}

#[test]
fn relative_home_resolves_against_the_cwd() {
    let (_temp, project, home) = layout("harness-relative-home");
    // The child, started in the project, finds `home` inside it.
    assert_eq!(
        child_home(&project, Path::new("home")),
        project.join("home")
    );
    assert!(home_inside_cwd(&project, Path::new("home")));
    assert!(home_inside_cwd(&project, Path::new("./x/../home")));
    // `../home` from the project is the sibling.
    assert!(!home_inside_cwd(&project, Path::new("../home")));
    assert!(!home_inside_cwd(&project, Path::new(".")));
    assert_eq!(
        common::physical(&child_home(&project, Path::new("../home"))),
        home
    );
    // Relative on both sides: the cwd against the process, HOME against it.
    let relative = Path::new("target/harness-656/project");
    assert!(home_inside_cwd(relative, Path::new("home")));
    assert!(!home_inside_cwd(relative, Path::new("../home")));
}

#[test]
fn the_child_gets_the_home_that_was_judged() {
    let (_temp, project, home) = layout("harness-child-home");
    let env = |command: &Command, name: &str| {
        command
            .get_envs()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| value)
            .map(PathBuf::from)
    };
    let store = home.join("store");
    let binary = Path::new(env!("CARGO_BIN_EXE_ward"));
    let command = command_for(binary, &project, Path::new("../home"), &store);
    let given = env(&command, "HOME").unwrap();
    assert!(given.is_absolute(), "{}", given.display());
    assert_eq!(given, project.join("../home"));
    assert_eq!(common::physical(&given), home);
    assert_eq!(command.get_current_dir(), Some(project.as_path()));
    assert_eq!(
        env(&command, "GREYWARD_RELEASE_MANIFEST").unwrap(),
        PathBuf::from(format!(
            "file://{}",
            project.join("../home/no-release.json").display()
        ))
    );
    // An absolute HOME goes through as given.
    let command = command_for(binary, &project, &home, &store);
    assert_eq!(env(&command, "HOME").unwrap(), home);
}

/// The home-derived store sits under the HOME the child gets, so a relative
/// HOME and `-C` cannot point the two at different directories.
#[test]
fn the_home_store_follows_the_child_home() {
    let (_temp, project, home) = layout("harness-home-store");
    let store = common::home_store(&project, Path::new("../home"));
    assert!(store.is_absolute(), "{}", store.display());
    assert_eq!(store, project.join("../home/store"));
    assert_eq!(common::physical(&store), home.join("store"));
    assert_eq!(common::home_store(&project, &home), home.join("store"));
}

#[test]
#[should_panic(expected = "is inside the directory ward runs in")]
fn the_child_never_gets_a_relative_home_inside_its_cwd() {
    let (_temp, project, _) = layout("harness-child-nested");
    let binary = Path::new(env!("CARGO_BIN_EXE_ward"));
    command_for(binary, &project, Path::new("home"), &project.join("store"));
}

#[test]
fn dot_components_are_normalized() {
    let (_temp, project, home) = layout("harness-dots");
    // Lexically below the project, physically its sibling.
    assert!(!home_inside_cwd(&project, &project.join("../home")));
    assert!(!home_inside_cwd(&project, &project.join("./../home/.")));
    // Lexically beside the project, physically inside it.
    let nested = project.join("home");
    std::fs::create_dir_all(&nested).unwrap();
    assert!(home_inside_cwd(&project, &home.join("../project/home")));
    assert!(home_inside_cwd(&project.join("."), &project.join("./home")));
    assert!(home_inside_cwd(&home.join("../project"), &nested));
}

#[test]
fn trailing_separators_are_ignored() {
    let (_temp, project, home) = layout("harness-trailing");
    let nested = project.join("home");
    std::fs::create_dir_all(&nested).unwrap();
    let with_slash = |path: &Path| PathBuf::from(format!("{}/", path.display()));
    assert!(home_inside_cwd(&with_slash(&project), &nested));
    assert!(home_inside_cwd(&project, &with_slash(&nested)));
    assert!(!home_inside_cwd(&with_slash(&project), &with_slash(&home)));
}

#[cfg(unix)]
#[test]
fn symlink_alias_into_the_project_is_refused() {
    let (temp, project, _) = layout("harness-alias-in");
    let nested = project.join("home");
    std::fs::create_dir_all(&nested).unwrap();
    // temp/home-link names temp/project/home: lexically a sibling.
    let alias = temp.path().join("home-link");
    std::os::unix::fs::symlink(&nested, &alias).unwrap();
    assert!(!alias.starts_with(&project));
    assert!(home_inside_cwd(&project, &alias));
    // The project reached through an alias, HOME through its real path.
    let project_alias = temp.path().join("project-link");
    std::os::unix::fs::symlink(&project, &project_alias).unwrap();
    assert!(home_inside_cwd(&project_alias, &nested));
    // An alias of the project itself is the equal-directory layout.
    assert!(!home_inside_cwd(&project, &project_alias));
}

#[cfg(unix)]
#[test]
fn symlink_out_of_the_project_is_allowed() {
    let (_temp, project, home) = layout("harness-alias-out");
    // temp/project/home names temp/home: lexically nested, physically not.
    let alias = project.join("home");
    std::os::unix::fs::symlink(&home, &alias).unwrap();
    assert!(alias.starts_with(&project));
    assert!(!home_inside_cwd(&project, &alias));
}

#[cfg(unix)]
#[test]
fn dot_dot_after_a_symlink_leaves_its_target() {
    let (temp, project, _) = layout("harness-alias-dotdot");
    let deep = project.join("deep");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::create_dir_all(project.join("home")).unwrap();
    // temp/link names temp/project/deep. temp/link/../home is temp/home
    // when `..` collapses lexically, temp/project/home on disk.
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&deep, &link).unwrap();
    assert!(home_inside_cwd(&project, &link.join("../home")));
    // A HOME not yet created below the target's parent, too.
    assert!(home_inside_cwd(&project, &link.join("../later")));
}
