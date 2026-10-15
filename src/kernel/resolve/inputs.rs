//! Conservative input coverage for executable project manifests. The
//! resolver sees only the listed project files and its private scratch.

use super::snapshot::PathGlob;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// How many symlinks one link's resolution may pass through, as the
/// kernel's own limit (`MAXSYMLINKS`) on Linux.
const MAX_LINK_HOPS: usize = 40;

/// List every regular file and symlink the project snapshot permits,
/// except outputs and the excluded patterns (the tool's own state and
/// everything ward projects into the project, from
/// `tailors::resolution_excludes`).
///
/// A symlink is listed as itself, not followed: the snapshot copies it as
/// a link and the receipt records its target text
/// (`record::symlink_digest`). A link whose target leaves the project is
/// refused, because the resolver's copy of the project would not hold what
/// it points at and the receipt could not cover it. A link to a directory
/// in the project is not walked through; the directory is walked where it
/// really is.
pub(crate) fn project_files(
    project: &ProjectRoot,
    excludes: &[&str],
    outputs: &[&str],
) -> io::Result<Vec<PathBuf>> {
    let excludes = excludes
        .iter()
        .map(|pattern| PathGlob::new(pattern))
        .collect::<io::Result<Vec<_>>>()?;
    let mut files = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let dir = if relative.as_os_str().is_empty() {
            project.try_clone()?
        } else {
            project.subdir(&relative)?.ok_or_else(|| {
                io::Error::other(format!(
                    "{} vanished while listing resolution inputs",
                    relative.display()
                ))
            })?
        };
        for name in dir.read_input_dir(Path::new("."))?.unwrap_or_default() {
            let path = relative.join(&name);
            if excludes.iter().any(|pattern| pattern.matches(&path))
                || outputs.iter().any(|output| path == Path::new(output))
            {
                continue;
            }
            match dir.entry(Path::new(&name))? {
                Entry::Regular => files.push(path),
                Entry::Directory => pending.push(path),
                Entry::Symlink => {
                    let target = dir.read_link(Path::new(&name))?.ok_or_else(|| {
                        io::Error::other(format!(
                            "{} vanished while listing resolution inputs",
                            path.display()
                        ))
                    })?;
                    refuse_escaping_link(project, &path, &target)?;
                    files.push(path);
                }
                _ => {}
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Refuse the symlink at `link` (project-relative) when following `target`
/// from where the link sits would leave the project. Resolved the way the
/// kernel resolves it: each `..` climbs from where the path really is, so
/// a link that passes through another link is followed through it (a
/// purely textual check would let `d/up -> ..` and `x -> d/up/../out`
/// through). A component that does not exist ends what the project can
/// show; the rest is checked by its text alone.
fn refuse_escaping_link(project: &ProjectRoot, link: &Path, target: &Path) -> io::Result<()> {
    let escapes = |why: &str| {
        io::Error::other(format!(
            "{} is a symlink to {}, which {why}; executable-manifest resolution copies only \
             the project, so the resolver could not read it and the receipt could not cover \
             it. Point the link inside the project or replace it with a regular file",
            link.display(),
            target.display()
        ))
    };
    let mut at: Vec<OsString> = link
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect();
    let mut queue: VecDeque<OsString> = VecDeque::new();
    let push_front = |queue: &mut VecDeque<OsString>, text: &Path| -> Result<(), ()> {
        let mut parts = Vec::new();
        for component in text.components() {
            match component {
                Component::Normal(name) => parts.push(name.to_os_string()),
                Component::ParentDir => parts.push(OsString::from("..")),
                Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) => return Err(()),
            }
        }
        for part in parts.into_iter().rev() {
            queue.push_front(part);
        }
        Ok(())
    };
    push_front(&mut queue, target).map_err(|()| escapes("is an absolute path"))?;
    let mut hops = 0usize;
    let mut textual = false;
    while let Some(part) = queue.pop_front() {
        if part == ".." {
            if at.pop().is_none() {
                return Err(escapes("climbs out of the project"));
            }
            continue;
        }
        at.push(part);
        if textual {
            continue;
        }
        let here: PathBuf = at.iter().collect();
        match project.entry(&here) {
            Ok(Entry::Directory) => {}
            Ok(Entry::Symlink) => {
                hops += 1;
                if hops > MAX_LINK_HOPS {
                    return Err(escapes("passes through too many symlinks"));
                }
                let Some(next) = project.read_link(&here)? else {
                    textual = true;
                    continue;
                };
                at.pop();
                push_front(&mut queue, &next).map_err(|()| {
                    escapes(&format!(
                        "reaches {}, a symlink to an absolute path",
                        here.display()
                    ))
                })?;
            }
            // Absent, a file used as a directory, or unreadable: the kernel
            // stops here too, so nothing past it can be reached.
            _ => textual = true,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn coverage_includes_nested_code_and_data_but_not_hidden_resolver_state() {
        let temp = TempDir::new();
        for directory in ["apps/web", "config/nested", ".greyward", ".git", "deps"] {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        for file in [
            "mix.exs",
            "mix.lock",
            "apps/web/mix.exs",
            "config/nested/data.json",
            ".greyward/closure.json",
            ".git/config",
            "deps/dep.exs",
        ] {
            fs::write(temp.0.join(file), "input").unwrap();
        }
        let held = ProjectRoot::open(&temp.0).unwrap();
        let files = project_files(
            &held,
            &[".greyward", ".git", "deps"],
            &["mix.exs", "mix.lock"],
        )
        .unwrap();
        assert_eq!(
            files,
            vec![
                PathBuf::from("apps/web/mix.exs"),
                PathBuf::from("config/nested/data.json")
            ]
        );
    }

    /// An in-project link is an input of its own, listed and not walked
    /// through; the directory it names is walked where it is.
    #[test]
    fn an_in_project_symlink_is_listed_as_itself() {
        let temp = TempDir::new();
        fs::create_dir_all(temp.0.join("test/source/data")).unwrap();
        fs::write(temp.0.join("test/source/data/a.yml"), "a").unwrap();
        symlink("data", temp.0.join("test/source/_data")).unwrap();
        symlink("../../Gemfile", temp.0.join("test/source/gemfile-link")).unwrap();
        symlink("missing/file", temp.0.join("dangling")).unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        assert_eq!(
            project_files(&held, &[".git"], &[]).unwrap(),
            vec![
                PathBuf::from("dangling"),
                PathBuf::from("test/source/_data"),
                PathBuf::from("test/source/data/a.yml"),
                PathBuf::from("test/source/gemfile-link"),
            ]
        );
    }

    #[test]
    fn a_symlink_out_of_the_project_is_refused() {
        for (name, target) in [
            ("absolute", "/etc/passwd"),
            ("climbing", "../outside"),
            ("deep/climbing", "../../outside"),
        ] {
            let temp = TempDir::new();
            fs::create_dir_all(temp.0.join("deep")).unwrap();
            symlink(target, temp.0.join(name)).unwrap();
            let held = ProjectRoot::open(&temp.0).unwrap();
            let error = project_files(&held, &[], &[]).unwrap_err();
            assert!(
                error.to_string().contains("is a symlink to"),
                "{name}: {error}"
            );
        }
    }

    /// `d/up -> ..` stays in the project by its text and by where it
    /// lands; `x -> d/up/../out` stays in by its text alone, but the
    /// kernel climbs from where `d/up` really is, the project root, and
    /// lands outside.
    #[test]
    fn a_link_that_escapes_through_another_link_is_refused() {
        let temp = TempDir::new();
        fs::create_dir_all(temp.0.join("d")).unwrap();
        symlink("..", temp.0.join("d/up")).unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        assert_eq!(
            project_files(&held, &[], &[]).unwrap(),
            vec![PathBuf::from("d/up")]
        );
        symlink("d/up/../out", temp.0.join("x")).unwrap();
        let error = project_files(&held, &[], &[]).unwrap_err();
        assert!(error.to_string().contains("climbs out"), "{error}");
        fs::remove_file(temp.0.join("x")).unwrap();
        symlink("loop-b", temp.0.join("loop-a")).unwrap();
        symlink("loop-a", temp.0.join("loop-b")).unwrap();
        let error = project_files(&held, &[], &[]).unwrap_err();
        assert!(error.to_string().contains("too many symlinks"), "{error}");
    }

    /// Ward's own projections are never walked, whatever they point at.
    #[test]
    fn excluded_projections_are_not_inputs() {
        let temp = TempDir::new();
        fs::create_dir_all(temp.0.join("packages/web")).unwrap();
        fs::write(temp.0.join("Gemfile"), "source").unwrap();
        symlink("/nix/store/forest", temp.0.join("node_modules")).unwrap();
        symlink("/elsewhere", temp.0.join("packages/web/node_modules")).unwrap();
        symlink("/store/env", temp.0.join(".venv")).unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        assert!(project_files(&held, &[], &[]).is_err());
        assert_eq!(
            project_files(&held, &["**/node_modules", "**/.venv"], &[]).unwrap(),
            vec![PathBuf::from("Gemfile")]
        );
    }
}
