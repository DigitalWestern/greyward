//! `node_modules/.bin` (node tailor): the launchers a sync links for the
//! packages a project can run by name.

use super::*;
use std::collections::btree_map::Entry;

/// .bin launchers for every placed package, each in the `.bin` of the
/// `node_modules` that holds it, as npm links them (`bin-links`'
/// `get-node-modules`): a hoisted package's into `node_modules/.bin`, a
/// nested one's into its parent's `node_modules/a/node_modules/.bin`, where
/// the parent's install scripts find that version first on PATH
/// ([`super::realize`]'s `lifecycle_path_env`).
///
/// Two packages in one `node_modules` that claim the same bin name keep the
/// first claim in plan order, as npm keeps the first; the one left out is
/// recorded as `file-collision`, subject the link's project path.
pub(super) fn link_package_bins(
    staged: &Path,
    packages: &[(NpmPackage, PathBuf)],
) -> io::Result<()> {
    // Per `.bin` directory: each bin name in folded form, with the name and
    // the package that claimed it first.
    let mut claimed = BTreeMap::<(PathBuf, String), (String, String)>::new();
    for (p, _) in packages {
        if p.bin.is_empty() {
            continue;
        }
        let (bin_dir_path, placed_name) = bin_dir_of(&p.path)?;
        let bin_dir = env_package_path(staged, &bin_dir_path);
        fs::create_dir_all(&bin_dir)?;
        for (bin_name, rel) in &p.bin {
            // bin metadata comes from the lockfile (attacker-editable), so
            // it is validated hard: single normal name component, relative
            // target with only normal components, canonical target inside
            // the package directory, not a symlink.
            let name_ok = !bin_name.is_empty()
                && !bin_name.starts_with('.')
                && !bin_name.contains('/')
                && !bin_name.contains('\\');
            let rel_path = normalized_bin_path(rel);
            if !name_ok || rel_path.is_err() {
                return Err(err(format!(
                    "{}: unsafe bin entry {bin_name:?} -> {rel:?}",
                    p.path
                )));
            }
            let rel_path = rel_path.unwrap();
            let pkg_dir = env_package_path(staged, &p.path);
            let target_file = pkg_dir.join(&rel_path);
            let md = match fs::symlink_metadata(&target_file) {
                Ok(md) => md,
                Err(_) => continue, // bin target genuinely absent: npm tolerates this
            };
            if !md.is_file() {
                return Err(err(format!(
                    "{}: bin target {rel} is not a regular file",
                    p.path
                )));
            }
            let canon = target_file.canonicalize()?;
            if !canon.starts_with(pkg_dir.canonicalize()?) {
                return Err(err(format!(
                    "{}: bin target {rel} escapes the package directory",
                    p.path
                )));
            }
            // Relative link: <node_modules>/.bin/x -> ../<name>/<rel>.
            let link_target = Path::new("..").join(placed_name).join(&rel_path);
            let link = bin_dir.join(bin_name);
            // A case-insensitive filesystem (APFS) keeps one of `Tool` and
            // `tool`, and the other command would run the wrong package.
            match claimed.entry((bin_dir.clone(), folded(bin_name))) {
                Entry::Occupied(first) if first.get().0 != *bin_name => {
                    let (first_name, first_path) = first.get();
                    return Err(err(format!(
                        "bin {bin_name:?} from {} and bin {first_name:?} from {first_path} \
                         differ only by case or Unicode normalization, so a case-insensitive \
                         filesystem would keep one of them",
                        p.path
                    )));
                }
                Entry::Occupied(first) => {
                    // Real graphs collide (playwright + @playwright/test
                    // both declare `playwright`). npm keeps the first claim;
                    // plan order is sorted, so first-wins is deterministic,
                    // and the closure says which one was left out.
                    let first_path = first.get().1.clone();
                    crate::kernel::policy::record(
                        crate::kernel::policy::FILE_COLLISION,
                        &format!("{bin_dir_path}/{bin_name}"),
                        &format!("{first_path} and {}; the first keeps it", p.path),
                    )?;
                    continue;
                }
                Entry::Vacant(slot) => {
                    slot.insert((bin_name.clone(), p.path.clone()));
                }
            }
            std::os::unix::fs::symlink(&link_target, &link)?;
            use std::os::unix::fs::PermissionsExt;
            let mut perms = md.permissions();
            perms.set_mode(perms.mode() | 0o755);
            fs::set_permissions(&target_file, perms)?;
        }
    }
    Ok(())
}

/// The project path of the `.bin` directory a package placed at `path`
/// links into, and the package's name below that `node_modules` (scoped
/// names keep their scope): `node_modules/a/node_modules/@s/b` links into
/// `node_modules/a/node_modules/.bin` as `@s/b`.
///
/// The holder is the last path component that is exactly `node_modules`
/// with a name after it, as bin-links' `get-node-modules` takes it: a scope
/// such as `@my-node_modules` only contains the word.
fn bin_dir_of(path: &str) -> io::Result<(String, &str)> {
    let components: Vec<&str> = path.split('/').collect();
    let holder = (0..components.len().saturating_sub(1))
        .rev()
        .find(|&index| components[index] == "node_modules")
        .ok_or_else(|| err(format!("{path}: not a node_modules placement")))?;
    let holder_len: usize = components[..=holder].iter().map(|c| c.len() + 1).sum();
    Ok((
        format!("{}/.bin", &path[..holder_len - 1]),
        &path[holder_len..],
    ))
}

/// A bin name as a case-insensitive filesystem compares it: Unicode NFC,
/// then lower case. Two names with the same folded form are one entry there.
fn folded(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization as _;
    name.nfc().collect::<String>().to_lowercase()
}

/// Bins land in the `.bin` of the `node_modules` that holds each package.
/// Two names that a case-insensitive filesystem would merge are refused;
/// the same name twice keeps npm's first claim, and the other is recorded.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn package(path: &str, bin: &str) -> (NpmPackage, PathBuf) {
        let package = NpmPackage {
            path: path.into(),
            name: path.rsplit('/').next().unwrap().into(),
            version: "1.0.0".into(),
            url: String::new(),
            integrity: String::new(),
            bin: vec![(bin.into(), "cli.js".into())],
            patch: None,
            git: None,
            foreign_platform: false,
            needs_workspace: false,
        };
        (package, PathBuf::new())
    }

    fn staged(paths: &[&str]) -> TempDir {
        let staged = TempDir::named("node-bins");
        for path in paths {
            let dir = env_package_path(&staged.0, path);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("cli.js"), "#!/usr/bin/env node\n").unwrap();
        }
        staged
    }

    #[test]
    fn bin_names_a_case_insensitive_filesystem_would_merge_are_refused() {
        for (first, second) in [
            ("Tool", "tool"),
            ("\u{e9}", "\u{c9}"),
            ("e\u{301}", "\u{e9}"),
        ] {
            let staged = staged(&["node_modules/a", "node_modules/b"]);
            let packages = [
                package("node_modules/a", first),
                package("node_modules/b", second),
            ];
            let error = link_package_bins(&staged.0, &packages).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "bin {second:?} from node_modules/b and bin {first:?} from node_modules/a \
                     differ only by case or Unicode normalization, so a case-insensitive \
                     filesystem would keep one of them"
                )
            );
        }
    }

    #[test]
    fn the_same_bin_name_keeps_the_first_claim_and_other_importers_are_separate() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let staged = staged(&[
            "node_modules/a",
            "node_modules/b",
            "packages/web/node_modules/c",
        ]);
        let packages = [
            package("node_modules/a", "tool"),
            package("node_modules/b", "tool"),
            package("packages/web/node_modules/c", "Tool"),
        ];
        link_package_bins(&staged.0, &packages).unwrap();
        let link = staged.0.join("node_modules/.bin/tool");
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("../a/cli.js"));
        let web = env_package_path(&staged.0, "packages/web/node_modules/.bin");
        assert_eq!(
            fs::read_link(web.join("Tool")).unwrap(),
            Path::new("../c/cli.js")
        );
        // The claim left out is in the closure, not only on the terminal.
        let recorded: Vec<(String, String, String)> = crate::kernel::policy::drain()
            .into_iter()
            .map(|e| (e.kind, e.subject, e.detail))
            .collect();
        assert_eq!(
            recorded,
            [(
                crate::kernel::policy::FILE_COLLISION.to_string(),
                "node_modules/.bin/tool".to_string(),
                "node_modules/a and node_modules/b; the first keeps it".to_string(),
            )]
        );
    }

    /// The audit's probe (#695): `tool@5` hoisted, `tool@7` nested under
    /// `a`. npm links the nested one into `node_modules/a/node_modules/.bin`,
    /// so `a`'s install script runs v7; ward linked hoisted bins only.
    /// Scoped and workspace placements link beside their own node_modules.
    #[test]
    fn a_nested_package_links_its_bins_into_its_parents_node_modules() {
        let staged = staged(&[
            "node_modules/tool",
            "node_modules/a/node_modules/tool",
            "node_modules/a/node_modules/@s/b",
            "packages/web/node_modules/c/node_modules/d",
        ]);
        let packages = [
            package("node_modules/tool", "tool"),
            package("node_modules/a/node_modules/tool", "tool"),
            package("node_modules/a/node_modules/@s/b", "b"),
            package("packages/web/node_modules/c/node_modules/d", "d"),
        ];
        link_package_bins(&staged.0, &packages).unwrap();
        let link = |dir: &str, name: &str| {
            fs::read_link(env_package_path(&staged.0, dir).join(name)).unwrap()
        };
        assert_eq!(
            link("node_modules/.bin", "tool"),
            Path::new("../tool/cli.js")
        );
        assert_eq!(
            link("node_modules/a/node_modules/.bin", "tool"),
            Path::new("../tool/cli.js")
        );
        assert_eq!(
            link("node_modules/a/node_modules/.bin", "b"),
            Path::new("../@s/b/cli.js")
        );
        assert_eq!(
            link("packages/web/node_modules/c/node_modules/.bin", "d"),
            Path::new("../d/cli.js")
        );
        let nested = env_package_path(&staged.0, "node_modules/a/node_modules/.bin/tool");
        assert!(fs::canonicalize(nested)
            .unwrap()
            .ends_with("node_modules/a/node_modules/tool/cli.js"));
        assert_eq!(
            bin_dir_of("node_modules/@s/x").unwrap(),
            ("node_modules/.bin".to_string(), "@s/x")
        );
    }

    /// A scope or package name that contains `node_modules` is a name, not
    /// the directory that holds the package (#695).
    #[test]
    fn the_holding_node_modules_is_a_whole_path_component() {
        assert_eq!(
            bin_dir_of("node_modules/@my-node_modules/tool").unwrap(),
            ("node_modules/.bin".to_string(), "@my-node_modules/tool")
        );
        assert_eq!(
            bin_dir_of("node_modules/a/node_modules/x-node_modules").unwrap(),
            (
                "node_modules/a/node_modules/.bin".to_string(),
                "x-node_modules"
            )
        );
        assert_eq!(
            bin_dir_of("packages/my-node_modules/node_modules/t").unwrap(),
            (
                "packages/my-node_modules/node_modules/.bin".to_string(),
                "t"
            )
        );
        assert!(bin_dir_of("node_modules").is_err());
        assert!(bin_dir_of("packages/x").is_err());
        let staged = staged(&["node_modules/@my-node_modules/tool"]);
        link_package_bins(
            &staged.0,
            &[package("node_modules/@my-node_modules/tool", "tool")],
        )
        .unwrap();
        assert_eq!(
            fs::read_link(staged.0.join("node_modules/.bin/tool")).unwrap(),
            Path::new("../@my-node_modules/tool/cli.js")
        );
    }
}
