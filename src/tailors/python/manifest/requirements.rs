//! requirements.txt projects (python tailor): include resolution, the
//! requirements tree hash, and index-option collection.

use super::*;

/// The requirements file and every include are read through the held
/// project descriptor (`read_project_file`).
pub(super) fn requirements_manifest(
    project: &ProjectRoot,
    path: &Path,
    input: &str,
) -> io::Result<Manifest> {
    let source = read_text(project, path)?;
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    let mut index_options = Vec::new();
    // The mode a file was first reached in. A file reached both as
    // requirements and as constraints lists its index options once.
    let mut first_mode = BTreeMap::new();
    let mut external_includes = Vec::new();
    walk_includes(project, path, &mut |step| {
        match step {
            IncludeStep::File {
                file,
                constraints_only,
            } => {
                if held_relative(project, file).is_none()
                    && !external_includes.contains(&file.to_path_buf())
                {
                    external_includes.push(file.to_path_buf());
                }
                first_mode
                    .entry(file.to_path_buf())
                    .or_insert(constraints_only);
            }
            IncludeStep::Line {
                file,
                line,
                constraints_only,
            } => {
                if first_mode.get(file) == Some(&constraints_only) {
                    index_options.extend(pypi::unattested_index_options(line));
                }
                if !pypi::is_requirement_option(line) {
                    let list = if constraints_only {
                        &mut constraints
                    } else {
                        &mut requirements
                    };
                    list.push(line.to_string());
                }
            }
        }
        Ok(())
    })?;
    let mut filtered = Vec::new();
    let mut has_skippable_specs = false;
    for requirement in requirements {
        if pypi::is_skippable_spec(&requirement) {
            has_skippable_specs = true;
            crate::kernel::policy::record(
                crate::kernel::policy::REQUIREMENT_SKIPPED,
                &requirement,
                "project-local or direct reference is not a locked registry package",
            )?;
        } else {
            filtered.push(requirement);
        }
    }
    let requirements = filtered;
    let has_index_options = !index_options.is_empty();
    for option in index_options {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_INDEX,
            &option,
            "requirements index/find-links options are recorded but never followed",
        )?;
    }
    Ok(Manifest {
        input: input.into(),
        requirements,
        constraints,
        python: PythonInputs::default(),
        provenance: input.into(),
        source,
        source_path: Some(path.to_path_buf()),
        external_includes,
        locked_packages: None,
        uv_lock: None,
        has_index_options,
        has_skippable_specs,
        setup: false,
        setup_cfg: false,
        dynamic_dependencies: false,
    })
}

pub(super) fn requirements_directory_candidate(
    project: &ProjectRoot,
    cfg: &GreywardPythonConfig,
) -> io::Result<Option<PathBuf>> {
    let dir = project.path();
    let requirements = dir.join("requirements");
    if !is_project_dir(project, &requirements) {
        return Ok(None);
    }
    if let Some(explicit) = &cfg.requirements {
        let path = if explicit.is_absolute() {
            explicit.clone()
        } else {
            dir.join(explicit)
        };
        if is_project_file(project, &path)? {
            return Ok(Some(path));
        }
        return Err(unreadable(
            &path,
            "greyward.toml [python].requirements points to a missing file",
        ));
    }
    for hardware in ["cpu.txt", "cuda.txt", "rocm.txt", "xpu.txt"] {
        let path = requirements.join(hardware);
        if is_project_file(project, &path)? {
            return Ok(Some(path));
        }
    }
    for name in ["common.txt", "base.txt", "requirements.in"] {
        let path = requirements.join(name);
        if is_project_file(project, &path)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// One step of [`walk_includes`].
pub(super) enum IncludeStep<'a> {
    /// A file entered for the first time under this `constraints_only`.
    File {
        file: &'a Path,
        constraints_only: bool,
    },
    /// One logical line of `file` that is not an include directive.
    Line {
        file: &'a Path,
        line: &'a str,
        constraints_only: bool,
    },
}

/// Walk a requirements file and its `-r`/`-c` include closure depth first,
/// in file order, calling `visit` for each file and each non-include line.
/// The one place the include rules live: an include without its file
/// argument, a missing included file and a cycle are all errors. A file is
/// visited once per `constraints_only` value, because the same file
/// reached through `-c` contributes constraints, not requirements.
pub(super) fn walk_includes(
    project: &ProjectRoot,
    path: &Path,
    visit: &mut dyn FnMut(IncludeStep<'_>) -> io::Result<()>,
) -> io::Result<()> {
    walk_from(
        project,
        path,
        false,
        &mut Vec::new(),
        &mut BTreeSet::new(),
        visit,
    )
}

fn walk_from(
    project: &ProjectRoot,
    path: &Path,
    constraints_only: bool,
    stack: &mut Vec<(PathBuf, bool)>,
    seen: &mut BTreeSet<(PathBuf, bool)>,
    visit: &mut dyn FnMut(IncludeStep<'_>) -> io::Result<()>,
) -> io::Result<()> {
    let path = canonical_project_path(project, path).map_err(|e| unreadable(path, e))?;
    let key = (path.clone(), constraints_only);
    if stack.contains(&key) {
        return Err(unreadable(
            &path,
            format!(
                "requirements include cycle: {}",
                stack
                    .iter()
                    .map(|(p, _)| p.display().to_string())
                    .chain([path.display().to_string()])
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
        ));
    }
    if !seen.insert(key.clone()) {
        return Ok(());
    }
    visit(IncludeStep::File {
        file: &path,
        constraints_only,
    })?;
    stack.push(key);
    for line in pypi::logical_requirement_lines(&read_text(project, &path)?) {
        let Some(include) = parse_include_directive(&line) else {
            visit(IncludeStep::Line {
                file: &path,
                line: &line,
                constraints_only,
            })?;
            continue;
        };
        let target = include.target.ok_or_else(|| {
            unreadable(&path, "requirements include is missing its file argument")
        })?;
        let child = path.parent().unwrap_or(Path::new(".")).join(target.trim());
        if !is_project_file(project, &child)? {
            return Err(unreadable(&child, "included requirements file is missing"));
        }
        walk_from(
            project,
            &child,
            constraints_only || include.constraint,
            stack,
            seen,
            visit,
        )?;
    }
    stack.pop();
    Ok(())
}

/// Hash a requirements file together with every file reached through its
/// `-r`/`-c` include closure.  uv follows those includes itself when the
/// source is handed to it, so the cache key must cover the same files rather
/// than only the bytes of the top-level file. Each file is read through the
/// held project descriptor, and named by its path in the project, so the
/// hash is the same in every checkout: it is part of the source a committed
/// lock names (#673). A file outside the project is named by its path from
/// the top file's directory, as its include spells it.
pub fn requirements_tree_hash(project: &ProjectRoot, path: &Path) -> io::Result<String> {
    let top = canonical_project_path(project, path).map_err(|e| unreadable(path, e))?;
    let root = top.parent().unwrap_or(Path::new("."));
    let project_root = project.path().canonicalize()?;
    let mut files = BTreeSet::new();
    walk_includes(project, &top, &mut |step| {
        if let IncludeStep::File { file, .. } = step {
            files.insert(file.to_path_buf());
        }
        Ok(())
    })?;
    let mut hasher = Sha256::new();
    for file in files {
        let relative = match file.strip_prefix(&project_root) {
            Ok(relative) => relative.to_path_buf(),
            Err(_) => relative_from(root, &file),
        };
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(read_project_file(project, &file).map_err(|e| unreadable(&file, e))?);
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Every `--hash` pin of `path`'s `-r`/`-c` include closure, each naming
/// the file it is in (its path in the project, or its own path when it
/// lies outside) and its line there: a lock compiled from the tree must
/// keep all of them, wherever in the tree they are (#689). A hash ward
/// cannot check is refused here, by file and line.
pub fn requirements_hash_pins(
    project: &ProjectRoot,
    path: &Path,
) -> io::Result<Vec<pypi::HashPin>> {
    let project_root = project.path().canonicalize()?;
    let mut pins = Vec::new();
    for file in include_closure(project, path)? {
        let name = file
            .strip_prefix(&project_root)
            .unwrap_or(&file)
            .display()
            .to_string();
        pins.extend(pypi::hash_pins(&read_text(project, &file)?, &name)?);
    }
    Ok(pins)
}

/// The `pins` that apply on `platform` under `python_version`: a pin
/// whose marker is false there pins nothing there, and its hashes must
/// neither be required of the lock nor widen the files planning may pick
/// (another platform's line beside this one's). A marker ward cannot
/// evaluate is refused, by file and line: whether its hashes guard this
/// environment cannot be told.
pub(crate) fn active_hash_pins(
    pins: Vec<pypi::HashPin>,
    python_version: &str,
    platform: Platform,
) -> io::Result<Vec<pypi::HashPin>> {
    let mut active = Vec::new();
    for pin in pins {
        let applies = match &pin.marker {
            None => true,
            Some(marker) => {
                markers::marker_matches(marker, python_version, platform).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{} line {}: ward cannot tell whether the marker `{marker}` \
                             applies here ({error}), so it cannot tell which files its \
                             hashes pin",
                            pin.file, pin.line
                        ),
                    )
                })?
            }
        };
        if applies {
            active.push(pin);
        }
    }
    Ok(active)
}

/// Why a lock holding `locked` (name, version) does not satisfy
/// `manifest`, or `None` when it does: every requirement that applies on
/// `platform` under `python_version` must name a locked package at a
/// version its specifier allows, and a constraint must allow the version
/// of a package the lock holds. A direct reference (a URL, a local path) is
/// no registry package and is not checked. A marker ward cannot evaluate
/// is a shortfall: the lock cannot be shown to satisfy it. This is the
/// check of a committed lock whose header names no source (#673).
pub(crate) fn lock_shortfall(
    manifest: &Manifest,
    locked: &[(String, String)],
    python_version: &str,
    platform: Platform,
) -> io::Result<Option<String>> {
    let entries = manifest
        .requirements
        .iter()
        .map(|line| (line, false))
        .chain(manifest.constraints.iter().map(|line| (line, true)));
    for (line, constraint) in entries {
        // The requirement without its options (`--hash=...`).
        let spec = line
            .split_whitespace()
            .filter(|token| !token.starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");
        if spec.is_empty()
            || pypi::is_skippable_spec(&spec)
            || pypi::parse_git_requirement(&spec).is_some()
            || spec.split(';').next().unwrap_or_default().contains('@')
        {
            continue;
        }
        let requirement = parse_uv_requirement(&spec)?;
        if let Some(marker) = &requirement.marker {
            match markers::marker_matches(marker, python_version, platform) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    return Ok(Some(format!(
                        "ward cannot tell whether `{spec}` applies here ({error})"
                    )))
                }
            }
        }
        let Some((_, version)) = locked.iter().find(|(name, _)| *name == requirement.name) else {
            if constraint {
                continue;
            }
            return Ok(Some(format!(
                "it does not have {}, which `{spec}` requires",
                requirement.name
            )));
        };
        let specifier = requirement
            .version
            .as_deref()
            .map(|version| {
                version
                    .trim()
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .trim()
            })
            .filter(|specifier| !specifier.is_empty() && *specifier != "*");
        if let Some(specifier) = specifier {
            if !crate::kernel::pep440::matches_specifier(specifier, version)? {
                return Ok(Some(format!(
                    "it has {} {version}, which `{spec}` does not allow",
                    requirement.name
                )));
            }
        }
    }
    Ok(None)
}

/// `file` as a path from the directory `base`, climbing with `..` as far
/// as their common ancestor. Both are canonical.
fn relative_from(base: &Path, file: &Path) -> PathBuf {
    let base: Vec<_> = base.components().collect();
    let target: Vec<_> = file.components().collect();
    let common = base
        .iter()
        .zip(&target)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..base.len() {
        relative.push("..");
    }
    for component in &target[common..] {
        relative.push(component);
    }
    relative
}

/// Every file of `path`'s `-r`/`-c` include closure, `path` first, each
/// canonical. A resolution record names the ones inside the project; one
/// outside it is a file no record can cover.
pub fn include_closure(project: &ProjectRoot, path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    walk_includes(project, path, &mut |step| {
        if let IncludeStep::File { file, .. } = step {
            if !files.iter().any(|seen| seen == file) {
                files.push(file.to_path_buf());
            }
        }
        Ok(())
    })?;
    Ok(files)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IncludeDirective {
    pub(super) target: Option<String>,
    pub(super) constraint: bool,
}

/// Parse every pip include spelling in one place. This parser is shared by
/// discovery, flattening, index-option traversal, and the transitive hash.
pub(super) fn parse_include_directive(line: &str) -> Option<IncludeDirective> {
    let first = line.split_whitespace().next()?;
    let exact = match first {
        "-r" | "--requirement" => Some(false),
        "-c" | "--constraint" => Some(true),
        _ => None,
    };
    if let Some(constraint) = exact {
        return Some(IncludeDirective {
            target: line.split_whitespace().nth(1).map(str::to_string),
            constraint,
        });
    }
    for (option, constraint) in [
        ("--requirement=", false),
        ("--constraint=", true),
        ("-r=", false),
        ("-c=", true),
    ] {
        if let Some(target) = first.strip_prefix(option) {
            return Some(IncludeDirective {
                target: (!target.is_empty()).then(|| target.to_string()),
                constraint,
            });
        }
    }
    if let Some(target) = first.strip_prefix("-r").filter(|target| !target.is_empty()) {
        return Some(IncludeDirective {
            target: Some(target.to_string()),
            constraint: false,
        });
    }
    if let Some(target) = first.strip_prefix("-c").filter(|target| !target.is_empty()) {
        return Some(IncludeDirective {
            target: Some(target.to_string()),
            constraint: true,
        });
    }
    None
}

pub(super) fn strip_inline_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(i, c)| *c == '#' && (*i == 0 || line.as_bytes()[*i - 1].is_ascii_whitespace()))
        .map(|(i, _)| &line[..i])
        .unwrap_or(line)
}
