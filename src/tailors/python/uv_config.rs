//! A project's uv configuration inside the resolution door (python tailor).
//!
//! Every confined uv run carries `--no-config` from the forced row, so uv
//! itself discovers no configuration: not the project's, not the user's
//! (`~/.config/uv/uv.toml`), not the system's. Greyward reads the project's
//! settings instead, from the run's snapshot (the bytes the receipt
//! digests), applies the rules in [`TOP`] and [`PIP`] to every key, and
//! hands uv the result with `--config-file`, a file in the run's scratch
//! directory. Command-line flags beat a config file in uv, so the forced
//! row (`--python`, `--keyring-provider disabled`, `--no-python-downloads`)
//! and the forced default index still win.
//!
//! **Which file.** uv's own discovery, held to the project: the lock root's
//! `uv.toml` when it has one, else the `[tool.uv]` table of its
//! `pyproject.toml`. A `uv.toml` replaces `[tool.uv]`'s settings whole (uv
//! ignores them then, and says so); the two are never merged. A workspace
//! member's own files are ignored, as uv ignores them for the workspace
//! root's. Nothing above the lock root is read: a file there is not the
//! project's, and no record could cover it. A lock root Greyward made (an
//! sdist's build requirements, a `ward x` root) has none of these files,
//! so no project configuration applies there.
//!
//! **Which keys.** The tables list every setting uv 0.12.7 accepts (the
//! ignored test `the_tables_name_every_setting_the_pinned_uv_accepts`
//! compares them with the pinned uv's own list). A key not in them is
//! refused. Each key has one [`Rule`].

use std::io;
use std::path::{Component, Path, PathBuf};

/// The project's own uv configuration file.
pub(crate) const UV_TOML: &str = "uv.toml";
const PYPROJECT: &str = "pyproject.toml";

/// Where the effective configuration is written, relative to the run's
/// scratch directory.
pub(crate) const SCRATCH_FILE: &str = "uv-project-config.toml";

/// What happens to one uv setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// Passed to uv as the project wrote it.
    Honor,
    /// Index and find-links locations (a string, a list of them, or a list
    /// of `[[index]]` tables whose `url` is one). An `http(s)` URL is passed
    /// as written: the proxy carries it, and an index other than PyPI is
    /// recorded as `unattested-index`. A local location (a `file:` URL or a
    /// path) must lie inside the lock root: it is passed as an absolute
    /// path, and its files are resolution inputs the record covers.
    Locations,
    /// Requirement strings: a `file:` direct reference must lie inside the
    /// lock root, and its files are resolution inputs the record covers.
    Requirements,
    /// Greyward sets this itself, so the project's value is set aside and
    /// named in a note. The text says what applies instead.
    Greyward(&'static str),
    /// A project field uv reads from the held `pyproject.toml` itself (it is
    /// not a setting `--no-config` drops), and refuses in a `uv.toml`.
    ProjectOnly,
    /// The `[pip]` table, whose keys follow [`PIP`].
    Pip,
}

const TRUST: &str = "TLS is verified against the session's proxy, which checks every upstream";
const CACHE: &str = "uv's cache is a fresh directory Greyward makes for each attempt";
const INTERPRETER: &str =
    "uv runs the store interpreter (`--python`) and never downloads one (`--no-python-downloads`)";
const KEYRING: &str = "keyring programs are disabled (`--keyring-provider disabled`)";
const PROXY: &str = "every request goes through the session's proxy";
const LOCK_FORMAT: &str = "Greyward compiles hash-pinned locks for the store interpreter's \
                           version and platform, with every dependency and its own header";
const SELECTION: &str = "Greyward compiles the requirements its manifest discovery selected";

/// Top-level settings (`uv.toml`, `[tool.uv]`), in uv 0.12.7's order.
const TOP: &[(&str, Rule)] = &[
    ("required-version", Rule::Honor),
    ("system-certs", Rule::Greyward(TRUST)),
    ("native-tls", Rule::Greyward(TRUST)),
    ("offline", Rule::Honor),
    ("no-cache", Rule::Greyward(CACHE)),
    ("cache-dir", Rule::Greyward(CACHE)),
    ("preview", Rule::Honor),
    ("preview-features", Rule::Honor),
    ("python-preference", Rule::Greyward(INTERPRETER)),
    ("python-downloads", Rule::Greyward(INTERPRETER)),
    ("concurrent-downloads", Rule::Honor),
    ("concurrent-builds", Rule::Honor),
    ("concurrent-installs", Rule::Honor),
    ("index", Rule::Locations),
    ("index-url", Rule::Locations),
    ("extra-index-url", Rule::Locations),
    ("no-index", Rule::Honor),
    ("find-links", Rule::Locations),
    ("index-strategy", Rule::Honor),
    ("keyring-provider", Rule::Greyward(KEYRING)),
    ("http-proxy", Rule::Greyward(PROXY)),
    ("https-proxy", Rule::Greyward(PROXY)),
    ("no-proxy", Rule::Greyward(PROXY)),
    ("allow-insecure-host", Rule::Greyward(TRUST)),
    ("resolution", Rule::Honor),
    ("prerelease", Rule::Honor),
    ("prerelease-package", Rule::Honor),
    ("fork-strategy", Rule::Honor),
    ("dependency-metadata", Rule::Requirements),
    ("config-settings", Rule::Honor),
    ("config-settings-package", Rule::Honor),
    ("no-build-isolation", Rule::Honor),
    ("no-build-isolation-package", Rule::Honor),
    ("extra-build-dependencies", Rule::Requirements),
    ("extra-build-variables", Rule::Honor),
    ("exclude-newer", Rule::Honor),
    ("exclude-newer-package", Rule::Honor),
    ("link-mode", Rule::Honor),
    ("compile-bytecode", Rule::Honor),
    ("no-sources", Rule::Honor),
    ("no-sources-package", Rule::Honor),
    ("upgrade", Rule::Honor),
    ("upgrade-package", Rule::Honor),
    ("reinstall", Rule::Honor),
    ("reinstall-package", Rule::Honor),
    ("no-build", Rule::Honor),
    ("no-build-package", Rule::Honor),
    ("no-binary", Rule::Honor),
    ("no-binary-package", Rule::Honor),
    ("torch-backend", Rule::Honor),
    ("python-install-mirror", Rule::Greyward(INTERPRETER)),
    ("pypy-install-mirror", Rule::Greyward(INTERPRETER)),
    ("python-downloads-json-url", Rule::Greyward(INTERPRETER)),
    ("publish-url", Rule::Honor),
    ("trusted-publishing", Rule::Honor),
    ("check-url", Rule::Honor),
    ("add-bounds", Rule::Honor),
    ("audit", Rule::Honor),
    ("pip", Rule::Pip),
    ("cache-keys", Rule::Honor),
    ("override-dependencies", Rule::Requirements),
    ("exclude-dependencies", Rule::Honor),
    ("constraint-dependencies", Rule::Requirements),
    ("build-constraint-dependencies", Rule::Requirements),
    ("environments", Rule::ProjectOnly),
    ("required-environments", Rule::ProjectOnly),
    ("conflicts", Rule::ProjectOnly),
    ("workspace", Rule::ProjectOnly),
    ("sources", Rule::ProjectOnly),
    ("managed", Rule::ProjectOnly),
    ("package", Rule::ProjectOnly),
    ("default-groups", Rule::ProjectOnly),
    ("dependency-groups", Rule::ProjectOnly),
    ("dev-dependencies", Rule::ProjectOnly),
    ("build-backend", Rule::ProjectOnly),
];

/// `[pip]` (`[tool.uv.pip]`) settings, in uv 0.12.7's order.
const PIP: &[(&str, Rule)] = &[
    ("python", Rule::Greyward(INTERPRETER)),
    ("system", Rule::Greyward(INTERPRETER)),
    ("break-system-packages", Rule::Greyward(INTERPRETER)),
    ("target", Rule::Greyward(INTERPRETER)),
    ("prefix", Rule::Greyward(INTERPRETER)),
    ("index-url", Rule::Locations),
    ("extra-index-url", Rule::Locations),
    ("no-index", Rule::Honor),
    ("find-links", Rule::Locations),
    ("index-strategy", Rule::Honor),
    ("keyring-provider", Rule::Greyward(KEYRING)),
    ("no-build", Rule::Honor),
    ("no-binary", Rule::Honor),
    ("only-binary", Rule::Honor),
    ("no-build-isolation", Rule::Honor),
    ("no-build-isolation-package", Rule::Honor),
    ("extra-build-dependencies", Rule::Requirements),
    ("extra-build-variables", Rule::Honor),
    ("strict", Rule::Honor),
    ("extra", Rule::Greyward(SELECTION)),
    ("all-extras", Rule::Greyward(SELECTION)),
    ("no-extra", Rule::Greyward(SELECTION)),
    ("no-deps", Rule::Greyward(LOCK_FORMAT)),
    ("group", Rule::Greyward(SELECTION)),
    ("allow-empty-requirements", Rule::Honor),
    ("resolution", Rule::Honor),
    ("prerelease", Rule::Honor),
    ("fork-strategy", Rule::Honor),
    ("dependency-metadata", Rule::Requirements),
    ("output-file", Rule::Greyward(LOCK_FORMAT)),
    ("no-strip-extras", Rule::Greyward(LOCK_FORMAT)),
    ("no-strip-markers", Rule::Greyward(LOCK_FORMAT)),
    ("no-annotate", Rule::Honor),
    ("no-header", Rule::Greyward(LOCK_FORMAT)),
    ("custom-compile-command", Rule::Greyward(LOCK_FORMAT)),
    ("generate-hashes", Rule::Greyward(LOCK_FORMAT)),
    ("config-settings", Rule::Honor),
    ("config-settings-package", Rule::Honor),
    ("python-version", Rule::Greyward(LOCK_FORMAT)),
    ("python-platform", Rule::Greyward(LOCK_FORMAT)),
    ("universal", Rule::Greyward(LOCK_FORMAT)),
    ("exclude-newer", Rule::Honor),
    ("exclude-newer-package", Rule::Honor),
    ("no-emit-package", Rule::Greyward(LOCK_FORMAT)),
    ("emit-index-url", Rule::Greyward(LOCK_FORMAT)),
    ("emit-find-links", Rule::Greyward(LOCK_FORMAT)),
    ("emit-build-options", Rule::Greyward(LOCK_FORMAT)),
    ("emit-marker-expression", Rule::Greyward(LOCK_FORMAT)),
    ("emit-index-annotation", Rule::Honor),
    ("annotation-style", Rule::Honor),
    ("link-mode", Rule::Honor),
    ("compile-bytecode", Rule::Honor),
    ("require-hashes", Rule::Honor),
    ("verify-hashes", Rule::Honor),
    ("no-sources", Rule::Honor),
    ("no-sources-package", Rule::Honor),
    ("upgrade", Rule::Honor),
    ("upgrade-package", Rule::Honor),
    ("reinstall", Rule::Honor),
    ("reinstall-package", Rule::Honor),
    ("torch-backend", Rule::Honor),
];

/// The deepest directory a local location's files are listed to.
const MAX_DEPTH: usize = 24;

/// Directories a local location's listing never enters: version control,
/// Greyward's own state, and an environment.
const UNLISTED: [&str; 3] = [".git", ".greyward", ".venv"];

/// The settings a uv run is given.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Effective {
    /// The file they came from, `None` when the project has no uv settings.
    pub source: Option<&'static str>,
    /// What `--config-file` names: the honored settings, local locations
    /// made absolute.
    pub settings: toml::Table,
    /// Settings set aside for Greyward's own, `key (what applies instead)`.
    pub set_aside: Vec<String>,
    /// Local locations and references, relative to the lock root.
    pub local: Vec<PathBuf>,
}

impl Effective {
    /// The `--config-file` bytes.
    pub(crate) fn render(&self) -> io::Result<Vec<u8>> {
        toml::to_string(&self.settings)
            .map(String::into_bytes)
            .map_err(|error| io::Error::other(format!("render uv settings: {error}")))
    }

    /// The note naming what was set aside, if anything was.
    pub(crate) fn note(&self) -> Option<String> {
        let source = self.source?;
        if self.set_aside.is_empty() {
            return None;
        }
        Some(format!(
            "uv settings in {source} that Greyward sets itself were set aside: {}",
            self.set_aside.join("; ")
        ))
    }
}

/// The project's uv settings: `read` gives a lock-root-relative file's
/// bytes (`None` when absent), `lock_root` is the lock root's real path
/// (where uv sees the project).
pub(crate) fn effective(
    read: impl Fn(&Path) -> io::Result<Option<Vec<u8>>>,
    lock_root: &Path,
) -> io::Result<Effective> {
    let parse = |name: &str, bytes: Vec<u8>| -> io::Result<toml::Table> {
        let text = String::from_utf8(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name} is not valid UTF-8"),
            )
        })?;
        text.parse::<toml::Table>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{name}: {error}")))
    };
    let (source, table) = if let Some(bytes) = read(Path::new(UV_TOML))? {
        (UV_TOML, parse(UV_TOML, bytes)?)
    } else if let Some(bytes) = read(Path::new(PYPROJECT))? {
        let mut pyproject = parse(PYPROJECT, bytes)?;
        let uv = pyproject.remove("tool").and_then(|tool| match tool {
            toml::Value::Table(mut tool) => tool.remove("uv"),
            _ => None,
        });
        match uv {
            None => return Ok(Effective::default()),
            Some(toml::Value::Table(uv)) => (PYPROJECT, uv),
            Some(_) => return Err(refused(PYPROJECT, "[tool.uv]", "is not a table")),
        }
    } else {
        return Ok(Effective::default());
    };
    let mut effective = Effective {
        source: Some(source),
        ..Effective::default()
    };
    let mut context = Context {
        source,
        lock_root,
        effective: &mut effective,
    };
    let settings = context.table(table, TOP, "")?;
    effective.settings = settings;
    effective.local.sort();
    effective.local.dedup();
    Ok(effective)
}

struct Context<'a> {
    source: &'static str,
    lock_root: &'a Path,
    effective: &'a mut Effective,
}

impl Context<'_> {
    /// `table` under `rules`, its keys spelled after `prefix` in messages.
    fn table(
        &mut self,
        table: toml::Table,
        rules: &[(&str, Rule)],
        prefix: &str,
    ) -> io::Result<toml::Table> {
        let mut kept = toml::Table::new();
        for (key, value) in table {
            let name = format!("{prefix}{key}");
            let Some(rule) = rules
                .iter()
                .find(|(known, _)| *known == key)
                .map(|(_, rule)| *rule)
            else {
                return Err(refused(
                    self.source,
                    &name,
                    "is not a setting the pinned uv (0.12.7) knows; uv would not apply it \
                     as written, so Greyward does not resolve with it. Remove it, or correct \
                     its spelling",
                ));
            };
            match rule {
                Rule::Honor => {
                    kept.insert(key, value);
                }
                Rule::Locations => {
                    let value = self.locations(&name, value)?;
                    kept.insert(key, value);
                }
                Rule::Requirements => {
                    self.requirements(&name, &value)?;
                    kept.insert(key, value);
                }
                Rule::Greyward(instead) => {
                    self.effective.set_aside.push(format!("{name} ({instead})"));
                }
                Rule::ProjectOnly => {
                    if self.source == UV_TOML {
                        return Err(refused(
                            self.source,
                            &name,
                            "is a project field uv accepts only in pyproject.toml's [tool.uv]; \
                             move it there",
                        ));
                    }
                }
                Rule::Pip => {
                    let toml::Value::Table(pip) = value else {
                        return Err(refused(self.source, &name, "is not a table"));
                    };
                    let pip = self.table(pip, PIP, "pip.")?;
                    kept.insert(key, toml::Value::Table(pip));
                }
            }
        }
        Ok(kept)
    }

    /// A location setting, local locations made absolute: a string, a
    /// list of strings, or a list of tables whose `url` is one.
    fn locations(&mut self, name: &str, value: toml::Value) -> io::Result<toml::Value> {
        match value {
            toml::Value::String(text) => self.location(name, &text).map(toml::Value::String),
            toml::Value::Array(items) => items
                .into_iter()
                .map(|item| self.locations(name, item))
                .collect::<io::Result<Vec<_>>>()
                .map(toml::Value::Array),
            toml::Value::Table(mut table) => {
                if let Some(url) = table.remove("url") {
                    let url = self.locations(&format!("{name}.url"), url)?;
                    table.insert("url".to_string(), url);
                }
                Ok(toml::Value::Table(table))
            }
            other => Ok(other),
        }
    }

    /// One location: a URL as written, a local one absolute and checked.
    fn location(&mut self, name: &str, text: &str) -> io::Result<String> {
        let path = if let Some(rest) = strip_scheme(text, "file") {
            file_url_path(self.source, name, text, rest)?
        } else if text.contains("://") {
            return Ok(text.to_string());
        } else {
            PathBuf::from(text)
        };
        let absolute = self.inside(name, text, &path)?;
        Ok(absolute.to_string_lossy().into_owned())
    }

    /// Every `file:` direct reference among the strings of `value`.
    fn requirements(&mut self, name: &str, value: &toml::Value) -> io::Result<()> {
        match value {
            toml::Value::String(text) => {
                let Some((_, reference)) = text.split_once('@') else {
                    return Ok(());
                };
                let reference = reference.split(';').next().unwrap_or_default().trim();
                if let Some(rest) = strip_scheme(reference, "file") {
                    let path = file_url_path(self.source, name, reference, rest)?;
                    self.inside(name, reference, &path)?;
                }
                Ok(())
            }
            toml::Value::Array(items) => items
                .iter()
                .try_for_each(|item| self.requirements(name, item)),
            toml::Value::Table(table) => table
                .values()
                .try_for_each(|item| self.requirements(name, item)),
            _ => Ok(()),
        }
    }

    /// `path` (relative paths from the lock root, where the source file
    /// is) as an absolute path inside the lock root, recorded as local.
    fn inside(&mut self, name: &str, written: &str, path: &Path) -> io::Result<PathBuf> {
        if written.contains("${") || written.starts_with('~') {
            return Err(refused(
                self.source,
                name,
                &format!(
                    "names {written:?}, a path Greyward cannot place before uv expands it; \
                     write the path relative to the project"
                ),
            ));
        }
        let joined = self.lock_root.join(path);
        let mut normal = PathBuf::new();
        for component in joined.components() {
            match component {
                Component::ParentDir => {
                    normal.pop();
                }
                Component::CurDir => {}
                other => normal.push(other),
            }
        }
        let Ok(relative) = normal.strip_prefix(self.lock_root) else {
            return Err(refused(
                self.source,
                name,
                &format!(
                    "names {written:?}, which is outside the project; uv resolves only from \
                     files inside it, which the resolution record covers. Move it into the \
                     project, or serve it from an index URL"
                ),
            ));
        };
        self.effective.local.push(relative.to_path_buf());
        Ok(normal)
    }
}

/// `text` after `<scheme>:`, case-insensitively.
fn strip_scheme<'t>(text: &'t str, scheme: &str) -> Option<&'t str> {
    let (head, rest) = text.split_once(':')?;
    head.eq_ignore_ascii_case(scheme).then_some(rest)
}

/// The path of a `file:` URL.
fn file_url_path(source: &str, name: &str, url: &str, rest: &str) -> io::Result<PathBuf> {
    // `file:relative/path` and `file:./x` name paths relative to the
    // source file's directory, as uv reads them.
    if !rest.starts_with("//") {
        return Ok(PathBuf::from(rest));
    }
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.to_file_path().ok())
        .ok_or_else(|| {
            refused(
                source,
                name,
                &format!("names {url:?}, which is not a local file URL"),
            )
        })
}

fn refused(source: &str, name: &str, why: &str) -> io::Error {
    crate::kernel::error::refused(
        io::ErrorKind::InvalidData,
        format!("uv setting {name} in {source} {why}"),
    )
}

/// The resolution inputs the project's uv configuration adds: the
/// `uv.toml` itself, and every regular file under a local location or
/// reference the settings name. A configuration the door would refuse adds
/// only `uv.toml`: the door refuses it when a resolution runs.
pub(crate) fn resolution_inputs(
    root: &crate::kernel::fsroot::ProjectRoot,
) -> io::Result<Vec<PathBuf>> {
    let mut inputs = vec![PathBuf::from(UV_TOML)];
    let Ok(effective) = effective(|relative| root.read_input(relative), root.path()) else {
        return Ok(inputs);
    };
    for local in effective.local {
        list_files(root, &local, 0, &mut inputs)?;
    }
    Ok(inputs)
}

/// `relative` itself when it is a file, else every regular file below it.
fn list_files(
    root: &crate::kernel::fsroot::ProjectRoot,
    relative: &Path,
    depth: usize,
    found: &mut Vec<PathBuf>,
) -> io::Result<()> {
    use crate::kernel::fsroot::Entry;
    let entry = if relative.as_os_str().is_empty() {
        Entry::Directory
    } else {
        root.input_entry(relative)?
    };
    match entry {
        Entry::Regular => {
            if !found.iter().any(|known| known == relative) {
                found.push(relative.to_path_buf());
            }
        }
        Entry::Directory if depth <= MAX_DEPTH => {
            let dir = if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative
            };
            for name in root.read_input_dir(dir)?.unwrap_or_default() {
                if UNLISTED.iter().any(|skip| name == *skip) {
                    continue;
                }
                list_files(root, &relative.join(name), depth + 1, found)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn rule_keys() -> (Vec<&'static str>, Vec<&'static str>) {
    (
        TOP.iter().map(|(key, _)| *key).collect(),
        PIP.iter().map(|(key, _)| *key).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const ROOT: &str = "/work/proj";

    fn files(entries: &[(&str, &str)]) -> BTreeMap<PathBuf, Vec<u8>> {
        entries
            .iter()
            .map(|(name, text)| (PathBuf::from(name), text.as_bytes().to_vec()))
            .collect()
    }

    fn effective_of(entries: &[(&str, &str)]) -> io::Result<Effective> {
        let held = files(entries);
        effective(|relative| Ok(held.get(relative).cloned()), Path::new(ROOT))
    }

    #[test]
    fn a_project_without_uv_settings_gives_uv_none() {
        assert_eq!(effective_of(&[]).unwrap(), Effective::default());
        let plain = "[project]\nname = \"p\"\n";
        assert_eq!(
            effective_of(&[("pyproject.toml", plain)]).unwrap(),
            Effective::default()
        );
    }

    /// `[tool.uv]` settings pass through; the project fields uv reads from
    /// pyproject.toml itself stay there.
    #[test]
    fn pyproject_settings_are_honored_and_project_fields_left_to_uv() {
        let text = "[project]\nname = \"p\"\n[tool.uv]\nresolution = \"lowest-direct\"\n\
                    exclude-newer = \"2025-01-01T00:00:00Z\"\n\
                    config-settings = { editable_mode = \"compat\" }\n\
                    dev-dependencies = [\"pytest\"]\n\
                    [tool.uv.sources]\nfoo = { workspace = true }\n\
                    [tool.uv.pip]\nprerelease = \"allow\"\n";
        let effective = effective_of(&[("pyproject.toml", text)]).unwrap();
        assert_eq!(effective.source, Some("pyproject.toml"));
        let rendered = String::from_utf8(effective.render().unwrap()).unwrap();
        let back: toml::Table = rendered.parse().unwrap();
        assert_eq!(back["resolution"].as_str(), Some("lowest-direct"));
        assert_eq!(back["pip"]["prerelease"].as_str(), Some("allow"));
        assert!(back.contains_key("config-settings"));
        assert!(!back.contains_key("sources"));
        assert!(!back.contains_key("dev-dependencies"));
        assert!(effective.set_aside.is_empty());
        assert_eq!(effective.note(), None);
    }

    /// A uv.toml replaces `[tool.uv]` whole, as uv does: nothing of the
    /// pyproject's settings survives beside it.
    #[test]
    fn a_uv_toml_replaces_tool_uv() {
        let pyproject = "[project]\nname = \"p\"\n[tool.uv]\nresolution = \"lowest\"\n";
        let effective = effective_of(&[
            ("pyproject.toml", pyproject),
            ("uv.toml", "prerelease = \"allow\"\n"),
        ])
        .unwrap();
        assert_eq!(effective.source, Some("uv.toml"));
        assert_eq!(effective.settings.len(), 1);
        assert_eq!(effective.settings["prerelease"].as_str(), Some("allow"));
    }

    /// The settings that would name another interpreter, run a keyring
    /// program, or move uv off the session are never handed to uv.
    #[test]
    fn hostile_settings_are_set_aside_and_named() {
        let text = "keyring-provider = \"subprocess\"\npython-preference = \"only-system\"\n\
                    https-proxy = \"http://elsewhere:3128\"\nnative-tls = true\n\
                    cache-dir = \"/tmp/x\"\nresolution = \"lowest\"\n\
                    [pip]\npython = \"/usr/bin/evil\"\nkeyring-provider = \"subprocess\"\n\
                    system = true\nuniversal = true\nno-header = true\n";
        let effective = effective_of(&[("uv.toml", text)]).unwrap();
        let rendered = String::from_utf8(effective.render().unwrap()).unwrap();
        for gone in [
            "keyring",
            "python",
            "proxy",
            "native-tls",
            "cache-dir",
            "system",
            "universal",
            "no-header",
            "evil",
        ] {
            assert!(!rendered.contains(gone), "{gone} in {rendered}");
        }
        assert!(rendered.contains("resolution = \"lowest\""), "{rendered}");
        let note = effective.note().unwrap();
        for named in [
            "keyring-provider (keyring",
            "pip.python (uv runs the store interpreter",
            "pip.keyring-provider",
            "https-proxy",
            "pip.no-header",
        ] {
            assert!(note.contains(named), "{named} not in {note}");
        }
    }

    #[test]
    fn unknown_keys_and_misplaced_project_fields_are_refused() {
        let error = effective_of(&[("uv.toml", "resolutoin = \"lowest\"\n")]).unwrap_err();
        assert!(error.to_string().contains("resolutoin"), "{error}");
        let error =
            effective_of(&[("pyproject.toml", "[tool.uv.pip]\nbogus = true\n")]).unwrap_err();
        assert!(error.to_string().contains("pip.bogus"), "{error}");
        let error =
            effective_of(&[("uv.toml", "[sources]\nfoo = { path = \"x\" }\n")]).unwrap_err();
        assert!(error.to_string().contains("pyproject.toml"), "{error}");
        assert!(effective_of(&[("uv.toml", "resolution = [\n")]).is_err());
    }

    /// Local locations are made absolute against the lock root and
    /// recorded; URLs pass as written; a path outside the project is
    /// refused by name.
    #[test]
    fn locations_are_absolute_inside_the_project_or_refused() {
        let text = "find-links = [\"wheels\", \"https://example.com/links/\", \
                    \"file:///work/proj/vendor/more\"]\n\
                    extra-index-url = [\"https://example.com/simple\"]\n\
                    [[index]]\nname = \"local\"\nurl = \"./simple/../simple\"\n\
                    [pip]\nfind-links = [\"file:pipwheels\"]\n";
        let effective = effective_of(&[("uv.toml", text)]).unwrap();
        let links: Vec<&str> = effective.settings["find-links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(
            links,
            [
                "/work/proj/wheels",
                "https://example.com/links/",
                "/work/proj/vendor/more"
            ]
        );
        assert_eq!(
            effective.settings["index"][0]["url"].as_str(),
            Some("/work/proj/simple")
        );
        assert_eq!(
            effective.settings["pip"]["find-links"][0].as_str(),
            Some("/work/proj/pipwheels")
        );
        assert_eq!(
            effective.local,
            [
                PathBuf::from("pipwheels"),
                PathBuf::from("simple"),
                PathBuf::from("vendor/more"),
                PathBuf::from("wheels")
            ]
        );
        for outside in [
            "find-links = [\"../wheels\"]\n",
            "find-links = [\"/opt/wheels\"]\n",
            "index-url = \"file:///etc\"\n",
            "find-links = [\"~/wheels\"]\n",
            "find-links = [\"${HOME}/wheels\"]\n",
            "override-dependencies = [\"foo @ file:///opt/foo\"]\n",
            "[extra-build-dependencies]\nfoo = [\"bar @ file:///opt/bar\"]\n",
        ] {
            let error = effective_of(&[("uv.toml", outside)]).unwrap_err();
            assert!(
                error.to_string().contains("in uv.toml"),
                "{outside}: {error}"
            );
        }
        let inside = "override-dependencies = [\"foo @ file:///work/proj/vendor/foo ; \
                      python_version > '3'\"]\n";
        let effective = effective_of(&[("uv.toml", inside)]).unwrap();
        assert_eq!(effective.local, [PathBuf::from("vendor/foo")]);
    }

    /// The record covers uv.toml and every file under a local location.
    #[test]
    fn resolution_inputs_cover_uv_toml_and_local_locations() {
        use crate::kernel::fsroot::ProjectRoot;
        use crate::kernel::testutil::TempDir;
        use std::fs;
        let temp = TempDir::named("py-uv-config-inputs");
        let root = temp.0.join("proj");
        fs::create_dir_all(root.join("wheels/sub/.git")).unwrap();
        fs::write(root.join("wheels/a-1-py3-none-any.whl"), b"a").unwrap();
        fs::write(root.join("wheels/sub/b.html"), b"b").unwrap();
        fs::write(root.join("wheels/sub/.git/HEAD"), b"x").unwrap();
        fs::write(root.join("uv.toml"), "find-links = [\"wheels\"]\n").unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        assert_eq!(
            resolution_inputs(&held).unwrap(),
            [
                PathBuf::from("uv.toml"),
                PathBuf::from("wheels/a-1-py3-none-any.whl"),
                PathBuf::from("wheels/sub/b.html")
            ]
        );
        // A configuration the door refuses still lists uv.toml.
        fs::write(root.join("uv.toml"), "find-links = [\"/opt\"]\n").unwrap();
        assert_eq!(
            resolution_inputs(&held).unwrap(),
            [PathBuf::from("uv.toml")]
        );
    }
}
