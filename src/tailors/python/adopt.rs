//! `ward update --adopt` for Python (`Tailor::adopt_lock`).
//!
//! A hand-hashed `requirements.txt` proves which bytes to install, but no
//! resolver wrote it, so no resolution record can say how its dependency
//! set was chosen, and `ward attest` refuses it. Adopting keeps the
//! original as the resolver's source (`requirements.in`, byte for byte)
//! and compiles `requirements.txt` from it with the same `uv pip compile`
//! an edit and `ward attest` run, through the edit door, which publishes
//! the lock with its signed record. No upgrade flag is passed: the
//! original's `==` pins decide every version, and uv reads the existing
//! `requirements.txt` as its preferences. A pip-compile pair whose
//! `requirements.txt` another tool generated is adopted the same way, from
//! its own `requirements.in`.

use super::edit::{python_shape, requirement_name, uv_compile, PyShape};
use super::inputs::is_fully_pinned;
use super::resolve;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::ResolutionDoor;
use crate::tailors::edit::{
    other, Adopted, Adoption, EditVerb, LockAdoption, ManifestEdit, Pin, Pins,
};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

const SOURCE: &str = "requirements.in";
const LOCK: &str = "requirements.txt";

/// `Tailor::adopt_lock` for Python.
pub(crate) fn adopt_lock(
    adoption: &LockAdoption<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<Adoption> {
    let project = adoption.project;
    let nothing = |text: &str| Ok(Adoption::Nothing(text.to_string()));
    match python_shape(project)? {
        PyShape::Requirements(path) => {
            let original = fs::read_to_string(&path)?;
            if !is_fully_pinned(&original) {
                return nothing(
                    "requirements.txt has no --hash pins, so it is a source, not a lock: `ward` \
                     compiles requirements.lock.txt from it with a signed resolution record",
                );
            }
            create_source(project, &original)?;
            let compiled = compile(adoption, door, &original);
            if compiled.is_err() {
                // The source this run created goes again, so a failed
                // adoption leaves the project as it found it. Through the
                // held descriptor: a swapped name is refused, not removed.
                ProjectRoot::open(project)?.remove_file(Path::new(SOURCE))?;
            }
            compiled
        }
        PyShape::PipCompile => {
            let source = fs::read(project.join(SOURCE))?;
            let lock = fs::read_to_string(project.join(LOCK))?;
            if resolve::compiled_by_ward(&lock) {
                return nothing(
                    "requirements.txt is already compiled by ward from requirements.in; \
                     `ward attest python` signs a resolution record for it",
                );
            }
            if source != lock.as_bytes() && !generated(&lock) {
                return Err(other(format!(
                    "{} already exists and differs from requirements.txt, which no tool \
                     generated; adopting would compile requirements.txt from that other \
                     source, so nothing was changed; move requirements.in aside to adopt \
                     requirements.txt as it is, or make requirements.in the source you mean",
                    project.join(SOURCE).display()
                )));
            }
            compile(adoption, door, &lock)
        }
        PyShape::Uv => nothing(
            "uv writes uv.lock itself (`ward` locks a project that has none); \
             `ward attest python` signs a resolution record for it",
        ),
        PyShape::Poetry | PyShape::Pdm => nothing(
            "Poetry and PDM locks are written by their own tools, which are not pinned tools",
        ),
        PyShape::Setup | PyShape::RequirementsDir => nothing(
            "`ward` compiles requirements.lock.txt from these requirements with a signed \
             resolution record",
        ),
    }
}

/// Write the original lock as `requirements.in`, refusing any name already
/// there: adoption never overwrites a source.
fn create_source(project: &Path, original: &str) -> io::Result<()> {
    let path = project.join(SOURCE);
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(other(format!(
                "{} appeared while adopting; nothing was changed",
                path.display()
            )))
        }
        Err(error) => return Err(error),
    };
    file.write_all(original.as_bytes())?;
    file.sync_all()
}

/// Compile `requirements.in` into `requirements.txt` through `door`, with
/// no upgrade flag, and report the pins `original` stated against the ones
/// the resolver wrote.
fn compile(
    adoption: &LockAdoption<'_>,
    door: &mut ResolutionDoor<'_>,
    original: &str,
) -> io::Result<Adoption> {
    let project = adoption.project;
    let edit = ManifestEdit {
        verb: EditVerb::Update,
        project,
        specs: &[],
        dev: false,
        host: adoption.host,
    };
    uv_compile(&edit, door, &project.join(SOURCE), &project.join(LOCK), &[])?;
    let compiled = fs::read_to_string(project.join(LOCK))?;
    Ok(Adoption::Adopted(Adopted {
        files: vec![SOURCE.to_string(), LOCK.to_string()],
        sync_root: project.to_path_buf(),
        lock: LOCK.to_string(),
        before: pins(original),
        after: pins(&compiled),
    }))
}

/// Whether a requirements file's header says a tool generated it
/// (pip-compile and uv both write "autogenerated" in their first lines).
fn generated(lock: &str) -> bool {
    lock.lines()
        .take(4)
        .any(|line| line.starts_with('#') && line.contains("autogenerated"))
}

/// The pins a requirements file states: each requirement's `==` version
/// (or its specifier when it has none) and its `--hash` values, keyed by
/// normalized name, with the environment marker when there is one.
pub(crate) fn pins(text: &str) -> Pins {
    let mut found = Pins::new();
    let mut logical = String::new();
    for raw in text.lines() {
        if let Some(continued) = raw.trim_end().strip_suffix('\\') {
            logical.push_str(continued);
            logical.push(' ');
            continue;
        }
        logical.push_str(raw);
        let line = std::mem::take(&mut logical);
        let line = line.trim();
        let line = match line.find(" #") {
            Some(at) => &line[..at],
            None => line,
        };
        let Some(name) = requirement_name(line) else {
            continue;
        };
        let mut hashes = std::collections::BTreeSet::new();
        let mut spec = Vec::new();
        for token in line.split_whitespace() {
            match token.strip_prefix("--hash=") {
                Some(hash) => {
                    hashes.insert(hash.to_string());
                }
                None => spec.push(token),
            }
        }
        let spec = spec.join(" ");
        let (requirement, marker) = match spec.split_once(';') {
            Some((requirement, marker)) => (requirement.trim(), Some(marker.trim())),
            None => (spec.trim(), None),
        };
        let version = match requirement.split_once("==") {
            Some((_, version)) => version.trim().to_string(),
            None => requirement
                .trim_start_matches(|c: char| !" [<>=!~@".contains(c))
                .trim()
                .to_string(),
        };
        let key = match marker {
            Some(marker) if !marker.is_empty() => format!("{name}; {marker}"),
            _ => name,
        };
        found.insert(key, Pin { version, hashes });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn pins_read_versions_hashes_and_markers() {
        let text = "# This file was autogenerated by uv via the following command:\n\
                    #    ward\n\
                    Six==1.16.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\n    # via -r requirements.in\n\
                    idna==3.10 ; python_version >= '3.8' --hash=sha256:cc  # pinned\n\
                    -r other.txt\n\
                    requests>=2\n";
        let pins = pins(text);
        assert_eq!(pins.len(), 3, "{pins:?}");
        assert_eq!(pins["six"].version, "1.16.0");
        assert_eq!(
            pins["six"].hashes.iter().collect::<Vec<_>>(),
            ["sha256:aa", "sha256:bb"]
        );
        let idna = &pins["idna; python_version >= '3.8'"];
        assert_eq!(idna.version, "3.10");
        assert!(idna.hashes.contains("sha256:cc"));
        assert_eq!(pins["requests"].version, ">=2");
        assert!(generated(text));
        assert!(!generated("six==1.16.0 --hash=sha256:aa\n"));
    }

    #[test]
    fn a_source_is_never_overwritten() {
        let temp = TempDir::named("py-adopt-source");
        create_source(&temp.0, "six==1.16.0\n").unwrap();
        assert_eq!(
            fs::read_to_string(temp.0.join(SOURCE)).unwrap(),
            "six==1.16.0\n"
        );
        let error = create_source(&temp.0, "idna==3.10\n").unwrap_err();
        assert!(error.to_string().contains("nothing was changed"), "{error}");
        assert_eq!(
            fs::read_to_string(temp.0.join(SOURCE)).unwrap(),
            "six==1.16.0\n"
        );
    }
}
