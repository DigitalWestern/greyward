//! `ward update --adopt` for Python (`Tailor::adopter`).
//!
//! A hand-hashed `requirements.txt` proves which bytes to install, but no
//! resolver wrote it, so no resolution record can say how its dependency
//! set was chosen, and `ward attest` refuses it. Adopting keeps the
//! original as the resolver's source (`requirements.in`, byte for byte,
//! with the original's permission bits) and compiles `requirements.txt`
//! from it with the same `uv pip compile` an edit and `ward attest` run,
//! through the edit door, which publishes the lock with its signed record.
//! No upgrade flag is passed: the original's `==` pins decide every
//! version, and uv reads the existing `requirements.txt` as its
//! preferences. A pip-compile pair whose `requirements.txt` another tool
//! generated is adopted the same way, from its own `requirements.in`.
//!
//! `requirements.in` is never written to the project ahead of the compile.
//! It is staged (`kernel::resolve::staging`): the door's snapshot gives it
//! to uv, and the resolution transaction publishes it together with the
//! compiled lock and the receipt, or not at all, so a failed, refused or
//! interrupted adoption leaves no source behind and nothing removes one by
//! name. The staged review compares the compiled pins with the original
//! ones before anything is published, and withholds a compile that moves a
//! pin or loses a hash unless the request accepts changes.

use super::edit::{python_shape, requirement_name, uv_compile, PyShape};
use super::inputs::is_fully_pinned;
use super::resolve;
use super::tailor::Python;
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::staging::{self, Candidate, Review, StagedFile, Staging};
use crate::kernel::resolve::ResolutionDoor;
use crate::tailors::adopt::{changes, Adopted, Adopter, Adoption, LockAdoption, Pin, Pins};
use crate::tailors::edit::{other, EditVerb, ManifestEdit};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

const SOURCE: &str = "requirements.in";
const LOCK: &str = "requirements.txt";

impl Adopter for Python {
    fn adopt_lock(
        &self,
        _ctx: &Context,
        adoption: &LockAdoption<'_>,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Adoption> {
        adopt_lock(adoption, door)
    }
}

fn adopt_lock(adoption: &LockAdoption<'_>, door: &mut ResolutionDoor<'_>) -> io::Result<Adoption> {
    let project = adoption.project;
    let root = ProjectRoot::open(project)?;
    let nothing = |text: &str| Ok(Adoption::Nothing(text.to_string()));
    match python_shape(project)? {
        PyShape::Requirements(_) => {
            let (original, mode) = read_lock(&root)?;
            if !is_fully_pinned(&original) {
                return nothing(
                    "requirements.txt has no --hash pins, so it is a source, not a lock: `ward` \
                     compiles requirements.lock.txt from it with a signed resolution record",
                );
            }
            // The original becomes the source, byte for byte and with its
            // own permission bits: a 0600 lock stays private as its source.
            let source = StagedFile {
                relative: PathBuf::from(SOURCE),
                bytes: original.as_bytes().to_vec(),
                mode,
            };
            compile(adoption, door, &root, original, vec![source])
        }
        PyShape::PipCompile => {
            let source = root
                .read_input(Path::new(SOURCE))?
                .ok_or_else(|| other(format!("{} vanished", project.join(SOURCE).display())))?;
            let (lock, _) = read_lock(&root)?;
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
            compile(adoption, door, &root, lock, Vec::new())
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

/// `requirements.txt` through the held project, with its permission bits.
fn read_lock(root: &ProjectRoot) -> io::Result<(String, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let shown = root.path().join(LOCK);
    let mut file = root
        .open_input_file(Path::new(LOCK))?
        .ok_or_else(|| other(format!("{} vanished", shown.display())))?;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", shown.display())))?;
    Ok((text, mode))
}

/// What the staged review saw: the compiled pins, every change to an
/// original pin, and whether the compile was withheld for them.
#[derive(Debug, Default)]
struct Reviewed {
    after: Pins,
    changes: Vec<String>,
    withheld: bool,
}

type Outcome = Arc<Mutex<Option<Reviewed>>>;

/// The review the resolution transaction runs before it publishes: the
/// lock it would write (or the one it leaves) against `original`, which
/// must still be the lock the transaction held. A compile that changes
/// what `original` pins is withheld unless `accept` (`--accept-changes`).
fn review(original: String, before: Pins, accept: bool, outcome: Outcome) -> Review {
    let digest: [u8; 32] = Sha256::digest(original.as_bytes()).into();
    Box::new(move |candidates: &[Candidate<'_>]| {
        let lock = candidates
            .iter()
            .find(|candidate| candidate.relative == Path::new(LOCK))
            .ok_or_else(|| other("the adoption's resolution does not hold requirements.txt"))?;
        if lock.before != Some(digest) {
            return Err(other(
                "requirements.txt changed while it was being adopted, so nothing was changed; \
                 run the command again",
            ));
        }
        let text = match lock.after {
            Some(bytes) => std::str::from_utf8(bytes)
                .map_err(|_| other("the compiled requirements.txt is not UTF-8"))?,
            None => original.as_str(),
        };
        let after = pins(text, "the compiled requirements.txt")?;
        let changes = changes(&before, &after);
        let withheld = !changes.is_empty() && !accept;
        *outcome.lock().unwrap_or_else(PoisonError::into_inner) = Some(Reviewed {
            after,
            changes,
            withheld,
        });
        if withheld {
            return Err(other(
                "the compiled requirements.txt changes what the original pins, so nothing was \
                 published",
            ));
        }
        Ok(())
    })
}

/// Compile `requirements.in` (staged in `files` when the project has none
/// yet) into `requirements.txt` through `door`, with no upgrade flag, and
/// report the pins `original` stated against the ones the resolver wrote.
fn compile(
    adoption: &LockAdoption<'_>,
    door: &mut ResolutionDoor<'_>,
    root: &ProjectRoot,
    original: String,
    files: Vec<StagedFile>,
) -> io::Result<Adoption> {
    let project = adoption.project;
    let before = pins(&original, &project.join(LOCK).display().to_string())?;
    let outcome = Outcome::default();
    let staged = staging::stage(
        root,
        Staging {
            files,
            review: Some(review(
                original,
                before.clone(),
                adoption.accept_changes,
                outcome.clone(),
            )),
        },
    )?;
    let edit = ManifestEdit {
        verb: EditVerb::Update,
        project,
        specs: &[],
        dev: false,
        host: adoption.host,
    };
    let compiled = uv_compile(&edit, door, &project.join(SOURCE), &project.join(LOCK), &[]);
    drop(staged);
    let reviewed = outcome
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let report = |after: Pins| Adopted {
        files: vec![SOURCE.to_string(), LOCK.to_string()],
        sync_root: project.to_path_buf(),
        lock: LOCK.to_string(),
        before: before.clone(),
        after,
    };
    match (compiled, reviewed) {
        (Err(_), Some(reviewed)) if reviewed.withheld => Ok(Adoption::Withheld {
            review: report(reviewed.after),
            changes: reviewed.changes,
        }),
        (Err(error), _) => Err(error),
        (Ok(()), Some(reviewed)) => Ok(Adoption::Adopted(report(reviewed.after))),
        (Ok(()), None) => Err(other(
            "the adoption's resolution published without its review; nothing to report",
        )),
    }
}

/// Whether a requirements file's header says a tool generated it
/// (pip-compile and uv both write "autogenerated" in their first lines).
fn generated(lock: &str) -> bool {
    lock.lines()
        .take(4)
        .any(|line| line.starts_with('#') && line.contains("autogenerated"))
}

/// The pins a requirements file (`shown` in messages) states: each
/// requirement's `==` version (or its specifier when it has none) and its
/// `--hash` values, keyed by normalized name, with the environment marker
/// when there is one. A package declared twice for the same marker is one
/// pin when both agree on the version (their hashes merged), and an error
/// when they do not: no single pin can be compared for it.
pub(crate) fn pins(text: &str, shown: &str) -> io::Result<Pins> {
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
        match found.get_mut(&key) {
            None => {
                found.insert(key, Pin { version, hashes });
            }
            Some(pin) if pin.version == version => pin.hashes.extend(hashes),
            Some(pin) => {
                return Err(other(format!(
                    "{shown} declares {key} twice with different versions ({} and {version}); \
                     keep one declaration per package and environment marker, then adopt again",
                    pin.version
                )))
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_read_versions_hashes_and_markers() {
        let text = "# This file was autogenerated by uv via the following command:\n\
                    #    ward\n\
                    Six==1.16.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\n    # via -r requirements.in\n\
                    idna==3.10 ; python_version >= '3.8' --hash=sha256:cc  # pinned\n\
                    -r other.txt\n\
                    requests>=2\n";
        let pins = pins(text, "requirements.txt").unwrap();
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

    /// A package declared twice for one marker: the same version is one
    /// pin with both declarations' hashes (none is lost from the review),
    /// different versions are refused by name, and other markers are other
    /// pins.
    #[test]
    fn repeated_declarations_merge_when_they_agree_and_are_refused_when_not() {
        let merged = pins(
            "six==1.16.0 --hash=sha256:aa\nSIX==1.16.0 --hash=sha256:bb\n\
             six==1.15.0 ; python_version < '3' --hash=sha256:cc\n",
            "requirements.txt",
        )
        .unwrap();
        assert_eq!(merged.len(), 2, "{merged:?}");
        assert_eq!(
            merged["six"].hashes.iter().collect::<Vec<_>>(),
            ["sha256:aa", "sha256:bb"]
        );
        assert_eq!(merged["six; python_version < '3'"].version, "1.15.0");
        let error = pins(
            "six==1.16.0 --hash=sha256:aa\nsix==1.17.0 --hash=sha256:bb\n",
            "requirements.txt",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("requirements.txt declares six twice")
                && error.contains("1.16.0 and 1.17.0"),
            "{error}"
        );
    }

    const ORIGINAL: &str = "six==1.16.0 --hash=sha256:aa\n";

    fn run_review(accept: bool, before: Option<&[u8]>, after: &[u8]) -> (io::Result<()>, Outcome) {
        let outcome = Outcome::default();
        let check = review(
            ORIGINAL.to_string(),
            pins(ORIGINAL, "requirements.txt").unwrap(),
            accept,
            outcome.clone(),
        );
        let digest: Option<[u8; 32]> = before.map(|bytes| Sha256::digest(bytes).into());
        let result = check(&[
            Candidate {
                relative: Path::new(SOURCE),
                before: None,
                after: Some(ORIGINAL.as_bytes()),
            },
            Candidate {
                relative: Path::new(LOCK),
                before: digest,
                after: Some(after),
            },
        ]);
        (result, outcome)
    }

    fn reviewed(outcome: &Outcome) -> Reviewed {
        outcome.lock().unwrap().take().expect("the review ran")
    }

    /// The review passes a compile that keeps every pin and hash, and
    /// withholds one that moves a version or loses a hash unless changes
    /// are accepted; it always leaves what it saw for the diff.
    #[test]
    fn the_review_withholds_moved_pins_and_lost_hashes_unless_accepted() {
        let kept = b"# autogenerated\nsix==1.16.0 --hash=sha256:aa --hash=sha256:bb\n";
        let (result, outcome) = run_review(false, Some(ORIGINAL.as_bytes()), kept);
        result.unwrap();
        let seen = reviewed(&outcome);
        assert!(!seen.withheld && seen.changes.is_empty(), "{seen:?}");
        assert_eq!(seen.after["six"].hashes.len(), 2);

        let moved = b"six==1.17.0 --hash=sha256:cc\n";
        let (result, outcome) = run_review(false, Some(ORIGINAL.as_bytes()), moved);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("nothing was published"));
        let seen = reviewed(&outcome);
        assert!(seen.withheld);
        assert_eq!(
            seen.changes,
            [
                "six 1.16.0 -> 1.17.0",
                "six: the original hash sha256:aa is lost"
            ]
        );

        let (result, outcome) = run_review(true, Some(ORIGINAL.as_bytes()), moved);
        result.unwrap();
        let seen = reviewed(&outcome);
        assert!(!seen.withheld && seen.changes.len() == 2, "{seen:?}");
    }

    /// A lock edited after it was read is not the one the review compares
    /// against, so the publication is refused.
    #[test]
    fn the_review_refuses_a_lock_that_changed_since_it_was_read() {
        let (result, outcome) = run_review(true, Some(b"six==1.17.0\n"), ORIGINAL.as_bytes());
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("changed while it was being adopted"),
            "{error}"
        );
        assert!(outcome.lock().unwrap().is_none());
    }
}
