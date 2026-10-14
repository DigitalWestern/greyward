//! The PyPI packages a uv run's lock names, for the door's `young-package`
//! check (`kernel::resolve::age`): every `uv.lock` package from the public
//! index, and every pinned line of a compiled requirements file (uv
//! compiles those against PyPI alone). Git, path and URL requirements are
//! left out.

use super::manifest::uv_pypi_packages;
use crate::kernel::resolve::age::LockedPackage;
use crate::kernel::resolve::door::{LockedList, Staged};
use std::io;
use std::path::PathBuf;

/// The [`LockedList`] of a uv run whose declared outputs are `outputs`:
/// `uv.lock`, or a compiled `.txt` requirements file.
pub(crate) fn locked_list<'a>(outputs: Vec<PathBuf>) -> LockedList<'a> {
    Box::new(move |staged: &Staged<'_>| {
        let mut locked = Vec::new();
        for output in &outputs {
            let Some(bytes) = staged.read(output)? else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            let name = output.file_name().and_then(|name| name.to_str());
            if name == Some("uv.lock") {
                locked.extend(
                    uv_pypi_packages(&text)?
                        .into_iter()
                        .map(|(name, version)| LockedPackage::new(name, version)),
                );
            } else if name.is_some_and(|name| name.ends_with(".txt")) {
                locked.extend(requirements_packages(&text)?);
            }
        }
        Ok(locked)
    })
}

/// The exact `name==version` pins of a requirements file, compiled or
/// not, each line read on its own: a marker or a hash after the pin is
/// ignored, and a line that is not an exact registry pin (an option, a
/// range, a URL or VCS requirement, an include) names nothing. The tailor's
/// own reader decides what the file may hold.
fn requirements_packages(text: &str) -> io::Result<Vec<LockedPackage>> {
    Ok(text
        .replace("\\\n", " ")
        .lines()
        .filter_map(exact_pin)
        .collect())
}

fn exact_pin(line: &str) -> Option<LockedPackage> {
    let line = line.split(" #").next()?.trim();
    let requirement = line.split(';').next()?.split_whitespace().next()?;
    let (name, version) = requirement.split_once("==")?;
    let name = name.split('[').next()?.trim();
    let plain = |word: &str, extra: &[u8]| {
        !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b) || extra.contains(&b))
    };
    (plain(name, b"") && plain(version, b"+!")).then(|| LockedPackage::new(name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_locks_list_public_index_packages_only() {
        let lock = r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "six"
version = "1.17.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "private"
version = "2.0.0"
source = { registry = "https://example.com/simple" }

[[package]]
name = "iniconfig"
version = "2.0.0"
source = { git = "https://github.com/pytest-dev/iniconfig?rev=v2.0.0#93f5930e668c0d1ddf4597e38dd0dea4e2665e7a" }
"#;
        assert_eq!(
            uv_pypi_packages(lock).unwrap(),
            [("six".to_string(), "1.17.0".to_string())]
        );
    }

    #[test]
    fn compiled_requirements_list_their_pins() {
        let text = "six==1.17.0 \\\n    --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\n\
                    iniconfig @ git+https://github.com/pytest-dev/iniconfig@93f5930e668c0d1ddf4597e38dd0dea4e2665e7a\n\
                    # via demo\n-r other.txt\nattrs>=23\n\
                    requests[socks]==2.32.3 ; python_version >= \"3\"\n\
                    torch==2.4.0+cpu  # a local version\n";
        assert_eq!(
            requirements_packages(text).unwrap(),
            [
                LockedPackage::new("six", "1.17.0"),
                LockedPackage::new("requests", "2.32.3"),
                LockedPackage::new("torch", "2.4.0+cpu"),
            ]
        );
    }
}
