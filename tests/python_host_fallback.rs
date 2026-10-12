//! The Python sdist build's fallback to the whole host, end to end: a
//! source package whose C extension needs a host development package the C
//! runtime lacks builds against the whole host, and the wheel's identity
//! follows that package. The package is the stand-in a debug build reads
//! from `GREYWARD_TEST_HOST_DEV_FILES` (tests/common/host_dev_files.rs).
//!
//! Heavy (it realizes CPython and setuptools on first run), so #[ignore]d;
//! the heavy workflow (.github/workflows/heavy.yml) runs it:
//!     cargo test --test python_host_fallback -- --ignored
//! The one test sets `GREYWARD_TEST_HOST_DEV_FILES` for this process, so
//! the file holds no other test.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use greyward::kernel::platform::Platform;
use greyward::kernel::types::*;
use greyward::tailors::python;
use greyward::tailors::python::build;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

mod common;

use common::host_dev_files;
use common::TempDir;

/// The extension's source: it includes the stand-in's header, links its
/// library, and keeps the header's marker in the built module, where the
/// test reads it back.
const EXTENSION_C: &str = r#"#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <greyward_probe.h>

const char greyward_probe_marker[] = "greyward-marker:" GREYWARD_PROBE;

static PyObject *probe(PyObject *self, PyObject *args) {
    (void)self;
    (void)args;
    return PyUnicode_FromString(greyward_probe());
}

static PyMethodDef methods[] = {
    {"probe", probe, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "hostprobe", NULL, -1, methods};

PyMODINIT_FUNC PyInit_hostprobe(void) { return PyModule_Create(&module); }
"#;

/// A setuptools sdist `hostprobe` 0.1 with the one extension module
/// `EXTENSION_C`, packed with the host tar into `dir`. The scratch path in
/// setup.py makes every run's sdist new to the store, so the build runs
/// here rather than coming back from an earlier run's cached wheel.
fn sdist(dir: &Path) -> LockedPackage {
    let name = "hostprobe";
    let root = dir.join(format!("{name}-0.1"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("PKG-INFO"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: 0.1\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("pyproject.toml"),
        "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"setuptools.build_meta\"\n",
    )
    .unwrap();
    std::fs::write(root.join("hostprobe.c"), EXTENSION_C).unwrap();
    std::fs::write(
        root.join("setup.py"),
        format!(
            "# built from {}\nfrom setuptools import Extension, setup\n\
             setup(name=\"{name}\", version=\"0.1\", ext_modules=[Extension(\"{name}\", \
             [\"hostprobe.c\"], libraries=[\"{}\"])])\n",
            dir.display(),
            host_dev_files::LIBRARY
        ),
    )
    .unwrap();
    let filename = format!("{name}-0.1.tar.gz");
    let archive = dir.join(&filename);
    let status = common::tar_create()
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(dir)
        .arg(format!("{name}-0.1"))
        .status()
        .unwrap();
    assert!(status.success(), "tar {filename}");
    let bytes = std::fs::read(&archive).unwrap();
    LockedPackage {
        name: name.into(),
        version: "0.1".into(),
        filename,
        url: format!("file://{}", archive.display()),
        sha256: hex::encode(Sha256::digest(&bytes)),
        kind: ArtifactKind::Sdist,
        git: None,
    }
}

/// The marker the built extension in `wheel` holds.
fn marker_in(wheel: &Path) -> String {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(wheel).unwrap()).unwrap();
    let name = archive
        .file_names()
        .find(|name| name.starts_with("hostprobe") && name.ends_with(".so"))
        .unwrap_or_else(|| panic!("no extension module in {}", wheel.display()))
        .to_string();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut archive.by_name(&name).unwrap(), &mut bytes).unwrap();
    let prefix = b"greyward-marker:";
    let at = bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .unwrap_or_else(|| panic!("no marker in {name}"));
    let rest = &bytes[at + prefix.len()..];
    let end = rest.iter().position(|&byte| byte == 0).unwrap();
    String::from_utf8(rest[..end].to_vec()).unwrap()
}

/// The identity inputs of the store object a built wheel was published in.
fn wheel_inputs(store: &Path, wheel: &Path) -> serde_json::Map<String, serde_json::Value> {
    let id = wheel
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy();
    let meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(store.join("meta").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    meta["identity"]["inputs"].as_object().unwrap().clone()
}

/// An sdist whose extension needs a header and library only the whole
/// host has fails against the C runtime alone, builds against the whole
/// host, and is committed under its own `host-fallback/1` identity, keyed
/// by the host's build inputs. The next build on the unchanged host reuses
/// that wheel; one after the development package changed builds a new
/// wheel against the new files, under a new identity.
#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn sdist_fallback_follows_the_host_dev_files() {
    let platform = Platform::host().unwrap();
    if !common::node_stub::sandbox_or_skip("sdist_fallback_follows_the_host_dev_files", platform) {
        return;
    }
    let temp = TempDir::new("python-host-dev-files");
    let dev = temp.0.join("host-dev-files");
    host_dev_files::write(&dev, "first");
    // Before anything else runs: no other thread reads the environment yet,
    // and the file holds no other test.
    std::env::set_var("GREYWARD_TEST_HOST_DEV_FILES", &dev);

    let store = common::open_store(&temp);
    let activity = &store
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let mut attribution = greyward::kernel::policy::Attribution::open("python").unwrap();
    let python = python::shipped_selection("3.12.14").unwrap();
    let package = sdist(temp.path());
    let mut build = || -> PathBuf {
        build::build_sdist_wheel(
            &mut greyward::kernel::resolve::ResolutionDoor::open(
                &store,
                activity,
                platform,
                greyward::kernel::resolve::DoorKind::Planner,
                &mut attribution,
            )
            .unwrap(),
            &package,
            &python,
        )
        .expect("the sdist builds against the whole host")
    };

    let first = build();
    assert_eq!(marker_in(&first), "first");
    let inputs = wheel_inputs(&store.root, &first);
    assert_eq!(
        inputs["build_view"].as_str(),
        Some("host-fallback/1"),
        "the build did not fall back: {inputs:?}"
    );
    assert_eq!(
        inputs["host_fallback"].as_str(),
        Some("hostprobe"),
        "{inputs:?}"
    );
    let first_host = inputs["host_inputs"].as_str().unwrap().to_string();
    let id = first
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy();
    let exceptions = store.exceptions(&id).unwrap();
    assert!(
        exceptions.iter().any(|exception| exception.kind
            == greyward::kernel::policy::HOST_BUILD_INPUTS
            && exception.subject == "hostprobe==0.1"),
        "no host-build-inputs exception: {exceptions:?}"
    );

    // The host as it was: the same wheel, through the fallback record.
    assert_eq!(build(), first, "an unchanged host built a new wheel");

    // The development package upgraded: a new wheel, built against it.
    host_dev_files::rewrite(&dev, "second, upgraded");
    let second = build();
    assert_ne!(second, first, "a changed host reused the old wheel");
    assert_eq!(marker_in(&second), "second, upgraded");
    let inputs = wheel_inputs(&store.root, &second);
    assert_eq!(
        inputs["build_view"].as_str(),
        Some("host-fallback/1"),
        "{inputs:?}"
    );
    assert_ne!(
        inputs["host_inputs"].as_str(),
        Some(first_host.as_str()),
        "the host fingerprint missed the changed header: {inputs:?}"
    );
}
