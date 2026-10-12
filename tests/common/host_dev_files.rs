//! A stand-in for a host development package, for the debug-only hook
//! `GREYWARD_TEST_HOST_DEV_FILES` (`hostview::test_host_dev_files`): a
//! directory laid out like a host root, with a header under `usr/include`
//! and a static library under `usr/lib` that neither the C runtime nor
//! ward's native library set has. A build that needs them fails against
//! the C runtime alone and builds against the whole host, which is how the
//! host-fallback end-to-end tests of each tailor reach that path on any
//! machine.

use std::path::Path;
use std::process::Command;

/// The header a probe includes.
pub const HEADER: &str = "greyward_probe.h";

/// What a probe passes to `-l`: `libgreyward_probe.a`.
pub const LIBRARY: &str = "greyward_probe";

/// A C file that includes the stand-in's header, links its library, and
/// prints the marker the header holds now.
pub const PROBE_C: &str = "#include <stdio.h>\n#include <greyward_probe.h>\n\
     int main(void) { puts(GREYWARD_PROBE); return greyward_probe()[0] == 0; }\n";

/// Lay out the stand-in at `dev`, with `marker` as what its library
/// returns, built by the host's `cc` and `ar`. A static library, so a probe
/// linked against it runs without a library search path.
pub fn write(dev: &Path, marker: &str) {
    let include = dev.join("usr/include");
    let lib = dev.join("usr/lib");
    std::fs::create_dir_all(&include).unwrap();
    std::fs::create_dir_all(&lib).unwrap();
    rewrite(dev, marker);
    // Built beside the stand-in, so the tree holds only what a package
    // would install.
    let build = dev.with_extension("build");
    std::fs::create_dir_all(&build).unwrap();
    let source = build.join("greyward_probe.c");
    std::fs::write(
        &source,
        "#include <greyward_probe.h>\n\
         const char *greyward_probe(void) { return GREYWARD_PROBE; }\n",
    )
    .unwrap();
    let object = build.join("greyward_probe.o");
    run(
        Command::new("cc")
            .args(["-c", "-fPIC", "-I"])
            .arg(&include)
            .arg("-o")
            .arg(&object)
            .arg(&source),
        "cc builds the stand-in library",
    );
    run(
        Command::new("ar")
            .arg("rcs")
            .arg(lib.join(format!("lib{LIBRARY}.a")))
            .arg(&object),
        "ar archives the stand-in library",
    );
}

/// Rewrite the stand-in's header with `marker`: the change a host makes
/// when it upgrades a development package. The library keeps the marker
/// it was built with; `PROBE_C` prints the header's.
pub fn rewrite(dev: &Path, marker: &str) {
    std::fs::write(
        dev.join("usr/include").join(HEADER),
        format!(
            "#ifndef GREYWARD_PROBE_H\n#define GREYWARD_PROBE_H\n\
             #define GREYWARD_PROBE \"{marker}\"\n\
             const char *greyward_probe(void);\n#endif\n"
        ),
    )
    .unwrap();
}

fn run(command: &mut Command, label: &str) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{label}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
