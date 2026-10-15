//! End-to-end Ruby tailor test. Heavy: downloads the pinned portable Ruby
//! and the gem closure (racc compiles a C extension in the sandbox; on
//! Linux, source nokogiri builds its vendored libxml2/libxslt there too).
//!
//! On Linux it is also the Ruby relocation gate:
//! it also records the ELF / RbConfig / pkg-config relocation observations
//! for the realized Ruby object and proves nothing at runtime depends on a
//! staging directory, a Homebrew prefix, or a host Ruby.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::{
    assert_frozen_never_writes_the_lock, assert_ok, fixture, ward, ward_offline, TempDir,
};

/// Linux project: only the SOURCE (`ruby` platform) variant of nokogiri, so
/// the gate compiles its vendored libxml2/libxslt in the sandbox instead of
/// silently picking a precompiled `x86_64-linux` gem. Exact versions; the
/// lock is consistent with the Gemfile and carries no CHECKSUMS section, so
/// plan_ruby obtains every digest from the platform-qualified RubyGems API.
fn linux_project_files(project: &Path) {
    std::fs::write(
        project.join("Gemfile"),
        r#"source "https://rubygems.org"

gem "mini_portile2", "2.8.9"
gem "nokogiri", "1.18.10"
gem "racc", "1.8.1"
gem "rake", "13.4.2"
"#,
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.9)
    nokogiri (1.18.10)
      mini_portile2 (~> 2.8.2)
      racc (~> 1.4)
    racc (1.8.1)
    rake (13.4.2)

PLATFORMS
  ruby

DEPENDENCIES
  mini_portile2 (= 2.8.9)
  nokogiri (= 1.18.10)
  racc (= 1.8.1)
  rake (= 13.4.2)

BUNDLED WITH
   2.6.9
"#,
    )
    .unwrap();
}

/// Published objects by identity kind: (object path, meta json).
fn find_object(store: &Path, kind: &str) -> Option<(PathBuf, serde_json::Value)> {
    for entry in std::fs::read_dir(store.join("meta")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if meta["identity"]["kind"].as_str() == Some(kind) {
            let obj = store.join("objects").join(meta["id"].as_str().unwrap());
            return Some((obj, meta));
        }
    }
    None
}

fn assert_immutable_tree(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path).unwrap();
    if metadata.file_type().is_symlink() {
        return;
    }
    assert_eq!(
        metadata.permissions().mode() & 0o222,
        0,
        "published path is writable: {}",
        path.display()
    );
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            assert_immutable_tree(&entry.unwrap().path());
        }
    }
}

/// Prefixes no ACTIVE path may mention: the store's staging area (objects are
/// renamed out of it at commit) and the Homebrew build/host prefixes.
fn forbidden_prefixes(staging: &Path) -> Vec<String> {
    vec![
        staging.to_string_lossy().into_owned(),
        "/home/linuxbrew".to_string(),
        "/opt/homebrew".to_string(),
        "/usr/local/Cellar".to_string(),
    ]
}

fn assert_no_forbidden_prefix(text: &str, staging: &Path, what: &str) {
    for forbidden in forbidden_prefixes(staging) {
        assert!(
            !text.contains(&forbidden),
            "{what} mentions forbidden prefix {forbidden:?}: {text}"
        );
    }
}

/// Run the realized interpreter directly (no ward, scrubbed env) so a
/// host Ruby can never answer for it.
fn pinned_ruby(ruby: &Path, cwd: &Path, script: &str, label: &str) -> String {
    let output = Command::new(ruby.join("bin/ruby"))
        .current_dir(cwd)
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ruby.join("bin").display()),
        )
        .env("HOME", cwd)
        .env("TMPDIR", cwd)
        .env("BUNDLE_IGNORE_CONFIG", "1")
        .arg("-e")
        .arg(script)
        .output()
        .unwrap();
    assert_ok(output, label)
}

fn tool(name: &str, args: &[&str], target: &Path) -> String {
    let output = Command::new(name).args(args).arg(target).output().unwrap();
    assert_ok(output, &format!("{name} {args:?} {}", target.display()))
}

fn collect_files(root: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_file() {
        if root.to_string_lossy().ends_with(suffix) {
            out.push(root.to_path_buf());
        }
    } else if metadata.is_dir() {
        for entry in std::fs::read_dir(root).unwrap() {
            collect_files(&entry.unwrap().path(), suffix, out);
        }
    }
}

fn collect_symlinks(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        out.push(root.to_path_buf());
    } else if metadata.is_dir() {
        for entry in std::fs::read_dir(root).unwrap() {
            collect_symlinks(&entry.unwrap().path(), out);
        }
    }
}

/// glibc sonames the portable bottle, and a gem extension built against the
/// host C runtime alone, may legitimately need from the host. Nothing else:
/// the gem sandbox hides every other host library (`HostView::RuntimeOnly`),
/// so nokogiri's vendored libxml2 finds neither the host's zlib nor its
/// liblzma, on every host (issue #304); what it links beyond glibc comes from
/// ward's native library set (#329).
fn is_glibc_soname(soname: &str) -> bool {
    [
        "libc.so",
        "libm.so",
        "libdl.so",
        "libpthread.so",
        "librt.so",
        "libcrypt.so",
        "libutil.so",
        "ld-linux-x86-64.so",
    ]
    .iter()
    .any(|prefix| soname.starts_with(prefix))
}

/// `readelf -dW`: NEEDED must be glibc-only; RPATH/RUNPATH is recorded as
/// historical provenance (the bottle retains its Homebrew build RUNPATH but
/// nothing NEEDED lives there). `ldd` then proves what actually resolves.
fn assert_elf_resolves_from_system(elf: &Path, staging: &Path) {
    assert_elf_resolves_from(elf, staging, None);
}

/// `assert_elf_resolves_from_system`, except that a NEEDED library `ldd`
/// resolves inside `libset`, ward's pinned native library set, is allowed:
/// a native gem builds with the set mounted and links it through its
/// RUNPATH (#329).
fn assert_elf_resolves_from(elf: &Path, staging: &Path, libset: Option<&Path>) {
    let ldd = tool("ldd", &[], elf);
    let from_set = |soname: &str| {
        libset.is_some_and(|set| {
            ldd.lines().any(|line| {
                let mut parts = line.trim().split(" => ");
                parts.next() == Some(soname)
                    && parts.next().is_some_and(|path| {
                        Path::new(path.split(' ').next().unwrap()).starts_with(set)
                    })
            })
        })
    };
    let dynamic = tool("readelf", &["-dW"], elf);
    for line in dynamic.lines() {
        if line.contains("(NEEDED)") {
            let soname = line
                .rsplit('[')
                .next()
                .unwrap()
                .trim_end_matches(']')
                .trim();
            assert!(
                is_glibc_soname(soname) || from_set(soname),
                "{} NEEDS a non-glibc library {soname} from outside the native library set:\n{ldd}",
                elf.display()
            );
        } else if line.contains("(RUNPATH)") || line.contains("(RPATH)") {
            eprintln!("{}: historical {}", elf.display(), line.trim());
        }
    }
    assert!(
        !ldd.contains("not found"),
        "{} has unresolved libraries:\n{ldd}",
        elf.display()
    );
    assert_no_forbidden_prefix(&ldd, staging, "ldd resolution");
}

/// Relocation observations for the realized Linux Ruby object.
/// Returns the interpreter's own `Gem::Platform.local`.
fn linux_toolchain_observations(project: &Path, ruby: &Path, staging: &Path) -> String {
    let ruby_obj = ruby.canonicalize().unwrap();
    let ruby_binary = ruby_obj.join("bin/ruby");

    let headers = tool("readelf", &["-lW"], &ruby_binary);
    let interpreter = headers
        .lines()
        .find(|line| line.contains("Requesting program interpreter"))
        .expect("bin/ruby has no PT_INTERP");
    eprintln!("bin/ruby {}", interpreter.trim());
    assert_no_forbidden_prefix(interpreter, staging, "program interpreter");
    assert_elf_resolves_from_system(&ruby_binary, staging);

    // Shipped native extensions (portable-ruby links openssl/zlib/yaml/ffi
    // statically into bin/ruby; only bundled gem extensions are .so files).
    let mut shared_objects = Vec::new();
    collect_files(&ruby_obj.join("lib"), ".so", &mut shared_objects);
    for so in &shared_objects {
        assert_elf_resolves_from_system(so, staging);
    }
    eprintln!("Ruby object ships {} .so files", shared_objects.len());

    let config = pinned_ruby(
        &ruby_obj,
        project,
        r#"
require "json"
require "rbconfig"
keys = %w[prefix bindir libdir rubyhdrdir rubyarchhdrdir arch CC CXX LDSHARED LIBRUBYARG ENABLE_SHARED configure_args]
out = keys.to_h { |key| [key, RbConfig::CONFIG[key]] }
out["gem_platform_local"] = Gem::Platform.local.to_s
out["gem_ruby"] = Gem.ruby
out["static_stdlib"] = begin
  require "openssl"
  require "zlib"
  $LOADED_FEATURES.grep(/\A(openssl|zlib)\.so\z/)
end
puts JSON.generate(out)
"#,
        "rbconfig observation",
    );
    let config: serde_json::Value = serde_json::from_str(config.trim()).unwrap();
    let text = |key: &str| config[key].as_str().unwrap_or_default().to_string();
    // Active paths must follow the object (--enable-load-relative).
    assert_eq!(
        Path::new(&text("prefix")).canonicalize().unwrap(),
        ruby_obj,
        "RbConfig prefix does not follow the store object"
    );
    for key in ["bindir", "libdir", "rubyhdrdir", "rubyarchhdrdir"] {
        let value = text(key);
        assert!(
            Path::new(&value).starts_with(&ruby_obj),
            "RbConfig::{key}={value} is outside the object {}",
            ruby_obj.display()
        );
        assert!(
            Path::new(&value).is_dir(),
            "RbConfig::{key}={value} missing"
        );
        assert_no_forbidden_prefix(&value, staging, key);
    }
    for key in [
        "arch",
        "CC",
        "CXX",
        "LDSHARED",
        "LIBRUBYARG",
        "ENABLE_SHARED",
    ] {
        let value = text(key);
        assert!(!value.is_empty(), "RbConfig::{key} is empty");
        assert_no_forbidden_prefix(&value, staging, key);
        eprintln!("RbConfig::{key}={value}");
    }
    assert_eq!(text("gem_ruby"), ruby_binary.to_string_lossy());
    // configure_args retains build provenance (Homebrew Cellar prefix,
    // portable-* dependency dirs). Recorded separately; not an active path.
    eprintln!(
        "RbConfig::configure_args (historical)={}",
        text("configure_args")
    );
    let static_stdlib = config["static_stdlib"].as_array().unwrap();
    assert_eq!(
        static_stdlib.len(),
        2,
        "openssl/zlib were not the statically linked features: {static_stdlib:?}"
    );

    // pkg-config: prefix must be relative to the .pc file and resolve to the
    // object; cflags must point at the object's headers.
    let mut pcs = Vec::new();
    collect_files(&ruby_obj.join("lib/pkgconfig"), ".pc", &mut pcs);
    assert!(!pcs.is_empty(), "portable-ruby shipped no pkg-config file");
    for pc in &pcs {
        let module = pc.file_stem().unwrap().to_str().unwrap();
        let pc_dir = pc.parent().unwrap();
        let pkg_config = |query: &str| {
            let output = Command::new("pkg-config")
                .env("PKG_CONFIG_PATH", pc_dir)
                .args([query, module])
                .output()
                .unwrap();
            assert_ok(output, &format!("pkg-config {query} {module}"))
        };
        let prefix = pkg_config("--variable=prefix");
        assert_eq!(
            Path::new(prefix.trim()).canonicalize().unwrap(),
            ruby_obj,
            "pkg-config {module} prefix does not resolve to the object"
        );
        let cflags = pkg_config("--cflags");
        assert!(
            cflags.contains(&format!("{}/", ruby_obj.display()))
                || cflags.contains("/lib/pkgconfig/../../include"),
            "pkg-config {module} cflags do not reference the object: {cflags}"
        );
        assert_no_forbidden_prefix(&cflags, staging, "pkg-config cflags");
        eprintln!(
            "pkg-config {module}: prefix={} cflags={}",
            prefix.trim(),
            cflags.trim()
        );
    }

    // Native compilation finds the pinned headers via mkmf + host cc (the
    // sandboxed gem build uses the same RbConfig; this is the cheap check).
    let mkmf_dir = project.join("mkmf-probe");
    std::fs::create_dir_all(&mkmf_dir).unwrap();
    let mkmf = pinned_ruby(
        &ruby_obj,
        &mkmf_dir,
        r#"require "mkmf"; $stdout = STDERR; ok = have_header("ruby.h"); STDOUT.puts(ok ? "ruby.h ok" : "ruby.h missing"); exit(ok ? 0 : 1)"#,
        "mkmf header probe",
    );
    assert!(mkmf.contains("ruby.h ok"), "{mkmf}");
    let mkmf_log = std::fs::read_to_string(mkmf_dir.join("mkmf.log")).unwrap_or_default();
    assert!(
        mkmf_log.contains(&format!("-I{}", ruby_obj.join("include").display())),
        "mkmf did not compile against the object's headers:\n{mkmf_log}"
    );
    assert_no_forbidden_prefix(&mkmf_log, staging, "mkmf.log");

    // Launchers: RubyGems' sh-prelude wrappers exec the sibling ruby.
    for launcher in ["bin/gem", "bin/bundle", "bin/bundler"] {
        let body = std::fs::read_to_string(ruby_obj.join(launcher)).unwrap();
        assert!(
            body.starts_with("#!/bin/sh\n"),
            "{launcher} shebang: {:?}",
            body.lines().next()
        );
        assert!(
            body.contains("exec \"$bindir/ruby\""),
            "{launcher} does not exec the sibling interpreter"
        );
        assert_no_forbidden_prefix(&body, staging, launcher);
    }

    let mut symlinks = Vec::new();
    collect_symlinks(&ruby_obj, &mut symlinks);
    for link in &symlinks {
        let target = std::fs::read_link(link).unwrap();
        assert!(
            target.is_relative() || target.starts_with(&ruby_obj),
            "symlink {} escapes the object: {}",
            link.display(),
            target.display()
        );
        assert_no_forbidden_prefix(&target.to_string_lossy(), staging, "symlink target");
    }
    eprintln!("Ruby object symlinks: {}", symlinks.len());

    let platform_local = text("gem_platform_local");
    assert!(!platform_local.is_empty());
    eprintln!(
        "Gem::Platform.local={platform_local}; bottle tag=x86_64_linux; Rust triple=x86_64-unknown-linux-gnu"
    );
    assert_ne!(platform_local, "x86_64_linux");
    assert_ne!(platform_local, "x86_64-unknown-linux-gnu");
    platform_local
}

const STDLIB_PROBE: &str = r#"
require "json"
require "digest"
require "openssl"
require "zlib"
input = "greyward-linux-ruby"
compressed = Zlib::Deflate.deflate(input)
abort "zlib round-trip failed" unless Zlib::Inflate.inflate(compressed) == input
digest = OpenSSL::Digest::SHA256.hexdigest(input)
abort "openssl digest disagrees with Digest" unless digest == Digest::SHA256.hexdigest(input)
puts JSON.generate("digest" => digest, "zlib" => "ok", "openssl" => OpenSSL::OPENSSL_LIBRARY_VERSION)
"#;

fn assert_stdlib_probe(output: &str, label: &str) {
    let probe: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(probe["zlib"], "ok", "{label}: {output}");
    assert_eq!(
        probe["digest"].as_str().map(str::len),
        Some(64),
        "{label}: {output}"
    );
    assert!(
        probe["openssl"]
            .as_str()
            .unwrap_or_default()
            .starts_with("OpenSSL "),
        "{label}: {output}"
    );
    eprintln!("{label}: {}", output.trim());
}

#[test]
#[ignore]
fn ruby_sync_native_ext_and_run() {
    let linux = cfg!(target_os = "linux");
    let temp = TempDir::new("ruby-e2e");
    let project = temp.0.join("ruby-hello");
    std::fs::create_dir_all(&project).unwrap();
    if linux {
        linux_project_files(&project);
    } else {
        let fixtures = fixture("ruby-hello");
        for f in ["Gemfile", "Gemfile.lock"] {
            std::fs::copy(fixtures.join(f), project.join(f)).unwrap();
        }
    }
    let store = temp.0.join("store");
    let staging = store.join("tmp");

    // Hostile .bundle/config must be neutralized (BUNDLE_IGNORE_CONFIG).
    std::fs::create_dir_all(project.join(".bundle")).unwrap();
    std::fs::write(
        project.join(".bundle/config"),
        "---\nBUNDLE_PATH: \"/nonexistent\"\nBUNDLE_GEMFILE: \"/nonexistent/Gemfile\"\n",
    )
    .unwrap();

    let mut platform_local = String::new();
    if linux {
        // `plan` publishes the Ruby object and prints the gem plan without
        // installing anything, so the toolchain can be gated on its own.
        let plan = assert_ok(ward(&project, &temp.0, &["plan"]), "plan");
        let plan: serde_json::Value = serde_json::from_str(plan.trim())
            .unwrap_or_else(|e| panic!("plan output is not JSON ({e}): {plan}"));
        let gems = plan["gems"].as_array().unwrap();
        let expect = [
            ("mini_portile2", "2.8.9"),
            ("nokogiri", "1.18.10"),
            ("racc", "1.8.1"),
            ("rake", "13.4.2"),
        ];
        assert_eq!(gems.len(), expect.len(), "{plan}");
        for (name, version) in expect {
            let gem = gems
                .iter()
                .find(|g| g["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing from plan: {plan}"));
            assert_eq!(gem["version"], version, "{plan}");
            // Bundler selected the SOURCE gem, not a precompiled platform gem.
            assert_eq!(gem["platform"], "ruby", "{name}: {plan}");
            assert_eq!(gem["full_name"], format!("{name}-{version}"), "{plan}");
            assert_eq!(gem["sha256"].as_str().map(str::len), Some(64), "{plan}");
        }

        let (ruby_obj, _) = find_object(&store, "ruby").expect("Ruby object published by plan");
        assert_immutable_tree(&ruby_obj);
        platform_local = linux_toolchain_observations(&project, &ruby_obj, &staging);
        assert_eq!(
            plan["ruby_platform"].as_str().unwrap(),
            platform_local,
            "plan ruby_platform must be the pinned interpreter's Gem::Platform.local"
        );
        let stdlib = pinned_ruby(
            &ruby_obj,
            &project,
            STDLIB_PROBE,
            "pinned Ruby stdlib probe",
        );
        assert_stdlib_probe(&stdlib, "Toolchain-object stdlib probe");
    }

    // Sandboxed gem realization: racc's C extension, and on Linux nokogiri's
    // vendored libxml2/libxslt, compile here (network denied).
    assert_ok(ward(&project, &temp.0, &["sync"]), "sync");

    let (ruby_obj, _) = find_object(&store, "ruby").expect("Ruby object published");
    let (gems_obj, gems_meta) = find_object(&store, "ruby-gems").expect("gems object published");
    assert_immutable_tree(&ruby_obj);
    assert_immutable_tree(&gems_obj);
    assert!(ruby_obj.join("bin/ruby").is_file());
    assert!(gems_obj.join("gems").is_dir());
    let inputs = gems_meta["identity"]["inputs"].as_object().unwrap();
    if linux {
        assert!(
            inputs.contains_key("gem:nokogiri-1.18.10"),
            "gem object was not built from source nokogiri: {inputs:?}"
        );
        assert!(
            !inputs
                .keys()
                .any(|key| key.starts_with("gem:nokogiri-1.18.10-")),
            "a platform nokogiri gem leaked into the object: {inputs:?}"
        );
        assert_eq!(
            inputs["ruby_platform"].as_str().unwrap(),
            platform_local,
            "gem object platform must be the pinned interpreter's Gem::Platform.local"
        );
        assert_eq!(
            inputs["build_view"].as_str(),
            Some("runtime-only/3"),
            "{inputs:?}"
        );
        // Every native gem here (racc, nokogiri) builds against the host C
        // runtime alone: none fell back to the whole host.
        let exceptions = gems_meta["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !exceptions
                .iter()
                .any(|exception| exception["kind"] == "host-build-inputs"),
            "a gem was rebuilt against the whole host: {exceptions:?}"
        );
    }

    // An unchanged project re-syncs with the network cut. The lock has no
    // CHECKSUMS section, so every digest the plan needs comes from what the
    // first sync verified and recorded in the store, and the same objects
    // are projected again.
    let closure = |project: &Path| -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(project.join(".greyward/closures/ruby.json")).unwrap(),
        )
        .unwrap()
    };
    let before = closure(&project);
    // No CHECKSUMS section: each gem's digest is rubygems.org's, and the
    // closure says so, gem by gem, where a policy can refuse it.
    let unpinned: Vec<String> = before["body"]["exceptions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|exception| exception["kind"] == "unpinned-digest")
        .filter_map(|exception| exception["subject"].as_str().map(str::to_string))
        .collect();
    assert!(
        unpinned.iter().any(|subject| subject.starts_with("rake-")),
        "no unpinned-digest for the gems: {unpinned:?}"
    );
    assert_ok(
        ward_offline(&project, &temp.0, &["sync"]),
        "offline re-sync of the unchanged project",
    );
    let after = closure(&project);
    for key in ["ruby_object", "gems_object"] {
        assert_eq!(
            after["body"][key], before["body"][key],
            "the offline re-sync projected a different {key}"
        );
    }
    // A store whose gem object predates its digest records (or lost them)
    // records them on the next online sync, which only hits the object:
    // each gem is verified again from the artifact cache first. After that
    // the offline re-sync works again.
    let records = store.join("records/rubygems-sha256");
    assert!(records.is_dir(), "the sync recorded no rubygems.org digest");
    greyward::kernel::store::remove_tree(&records).unwrap();
    assert_ok(
        ward(&project, &temp.0, &["sync"]),
        "sync over the gem object",
    );
    assert!(
        std::fs::read_dir(&records).unwrap().count() > 0,
        "an object hit recorded no rubygems.org digest"
    );
    assert_ok(
        ward_offline(&project, &temp.0, &["sync"]),
        "offline re-sync after an object hit recorded the digests",
    );

    // Nothing that follows may depend on a staging directory: after the
    // commits, clear whatever is left under store/tmp.
    if let Ok(entries) = std::fs::read_dir(&staging) {
        for entry in entries {
            let path = entry.unwrap().path();
            let _ = greyward::kernel::store::remove_tree(&path);
            let _ = std::fs::remove_file(&path);
        }
    }
    assert!(
        std::fs::read_dir(&staging)
            .map(|mut d| d.next().is_none())
            .unwrap_or(true),
        "staging directory still populated"
    );

    if linux {
        let stdlib = assert_ok(
            ward(&project, &temp.0, &["run", "ruby", "-e", STDLIB_PROBE]),
            "committed Ruby stdlib probe",
        );
        assert_stdlib_probe(&stdlib, "Projected-env stdlib probe");
    }

    // racc's C extension compiled in the sandbox; requiring it proves the
    // native extension (.bundle on Darwin, .so on Linux) stayed loadable and
    // the projected env works.
    let out = assert_ok(
        ward(
            &project,
            &temp.0,
            &[
                "run",
                "ruby",
                "-e",
                "require \"racc/parser\"; require \"rake\"; puts \"ok \" + Rake::VERSION",
            ],
        ),
        "run",
    );
    assert!(out.trim().starts_with("ok 13."), "{out}");
    // The binstub that runs must be the STORE object's wrapper, not a host
    // /usr/bin fallback: a symlink binstub that dangles after the commit
    // rename would otherwise let host rake answer and the check still pass.
    let which = assert_ok(
        ward(&project, &temp.0, &["run", "sh", "-c", "command -v rake"]),
        "which rake",
    );
    let which = which.trim().to_string();
    assert!(
        which.contains("/objects/") && which.contains("gems"),
        "rake resolved outside the store: {which}"
    );
    assert_eq!(
        Path::new(&which).canonicalize().unwrap(),
        gems_obj.canonicalize().unwrap().join("bin/rake"),
        "rake is not the gem object's binstub: {which}"
    );
    // The wrapper itself must execute (relocatable, not a dangling link).
    // Pass the absolute store path as argv[0]; no shell that could quietly
    // fall back to /usr/bin/rake.
    let direct = ward(&project, &temp.0, &["run", which.as_str(), "--version"]);
    let version = assert_ok(direct, "store binstub direct exec");
    assert!(version.contains("13."), "{version}");

    if linux {
        let nokogiri = assert_ok(
            ward(
                &project,
                &temp.0,
                &[
                    "run",
                    "ruby",
                    "-e",
                    r#"
require "json"
require "nokogiri"
xml = Nokogiri::XML("<root><value>ok</value></root>")
value = xml.at_xpath("/root/value").text
native = $LOADED_FEATURES.find { |path| path.end_with?(".so") && File.basename(path) == "nokogiri.so" }
abort "nokogiri native library was not loaded" unless native
info = Nokogiri::VERSION_INFO
puts JSON.generate("native" => File.realpath(native), "value" => value,
  "nokogiri" => info["nokogiri"]["version"], "libxml_source" => info["libxml"]["source"],
  "libxml" => info["libxml"]["loaded"], "libxslt_source" => info.dig("libxslt", "source"))
"#,
                ],
            ),
            "nokogiri native extension probe",
        );
        let nokogiri: serde_json::Value = serde_json::from_str(nokogiri.trim()).unwrap();
        eprintln!("nokogiri probe: {nokogiri}");
        assert_eq!(nokogiri["value"], "ok");
        assert_eq!(nokogiri["nokogiri"], "1.18.10");
        // Vendored-library source build, not system libxml2 and not a
        // precompiled gem.
        assert_eq!(nokogiri["libxml_source"], "packaged", "{nokogiri}");
        assert_eq!(nokogiri["libxslt_source"], "packaged", "{nokogiri}");
        let native = nokogiri["native"].as_str().unwrap();
        assert!(
            native.ends_with(".so"),
            "not a Linux native library: {native}"
        );
        assert!(
            Path::new(native).starts_with(gems_obj.canonicalize().unwrap()),
            "nokogiri loaded outside the committed gem object: {native}"
        );
        assert_no_forbidden_prefix(native, &staging, "nokogiri native library");
        // Its vendored libxml2 may link zlib or liblzma from the native
        // library set the build mounted; nothing from the host.
        let libset = find_object(&store, "native-libs").map(|(set, _)| set.canonicalize().unwrap());
        assert_elf_resolves_from(Path::new(native), &staging, libset.as_deref());
    }
    // Without its lock the project is refused under --frozen and left
    // alone; a plan regenerates the lock with the store bundler.
    assert_frozen_never_writes_the_lock(&project, &temp.0, "Gemfile.lock");
}

/// Linux project whose only gem is the source `zlib` gem. Its extension
/// needs `zlib.h` and `libz.so`, which the C-runtime-only view hides, and it
/// bundles no zlib source of its own.
#[cfg(target_os = "linux")]
fn zlib_project_files(project: &Path) {
    std::fs::write(
        project.join("Gemfile"),
        r#"source "https://rubygems.org"

gem "zlib", "3.2.3"
"#,
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    zlib (3.2.3)

PLATFORMS
  ruby

DEPENDENCIES
  zlib (= 3.2.3)

BUNDLED WITH
   2.6.9
"#,
    )
    .unwrap();
}

/// A gem that needs a library ward pins builds against ward's native library
/// set, never the host's: the C-runtime-only view hides the host's zlib,
/// the set's is mounted, and the extension's RUNPATH names the set, so it
/// loads the store's libz at run time (issue #329). Nothing falls back to
/// the whole host. The next sync finds the object from the store alone:
/// with the `.gem` gone from the artifact cache and the network cut, a
/// rebuild could not even start, and the gem's native classification,
/// recorded on the first sync, names the set without the gemspec.
#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn ruby_gem_needing_a_pinned_library_builds_against_the_native_libs() {
    const ZLIB_SHA256: &str = "5bd316698b32f31a64ab910a8b6c282442ca1626a81bbd6a1674e8522e319c20";
    let temp = TempDir::new("ruby-e2e-native-libs");
    let project = temp.0.join("ruby-zlib");
    std::fs::create_dir_all(&project).unwrap();
    zlib_project_files(&project);
    let store = temp.0.join("store");

    assert_ok(ward(&project, &temp.0, &["sync"]), "sync");
    let (gems_obj, gems_meta) = find_object(&store, "ruby-gems").expect("gems object published");
    assert_immutable_tree(&gems_obj);
    let inputs = gems_meta["identity"]["inputs"].as_object().unwrap();
    assert_eq!(
        inputs["gem:zlib-3.2.3"].as_str(),
        Some(ZLIB_SHA256),
        "{inputs:?}"
    );
    assert_eq!(
        inputs["build_view"].as_str(),
        Some("runtime-only/3"),
        "{inputs:?}"
    );
    assert_eq!(inputs["native"].as_str(), Some("native-libs"), "{inputs:?}");
    let (libset, _) = find_object(&store, "native-libs").expect("native library set realized");
    assert_eq!(
        inputs["native_libs"].as_str(),
        libset.file_name().unwrap().to_str(),
        "{inputs:?}"
    );
    let exceptions = gems_meta["exceptions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !exceptions
            .iter()
            .any(|exception| exception["kind"] == "host-build-inputs"),
        "zlib was rebuilt against the whole host: {exceptions:?}"
    );
    // The extension links libz and finds it in the set.
    let mut extensions = Vec::new();
    collect_files(&gems_obj.join("extensions"), "/zlib.so", &mut extensions);
    assert_eq!(extensions.len(), 1, "{extensions:?}");
    let dynamic = tool("readelf", &["-dW"], &extensions[0]);
    assert!(dynamic.contains("[libz.so.1]"), "{dynamic}");
    let libset = libset.canonicalize().unwrap();
    let lib = libset.join("lib");
    assert!(
        dynamic.contains(&lib.display().to_string()),
        "the extension's RUNPATH does not name the set's lib ({}): {dynamic}",
        lib.display()
    );
    // And the loader resolves libz there, not from the host.
    assert_elf_resolves_from(&extensions[0], &store.join("tmp"), Some(&libset));
    let closure = |project: &Path| -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(project.join(".greyward/closures/ruby.json")).unwrap(),
        )
        .unwrap()
    };
    let before = closure(&project);
    assert_eq!(
        before["body"]["native_libs"]["id"].as_str(),
        libset.file_name().unwrap().to_str(),
        "the closure does not keep the set live: {before}"
    );

    let cached = store.join("cache/sha256").join(ZLIB_SHA256);
    assert!(cached.exists(), "the zlib gem is not in the artifact cache");
    greyward::kernel::store::remove_tree(&cached)
        .or_else(|_| std::fs::remove_file(&cached))
        .unwrap();
    let second = assert_ok(
        ward_offline(&project, &temp.0, &["sync"]),
        "offline re-sync over the native-libs object",
    );
    eprintln!("second sync: {second}");
    let after = closure(&project);
    assert_eq!(
        after["body"]["gems_object"], before["body"]["gems_object"],
        "the re-sync projected a different gems object"
    );
    assert_eq!(
        after["body"]["gems_object"]["id"], gems_meta["id"],
        "{after}"
    );
}

/// Linux project whose only gem is the source `gdbm` gem. Its `extconf.rb`
/// needs `gdbm.h` and `libgdbm`, which neither the C runtime nor ward's
/// native library set has, so its build against the C runtime alone fails
/// whatever the host has installed.
#[cfg(target_os = "linux")]
fn gdbm_project_files(project: &Path) {
    std::fs::write(
        project.join("Gemfile"),
        r#"source "https://rubygems.org"

gem "gdbm", "2.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    gdbm (2.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  gdbm (= 2.1.0)

BUNDLED WITH
   2.6.9
"#,
    )
    .unwrap();
}

/// A stand-in for the host's `gdbm-devel` package: what the gem's
/// `extconf.rb` probes (`gdbm_open` in `libgdbm`, `gdbm.h`) and what its
/// `gdbm.c` compiles against. The functions are declared, never run.
#[cfg(target_os = "linux")]
const STUB_GDBM_H: &str = r#"
#ifndef GREYWARD_STUB_GDBM_H
#define GREYWARD_STUB_GDBM_H
typedef struct { char *dptr; int dsize; } datum;
typedef struct gdbm_file_info *GDBM_FILE;
#define GDBM_READER 0
#define GDBM_WRITER 1
#define GDBM_WRCREAT 2
#define GDBM_NEWDB 3
#define GDBM_FAST 0x010
#define GDBM_SYNC 0x020
#define GDBM_NOLOCK 0x040
#define GDBM_CLOEXEC 0x100
#define GDBM_INSERT 0
#define GDBM_REPLACE 1
#define GDBM_CACHESIZE 1
#define GDBM_FASTMODE 2
#define GDBM_SYNCMODE 3
#define GDBM_FILE_OPEN_ERROR 3
#define GDBM_CANT_BE_READER 9
#define GDBM_CANT_BE_WRITER 10
extern int gdbm_errno;
extern const char *gdbm_version;
GDBM_FILE gdbm_open(const char *, int, int, int, void (*)(const char *));
void gdbm_close(GDBM_FILE);
int gdbm_store(GDBM_FILE, datum, datum, int);
datum gdbm_fetch(GDBM_FILE, datum);
int gdbm_delete(GDBM_FILE, datum);
datum gdbm_firstkey(GDBM_FILE);
datum gdbm_nextkey(GDBM_FILE, datum);
int gdbm_reorganize(GDBM_FILE);
void gdbm_sync(GDBM_FILE);
int gdbm_exists(GDBM_FILE, datum);
int gdbm_setopt(GDBM_FILE, int, void *, int);
int gdbm_fdesc(GDBM_FILE);
const char *gdbm_strerror(int);
#endif
"#;

/// The one symbol `have_library("gdbm", "gdbm_open")` links against.
#[cfg(target_os = "linux")]
const STUB_LIBGDBM_C: &str = r#"
#include <gdbm.h>
int gdbm_errno;
const char *gdbm_version = "ward stub";
GDBM_FILE gdbm_open(const char *name, int block, int flags, int mode, void (*fatal)(const char *)) {
    (void)name; (void)block; (void)flags; (void)mode; (void)fatal;
    return 0;
}
"#;

/// A directory laid out like a host root with the stub `gdbm-devel` in it,
/// for `GREYWARD_TEST_HOST_DEV_FILES` (`hostview::test_host_dev_files`): the
/// header under `usr/include`, `libgdbm.so` under `usr/lib`, built with the
/// host's gcc, with the real library's soname so the extension's NEEDED
/// entry reads the same on a host that has `libgdbm-dev` installed.
#[cfg(target_os = "linux")]
fn stub_host_dev_files(dev: &Path) {
    let include = dev.join("usr/include");
    let lib = dev.join("usr/lib");
    std::fs::create_dir_all(&include).unwrap();
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(include.join("gdbm.h"), STUB_GDBM_H).unwrap();
    let source = dev.join("libgdbm.c");
    std::fs::write(&source, STUB_LIBGDBM_C).unwrap();
    let output = Command::new("gcc")
        .args(["-shared", "-fPIC", "-Wl,-soname,libgdbm.so.6", "-I"])
        .arg(&include)
        .arg("-o")
        .arg(lib.join("libgdbm.so"))
        .arg(&source)
        .output()
        .unwrap();
    assert_ok(output, "gcc builds the stub libgdbm");
}

/// A gem that needs a development package the C runtime and ward's native
/// library set lack still installs: its hermetic build fails, what that
/// attempt left in the shared GEM_HOME is discarded, it is rebuilt against
/// the whole host, and the object is committed under its own
/// `host-fallback/1` identity with a `host-build-inputs` exception naming
/// the gem (issue #304). The next sync on the unchanged host reaches that
/// object through the store record instead of building again.
///
/// The development package is a stand-in a debug build reads from
/// `GREYWARD_TEST_HOST_DEV_FILES` (`stub_host_dev_files`): no rubygems.org gem
/// needs a header every host has outside glibc and the set, and the Ruby
/// tailor admits no other gem source (#559).
#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn ruby_gem_needing_host_headers_falls_back_once() {
    const GDBM_SHA256: &str = "0b618465946a6e7a630b8dd3d10e30570cbc8fb8710bcb28f2db89058a7bbe77";
    let temp = TempDir::new("ruby-e2e-host-fallback");
    let project = temp.0.join("ruby-gdbm");
    std::fs::create_dir_all(&project).unwrap();
    gdbm_project_files(&project);
    let dev = temp.0.join("host-dev-files");
    stub_host_dev_files(&dev);
    let store = temp.0.join("store");

    assert_ok(
        common::ward_env(
            &project,
            &temp.0,
            &["sync"],
            &[("GREYWARD_TEST_HOST_DEV_FILES", dev.as_os_str())],
        ),
        "sync",
    );
    let (gems_obj, gems_meta) = find_object(&store, "ruby-gems").expect("gems object published");
    assert_immutable_tree(&gems_obj);
    let inputs = gems_meta["identity"]["inputs"].as_object().unwrap();
    assert_eq!(
        inputs["gem:gdbm-2.1.0"].as_str(),
        Some(GDBM_SHA256),
        "{inputs:?}"
    );
    assert_eq!(
        inputs["build_view"].as_str(),
        Some("host-fallback/1"),
        "{inputs:?}"
    );
    assert_eq!(
        inputs["host_fallback"].as_str(),
        Some("gdbm-2.1.0"),
        "{inputs:?}"
    );
    // Keyed by this host's build inputs too (`hostview::host_build_inputs`).
    assert!(
        inputs["host_inputs"]
            .as_str()
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())),
        "{inputs:?}"
    );
    assert_eq!(inputs["native"].as_str(), Some("native-libs"), "{inputs:?}");
    let exceptions = gems_meta["exceptions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        exceptions
            .iter()
            .any(|exception| exception["kind"] == "host-build-inputs"
                && exception["subject"] == "gdbm-2.1.0"),
        "no host-build-inputs exception for gdbm-2.1.0: {exceptions:?}"
    );
    // The retry started from what a clean install would leave: one gem,
    // one extension, and a build log that is the retry's, which found the
    // header the hermetic attempt could not.
    let mut extensions = Vec::new();
    collect_files(&gems_obj.join("extensions"), "/gdbm.so", &mut extensions);
    assert_eq!(extensions.len(), 1, "{extensions:?}");
    let dynamic = tool("readelf", &["-dW"], &extensions[0]);
    assert!(dynamic.contains("[libgdbm.so.6]"), "{dynamic}");
    let mut logs = Vec::new();
    collect_files(&gems_obj.join("extensions"), "/mkmf.log", &mut logs);
    assert_eq!(logs.len(), 1, "{logs:?}");
    let log = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(
        log.contains("have_header: checking for gdbm.h... -------------------- yes"),
        "{log}"
    );
    let gems: Vec<String> = std::fs::read_dir(gems_obj.join("gems"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(gems, ["gdbm-2.1.0"]);
    let records = store.join("records/ruby-gems-host-fallback");
    assert_eq!(
        std::fs::read_dir(&records).unwrap().count(),
        1,
        "the fallback was not recorded"
    );

    // The next sync reaches the fallback object through the record, never
    // by building again: with the `.gem` gone from the artifact cache and
    // the network cut, a rebuild could not even start. The stand-in
    // development package stays as it was, and named: it is part of the
    // host's fingerprint, so the record is found only for the same host.
    let closure = |project: &Path| -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(project.join(".greyward/closures/ruby.json")).unwrap(),
        )
        .unwrap()
    };
    let before = closure(&project);
    let cached = store.join("cache/sha256").join(GDBM_SHA256);
    assert!(cached.exists(), "the gdbm gem is not in the artifact cache");
    greyward::kernel::store::remove_tree(&cached)
        .or_else(|_| std::fs::remove_file(&cached))
        .unwrap();
    let second = assert_ok(
        common::offline_command(&project, &temp.0, &store)
            .env("GREYWARD_TEST_HOST_DEV_FILES", &dev)
            .arg("sync")
            .output()
            .expect("spawn ward without network"),
        "offline re-sync over the fallback object",
    );
    eprintln!("second sync: {second}");
    let after = closure(&project);
    assert_eq!(
        after["body"]["gems_object"], before["body"]["gems_object"],
        "the re-sync projected a different gems object"
    );
    assert_eq!(
        after["body"]["gems_object"]["id"], gems_meta["id"],
        "{after}"
    );
}

/// Write `files` (relative path, contents) under `root`.
fn write_tree(root: &Path, files: &[(&str, &str)]) {
    for (relative, contents) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

fn git(args: &[&str], cwd: &Path) -> String {
    let out = Command::new("/usr/bin/git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository holding a gem with a C extension and an executable, a
/// second gem under `sub/`, and under `dup/` a third whose executable has
/// the first's name, committed once; returns its `file://` URL and the
/// commit. Each gemspec lists its files with `git ls-files` and derives
/// its executables from them, as `bundle gem` writes one.
fn git_gem_repo(root: &Path) -> (String, String) {
    let repo = root.join("gitgem-repo");
    write_tree(
        &repo,
        &[
            (
                "gitgem.gemspec",
                r#"Gem::Specification.new do |s|
  s.name = "gitgem"
  s.version = "0.1.0"
  s.summary = "fixture"
  s.authors = ["t"]
  s.files = `git ls-files -z`.split("\x0").reject { |f| f.start_with?("sub/", "dup/") }
  s.bindir = "exe"
  s.executables = s.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  s.extensions = ["ext/gitnative/extconf.rb"]
  s.require_paths = ["lib"]
end
"#,
            ),
            (
                "sub/subgem.gemspec",
                r#"Gem::Specification.new do |s|
  s.name = "subgem"
  s.version = "0.3.0"
  s.summary = "fixture"
  s.authors = ["t"]
  s.files = `git ls-files -z`.split("\x0")
  s.bindir = "exe"
  s.executables = s.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  s.require_paths = ["lib"]
end
"#,
            ),
            (
                "sub/lib/subgem.rb",
                "module Subgem\n  def self.hello\n    \"from-sub\"\n  end\nend\n",
            ),
            (
                "sub/exe/subgem",
                "#!/usr/bin/env ruby\nrequire \"subgem\"\nputs Subgem.hello\n",
            ),
            (
                "dup/dupgem.gemspec",
                r#"Gem::Specification.new do |s|
  s.name = "dupgem"
  s.version = "0.4.0"
  s.summary = "fixture"
  s.authors = ["t"]
  s.files = `git ls-files -z`.split("\x0")
  s.bindir = "exe"
  s.executables = s.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  s.require_paths = ["lib"]
end
"#,
            ),
            ("dup/lib/dupgem.rb", "module Dupgem; end\n"),
            ("dup/exe/gitgem", "#!/usr/bin/env ruby\nputs \"impostor\"\n"),
            (
                "lib/gitgem.rb",
                "require \"gitnative\"\n\nmodule Gitgem\n  def self.hello\n    \"from-git #{Gitnative.answer}\"\n  end\nend\n",
            ),
            (
                "ext/gitnative/extconf.rb",
                "require \"mkmf\"\ncreate_makefile(\"gitnative\")\n",
            ),
            (
                "ext/gitnative/gitnative.c",
                "#include <ruby.h>\n\nstatic VALUE answer(VALUE self) { return INT2FIX(42); }\n\n\
                 void Init_gitnative(void) {\n  VALUE m = rb_define_module(\"Gitnative\");\n  \
                 rb_define_singleton_method(m, \"answer\", answer, 0);\n}\n",
            ),
            (
                "exe/gitgem",
                "#!/usr/bin/env ruby\nrequire \"gitgem\"\nputs Gitgem.hello\n",
            ),
        ],
    );
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["add", "-A"], &repo);
    git(
        &[
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "one",
        ],
        &repo,
    );
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("file://{}", repo.display()), commit)
}

/// A project whose Gemfile has `gemspec` (its own gem, a `PATH` section
/// at `.`), a `path:` gem in a subdirectory, and a `git:` gem with a C
/// extension, with no rubygems.org gem at all.
fn path_and_git_project(project: &Path, url: &str, commit: &str) {
    write_tree(
        project,
        &[
            (
                "app.gemspec",
                r#"Gem::Specification.new do |s|
  s.name = "app"
  s.version = "1.0.0"
  s.summary = "fixture"
  s.authors = ["t"]
  s.files = ["lib/app.rb"]
  s.require_paths = ["lib"]
end
"#,
            ),
            (
                "lib/app.rb",
                "module App\n  def self.hello\n    \"from-app\"\n  end\nend\n",
            ),
            (
                "localgem/localgem.gemspec",
                r#"Gem::Specification.new do |s|
  s.name = "localgem"
  s.version = "0.2.0"
  s.summary = "fixture"
  s.authors = ["t"]
  s.files = ["lib/localgem.rb"]
  s.require_paths = ["lib"]
end
"#,
            ),
            (
                "localgem/lib/localgem.rb",
                "module Localgem\n  def self.hello\n    \"from-path\"\n  end\nend\n",
            ),
            (
                "check.rb",
                "require \"app\"\nrequire \"localgem\"\nrequire \"gitgem\"\nrequire \"subgem\"\n\
                 puts [App.hello, Localgem.hello, Gitgem.hello, Subgem.hello].join(\" \")\n",
            ),
        ],
    );
    // Two `GIT` sections of one repository at one commit, the second with
    // a glob: Bundler reads both from one checkout directory.
    std::fs::write(
        project.join("Gemfile"),
        format!(
            "source \"https://rubygems.org\"\n\ngemspec\n\ngem \"localgem\", path: \"localgem\"\n\
             gem \"gitgem\", git: \"{url}\"\n\
             gem \"subgem\", git: \"{url}\", glob: \"sub/*.gemspec\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        format!(
            "GIT\n  remote: {url}\n  revision: {commit}\n  specs:\n    gitgem (0.1.0)\n\n\
             GIT\n  remote: {url}\n  revision: {commit}\n  glob: sub/*.gemspec\n  specs:\n    \
             subgem (0.3.0)\n\n\
             PATH\n  remote: .\n  specs:\n    app (1.0.0)\n\n\
             PATH\n  remote: localgem\n  specs:\n    localgem (0.2.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
             PLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  app!\n  gitgem!\n  localgem!\n  subgem!\n\n\
             BUNDLED WITH\n   2.6.9\n"
        ),
    )
    .unwrap();
}

/// A project taking `gitgem` and `dupgem` from one repository: both
/// provide an executable named `gitgem`.
fn executable_clash_project(project: &Path, url: &str, commit: &str) {
    std::fs::create_dir_all(project).unwrap();
    std::fs::write(
        project.join("Gemfile"),
        format!(
            "source \"https://rubygems.org\"\n\ngem \"gitgem\", git: \"{url}\"\n\
             gem \"dupgem\", git: \"{url}\", glob: \"dup/*.gemspec\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        format!(
            "GIT\n  remote: {url}\n  revision: {commit}\n  specs:\n    gitgem (0.1.0)\n\n\
             GIT\n  remote: {url}\n  revision: {commit}\n  glob: dup/*.gemspec\n  specs:\n    \
             dupgem (0.4.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
             PLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  dupgem!\n  gitgem!\n\n\
             BUNDLED WITH\n   2.6.9\n"
        ),
    )
    .unwrap();
}

/// Gemfile.lock `PATH` and `GIT` sources (issue #771). The project's own
/// gem and a `path:` gem inside it are recorded in the closure and loaded
/// from the project; the git gem is fetched at its locked commit, recorded
/// as `git-dependency`, placed where Bundler reads it, and its C extension
/// is built by Bundler's own installer in the sandbox. A policy denying
/// `git-dependency` refuses the sync, and a `path:` gem outside the
/// project is refused.
#[test]
#[ignore]
fn ruby_path_and_git_sources_sync_and_run() {
    let temp = TempDir::new("ruby-e2e-path-git");
    let (url, commit) = git_gem_repo(&temp.0);
    let project = temp.0.join("app");
    std::fs::create_dir_all(&project).unwrap();
    path_and_git_project(&project, &url, &commit);
    let store = temp.0.join("store");

    // A policy that denies git dependencies stops the sync before the
    // fetch: no gems object is built.
    std::fs::create_dir_all(project.join(".greyward")).unwrap();
    std::fs::write(
        project.join(".greyward/policy.toml"),
        "deny = [\"git-dependency\"]\n",
    )
    .unwrap();
    let denied = ward(&project, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert_eq!(denied.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("git-dependency"), "{stderr}");
    assert!(find_object(&store, "ruby-gems").is_none(), "{stderr}");
    std::fs::remove_file(project.join(".greyward/policy.toml")).unwrap();

    let out = ward(&project, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "sync failed: {stderr}");
    assert!(
        stderr.contains(&format!(
            "exception git-dependency: gitgem: {url} at {commit}"
        )),
        "{stderr}"
    );
    let closure: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".greyward/closures/ruby.json")).unwrap(),
    )
    .unwrap();
    let plan = &closure["body"]["plan"];
    assert_eq!(plan["gems"], serde_json::json!([]), "{plan}");
    assert_eq!(
        plan["path_gems"],
        serde_json::json!([
            {"name": "app", "version": "1.0.0", "path": "."},
            {"name": "localgem", "version": "0.2.0", "path": "localgem"},
        ]),
        "{plan}"
    );
    let short = &commit[..12];
    let checkout_name = format!("gitgem-repo-{short}");
    assert_eq!(
        plan["git_gems"],
        serde_json::json!([
            {
                "name": "gitgem", "version": "0.1.0", "url": url, "revision": commit,
                "checkout": checkout_name,
            },
            {
                "name": "subgem", "version": "0.3.0", "url": url, "revision": commit,
                "checkout": checkout_name, "glob": "sub/*.gemspec",
            },
        ]),
        "{plan}"
    );

    let (gems_obj, gems_meta) = find_object(&store, "ruby-gems").expect("gems object published");
    assert_immutable_tree(&gems_obj);
    let inputs = gems_meta["identity"]["inputs"].as_object().unwrap();
    // One checkout directory, one input, naming both lock sections.
    let git_input: serde_json::Value = serde_json::from_str(
        inputs[&format!("git:{checkout_name}")]
            .as_str()
            .unwrap_or_else(|| panic!("{inputs:?}")),
    )
    .unwrap();
    assert_eq!(
        git_input,
        serde_json::json!([
            commit,
            [
                [url, "", ["gitgem:0.1.0"]],
                [url, "sub/*.gemspec", ["subgem:0.3.0"]],
            ]
        ]),
    );
    // The checkout is where Bundler reads it. The repository ward made so
    // `git ls-files` answers the gemspecs is gone, and Bundler kept no git
    // cache.
    let checkout = gems_obj.join(format!("bundler/gems/{checkout_name}"));
    assert!(checkout.join("gitgem.gemspec").is_file());
    assert!(!checkout.join(".git").exists());
    assert!(!gems_obj.join("cache/bundler/git").exists());
    // Bundler serialized each gemspec as evaluated: the file lists `git
    // ls-files` gave are in them, and so are the executables derived from
    // those lists, with their wrappers in the bin dir.
    let serialized = std::fs::read_to_string(checkout.join("gitgem.gemspec")).unwrap();
    assert!(serialized.contains("\"exe/gitgem\""), "{serialized}");
    assert!(serialized.contains("\"lib/gitgem.rb\""), "{serialized}");
    let serialized = std::fs::read_to_string(checkout.join("sub/subgem.gemspec")).unwrap();
    assert!(serialized.contains("\"exe/subgem\""), "{serialized}");
    assert!(gems_obj.join("bin/gitgem").is_file());
    assert!(gems_obj.join("bin/subgem").is_file());
    let mut extensions = Vec::new();
    collect_files(
        &gems_obj.join("bundler/gems/extensions"),
        "/gitnative.so",
        &mut extensions,
    );
    assert_eq!(extensions.len(), 1, "{extensions:?}");

    let run = assert_ok(
        ward(
            &project,
            &temp.0,
            &["run", "bundle", "exec", "ruby", "check.rb"],
        ),
        "bundle exec over path and git gems",
    );
    assert!(
        run.contains("from-app from-path from-git 42 from-sub"),
        "{run}"
    );
    let exe = assert_ok(
        ward(&project, &temp.0, &["run", "bundle", "exec", "gitgem"]),
        "the git gem's executable",
    );
    assert!(exe.contains("from-git 42"), "{exe}");
    let exe = assert_ok(
        ward(&project, &temp.0, &["run", "bundle", "exec", "subgem"]),
        "the globbed git gem's executable",
    );
    assert!(exe.contains("from-sub"), "{exe}");

    // The next sync answers from the store: same object, no rebuild.
    assert_ok(ward(&project, &temp.0, &["sync"]), "re-sync");
    let again: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".greyward/closures/ruby.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(again["body"]["gems_object"]["id"], gems_meta["id"]);

    // A `path:` gem outside the project is refused, naming it.
    let outside = temp.0.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(
        outside.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"localgem\", path: \"../app/localgem\"\n",
    )
    .unwrap();
    std::fs::write(
        outside.join("Gemfile.lock"),
        "PATH\n  remote: ../app/localgem\n  specs:\n    localgem (0.2.0)\n\n\
         GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  localgem!\n\nBUNDLED WITH\n   2.6.9\n",
    )
    .unwrap();
    let refused = ward(&outside, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{stderr}");
    assert!(
        stderr.contains("\"../app/localgem\", which is outside the project"),
        "{stderr}"
    );

    // Two git gems providing one executable are refused, as two
    // rubygems.org gems are.
    let clash = temp.0.join("clash");
    executable_clash_project(&clash, &url, &commit);
    let refused = ward(&clash, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{stderr}");
    assert!(
        stderr.contains("executable \"gitgem\" provided by both gitgem and dupgem")
            || stderr.contains("executable \"gitgem\" provided by both dupgem and gitgem"),
        "{stderr}"
    );
}

/// A project with no gems whose lock names `bundled_with`, and the lock's
/// CHECKSUMS entry for that Bundler when `checksum` is given.
fn bundled_with_project(project: &Path, bundled_with: &str, pins: Option<(&str, &str)>) {
    std::fs::create_dir_all(project).unwrap();
    let Some((bundler_sha, gem_sha)) = pins else {
        std::fs::write(project.join("Gemfile"), "source \"https://rubygems.org\"\n").unwrap();
        std::fs::write(
            project.join("Gemfile.lock"),
            format!(
                "GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   {bundled_with}\n"
            ),
        )
        .unwrap();
        return;
    };
    // One gem, pinned by the lock's CHECKSUMS section beside the Bundler.
    std::fs::write(
        project.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"wardtiny\"\n",
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    wardtiny (1.0.0)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  wardtiny\n\n\
             CHECKSUMS\n  bundler ({bundled_with}) sha256={bundler_sha}\n  \
             wardtiny (1.0.0) sha256={gem_sha}\n\n\
             BUNDLED WITH\n   {bundled_with}\n"
        ),
    )
    .unwrap();
}

/// A one-file pure-Ruby gem, `wardtiny-1.0.0.gem`, built in `dir`.
fn tiny_gem(ruby: &Path, dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::write(
        dir.join("lib/wardtiny.rb"),
        "module Wardtiny\n  SAID = \"from-tiny\"\nend\n",
    )
    .unwrap();
    let script = r#"require "rubygems/package"
spec = Gem::Specification.new do |s|
  s.name = "wardtiny"
  s.version = "1.0.0"
  s.summary = "A gem made for a test"
  s.authors = ["ward"]
  s.license = "MIT"
  s.files = ["lib/wardtiny.rb"]
end
puts Gem::Package.build(spec)
"#;
    pinned_ruby(ruby, dir, script, "build the tiny gem");
    dir.join("wardtiny-1.0.0.gem")
}

/// Build `bundler-<version>.gem` in `dir` from the store Ruby's own
/// Bundler with only its version changed: a Bundler release newer than the
/// one the Ruby ships, made locally so the test needs no live RubyGems.
fn bumped_bundler_gem(ruby: &Path, dir: &Path, version: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let script = format!(
        r#"require "fileutils"
require "rubygems/package"
shipped = Gem::Specification.find_by_name("bundler")
lib = RbConfig::CONFIG["rubylibdir"]
FileUtils.mkdir_p("lib")
FileUtils.cp(File.join(lib, "bundler.rb"), "lib")
FileUtils.cp_r(File.join(lib, "bundler"), "lib")
FileUtils.cp_r(File.join(shipped.full_gem_path, "exe"), ".")
# The store's files are read-only, and so are their copies.
FileUtils.chmod_R("u+w", %w[lib exe])
file = "lib/bundler/version.rb"
File.write(file, File.read(file).sub(/VERSION = "[^"]+"/, 'VERSION = "{version}"'))
spec = Gem::Specification.new do |s|
  s.name = "bundler"
  s.version = "{version}"
  s.summary = "Bundler, version-bumped for a test"
  s.authors = ["ward"]
  s.license = "MIT"
  s.files = Dir["lib/**/*", "exe/*"]
  s.bindir = "exe"
  s.executables = %w[bundle bundler]
  s.required_ruby_version = ">= 3.1.0"
end
puts Gem::Package.build(spec)
"#
    );
    pinned_ruby(ruby, dir, &script, "build the bumped bundler gem");
    let gem = dir.join(format!("bundler-{version}.gem"));
    assert!(gem.is_file(), "{}", gem.display());
    gem
}

/// A lock written by a Bundler newer than the store Ruby's is planned and
/// installed with that exact Bundler: ward provisions the release the lock
/// names, checked against the lock's CHECKSUMS entry, as its own object,
/// and `bundle` in the project is that release. A lock no newer than the
/// shipped Bundler provisions nothing. The newer release is built from the
/// shipped one and seeded into the verified cache, so the sync that uses
/// it runs with the network cut.
#[test]
#[ignore]
fn ruby_lock_bundled_with_a_newer_bundler_syncs_with_it() {
    let temp = TempDir::new("ruby-e2e-bundler");
    let store = temp.0.join("store");

    // A lock no newer than the Ruby's own Bundler: nothing provisioned.
    let older = temp.0.join("older");
    bundled_with_project(&older, "2.6.9", None);
    assert_ok(
        ward(&older, &temp.0, &["sync"]),
        "sync with the shipped bundler",
    );
    let closure: serde_json::Value =
        serde_json::from_slice(&std::fs::read(older.join(".greyward/closures/ruby.json")).unwrap())
            .unwrap();
    assert!(
        closure["body"]["plan"].get("bundler").is_none(),
        "{closure}"
    );
    assert!(find_object(&store, "ruby-bundler").is_none());

    let version = "2.99.0";
    let (ruby, _) = find_object(&store, "ruby").expect("ruby object published");
    let gem = bumped_bundler_gem(&ruby, &temp.0.join("bundler-src"), version);
    let opened = greyward::kernel::store::Store::open_at(&store).unwrap();
    let activity = opened
        .activity(greyward::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let (sha256, _) = greyward::kernel::fetch::cache_insert(&opened, &activity, &gem).unwrap();
    let tiny = tiny_gem(&ruby, &temp.0.join("tiny-src"));
    let (tiny_sha, _) = greyward::kernel::fetch::cache_insert(&opened, &activity, &tiny).unwrap();
    drop(activity);

    let newer = temp.0.join("newer");
    bundled_with_project(&newer, version, Some((&sha256, &tiny_sha)));
    // Under the policy, the ordinary gem's checksum is insufficient:
    // Bundler's artifact needs its own pin. Follow the documented repair
    // by adding its verified SHA-256 under CHECKSUMS, without a Gemfile
    // dependency on Bundler.
    let lock = std::fs::read_to_string(newer.join("Gemfile.lock")).unwrap();
    let bundler_entry = format!("  bundler ({version}) sha256={sha256}\n");
    std::fs::write(newer.join("Gemfile.lock"), lock.replace(&bundler_entry, "")).unwrap();
    std::fs::create_dir_all(newer.join(".greyward")).unwrap();
    std::fs::write(
        newer.join(".greyward/policy.toml"),
        "deny = [\"unpinned-digest\"]\n",
    )
    .unwrap();
    let denied = ward_offline(&newer, &temp.0, &["sync"]);
    let error = String::from_utf8_lossy(&denied.stderr);
    assert_eq!(denied.status.code(), Some(3), "{error}");
    assert!(error.contains("bundler-2.99.0"), "{error}");
    assert!(error.contains("verified gem SHA-256"), "{error}");
    std::fs::write(newer.join("Gemfile.lock"), lock).unwrap();
    let out = ward_offline(&newer, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "sync failed: {stderr}");
    let closure: serde_json::Value =
        serde_json::from_slice(&std::fs::read(newer.join(".greyward/closures/ruby.json")).unwrap())
            .unwrap();
    assert_eq!(
        closure["body"]["plan"]["bundler"],
        serde_json::json!({"version": version, "sha256": sha256}),
        "{closure}"
    );
    // The gem's digest is the lock's CHECKSUMS entry, read by that Bundler.
    let gems = closure["body"]["plan"]["gems"].as_array().unwrap();
    assert_eq!(gems.len(), 1, "{closure}");
    assert_eq!(gems[0]["sha256"], serde_json::json!(tiny_sha), "{closure}");
    let (bundler_obj, meta) = find_object(&store, "ruby-bundler").expect("bundler object");
    assert_immutable_tree(&bundler_obj);
    let inputs = &meta["identity"]["inputs"];
    assert_eq!(inputs["gem_sha256"], serde_json::json!(sha256), "{meta}");
    assert_eq!(
        meta["identity"]["version"],
        serde_json::json!(version),
        "{meta}"
    );
    // The older project's gems object is in the store too: read this one's.
    let gems_id = closure["body"]["gems_object"]["id"].as_str().unwrap();
    let gems_meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(store.join("meta").join(format!("{gems_id}.json"))).unwrap(),
    )
    .unwrap();
    assert!(
        gems_meta["identity"]["inputs"]["bundler"]
            .as_str()
            .is_some_and(|input| input.contains(&sha256)),
        "{gems_meta}"
    );

    let shown = assert_ok(
        ward_offline(&newer, &temp.0, &["run", "bundle", "-v"]),
        "bundle -v in the project",
    );
    assert!(shown.contains(version), "{shown}");
    let said = assert_ok(
        ward_offline(
            &newer,
            &temp.0,
            &[
                "run",
                "bundle",
                "exec",
                "ruby",
                "-e",
                "require 'wardtiny'; puts Wardtiny::SAID",
            ],
        ),
        "bundle exec with the locked Bundler",
    );
    assert!(said.contains("from-tiny"), "{said}");
}

/// A project with no lock whose gemspec lists its files with `git ls-files`
/// (as most do) resolves: Bundler evaluates the gemspec in ward's copy of
/// the project, which has no git data, so ward indexes the copy for the run
/// and removes the index after it. The gemspec refuses an empty list, so a
/// run without the index fails. Nothing of the index reaches the project.
#[test]
#[ignore]
fn ruby_lock_generation_answers_a_gemspecs_git_ls_files() {
    let temp = TempDir::new("ruby-e2e-indexed");
    let project = temp.0.join("app");
    write_tree(
        &project,
        &[
            (
                "Gemfile",
                "source \"https://rubygems.org\"\n\ngemspec\ngem \"rake\", \"13.4.2\"\n",
            ),
            (
                "app.gemspec",
                r#"Gem::Specification.new do |s|
  s.name = "app"
  s.version = "1.0.0"
  s.summary = "A project whose gemspec asks git for its files"
  s.authors = ["ward"]
  s.files = `git ls-files -z`.split("\x0")
  raise "git ls-files listed nothing" unless s.files.include?("lib/app.rb")
end
"#,
            ),
            ("lib/app.rb", "module App; end\n"),
        ],
    );
    let out = ward(&project, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "sync failed: {stderr}");
    assert!(!stderr.contains("not a git repository"), "{stderr}");
    let lock = std::fs::read_to_string(project.join("Gemfile.lock")).unwrap();
    assert!(lock.contains("    app (1.0.0)"), "{lock}");
    assert!(!project.join(".git").exists());
    let removed = ward(&project, &temp.0, &["remove", "rake"]);
    let stderr = String::from_utf8_lossy(&removed.stderr);
    assert!(removed.status.success(), "remove failed: {stderr}");
    assert!(!stderr.contains("not a git repository"), "{stderr}");
    let lock = std::fs::read_to_string(project.join("Gemfile.lock")).unwrap();
    assert!(!lock.contains("rake"), "{lock}");
    assert!(lock.contains("    app (1.0.0)"), "{lock}");
    assert!(!project.join(".git").exists());
}

/// A missing lock makes Bundler itself clone the Git dependency through
/// the confined resolver. The proxy records that fetch and enforces the
/// policy before serving it, then ward installs the locked checkout.
#[test]
#[ignore]
fn ruby_missing_lock_resolves_a_git_source_through_the_proxy() {
    let temp = TempDir::new("ruby-e2e-git-lock");
    let project = temp.0.join("app");
    let revision = "0fdacef47aa9a4140e472b0ce302a2dd09423a75";
    let remote = "https://github.com/ruby/rake.git";
    std::fs::create_dir_all(project.join(".greyward")).unwrap();
    std::fs::write(
        project.join("Gemfile"),
        format!(
            "source \"https://rubygems.org\"\ngem \"rake\", git: \"{remote}\", ref: \"{revision}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        project.join(".greyward/policy.toml"),
        "deny = [\"git-dependency\"]\n",
    )
    .unwrap();
    let denied = ward(&project, &temp.0, &["sync"]);
    let error = String::from_utf8_lossy(&denied.stderr);
    assert!(!denied.status.success(), "{error}");
    assert!(error.contains("git-dependency"), "{error}");
    assert!(!project.join("Gemfile.lock").exists());
    std::fs::remove_file(project.join(".greyward/policy.toml")).unwrap();

    let out = ward(&project, &temp.0, &["sync"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "sync failed: {stderr}");
    assert!(stderr.contains("git-dependency"), "{stderr}");
    let lock = std::fs::read_to_string(project.join("Gemfile.lock")).unwrap();
    assert!(lock.contains(&format!("  revision: {revision}")), "{lock}");
    assert!(lock.contains("    rake (13.3.0)"), "{lock}");
    let said = assert_ok(
        ward(
            &project,
            &temp.0,
            &["run", "bundle", "exec", "rake", "--version"],
        ),
        "the Git dependency's executable",
    );
    assert!(said.contains("rake, version 13.3.0"), "{said}");
}
