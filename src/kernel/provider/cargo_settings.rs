//! The cargo settings a project's configuration may not make, because no
//! forced `--config` of ward's undoes them
//! ([`refuse_unneutralized_settings`]). The configuration files are read by
//! [`cargo_door::config_files`](super::cargo_door::config_files) and its
//! siblings; this module judges what they say.

use super::cargo_door::ConfigFile;
use super::crates::VENDOR_SOURCE;
use crate::kernel::resolve::confine;
use std::io;
use std::path::Path;

/// The settings a project's cargo configuration may not make, because no
/// forced `--config` undoes them:
///
/// - `paths` swaps a crate the lock pins for a directory of the
///   project's choosing, with the same name and version. Cargo prints
///   nothing and leaves `Cargo.lock` as it was, so the verified vendor
///   copy would never be built. Cargo has no flag or variable that clears
///   the list.
/// - `registry.global-credential-providers`, `registry.credential-provider`,
///   `registries.<name>.credential-provider` and `[credential-alias]` name
///   programs cargo runs for a token. Ward forces each registry's own slot,
///   but a source reached through `[source.<name>] replace-with` has no
///   `[registries]` row, so cargo asks the global list, and a `--config`
///   array is appended to a config file's array rather than replacing it:
///   with ward's `cargo:token` finding no token, the project's program runs
///   next.
/// - Source replacement that leads to files the project wrote, or away
///   from ward's own vendor: `[source.greyward-vendor]` at all, or a
///   `replace-with` naming it (the build's forced
///   `crates-io -> greyward-vendor` would then follow the project's
///   definition, since a forced setting replaces only the keys it sets), a
///   `directory` or `local-registry` source, and a `replace-with` chain
///   that ends at one, in this file or another. Cargo trusts a directory
///   source's own `.cargo-checksum.json` for the package checksum the lock
///   is compared with, and its file hashes are as editable as the files,
///   so such a source can serve any code under a locked name. A chain of
///   network registries (`registry = "sparse+https://..."`, a corporate
///   mirror) stays allowed: cargo downloads each `.crate` and checks it
///   against the checksum in `Cargo.lock`.
/// - An `[alias]` whose expansion holds `--config` or `-Z`. The `ward run`
///   wrapper refuses `--config` on its command line because a later one
///   outranks ward's, but it sees only the alias name; cargo expands the
///   alias after it. `-Z` is the other way to change cargo's settings from
///   the command line (`-Z unstable-options` and the unstable config
///   flags), so it is refused with it. Other flags (`--manifest-path`,
///   `--target-dir`) change what is built or where, not which sources or
///   programs ward forces, and stay allowed.
/// - An `[env]` entry for a dynamic-loader variable (`LD_*`, `DYLD_*`):
///   cargo sets `[env]` for every program it starts, the `rustc -vV`
///   probe during resolution included, so `LD_PRELOAD` loads a project
///   library into the forced compiler. Also any variable ward forces or
///   removes for cargo ([`forced_env_names`]).
pub fn refuse_unneutralized_settings(files: &[ConfigFile]) -> io::Result<()> {
    let sources = SourceGraph::of(files);
    for file in files {
        let found = unneutralized_keys(&file.table, &sources);
        if found.is_empty() {
            continue;
        }
        return Err(crate::kernel::error::refused(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} sets {}; ward does not run cargo with a project configuration that \
                 replaces a locked crate with files the project chose (`paths`, a directory \
                 or local-registry source, a change to ward's {} source), names a \
                 credential provider, adds `--config` or `-Z` through an alias, or sets a \
                 dynamic-loader or ward-forced variable in `[env]`, since no setting of \
                 ward's can undo any of these. Remove {} (a `[patch]` table in Cargo.toml \
                 overrides a crate where the lock records it, a network registry mirror \
                 stays allowed, and credential providers belong in your own \
                 ~/.cargo/config.toml)",
                file.real.display(),
                found.join(", "),
                VENDOR_SOURCE,
                if found.len() == 1 { "it" } else { "them" },
            ),
        ));
    }
    Ok(())
}

/// The keys of one config file's `table` that [`refuse_unneutralized_settings`]
/// refuses, spelled as cargo spells them.
fn unneutralized_keys(table: &toml::Table, sources: &SourceGraph) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let section = |name: &str| table.get(name).and_then(|value| value.as_table());
    if table.contains_key("paths") {
        found.push("paths".into());
    }
    for key in ["global-credential-providers", "credential-provider"] {
        if section("registry").is_some_and(|registry| registry.contains_key(key)) {
            found.push(format!("registry.{key}"));
        }
    }
    for (name, row) in section("registries").into_iter().flatten() {
        if row
            .as_table()
            .is_some_and(|row| row.contains_key("credential-provider"))
        {
            found.push(format!("registries.{name}.credential-provider"));
        }
    }
    if table.contains_key("credential-alias") {
        found.push("credential-alias".into());
    }
    for (name, row) in section("source").into_iter().flatten() {
        if name == VENDOR_SOURCE {
            found.push(format!("source.{name}"));
            continue;
        }
        let Some(row) = row.as_table() else {
            continue;
        };
        for key in ["directory", "local-registry"] {
            if row.contains_key(key) {
                found.push(format!("source.{name}.{key}"));
            }
        }
        if let Some(target) = row.get("replace-with").and_then(|value| value.as_str()) {
            if sources.ends_at_local_files(target) {
                found.push(format!("source.{name}.replace-with"));
            }
        }
    }
    for (name, expansion) in section("alias").into_iter().flatten() {
        let words: Vec<&str> = match expansion {
            toml::Value::String(text) => text.split_whitespace().collect(),
            toml::Value::Array(items) => items.iter().filter_map(|item| item.as_str()).collect(),
            _ => Vec::new(),
        };
        if words.iter().any(|word| {
            *word == "--config" || word.starts_with("--config=") || word.starts_with("-Z")
        }) {
            found.push(format!("alias.{name}"));
        }
    }
    let forced = forced_env_names();
    for name in section("env").into_iter().flatten().map(|(name, _)| name) {
        if name.starts_with("LD_")
            || name.starts_with("DYLD_")
            || forced.iter().any(|forced| forced == name)
        {
            found.push(format!("env.{name}"));
        }
    }
    found
}

/// Every `[source.<name>]` the files define, so a `replace-with` chain can
/// be followed through files other than the one it starts in.
struct SourceGraph<'a> {
    sources: Vec<(&'a str, &'a toml::Table)>,
}

impl<'a> SourceGraph<'a> {
    fn of(files: &'a [ConfigFile]) -> Self {
        let sources = files
            .iter()
            .filter_map(|file| file.table.get("source").and_then(|value| value.as_table()))
            .flatten()
            .filter_map(|(name, row)| Some((name.as_str(), row.as_table()?)))
            .collect();
        SourceGraph { sources }
    }

    /// Whether replacing with `name` ends at ward's vendor or at files on
    /// disk (`directory`, `local-registry`), following `replace-with` as
    /// cargo does. A name defined nowhere here is not the project's to
    /// judge (cargo reports it, or it is the user's own).
    fn ends_at_local_files(&self, name: &str) -> bool {
        let mut name = name;
        let mut seen: Vec<&str> = Vec::new();
        loop {
            if name == VENDOR_SOURCE {
                return true;
            }
            if seen.contains(&name) {
                // A cycle: cargo refuses it.
                return false;
            }
            seen.push(name);
            let rows: Vec<&toml::Table> = self
                .sources
                .iter()
                .filter(|(defined, _)| *defined == name)
                .map(|(_, row)| *row)
                .collect();
            if rows
                .iter()
                .any(|row| row.contains_key("directory") || row.contains_key("local-registry"))
            {
                return true;
            }
            match rows
                .iter()
                .find_map(|row| row.get("replace-with").and_then(|value| value.as_str()))
            {
                Some(next) => name = next,
                None => return false,
            }
        }
    }
}

/// The variables ward sets or removes for cargo: the forced-settings row's
/// (its git settings included), and what the door's spec and the `ward run`
/// wrapper set. A project `[env]` entry for one would hand the programs
/// cargo starts a value ward chose otherwise.
pub fn forced_env_names() -> Vec<String> {
    let inputs = confine::ForcedInputs {
        rust: Some(Path::new("/")),
        ..confine::ForcedInputs::default()
    };
    let mut names: Vec<String> = [
        "CARGO_HOME",
        "CARGO_NET_OFFLINE",
        "PATH",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
    ]
    .map(String::from)
    .to_vec();
    if let Ok(forced) = confine::forced_settings("cargo", &inputs, &[]) {
        names.extend(
            forced
                .env
                .iter()
                .map(|(name, _)| name.to_string_lossy().into_owned()),
        );
        names.extend(forced.unset.iter().map(|name| name.to_string()));
    }
    names
}
