//! Rust nightlies: `channel = "nightly-YYYY-MM-DD"` or plain `nightly` in
//! rust-toolchain(.toml).
//!
//! The shipped catalog holds stable releases only; a nightly is published
//! every day, so it is resolved when a lock is written instead. The dated
//! channel manifest (`dist/<date>/channel-rust-nightly.toml`) is fetched,
//! its detached OpenPGP signature is checked against the Rust release key
//! checked in at `tools/keys/rust-release-signing-key.asc` (the key
//! `tools/catalog.py` checks every stable manifest with), and the release
//! bundle is read from its rows: rustc, rust-std and cargo for every
//! platform, rustfmt when every platform has it, and the manifest itself,
//! pinned by its sha256 like a stable release's. From there the lock holds
//! the answer, so later runs neither fetch the manifest again nor check the
//! signature again: the lock's digests are the pin, as for any release.
//!
//! Plain `nightly` means the newest nightly at the moment the lock is
//! written. The undated `channel-rust-nightly.toml` names its date; the
//! dated manifest of that date is what is verified and locked. It stays
//! the project's nightly until `ward update --toolchain rust` moves it.

use crate::kernel::digest::Digest;
use crate::kernel::openpgp::Keyring;
use crate::kernel::platform::Platform;
use crate::kernel::provider::rust::{
    CHANNEL_MANIFEST, CHANNEL_MANIFEST_RECIPE, RUNTIME_COMPONENTS, RUSTFMT_RECIPE, RUST_RECIPE,
};
use crate::kernel::provider::rust_channel::{Archive, ChannelManifest, DIST};
use crate::kernel::toolchain::{ArtifactRow, Bundle, Component, Version};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::io::{self, Read};

/// The Rust release signing key: the keyring a nightly manifest's
/// signature must come from.
const RUST_KEY: &str = include_str!("../../../tools/keys/rust-release-signing-key.asc");

/// The publisher every nightly row names, as the stable catalog's do.
const PUBLISHER: &str = "static.rust-lang.org";

/// The release key a nightly's lock section records: `rust-nightly-<date>`.
pub const NIGHTLY_RELEASE_PREFIX: &str = "rust-nightly-";

/// The most bytes a channel manifest may have. A nightly's is about 1 MB.
const MAX_MANIFEST: u64 = 64 << 20;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// What a nightly channel asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nightly {
    /// `nightly`: the newest one, resolved once.
    Newest,
    /// `nightly-YYYY-MM-DD`.
    Dated(String),
}

impl Nightly {
    /// `None` for a channel that is not a nightly at all. `nightly-` with
    /// anything but a calendar date after it is refused: it would become a
    /// path segment of the manifest URL.
    pub fn parse(channel: &str) -> io::Result<Option<Nightly>> {
        if channel == "nightly" {
            return Ok(Some(Nightly::Newest));
        }
        let Some(date) = channel.strip_prefix("nightly-") else {
            return Ok(None);
        };
        if !is_date(date) {
            return Err(invalid(format!(
                "rust channel {channel}: a dated nightly is nightly-YYYY-MM-DD"
            )));
        }
        Ok(Some(Nightly::Dated(date.to_string())))
    }
}

/// `YYYY-MM-DD`, with a month and day that exist on some calendar.
fn is_date(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return false;
    };
    let digits =
        |part: &str, width: usize| part.len() == width && part.bytes().all(|b| b.is_ascii_digit());
    if !digits(year, 4) || !digits(month, 2) || !digits(day, 2) {
        return false;
    }
    let (month, day): (u32, u32) = (month.parse().unwrap(), day.parse().unwrap());
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// The fields of a channel manifest [`ChannelManifest`] does not read.
#[derive(Deserialize)]
struct Header {
    date: String,
    pkg: HeaderPackages,
}

#[derive(Deserialize)]
struct HeaderPackages {
    rustc: HeaderPackage,
}

#[derive(Deserialize)]
struct HeaderPackage {
    version: String,
}

/// The bundle a lock records for the nightly `channel`, fetched and checked
/// now. `Ok(None)` when the channel is not a nightly.
pub fn select(channel: &str) -> io::Result<Option<Bundle>> {
    select_with(channel, &fetch)
}

/// [`select`] with the fetch passed in, so the tests run offline.
pub(crate) fn select_with(
    channel: &str,
    fetch: &dyn Fn(&str) -> io::Result<Vec<u8>>,
) -> io::Result<Option<Bundle>> {
    let Some(nightly) = Nightly::parse(channel)? else {
        return Ok(None);
    };
    let date = match nightly {
        Nightly::Dated(date) => date,
        Nightly::Newest => {
            let url = format!("{DIST}/channel-rust-nightly.toml");
            let text = text_of(&url, fetch(&url)?)?;
            let date = header(&url, &text)?.date;
            if !is_date(&date) {
                return Err(invalid(format!("{url} names date {date:?}")));
            }
            crate::kernel::ui::note(&format!(
                "rust channel nightly is nightly-{date} today; the lock pins that one"
            ));
            date
        }
    };
    let url = format!("{DIST}/{date}/channel-rust-nightly.toml");
    let bytes = fetch(&url).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("rust channel nightly-{date}: fetch its channel manifest: {error}"),
        )
    })?;
    let signature = text_of(&format!("{url}.asc"), fetch(&format!("{url}.asc"))?)?;
    Keyring::from_armored(RUST_KEY)?
        .verify_detached(&bytes, &signature)
        .map_err(|error| {
            invalid(format!(
                "rust channel nightly-{date}: the channel manifest at {url} fails its \
                 signature check: {error}"
            ))
        })?;
    let digest = Digest::sha256(&hex::encode(Sha256::digest(&bytes)))?;
    let text = text_of(&url, bytes)?;
    Ok(Some(bundle(&date, &url, digest, &text)?))
}

/// The fetched bytes as text: a manifest is TOML, a signature is armored.
fn text_of(url: &str, bytes: Vec<u8>) -> io::Result<String> {
    String::from_utf8(bytes).map_err(|_| invalid(format!("{url} is not UTF-8")))
}

fn header(url: &str, text: &str) -> io::Result<Header> {
    toml::from_str(text).map_err(|error| invalid(format!("{url}: {}", error.to_string().trim())))
}

/// The release bundle a verified dated manifest describes.
fn bundle(date: &str, url: &str, manifest_digest: Digest, text: &str) -> io::Result<Bundle> {
    let build = format!("nightly-{date}");
    let head = header(url, text)?;
    if head.date != date {
        return Err(invalid(format!(
            "{url} is the manifest of {}, not of {date}",
            head.date
        )));
    }
    // `1.100.0-nightly (0dfb098f3 2026-08-31)`: the release it leads up to
    // is the version selection and the object identity read. The date in
    // `build` and in the release key keeps two nightlies apart.
    let version = head
        .pkg
        .rustc
        .version
        .split(['-', ' '])
        .next()
        .unwrap_or_default()
        .to_string();
    Version::parse(&version).map_err(|_| {
        invalid(format!(
            "{url}: rustc version {:?} does not start with a release number",
            head.pkg.rustc.version
        ))
    })?;
    let manifest = ChannelManifest::parse(&build, text)?;
    let mut artifacts = Vec::new();
    let row = |platform: Platform, component: &str, recipe: &str, archive: Archive| {
        if archive.compression != crate::kernel::archive::Compression::Xz {
            return Err(invalid(format!(
                "Rust {build} publishes {component} for {} as gzip only; ward lays out the \
                 .tar.xz archives",
                platform.triple()
            )));
        }
        Ok(ArtifactRow::new(
            platform,
            component,
            PUBLISHER,
            &build,
            recipe,
            &archive.url,
            archive.digest,
        ))
    };
    for component in RUNTIME_COMPONENTS {
        for platform in Platform::ALL {
            let archive = manifest.component(component, platform.triple())?;
            artifacts.push(row(*platform, component, RUST_RECIPE, archive)?);
        }
    }
    // rustfmt is a convenience: a nightly some platform lacks it on (it has
    // happened) is still a usable compiler, so it is left out everywhere
    // rather than locked for some platforms only.
    let rustfmt: Option<Vec<ArtifactRow>> = Platform::ALL
        .iter()
        .map(|platform| {
            let archive = manifest.component("rustfmt", platform.triple()).ok()?;
            row(*platform, "rustfmt", RUSTFMT_RECIPE, archive).ok()
        })
        .collect();
    let has_rustfmt = rustfmt.is_some();
    artifacts.extend(rustfmt.unwrap_or_default());
    for platform in Platform::ALL {
        artifacts.push(ArtifactRow::new(
            *platform,
            CHANNEL_MANIFEST,
            PUBLISHER,
            &build,
            CHANNEL_MANIFEST_RECIPE,
            url,
            manifest_digest.clone(),
        ));
    }
    let mut components: Vec<Component> = RUNTIME_COMPONENTS
        .iter()
        .map(|name| Component::new(name, &version))
        .collect();
    if has_rustfmt {
        // The rustfmt archive's root directory is `rustfmt-<version>-<host>`
        // and a nightly's says `nightly` there, so that is its version.
        components.push(Component::new("rustfmt", "nightly"));
    }
    components.push(Component::new(CHANNEL_MANIFEST, &version));
    Ok(Bundle {
        release: format!("{NIGHTLY_RELEASE_PREFIX}{date}"),
        revision: None,
        primary: vec!["rustc".into()],
        components,
        artifacts,
    })
}

/// One file from static.rust-lang.org, through the source policy like
/// every toolchain download.
fn fetch(url: &str) -> io::Result<Vec<u8>> {
    let (reader, _) = crate::kernel::fetch::open_authorized(
        crate::kernel::toolchain::source::SourcePolicy::effective(),
        PUBLISHER,
        url,
    )?;
    let mut body = Vec::new();
    reader.take(MAX_MANIFEST + 1).read_to_end(&mut body)?;
    if body.len() as u64 > MAX_MANIFEST {
        return Err(invalid(format!(
            "{url} is larger than {MAX_MANIFEST} bytes"
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const STABLE_XZ: &[u8] = include_bytes!("../../../tools/keys/channel-rust-1.96.1.toml.xz");
    const STABLE_ASC: &str = include_str!("../../../tools/keys/channel-rust-1.96.1.toml.asc");

    fn stable_manifest() -> Vec<u8> {
        let mut out = Vec::new();
        liblzma::read::XzDecoder::new(STABLE_XZ)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// A small dated manifest: rustc, rust-std, cargo and rustfmt for both
    /// hosts, xz rows.
    fn manifest(date: &str, rustfmt_on_darwin: bool) -> String {
        let mut text = format!(
            "manifest-version = \"2\"\ndate = \"{date}\"\n\
             [pkg.rustc]\nversion = \"1.100.0-nightly (0dfb098f3 2026-08-31)\"\n"
        );
        for package in ["rustc", "rust-std", "cargo", "rustfmt-preview"] {
            for host in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
                let available = package != "rustfmt-preview"
                    || rustfmt_on_darwin
                    || host != "aarch64-apple-darwin";
                let name = package.trim_end_matches("-preview");
                text.push_str(&format!(
                    "[pkg.{package}.target.{host}]\navailable = {available}\n\
                     xz_url = \"{DIST}/{date}/{name}-nightly-{host}.tar.xz\"\n\
                     xz_hash = \"{}\"\n",
                    "ab".repeat(32)
                ));
            }
        }
        text.push_str("[renames.rustfmt]\nto = \"rustfmt-preview\"\n");
        text
    }

    #[test]
    fn channels_are_nightly_or_a_calendar_date() {
        assert_eq!(Nightly::parse("nightly").unwrap(), Some(Nightly::Newest));
        assert_eq!(
            Nightly::parse("nightly-2026-09-01").unwrap(),
            Some(Nightly::Dated("2026-09-01".into()))
        );
        for other in ["stable", "1.96.1", "beta", "nightlyx"] {
            assert_eq!(Nightly::parse(other).unwrap(), None, "{other}");
        }
        for bad in [
            "nightly-2026-9-01",
            "nightly-2026-13-01",
            "nightly-2026-09-00",
            "nightly-../../x",
            "nightly-2026-09-01-x86_64-unknown-linux-gnu",
            "nightly-",
        ] {
            let error = Nightly::parse(bad).unwrap_err().to_string();
            assert!(error.contains("nightly-YYYY-MM-DD"), "{bad}: {error}");
        }
    }

    #[test]
    fn a_dated_manifest_becomes_a_bundle_for_every_platform() {
        let date = "2026-09-01";
        let url = format!("{DIST}/{date}/channel-rust-nightly.toml");
        let digest = Digest::sha256(&"cd".repeat(32)).unwrap();
        let bundle = bundle(date, &url, digest.clone(), &manifest(date, true)).unwrap();
        assert_eq!(bundle.release, "rust-nightly-2026-09-01");
        assert_eq!(bundle.primary, ["rustc"]);
        assert_eq!(bundle.component("rustc").unwrap().version, "1.100.0");
        assert_eq!(bundle.component("rustfmt").unwrap().version, "nightly");
        assert!(bundle.complete_everywhere());
        for platform in Platform::ALL {
            let rustc = bundle.artifact(*platform, "rustc").unwrap();
            assert_eq!(rustc.build, "nightly-2026-09-01");
            assert_eq!(rustc.recipe, RUST_RECIPE);
            assert_eq!(
                rustc.url,
                format!(
                    "{DIST}/2026-09-01/rustc-nightly-{}.tar.xz",
                    platform.triple()
                )
            );
            let pinned = bundle.artifact(*platform, CHANNEL_MANIFEST).unwrap();
            assert_eq!(pinned.url, url);
            assert_eq!(pinned.digest, digest);
            assert_eq!(pinned.recipe, CHANNEL_MANIFEST_RECIPE);
        }
        // The lock a nightly writes reads back as the same bundle.
        let mut lock = crate::kernel::toolchain::lock::ToolchainLock::new("0.0.0");
        let rows = vec![crate::kernel::toolchain::input::InputRow {
            path: "rust-toolchain.toml".into(),
            field: "toolchain.channel".into(),
            value: Some("nightly-2026-09-01".into()),
            absent: false,
            sha256: Some("a".repeat(64)),
        }];
        lock.set_ecosystem("rust", &bundle, &rows).unwrap();
        let reread =
            crate::kernel::toolchain::lock::ToolchainLock::parse(&lock.canonical_bytes()).unwrap();
        let section = reread.ecosystem("rust").unwrap();
        assert_eq!(section.bundle().unwrap().bundle_id(), bundle.bundle_id());
        assert_eq!(section.bundle_id(), bundle.bundle_id());
    }

    #[test]
    fn rustfmt_missing_on_one_platform_is_left_out_on_all() {
        let date = "2026-09-01";
        let url = format!("{DIST}/{date}/channel-rust-nightly.toml");
        let digest = Digest::sha256(&"cd".repeat(32)).unwrap();
        let bundle = bundle(date, &url, digest, &manifest(date, false)).unwrap();
        assert!(bundle.component("rustfmt").is_none());
        assert!(bundle
            .artifacts
            .iter()
            .all(|row| row.component != "rustfmt"));
        assert!(bundle.complete_everywhere());
    }

    #[test]
    fn a_manifest_of_another_date_is_refused() {
        let url = format!("{DIST}/2026-09-01/channel-rust-nightly.toml");
        let digest = Digest::sha256(&"cd".repeat(32)).unwrap();
        let error = bundle("2026-09-01", &url, digest, &manifest("2026-08-31", true))
            .unwrap_err()
            .to_string();
        assert!(error.contains("manifest of 2026-08-31"), "{error}");
    }

    #[test]
    fn a_gzip_only_row_is_refused() {
        let date = "2026-09-01";
        let url = format!("{DIST}/{date}/channel-rust-nightly.toml");
        let text = manifest(date, true)
            .replacen("xz_url", "url", 1)
            .replacen("xz_hash", "hash", 1);
        let digest = Digest::sha256(&"cd".repeat(32)).unwrap();
        let error = bundle(date, &url, digest, &text).unwrap_err().to_string();
        assert!(error.contains("gzip only"), "{error}");
    }

    /// The whole path offline: a manifest whose signature checks, then the
    /// same bytes with a changed byte, which must not lock.
    #[test]
    fn the_manifest_must_carry_the_rust_release_signature() {
        // A stable manifest stands in for the nightly's bytes: it is signed
        // by the same key, which is the part under test. Its date and rows
        // do not describe a nightly, so the bundle step refuses it after
        // the signature check passed.
        let files: BTreeMap<String, Vec<u8>> = [
            (
                format!("{DIST}/2026-01-01/channel-rust-nightly.toml"),
                stable_manifest(),
            ),
            (
                format!("{DIST}/2026-01-01/channel-rust-nightly.toml.asc"),
                STABLE_ASC.as_bytes().to_vec(),
            ),
        ]
        .into();
        let fetch = |url: &str| {
            files
                .get(url)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, url.to_string()))
        };
        let error = select_with("nightly-2026-01-01", &fetch)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("signature"), "{error}");
        assert!(error.contains("not of 2026-01-01"), "{error}");

        let mut tampered = files.clone();
        let key = format!("{DIST}/2026-01-01/channel-rust-nightly.toml");
        tampered.get_mut(&key).unwrap()[100] ^= 1;
        let fetch = |url: &str| {
            tampered
                .get(url)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, url.to_string()))
        };
        let error = select_with("nightly-2026-01-01", &fetch)
            .unwrap_err()
            .to_string();
        assert!(error.contains("fails its signature check"), "{error}");
    }

    #[test]
    fn plain_nightly_follows_the_undated_manifest_to_its_date() {
        let fetched = std::cell::RefCell::new(Vec::new());
        let fetch = |url: &str| -> io::Result<Vec<u8>> {
            fetched.borrow_mut().push(url.to_string());
            if url == format!("{DIST}/channel-rust-nightly.toml") {
                return Ok(manifest("2026-09-01", true).into_bytes());
            }
            Err(io::Error::new(io::ErrorKind::NotFound, url.to_string()))
        };
        let error = select_with("nightly", &fetch).unwrap_err().to_string();
        assert!(error.contains("nightly-2026-09-01"), "{error}");
        assert_eq!(
            *fetched.borrow(),
            [
                format!("{DIST}/channel-rust-nightly.toml"),
                format!("{DIST}/2026-09-01/channel-rust-nightly.toml"),
            ]
        );
    }

    #[test]
    fn a_stable_channel_is_not_answered_here() {
        let fetch = |url: &str| -> io::Result<Vec<u8>> { panic!("fetched {url}") };
        assert!(select_with("1.96.1", &fetch).unwrap().is_none());
        assert!(select_with("stable", &fetch).unwrap().is_none());
    }
}
