//! The Bundler a lock was written with, when the store Ruby ships an older
//! one.
//!
//! A `Gemfile.lock` ends with `BUNDLED WITH <version>`. Each portable Ruby
//! carries the Bundler of its release as a default gem (Ruby 3.4.6 has
//! 2.6.9), and a lock from a newer Bundler is one that Bundler may not read
//! the same way. So when the lock names a newer Bundler, ward provisions
//! exactly that release, the way a Node project gets the exact pnpm its
//! `packageManager` field pins:
//!
//! - The version is the one `BUNDLED WITH` names, never another: no newest
//!   match, no range.
//! - Bundler is a gem on rubygems.org. Its sha256 is the lock's own
//!   `CHECKSUMS` entry for it when there is one, else the digest an earlier
//!   sync verified and recorded in the store, else rubygems.org's API. A
//!   digest the lock does not pin is recorded as `unpinned-digest` before
//!   anything is fetched, as for every other gem.
//! - The `.gem` comes through the kernel's verified download, its embedded
//!   gemspec must name `bundler` at that version, and it is installed in
//!   the sandbox into an object of its own (`ruby-bundler`), whose identity
//!   names the version, the gem's sha256 and the Ruby that installed it.
//! - The planner's lock checks and every confined `bundle` run find that
//!   object on `GEM_PATH`, and the helper activates exactly that version.
//!   The gems object gets the same `.gem` installed first, so the
//!   project's own `bundle` at run time is the locked one too.
//!
//! A lock naming the store's Bundler or an older one changes nothing.

use super::{
    err, read_gem_spec_checked, record_gem_digest, recorded_gem_digest, RubyGem, RubySpec, HELPER,
};
use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Algo;
use crate::kernel::fetch::{download_verified_held, hash_file, CacheLease};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::types::Identity;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The gem's name on rubygems.org, and the identity schema of its object.
pub(super) const NAME: &str = "bundler";
const SCHEMA: &str = "ruby-bundler/1";

/// The environment variable that tells the helper which Bundler to
/// activate before it requires one.
pub(super) const VERSION_VARIABLE: &str = "WARD_BUNDLER_VERSION";

/// The Bundler a plan runs with when the lock names one newer than the
/// store Ruby's own: recorded in the plan, so the closure says which
/// Bundler read the lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RubyBundler {
    pub version: String,
    pub sha256: String,
    /// The lock's CHECKSUMS section pinned `sha256`. Planning state only.
    #[serde(skip)]
    pub digest_in_lock: bool,
    /// The digest came from the rubygems.org API on this plan, so it is
    /// recorded in the store once the bytes match it. Planning state only.
    #[serde(skip)]
    pub digest_from_api: bool,
}

impl RubyBundler {
    /// Bundler as one gem coordinate, so the gem checks and the installer
    /// every other gem goes through take it unchanged.
    pub(super) fn gem(&self) -> RubyGem {
        RubyGem {
            name: NAME.to_string(),
            version: self.version.clone(),
            platform: "ruby".to_string(),
            full_name: format!("{NAME}-{}", self.version),
            sha256: self.sha256.clone(),
            digest_from_api: self.digest_from_api,
            digest_in_lock: self.digest_in_lock,
        }
    }

    /// The value the gems object's identity carries for it.
    pub(super) fn identity_input(&self) -> String {
        format!("{}:{}", self.version, self.sha256)
    }
}

/// A provisioned Bundler: what the plan records, and the object it was
/// installed into.
#[derive(Debug, Clone)]
pub(crate) struct Provisioned {
    pub(crate) pin: RubyBundler,
    pub(crate) object: PathBuf,
}

/// What a lock says about its Bundler: the `BUNDLED WITH` version, and the
/// sha256 its CHECKSUMS section gives for that version, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LockedBundler {
    pub(super) version: String,
    pub(super) sha256: Option<String>,
}

/// Whether `version` is a release number ward may place in a URL and a
/// store path: digits first, then digits, letters and single dots.
fn valid_version(version: &str) -> bool {
    version.len() <= 64
        && version.bytes().next().is_some_and(|b| b.is_ascii_digit())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
        && !version.contains("..")
        && !version.ends_with('.')
}

/// The lock's `BUNDLED WITH` version and the CHECKSUMS entry for it.
/// `None` when the lock names no Bundler. A `BUNDLED WITH` with no version,
/// a version that is not a plain release number, or a CHECKSUMS entry for
/// that version without a usable sha256 is refused: the lock is malformed,
/// and ward will not guess which Bundler it meant.
pub(super) fn locked(lock: &str) -> io::Result<Option<LockedBundler>> {
    let lines: Vec<&str> = lock.lines().collect();
    let Some(at) = lines
        .iter()
        .position(|line| line.trim_end() == "BUNDLED WITH")
    else {
        return Ok(None);
    };
    let version = lines
        .get(at + 1)
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .ok_or_else(|| err("Gemfile.lock has BUNDLED WITH but names no version"))?;
    if !valid_version(version) {
        return Err(err(format!(
            "Gemfile.lock: BUNDLED WITH {version:?} is not a Bundler release number"
        )));
    }
    Ok(Some(LockedBundler {
        version: version.to_string(),
        sha256: locked_checksum(&lines, version)?,
    }))
}

/// The sha256 the lock's CHECKSUMS section gives `bundler (<version>)`.
/// Bundler writes `  name (version) sha256=<hex>`, with further
/// algorithms after a comma.
fn locked_checksum(lines: &[&str], version: &str) -> io::Result<Option<String>> {
    let Some(start) = lines.iter().position(|line| line.trim_end() == "CHECKSUMS") else {
        return Ok(None);
    };
    let wanted = format!("{NAME} ({version})");
    for line in &lines[start + 1..] {
        if line.trim().is_empty() || !line.starts_with(' ') {
            break;
        }
        let entry = line.trim();
        let Some(rest) = entry.strip_prefix(&wanted) else {
            continue;
        };
        if !rest.is_empty() && !rest.starts_with(' ') {
            continue;
        }
        let hex = rest
            .split([' ', ','])
            .find_map(|part| part.strip_prefix("sha256="))
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        return match hex {
            Some(hex) => Ok(Some(hex.to_ascii_lowercase())),
            None => Err(err(format!(
                "Gemfile.lock: the CHECKSUMS entry for {wanted} has no usable sha256; \
                 refusing to ask rubygems.org instead"
            ))),
        };
    }
    Ok(None)
}

/// One segment of a RubyGems version: a run of digits or of letters.
/// Letters sort below any number, which is how RubyGems orders a
/// prerelease (`2.7.0.pre1`) before its release.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Segment {
    Letters(String),
    /// Leading zeros removed, compared by length and then digit by digit,
    /// so no release number overflows.
    Number(usize, String),
}

fn segments(version: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut chars = version.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut run = String::new();
            while let Some(&d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                run.push(d);
                chars.next();
            }
            let trimmed = run.trim_start_matches('0').to_string();
            out.push(Segment::Number(trimmed.len(), trimmed));
        } else if c.is_ascii_alphabetic() {
            let mut run = String::new();
            while let Some(&l) = chars.peek().filter(|l| l.is_ascii_alphabetic()) {
                run.push(l);
                chars.next();
            }
            out.push(Segment::Letters(run));
        } else {
            chars.next();
        }
    }
    out
}

/// `a` against `b` as RubyGems' `Gem::Version#<=>` orders them: segment by
/// segment, a missing segment reading as zero, letters below numbers.
pub(super) fn compare(a: &str, b: &str) -> Ordering {
    let (a, b) = (segments(a), segments(b));
    let zero = Segment::Number(0, String::new());
    for i in 0..a.len().max(b.len()) {
        let ordering = a.get(i).unwrap_or(&zero).cmp(b.get(i).unwrap_or(&zero));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// The version of the Bundler the store Ruby ships as a default gem,
/// named by its default gemspec, `lib/ruby/gems/<abi>/specifications/
/// default/bundler-<version>.gemspec`: the one RubyGems activates when no
/// other is installed.
pub(super) fn shipped_version(ruby_obj: &Path) -> io::Result<String> {
    let gems = ruby_obj.join("lib/ruby/gems");
    let mut found = Vec::new();
    for abi in fs::read_dir(&gems)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", gems.display())))?
    {
        let defaults = abi?.path().join("specifications/default");
        let Ok(entries) = fs::read_dir(&defaults) else {
            continue;
        };
        for entry in entries {
            let name = entry?.file_name();
            let version = name
                .to_str()
                .and_then(|name| name.strip_prefix("bundler-"))
                .and_then(|rest| rest.strip_suffix(".gemspec"));
            if let Some(version) = version.filter(|v| valid_version(v)) {
                found.push(version.to_string());
            }
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(err(format!(
            "the store Ruby at {} ships no Bundler default gem",
            ruby_obj.display()
        ))),
        many => Err(err(format!(
            "the store Ruby at {} ships more than one Bundler: {}",
            ruby_obj.display(),
            many.join(", ")
        ))),
    }
}

/// The Bundler to provision for `lock`: the one it names, when that is
/// newer than `shipped`, the store Ruby's own. `None` keeps the shipped
/// one.
pub(super) fn wanted(lock: &str, shipped: &str) -> io::Result<Option<LockedBundler>> {
    Ok(locked(lock)?.filter(|locked| compare(&locked.version, shipped) == Ordering::Greater))
}

/// The digest to verify the locked Bundler against: the lock's own, else
/// the store's record of rubygems.org's answer, else rubygems.org's API
/// (platform-qualified, and the reply must describe this coordinate).
fn pin(store: &Store, locked: &LockedBundler) -> io::Result<RubyBundler> {
    let version = locked.version.clone();
    if let Some(sha256) = &locked.sha256 {
        return Ok(RubyBundler {
            version,
            sha256: sha256.clone(),
            digest_in_lock: true,
            digest_from_api: false,
        });
    }
    if let Some(sha256) = recorded_gem_digest(store, NAME, &version, "ruby")? {
        return Ok(RubyBundler {
            version,
            sha256,
            digest_in_lock: false,
            digest_from_api: false,
        });
    }
    let full_name = format!("{NAME}-{version}");
    let url = format!(
        "https://rubygems.org/api/v2/rubygems/{NAME}/versions/{version}.json?platform=ruby"
    );
    let body =
        crate::kernel::fetch::fetch_text(&url).map_err(|e| err(format!("{full_name}: {e}")))?;
    let sha256 = super::digest_from_api_reply(&full_name, &version, "ruby", &body)?;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(format!(
            "{full_name}: rubygems.org gave no usable sha256"
        )));
    }
    Ok(RubyBundler {
        version,
        sha256: sha256.to_ascii_lowercase(),
        digest_in_lock: false,
        digest_from_api: true,
    })
}

/// The identity of the object one Bundler release is installed into by
/// one store Ruby.
pub(super) fn identity(spec: &RubySpec, bundler: &RubyBundler) -> Identity {
    Identity {
        kind: "ruby-bundler".into(),
        name: NAME.into(),
        version: bundler.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), SCHEMA.to_string()),
            ("gem_sha256".to_string(), bundler.sha256.clone()),
            // RubyGems writes the gemspec and the wrappers.
            (
                "installer".to_string(),
                format!("ruby{}:{}", spec.version, spec.sha256),
            ),
        ]),
    }
}

/// The Bundler `lock` names, provisioned, when it is newer than the one the
/// store Ruby at `ruby_obj` ships; `None` otherwise. A digest the lock does
/// not pin is recorded as `unpinned-digest` through `record` before
/// anything is fetched.
pub(super) fn for_lock(
    store: &Store,
    activity: &StoreActivity,
    spec: &RubySpec,
    ruby_obj: &Path,
    lock: &str,
    record: impl FnOnce(&str, &str, &str) -> io::Result<()>,
) -> io::Result<Option<Provisioned>> {
    let Some(locked) = wanted(lock, &shipped_version(ruby_obj)?)? else {
        return Ok(None);
    };
    if locked.sha256.is_none() {
        record(
            crate::kernel::policy::UNPINNED_DIGEST,
            &format!("{NAME}-{}", locked.version),
            "Gemfile.lock has no CHECKSUMS entry for the Bundler it was written with, so its \
             sha256 is the one rubygems.org served; add `bundler (<BUNDLED WITH version>) \
             sha256=<verified gem SHA-256>` under CHECKSUMS in Gemfile.lock, as documented \
             in docs/human/CLI.md (Ruby Bundler pinning)",
        )?;
    }
    let pin = pin(store, &locked)?;
    let object = realize(store, activity, spec, ruby_obj, &pin)?;
    Ok(Some(Provisioned { pin, object }))
}

/// Install `bundler` into its own object with the store Ruby, or find it
/// there: the `.gem` verified against the pinned sha256 and its gemspec
/// against the coordinate, installed in the sandbox as any pure-Ruby gem.
pub(super) fn realize(
    store: &Store,
    activity: &StoreActivity,
    spec: &RubySpec,
    ruby_obj: &Path,
    bundler: &RubyBundler,
) -> io::Result<PathBuf> {
    let identity = identity(spec, bundler);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let gem = bundler.gem();
    let scratch = store.stage_with_activity(activity)?;
    let staged = store.stage_with_activity(activity)?;
    let result = (|| {
        let helper = scratch.join("helper.rb");
        fs::write(&helper, HELPER)?;
        let lease = download_verified_held(store, activity, &super::gem_url(&gem), &gem.sha256)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", gem.full_name)))?;
        read_gem_spec_checked(activity, ruby_obj, &scratch, &helper, &gem, &lease)?;
        if gem.digest_from_api {
            record_gem_digest(store, activity, &gem);
        }
        let named = scratch.join(format!("{}.gem", gem.full_name));
        fs::copy(&*lease, &named)?;
        let hex = hash_file(&named, Algo::Sha256)?;
        if hex != gem.sha256 {
            return Err(err(format!(
                "{}: the copy to install does not match the pinned digest",
                gem.full_name
            )));
        }
        let installer = super::native::GemInstall {
            platform: spec.platform,
            activity,
            ruby_obj,
            helper: &helper,
            scratch: &scratch,
            staged: &staged,
            native_libs: None,
            bundler: None,
        };
        installer.install(&gem, &named, false)?;
        check_installed(&staged, &bundler.version)?;
        let mut deps = crate::kernel::store::ObjectDeps::new();
        deps.object_id(&crate::kernel::store::object_id_from_path(ruby_obj)?)?;
        deps.cache_digest(crate::kernel::fetch::Digest::sha256(&gem.sha256)?);
        store
            .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
            .map(|(path, _)| path)
    })();
    let _ = crate::kernel::store::remove_tree(&scratch);
    if result.is_err() {
        let _ = crate::kernel::store::remove_tree(&staged);
    }
    result
}

/// The installed Bundler is where RubyGems looks for it: its gemspec and
/// its library under the GEM_HOME.
fn check_installed(home: &Path, version: &str) -> io::Result<()> {
    for relative in [
        format!("specifications/{NAME}-{version}.gemspec"),
        format!("gems/{NAME}-{version}/lib/bundler.rb"),
        format!("gems/{NAME}-{version}/lib/bundler/version.rb"),
    ] {
        let metadata = fs::symlink_metadata(home.join(&relative))
            .map_err(|e| err(format!("{NAME} {version} installed no {relative}: {e}")))?;
        if !metadata.is_file() {
            return Err(err(format!(
                "{NAME} {version}: {relative} is not a regular file"
            )));
        }
    }
    Ok(())
}

/// The Bundler `lock` was written with, provisioned through `door`'s store
/// when the selected Ruby ships an older one ([`for_lock`]); `None` keeps
/// the Ruby's own. A digest the lock does not pin is recorded as
/// `unpinned-digest` in the door's attribution before anything is fetched.
pub(super) fn locked_bundler(
    door: &mut ResolutionDoor<'_>,
    ruby_obj: &Path,
    selected: &Selected,
    lock: &str,
) -> io::Result<Option<Provisioned>> {
    let spec = super::ruby_spec(door.platform(), selected)?;
    let (store, activity) = (door.store(), door.lease());
    let attribution = door.attribution();
    for_lock(
        store,
        activity,
        &spec,
        ruby_obj,
        lock,
        |kind, subject, detail| attribution.record(kind, subject, detail),
    )
}

/// [`locked_bundler`] for a project whose lock may not exist yet: none
/// names no Bundler.
pub(super) fn project_bundler(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<Option<Provisioned>> {
    match project.read_input_string(Path::new(super::GEMFILE_LOCK))? {
        Some(lock) => locked_bundler(door, ruby_obj, selected, &lock),
        None => Ok(None),
    }
}

/// The helper names the Bundler that read the lock: a provisioned one must
/// be the one that did.
pub(super) fn check_reader(bundler: Option<&Provisioned>, reader: &str) -> io::Result<()> {
    match bundler {
        Some(bundler) if bundler.pin.version != reader => Err(err(format!(
            "the lock was read by Bundler {reader}, not the {} it was written with",
            bundler.pin.version
        ))),
        _ => Ok(()),
    }
}

/// Install `bundler`'s `.gem` into a gems object through `sandboxed`, from
/// the verified download `verify` holds (the same check every gem gets),
/// copied into `scratch` and hashed again. Pure Ruby, so it builds nothing
/// and never falls back. The lease is the caller's to hold.
pub(super) fn install(
    bundler: &RubyBundler,
    scratch: &Path,
    sandboxed: &super::native::GemInstall<'_>,
    verify: impl FnOnce(&RubyGem) -> io::Result<CacheLease>,
) -> io::Result<CacheLease> {
    let gem = bundler.gem();
    let lease = verify(&gem)?;
    let named = scratch.join(format!("{}.gem", gem.full_name));
    fs::copy(&*lease, &named)?;
    let hex = hash_file(&named, Algo::Sha256)?;
    if hex != gem.sha256 {
        return Err(err(format!(
            "{}: the copy to install does not match the plan digest (found {hex})",
            gem.full_name
        )));
    }
    sandboxed.install(&gem, &named, false)?;
    Ok(lease)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    const LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.4.2)\n\n\
                        PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n\n";

    #[test]
    fn versions_order_as_rubygems_orders_them() {
        for (a, b, expected) in [
            ("4.0.3", "2.6.9", Ordering::Greater),
            ("2.6.9", "2.6.9", Ordering::Equal),
            ("2.6.10", "2.6.9", Ordering::Greater),
            ("2.7.2", "2.6.9", Ordering::Greater),
            ("2.5.23", "2.6.9", Ordering::Less),
            ("2.6", "2.6.0", Ordering::Equal),
            ("2.6.0.pre1", "2.6.0", Ordering::Less),
            ("2.7.0.pre.1", "2.6.9", Ordering::Greater),
            ("2.6.9.1", "2.6.9", Ordering::Greater),
            ("02.6.9", "2.6.9", Ordering::Equal),
            ("100000000000000000000000.0", "4.0.15", Ordering::Greater),
            ("4.0.15", "4.0.3", Ordering::Greater),
        ] {
            assert_eq!(compare(a, b), expected, "{a} vs {b}");
            assert_eq!(compare(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    /// Only a lock naming a newer Bundler provisions one, and only the one
    /// it names.
    #[test]
    fn only_a_newer_locked_bundler_is_wanted() {
        let with = |version: &str| format!("{LOCK}BUNDLED WITH\n   {version}\n");
        assert_eq!(wanted(LOCK, "2.6.9").unwrap(), None);
        assert_eq!(wanted(&with("2.6.9"), "2.6.9").unwrap(), None);
        assert_eq!(wanted(&with("2.5.23"), "2.6.9").unwrap(), None);
        for newer in ["4.0.3", "4.0.15", "2.7.2"] {
            assert_eq!(
                wanted(&with(newer), "2.6.9").unwrap(),
                Some(LockedBundler {
                    version: newer.to_string(),
                    sha256: None
                })
            );
        }
        // Bundler 4 indents the version by two spaces.
        assert_eq!(
            wanted(&format!("{LOCK}BUNDLED WITH\n  4.0.3\n"), "2.6.9")
                .unwrap()
                .unwrap()
                .version,
            "4.0.3"
        );
    }

    #[test]
    fn a_malformed_bundled_with_is_refused() {
        for bad in [
            "BUNDLED WITH\n",
            "BUNDLED WITH\n\n",
            "BUNDLED WITH\n   4.0.3/../../x\n",
            "BUNDLED WITH\n   >= 4\n",
            "BUNDLED WITH\n   4.0.3?platform=java\n",
            "BUNDLED WITH\n   .4\n",
            "BUNDLED WITH\n   4..0\n",
        ] {
            assert!(locked(&format!("{LOCK}{bad}")).is_err(), "{bad:?}");
        }
    }

    /// The lock's CHECKSUMS entry for the locked version pins the digest;
    /// an entry for another version, or for another gem whose name starts
    /// the same way, does not.
    #[test]
    fn the_locked_checksum_is_the_entry_for_that_version() {
        let sha = "a4ceb882fe94a0e0ac63cd0813932bbfd631a14e5ac0b7975189b19a4d28d9e7";
        let other = "b".repeat(64);
        let lock = format!(
            "{LOCK}CHECKSUMS\n  bundler (4.0.14) sha256={other}\n  bundler-audit (4.0.15) \
             sha256={other}\n  bundler (4.0.15) sha256={sha}\n  rake (13.4.2) sha256={other}\n\n\
             BUNDLED WITH\n  4.0.15\n"
        );
        assert_eq!(
            locked(&lock).unwrap(),
            Some(LockedBundler {
                version: "4.0.15".into(),
                sha256: Some(sha.into())
            })
        );
        // Several algorithms, upper-case hex.
        let lock = format!(
            "{LOCK}CHECKSUMS\n  bundler (4.0.15) sha512={},sha256={}\n\nBUNDLED WITH\n  4.0.15\n",
            "c".repeat(128),
            sha.to_ascii_uppercase()
        );
        assert_eq!(locked(&lock).unwrap().unwrap().sha256.as_deref(), Some(sha));
        // No entry for the version: rubygems.org is asked.
        let lock = format!(
            "{LOCK}CHECKSUMS\n  bundler (4.0.14) sha256={other}\n\nBUNDLED WITH\n  4.0.15\n"
        );
        assert_eq!(locked(&lock).unwrap().unwrap().sha256, None);
        // An entry that names the version but no usable sha256 fails closed.
        for entry in [
            "bundler (4.0.15)",
            "bundler (4.0.15) sha256=abc",
            "bundler (4.0.15) md5=x",
        ] {
            let lock = format!("{LOCK}CHECKSUMS\n  {entry}\n\nBUNDLED WITH\n  4.0.15\n");
            assert!(locked(&lock).is_err(), "{entry}");
        }
    }

    #[test]
    fn the_shipped_bundler_is_named_by_its_default_gemspec() {
        let temp = TempDir::named("ruby-shipped-bundler");
        let defaults = temp.0.join("lib/ruby/gems/3.4.0/specifications/default");
        fs::create_dir_all(&defaults).unwrap();
        assert!(shipped_version(&temp.0).is_err());
        fs::write(defaults.join("bundler-2.6.9.gemspec"), "").unwrap();
        fs::write(defaults.join("rake-13.2.1.gemspec"), "").unwrap();
        fs::write(defaults.join("bundler-audit-1.0.gemspec"), "").unwrap();
        assert_eq!(shipped_version(&temp.0).unwrap(), "2.6.9");
        fs::write(defaults.join("bundler-2.7.0.gemspec"), "").unwrap();
        assert!(shipped_version(&temp.0).is_err());
    }

    /// The object is named by the release and its digest: another digest
    /// for the same version is another object.
    #[test]
    fn the_object_identity_names_the_version_and_the_digest() {
        let spec = super::super::pin_spec(crate::kernel::platform::Platform::X86_64UnknownLinuxGnu);
        let bundler = RubyBundler {
            version: "4.0.3".into(),
            sha256: "f06623d5edf4183e5fac847a953c1f1bd95e27aa766471525d3a9c70bdee9394".into(),
            digest_in_lock: false,
            digest_from_api: true,
        };
        let one = identity(&spec, &bundler);
        assert_eq!(one.version, "4.0.3");
        assert_eq!(one.inputs["gem_sha256"], bundler.sha256);
        let other = identity(
            &spec,
            &RubyBundler {
                sha256: "0".repeat(64),
                ..bundler.clone()
            },
        );
        assert_ne!(one.object_id(), other.object_id());
        let gem = bundler.gem();
        assert_eq!(
            (
                gem.name.as_str(),
                gem.full_name.as_str(),
                gem.platform.as_str()
            ),
            ("bundler", "bundler-4.0.3", "ruby")
        );
        assert_eq!(
            super::super::gem_url(&gem),
            "https://rubygems.org/downloads/bundler-4.0.3.gem"
        );
    }

    /// The gemspec check every downloaded gem gets refuses a `.gem` whose
    /// embedded spec is another release or another gem.
    #[test]
    fn the_downloaded_gemspec_must_be_the_locked_bundler() {
        let gem = RubyBundler {
            version: "4.0.3".into(),
            sha256: "a".repeat(64),
            digest_in_lock: true,
            digest_from_api: false,
        }
        .gem();
        let spec = |name: &str, version: &str| {
            serde_json::json!({"name": name, "version": version, "platform": "ruby",
                               "executables": ["bundle", "bundler"], "extensions": []})
            .to_string()
        };
        let (exes, native) =
            super::super::spec_matches_plan(&gem, spec("bundler", "4.0.3").as_bytes()).unwrap();
        assert_eq!(exes, ["bundle", "bundler"]);
        assert!(!native);
        assert!(
            super::super::spec_matches_plan(&gem, spec("bundler", "4.0.2").as_bytes()).is_err()
        );
        assert!(super::super::spec_matches_plan(&gem, spec("bundlr", "4.0.3").as_bytes()).is_err());
    }
}
