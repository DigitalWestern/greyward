//! `global.json`'s SDK request, read the way the .NET host (hostfxr) reads
//! it: `sdk.version` is the lowest SDK the project accepts and
//! `sdk.rollForward` says how far above it the host may go. Each policy is
//! a range, and Greyward locks one catalog SDK inside it, the same as a `>=`
//! range in any other ecosystem: the toolchain lock records the exact SDK,
//! later syncs honor the lock, and `ward update --toolchain` selects again.
//!
//! The ranges, for `version` A.B.C with feature band F = C / 100:
//!
//! | rollForward | admits |
//! |---|---|
//! | `disable` | exactly A.B.C |
//! | `patch`, `latestPatch`, absent | >= A.B.C, < A.B.(F+1)00 |
//! | `feature`, `latestFeature` | >= A.B.C, < A.(B+1) |
//! | `minor`, `latestMinor` | >= A.B.C, < (A+1) |
//! | `major`, `latestMajor` | >= A.B.C |
//!
//! The `latest*` policies take the newest installed SDK in the range and
//! the others the lowest band that has one; on a machine with every SDK
//! installed both are in the range, which is the contract the project
//! states. Greyward picks inside it the way it does for every ecosystem: the
//! catalog default when the range admits it, otherwise the newest.
//!
//! A `version` the host cannot parse (`9.0.*`) is ignored by the host, which
//! then uses the newest SDK it has, so it states nothing here either. A
//! prerelease `version` (`11.0.100-rc.1`) is lower than its release, and
//! the catalog holds releases only, so its range starts at the release.
//! `allowPrerelease` is not read: the catalog has no prerelease SDKs.

use super::err;
use crate::kernel::toolchain::select::{Op, Specifier, Version, VersionRequest};
use std::io;

/// The policies `sdk.rollForward` may name.
const POLICIES: &[&str] = &[
    "disable",
    "patch",
    "latestPatch",
    "feature",
    "latestFeature",
    "minor",
    "latestMinor",
    "major",
    "latestMajor",
];

/// An SDK version as the host parses it: three dotted numbers, then an
/// optional `-prerelease` and `+build`. `None` for anything else, which
/// the host ignores. Returns the three numbers and whether a prerelease
/// was named.
fn sdk_version(text: &str) -> Option<([u64; 3], bool)> {
    let core_end = text.find(['-', '+']).unwrap_or(text.len());
    let (core, rest) = text.split_at(core_end);
    let (pre, build) = match rest.find('+') {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    };
    let prerelease = !pre.is_empty();
    if prerelease && !identifiers(&pre[1..], false) {
        return None;
    }
    if build.is_some_and(|build| !identifiers(build, true)) {
        return None;
    }
    let mut parts = [0u64; 3];
    let mut count = 0;
    for piece in core.split('.') {
        if count == 3
            || piece.is_empty()
            || (piece.len() > 1 && piece.starts_with('0'))
            || !piece.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        parts[count] = piece.parse().ok()?;
        count += 1;
    }
    (count == 3).then_some((parts, prerelease))
}

/// Whether `text` is dot-separated identifiers the host accepts (its
/// `fx_ver_t` parser): each non-empty, ASCII letters, digits and `-` only,
/// and in a prerelease a numeric one has no leading zero. Anything else
/// (`11.0.100-?`, a trailing space) makes the host ignore the version.
fn identifiers(text: &str, build: bool) -> bool {
    text.split('.').all(|id| {
        !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && (build
                || id.len() == 1
                || !id.starts_with('0')
                || !id.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn version(parts: &[u64]) -> io::Result<Version> {
    let text: Vec<String> = parts.iter().map(u64::to_string).collect();
    Version::parse(&text.join("."))
}

/// The SDK request `global.json`'s `sdk.version` and `sdk.rollForward`
/// state, or `None` when they state nothing (no version, or one the host
/// ignores). An unknown policy is refused by name, as the host refuses it.
pub fn sdk_request(
    version_text: Option<&str>,
    roll_forward: Option<&str>,
) -> io::Result<Option<VersionRequest>> {
    // The host compares policy names without regard to case.
    let policy = match roll_forward {
        None => "patch",
        Some(policy) => POLICIES
            .iter()
            .copied()
            .find(|known| known.eq_ignore_ascii_case(policy))
            .ok_or_else(|| {
                err(format!(
                    "global.json sdk.rollForward {policy:?} is not a .NET roll-forward policy \
                     (one of {})",
                    POLICIES.join(", ")
                ))
            })?,
    };
    let Some(text) = version_text else {
        return Ok(None);
    };
    let Some(([major, minor, patch], prerelease)) = sdk_version(text) else {
        return Ok(None);
    };
    let low = version(&[major, minor, patch])?;
    if policy == "disable" {
        if prerelease {
            return Err(err(format!(
                "global.json pins the prerelease SDK {text} with rollForward \"disable\"; \
                 the catalog holds release SDKs only"
            )));
        }
        return Ok(Some(VersionRequest::Exact(low)));
    }
    let high = match policy {
        "patch" | "latestPatch" => Some(version(&[major, minor, (patch / 100 + 1) * 100])?),
        "feature" | "latestFeature" => Some(version(&[major, minor + 1])?),
        "minor" | "latestMinor" => Some(version(&[major + 1])?),
        _ => None,
    };
    let mut specifiers = vec![Specifier::new(Op::Ge, low)?];
    if let Some(high) = high {
        specifiers.push(Specifier::new(Op::Lt, high)?);
    }
    Ok(Some(VersionRequest::Specifiers(specifiers)))
}

/// The SDK request a project's newest target framework states when
/// `global.json` states none: `netN.0` builds on SDK N.0.100 and every
/// later one, so the catalog default stays selected while it is new enough
/// and a newer target takes the newest SDK that builds it.
pub fn target_request(major: u64) -> io::Result<VersionRequest> {
    Ok(VersionRequest::Specifiers(vec![Specifier::new(
        Op::Ge,
        version(&[major, 0, 100])?,
    )?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_framework_is_its_lowest_sdk() {
        assert_eq!(target_request(10).unwrap().to_string(), ">=10.0.100");
    }

    fn shown(version: Option<&str>, policy: Option<&str>) -> String {
        sdk_request(version, policy)
            .unwrap()
            .map(|request| request.to_string())
            .unwrap_or_else(|| "none".into())
    }

    #[test]
    fn every_policy_is_its_range() {
        let v = Some("9.0.317");
        assert_eq!(shown(v, Some("disable")), "==9.0.317");
        for policy in [None, Some("patch"), Some("latestPatch")] {
            assert_eq!(shown(v, policy), ">=9.0.317,<9.0.400", "{policy:?}");
        }
        for policy in ["feature", "latestFeature"] {
            assert_eq!(shown(v, Some(policy)), ">=9.0.317,<9.1", "{policy}");
        }
        for policy in ["minor", "latestMinor"] {
            assert_eq!(shown(v, Some(policy)), ">=9.0.317,<10", "{policy}");
        }
        for policy in ["major", "latestMajor"] {
            assert_eq!(shown(v, Some(policy)), ">=9.0.317", "{policy}");
        }
        assert_eq!(shown(Some("8.0.100"), None), ">=8.0.100,<8.0.200");
    }

    #[test]
    fn what_the_host_ignores_states_nothing() {
        assert_eq!(shown(None, Some("latestMajor")), "none");
        assert_eq!(shown(None, None), "none");
        for ignored in [
            "9.0.*",
            "9.0",
            "9",
            "v9.0.100",
            "9.0.100.1",
            "09.0.100",
            "9.0.100-",
            "9.0.100+",
            "11.0.100-?",
            "11.0.100-rc..1",
            "11.0.100-rc.01",
            "11.0.100+a_b",
            " 9.0.100",
            "9.0.100 ",
        ] {
            assert_eq!(
                shown(Some(ignored), Some("latestPatch")),
                "none",
                "{ignored}"
            );
        }
    }

    #[test]
    fn a_prerelease_starts_its_range_at_the_release() {
        assert_eq!(
            shown(Some("11.0.100-rc.1.26425.128"), Some("latestMajor")),
            ">=11.0.100"
        );
        assert_eq!(shown(Some("10.0.100+build"), Some("disable")), "==10.0.100");
        assert_eq!(
            shown(Some("9.0.100-rc.1+abc.01"), Some("latestMajor")),
            ">=9.0.100"
        );
        assert_eq!(shown(Some("9.0.100-rc-1.0"), Some("major")), ">=9.0.100");
        let why = sdk_request(Some("11.0.100-rc.1"), Some("disable"))
            .unwrap_err()
            .to_string();
        assert!(why.contains("release SDKs only"), "{why}");
    }

    #[test]
    fn an_unknown_policy_is_refused_by_name() {
        let why = sdk_request(Some("9.0.100"), Some("latest"))
            .unwrap_err()
            .to_string();
        assert!(why.contains("\"latest\""), "{why}");
        assert!(why.contains("latestMajor"), "{why}");
        assert!(sdk_request(None, Some("sideways")).is_err());
    }

    #[test]
    fn policy_names_ignore_case_as_the_host_does() {
        let v = Some("9.0.317");
        assert_eq!(shown(v, Some("LATESTPATCH")), ">=9.0.317,<9.0.400");
        assert_eq!(shown(v, Some("Disable")), "==9.0.317");
        assert_eq!(shown(v, Some("latestfeature")), ">=9.0.317,<9.1");
        assert_eq!(shown(v, Some("MAJOR")), ">=9.0.317");
    }
}
