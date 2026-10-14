//! Object kinds the .NET tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::ObjectKind;
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "dotnet-sdk",
        schema: Some("dotnet-sdk/1"),
        live_required: &["schema", "artifact_sha512", "platform"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "nuget-packages",
        schema: Some("nuget-packages/2"),
        live_required: &["schema", "extractor"],
        live_optional: &["pkg:"],
        live_contract: Some(nuget_package_contract),
    },
];

/// `nuget-packages/2` keys each package on its lock contentHash alone (the
/// raw download sha256 `/1` also keyed on is a cache dependency now, not an
/// input), so the one relation left is the count: `identity.version` is the
/// number of `pkg:` inputs. Empty restore plans are legitimate and record
/// zero.
fn nuget_package_contract(identity: &Identity) -> Result<(), String> {
    let pkg = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("pkg:"))
        .count();
    let version = identity.version.parse::<usize>().map_err(|_| {
        format!(
            "NuGet package count/version relation: version {:?} is not a count for {pkg} pkg: inputs",
            identity.version
        )
    })?;
    if version != pkg {
        return Err(format!(
            "NuGet package count/version relation: version {version}, pkg: count {pkg}"
        ));
    }
    Ok(())
}
