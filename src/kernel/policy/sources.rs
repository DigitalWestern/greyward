//! The registry tables of a policy file (kernel layer): `[credentials]`,
//! `[[registry]]` and `[sources]`, merged into the chain's
//! [`Sources`](crate::kernel::registries::effective::Sources) alongside the
//! rest of the file.

use super::{merge, Policy, SourceOrigin};
use crate::kernel::registries::effective::Tables;
use std::io;
use std::path::Path;

/// [`merge`] one file's policy, plus its registry tables: checked against
/// the chain so far (a project or `--policy` file may only narrow the
/// machine's `[sources]`), then merged. A refusal names `path`.
pub fn merge_file(
    policy: &mut Policy,
    other: &Policy,
    origin: SourceOrigin,
    path: &Path,
) -> io::Result<()> {
    let tables = tables(other);
    policy
        .registries
        .check(&tables, origin, path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    merge(policy, other, origin);
    policy.registries.merge(&tables, origin, path);
    Ok(())
}

fn tables(policy: &Policy) -> Tables<'_> {
    Tables {
        credentials: &policy.credentials,
        registry: &policy.registry,
        sources: &policy.sources,
    }
}
