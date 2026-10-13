//! The policy check a cached object gets before it is reused: its stored
//! exceptions are judged against the policy in force now, since an object's
//! id does not include the policy it was built under.

use super::{
    current, denied, record, Exception, ARTIFACT_NOT_PROVISIONED, ARTIFACT_PROVISIONED,
    BUILT_FROM_SOURCE, EXTERNAL_TOOLCHAIN,
};
use crate::kernel::store::Store;
use std::io;

/// The object kinds an `object-meta/2` record never stored: `/2` kept only
/// file-collision, install-script-failed, git-dependency,
/// unattested-cargo-lock and host-build-inputs from a build's frame (a
/// producer that wrote another kind explicitly still has it). A `/2`
/// object may have been built with any of these and not say so, so
/// [`check_cached_reusable`] rebuilds it rather than trust it under a
/// policy that denies one.
pub const KINDS_NOT_IN_META_2: &[&str] = &[
    ARTIFACT_NOT_PROVISIONED,
    ARTIFACT_PROVISIONED,
    BUILT_FROM_SOURCE,
    EXTERNAL_TOOLCHAIN,
];

/// Refuse a cached object when its recorded exceptions are denied now.
pub fn check_cached_with_activity(
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    id: &str,
) -> io::Result<()> {
    store.require_activity(activity, "cached policy check")?;
    let exceptions = store.exceptions(id)?;
    check_exception_set(id, &exceptions)?;
    for exception in &exceptions {
        record(&exception.kind, &exception.subject, &exception.detail)?;
    }
    Ok(())
}

/// [`check_cached_with_activity`] for an object whose producer stores its
/// frame through [`object_exceptions`] and can build it again. `Ok(true)`:
/// the object was checked and its exceptions replayed, so reuse it.
/// `Ok(false)`: its record is `object-meta/2`, whose exceptions are a lower
/// bound, and the current policy denies a kind `/2` never stored
/// ([`KINDS_NOT_IN_META_2`]). The caller realizes the object again: the
/// build records its exceptions as it goes, so a denied one is refused at
/// record time, and an allowed build upgrades the record to `/3` at commit.
/// A denied kind the record does carry is still refused here.
pub fn check_cached_reusable(
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    id: &str,
) -> io::Result<bool> {
    store.require_activity(activity, "cached policy check")?;
    let stored = crate::kernel::objmeta::read_store_record(store, id)?;
    check_exception_set(id, &stored.exceptions)?;
    if !stored.exceptions_complete {
        let policy = current();
        if KINDS_NOT_IN_META_2.iter().any(|kind| denied(&policy, kind)) {
            return Ok(false);
        }
    }
    for exception in &stored.exceptions {
        record(&exception.kind, &exception.subject, &exception.detail)?;
    }
    Ok(true)
}

pub(crate) fn check_exception_set(id: &str, exceptions: &[Exception]) -> io::Result<()> {
    if exceptions.is_empty() {
        return Ok(());
    }
    let denied_kinds: Vec<&str> = exceptions
        .iter()
        .filter(|e| denied(&current(), &e.kind))
        .map(|e| e.kind.as_str())
        .collect();
    if denied_kinds.is_empty() {
        return Ok(());
    }
    Err(crate::kernel::error::refused(
        io::ErrorKind::PermissionDenied,
        format!(
            "cached object {id} carries exception(s): {}; 'ward --fresh' will not help; rebuild the object under a permissive policy or fix the cause",
            denied_kinds.join(", ")
        ),
    ))
}
