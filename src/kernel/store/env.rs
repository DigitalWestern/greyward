//! `GREYWARD_STORE` handling (kernel store): the process-global lock tests
//! take around the variable. The home lookup is `kernel::home`.

/// Serializes every test that sets or clears `GREYWARD_STORE`. The variable is
/// process-global, so an unguarded test clearing it mid-run sends a guarded one
/// to the real `~/.greyward/store` — which is populated, and fails any assertion
/// about a fresh store. One lock for the whole crate: separate per-module locks
/// do not exclude each other. Poison is ignored deliberately, so a single
/// failing test does not cascade into every other holder.
#[cfg(test)]
pub(crate) static STORE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
