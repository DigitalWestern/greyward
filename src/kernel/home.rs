//! The user's home directory, as every default location under it reads it:
//! the store (`~/.greyward/store`), the machine policy
//! (`~/.greyward/policy.toml`) and the `x` environments (`~/.greyward/x`).
//!
//! One rule for all of them (#681). An unset `HOME` is refused, and so is a
//! relative one, an empty one included: joined onto `.greyward/policy.toml`
//! an empty `HOME` names `./.greyward/policy.toml`, a file the project in the
//! working directory can commit, so a project could pose as the machine
//! policy, and a relative store root would move with `-C`.

use std::io;
use std::path::PathBuf;

/// `$HOME`, refused unless it is set and absolute.
pub fn home() -> io::Result<PathBuf> {
    home_from(std::env::var_os("HOME"))
}

fn home_from(value: Option<std::ffi::OsString>) -> io::Result<PathBuf> {
    let home = value
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("HOME is not set; set HOME to an absolute directory"))?;
    if !home.is_absolute() {
        return Err(io::Error::other(format!(
            "HOME must be an absolute directory, got {:?}; refusing to use it",
            home.display().to_string()
        )));
    }
    Ok(home)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_absolute_home_is_used() {
        assert_eq!(
            home_from(Some("/home/a".into())).unwrap(),
            PathBuf::from("/home/a")
        );
        let unset = home_from(None).unwrap_err().to_string();
        assert!(unset.starts_with("HOME is not set"), "{unset}");
        for relative in ["", ".", "home/a"] {
            let error = home_from(Some(relative.into())).unwrap_err().to_string();
            assert!(
                error.starts_with("HOME must be an absolute directory, got"),
                "{relative:?}: {error}"
            );
        }
    }
}
