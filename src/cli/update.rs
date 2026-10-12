//! `ward update`'s modes. `update` is four commands sharing one word: the
//! dependency update (the default), `--toolchain`, `--adopt`, and `--self`.
//! One run is exactly one of them, so the mode flags refuse each other,
//! and a flag that belongs to one mode (`--accept-changes` to `--adopt`)
//! is refused in the others. `parse::parse_deps` reads the words; this
//! decides the mode.

use super::parse::with_suggestion;
use super::spec::{toolchain_aliases, toolchain_section, ECOSYSTEM_IDS, TOOLCHAIN_WORDS};
use super::{Command, ToolchainUpdate, UsageError};

/// The mode flags `update` was given.
pub(super) struct Modes {
    pub toolchain: bool,
    pub adopt: bool,
    pub accept_changes: bool,
    pub self_update: bool,
}

/// The command a mode flag selects, or `None` for the dependency update.
pub(super) fn parse_mode(
    modes: &Modes,
    positional: &[String],
    no_sync: bool,
) -> Result<Option<Command>, UsageError> {
    if modes.self_update {
        // `--self` updates ward itself and nothing in the project, so a
        // package, another mode, `--accept-changes`, or `--no-sync` beside
        // it has no meaning.
        let stray = if modes.toolchain {
            Some("--toolchain".to_string())
        } else if modes.adopt {
            Some("--adopt".to_string())
        } else if modes.accept_changes {
            Some("--accept-changes".to_string())
        } else if no_sync {
            Some("--no-sync".to_string())
        } else {
            positional.first().map(|word| format!("'{word}'"))
        };
        if let Some(stray) = stray {
            return Err(UsageError::new(
                format!(
                    "update --self replaces the ward binary and takes nothing else; drop {stray}"
                ),
                Some("update"),
            ));
        }
        return Ok(Some(Command::SelfUpdate));
    }
    if modes.toolchain && modes.adopt {
        return Err(UsageError::new(
            "update --toolchain re-selects a toolchain and update --adopt adopts a lock; run them \
             one at a time",
            Some("update"),
        ));
    }
    if modes.accept_changes && !modes.adopt {
        return Err(UsageError::new(
            "--accept-changes accepts what update --adopt's compile changed; it applies only \
             to update --adopt",
            Some("update"),
        ));
    }
    if modes.toolchain {
        return parse_toolchain(positional, no_sync).map(Some);
    }
    if modes.adopt {
        return parse_adopt(positional, no_sync, modes.accept_changes).map(Some);
    }
    Ok(None)
}

/// `update --toolchain [<ecosystem>]`. It is a different verb wearing the
/// same word: it re-selects a toolchain and never edits a dependency lock,
/// so the one positional it takes is an ecosystem and a package name is
/// refused by name rather than delegated to a tool that would not know what
/// to do with it.
fn parse_toolchain(positional: &[String], no_sync: bool) -> Result<Command, UsageError> {
    let ecosystem = match positional {
        [] => None,
        [word] => match toolchain_section(word) {
            Some(section) => Some(section.to_string()),
            None => return Err(not_an_ecosystem(word)),
        },
        [_, word, ..] => return Err(not_an_ecosystem(word)),
    };
    Ok(Command::Update {
        names: Vec::new(),
        no_sync,
        toolchain: Some(ToolchainUpdate { ecosystem }),
    })
}

/// `update --adopt [<ecosystem>] [--accept-changes]`. Like `--toolchain`,
/// the one positional is an ecosystem (a tailor id, the words `attest`
/// takes), never a package: adoption keeps every pin the original lock
/// states, unless `--accept-changes` accepts what the compile moved.
fn parse_adopt(
    positional: &[String],
    no_sync: bool,
    accept_changes: bool,
) -> Result<Command, UsageError> {
    let ecosystem = match positional {
        [] => None,
        [word] if ECOSYSTEM_IDS.contains(&word.as_str()) => Some(word.clone()),
        [word] | [_, word, ..] => {
            return Err(UsageError::new(
                with_suggestion(
                    format!(
                        "update --adopt takes one ecosystem name, not a package; '{word}' is not \
                         one of {}",
                        ECOSYSTEM_IDS.join(", ")
                    ),
                    word,
                    ECOSYSTEM_IDS.iter().copied(),
                ),
                Some("update"),
            ))
        }
    };
    Ok(Command::Adopt {
        ecosystem,
        no_sync,
        accept_changes,
    })
}

fn not_an_ecosystem(word: &str) -> UsageError {
    UsageError::new(
        with_suggestion(
            format!(
                "update --toolchain takes an ecosystem name, not a package; '{word}' is not one \
                 of {}",
                TOOLCHAIN_WORDS.join(", ")
            ),
            word,
            TOOLCHAIN_WORDS.iter().copied().chain(toolchain_aliases()),
        ),
        Some("update"),
    )
}
