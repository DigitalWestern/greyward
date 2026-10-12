//! `ward completions <shell>`: print the shell completion script.

use crate::cli;
use crate::tailors::{self, FileRunner};
use std::io;
use std::path::Path;

pub fn run(shell: cli::Shell) -> io::Result<i32> {
    // Only the extensions a first word actually runs: a .rs or .cs file is
    // refused with a pointer to `ward build`, so it is not offered.
    let extensions: Vec<&str> = tailors::registry()
        .iter()
        .flat_map(|tailor| tailor.source_files())
        .filter(|file| !matches!(file.runner, FileRunner::Built(_)))
        .map(|file| file.extension)
        .collect();
    print!("{}", cli::completions(shell, &extensions));
    Ok(0)
}

/// The hidden `ward __scripts`: the package.json script names a first word
/// would run here, one per line, for the completion scripts. The file is
/// read as JSON, so a one-line or minified package.json, a name with `:`
/// in it, and a `}` inside a command all come out right, which no sed
/// pipeline managed. Silent and exit 0 whatever goes wrong: a completion
/// helper that prints an error prints it into the user's command line.
pub fn script_names() -> i32 {
    let names = std::env::current_dir()
        .ok()
        .and_then(|cwd| crate::commands::shared::project_root(&cwd).ok())
        .map(|root| package_script_names(&root))
        .unwrap_or_default();
    for name in names {
        println!("{name}");
    }
    0
}

/// The keys of `root/package.json`'s `scripts` object whose values are
/// commands (strings), in name order. Names a line cannot carry are left
/// out.
fn package_script_names(root: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read(root.join("package.json")) else {
        return Vec::new();
    };
    let Ok(package) = serde_json::from_slice::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let Some(scripts) = package
        .get("scripts")
        .and_then(|scripts| scripts.as_object())
    else {
        return Vec::new();
    };
    scripts
        .iter()
        .filter(|(name, command)| command.is_string() && !name.is_empty() && !name.contains('\n'))
        .map(|(name, _)| name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// Every shape the old sed pipeline got wrong: a `scripts` key offered
    /// as a script, keys of later blocks on one line, minified JSON, a `:`
    /// in a name, and a `}` inside a command.
    #[test]
    fn script_names_are_read_as_json() {
        let project = TempDir::new();
        let names = |text: &str| {
            std::fs::write(project.0.join("package.json"), text).unwrap();
            package_script_names(&project.0)
        };
        assert_eq!(
            names(
                r#"{"scripts": {"test:unit": "jest", "build": "echo }"}, "dependencies": {"react": "1"}}"#
            ),
            ["build", "test:unit"]
        );
        assert_eq!(
            names("{\n  \"name\": \"p\",\n  \"scripts\": {\n    \"dev\": \"vite\"\n  }\n}\n"),
            ["dev"]
        );
        // A value that is not a command is not a script; nothing else is.
        assert_eq!(names(r#"{"scripts":{"a":"x","b":1}}"#), ["a"]);
        assert!(names(r#"{"name":"p"}"#).is_empty());
        assert!(names("not json").is_empty());
        std::fs::remove_file(project.0.join("package.json")).unwrap();
        assert!(package_script_names(&project.0).is_empty());
    }
}
