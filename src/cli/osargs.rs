//! argv as the kernel hands it over: bytes, not necessarily UTF-8. A Linux
//! file name can be any bytes but `/` and NUL, and `ward run cat <name>`
//! must hand such a name to `cat` unchanged. Every word ward reads itself
//! (a command, an option, a package name) is text, and a word that is not
//! is a usage error.
//!
//! The grammar ([`parse`]) works on text. So each argument that is not
//! UTF-8 goes in as a stand-in, NUL and its index between two NULs, which
//! no real argument can spell (argv strings end at NUL), and comes back as
//! the original bytes wherever the grammar handed it on untouched: a
//! program's arguments (`run`, a script, `x`'s tool's) and `-C`'s
//! directory. A stand-in left anywhere else names an argument ward would
//! have to read as text.

use super::{parse, Command, Options, Parsed, UsageError};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// [`parse`] over the arguments as the kernel passed them.
pub fn parse_os(args: &[OsString]) -> Result<Parsed, UsageError> {
    let mut slots: Vec<Option<OsString>> = Vec::new();
    let words: Vec<String> = args.iter().map(|arg| word(arg, &mut slots)).collect();
    let mut parsed = match parse(&words) {
        Ok(parsed) => parsed,
        // The grammar's own error, about the words as a terminal shows
        // them; if those parse, the stand-in itself was what it refused
        // (a NUL in a package name).
        Err(_) => {
            let shown: Vec<String> = args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            return Err(parse(&shown).err().unwrap_or_else(|| not_text(&slots)));
        }
    };
    restore(&mut parsed, &mut slots);
    match slots.iter().flatten().next() {
        None => Ok(parsed),
        Some(_) => Err(not_text(&slots)),
    }
}

/// The usage error for the first argument still stood in for: one ward
/// would have to read as text.
fn not_text(slots: &[Option<OsString>]) -> UsageError {
    let left = slots
        .iter()
        .flatten()
        .next()
        .map(|arg| arg.to_string_lossy());
    UsageError {
        message: format!(
            "the argument '{}' is not valid UTF-8; ward reads every argument but a \
             program's own (after 'run', 'x <tool>', a script or a file) and the -C \
             directory as text",
            left.unwrap_or_default()
        ),
        command: None,
    }
}

/// `arg` as text: itself when it is UTF-8, else a stand-in for it, kept in
/// `slots`. `--directory=<dir>` and `-C<dir>` keep their spelling, so only
/// the directory is stood in for and the grammar still sees the option.
fn word(arg: &OsStr, slots: &mut Vec<Option<OsString>>) -> String {
    if let Some(text) = arg.to_str() {
        return text.to_string();
    }
    let bytes = arg.as_bytes();
    let (option, value) = ["--directory=", "-C"]
        .iter()
        .find(|option| bytes.starts_with(option.as_bytes()))
        .map_or(("", bytes), |option| (*option, &bytes[option.len()..]));
    slots.push(Some(OsStr::from_bytes(value).to_owned()));
    format!("{option}{}", stand_in(slots.len() - 1))
}

fn stand_in(index: usize) -> String {
    format!("\0{index}\0")
}

/// The slot a stand-in names, if `text` is exactly one.
fn slot_of(text: &str) -> Option<usize> {
    text.strip_prefix('\0')?.strip_suffix('\0')?.parse().ok()
}

/// Put the original bytes back in every place the grammar passes an
/// argument through untouched, taking each slot it fills.
fn restore(parsed: &mut Parsed, slots: &mut [Option<OsString>]) {
    let mut take = |arg: &mut OsString| {
        if let Some(slot) = arg.to_str().and_then(slot_of) {
            if let Some(original) = slots.get_mut(slot).and_then(Option::take) {
                *arg = original;
            }
        }
    };
    let options = match parsed {
        Parsed::Run(invocation) => {
            match &mut invocation.command {
                Command::Run { command } => command.iter_mut().for_each(&mut take),
                Command::X { args, .. } => args.iter_mut().for_each(&mut take),
                _ => {}
            }
            Some(&mut invocation.options)
        }
        Parsed::Script { options, args, .. } => {
            args.iter_mut().for_each(&mut take);
            Some(options)
        }
        Parsed::Implicit(options) => Some(options),
        _ => None,
    };
    if let Some(Options {
        directory: Some(directory),
        ..
    }) = options
    {
        let mut path = std::mem::take(directory).into_os_string();
        take(&mut path);
        *directory = PathBuf::from(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn os(words: &[&[u8]]) -> Vec<OsString> {
        words
            .iter()
            .map(|word| OsString::from_vec(word.to_vec()))
            .collect()
    }

    /// A program's arguments, a script's and `x`'s tool's arrive as the
    /// bytes typed, and so does `-C`'s directory in all three spellings.
    #[test]
    fn a_programs_arguments_keep_their_bytes() {
        let name = b"caf\xe9.txt";
        let Parsed::Run(invocation) = parse_os(&os(&[b"run", b"cat", name])).unwrap() else {
            panic!("not a run");
        };
        assert_eq!(
            invocation.command,
            Command::Run {
                command: os(&[b"cat", name])
            }
        );
        let Parsed::Run(invocation) = parse_os(&os(&[b"x", b"black", name])).unwrap() else {
            panic!("not an x");
        };
        assert!(matches!(invocation.command, Command::X { ref args, .. } if *args == os(&[name])));
        let Parsed::Script { args, .. } = parse_os(&os(&[b"lint", name])).unwrap() else {
            panic!("not a script");
        };
        assert_eq!(args, os(&[name]));
        for words in [
            &[&b"-C"[..], name, b"status"][..],
            &[b"-Ccaf\xe9.txt", b"status"],
            &[b"--directory=caf\xe9.txt", b"status"],
            &[b"status", b"-C", name],
        ] {
            let Parsed::Run(invocation) = parse_os(&os(words)).unwrap() else {
                panic!("not a command: {words:?}");
            };
            let directory = invocation.options.directory.unwrap();
            assert_eq!(directory.as_os_str().as_bytes(), name, "{words:?}");
        }
    }

    /// Anywhere ward reads the word itself, a word that is not UTF-8 is a
    /// usage error that shows it, never a stand-in.
    #[test]
    fn a_word_ward_reads_must_be_text() {
        for words in [
            &[&b"status"[..], b"\xff"][..],
            &[b"\xff"],
            &[b"add", b"\xff"],
            &[b"build", b"\xff"],
            &[b"fmt", b"--", b"\xff"],
            &[b"x", b"\xff"],
            &[b"--\xff"],
        ] {
            let error = parse_os(&os(words)).unwrap_err();
            assert!(
                error.message.contains('\u{fffd}'),
                "{words:?}: {}",
                error.message
            );
            assert!(
                !error.message.contains('\0'),
                "{words:?}: {}",
                error.message
            );
            assert!(
                !error.message.contains("\\0"),
                "{words:?}: {}",
                error.message
            );
        }
        // Text is untouched.
        assert_eq!(
            parse_os(&os(&[b"run", b"echo", b"hi"])).unwrap(),
            parse(&["run".into(), "echo".into(), "hi".into()]).unwrap()
        );
    }
}
