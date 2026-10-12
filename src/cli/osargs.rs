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
    let mut slots: Vec<Option<Slot>> = Vec::new();
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
fn not_text(slots: &[Option<Slot>]) -> UsageError {
    let left = slots
        .iter()
        .flatten()
        .next()
        .map(|slot| slot.arg.to_string_lossy());
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

/// One argument that is not UTF-8: its bytes, and how many of them are a
/// directory option's spelling (`-C`, `--directory=`) the stand-in keeps.
struct Slot {
    arg: OsString,
    prefix: usize,
}

/// `arg` as text: itself when it is UTF-8, else a stand-in for it, kept in
/// `slots`. `--directory=<dir>` and `-C<dir>` keep their spelling, so where
/// ward reads its own options the grammar still sees the option; wherever
/// the word is a program's argument, the whole of it comes back.
fn word(arg: &OsStr, slots: &mut Vec<Option<Slot>>) -> String {
    if let Some(text) = arg.to_str() {
        return text.to_string();
    }
    let bytes = arg.as_bytes();
    let option = ["--directory=", "-C"]
        .into_iter()
        .find(|option| bytes.starts_with(option.as_bytes()))
        .unwrap_or_default();
    slots.push(Some(Slot {
        arg: arg.to_owned(),
        prefix: option.len(),
    }));
    format!("{option}{}", stand_in(slots.len() - 1))
}

fn stand_in(index: usize) -> String {
    format!("\0{index}\0")
}

/// The slot a stand-in names and the length of the text before it, if
/// `text` ends in one.
fn slot_of(text: &str) -> Option<(usize, usize)> {
    let body = text.strip_suffix('\0')?;
    let start = body.rfind('\0')?;
    Some((body[start + 1..].parse().ok()?, start))
}

/// Put the original bytes back in every place the grammar passes an
/// argument through untouched, taking each slot it fills: a program's
/// argument is the whole word as typed, `-C`'s directory the bytes after
/// the option's spelling.
fn restore(parsed: &mut Parsed, slots: &mut [Option<Slot>]) {
    let mut fill = |arg: &mut OsString, directory: bool| {
        let Some((index, before)) = arg.to_str().and_then(slot_of) else {
            return;
        };
        let Some(entry) = slots.get_mut(index) else {
            return;
        };
        let fits = entry.as_ref().is_some_and(|slot| {
            if directory {
                before == 0
            } else {
                before == slot.prefix
            }
        });
        if let Some(slot) = entry.take_if(|_| fits) {
            let start = if directory { slot.prefix } else { 0 };
            *arg = OsStr::from_bytes(&slot.arg.as_bytes()[start..]).to_owned();
        }
    };
    let mut take = |arg: &mut OsString| fill(arg, false);
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
        fill(&mut path, true);
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

    /// A program's argument spelled like ward's directory option is still
    /// the program's, and comes back whole, `-C` and all.
    #[test]
    fn a_programs_argument_spelled_like_a_directory_option_stays_whole() {
        for arg in [&b"-C\xff"[..], b"--directory=\xff", b"-Cx\xff"] {
            let Parsed::Run(invocation) = parse_os(&os(&[b"run", b"printf", b"%s", arg])).unwrap()
            else {
                panic!("not a run");
            };
            let Command::Run { command } = invocation.command else {
                panic!("not a run");
            };
            assert_eq!(command, os(&[b"printf", b"%s", arg]));
            assert_eq!(invocation.options.directory, None);
            let Parsed::Run(invocation) = parse_os(&os(&[b"x", b"tool", arg])).unwrap() else {
                panic!("not an x");
            };
            assert!(
                matches!(invocation.command, Command::X { ref args, .. } if *args == os(&[arg]))
            );
            let Parsed::Script { args, .. } = parse_os(&os(&[b"lint", arg])).unwrap() else {
                panic!("not a script");
            };
            assert_eq!(args, os(&[arg]));
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
