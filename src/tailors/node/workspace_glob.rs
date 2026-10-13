//! npm's `workspaces` patterns, read the way `@npmcli/map-workspaces`
//! reads them: each entry loses a leading run of `!` (an odd count makes
//! it a negation) and a leading `./` or `/`; a later positive entry that a
//! negation matches cancels that negation; each pattern is a minimatch
//! glob (`{a,b}` and `{1..3}` braces, `*`, `?`, `[..]`, `**`) that names
//! directories only, takes no dot-named segment it does not spell out, and
//! never reaches into `node_modules`; and a negation takes out what it
//! matches, and with a trailing `/**` everything under it too.

use crate::kernel::fsroot::{Entry, ProjectRoot};
use std::io;
use std::path::{Path, PathBuf};

/// How deep a walk for a glob's directories goes.
const MAX_DEPTH: usize = 24;

/// The most alternatives one pattern's braces may expand to. A pattern
/// past it is refused rather than truncated, so no member is silently
/// left out.
const MAX_EXPANSIONS: usize = 4096;

/// A `workspaces` list after npm's negation pass.
pub(super) struct NpmWorkspaces {
    /// The positive patterns, in order, each brace-expanded.
    patterns: Vec<Vec<String>>,
    /// The negations that still stand, each brace-expanded.
    negated: Vec<Vec<String>>,
}

impl NpmWorkspaces {
    /// The list `entries` as `appendNegatedPatterns` leaves it.
    pub(super) fn new(entries: &[String]) -> io::Result<Self> {
        let mut patterns: Vec<String> = Vec::new();
        let mut negated: Vec<String> = Vec::new();
        for entry in entries {
            let (negate, pattern) = parse_entry(entry);
            if negate {
                negated.push(pattern);
            } else {
                let as_path = pattern.trim_end_matches('/');
                negated.retain(|negation| !matches(negation, as_path, false).unwrap_or(false));
                patterns.push(pattern);
            }
        }
        for negation in &negated {
            patterns.retain(|pattern| {
                !matches(negation, pattern.trim_end_matches('/'), false).unwrap_or(false)
            });
        }
        let expand = |list: Vec<String>| -> io::Result<Vec<Vec<String>>> {
            list.iter().map(|pattern| expand_braces(pattern)).collect()
        };
        Ok(NpmWorkspaces {
            patterns: expand(patterns)?,
            negated: expand(negated)?,
        })
    }

    /// Whether npm takes the directory `relative` (relative to the root,
    /// `/`-separated) as a member, its `package.json` aside: a positive
    /// pattern matches it, no negation takes it out, and no segment is
    /// `node_modules`.
    pub(super) fn names(&self, relative: &str) -> bool {
        let relative = relative.trim_end_matches('/');
        if relative.split('/').any(|segment| segment == "node_modules") {
            return false;
        }
        let named = self
            .patterns
            .iter()
            .flatten()
            .any(|pattern| matches(pattern, relative, false).unwrap_or(false));
        named && !self.ignores(relative)
    }

    /// The directories under `root` that npm takes as members, their
    /// `package.json` aside, relative to it.
    pub(super) fn directories(&self, root: &ProjectRoot) -> io::Result<Vec<String>> {
        let positive: Vec<String> = self.patterns.iter().flatten().cloned().collect();
        let mut found: Vec<String> = positive
            .iter()
            .map(|pattern| pattern.trim_end_matches('/'))
            .filter(|pattern| !pattern.contains(['*', '?', '[']))
            .map(str::to_string)
            .collect();
        found.extend(walk(root, &positive)?);
        let mut named: Vec<String> = Vec::new();
        for dir in found {
            if self.names(&dir) && !named.contains(&dir) {
                named.push(dir);
            }
        }
        Ok(named)
    }

    /// glob's `ignore` with the negations: a negation that matches the
    /// path, or one ending `/**` whose stem matches the path or a
    /// directory above it.
    fn ignores(&self, relative: &str) -> bool {
        self.negated.iter().flatten().any(|negation| {
            let pattern = negation.trim_end_matches('/');
            if matches(pattern, relative, true).unwrap_or(false) {
                return true;
            }
            let Some(stem) = pattern.strip_suffix("/**") else {
                return false;
            };
            let mut prefix = String::new();
            relative.split('/').any(|segment| {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(segment);
                matches(stem, &prefix, true).unwrap_or(false)
            })
        })
    }
}

/// Every directory any positive entry of `entries` can name, negations
/// left out, so a record covers what they would exclude too: each pattern
/// brace-expanded and globbed, and each alternative's literal path as
/// well. The wide set a resolution record covers.
pub(super) fn every_named_directory(
    root: &ProjectRoot,
    entries: &[String],
) -> io::Result<Vec<String>> {
    let mut alternatives: Vec<String> = Vec::new();
    for entry in entries {
        let (negate, pattern) = parse_entry(entry);
        if !negate {
            alternatives.extend(
                expand_braces(&pattern).map_err(|error| {
                    io::Error::new(error.kind(), format!("package.json: {error}"))
                })?,
            );
        }
    }
    let mut found: Vec<String> = alternatives
        .iter()
        .map(|alternative| alternative.trim_end_matches('/').to_string())
        .collect();
    found.extend(walk(root, &alternatives)?);
    Ok(found)
}

/// One entry split into whether it negates and the pattern left once the
/// `!` run and a leading `./` or `/` are stripped, `\` read as `/`.
fn parse_entry(entry: &str) -> (bool, String) {
    let pattern = entry.trim_start_matches('!');
    let bangs = entry.len() - pattern.len();
    let pattern = pattern.replace('\\', "/");
    let stripped = pattern.strip_prefix('.').unwrap_or(&pattern);
    let pattern = if stripped.starts_with('/') {
        stripped.trim_start_matches('/').to_string()
    } else {
        pattern.trim_start_matches('/').to_string()
    };
    (bangs % 2 == 1, pattern)
}

/// Whether the minimatch pattern `pattern` matches the `/`-separated path
/// `path`. `dot` lets a wildcard take a dot-named segment.
fn matches(pattern: &str, path: &str, dot: bool) -> io::Result<bool> {
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: !dot,
    };
    for alternative in expand_braces(pattern)? {
        let alternative = alternative.trim_end_matches('/');
        if alternative == path {
            return Ok(true);
        }
        if let Ok(compiled) = glob::Pattern::new(alternative) {
            if compiled.matches_with(path, options) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The directories under `root` some brace-free pattern of `patterns`
/// matches, relative to it. The walk follows no symlink and skips
/// `node_modules`. A wildcard here takes dot-named directories too, so
/// the wide set stays a superset; [`NpmWorkspaces::names`] drops them.
fn walk(root: &ProjectRoot, patterns: &[String]) -> io::Result<Vec<String>> {
    let mut compiled: Vec<glob::Pattern> = Vec::new();
    for pattern in patterns {
        let pattern = pattern.trim_end_matches('/');
        if !pattern.contains(['*', '?', '[']) {
            continue;
        }
        compiled.push(glob::Pattern::new(pattern).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("package.json: the workspaces pattern {pattern:?} is not a glob: {error}"),
            )
        })?);
    }
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let mut found = Vec::new();
    if compiled.is_empty() {
        return Ok(found);
    }
    let mut stack: Vec<(PathBuf, usize)> = vec![(PathBuf::new(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let listing = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &dir
        };
        let Some(entries) = root.read_input_dir(listing)? else {
            continue;
        };
        for name in entries {
            if name == "node_modules" {
                continue;
            }
            let path = dir.join(&name);
            if !matches!(root.entry(&path), Ok(Entry::Directory)) {
                continue;
            }
            let relative = path.to_string_lossy().into_owned();
            if compiled
                .iter()
                .any(|pattern| pattern.matches_with(&relative, options))
            {
                found.push(relative);
            }
            if depth + 1 < MAX_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(found)
}

/// `pattern`'s brace expansion, as the `brace-expansion` package minimatch
/// uses gives it: `{a,b}` lists (nested, an empty alternative allowed) and
/// `{1..5}`, `{01..10..2}`, `{a..e}` sequences. A set that is neither, such
/// as `{a}` or `{}`, is literal.
pub(super) fn expand_braces(pattern: &str) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    expand_into(pattern, &mut out)?;
    Ok(out)
}

fn expand_into(pattern: &str, out: &mut Vec<String>) -> io::Result<()> {
    let Some((open, close)) = first_brace_set(pattern) else {
        push_capped(out, pattern.to_string())?;
        return Ok(());
    };
    let pre = &pattern[..open];
    let body = &pattern[open + 1..close];
    let post = &pattern[close + 1..];
    let parts = split_top_level(body);
    let alternatives: Vec<String> = if parts.len() > 1 {
        parts
    } else if let Some(sequence) = sequence(body)? {
        sequence
    } else if body.contains(',') {
        // `{a{b,c}}`: the inner set expands and the outer braces stay.
        expand_braces(body)?
            .into_iter()
            .map(|inner| format!("{{{inner}}}"))
            .collect()
    } else {
        // A literal set: keep it and expand what follows.
        let mut tails = Vec::new();
        expand_into(post, &mut tails)?;
        for tail in tails {
            push_capped(out, format!("{pre}{{{body}}}{tail}"))?;
        }
        return Ok(());
    };
    for alternative in alternatives {
        expand_into(&format!("{pre}{alternative}{post}"), out)?;
    }
    Ok(())
}

fn push_capped(out: &mut Vec<String>, item: String) -> io::Result<()> {
    if out.len() >= MAX_EXPANSIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a workspaces pattern's braces expand past {MAX_EXPANSIONS} paths"),
        ));
    }
    out.push(item);
    Ok(())
}

/// The first `{` that has a balanced `}`, and that `}`.
fn first_brace_set(pattern: &str) -> Option<(usize, usize)> {
    let bytes = pattern.as_bytes();
    for (open, &byte) in bytes.iter().enumerate() {
        if byte != b'{' {
            continue;
        }
        let mut depth = 0usize;
        for (index, &inner) in bytes.iter().enumerate().skip(open) {
            match inner {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((open, index));
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// `body` split at the commas outside any nested braces.
fn split_top_level(body: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0usize;
    for character in body.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        parts.last_mut().expect("never empty").push(character);
    }
    parts
}

/// A `{x..y}` or `{x..y..step}` sequence: integers (zero-padded to the
/// wider end when either end is padded) or single letters.
fn sequence(body: &str) -> io::Result<Option<Vec<String>>> {
    let pieces: Vec<&str> = body.split("..").collect();
    if !(2..=3).contains(&pieces.len()) {
        return Ok(None);
    }
    let step = match pieces.get(2) {
        Some(step) => match step.parse::<i64>() {
            Ok(step) => step.unsigned_abs().max(1),
            Err(_) => return Ok(None),
        },
        None => 1,
    };
    let (from, to) = (pieces[0], pieces[1]);
    let too_many = |count: u64| count / step >= MAX_EXPANSIONS as u64;
    if let (Ok(start), Ok(end)) = (from.parse::<i64>(), to.parse::<i64>()) {
        if too_many(start.abs_diff(end)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the workspaces sequence {{{body}}} expands past {MAX_EXPANSIONS} paths"),
            ));
        }
        let padded = |end: &str| {
            let digits = end.trim_start_matches('-');
            digits.len() > 1 && digits.starts_with('0')
        };
        let width = if padded(from) || padded(to) {
            from.len().max(to.len())
        } else {
            0
        };
        let values = stepped(start, end, step);
        return Ok(Some(
            values
                .into_iter()
                .map(|value| {
                    let digits = format!("{:0width$}", value.unsigned_abs(), width = width);
                    if value < 0 {
                        let width = width.saturating_sub(1);
                        format!("-{:0width$}", value.unsigned_abs(), width = width)
                    } else {
                        digits
                    }
                })
                .collect(),
        ));
    }
    let letter = |end: &str| {
        let mut chars = end.chars();
        match (chars.next(), chars.next()) {
            (Some(character), None) if character.is_ascii_alphabetic() => Some(character as i64),
            _ => None,
        }
    };
    let (Some(start), Some(end)) = (letter(from), letter(to)) else {
        return Ok(None);
    };
    Ok(Some(
        stepped(start, end, step)
            .into_iter()
            .map(|value| char::from(value as u8).to_string())
            .collect(),
    ))
}

/// `start` to `end` inclusive, by `step`, in whichever direction.
fn stepped(start: i64, end: i64, step: u64) -> Vec<i64> {
    let step = step as i64;
    let mut values = Vec::new();
    let mut value = start;
    if start <= end {
        while value <= end {
            values.push(value);
            value += step;
        }
    } else {
        while value >= end {
            values.push(value);
            value -= step;
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> NpmWorkspaces {
        let entries: Vec<String> = entries.iter().map(|entry| entry.to_string()).collect();
        NpmWorkspaces::new(&entries).unwrap()
    }

    /// The braces minimatch expands before it globs (#694).
    #[test]
    fn braces_expand_as_minimatch_expands_them() {
        let expand = |pattern: &str| expand_braces(pattern).unwrap();
        assert_eq!(expand("packages/{a,b}"), ["packages/a", "packages/b"]);
        assert_eq!(expand("{apps,libs}/*"), ["apps/*", "libs/*"]);
        assert_eq!(expand("a{,b}"), ["a", "ab"]);
        assert_eq!(expand("x/{a,{b,c}}"), ["x/a", "x/b", "x/c"]);
        assert_eq!(expand("{a,b}/{c,d}"), ["a/c", "a/d", "b/c", "b/d"]);
        assert_eq!(expand("p{1..3}"), ["p1", "p2", "p3"]);
        assert_eq!(expand("p{3..1}"), ["p3", "p2", "p1"]);
        assert_eq!(expand("p{08..10}"), ["p08", "p09", "p10"]);
        assert_eq!(expand("p{1..7..3}"), ["p1", "p4", "p7"]);
        assert_eq!(expand("p{a..c}"), ["pa", "pb", "pc"]);
        assert_eq!(expand("p{a}"), ["p{a}"]);
        assert_eq!(expand("p{}"), ["p{}"]);
        assert_eq!(expand("{a}{b,c}"), ["{a}b", "{a}c"]);
        assert_eq!(expand("a{b{c,d}}"), ["a{bc}", "a{bd}"]);
        assert_eq!(expand("p{a,b"), ["p{a,b"]);
        assert!(expand_braces("p{1..100000}").is_err());
        assert!(
            expand_braces("{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}")
                .is_err()
        );
    }

    /// map-workspaces' negation rules: an odd run of `!` negates, a later
    /// positive pattern a negation matches cancels it, a negation removes
    /// the positive patterns it matches, `x/**` takes out `x` and below,
    /// and `node_modules` and unspelled dot segments are never members.
    #[test]
    fn negations_and_dots_follow_map_workspaces() {
        let workspaces = list(&["packages/*", "!packages/b", "./tools/{x,y}", "/abs"]);
        assert!(workspaces.names("packages/a"));
        assert!(!workspaces.names("packages/b"));
        assert!(workspaces.names("tools/x") && workspaces.names("tools/y"));
        assert!(workspaces.names("abs"));
        assert!(!workspaces.names("packages/.hidden"));
        assert!(!workspaces.names("packages/node_modules"));
        assert!(list(&[".config/*"]).names(".config/a"));
        let readded = list(&["packages/**", "!packages/b/**", "packages/b/a"]);
        assert!(readded.names("packages/b/a"));
        assert!(readded.names("packages/b"));
        let subtree = list(&["packages/**", "!packages/b/**"]);
        assert!(!subtree.names("packages/b"));
        assert!(!subtree.names("packages/b/c/d"));
        assert!(subtree.names("packages/c/d"));
        assert!(list(&["!!packages/a"]).names("packages/a"));
        assert!(!list(&["!!!packages/a"]).names("packages/a"));
        assert!(!list(&["packages/a", "!packages/{a,b}"]).names("packages/a"));
    }
}
