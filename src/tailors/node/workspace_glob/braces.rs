//! Brace expansion as the `brace-expansion` package minimatch uses gives
//! it: `{a,b}` lists (nested, an empty alternative allowed) and `{1..5}`,
//! `{01..10..2}`, `{a..e}` sequences. A set that is neither, such as `{a}`
//! or `{}`, is literal.

use std::io;

/// The most paths one pattern's braces may expand to. A pattern past it is
/// refused rather than truncated, so no member is silently left out; the
/// count is checked as each path is produced, so nothing larger is ever
/// built.
pub(super) const MAX_EXPANSIONS: usize = 4096;

/// `pattern`'s brace expansion.
pub(crate) fn expand_braces(pattern: &str) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    expand_into(pattern, &mut out)?;
    Ok(out)
}

fn too_many() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("a workspaces pattern's braces expand past {MAX_EXPANSIONS} paths"),
    )
}

fn expand_into(pattern: &str, out: &mut Vec<String>) -> io::Result<()> {
    let Some((open, close)) = first_brace_set(pattern) else {
        return push_capped(out, pattern.to_string());
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
        return Err(too_many());
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
/// wider end when either end is padded) or single letters. The arithmetic
/// is checked: a step of zero, or one or an end past `i64`, is refused, as
/// is a sequence longer than [`MAX_EXPANSIONS`], before any of it is built.
fn sequence(body: &str) -> io::Result<Option<Vec<String>>> {
    let pieces: Vec<&str> = body.split("..").collect();
    if !(2..=3).contains(&pieces.len()) {
        return Ok(None);
    }
    let refused = |why: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the workspaces sequence {{{body}}} {why}"),
        )
    };
    let (from, to) = (pieces[0], pieces[1]);
    let numeric = |end: &str| {
        let digits = end.strip_prefix('-').unwrap_or(end);
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    };
    let letter = |end: &str| {
        let mut chars = end.chars();
        match (chars.next(), chars.next()) {
            (Some(character), None) if character.is_ascii_alphabetic() => Some(character as i128),
            _ => None,
        }
    };
    let ends = if numeric(from) && numeric(to) {
        let parse = |end: &str| {
            end.parse::<i64>()
                .map(i128::from)
                .map_err(|_| refused("has an end past the integers ward counts in"))
        };
        Some((parse(from)?, parse(to)?, false))
    } else {
        letter(from).zip(letter(to)).map(|(a, b)| (a, b, true))
    };
    let Some((start, end, letters)) = ends else {
        return Ok(None);
    };
    let step = match pieces.get(2) {
        None => 1i128,
        Some(step) if numeric(step) => {
            let step = step
                .parse::<i64>()
                .map_err(|_| refused("has a step past the integers ward counts in"))?;
            if step == 0 {
                return Err(refused("has a step of zero"));
            }
            i128::from(step).abs()
        }
        Some(_) => return Ok(None),
    };
    let count = (end - start).abs() / step + 1;
    if count > MAX_EXPANSIONS as i128 {
        return Err(too_many());
    }
    let padded = |end: &str| {
        let digits = end.strip_prefix('-').unwrap_or(end);
        digits.len() > 1 && digits.starts_with('0')
    };
    let pad = !letters && (padded(from) || padded(to));
    let width = from.len().max(to.len());
    let direction = if end < start { -step } else { step };
    let mut values = Vec::new();
    let mut value = start;
    for _ in 0..count {
        values.push(if letters {
            match char::from_u32(value as u32) {
                Some('\\') | None => String::new(),
                Some(character) => character.to_string(),
            }
        } else {
            let text = value.to_string();
            match width.checked_sub(text.len()) {
                Some(need) if pad && need > 0 => {
                    let zeros = "0".repeat(need);
                    match text.strip_prefix('-') {
                        Some(digits) => format!("-{zeros}{digits}"),
                        None => format!("{zeros}{text}"),
                    }
                }
                _ => text,
            }
        });
        value += direction;
    }
    Ok(Some(values))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(expand("p{-1..1}"), ["p-1", "p0", "p1"]);
        assert_eq!(expand("p{-01..1}"), ["p-01", "p000", "p001"]);
        assert_eq!(expand("p{1..7..3}"), ["p1", "p4", "p7"]);
        assert_eq!(expand("p{1..7..-3}"), ["p1", "p4", "p7"]);
        assert_eq!(expand("p{a..c}"), ["pa", "pb", "pc"]);
        assert_eq!(expand("p{a}"), ["p{a}"]);
        assert_eq!(expand("p{}"), ["p{}"]);
        assert_eq!(expand("{a}{b,c}"), ["{a}b", "{a}c"]);
        assert_eq!(expand("a{b{c,d}}"), ["a{bc}", "a{bd}"]);
        assert_eq!(expand("p{a,b"), ["p{a,b"]);
    }

    /// A sequence's arithmetic is checked and its length capped before it
    /// is built: an `i64::MIN` step no longer loops forever (#694).
    #[test]
    fn a_sequence_past_the_cap_or_the_integers_is_refused() {
        let error = |pattern: &str| expand_braces(pattern).unwrap_err().to_string();
        assert_eq!(
            expand_braces("packages/{0..1..-9223372036854775808}").unwrap(),
            ["packages/0"]
        );
        assert!(error("p{0..9223372036854775808}").contains("past the integers"));
        assert!(error("p{1..3..0}").contains("step of zero"));
        assert!(error("p{1..100000}").contains("past 4096"));
        assert!(error("p{-9223372036854775808..9223372036854775807}").contains("past 4096"));
        assert!(error(&"{a,b}".repeat(13)).contains("past 4096"));
        assert_eq!(expand_braces("p{1..4096}").unwrap().len(), 4096);
    }
}
