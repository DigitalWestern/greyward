//! One minimatch pattern, compiled: braces expanded, each alternative split
//! at `/` into segments, and each segment a literal name, `**`, or a magic
//! segment built from `*`, `?`, `[...]` classes (POSIX `[:name:]` classes
//! and `!`/`^` negation included) and the extglobs `@(..)`, `!(..)`,
//! `+(..)`, `*(..)`, `?(..)`. A `[` or an extglob with no close is literal.

use super::braces::expand_braces;
use std::io;

#[derive(Debug, Clone)]
pub(super) enum Node {
    Char(char),
    Any,
    Star,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    Ext {
        kind: char,
        alts: Vec<Vec<Node>>,
    },
}

#[derive(Debug, Clone)]
pub(super) enum ClassItem {
    Char(char),
    Range(char, char),
    Posix(fn(char) -> bool),
}

#[derive(Debug, Clone)]
pub(super) enum Segment {
    Globstar,
    Literal(String),
    Magic {
        nodes: Vec<Node>,
        /// The segment spells a leading `.`, so it may match a dot name.
        leading_dot: bool,
    },
}

impl Segment {
    /// A segment that names nothing: the `''` a trailing or doubled `/`
    /// leaves, or `.`.
    pub(super) fn is_empty(&self) -> bool {
        matches!(self, Segment::Literal(text) if text.is_empty() || text == ".")
    }
}

/// Every brace alternative of `pattern`, split into segments.
pub(super) fn compile(pattern: &str) -> io::Result<Vec<Vec<Segment>>> {
    Ok(expand_braces(pattern)?
        .iter()
        .map(|alternative| alternative.split('/').map(segment).collect())
        .collect())
}

/// The literal path of a compiled alternative with no magic in it, its
/// empty segments dropped.
pub(super) fn literal_path(segments: &[Segment]) -> Option<String> {
    let mut names = Vec::new();
    for segment in segments {
        match segment {
            Segment::Literal(_) if segment.is_empty() => {}
            Segment::Literal(text) => names.push(text.as_str()),
            _ => return None,
        }
    }
    Some(names.join("/"))
}

fn segment(text: &str) -> Segment {
    if text == "**" {
        return Segment::Globstar;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    let nodes = parse_sequence(&chars, &mut index, false);
    if nodes.iter().all(|node| matches!(node, Node::Char(_))) {
        Segment::Literal(text.to_string())
    } else {
        Segment::Magic {
            leading_dot: matches!(nodes.first(), Some(Node::Char('.'))),
            nodes,
        }
    }
}

const EXTGLOB: [char; 5] = ['@', '!', '+', '*', '?'];

fn parse_sequence(chars: &[char], index: &mut usize, in_ext: bool) -> Vec<Node> {
    let mut nodes = Vec::new();
    while *index < chars.len() {
        let character = chars[*index];
        if in_ext && (character == '|' || character == ')') {
            break;
        }
        if EXTGLOB.contains(&character)
            && chars.get(*index + 1) == Some(&'(')
            && closing_paren(chars, *index + 1).is_some()
        {
            *index += 2;
            let mut alts = Vec::new();
            loop {
                alts.push(parse_sequence(chars, index, true));
                let separator = chars.get(*index).copied();
                *index += 1;
                if separator != Some('|') {
                    break;
                }
            }
            nodes.push(Node::Ext {
                kind: character,
                alts,
            });
            continue;
        }
        match character {
            '*' => {
                if !matches!(nodes.last(), Some(Node::Star)) {
                    nodes.push(Node::Star);
                }
            }
            '?' => nodes.push(Node::Any),
            '[' => {
                if let Some((class, next)) = parse_class(chars, *index) {
                    nodes.push(class);
                    *index = next;
                    continue;
                }
                nodes.push(Node::Char('['));
            }
            other => nodes.push(Node::Char(other)),
        }
        *index += 1;
    }
    nodes
}

/// The `)` closing the extglob whose `(` is at `open`: only an extglob's
/// own `(` nests, as [`parse_sequence`] reads them.
fn closing_paren(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut index = open;
    while index < chars.len() {
        match chars[index] {
            '(' if index == open || (index > 0 && EXTGLOB.contains(&chars[index - 1])) => {
                depth += 1
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn parse_class(chars: &[char], start: usize) -> Option<(Node, usize)> {
    let mut index = start + 1;
    let negated = matches!(chars.get(index), Some('!' | '^'));
    if negated {
        index += 1;
    }
    let mut items = Vec::new();
    let mut first = true;
    while index < chars.len() {
        let character = chars[index];
        if character == ']' && !first {
            return Some((Node::Class { negated, items }, index + 1));
        }
        first = false;
        if character == '[' && chars.get(index + 1) == Some(&':') {
            let rest: String = chars[index + 2..].iter().collect();
            if let Some(end) = rest.find(":]") {
                if let Some(test) = posix_class(&rest[..end]) {
                    items.push(ClassItem::Posix(test));
                    index += 2 + rest[..end].chars().count() + 2;
                    continue;
                }
            }
        }
        if chars.get(index + 1) == Some(&'-') && chars.get(index + 2).is_some_and(|&c| c != ']') {
            items.push(ClassItem::Range(character, chars[index + 2]));
            index += 3;
            continue;
        }
        items.push(ClassItem::Char(character));
        index += 1;
    }
    None
}

fn posix_class(name: &str) -> Option<fn(char) -> bool> {
    Some(match name {
        "alnum" => |c: char| c.is_alphanumeric(),
        "alpha" => |c: char| c.is_alphabetic(),
        "ascii" => |c: char| c.is_ascii(),
        "blank" => |c: char| c == ' ' || c == '\t',
        "cntrl" => |c: char| c.is_control(),
        "digit" => |c: char| c.is_ascii_digit(),
        "graph" => |c: char| !c.is_control() && !c.is_whitespace(),
        "lower" => |c: char| c.is_lowercase(),
        "print" => |c: char| !c.is_control(),
        "punct" => |c: char| c.is_ascii_punctuation(),
        "space" => |c: char| c.is_whitespace(),
        "upper" => |c: char| c.is_uppercase(),
        "word" => |c: char| c.is_alphanumeric() || c == '_',
        "xdigit" => |c: char| c.is_ascii_hexdigit(),
        _ => return None,
    })
}

/// Whether one segment matches the name `name`. A magic segment takes no
/// empty name, no `.` or `..`, and (unless `dot`) no dot name it does not
/// spell with a leading `.`.
pub(super) fn segment_matches(segment: &Segment, name: &str, dot: bool) -> bool {
    match segment {
        Segment::Globstar => true,
        Segment::Literal(text) => text == name,
        Segment::Magic { nodes, leading_dot } => {
            if name.is_empty() || name == "." || name == ".." {
                return false;
            }
            if !dot && name.starts_with('.') && !leading_dot {
                return false;
            }
            let chars: Vec<char> = name.chars().collect();
            nodes_match(nodes, &chars, 0)
        }
    }
}

/// Whether `nodes` match all of `text[at..]`.
fn nodes_match(nodes: &[Node], text: &[char], at: usize) -> bool {
    let Some((node, rest)) = nodes.split_first() else {
        return at == text.len();
    };
    match node {
        Node::Char(character) => text.get(at) == Some(character) && nodes_match(rest, text, at + 1),
        Node::Any => at < text.len() && nodes_match(rest, text, at + 1),
        Node::Star => (at..=text.len()).any(|end| nodes_match(rest, text, end)),
        Node::Class { negated, items } => text.get(at).is_some_and(|&character| {
            let inside = items.iter().any(|item| match item {
                ClassItem::Char(c) => *c == character,
                ClassItem::Range(low, high) => (*low..=*high).contains(&character),
                ClassItem::Posix(test) => test(character),
            });
            inside != *negated && nodes_match(rest, text, at + 1)
        }),
        Node::Ext { kind, alts } => {
            let then = |alt: &[Node]| [alt, rest].concat();
            match kind {
                '@' => alts.iter().any(|alt| nodes_match(&then(alt), text, at)),
                '?' => {
                    nodes_match(rest, text, at)
                        || alts.iter().any(|alt| nodes_match(&then(alt), text, at))
                }
                '+' => repeat(alts, rest, text, at, true),
                '*' => repeat(alts, rest, text, at, false),
                // minimatch's `(?:(?!(?:alts)rest$)[^/]*?)rest`: nothing an
                // alternative and the rest of the segment would match, then
                // anything the rest can follow.
                _ => {
                    !alts.iter().any(|alt| nodes_match(&then(alt), text, at))
                        && (at..=text.len()).any(|end| nodes_match(rest, text, end))
                }
            }
        }
    }
}

fn repeat(alts: &[Vec<Node>], rest: &[Node], text: &[char], at: usize, need: bool) -> bool {
    if !need && nodes_match(rest, text, at) {
        return true;
    }
    alts.iter().any(|alt| {
        (at..=text.len()).any(|end| {
            if !nodes_match(alt, &text[..end], at) {
                return false;
            }
            if end == at {
                // An empty repetition only satisfies the one `+` needs.
                need && nodes_match(rest, text, at)
            } else {
                repeat(alts, rest, text, end, false)
            }
        })
    })
}

/// minimatch's `match`: whether the `/`-separated `path` matches a
/// compiled alternative. A `**` takes any run of segments other than `.`,
/// `..` and (unless `dot`) dot names; one that ends the pattern must take
/// at least one. A path may end in one extra `/` the pattern does not.
pub(super) fn path_matches(path: &str, segments: &[Segment], dot: bool) -> bool {
    let file: Vec<&str> = path.split('/').collect();
    file_matches(&file, segments, dot)
}

fn file_matches(file: &[&str], pattern: &[Segment], dot: bool) -> bool {
    match pattern.split_first() {
        None => file.is_empty() || file == [""],
        Some((Segment::Globstar, rest)) => {
            let fits =
                |name: &&str| *name != "." && *name != ".." && (dot || !name.starts_with('.'));
            if rest.is_empty() {
                return !file.is_empty() && file.iter().all(fits);
            }
            for taken in 0..=file.len() {
                if taken > 0 && !fits(&file[taken - 1]) {
                    return false;
                }
                if file_matches(&file[taken..], rest, dot) {
                    return true;
                }
            }
            false
        }
        Some((segment, rest)) => {
            !file.is_empty()
                && segment_matches(segment, file[0], dot)
                && file_matches(&file[1..], rest, dot)
        }
    }
}

/// glob's reading of a directory path against a compiled alternative, as
/// its walk would find it (dot names only where spelled): a `**` takes
/// zero or more segments, and an empty segment (a trailing `/`) is none.
pub(super) fn walk_matches(file: &[&str], pattern: &[Segment]) -> bool {
    match pattern.split_first() {
        None => file.is_empty(),
        Some((segment, rest)) if segment.is_empty() => walk_matches(file, rest),
        Some((Segment::Globstar, rest)) => {
            walk_matches(file, rest)
                || (!file.is_empty()
                    && !file[0].starts_with('.')
                    && walk_matches(&file[1..], pattern))
        }
        Some((segment, rest)) => {
            !file.is_empty()
                && segment_matches(segment, file[0], false)
                && walk_matches(&file[1..], rest)
        }
    }
}
