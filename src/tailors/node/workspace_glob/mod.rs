//! npm's `workspaces` patterns, read the way `@npmcli/map-workspaces`
//! reads them over glob and minimatch. Each entry loses a leading run of
//! `!` (an odd count makes it a negation) and a leading `./` or `/`. A
//! later positive entry that a negation matches cancels it, and a negation
//! then removes the positive entries it matches, both exactly as npm's
//! splice loops do. Each pattern is a minimatch glob ([`pattern`]) that
//! names directories only, takes no dot-named segment it does not spell,
//! never reaches into `node_modules`, and follows a symlinked directory
//! the project contains (a `**` matches one but does not descend it). A
//! negation is glob's `ignore`: it takes out what it matches, with or
//! without a trailing `/`, and with a trailing `/**` everything below.
//!
//! `corpus.json` holds cases with the member set npm's own map-workspaces
//! gives for each (`tools/npm_workspace_corpus.js` regenerates it), and
//! the tests hold ward to it.

mod braces;
mod pattern;

pub(crate) use braces::expand_braces;
use pattern::{compile, literal_path, path_matches, segment_matches, walk_matches, Segment};

use crate::kernel::fsroot::{Containment, Entry, ProjectRoot};
use std::io;
use std::path::{Path, PathBuf};

/// How deep a `**` walk goes.
const MAX_DEPTH: usize = 24;

/// One pattern, every brace alternative compiled.
type Compiled = Vec<Vec<Segment>>;

/// A `workspaces` list after npm's negation pass.
pub(super) struct NpmWorkspaces {
    patterns: Vec<Compiled>,
    negated: Vec<Compiled>,
}

/// The directories a walk found, and the symlinked ones it left out
/// because they lead outside the project.
pub(super) struct Found {
    pub(super) members: Vec<String>,
    pub(super) outside: Vec<String>,
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
                continue;
            }
            // npm's forward loop: a splice moves the next negation into
            // the index the loop then steps past, so it is not tested.
            let mut index = 0;
            while index < negated.len() {
                if minimatch(&pattern, &negated[index])? {
                    negated.remove(index);
                }
                index += 1;
            }
            patterns.push(pattern);
        }
        for negation in &negated {
            let mut matched = Vec::new();
            for pattern in &patterns {
                if minimatch(pattern, negation)? {
                    matched.push(pattern.clone());
                }
            }
            for pattern in matched {
                if let Some(index) = patterns.iter().position(|p| *p == pattern) {
                    patterns.remove(index);
                }
            }
        }
        let compile_all = |list: &[String]| -> io::Result<Vec<Compiled>> {
            list.iter().map(|pattern| compile(pattern)).collect()
        };
        Ok(NpmWorkspaces {
            patterns: compile_all(&patterns)?,
            negated: compile_all(&negated)?,
        })
    }

    /// Whether npm takes the directory `relative` (relative to the root,
    /// `/`-separated) as a member, its `package.json` aside.
    pub(super) fn names(&self, relative: &str) -> bool {
        let relative = relative.trim_end_matches('/');
        let file: Vec<&str> = relative.split('/').collect();
        !file.contains(&"node_modules")
            && self
                .patterns
                .iter()
                .flatten()
                .any(|alternative| walk_matches(&file, alternative))
            && !self.ignores(relative)
    }

    /// The directories under `root` that npm takes as members, their
    /// `package.json` aside, relative to it and sorted; and the symlinked
    /// ones npm would take that lead outside the project.
    pub(super) fn directories(&self, root: &ProjectRoot) -> io::Result<Found> {
        let mut walker = Walker::new(root, false);
        for alternative in self.patterns.iter().flatten() {
            match literal_path(alternative) {
                Some(path) => walker.candidate(path),
                None => walker.walk("", PathBuf::new(), alternative, 0)?,
            }
        }
        let Walker {
            mut found,
            mut outside,
            ..
        } = walker;
        outside.retain(|dir| !self.ignores(dir));
        outside.sort();
        outside.dedup();
        found.retain(|dir| !dir.split('/').any(|name| name == "node_modules"));
        found.retain(|dir| !self.ignores(dir));
        found.sort();
        found.dedup();
        Ok(Found {
            members: found,
            outside,
        })
    }

    /// glob's `ignore` with the negations, which it reads with `dot`: one
    /// that matches the path or the path with a `/` after it, or one ending
    /// `**` that matches a directory above it with a `/` after.
    fn ignores(&self, relative: &str) -> bool {
        self.negated.iter().flatten().any(|negation| {
            if path_matches(relative, negation, true)
                || path_matches(&format!("{relative}/"), negation, true)
            {
                return true;
            }
            if !matches!(negation.last(), Some(Segment::Globstar)) {
                return false;
            }
            let names: Vec<&str> = relative.split('/').collect();
            (1..names.len())
                .any(|end| path_matches(&format!("{}/", names[..end].join("/")), negation, true))
        })
    }
}

/// Every directory any positive entry of `entries` can name, negations
/// left out so a record covers what they would exclude too: each
/// alternative globbed with dot names allowed, and each alternative's text
/// as a literal path as well. The wide set a resolution record covers.
pub(super) fn every_named_directory(
    root: &ProjectRoot,
    entries: &[String],
) -> io::Result<Vec<String>> {
    let mut walker = Walker::new(root, true);
    for entry in entries {
        let (negate, pattern) = parse_entry(entry);
        if negate {
            continue;
        }
        let alternatives = compile(&pattern)
            .map_err(|error| io::Error::new(error.kind(), format!("package.json: {error}")))?;
        for (text, alternative) in expand_braces(&pattern)?.iter().zip(&alternatives) {
            walker.found.push(text.trim_end_matches('/').to_string());
            if literal_path(alternative).is_none() {
                walker.walk("", PathBuf::new(), alternative, 0)?;
            }
        }
    }
    Ok(walker.found)
}

/// One entry split into whether it negates and the pattern left once the
/// `!` run and a leading `./` or `/` (npm's `/^\.?\/+/`) are stripped.
fn parse_entry(entry: &str) -> (bool, String) {
    let pattern = entry.trim_start_matches('!');
    let bangs = entry.len() - pattern.len();
    let pattern = pattern.replace('\\', "/");
    let undotted = pattern.strip_prefix('.').unwrap_or(&pattern);
    let pattern = if undotted.starts_with('/') {
        undotted.trim_start_matches('/').to_string()
    } else {
        pattern.trim_start_matches('/').to_string()
    };
    (bangs % 2 == 1, pattern)
}

/// `minimatch(path, pattern)` with npm's default options (no `dot`).
fn minimatch(path: &str, pattern: &str) -> io::Result<bool> {
    Ok(compile(pattern)?
        .iter()
        .any(|alternative| path_matches(path, alternative, false)))
}

/// glob's directory walk from the project root. Each directory is reached
/// by its logical path (what npm reports) and its real one (where it is
/// read from), so a member under a symlinked directory is read through
/// the symlink's resolved target.
struct Walker<'a> {
    root: &'a ProjectRoot,
    dot: bool,
    found: Vec<String>,
    outside: Vec<String>,
}

/// A child directory: where it is read from, and whether a symlink led
/// there.
struct Child {
    name: String,
    real: PathBuf,
    linked: bool,
}

impl<'a> Walker<'a> {
    fn new(root: &'a ProjectRoot, dot: bool) -> Self {
        Walker {
            root,
            dot,
            found: Vec::new(),
            outside: Vec::new(),
        }
    }

    /// A pattern with no magic names one path: kept unless a symlink on
    /// the way leads outside the project. A path that is not plain is kept
    /// too, for the caller to refuse.
    fn candidate(&mut self, path: String) {
        if path.is_empty() {
            return;
        }
        match self.root.input_containment(Path::new(&path)) {
            Ok(Containment::Outside) => self.outside.push(path),
            Ok(Containment::Dangling) => {}
            Ok(Containment::Inside) | Err(_) => self.found.push(path),
        }
    }

    fn walk(
        &mut self,
        logical: &str,
        real: PathBuf,
        pattern: &[Segment],
        depth: usize,
    ) -> io::Result<()> {
        let Some((segment, rest)) = pattern.split_first() else {
            if !logical.is_empty() {
                self.found.push(logical.to_string());
            }
            return Ok(());
        };
        if segment.is_empty() {
            return self.walk(logical, real, rest, depth);
        }
        let join = |name: &str| {
            if logical.is_empty() {
                name.to_string()
            } else {
                format!("{logical}/{name}")
            }
        };
        match segment {
            Segment::Globstar => {
                self.walk(logical, real.clone(), rest, depth)?;
                if depth >= MAX_DEPTH {
                    return Ok(());
                }
                for child in self.children(logical, &real)? {
                    if !self.dot && child.name.starts_with('.') {
                        continue;
                    }
                    // glob's `**` matches a symlinked directory but does
                    // not walk below it.
                    let next = if child.linked { rest } else { pattern };
                    self.walk(&join(&child.name), child.real, next, depth + 1)?;
                }
            }
            Segment::Literal(name) => {
                if name == "node_modules" || name == ".." {
                    return Ok(());
                }
                let logical_child = join(name);
                if let Some(child) = self.child(&logical_child, real.join(name))? {
                    self.walk(&logical_child, child.real, rest, depth + 1)?;
                }
            }
            Segment::Magic { .. } => {
                for child in self.children(logical, &real)? {
                    if segment_matches(segment, &child.name, self.dot) {
                        self.walk(&join(&child.name), child.real, rest, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// The child directories of `real`, `node_modules` left out.
    fn children(&mut self, logical: &str, real: &Path) -> io::Result<Vec<Child>> {
        let listing = if real.as_os_str().is_empty() {
            Path::new(".")
        } else {
            real
        };
        let Some(names) = self.root.read_input_dir(listing)? else {
            return Ok(Vec::new());
        };
        let mut children = Vec::new();
        for name in names {
            let Some(name) = name.to_str() else {
                continue;
            };
            if name == "node_modules" {
                continue;
            }
            let logical_child = if logical.is_empty() {
                name.to_string()
            } else {
                format!("{logical}/{name}")
            };
            if let Some(child) = self.child(&logical_child, real.join(name))? {
                children.push(child);
            }
        }
        Ok(children)
    }

    /// `real` as a directory to walk: a directory, or a symlink to one
    /// inside the project (resolved), or nothing. A symlink that leads
    /// outside is noted under its logical path.
    fn child(&mut self, logical: &str, real: PathBuf) -> io::Result<Option<Child>> {
        let name = logical.rsplit('/').next().unwrap_or(logical).to_string();
        Ok(match self.root.entry(&real)? {
            Entry::Directory => Some(Child {
                name,
                real,
                linked: false,
            }),
            Entry::Symlink if self.root.is_input_dir(&real) => {
                match self.root.input_containment(&real)? {
                    Containment::Inside => Some(Child {
                        name,
                        real: self.root.contained_input_path(&real)?,
                        linked: true,
                    }),
                    Containment::Outside => {
                        self.outside.push(logical.to_string());
                        None
                    }
                    Containment::Dangling => None,
                }
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> NpmWorkspaces {
        let entries: Vec<String> = entries.iter().map(|entry| entry.to_string()).collect();
        NpmWorkspaces::new(&entries).unwrap()
    }

    /// The corpus: for each case, the member set npm's map-workspaces
    /// found over the same tree (#694).
    #[test]
    fn members_match_npm_on_the_corpus() {
        let corpus: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("corpus.json")).unwrap();
        let strings = |value: &serde_json::Value| -> Vec<String> {
            value
                .as_array()
                .into_iter()
                .flatten()
                .map(|item| item.as_str().unwrap().to_string())
                .collect()
        };
        let mut failures = Vec::new();
        for case in &corpus {
            let name = case["name"].as_str().unwrap();
            let scratch = crate::kernel::testutil::TempDir::named("npm-ws-corpus");
            let root = scratch.0.join("project");
            std::fs::create_dir_all(&root).unwrap();
            for dir in strings(&case["dirs"]) {
                std::fs::create_dir_all(root.join(&dir)).unwrap();
                std::fs::write(root.join(&dir).join("package.json"), "{}").unwrap();
            }
            for dir in strings(&case["bare"]) {
                std::fs::create_dir_all(root.join(&dir)).unwrap();
            }
            for link in case["links"].as_array().into_iter().flatten() {
                let at = root.join(link[0].as_str().unwrap());
                std::fs::create_dir_all(at.parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(link[1].as_str().unwrap(), at).unwrap();
            }
            let package = serde_json::json!({"name": "root", "workspaces": case["workspaces"]});
            std::fs::write(root.join("package.json"), package.to_string()).unwrap();
            let held = ProjectRoot::open(&root).unwrap();
            let found = crate::tailors::node::resolve::npm_manifest_members(&held)
                .map_err(|error| error.to_string());
            let expected = Ok(strings(&case["expected"]));
            if found != expected {
                failures.push(format!("{name}: ward {found:?}, npm {expected:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The literal-path matcher agrees with the walk for the cases it can
    /// see without a tree.
    #[test]
    fn names_follow_the_walk_rules() {
        let workspaces = list(&["packages/*", "!packages/b", "./tools/{x,y}", "/abs"]);
        assert!(workspaces.names("packages/a"));
        assert!(!workspaces.names("packages/b"));
        assert!(workspaces.names("tools/x") && workspaces.names("tools/y"));
        assert!(workspaces.names("abs"));
        assert!(!workspaces.names("packages/.hidden"));
        assert!(!workspaces.names("packages/node_modules"));
        assert!(list(&[".config/*"]).names(".config/a"));
        assert!(list(&["packages/**"]).names("packages"));
        assert!(list(&["packages/@(a|b)"]).names("packages/b"));
        assert!(!list(&["packages/*", "!packages/b/", "packages/b"]).names("packages/b"));
        let spliced = list(&["packages/*", "!packages/a", "!packages/{a,b}", "packages/a"]);
        assert!(!spliced.names("packages/a") && !spliced.names("packages/b"));
        assert!(spliced.names("packages/c"));
    }

    /// A symlinked member that leads outside the project is left out and
    /// named, never walked (#694).
    #[test]
    fn a_member_symlinked_outside_the_project_is_left_out_and_named() {
        let scratch = crate::kernel::testutil::TempDir::named("npm-ws-outside");
        let root = scratch.0.join("project");
        for dir in ["packages/a", "../elsewhere/lib"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("package.json"), "{}").unwrap();
        }
        std::os::unix::fs::symlink("../../elsewhere/lib", root.join("packages/ext")).unwrap();
        std::os::unix::fs::symlink("../elsewhere/lib", root.join("direct")).unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let found = list(&["packages/*", "direct"]).directories(&held).unwrap();
        assert_eq!(found.members, ["packages/a"]);
        assert_eq!(found.outside, ["direct", "packages/ext"]);
    }
}
