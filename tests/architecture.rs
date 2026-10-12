//! The layering rules of docs/human/ARCHITECTURE.md ("Layering rules"),
//! enforced by a source scan: `commands → tailors → comforter → kernel`, one
//! direction only, and no tailor names another tailor. A command file does
//! not name a tailor's module or spell its name as a string either (the
//! tokens scan below).
//!
//! The scans read the crate as rustc does: the files its module tree
//! reaches from the crate roots, each with its module path, which decides
//! its layer. Test code (whatever cannot compile without `cfg(test)`,
//! found by attribute wherever it sits, or a file only a test-only `mod`
//! reaches) is exempt: tests may wire the whole crate together. Size budgets (layering rule 5) are a
//! ratchet against `tests/size_baseline.txt`: what is over budget today may
//! shrink, nothing may grow or newly cross a budget.
//!
//! Five housekeeping rules are enforced the same way: a test that sets
//! `GREYWARD_STORE` holds `STORE_ENV_LOCK`, comments describe code rather
//! than cite plan documents or review rounds, narration goes through
//! `kernel::ui` rather than a raw stderr write, HTTP goes through
//! `kernel::fetch` rather than a raw `ureq` call, and `docs/agent/` holds
//! only its two files.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/` and `tests/`, as (repo-relative path, text).
fn all_sources() -> Vec<(String, String)> {
    let root = repo();
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    files
        .into_iter()
        .map(|file| {
            let relative = file
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&file).unwrap();
            (relative, text)
        })
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out.sort();
}

/// A source file of one of the package's crates, reached from the crate's
/// root through its `mod` declarations, the way the compiler finds it.
#[derive(Debug)]
struct Module {
    /// Repo-relative: `src/kernel/gc/mod.rs`.
    relative: String,
    /// Whether it belongs to the library (`src/lib.rs`), not a binary.
    library: bool,
    /// Its module path from the crate root: `["kernel", "gc"]`.
    path: Vec<String>,
    /// Whether it is compiled only with `test` on: its `mod` declaration,
    /// an inline module around that, a module above it, or the file itself
    /// (`#![cfg(test)]`) is marked test-only (`marks_test_code`).
    test_only: bool,
    text: String,
}

/// Every module file of the package's crates. Which layer a file is in,
/// and whether it is test code, come from the module tree rather than the
/// folder it sits in: `#[path = "../compat.rs"] mod compat;` in
/// `kernel/mod.rs` is a kernel module, and a file declared by
/// `#[cfg(test)] mod helper;` is test code wherever it lives.
fn crate_modules() -> &'static [Module] {
    static MODULES: std::sync::OnceLock<Vec<Module>> = std::sync::OnceLock::new();
    MODULES.get_or_init(|| module_tree(&repo(), crate_roots()))
}

/// The package's crate roots, as (file, is the library): `src/lib.rs`,
/// and each binary: those `[[bin]]` sections of Cargo.toml name, `src/main.rs`
/// and `src/bin/`.
fn crate_roots() -> Vec<(PathBuf, bool)> {
    let root = repo();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let mut bins = vec![root.join("src/main.rs")];
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if let Some(value) = line
            .strip_prefix("path")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .filter(|_| in_bin)
        {
            bins.push(root.join(value.trim().trim_matches('"')));
        }
    }
    if let Ok(entries) = fs::read_dir(root.join("src/bin")) {
        for entry in entries {
            let path = entry.unwrap().path();
            bins.push(if path.is_dir() {
                path.join("main.rs")
            } else {
                path
            });
        }
    }
    bins.sort();
    bins.dedup();
    let mut roots = vec![(root.join("src/lib.rs"), true)];
    roots.extend(
        bins.into_iter()
            .filter(|bin| bin.extension().is_some_and(|ext| ext == "rs") && bin.exists())
            .map(|bin| (bin, false)),
    );
    roots
}

/// The module files reached from `roots`, with paths relative to `base`.
/// A file reached more than once with the same module path (a module
/// declared under two cfgs) is one entry, test-only only if every
/// declaration reaching it is.
fn module_tree(base: &Path, roots: Vec<(PathBuf, bool)>) -> Vec<Module> {
    let mut found = std::collections::BTreeMap::<(String, Vec<String>), Module>::new();
    // (file, whether it is a mod-rs file, module path, test-only, library)
    let mut pending: Vec<(PathBuf, bool, Vec<String>, bool, bool)> = roots
        .into_iter()
        .map(|(file, library)| (file, true, Vec::new(), false, library))
        .collect();
    while let Some((file, mod_rs, path, test_only, library)) = pending.pop() {
        let relative = file
            .strip_prefix(base)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let key = (relative.clone(), path.clone());
        if found
            .get(&key)
            .is_some_and(|seen| !seen.test_only || test_only)
        {
            continue;
        }
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{relative}, declared as module {path:?}: {error}"));
        let parsed = parse(&text);
        let test_only = test_only || marks_test_code(&parsed.attrs);
        let dir = file.parent().unwrap().to_path_buf();
        // A mod-rs file (a crate root, a `mod.rs`, or a file a `#[path]`
        // names) keeps its children beside it; `a/b.rs` keeps them in `a/b/`.
        let children = if mod_rs {
            dir.clone()
        } else {
            dir.join(file.file_stem().unwrap())
        };
        let mut declared = Vec::new();
        declared_modules(
            &parsed.items,
            &dir,
            &children,
            false,
            &path,
            test_only,
            &mut declared,
        );
        pending.extend(
            declared
                .into_iter()
                .map(|(file, mod_rs, path, test_only)| (file, mod_rs, path, test_only, library)),
        );
        found.insert(
            key,
            Module {
                relative,
                library,
                path,
                test_only,
                text,
            },
        );
    }
    found.into_values().collect()
}

/// The files `items` declare as modules (`mod x;`), here and inside inline
/// modules, as (file, whether it is mod-rs, module path, test-only).
/// `file_dir` is the folder of the file the items are in, `dir` the folder
/// its children live in (with the inline modules around `items` added).
/// A `#[path]` is relative to `file_dir` at the file's top level and to
/// `dir` inside an inline module, as rustc reads it.
fn declared_modules(
    items: &[syn::Item],
    file_dir: &Path,
    dir: &Path,
    inline: bool,
    path: &[String],
    test_only: bool,
    out: &mut Vec<(PathBuf, bool, Vec<String>, bool)>,
) {
    use syn::ext::IdentExt;
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let name = module.ident.unraw().to_string();
        let mut child = path.to_vec();
        child.push(name.clone());
        let test_only = test_only || marks_test_code(&module.attrs);
        let named = path_attribute(&module.attrs).map(|named| {
            lexical(&if inline {
                dir.join(named)
            } else {
                file_dir.join(named)
            })
        });
        match (&module.content, named) {
            (Some((_, items)), named) => declared_modules(
                items,
                file_dir,
                &named.unwrap_or_else(|| dir.join(&name)),
                true,
                &child,
                test_only,
                out,
            ),
            (None, Some(file)) => out.push((file, true, child, test_only)),
            (None, None) if dir.join(format!("{name}.rs")).exists() => {
                out.push((dir.join(format!("{name}.rs")), false, child, test_only))
            }
            (None, None) => out.push((dir.join(&name).join("mod.rs"), true, child, test_only)),
        }
    }
}

/// `path` with `.` and `..` resolved as text: `src/kernel/../compat.rs`
/// is `src/compat.rs`.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// The value of a `#[path = "…"]` attribute.
fn path_attribute(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| match &attr.meta {
        syn::Meta::NameValue(pair) if pair.path.is_ident("path") => match &pair.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Some(value.value()),
            _ => None,
        },
        _ => None,
    })
}

/// The production files of the package's crates (every module file not
/// test-only), each file once.
fn production_sources() -> Vec<&'static Module> {
    let mut seen = std::collections::BTreeSet::new();
    crate_modules()
        .iter()
        .filter(|module| !module.test_only && seen.insert(module.relative.as_str()))
        .collect()
}

/// `production_sources` as (repo-relative path, text).
fn production_files() -> Vec<(String, String)> {
    production_sources()
        .into_iter()
        .map(|module| (module.relative.clone(), module.text.clone()))
        .collect()
}

/// The scans read the module tree, so a file no crate root reaches would
/// go unchecked: every `.rs` file under `src/` must be a module.
#[test]
fn every_source_file_is_a_module() {
    let root = repo();
    let mut files = Vec::new();
    rust_files(&src(), &mut files);
    let reached: std::collections::BTreeSet<&str> = crate_modules()
        .iter()
        .map(|module| module.relative.as_str())
        .collect();
    let unreached: Vec<String> = files
        .iter()
        .map(|file| {
            file.strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|relative| !reached.contains(relative.as_str()))
        .collect();
    assert!(
        unreached.is_empty(),
        "files under src/ that no crate root declares as a module:\n  {}",
        unreached.join("\n  ")
    );
    // The crate root itself is production code, and so is the kernel.
    let kernel = crate_modules()
        .iter()
        .find(|module| module.relative == "src/kernel/mod.rs")
        .unwrap();
    assert!(kernel.library && kernel.path == ["kernel"] && !kernel.test_only);
}

/// The module tree follows `#[path]` in every position, carries test-only
/// status down to every file below a test-only declaration, and the layer a
/// file is in is the module it is, not the folder.
#[test]
fn the_module_tree_is_read_as_rustc_reads_it() {
    let base = std::env::temp_dir().join(format!("greyward-arch-modules-{}", std::process::id()));
    let files = [
        (
            "src/lib.rs",
            "pub mod kernel;\nmod tailors;\n#[cfg(test)]\nmod helper;\n",
        ),
        (
            "src/kernel/mod.rs",
            "#[path = \"../compat.rs\"]\nmod compat;\nmod inner {\n    #[path = \"deep.rs\"]\n    mod deep;\n}\n",
        ),
        ("src/compat.rs", "mod child;\nfn f() { crate::tailors::x(); }\n"),
        ("src/child.rs", ""),
        ("src/kernel/inner/deep.rs", ""),
        (
            "src/tailors.rs",
            "#[path = \"elsewhere.rs\"]\nmod top;\nmod inline {\n    #[path = \"nested.rs\"]\n    mod nested;\n}\n",
        ),
        ("src/elsewhere.rs", ""),
        ("src/tailors/inline/nested.rs", ""),
        ("src/helper.rs", "mod below;\n"),
        ("src/helper/below.rs", ""),
        ("src/main.rs", "fn main() {}\n"),
    ];
    for (file, text) in files {
        let path = base.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let modules = module_tree(
        &base,
        vec![
            (base.join("src/lib.rs"), true),
            (base.join("src/main.rs"), false),
        ],
    );
    fs::remove_dir_all(&base).unwrap();
    let mut read: Vec<(String, String, bool, bool)> = modules
        .iter()
        .map(|module| {
            (
                module.relative.clone(),
                module.path.join("::"),
                module.library,
                module.test_only,
            )
        })
        .collect();
    read.sort();
    let expected: Vec<(String, String, bool, bool)> = [
        ("src/child.rs", "kernel::compat::child", true, false),
        ("src/compat.rs", "kernel::compat", true, false),
        ("src/elsewhere.rs", "tailors::top", true, false),
        ("src/helper.rs", "helper", true, true),
        ("src/helper/below.rs", "helper::below", true, true),
        (
            "src/kernel/inner/deep.rs",
            "kernel::inner::deep",
            true,
            false,
        ),
        ("src/kernel/mod.rs", "kernel", true, false),
        ("src/lib.rs", "", true, false),
        ("src/main.rs", "", false, false),
        ("src/tailors.rs", "tailors", true, false),
        (
            "src/tailors/inline/nested.rs",
            "tailors::inline::nested",
            true,
            false,
        ),
    ]
    .into_iter()
    .map(|(file, path, library, test_only)| {
        (file.to_string(), path.to_string(), library, test_only)
    })
    .collect();
    assert_eq!(read, expected);
    // `compat.rs` sits outside `src/kernel/` and is held to the kernel's rules.
    let compat = modules
        .iter()
        .find(|module| module.relative == "src/compat.rs")
        .unwrap();
    let (found, _) = layer_violations("compat.rs", &compat.path, &compat.text, &[], &[]);
    assert_eq!(found, ["compat.rs:2: crate::tailors::x"]);
}

/// Where a path a file names leads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Root {
    /// Into this crate, from its root.
    Crate,
    /// Anywhere else: an extern crate (`::zip`, `std`, a name only an
    /// extern crate binds), or a name nothing in scope binds (a local item,
    /// a type parameter, an enum).
    Other,
}

/// What a name, or a path being read, stands for before it is resolved.
#[derive(Clone, Debug)]
enum Target {
    /// A path from a root: `crate::a`, `self::a`, `super::a`, a child
    /// `mod a`, or `::zip`.
    Rooted(Root, Vec<String>),
    /// A path starting with a name to resolve where it is written:
    /// `t::python` after `use crate::tailors as t;`.
    Relative(String, Vec<String>),
}

/// `target` with `segment` added, in `module`: a leading `crate`, `self`
/// or `super` (and `super` after it) moves the root, `self` after a prefix
/// names the prefix.
fn extend(target: Option<Target>, segment: &str, module: &[String]) -> Target {
    match (target, segment) {
        (None, "crate") => Target::Rooted(Root::Crate, Vec::new()),
        (None, "self") => Target::Rooted(Root::Crate, module.to_vec()),
        (None, "super") => Target::Rooted(
            Root::Crate,
            module[..module.len().saturating_sub(1)].to_vec(),
        ),
        (None, name) => Target::Relative(name.to_string(), Vec::new()),
        (Some(Target::Rooted(Root::Crate, mut path)), "super") => {
            path.pop();
            Target::Rooted(Root::Crate, path)
        }
        (Some(target), "self") => target,
        (Some(Target::Rooted(root, mut path)), name) => {
            path.push(name.to_string());
            Target::Rooted(root, path)
        }
        (Some(Target::Relative(first, mut path)), name) => {
            path.push(name.to_string());
            Target::Relative(first, path)
        }
    }
}

/// The leaves of a `use` tree in `module`: each name it binds (`None` for a
/// glob) with the path it binds it to, and where it is written.
fn use_leaves(
    tree: &syn::UseTree,
    prefix: Option<Target>,
    module: &[String],
    out: &mut Vec<(Option<String>, Target, Position)>,
) {
    use syn::ext::IdentExt;
    match tree {
        syn::UseTree::Path(path) => use_leaves(
            &path.tree,
            Some(extend(prefix, &path.ident.unraw().to_string(), module)),
            module,
            out,
        ),
        syn::UseTree::Name(name) => {
            let ident = name.ident.unraw().to_string();
            let target = extend(prefix, &ident, module);
            let local = match (&target, ident.as_str()) {
                (Target::Rooted(_, path), "self" | "crate" | "super") => {
                    path.last().cloned().unwrap_or_default()
                }
                (Target::Relative(first, path), "self") => path.last().unwrap_or(first).clone(),
                _ => ident,
            };
            out.push((Some(local), target, position(name.ident.span().start())));
        }
        syn::UseTree::Rename(rename) => out.push((
            Some(rename.rename.unraw().to_string()),
            extend(prefix, &rename.ident.unraw().to_string(), module),
            position(rename.ident.span().start()),
        )),
        syn::UseTree::Glob(glob) => {
            if let Some(prefix) = prefix {
                out.push((None, prefix, position(glob.star_token.span.start())));
            }
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .for_each(|tree| use_leaves(tree, prefix.clone(), module, out)),
    }
}

/// The names one module or block binds, from its production items: what
/// each `use` binds, each glob it imports, each child `mod` and each
/// `extern crate`.
#[derive(Default)]
struct Scope {
    /// A module's scope: no name bound outside it is seen inside it.
    module: bool,
    bindings: Vec<(String, Target)>,
    globs: Vec<Target>,
}

fn scope_of<'a>(
    items: impl IntoIterator<Item = &'a syn::Item>,
    module: &[String],
    is_module: bool,
) -> Scope {
    use syn::ext::IdentExt;
    let mut scope = Scope {
        module: is_module,
        ..Scope::default()
    };
    for item in items {
        if marks_test_code(item.attrs()) {
            continue;
        }
        match item {
            syn::Item::Use(declaration) => {
                let mut leaves = Vec::new();
                let root = declaration
                    .leading_colon
                    .map(|_| Target::Rooted(Root::Other, Vec::new()));
                use_leaves(&declaration.tree, root, module, &mut leaves);
                for (local, target, _) in leaves {
                    match local {
                        Some(local) => scope.bindings.push((local, target)),
                        None => scope.globs.push(target),
                    }
                }
            }
            syn::Item::Mod(child) => {
                let name = child.ident.unraw().to_string();
                let path = [module, std::slice::from_ref(&name)].concat();
                scope
                    .bindings
                    .push((name, Target::Rooted(Root::Crate, path)));
            }
            syn::Item::ExternCrate(krate) => {
                let name = krate.ident.unraw().to_string();
                let target = if name == "self" {
                    Target::Rooted(Root::Crate, Vec::new())
                } else {
                    Target::Rooted(Root::Other, vec![name.clone()])
                };
                let local = krate
                    .rename
                    .as_ref()
                    .map_or(name, |(_, rename)| rename.unraw().to_string());
                scope.bindings.push((local, target));
            }
            _ => {}
        }
    }
    scope
}

/// One path a file names, resolved.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Named {
    at: Position,
    /// The module it is written in: the file's, and inline modules inside.
    module: Vec<String>,
    root: Root,
    path: Vec<String>,
}

/// Every path one parsed file names, resolved the way the compiler
/// resolves names: from the module or block it is written in, through the
/// `use` declarations, child modules and `extern crate`s in scope there
/// (an inner block's shadowing an outer one's, a module seeing none of the
/// modules around it), following a binding of a binding to the end, and
/// trying each glob import for a name nothing binds. Paths in code, in
/// `use` declarations, and in macro input read as code; tokens where the
/// input is not code (`if_chain!`).
struct PathScan<'a> {
    module: Vec<String>,
    scopes: Vec<Scope>,
    named: Vec<Named>,
    rules: UnreadRules<'a>,
}

impl PathScan<'_> {
    /// What `name` stands for at scope `top`: its binding (resolved in turn,
    /// never twice), or, bound nowhere, itself and each glob's path with it.
    fn resolve_name(
        &self,
        name: &str,
        top: usize,
        seen: &[(usize, String)],
    ) -> Vec<(Root, Vec<String>)> {
        let bottom = (0..=top)
            .rev()
            .find(|&i| self.scopes[i].module)
            .unwrap_or(0);
        for i in (bottom..=top).rev() {
            if let Some((_, target)) = self.scopes[i]
                .bindings
                .iter()
                .find(|(local, _)| local == name)
            {
                let key = (i, name.to_string());
                if seen.contains(&key) {
                    return Vec::new();
                }
                return self.resolve(target, i, &[seen, &[key]].concat());
            }
        }
        let mut out = vec![(Root::Other, vec![name.to_string()])];
        for i in (bottom..=top).rev() {
            for (index, glob) in self.scopes[i].globs.iter().enumerate() {
                let key = (i, format!("*{index}"));
                if seen.contains(&key) {
                    continue;
                }
                for (root, mut path) in self.resolve(glob, i, &[seen, &[key]].concat()) {
                    if root == Root::Crate {
                        path.push(name.to_string());
                        out.push((root, path));
                    }
                }
            }
        }
        out
    }

    fn resolve(
        &self,
        target: &Target,
        top: usize,
        seen: &[(usize, String)],
    ) -> Vec<(Root, Vec<String>)> {
        match target {
            Target::Rooted(root, path) => vec![(*root, path.clone())],
            Target::Relative(name, rest) => self
                .resolve_name(name, top, seen)
                .into_iter()
                .map(|(root, path)| (root, [path, rest.clone()].concat()))
                .collect(),
        }
    }

    fn record(&mut self, at: Position, target: &Target) {
        let top = self.scopes.len() - 1;
        for (root, path) in self.resolve(target, top, &[]) {
            if !path.is_empty() {
                self.named.push(Named {
                    at,
                    module: self.module.clone(),
                    root,
                    path,
                });
            }
        }
    }

    /// A path written as `segments` (after `::` when `rooted`). A single
    /// name that is not `crate`, `self` or `super` names no module, and
    /// `Self` is the type at hand.
    fn path(&mut self, at: Position, rooted: bool, segments: &[String]) {
        if segments.is_empty() || segments[0] == "Self" {
            return;
        }
        let start = rooted.then(|| Target::Rooted(Root::Other, Vec::new()));
        let target = segments
            .iter()
            .fold(start, |target, segment| {
                Some(extend(target, segment, &self.module))
            })
            .unwrap();
        if matches!(&target, Target::Relative(_, rest) if rest.is_empty()) {
            return;
        }
        self.record(at, &target);
    }

    /// Paths in tokens that are not code: each run of `name :: name …`,
    /// rooted when a `::` opens it.
    fn token_paths(&mut self, tokens: proc_macro2::TokenStream) {
        use proc_macro2::{Spacing, TokenTree};
        let mut flat = Vec::new();
        flatten(tokens, &mut flat);
        let ident = |at: usize| match flat.get(at) {
            Some(Some(TokenTree::Ident(ident))) => Some(ident.clone()),
            _ => None,
        };
        let separator = |at: usize| {
            matches!(flat.get(at), Some(Some(TokenTree::Punct(p))) if p.as_char() == ':' && p.spacing() == Spacing::Joint)
                && matches!(flat.get(at + 1), Some(Some(TokenTree::Punct(p))) if p.as_char() == ':')
        };
        let mut at = 0;
        while at < flat.len() {
            let Some(first) = ident(at) else {
                at += 1;
                continue;
            };
            let after_separator = at >= 2 && separator(at - 2);
            // `::name` opens a path unless a name or `>` stands before it.
            let before = at.checked_sub(3).and_then(|index| flat.get(index));
            let rooted = after_separator
                && !matches!(before, Some(Some(TokenTree::Ident(_))))
                && !matches!(before, Some(Some(TokenTree::Punct(p))) if p.as_char() == '>');
            let mut segments = vec![first.to_string()];
            let mut next = at + 1;
            while separator(next) {
                let Some(segment) = ident(next + 2) else {
                    break;
                };
                segments.push(segment.to_string());
                next += 3;
            }
            if !after_separator || rooted {
                self.path(position(first.span().start()), rooted, &segments);
            }
            at = next;
        }
    }

    fn in_scope(&mut self, scope: Scope, visit: impl FnOnce(&mut Self)) {
        self.scopes.push(scope);
        visit(self);
        self.scopes.pop();
    }

    /// Statements a macro holds, in a block of their own.
    fn statements(&mut self, statements: &[syn::Stmt]) {
        let items = statements.iter().filter_map(|stmt| match stmt {
            syn::Stmt::Item(item) => Some(item),
            _ => None,
        });
        let scope = scope_of(items, &self.module, false);
        self.in_scope(scope, |scan| {
            statements.iter().for_each(|stmt| scan.visit_stmt(stmt))
        });
    }
}

impl<'ast> Visit<'ast> for PathScan<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        use syn::ext::IdentExt;
        let Some((_, items)) = &node.content else {
            return visit::visit_item_mod(self, node);
        };
        self.module.push(node.ident.unraw().to_string());
        let scope = scope_of(items, &self.module, true);
        self.in_scope(scope, |scan| visit::visit_item_mod(scan, node));
        self.module.pop();
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        let items = node.stmts.iter().filter_map(|stmt| match stmt {
            syn::Stmt::Item(item) => Some(item),
            _ => None,
        });
        let scope = scope_of(items, &self.module, false);
        self.in_scope(scope, |scan| visit::visit_block(scan, node));
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut leaves = Vec::new();
        let root = node
            .leading_colon
            .map(|_| Target::Rooted(Root::Other, Vec::new()));
        use_leaves(&node.tree, root, &self.module, &mut leaves);
        for (_, target, at) in leaves {
            self.record(at, &target);
        }
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        use syn::ext::IdentExt;
        let name = node.ident.unraw().to_string();
        self.path(position(node.ident.span().start()), name != "self", &[name]);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        use syn::ext::IdentExt;
        let segments: Vec<String> = node
            .segments
            .iter()
            .map(|segment| segment.ident.unraw().to_string())
            .collect();
        self.path(
            position(node.span().start()),
            node.leading_colon.is_some(),
            &segments,
        );
        visit::visit_path(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        let outer = self.rules.entering(node);
        visit::visit_item_macro(self, node);
        self.rules.name = outer;
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.visit_path(&node.path);
        match macro_input(node) {
            MacroInput::Opaque => self.token_paths(node.tokens.clone()),
            MacroInput::Statements(statements) => self.statements(&statements),
            MacroInput::Rules(rules) => {
                for rule in rules {
                    match rule {
                        Ok(statements) => self.statements(&statements),
                        Err((at, tokens)) => {
                            if self.rules.read_as_tokens(at) {
                                self.token_paths(tokens);
                            }
                        }
                    }
                }
            }
            input => walk_macro_input(self, &input),
        }
    }
}

/// The production paths `text` names, read as the module `module`, and
/// the `macro_rules!` rules in it no context reads (`UnreadRules`).
/// `relative` is the file under `src/`; `opaque_rules` the rules it may
/// read as tokens instead.
fn named_paths(
    relative: &str,
    text: &str,
    module: &[String],
    opaque_rules: &[(&str, &str, &str)],
) -> (Vec<Named>, Vec<String>) {
    let file = parse(text);
    let tests = test_spans(&file);
    let in_test = |at: &Position| tests.iter().any(|(start, end)| (*start..*end).contains(at));
    let path = format!("src/{relative}");
    let mut scan = PathScan {
        module: module.to_vec(),
        scopes: vec![scope_of(&file.items, module, true)],
        named: Vec::new(),
        rules: UnreadRules::new(&path, opaque_rules),
    };
    scan.visit_file(&file);
    // A path read twice (a rule read in two contexts) is one path.
    let mut named: Vec<Named> = scan
        .named
        .into_iter()
        .filter(|named| !in_test(&named.at))
        .collect();
    named.sort();
    named.dedup();
    let unread = scan
        .rules
        .findings
        .iter()
        .filter(|(at, _, _)| !in_test(at))
        .map(|(at, name, _)| unread_rule_message(relative, at.0, name))
        .collect();
    (named, unread)
}

/// The module path a file under `src/` has when the module tree follows
/// the folders: `kernel/gc/mod.rs` is `kernel::gc`, `kernel/gc/sweep.rs`
/// is `kernel::gc::sweep`, and the crate roots `lib.rs` and `main.rs` are
/// the empty path. Fixtures stand at such a path.
fn module_path(relative: &Path) -> Vec<String> {
    let mut segments: Vec<String> = relative
        .with_extension("")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    if matches!(
        segments.last().map(String::as_str),
        Some("mod" | "lib" | "main")
    ) {
        segments.pop();
    }
    segments
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The one-way exceptions, each documented where it lives. Adding to this
/// list is a shared-layer review (layering rule 2).
const ALLOWED: &[(&str, &str, &str)] = &[
    // The dependency-spec validator lives with the command that owns the
    // spec grammar; cli calls it for argv validation only.
    (
        "cli/parse.rs",
        "commands::deps::validate_spec",
        "argv validation",
    ),
    // Likewise `ward x`'s argument rules, owned by its command.
    (
        "cli/x.rs",
        "commands::x::request_version",
        "argv validation",
    ),
    ("cli/x.rs", "commands::x::split_version", "argv validation"),
    (
        "cli/x.rs",
        "commands::x::validate_from_bin",
        "argv validation",
    ),
    (
        "cli/x.rs",
        "commands::x::validate_package",
        "argv validation",
    ),
];

/// Whether `path`, named in `relative`, is one of the listed exceptions.
/// The match is exact: `tailors::Tailor` allows the trait and nothing that
/// merely starts with its name (`tailors::TailorRegistry`, `tailors::Tailor::x`).
fn allowed(relative: &str, path: &[String]) -> bool {
    let joined = path.join("::");
    ALLOWED
        .iter()
        .any(|(file, exact, _)| relative == *file && joined == *exact)
}

/// The paths `text`, the library module `module` in `relative` (under
/// `src/`), names against the layering rules, and how many crate paths it
/// named in all. The layer is the module a path is written in: its first
/// segment, and for a tailor's code the second is the tailor.
/// `tailor_dirs` are the tailors (the modules under `tailors`).
fn layer_violations(
    relative: &str,
    module: &[String],
    text: &str,
    tailor_dirs: &[String],
    opaque_rules: &[(&str, &str, &str)],
) -> (Vec<String>, usize) {
    let (named, mut violations) = named_paths(relative, text, module, opaque_rules);
    let mut seen = 0;
    for Named {
        at, module, path, ..
    } in named.iter().filter(|named| named.root == Root::Crate)
    {
        seen += 1;
        let target = path[0].as_str();
        let tailor = |path: &[String]| {
            path.first().is_some_and(|first| first == "tailors")
                && path.get(1).is_some_and(|name| tailor_dirs.contains(name))
        };
        let forbidden = match module.first().map(String::as_str) {
            Some("kernel") => matches!(target, "tailors" | "comforter" | "commands" | "cli"),
            Some("comforter") => matches!(target, "tailors" | "commands" | "cli"),
            // A tailor's code names no other tailor: tailors::<other>::…
            // The layer's own root (the registry) is no tailor.
            Some("tailors") => {
                matches!(target, "commands" | "cli")
                    || (tailor(module) && tailor(path) && module[1] != path[1])
            }
            // A command reaches a tailor through the trait and the
            // registry, never by its module: tailors::<name>::… (rule 3).
            Some("commands") => tailor(path),
            Some("cli") => matches!(target, "tailors" | "comforter" | "kernel" | "commands"),
            _ => false,
        };
        if forbidden && !allowed(relative, path) {
            violations.push(format!("{relative}:{}: crate::{}", at.0, path.join("::")));
        }
    }
    (violations, seen)
}

/// The tailors: the modules under `tailors` that are folders.
fn tailor_dirs() -> Vec<String> {
    fs::read_dir(src().join("tailors"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
        .collect()
}

#[test]
fn layers_point_one_way() {
    let dirs = tailor_dirs();
    let mut violations = Vec::new();
    let mut seen = 0;
    for module in crate_modules() {
        if !module.library || module.test_only {
            continue;
        }
        let relative = module.relative.trim_start_matches("src/");
        let (found, paths) = layer_violations(
            relative,
            &module.path,
            &module.text,
            &dirs,
            OPAQUE_MACRO_RULES,
        );
        violations.extend(found);
        seen += paths;
    }
    // Positive control: the crate names itself thousands of times. A scan
    // that stops finding paths (a parser regression, a renamed prefix)
    // fails here instead of passing with nothing to check.
    assert!(
        seen >= 1000,
        "the layering scan found only {seen} crate paths under src/; it is passing vacuously"
    );
    assert!(
        violations.is_empty(),
        "layering violations (docs/human/ARCHITECTURE.md, layering rule 1):\n  {}",
        violations.join("\n  ")
    );
}

/// The kernel branches on no ecosystem by name: a `match` or `matches!`
/// pattern holding a tailor's id or lock ecosystem, or a comparison with
/// one, means an eighth ecosystem would have to edit the kernel. What an
/// ecosystem knows goes through a `Tailor` method or a table the tailors
/// install (#255).
///
/// A comparison listed in `ECOSYSTEM_COMPARISONS` is the one exception,
/// and every entry must occur exactly once, so a fixed site leaves no stale
/// permission behind and a copied site needs its own review.
#[test]
fn the_kernel_branches_on_no_ecosystem_name() {
    let mut names: Vec<&str> = greyward::tailors::registry()
        .iter()
        .flat_map(|tailor| [tailor.id(), tailor.lock_ecosystem()])
        .collect();
    names.sort();
    names.dedup();
    let mut violations = Vec::new();
    let mut allowed_counts = vec![0; ECOSYSTEM_COMPARISONS.len()];
    let kernel = crate_modules().iter().filter(|module| {
        module.library && !module.test_only && module.path.first().is_some_and(|m| m == "kernel")
    });
    for module in kernel {
        violations.extend(ecosystem_violations(
            module.relative.trim_start_matches("src/"),
            &module.text,
            &names,
            &mut allowed_counts,
            OPAQUE_MACRO_RULES,
        ));
    }
    assert!(
        violations.is_empty(),
        "the kernel matches on an ecosystem name; give the tailors a method or a table instead:\n  {}",
        violations.join("\n  ")
    );
    let allowances = ecosystem_allowance_violations(&allowed_counts);
    assert!(
        allowances.is_empty(),
        "ECOSYSTEM_COMPARISONS must allow exactly one occurrence per entry; remove stale entries or review copied sites:\n  {}",
        allowances.join("\n  ")
    );
}

/// The ecosystem names `text`, the kernel file `relative` (under `src/`),
/// branches on, and its `macro_rules!` rules no context reads.
/// `opaque_rules` are the rules it may read as tokens instead.
fn ecosystem_violations(
    relative: &str,
    text: &str,
    names: &[&str],
    allowed_counts: &mut [usize],
    opaque_rules: &[(&str, &str, &str)],
) -> Vec<String> {
    let file = parse(text);
    let tests = test_spans(&file);
    let in_test = |at: &Position| tests.iter().any(|(start, end)| (*start..*end).contains(at));
    let path = format!("src/{relative}");
    let mut scan = EcosystemScan {
        names,
        functions: Vec::new(),
        allowing: None,
        sites: Vec::new(),
        rules: UnreadRules::new(&path, opaque_rules),
    };
    scan.visit_file(&file);
    scan.sites.sort();
    scan.sites.dedup();
    let mut violations = Vec::new();
    for (at, name, allowance) in scan.sites {
        if in_test(&at) {
            continue;
        }
        match allowance {
            Some(index) => allowed_counts[index] += 1,
            None => violations.push(format!("{relative}:{}: \"{name}\"", at.0)),
        }
    }
    for (at, name, _) in &scan.rules.findings {
        if !in_test(at) {
            violations.push(unread_rule_message(relative, at.0, name));
        }
    }
    violations
}

fn ecosystem_allowance_violations(allowed_counts: &[usize]) -> Vec<String> {
    ECOSYSTEM_COMPARISONS
        .iter()
        .zip(allowed_counts)
        .filter(|(_, count)| **count != 1)
        .map(|((path, function, condition, _), count)| {
            format!("{path}: fn {function}: if {condition} (found {count}, expected 1)")
        })
        .collect()
}

/// The kernel's reviewed comparisons with an ecosystem name: the file, the
/// function, the whole condition of the `if` it is (compared as parsed, so
/// however it is spread over lines or commented), and why it is not a
/// branch an eighth ecosystem would have to edit.
const ECOSYSTEM_COMPARISONS: &[(&str, &str, &str, &str)] = &[(
    "src/kernel/provider/cpython.rs",
    "row",
    "selected.ecosystem != \"python\"",
    "the CPython provider refuses a selection from another ecosystem's \
     section: a guard on its own input, not a branch per ecosystem",
)];

/// Methods that compare their receiver with their argument.
const COMPARING_METHODS: &[&str] = &["eq", "ne"];

/// Macros that compare their first two arguments.
const COMPARING_MACROS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "debug_assert_eq",
    "debug_assert_ne",
];

/// Macros that take an expression, then a pattern with an optional guard.
const PATTERN_MACROS: &[&str] = &["matches", "assert_matches", "debug_assert_matches"];

/// The ecosystem names one parsed file branches on: a string literal in
/// any pattern (`match` arms, `if let`, `while let`, `let … else`, a
/// `matches!`), or an operand of `==`, `!=`, `.eq()`, `.ne()` or
/// `assert_eq!`. An operand is seen through parentheses, references and
/// constructor calls (`Some("go") == x`). A guard is an expression, not a
/// pattern, and a literal anywhere else is data.
struct EcosystemScan<'a> {
    names: &'a [&'a str],
    /// The functions around the node being visited, innermost last.
    functions: Vec<String>,
    /// The `ECOSYSTEM_COMPARISONS` entry the condition being visited is.
    allowing: Option<usize>,
    /// (where, name, the entry allowing it).
    sites: Vec<(Position, &'a str, Option<usize>)>,
    /// The file's `macro_rules!` rules no context reads.
    rules: UnreadRules<'a>,
}

impl EcosystemScan<'_> {
    fn literal(&mut self, lit: &syn::LitStr) {
        let value = lit.value();
        if let Some(name) = self.names.iter().copied().find(|name| *name == value) {
            self.sites
                .push((position(lit.span().start()), name, self.allowing));
        }
    }

    /// The ecosystem literals a comparison operand is, through parentheses,
    /// references, dereferences, tuples, arrays, a block's final expression
    /// and constructor calls (a path ending in an upper-case name:
    /// `Some("go")`, `Kind::Go("go")`).
    /// A call to anything else, or a method on the literal
    /// (`"python".len()`), computes a value from it and is not one.
    fn operand(&mut self, expr: &syn::Expr) {
        match expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit),
                ..
            }) => self.literal(lit),
            syn::Expr::Paren(e) => self.operand(&e.expr),
            syn::Expr::Group(e) => self.operand(&e.expr),
            syn::Expr::Reference(e) => self.operand(&e.expr),
            syn::Expr::Unary(e) if matches!(e.op, syn::UnOp::Deref(_)) => self.operand(&e.expr),
            syn::Expr::Tuple(e) => e.elems.iter().for_each(|elem| self.operand(elem)),
            syn::Expr::Array(e) => e.elems.iter().for_each(|elem| self.operand(elem)),
            syn::Expr::Call(e) if constructor(&e.func) => {
                e.args.iter().for_each(|arg| self.operand(arg))
            }
            syn::Expr::Block(e) => self.block_operand(&e.block),
            syn::Expr::Const(e) => self.block_operand(&e.block),
            syn::Expr::Unsafe(e) => self.block_operand(&e.block),
            _ => {}
        }
    }

    /// A block as an operand is its final expression (`{ "go" }`).
    fn block_operand(&mut self, block: &syn::Block) {
        if let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() {
            self.operand(tail);
        }
    }

    /// Macro input no parser reads (`MacroInput::Opaque`, such as
    /// `if_chain!`, or a `macro_rules!` transcriber that is not Rust even
    /// made plain) is still read as tokens: an ecosystem literal right
    /// beside `==` or `!=`, past any `&`. The one token heuristic left, and
    /// only for input that is not code until it is expanded.
    fn opaque_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        let mut flat = Vec::new();
        flatten(tokens, &mut flat);
        let punct = |at: usize| match flat.get(at) {
            Some(Some(proc_macro2::TokenTree::Punct(p))) => Some(p.as_char()),
            _ => None,
        };
        let operator_at = |first: usize| {
            COMPARISONS
                .iter()
                .any(|[a, b]| punct(first) == Some(*a) && punct(first + 1) == Some(*b))
        };
        for (at, tree) in flat.iter().enumerate() {
            let Some(proc_macro2::TokenTree::Literal(literal)) = tree else {
                continue;
            };
            let syn::Lit::Str(lit) = syn::Lit::new(literal.clone()) else {
                continue;
            };
            let mut before = at;
            while before > 0 && punct(before - 1) == Some('&') {
                before -= 1;
            }
            if operator_at(at + 1) || (before >= 2 && operator_at(before - 2)) {
                self.literal(&lit);
            }
        }
    }
}

/// The comparison operators, as the one-character tokens they are made of.
const COMPARISONS: &[[char; 2]] = &[['=', '='], ['!', '=']];

/// `tokens` as one flat list, with `None` where a bracket group opens or
/// closes, so nothing reads as adjacent across a bracket.
fn flatten(tokens: proc_macro2::TokenStream, out: &mut Vec<Option<proc_macro2::TokenTree>>) {
    for tree in tokens {
        if let proc_macro2::TokenTree::Group(group) = tree {
            out.push(None);
            flatten(group.stream(), out);
            out.push(None);
        } else {
            out.push(Some(tree));
        }
    }
}

/// A macro's input, parsed as what the macro takes. The test-code search
/// and the scans all read macros through this, so they see the same code
/// inside them.
enum MacroInput {
    /// A pattern macro's expression, pattern, guard and any message.
    Pattern(Box<(syn::Expr, syn::Pat, Option<syn::Expr>, Vec<syn::Expr>)>),
    Expressions(Vec<syn::Expr>),
    Statements(Vec<syn::Stmt>),
    /// A `macro_rules!` definition: each rule's transcriber as the code it
    /// reads as (`rule_statements`), or, if it reads as none, where it is
    /// and its tokens.
    Rules(Vec<Result<Vec<syn::Stmt>, (Position, proc_macro2::TokenStream)>>),
    /// None of these: not code until the macro expands it.
    Opaque,
}

fn macro_name(mac: &syn::Macro) -> String {
    mac.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default()
}

/// A macro's input as a pattern macro's (`PATTERN_MACROS`), as
/// `macro_rules!` rules, or else as comma-separated expressions, or else
/// as statements.
fn macro_input(mac: &syn::Macro) -> MacroInput {
    if macro_name(mac) == "macro_rules" {
        if let Some(rules) = rules(mac.tokens.clone()) {
            return MacroInput::Rules(
                rules
                    .into_iter()
                    .map(|(matcher, body)| {
                        rule_statements(&matcher, &body)
                            .ok_or_else(|| (position(body.span().start()), body.stream()))
                    })
                    .collect(),
            );
        }
    }
    if PATTERN_MACROS.contains(&macro_name(mac).as_str()) {
        if let Ok(parts) = mac.parse_body_with(pattern_macro) {
            return MacroInput::Pattern(Box::new(parts));
        }
    }
    let expressions = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
    if let Ok(args) = mac.parse_body_with(expressions) {
        MacroInput::Expressions(args.into_iter().collect())
    } else if let Ok(statements) = mac.parse_body_with(syn::Block::parse_within) {
        MacroInput::Statements(statements)
    } else {
        MacroInput::Opaque
    }
}

/// Walk a macro's parsed input with `visitor`, as the code it is.
fn walk_macro_input<V: for<'a> Visit<'a>>(visitor: &mut V, input: &MacroInput) {
    match input {
        MacroInput::Pattern(parts) => {
            let (scrutinee, pattern, guard, rest) = &**parts;
            visitor.visit_expr(scrutinee);
            visitor.visit_pat(pattern);
            guard.iter().chain(rest).for_each(|e| visitor.visit_expr(e));
        }
        MacroInput::Expressions(args) => args.iter().for_each(|arg| visitor.visit_expr(arg)),
        MacroInput::Statements(statements) => {
            statements.iter().for_each(|stmt| visitor.visit_stmt(stmt))
        }
        MacroInput::Rules(rules) => rules
            .iter()
            .flatten()
            .flatten()
            .for_each(|stmt| visitor.visit_stmt(stmt)),
        MacroInput::Opaque => {}
    }
}

/// The rules of `macro_rules!` input (`(matcher) => {transcriber}`,
/// separated by `;`), or `None` if it is not rules.
fn rules(
    tokens: proc_macro2::TokenStream,
) -> Option<Vec<(proc_macro2::Group, proc_macro2::Group)>> {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let punct =
        |at: usize, c: char| matches!(trees.get(at), Some(TokenTree::Punct(p)) if p.as_char() == c);
    let mut out = Vec::new();
    let mut at = 0;
    while at < trees.len() {
        let (TokenTree::Group(matcher), Some(TokenTree::Group(body))) =
            (&trees[at], trees.get(at + 3))
        else {
            return None;
        };
        if !punct(at + 1, '=') || !punct(at + 2, '>') {
            return None;
        }
        out.push((matcher.clone(), body.clone()));
        at += 4 + usize::from(punct(at + 4, ';'));
    }
    Some(out)
}

/// Where a transcriber's expansion can stand, each as code around the
/// placeholder `__mv_body`: as it is (statements, items, associated items,
/// an expression), a `match`'s arms, a struct's fields, an enum's variants,
/// a type, a pattern, call arguments, or a struct literal's fields. Which
/// one a rule is depends on where the macro is invoked, so a rule is read
/// in every context it parses in: `"go" | "golang"` is an expression and a
/// pattern, and a scan sees both.
const RULE_CONTEXTS: &[&str] = &[
    "__mv_body",
    "match __mv_scrutinee { __mv_body }",
    "struct __mv_Struct { __mv_body }",
    "enum __mv_Enum { __mv_body }",
    "let _: __mv_body;",
    "match __mv_scrutinee { __mv_body => {} }",
    "__mv_call(__mv_body);",
    "__mv_Struct { __mv_body };",
];

/// A rule's transcriber read as code, in every one of `RULE_CONTEXTS` it
/// parses in, with each metavariable replaced as its fragment kind in the
/// matcher says (`placeholder`). `None` if it parses in none.
fn rule_statements(
    matcher: &proc_macro2::Group,
    body: &proc_macro2::Group,
) -> Option<Vec<syn::Stmt>> {
    let mut kinds = Vec::new();
    fragments(matcher.stream(), &mut kinds);
    let plain = plain_transcriber(body.stream(), &kinds);
    let readings: Vec<Vec<syn::Stmt>> = RULE_CONTEXTS
        .iter()
        .filter_map(|context| {
            let context: proc_macro2::TokenStream = context.parse().unwrap();
            let tokens = fill_context(context, &plain, body.span());
            syn::parse::Parser::parse2(syn::Block::parse_within, tokens).ok()
        })
        .collect();
    (!readings.is_empty()).then(|| readings.into_iter().flatten().collect())
}

/// `context` with `__mv_body` replaced by `body`, and its own tokens at
/// `span` (the transcriber's), so every node read spans one source.
fn fill_context(
    context: proc_macro2::TokenStream,
    body: &proc_macro2::TokenStream,
    span: proc_macro2::Span,
) -> proc_macro2::TokenStream {
    use proc_macro2::{Group, TokenTree};
    let mut out = Vec::new();
    for mut tree in context {
        match &tree {
            TokenTree::Ident(ident) if ident == "__mv_body" => out.extend(body.clone()),
            TokenTree::Group(group) => {
                let mut filled =
                    Group::new(group.delimiter(), fill_context(group.stream(), body, span));
                filled.set_span(span);
                out.push(TokenTree::Group(filled));
            }
            _ => {
                tree.set_span(span);
                out.push(tree);
            }
        }
    }
    out.into_iter().collect()
}

/// The fragment kind of each metavariable a matcher declares
/// (`$name:expr`), inside repetitions and groups too.
fn fragments(tokens: proc_macro2::TokenStream, out: &mut Vec<(String, String)>) {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        match (
            tree,
            trees.get(at + 1),
            trees.get(at + 2),
            trees.get(at + 3),
        ) {
            (TokenTree::Group(group), ..) => fragments(group.stream(), out),
            (
                TokenTree::Punct(dollar),
                Some(TokenTree::Ident(name)),
                Some(TokenTree::Punct(colon)),
                Some(TokenTree::Ident(kind)),
            ) if dollar.as_char() == '$' && colon.as_char() == ':' => {
                out.push((name.to_string(), kind.to_string()))
            }
            _ => {}
        }
    }
}

/// What the metavariable `name` of fragment kind `kind` reads as: tokens
/// that parse wherever a fragment of that kind does. A name is `__mv_name`,
/// which no name in code equals, so `#[cfg($test)]` reads as
/// `cfg(__mv_test)`, an option free to hold, not as `cfg(test)`. A
/// visibility or an item may be empty, so it reads as nothing; a block or
/// statement as `{}`, a literal as `0`, a lifetime as `'__mv_name`, and an
/// expression, identifier, type, path, pattern, meta or token tree (or a
/// name the matcher does not declare) as the name.
fn placeholder(name: &proc_macro2::Ident, kind: Option<&str>) -> Vec<proc_macro2::TokenTree> {
    use proc_macro2::{Delimiter, Group, Ident, Literal, Punct, Spacing, TokenTree};
    let span = name.span();
    let ident = TokenTree::Ident(Ident::new(&format!("__mv_{name}"), span));
    let mut tokens = match kind {
        Some("vis" | "item") => Vec::new(),
        Some("block" | "stmt") => vec![TokenTree::Group(Group::new(
            Delimiter::Brace,
            proc_macro2::TokenStream::new(),
        ))],
        Some("literal") => vec![TokenTree::Literal(Literal::u8_unsuffixed(0))],
        Some("lifetime") => vec![TokenTree::Punct(Punct::new('\'', Spacing::Joint)), ident],
        _ => vec![ident],
    };
    tokens.iter_mut().for_each(|token| token.set_span(span));
    tokens
}

/// A transcriber as plain Rust a parser reads: each `$name` replaced by
/// its `placeholder` (from `kinds`, the matcher's fragments), `$crate` by
/// `crate`, and a repetition `$( … ) sep op` by one copy of its body.
/// Spans are kept, so a finding still names its line.
fn plain_transcriber(
    tokens: proc_macro2::TokenStream,
    kinds: &[(String, String)],
) -> proc_macro2::TokenStream {
    use proc_macro2::{Group, TokenTree};
    let mut out = Vec::new();
    let mut trees = tokens.into_iter().peekable();
    while let Some(tree) = trees.next() {
        match tree {
            TokenTree::Punct(dollar) if dollar.as_char() == '$' => match trees.next() {
                Some(TokenTree::Group(repeated)) => {
                    out.extend(plain_transcriber(repeated.stream(), kinds));
                    // An optional separator, then `*`, `+` or `?`.
                    let operator = |tree: Option<&TokenTree>| matches!(tree, Some(TokenTree::Punct(p)) if matches!(p.as_char(), '*' | '+' | '?'));
                    if !operator(trees.peek()) {
                        trees.next();
                    }
                    trees.next();
                }
                Some(TokenTree::Ident(name)) if name == "crate" => out.push(TokenTree::Ident(name)),
                Some(TokenTree::Ident(name)) => {
                    let kind = kinds
                        .iter()
                        .find(|(declared, _)| name == declared)
                        .map(|(_, kind)| kind.as_str());
                    out.extend(placeholder(&name, kind));
                }
                Some(other) => out.push(other),
                None => {}
            },
            TokenTree::Group(group) => {
                let mut plain =
                    Group::new(group.delimiter(), plain_transcriber(group.stream(), kinds));
                plain.set_span(group.span());
                out.push(TokenTree::Group(plain));
            }
            other => out.push(other),
        }
    }
    out.into_iter().collect()
}

/// The `macro_rules!` rules a scan cannot read as code: a transcriber that
/// parses in none of `RULE_CONTEXTS` however its metavariables are filled.
/// Each is a finding, since a scan that skipped it would pass whatever the
/// rule expands to, unless `OPAQUE_MACRO_RULES` lists its macro: its rules
/// are then read as tokens, a weaker reading, and so a reviewed one.
struct UnreadRules<'a> {
    /// The file, as `src/…`.
    file: &'a str,
    /// The macros whose rules may be read as tokens: (file, macro, reason).
    allowed: &'a [(&'a str, &'a str, &'a str)],
    /// The `macro_rules!` being visited, and where it starts.
    name: Option<(String, Position)>,
    /// The rules neither read nor allowed: (where, macro, where the macro starts).
    findings: Vec<(Position, String, Position)>,
}

impl<'a> UnreadRules<'a> {
    fn new(file: &'a str, allowed: &'a [(&'a str, &'a str, &'a str)]) -> Self {
        UnreadRules {
            file,
            allowed,
            name: None,
            findings: Vec::new(),
        }
    }

    /// Enter the item `node`; returns the macro the scan was in before.
    fn entering(&mut self, node: &syn::ItemMacro) -> Option<(String, Position)> {
        let name = node
            .ident
            .as_ref()
            .map(|ident| (ident.to_string(), position(node.span().start())));
        std::mem::replace(&mut self.name, name)
    }

    /// Whether the unread rule at `at` may be read as tokens. If not, it is
    /// a finding.
    fn read_as_tokens(&mut self, at: Position) -> bool {
        let (name, start) = self.name.clone().unwrap_or_default();
        if self
            .allowed
            .iter()
            .any(|(file, allowed, _)| *file == self.file && *allowed == name)
        {
            return true;
        }
        self.findings.push((at, name, start));
        false
    }
}

fn unread_rule_message(relative: &str, line: usize, name: &str) -> String {
    format!(
        "{relative}:{line}: macro_rules! {name}: a rule that does not parse as code in any \
         context the scans know; give it a form that parses, or list the macro in \
         OPAQUE_MACRO_RULES with a reason"
    )
}

/// The `macro_rules!` whose rules the scans read as tokens, as (file,
/// macro, why no rule of it can be written in a form that parses). Every
/// entry must name one macro with such a rule.
const OPAQUE_MACRO_RULES: &[(&str, &str, &str)] = &[];

/// Every `macro_rules!` rule in production code reads as code, or its
/// macro is a listed exception, and every exception is still needed.
#[test]
fn macro_rules_read_as_code() {
    let mut unread = Vec::new();
    let mut counts = vec![0; OPAQUE_MACRO_RULES.len()];
    for module in production_sources() {
        let relative = module.relative.trim_start_matches("src/");
        let file = parse(&module.text);
        let mut scan = PathScan {
            module: module.path.clone(),
            scopes: vec![scope_of(&file.items, &module.path, true)],
            named: Vec::new(),
            rules: UnreadRules::new(&module.relative, &[]),
        };
        scan.visit_file(&file);
        let tests = test_spans(&file);
        let mut macros = Vec::new();
        for (at, name, start) in &scan.rules.findings {
            if tests
                .iter()
                .any(|(first, last)| (*first..*last).contains(at))
            {
                continue;
            }
            let entry = OPAQUE_MACRO_RULES
                .iter()
                .position(|(file, allowed, _)| *file == module.relative && allowed == name);
            match entry {
                Some(index) => macros.push((index, *start)),
                None => unread.push(unread_rule_message(relative, at.0, name)),
            }
        }
        macros.sort();
        macros.dedup();
        for (index, _) in macros {
            counts[index] += 1;
        }
    }
    assert!(unread.is_empty(), "{}", unread.join("\n"));
    for ((file, name, _), count) in OPAQUE_MACRO_RULES.iter().zip(counts) {
        assert_eq!(
            count, 1,
            "OPAQUE_MACRO_RULES: {file}: macro_rules! {name} must be one macro with a rule \
             that does not parse; remove a stale entry"
        );
    }
}

/// `matches!` input:`expression, pattern [if guard] [, message…]`.
fn pattern_macro(
    input: syn::parse::ParseStream,
) -> syn::Result<(syn::Expr, syn::Pat, Option<syn::Expr>, Vec<syn::Expr>)> {
    let scrutinee = input.parse()?;
    input.parse::<syn::Token![,]>()?;
    let pattern = syn::Pat::parse_multi_with_leading_vert(input)?;
    let guard = match input.parse::<Option<syn::Token![if]>>()? {
        Some(_) => Some(input.parse()?),
        None => None,
    };
    let mut rest = Vec::new();
    if input.parse::<Option<syn::Token![,]>>()?.is_some() {
        rest.extend(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated(input)?,
        );
    }
    Ok((scrutinee, pattern, guard, rest))
}

/// Whether a called path is a tuple struct or enum variant: its last
/// segment starts upper-case.
fn constructor(func: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = func else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident.to_string().starts_with(char::is_uppercase))
}

impl<'ast> Visit<'ast> for EcosystemScan<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.functions.push(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.functions.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.functions.push(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.functions.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.functions.push(node.sig.ident.to_string());
        visit::visit_trait_item_fn(self, node);
        self.functions.pop();
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            self.operand(&node.left);
            self.operand(&node.right);
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if COMPARING_METHODS.contains(&node.method.to_string().as_str()) {
            self.operand(&node.receiver);
            node.args.iter().for_each(|arg| self.operand(arg));
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        if let syn::Pat::Lit(syn::ExprLit {
            lit: syn::Lit::Str(lit),
            ..
        }) = node
        {
            self.literal(lit);
        }
        visit::visit_pat(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let input = macro_input(node);
        match &input {
            MacroInput::Expressions(args)
                if COMPARING_MACROS.contains(&macro_name(node).as_str()) =>
            {
                args.iter().take(2).for_each(|arg| self.operand(arg));
            }
            MacroInput::Opaque => self.opaque_tokens(node.tokens.clone()),
            MacroInput::Rules(rules) => {
                for (at, tokens) in rules.iter().filter_map(|rule| rule.as_ref().err()) {
                    if self.rules.read_as_tokens(*at) {
                        self.opaque_tokens(tokens.clone());
                    }
                }
            }
            _ => {}
        }
        walk_macro_input(self, &input);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        let outer = self.rules.entering(node);
        visit::visit_item_macro(self, node);
        self.rules.name = outer;
    }

    /// The condition of an `if` is allowed when it is, as parsed, one
    /// `ECOSYSTEM_COMPARISONS` entry in that entry's file and function.
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let allowance = ECOSYSTEM_COMPARISONS
            .iter()
            .position(|(file, function, condition, _)| {
                self.rules.file == *file
                    && self.functions.last().is_some_and(|name| name == function)
                    && syn::parse_str::<syn::Expr>(condition).is_ok_and(|c| *node.cond == c)
            });
        let outer = std::mem::replace(&mut self.allowing, allowance);
        self.visit_expr(&node.cond);
        self.allowing = outer;
        self.visit_block(&node.then_branch);
        if let Some((_, otherwise)) = &node.else_branch {
            self.visit_expr(otherwise);
        }
    }
}

/// A fixture run as a kernel file where no reviewed comparison lives,
/// inside a function opened on its first line, so its lines are the
/// fixture's own.
fn ecosystem_fixture(source: &str) -> Vec<String> {
    ecosystem_fixture_allowing(source, &[])
}

/// `ecosystem_fixture` with `opaque_rules` as `OPAQUE_MACRO_RULES`.
fn ecosystem_fixture_allowing(source: &str, opaque_rules: &[(&str, &str, &str)]) -> Vec<String> {
    let mut counts = vec![0; ECOSYSTEM_COMPARISONS.len()];
    ecosystem_violations(
        "kernel/fixture.rs",
        &format!("fn fixture() {{ {source}\n}}\n"),
        &["go", "python"],
        &mut counts,
        opaque_rules,
    )
}

#[test]
fn ecosystem_allowances_cover_one_live_site_only() {
    let path = "kernel/provider/cpython.rs";
    let guard = "fn row() {\n    if selected.ecosystem != \"python\" {\n        return Err(refused());\n    }\n}\n";
    let spread = "fn row() {\n    if selected\n        .ecosystem // the section\n        !=\n        \"python\"\n    {\n    }\n}\n";
    let in_test = format!("#[cfg(test)]\nmod tests {{\n{guard}}}\n");
    for (source, accepted) in [
        (String::new(), false),
        (guard.into(), true),
        (spread.into(), true),
        (in_test.clone(), false),
        (format!("{guard}{in_test}"), true),
        (guard.repeat(2), false),
        (format!("{guard}{spread}"), false),
    ] {
        let mut counts = vec![0; ECOSYSTEM_COMPARISONS.len()];
        assert!(ecosystem_violations(path, &source, &["python"], &mut counts, &[]).is_empty());
        assert_eq!(
            ecosystem_allowance_violations(&counts).is_empty(),
            accepted,
            "{source}"
        );
    }
    // Neither another provider, another function, nor another comparison
    // in the same function inherits the reviewed input guard's permission.
    for (path, source) in [
        ("kernel/provider/rust.rs", guard),
        (
            path,
            "fn row() {\n    if selected.ecosystem == \"python\" {\n        choose_runtime();\n    }\n}\n",
        ),
        (path, "fn row() {\n    if other.ecosystem != \"python\" {}\n}\n"),
        (
            path,
            "fn row() {\n    if selected.ecosystem != \"python\" && x {}\n}\n",
        ),
        (
            path,
            "fn row() {\n    let foreign = selected.ecosystem != \"python\";\n}\n",
        ),
        (
            path,
            "fn other() {\n    if selected.ecosystem != \"python\" {}\n}\n",
        ),
        (
            path,
            "fn row() {\n    if selected.ecosystem != \"python\" {\n        if selected.ecosystem != \"python\" {}\n    }\n}\n",
        ),
    ] {
        let mut counts = vec![0; ECOSYSTEM_COMPARISONS.len()];
        let violations = ecosystem_violations(path, source, &["python"], &mut counts, &[]);
        // Every comparison is seen, as a violation or a (spent) allowance.
        let allowed = counts.iter().sum::<usize>();
        assert_eq!(
            violations.len() + allowed,
            source.matches("\"python\"").count(),
            "{source}"
        );
        assert!(!ecosystem_allowance_violations(&counts).is_empty(), "{source}");
    }
}

/// The scan reads every production kernel module, and a comparison split
/// over lines is caught under every kernel directory, at the line its name
/// is on.
#[test]
fn the_ecosystem_scan_covers_every_kernel_directory() {
    for module in production_sources() {
        if module.relative.starts_with("src/kernel/") {
            assert!(
                module.library && module.path.first().is_some_and(|m| m == "kernel"),
                "{} is not read as a kernel module",
                module.relative
            );
        }
    }
    let split = "fn f() {\n    if selected.ecosystem\n        !=\n        \"python\"\n    {\n        choose_runtime();\n    }\n}\n";
    let root = src();
    let mut dirs = vec![root.join("kernel")];
    let mut seen = 0;
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            }
        }
        let relative = dir
            .strip_prefix(&root)
            .unwrap()
            .join("fixture.rs")
            .to_string_lossy()
            .replace('\\', "/");
        let mut counts = vec![0; ECOSYSTEM_COMPARISONS.len()];
        assert_eq!(
            ecosystem_violations(&relative, split, &["python"], &mut counts, &[]),
            [format!("{relative}:4: \"python\"")]
        );
        seen += 1;
    }
    assert!(seen > 1, "no kernel subdirectories found");
}

#[test]
fn the_ecosystem_scan_sees_every_spelling() {
    for (source, expected) in [
        ("match name {\n    \"python\" => {}\n}", &["2: \"python\""][..]),
        (
            "match name {\n    \"go\"\n    | \"node\" => true,\n    _ => false,\n}",
            &["2: \"go\""],
        ),
        ("x = matches!(name, \"node\" | \"go\");", &["1: \"go\""]),
        (
            "x = matches!(\n    name,\n    \"node\"\n        | \"go\"\n);",
            &["4: \"go\""],
        ),
        ("x = matches! { name, \"go\" };", &["1: \"go\""]),
        ("x = matches!(x, Some(n) if n == \"go\");", &["1: \"go\""]),
        (
            "x = matches!(get::<A, B>(x), Some(\"go\"));",
            &["1: \"go\""],
        ),
        ("match name {\n    \"python\"=> 1,\n    _ => 2,\n}", &["2: \"python\""]),
        (
            "match rows {\n    \"go\" if rows.is_empty() => newest(),\n    _ => old(),\n}",
            &["2: \"go\""],
        ),
        (
            "match pair {\n    (\n        \"python\",\n        _,\n    ) => cpython(),\n    _ => {}\n}",
            &["3: \"python\""],
        ),
        (
            "match pair {\n    (_, Some(\"go\")) => std_only(),\n    _ => {}\n}",
            &["2: \"go\""],
        ),
        (
            "match pair {\n    _ if done => {}\n    Some(\"go\") => {}\n}",
            &["3: \"go\""],
        ),
        // Arm bodies that need no comma before the next arm.
        (
            "match a {\n    _ if x => if y { 1 } else { 2 }\n    \"go\" => 3,\n}",
            &["3: \"go\""],
        ),
        (
            "match x {\n    _ if flag => const { () }\n    \"go\" => {}\n}",
            &["3: \"go\""],
        ),
        // A block as the scrutinee.
        (
            "match { name } {\n    \"go\" => (),\n    _ => (),\n}",
            &["2: \"go\""],
        ),
        (
            "match outer {\n    _ => match inner {\n        \"go\" => 1,\n        _ => 2,\n    },\n}",
            &["3: \"go\""],
        ),
        (
            "if selected.ecosystem\n    !=\n    \"python\"\n{\n    choose_runtime();\n}",
            &["3: \"python\""],
        ),
        ("let go = name\n    == \"go\" || other;", &["2: \"go\""]),
        ("if \"go\"\n    == name {}", &["1: \"go\""]),
        ("if name != &\"go\" {}", &["1: \"go\""]),
        ("if name == (\"python\") {}", &["1: \"python\""]),
        ("if Some(\"python\") == x {}", &["1: \"python\""]),
        ("if (\"go\", 1) == pair {}", &["1: \"go\""]),
        ("if let Some(\"python\") = x {}", &["1: \"python\""]),
        ("while let Some(\"go\") = it.next() {}", &["1: \"go\""]),
        ("let Some(\"go\") = x else {\n    return;\n};", &["1: \"go\""]),
        ("if x.eq(\"python\") {}", &["1: \"python\""]),
        ("if \"go\".ne(&x) {}", &["1: \"go\""]),
        ("assert_eq!(\n    x,\n    \"python\"\n);", &["3: \"python\""]),
        ("assert!(name == \"go\");", &["1: \"go\""]),
        ("if name == /* c */ \"go\" {}", &["1: \"go\""]),
        ("if name == \"pyth\\x6fn\" {}", &["1: \"python\""]),
        (
            "if name == r\"go\" ||\n    name == r#\"python\"# {}",
            &["1: \"go\"", "2: \"python\""],
        ),
        // A block's final expression.
        ("let b = name == { \"python\" };", &["1: \"python\""]),
        ("let b = name == const { \"go\" };", &["1: \"go\""]),
        ("let b = unsafe { \"go\" } != name;", &["1: \"go\""]),
        // Macro input no parser reads is still read for comparisons.
        (
            "if_chain! {\n    if name == \"python\";\n    then { choose_runtime(); }\n}",
            &["2: \"python\""],
        ),
        (
            "macro_rules! m {\n    ($x:expr) => { $x == \"python\" };\n}",
            &["2: \"python\""],
        ),
        // A `macro_rules!` transcriber is read as the code it expands to.
        (
            "macro_rules! is_python {\n    ($name:expr) => {\n        matches!($name, \"python\")\n    };\n}",
            &["3: \"python\""],
        ),
        (
            "macro_rules! pick {\n    ($name:expr) => {\n        match $name {\n            \"python\" => 1,\n            _ => 2,\n        }\n    };\n}",
            &["4: \"python\""],
        ),
        (
            "macro_rules! any_go {\n    () => { false };\n    ($($x:expr),+ $(,)?) => { false $(|| $x == \"go\")+ };\n}",
            &["3: \"go\""],
        ),
        // A repetition is read once, whatever it holds.
        (
            "macro_rules! any_go {\n    ($($x:expr),*) => {\n        $(if matches!($x, \"go\") {})*\n    };\n}",
            &["3: \"go\""],
        ),
        // A metavariable reads as what its fragment kind parses as.
        (
            "macro_rules! define {\n    ($vis:vis) => {\n        $vis fn is_python(name: &str) -> bool {\n            matches!(name, \"python\")\n        }\n    };\n}\ndefine!(pub);",
            &["4: \"python\""],
        ),
        (
            "macro_rules! kinds {\n    ($l:lifetime, $n:literal, $b:block, $s:stmt, $i:item, $t:ty) => {\n        $i\n        fn f<$l>(x: &$l $t) -> bool { $s; let _ = $n; $b; x == \"go\" }\n    };\n}",
            &["4: \"go\""],
        ),
        // A metavariable is never a cfg option: `$test` is not `test`.
        (
            "macro_rules! gated {\n    ($test:meta) => {\n        #[cfg($test)]\n        fn is_python(name: &str) -> bool {\n            name == \"python\"\n        }\n    };\n}\ngated!(unix);",
            &["5: \"python\""],
        ),
        // A transcriber is read wherever it can stand: match arms, fields,
        // variants, a type, a pattern (which is also an expression here),
        // call arguments, struct literal fields.
        (
            "macro_rules! arms {\n    () => {\n        \"go\" => 1,\n        _ => 2,\n    };\n}",
            &["3: \"go\""],
        ),
        (
            "macro_rules! field {\n    () => { pub name: [u8; { if x == \"go\" { 1 } else { 2 } }], };\n}",
            &["2: \"go\""],
        ),
        (
            "macro_rules! variant {\n    () => { Go(&'static str) = { if x == \"go\" { 1 } else { 2 } }, };\n}",
            &["2: \"go\""],
        ),
        (
            "macro_rules! ty {\n    () => { [&'static str; { if x == \"go\" { 1 } else { 2 } }] };\n}",
            &["2: \"go\""],
        ),
        (
            "macro_rules! go_pattern {\n    () => { \"go\" | \"golang\" };\n}",
            &["2: \"go\""],
        ),
        (
            "macro_rules! args {\n    ($a:expr) => { $a, \"go\" == b };\n}",
            &["2: \"go\""],
        ),
        (
            "macro_rules! fields {\n    () => { name: { x == \"go\" }, ..Default::default() };\n}",
            &["2: \"go\""],
        ),
        // A lone literal may be a pattern where the macro is invoked.
        (
            "macro_rules! m {\n    ($x:expr) => { \"go\" };\n}",
            &["2: \"go\""],
        ),
        (
            "macro_rules! site {\n    () => { $crate::kernel::is(x, \"go\") || matches!(y, Some(\"go\")) };\n}",
            &["2: \"go\""],
        ),
        // A transcriber that parses in no context is a finding.
        (
            "macro_rules! tail {\n    ($x:ident) => { $x == \"go\" && };\n}",
            &["2: macro_rules! tail: a rule that does not parse as code in any context the \
               scans know; give it a form that parses, or list the macro in \
               OPAQUE_MACRO_RULES with a reason"],
        ),
        // Test code is what cannot compile without `test`, no more.
        (
            "#[cfg(any(test, feature = \"x\"))]\nfn h() {\n    if name == \"go\" {}\n}",
            &["3: \"go\""],
        ),
        (
            "#[cfg(not(test))]\nfn h() {\n    if name == \"go\" {}\n}",
            &["3: \"go\""],
        ),
        // A quote in a char literal opens no string.
        ("let q = '\"';\nif name == \"go\" {}", &["2: \"go\""]),
        // Production code after test-only code is still production code.
        (
            "#[cfg(test)]\nmod tests {}\nfn late() {\n    if name == \"go\" {}\n}",
            &["4: \"go\""],
        ),
        (
            "#[cfg(test)]\nconst LESS: bool = 1 < 2;\nif name == \"go\" {}",
            &["3: \"go\""],
        ),
    ] {
        let expected: Vec<String> = expected
            .iter()
            .map(|site| format!("kernel/fixture.rs:{site}"))
            .collect();
        assert_eq!(ecosystem_fixture(source), expected, "{source}");
    }
    // A macro listed in `OPAQUE_MACRO_RULES` has its unread rules read as
    // tokens instead.
    assert_eq!(
        ecosystem_fixture_allowing(
            "macro_rules! tail {\n    ($x:ident) => { $x == \"go\" && };\n}",
            &[("src/kernel/fixture.rs", "tail", "a fixture")],
        ),
        ["kernel/fixture.rs:2: \"go\""]
    );
    for source in [
        "let tool = \"go\";",
        "run(&[\"go\", \"build\"]);",
        "let c = vec![Component::new(\"go\", \"1.27.0\")];",
        "const OLD: &[(&str, &str)] = &[\n    (\"python\", \"old\"),\n];",
        "match name {\n    _ => Some(\"go\"),\n    Other => format!(\"{}\", \"python\"),\n}",
        "match name {\n    _ if x => if y { \"go\" } else { \"python\" }\n    _ => {}\n}",
        "match name {\n    \"golang\" => {}\n    _ => {}\n}",
        "let longer = name.len() >= \"go\".len();",
        "let same = count == \"python\".len();",
        "assert_eq!(x.len(), \"python\".len());",
        "if x == normalize(\"go\") {}",
        "macro_rules! tools {\n    ($($x:expr),*) => {\n        vec![\"go\", \"python\" $(, $x)*]\n    };\n}",
        "macro_rules! named {\n    ($name:ident) => {\n        match $name.kind() {\n            Kind::Tool => \"python\",\n            _ => \"go\",\n        }\n    };\n}",
        "macro_rules! test_only {\n    () => {\n        #[cfg(test)]\n        fn helper() -> bool {\n            matches!(NAME, \"go\")\n        }\n    };\n}",
        // An arm body is not a pattern, however the arms are laid out.
        "match x {\n    true => if { ready() } { log(\"python\"); }\n    false => {}\n}",
        // A guard is an expression, not a pattern.
        "match x {\n    _ if { log(\"python\"); ready() } => {}\n}",
        // Commas in a turbofish split nothing.
        "x = matches!(get::<A, B>(\"python\"), Some(_));",
        "match get::<A, B>(\"python\") {\n    _ => {}\n}",
        // Comments, every kind.
        "// if name == \"python\" {}",
        "/// matches!(name, \"go\")\nfn f() {}",
        "//! \"go\" => x",
        "/* name == \"go\" */",
        "/* outer /* inner */ name\n    == \"go\" */",
        "/** \"python\" => doc */\nfn f() {}",
        // String data that spells a comparison.
        "let s = \"if name == \\\"python\\\" {}\";",
        "let s = r#\"name == \"go\"\"#;",
        "let s = r##\"match x {\n    \"go\" => 1,\n}\"##;",
        "let s = b\"x != \\\"go\\\"\";",
        // Test-only code.
        "#[cfg(test)]\nmod tests {\n    fn t() {\n        assert!(name\n            == \"python\");\n    }\n}",
        "#[cfg(test)]\nfn helper(name: &str) -> bool {\n    matches!(\n        name,\n        \"go\"\n    )\n}",
        "#[cfg(test)]\nmod fixture_tests {\n    const X: bool = matches!(N, \"go\");\n}",
        "#[cfg(test)]\nif name == \"go\" {}",
        "match x {\n    #[cfg(test)]\n    \"go\" => {}\n    _ => {}\n}",
        "#[cfg(all(test, unix))]\nfn h() {\n    if name == \"go\" {}\n}",
        "#[cfg(all(test, debug_assertions))]\nfn h() {\n    if name == \"go\" {}\n}",
        "#[cfg_attr(not(test), cfg(any()))]\nfn h() {\n    if name == \"go\" {}\n}",
        // Test code inside a macro's input is test code too.
        "identity! {\n    #[cfg(test)]\n    fn helper() {\n        if name == \"go\" {}\n    }\n}",
    ] {
        assert_eq!(ecosystem_fixture(source), Vec::<String>::new(), "{source}");
    }
}

/// Every spelling of a path into another layer is seen: nested groups,
/// `self` in a group, `super` chains (from inline modules too), `$crate`,
/// a comment inside a path, a name a `use` bound (through another such
/// name, in the scope it is bound in), a glob, and macro input that is not
/// code; and paths that stay in the layer, or are only text, are not
/// reported.
#[test]
fn the_layering_scan_sees_every_spelling() {
    let dirs = vec!["node".to_string(), "python".to_string()];
    let check = |relative: &str, source: &str| {
        let module = module_path(Path::new(relative));
        let (mut found, _) = layer_violations(relative, &module, source, &dirs, &[]);
        found.sort();
        found
    };
    for (relative, source, expected) in [
        (
            "kernel/gc/sweep.rs",
            "use crate::{store::Store, kernel::{ui, gc::{sweep::{self, Plan}}}};\n\
             use crate::{\n    comforter::{\n        toolchain as t,\n    },\n};\n\
             use super::super::super::commands::gc;\n\
             use super::sibling;\n\
             macro_rules! m { () => { $crate::cli::parse() }; }\n\
             fn f() { not_crate::tailors::x(); }",
            &[
                "kernel/gc/sweep.rs:4: crate::comforter::toolchain",
                "kernel/gc/sweep.rs:7: crate::commands::gc",
                "kernel/gc/sweep.rs:9: crate::cli::parse",
            ][..],
        ),
        (
            "tailors/python/sync.rs",
            "use super::super::node::Lock;\n\
             use super::wheel;\n\
             use crate::tailors::{python::venv, Tailor};",
            &["tailors/python/sync.rs:1: crate::tailors::node::Lock"],
        ),
        // Test modules are exempt; production code below one is not (#706).
        (
            "kernel/mod.rs",
            "#[cfg(test)]\nmod tests { use crate::tailors::x; }",
            &[],
        ),
        (
            "kernel/gitsrc.rs",
            "#[cfg(test)]\nmod tests { use crate::tailors::x; }\n\
             fn late() { crate::comforter::clone_tree_with_activity(); }\n\
             #[cfg(test)]\nmod more_tests {}",
            &["kernel/gitsrc.rs:3: crate::comforter::clone_tree_with_activity"],
        ),
        // A name a `use` bound to a crate path reaches through it (#706).
        (
            "commands/sync.rs",
            "use crate::tailors as t;\nfn f() { t::python::venv::make(); t::registry(); }",
            &["commands/sync.rs:2: crate::tailors::python::venv::make"],
        ),
        (
            "commands/sync.rs",
            "use crate::tailors;\nuse tailors::{node::Lock, Tailor};\n\
             fn f() { tailors::python::run(); tailors::registry(); }",
            &[
                "commands/sync.rs:2: crate::tailors::node::Lock",
                "commands/sync.rs:3: crate::tailors::python::run",
            ],
        ),
        (
            "tailors/python/sync.rs",
            "use crate::tailors as all;\nfn f() { all::node::Lock::new(); all::python::own(); }",
            &["tailors/python/sync.rs:2: crate::tailors::node::Lock::new"],
        ),
        (
            "kernel/fetch.rs",
            "use crate::kernel::store;\nuse crate::kernel as k;\n\
             fn f() { store::Store::open(); k::ui::say(); std::store::x(); }",
            &[],
        ),
        // A binding of a binding, to the end; a cycle ends.
        (
            "commands/sync.rs",
            "use crate::tailors as t;\nuse t as u;\nuse u as v;\nfn f() { v::python::run(); }",
            &["commands/sync.rs:4: crate::tailors::python::run"],
        ),
        (
            "commands/sync.rs",
            "use a as b;\nuse b as a;\nfn f() { a::python::run(); }",
            &[],
        ),
        // A name resolves in the module or block it is written in.
        (
            "commands/sync.rs",
            "mod a {\n    use crate::kernel as t;\n    fn f() { t::python::run(); }\n}\n\
             mod b {\n    use crate::tailors as t;\n    fn g() { t::python::run(); }\n}",
            &["commands/sync.rs:7: crate::tailors::python::run"],
        ),
        (
            "commands/sync.rs",
            "use crate::tailors as t;\nfn f() {\n    use crate::kernel as t;\n    t::python::run();\n}\n\
             fn g() { t::node::x(); }",
            &["commands/sync.rs:6: crate::tailors::node::x"],
        ),
        (
            "commands/sync.rs",
            "use crate::tailors as t;\nmod inner {\n    fn f() { t::python::run(); }\n}",
            &[],
        ),
        // A glob import, for a name nothing else binds.
        (
            "commands/sync.rs",
            "use crate::tailors::*;\nfn f() { python::run(); }",
            &["commands/sync.rs:2: crate::tailors::python::run"],
        ),
        // A path is tokens: a comment inside it is nothing, a string
        // spelling one is no path.
        (
            "kernel/x.rs",
            "fn f() { crate /* c */ ::comforter::x(); }",
            &["kernel/x.rs:1: crate::comforter::x"],
        ),
        (
            "kernel/x.rs",
            "fn f() { let s = \"crate::comforter::x\"; log!(\"crate::cli::y\"); }",
            &[],
        ),
        // `super` counts the inline modules it is in: here it names
        // another tailor, though from the file's own module it would not.
        (
            "tailors/python/mod.rs",
            "mod inner {\n    fn f() { super::super::node::f(); }\n}\nfn g() { super::super::node::f(); }",
            &["tailors/python/mod.rs:2: crate::tailors::node::f"],
        ),
        // Macro input that is not code is read as tokens.
        (
            "kernel/x.rs",
            "fn f() {\n    if_chain! {\n        if crate::comforter::ready();\n        then { go(\"crate::cli::x\"); }\n    }\n}",
            &["kernel/x.rs:3: crate::comforter::ready"],
        ),
    ] {
        assert_eq!(check(relative, source), expected, "{source}");
    }
    let (named, _) = named_paths(
        "kernel/gc/sweep.rs",
        "use crate::{store::Store, kernel::{ui, gc::{sweep::{self, Plan}}}};",
        &module_path(Path::new("kernel/gc/sweep.rs")),
        &[],
    );
    let paths: Vec<String> = named.iter().map(|named| named.path.join("::")).collect();
    assert_eq!(
        paths,
        [
            "store::Store",
            "kernel::ui",
            "kernel::gc::sweep",
            "kernel::gc::sweep::Plan"
        ]
    );
}
/// Size budgets as a ratchet. `tests/size_baseline.txt` lists every file
/// over 1,500 non-test lines and every non-test function over 150 lines,
/// with its size today. Nothing new may cross a budget, nothing listed may
/// grow, and an entry that shrinks or falls back under budget must be
/// written down, so the baseline only ever moves toward empty.
///
/// Baseline format, one entry per line, sorted, `#` comments and blank
/// lines ignored:
///
/// ```text
/// file <non-test lines> <repo-relative path>
/// fn <lines> <repo-relative path>::<name>
/// ```
///
/// A function name that appears more than once in a file (methods of two
/// impls, say) gets `#2`, `#3`, ... after the name for its second and later
/// occurrences, counted in file order. On failure the test prints the whole
/// baseline as it should read now, ready to paste over the file.
#[test]
fn size_budgets_ratchet() {
    const FILE_BUDGET: usize = 1500;
    const FUNCTION_BUDGET: usize = 150;
    let root = repo();
    let mut current = std::collections::BTreeMap::new();
    // A file only a test-only `mod` reaches is a test module whole.
    for module in production_sources() {
        let (relative, text) = (&module.relative, &module.text);
        let lines = text.lines().count() - test_module_lines(text).len();
        if lines > FILE_BUDGET {
            current.insert(format!("file {relative}"), lines);
        }
        let mut seen = std::collections::BTreeMap::<String, usize>::new();
        for (name, length) in function_lengths(&production_text(text)) {
            let count = seen.entry(name.clone()).or_default();
            *count += 1;
            let name = if *count == 1 {
                name
            } else {
                format!("{name}#{count}")
            };
            if length > FUNCTION_BUDGET {
                current.insert(format!("fn {relative}::{name}"), length);
            }
        }
    }

    let baseline_path = root.join("tests/size_baseline.txt");
    let baseline_text = fs::read_to_string(&baseline_path).unwrap_or_default();
    let mut baseline = std::collections::BTreeMap::new();
    for line in baseline_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let (Some(kind), Some(size), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            panic!("tests/size_baseline.txt: malformed line {line:?}");
        };
        let size: usize = size
            .parse()
            .unwrap_or_else(|_| panic!("tests/size_baseline.txt: bad size in {line:?}"));
        baseline.insert(format!("{kind} {name}"), size);
    }

    let entry = |key: &str, size: usize| {
        let (kind, name) = key.split_once(' ').unwrap();
        format!("{kind} {size} {name}")
    };
    let budget = |key: &str| {
        if key.starts_with("file ") {
            format!("{FILE_BUDGET} non-test lines")
        } else {
            format!("{FUNCTION_BUDGET} lines")
        }
    };
    let mut problems = Vec::new();
    for (key, &size) in &current {
        match baseline.get(key) {
            None => problems.push(format!(
                "new: {key} is {size} lines, over the {} budget. Split it; \
                 if it must stay this size, add `{}` to the baseline.",
                budget(key),
                entry(key, size)
            )),
            Some(&allowed) if size > allowed => problems.push(format!(
                "grew: {key} is {size} lines, baseline {allowed}. Shrink it back; \
                 if the growth is deliberate, change its baseline line to `{}`.",
                entry(key, size)
            )),
            Some(&allowed) if size < allowed => problems.push(format!(
                "shrank: {key} is {size} lines, baseline {allowed}. Update the \
                 baseline downward: `{}`.",
                entry(key, size)
            )),
            Some(_) => {}
        }
    }
    for (key, &allowed) in &baseline {
        if !current.contains_key(key) {
            problems.push(format!(
                "under budget: {key} (baseline {allowed}) is now within the {} \
                 budget or gone. Delete its line `{}` from the baseline.",
                budget(key),
                entry(key, allowed)
            ));
        }
    }
    if !problems.is_empty() {
        let mut expected = String::from(BASELINE_HEADER);
        for (key, &size) in &current {
            expected.push_str(&entry(key, size));
            expected.push('\n');
        }
        panic!(
            "size budgets (docs/human/ARCHITECTURE.md, layering rule 5):\n  {}\n\n\
             tests/size_baseline.txt as it reads now (paste over the file):\n\n{expected}",
            problems.join("\n  ")
        );
    }
    println!(
        "size budgets: {} file(s) and {} function(s) over budget, none above baseline",
        current
            .keys()
            .filter(|key| key.starts_with("file "))
            .count(),
        current.keys().filter(|key| key.starts_with("fn ")).count()
    );
}

/// The comment block at the top of `tests/size_baseline.txt`.
const BASELINE_HEADER: &str = "\
# Size budget ratchet (tests/architecture.rs::size_budgets_ratchet).
# Every src/ file over 1,500 non-test lines and every non-test function
# over 150 lines, with its size today. Entries may only shrink or go away;
# the test prints this file's new contents whenever it must change.
#
#   file <non-test lines> <path>
#   fn <lines> <path>::<name>[#<nth occurrence in the file>]
";

/// Rough function lengths: a `fn` at indentation ≤ 4 runs to its matching
/// brace, with strings, chars, and comments blanked so their braces do not
/// count. A function under `#[cfg(test)]` is test code wherever it sits in
/// the file, so it is measured (to step over its body) and left out of the
/// function budget. (`size_budgets_ratchet` hands this production text,
/// where test code is already blanked.)
fn function_lengths(text: &str) -> Vec<(String, usize)> {
    let clean = blank_literals(text);
    let lines: Vec<&str> = clean.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let name = if indent <= 4 { fn_name(trimmed) } else { None };
        let Some(name) = name else {
            i += 1;
            continue;
        };
        let mut depth = 0i32;
        let mut started = false;
        let mut j = i;
        while j < lines.len() {
            for c in lines[j].chars() {
                if c == '{' {
                    depth += 1;
                    started = true;
                } else if c == '}' {
                    depth -= 1;
                }
            }
            if started && depth <= 0 {
                break;
            }
            if !started && lines[j].trim_end().ends_with(';') {
                break;
            }
            j += 1;
        }
        if !test_only(&lines[..i]) {
            out.push((name, j - i + 1));
        }
        i = j + 1;
    }
    out
}

/// Whether the item starting after `above` carries `#[cfg(test)]`: one of
/// the attribute lines directly over it says so. Doc comments are already
/// blank here, so blank lines between attributes are stepped over.
fn test_only(above: &[&str]) -> bool {
    above
        .iter()
        .rev()
        .map(|line| line.trim())
        .take_while(|line| line.is_empty() || line.starts_with("#["))
        .any(|line| line == "#[cfg(test)]")
}

#[test]
fn function_lengths_leave_out_test_only_functions() {
    let text = "fn kept() {\n    a();\n}\n\n\
        #[cfg(test)]\npub(crate) fn dropped() {\n    b();\n    c();\n}\n\n\
        /// Docs.\n#[cfg(test)]\n#[allow(dead_code)]\nfn also_dropped() {}\n\n\
        #[cfg(unix)]\nfn also_kept() {}\n";
    assert_eq!(
        function_lengths(text),
        vec![("kept".to_string(), 3), ("also_kept".to_string(), 1)]
    );
}

fn fn_name(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub(super) "))
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn blank_literals(text: &str) -> String {
    let bytes: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let c = bytes[i];
        if c == '/' && i + 1 < n && bytes[i + 1] == '/' {
            while i < n && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < n && bytes[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                if bytes[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == 'r' && i + 1 < n && (bytes[i + 1] == '"' || bytes[i + 1] == '#') {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && bytes[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < n && bytes[j] == '"' {
                j += 1;
                loop {
                    if j >= n {
                        break;
                    }
                    if bytes[j] == '"' && (j + 1..=j + hashes).all(|k| k < n && bytes[k] == '#') {
                        j += 1 + hashes;
                        break;
                    }
                    if bytes[j] == '\n' {
                        out.push('\n');
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            while j < n && bytes[j] != '"' {
                if bytes[j] == '\\' {
                    j += 1;
                }
                if j < n && bytes[j] == '\n' {
                    out.push('\n');
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        if c == '\'' {
            if i + 2 < n && bytes[i + 1] != '\\' && bytes[i + 2] == '\'' {
                i += 3;
                continue;
            }
            if i + 1 < n && bytes[i + 1] == '\\' {
                let mut j = i + 2;
                while j < n && bytes[j] != '\'' {
                    j += 1;
                }
                i = j + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `GREYWARD_STORE` is process-global. A test that sets or clears it without
/// holding `store::STORE_ENV_LOCK` redirects a concurrent test to the real
/// store, so every write must happen with the lock held: in a function
/// that took the lock earlier in its body, or in a method of an env guard
/// (`impl Drop for StoreEnv`, `StoreEnv::enter`), where every function that
/// names the guard took the lock before naming it. The scan reads code
/// tokens, so the lock named in a comment or a string does not count.
#[test]
fn store_env_writes_hold_the_lock() {
    let mut violations = Vec::new();
    let mut writes = 0;
    for (relative, text) in all_sources() {
        let (found, sites) = store_env_violations(&text);
        writes += sites;
        violations.extend(found.into_iter().map(|v| format!("{relative}: {v}")));
    }
    // Positive control: the unit tests that point the store elsewhere
    // write the variable dozens of times.
    assert!(
        writes >= 20,
        "the GREYWARD_STORE scan found only {writes} writes; it is passing vacuously"
    );
    assert!(
        violations.is_empty(),
        "GREYWARD_STORE written without STORE_ENV_LOCK held:\n  {}",
        violations.join("\n  ")
    );
}

/// What a `{` opened, for the GREYWARD_STORE scan.
enum EnvScope {
    /// Index into the function table.
    Function(usize),
    /// The type an `impl` block is for.
    Impl(String),
    Block,
}

/// The GREYWARD_STORE writes in `text` made without the lock held, and how many
/// writes there were.
fn store_env_violations(text: &str) -> (Vec<String>, usize) {
    let tokens = tokenize(text);
    let write_at = |i: usize| {
        (is_ident(tokens.get(i), "set_var") || is_ident(tokens.get(i), "remove_var"))
            && is_punct(tokens.get(i + 1), '(')
            && matches!(tokens.get(i + 2), Some(Token::Str(name)) if name == "GREYWARD_STORE")
    };
    // Pass one finds the guard types: impls whose methods write the
    // variable. Pass two checks every write and every use of a guard.
    let mut guards: Vec<String> = Vec::new();
    let mut violations = Vec::new();
    let mut sites = 0;
    for pass in 0..2 {
        // (name, impl type, lock taken so far)
        let mut functions: Vec<(String, Option<String>, bool)> = Vec::new();
        let mut scopes: Vec<EnvScope> = Vec::new();
        let mut pending_fn: Option<String> = None;
        let mut pending_impl: Option<Option<String>> = None;
        for i in 0..tokens.len() {
            let current = scopes.iter().rev().find_map(|scope| match scope {
                EnvScope::Function(index) => Some(*index),
                _ => None,
            });
            match &tokens[i] {
                Token::Ident(word) if word == "fn" => {
                    if let Some(Token::Ident(name)) = tokens.get(i + 1) {
                        pending_fn = Some(name.clone());
                    }
                }
                Token::Ident(word) if word == "impl" => pending_impl = Some(None),
                Token::Ident(word) if pending_impl.is_some() && pending_fn.is_none() => {
                    pending_impl = Some(Some(word.clone()));
                }
                Token::Punct(';') => {
                    pending_fn = None;
                    pending_impl = None;
                }
                Token::Punct('{') => {
                    if let Some(name) = pending_fn.take() {
                        // `impl Trait` in a signature opens no impl block.
                        pending_impl = None;
                        let owner = scopes.iter().rev().find_map(|scope| match scope {
                            EnvScope::Impl(ty) => Some(ty.clone()),
                            EnvScope::Function(_) => Some(String::new()),
                            EnvScope::Block => None,
                        });
                        let owner = owner.filter(|ty| !ty.is_empty());
                        functions.push((name, owner, false));
                        scopes.push(EnvScope::Function(functions.len() - 1));
                    } else if let Some(ty) = pending_impl.take() {
                        scopes.push(EnvScope::Impl(ty.unwrap_or_default()));
                    } else {
                        scopes.push(EnvScope::Block);
                    }
                }
                Token::Punct('}') => {
                    scopes.pop();
                }
                _ => {}
            }
            let Some(index) = current else { continue };
            let (name, owner, locked) = &functions[index];
            if is_ident(tokens.get(i), "STORE_ENV_LOCK") {
                functions[index].2 = true;
            } else if write_at(i) {
                match owner {
                    Some(ty) if pass == 0 => {
                        if !guards.contains(ty) {
                            guards.push(ty.clone());
                        }
                    }
                    _ if pass == 0 => {}
                    _ if *locked => sites += 1,
                    Some(ty) if guards.contains(ty) => sites += 1,
                    _ => {
                        sites += 1;
                        violations.push(format!(
                            "fn {name} writes GREYWARD_STORE before taking the lock"
                        ));
                    }
                }
            } else if pass == 1 {
                if let Some(Token::Ident(word)) = tokens.get(i) {
                    if guards.contains(word) && owner.as_ref() != Some(word) && !*locked {
                        violations.push(format!(
                            "fn {name} uses the GREYWARD_STORE guard {word} before taking the lock"
                        ));
                    }
                }
            }
        }
    }
    (violations, sites)
}

#[test]
fn the_store_env_scan_sees_through_comments_and_guards() {
    let unlocked = "// STORE_ENV_LOCK is held by the caller\n\
        fn t() { let s = \"STORE_ENV_LOCK\"; std::env::set_var(\"GREYWARD_STORE\", p); }";
    assert_eq!(
        store_env_violations(unlocked).0,
        ["fn t writes GREYWARD_STORE before taking the lock"]
    );
    let late = "fn t() { env::remove_var(\"GREYWARD_STORE\"); let _l = STORE_ENV_LOCK.lock(); }";
    assert_eq!(
        store_env_violations(late).0,
        ["fn t writes GREYWARD_STORE before taking the lock"]
    );
    let guarded = "struct StoreEnv(Option<OsString>);\n\
        impl StoreEnv { fn enter(p: &Path) -> Self { std::env::set_var(\"GREYWARD_STORE\", p); Self(None) } }\n\
        impl Drop for StoreEnv { fn drop(&mut self) { std::env::remove_var(\"GREYWARD_STORE\"); } }\n\
        fn good() { let _l = STORE_ENV_LOCK.lock(); let _e = StoreEnv::enter(p); }\n\
        fn bad() { let _e = StoreEnv::enter(p); }";
    let (found, sites) = store_env_violations(guarded);
    assert_eq!(
        found,
        ["fn bad uses the GREYWARD_STORE guard StoreEnv before taking the lock"]
    );
    assert_eq!(sites, 2);
    let nested = "fn t() { let _l = STORE_ENV_LOCK.lock();\n\
        struct G; impl Drop for G { fn drop(&mut self) { std::env::remove_var(\"GREYWARD_STORE\"); } }\n\
        std::env::set_var(\"GREYWARD_STORE\", p); let _g = G; }";
    assert_eq!(store_env_violations(nested), (Vec::<String>::new(), 2));
}

/// Plan documents and review rounds get deleted; a comment that cites one
/// goes stale with it. Comments describe the code they sit on instead.
#[test]
fn comments_do_not_cite_plans() {
    const CITATIONS: &[&str] = &[
        "DESIGNS.md",
        "FOLLOW-UPS.md",
        "NEXT.md",
        "REFACTOR.md",
        "REVIEW.md",
        "Sol review",
        "per Sol",
    ];
    // A word followed directly by a digit: a plan item number or review round.
    const NUMBERED: &[&str] = &["item ", "WP", "A-R", "Sol r"];
    let mut violations = Vec::new();
    for (relative, text) in all_sources() {
        for (index, line) in text.lines().enumerate() {
            let Some(comment) = comment_text(line) else {
                continue;
            };
            let cited = CITATIONS.iter().any(|c| comment.contains(c))
                || NUMBERED.iter().any(|word| {
                    comment.match_indices(word).any(|(at, _)| {
                        let before_ok = at == 0
                            || !comment[..at]
                                .chars()
                                .next_back()
                                .is_some_and(|c| c.is_alphanumeric());
                        let after = comment[at + word.len()..].chars().next();
                        before_ok && after.is_some_and(|c| c.is_ascii_digit())
                    })
                });
            if cited {
                violations.push(format!("{relative}:{}: {}", index + 1, comment.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "comments citing plan documents or review rounds:\n  {}",
        violations.join("\n  ")
    );
}

/// The comment on a line: everything from a `//` that sits outside a string
/// or char literal. Good enough for a lint; a line the scanner misreads is a
/// missed comment, not a false report, unless a literal on the same line
/// contains one of the cited names.
fn comment_text(line: &str) -> Option<&str> {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut in_string = false;
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        if in_string {
            if c == '\\' {
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '\'' && chars.get(i + 2).is_some_and(|&(_, q)| q == '\'') {
            i += 2;
        } else if c == '"' {
            in_string = true;
        } else if c == '/' && chars.get(i + 1).is_some_and(|&(_, n)| n == '/') {
            return Some(&line[at..]);
        }
        i += 1;
    }
    None
}

/// Narration has one vocabulary: `kernel::ui` prints `ward:` for progress and
/// `ward: warning:` for an advisory, and it is the module `--quiet` and
/// `--no-color` are implemented in. A raw `eprintln!` elsewhere in `src/`
/// bypasses that distinction, so the user cannot tell a fallback from a
/// phase. Test modules are exempt: a skip message is for whoever ran the
/// suite, not for a user.
///
/// Two spellings are ward's own narration: `eprintln!`, and a handle from
/// `io::stderr()` written with `writeln!`. `eprint!` is the verbatim
/// pass-through of a subprocess's captured output and of an
/// already-rendered usage error, neither of which takes a `ward:` prefix.
/// A lower layer that renders its own narration into a `Write` gets its
/// handle from `ui::narration()`.
///
/// The `io::stderr()` sites below are not narration, each for the reason
/// given. The match is on the line's code, so a second site in a listed
/// file is still reported, and a listed site that disappears fails the
/// test until its row goes too.
const STDERR_HANDLES: &[(&str, &str, &str)] = &[
    (
        "src/kernel/supervise.rs",
        "let _ = io::stderr().write_all(bytes);",
        "verbatim relay of a supervised child's stderr",
    ),
    (
        "src/kernel/sandbox.rs",
        "&mut io::stderr(),",
        "scrubbed relay of a sandboxed build's stderr",
    ),
    (
        "src/commands/deps.rs",
        "if !(io::stderr().is_terminal() && io::stdin().is_terminal()) {",
        "a terminal test; writes nothing",
    ),
    (
        "src/commands/deps.rs",
        "let mut stderr = io::stderr();",
        "the interactive which-registry prompt, a question rather than narration",
    ),
];

/// Does this line of code write ward's narration to stderr directly? The
/// comment part of the line is ignored; `.stderr(…)` (a `Command` method)
/// and `child.stderr` (a field) are not the process's stderr.
fn writes_stderr(line: &str) -> bool {
    let code = match comment_text(line) {
        Some(comment) => &line[..line.len() - comment.len()],
        None => line,
    };
    code.contains("eprintln!")
        || code.match_indices("stderr()").any(|(at, _)| {
            !code[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c == '.' || is_ident_char(c))
        })
}

#[test]
fn narration_goes_through_kernel_ui() {
    let mut violations = Vec::new();
    let mut listed = vec![false; STDERR_HANDLES.len()];
    for (relative, text) in production_files() {
        if relative == "src/kernel/ui.rs" {
            continue;
        }
        for (index, line) in production_text(&text).lines().enumerate() {
            if !writes_stderr(line) {
                continue;
            }
            match STDERR_HANDLES
                .iter()
                .position(|(file, code, _)| *file == relative && line.trim() == *code)
            {
                Some(row) => listed[row] = true,
                None => violations.push(format!("{relative}:{}: {}", index + 1, line.trim())),
            }
        }
    }
    let stale: Vec<_> = STDERR_HANDLES
        .iter()
        .zip(&listed)
        .filter(|(_, seen)| !**seen)
        .map(|((file, code, _), _)| format!("{file}: {code}"))
        .collect();
    assert!(
        stale.is_empty(),
        "STDERR_HANDLES rows that match nothing (delete them):\n  {}",
        stale.join("\n  ")
    );
    assert!(
        violations.is_empty(),
        "stderr written outside kernel::ui (use ui::note for progress, \
         ui::warning for an advisory, ui::error for a failure, \
         ui::narration for a report rendered into a writer):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_stderr_scan_sees_every_spelling() {
    for line in [
        "eprintln!(\"ward: x\");",
        "let mut out = io::stderr().lock();",
        "writeln!(std::io::stderr(), \"x\")?;",
        "let e = stderr(); // after `use std::io::stderr`",
    ] {
        assert!(writes_stderr(line), "{line}");
    }
    for line in [
        "eprint!(\"{captured}\");",
        "command.stderr(Stdio::piped());",
        "let pipe = child.stderr.take();",
        "// io::stderr() is locked by ui::narration",
        "let s = my_stderr();",
    ] {
        assert!(!writes_stderr(line), "{line}");
    }
}

/// `docs/agent/` is two files. Ledgers, review reports, and evidence dumps
/// go in pull request descriptions; history is git.
#[test]
fn agent_docs_are_two_files() {
    let mut names: Vec<String> = fs::read_dir(repo().join("docs/agent"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["DESIGNS.md", "HITRATE.md"]);
}

/// One Rust token, with comments and whitespace gone and every literal
/// collapsed to `Lit`, so a scan cannot be fooled by `.status /* c */ ()`,
/// by a call split across lines, or by a string that happens to spell code.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Punct(char),
    /// A string literal, with its escapes processed (`"t\x61r"` is `tar`),
    /// so a scan matching on contents sees what the program sees. A raw
    /// string has none to process.
    Str(String),
    Lit,
}

/// The contents of a (non-raw) string literal with its escapes processed:
/// `\x61`, `\u{61}`, the one-character escapes, and a `\` before a line
/// break, which with the indentation after it is dropped. An escape the
/// language does not have is kept as written.
fn unescape(chars: &[char]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' || i >= chars.len() {
            out.push(c);
            continue;
        }
        let escaped = chars[i];
        i += 1;
        match escaped {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            '\\' | '"' | '\'' => out.push(escaped),
            'x' if i + 2 <= chars.len() => {
                let hex: String = chars[i..i + 2].iter().collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(c) => {
                        out.push(c);
                        i += 2;
                    }
                    None => out.extend(['\\', 'x']),
                }
            }
            'u' if chars.get(i) == Some(&'{') => {
                let close = chars[i..].iter().position(|&c| c == '}');
                let code = close.and_then(|at| {
                    let hex: String = chars[i + 1..i + at].iter().filter(|&&c| c != '_').collect();
                    u32::from_str_radix(&hex, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .map(|c| (c, at))
                });
                match code {
                    Some((c, at)) => {
                        out.push(c);
                        i += at + 1;
                    }
                    None => out.extend(['\\', 'u']),
                }
            }
            '\n' => {
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
            }
            other => out.extend(['\\', other]),
        }
    }
    out
}

fn tokenize(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && i + 1 < n && chars[i + 1] == '/' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && i + 1 < n && chars[i + 1] == '*' {
            // Block comments nest in Rust.
            let mut depth = 0;
            while i < n {
                if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if let Some((start, end, close)) = raw_string_end(&chars, i) {
            out.push(Token::Str(chars[start..end.min(n)].iter().collect()));
            i = close;
        } else if c == '"' || (c == 'b' && i + 1 < n && chars[i + 1] == '"') {
            i += if c == 'b' { 2 } else { 1 };
            let start = i;
            while i < n && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push(Token::Str(unescape(&chars[start..i.min(n)])));
            i += 1;
        } else if c == '\'' || (c == 'b' && i + 1 < n && chars[i + 1] == '\'') {
            let start = if c == 'b' { i + 1 } else { i };
            // A char literal closes within a few characters; otherwise this
            // quote starts a lifetime or label, which is an identifier here.
            let close = if start + 1 < n && chars[start + 1] == '\\' {
                (start + 2..n.min(start + 12)).find(|&j| chars[j] == '\'')
            } else if start + 2 < n && chars[start + 2] == '\'' {
                Some(start + 2)
            } else {
                None
            };
            match close {
                Some(j) => {
                    out.push(Token::Lit);
                    i = j + 1;
                }
                None => {
                    i = start + 1;
                    while i < n && (chars[i].is_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                }
            }
        } else if c.is_alphabetic() || c == '_' {
            // A raw identifier `r#spawn` is the identifier `spawn`.
            if c == 'r'
                && i + 2 < n
                && chars[i + 1] == '#'
                && (chars[i + 2].is_alphabetic() || chars[i + 2] == '_')
            {
                i += 2;
            }
            let start = i;
            while i < n && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Token::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            while i < n && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                // `0..n` is a range, not a float.
                if chars[i] == '.' && i + 1 < n && chars[i + 1] == '.' {
                    break;
                }
                i += 1;
            }
            out.push(Token::Lit);
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    out
}

/// Where the contents of a raw string literal (`r"…"`, `r#"…"#`, `br"…"`)
/// starting at `i` begin and end, and where the literal ends, if one does.
fn raw_string_end(chars: &[char], i: usize) -> Option<(usize, usize, usize)> {
    let n = chars.len();
    let mut j = i;
    if chars[j] == 'b' {
        j += 1;
    }
    if j >= n || chars[j] != 'r' {
        return None;
    }
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while j < n && chars[j] == '#' {
        hashes += 1;
        j += 1;
    }
    if j >= n || chars[j] != '"' {
        return None;
    }
    j += 1;
    let start = j;
    while j < n {
        if chars[j] == '"' && (1..=hashes).all(|k| j + k < n && chars[j + k] == '#') {
            return Some((start, j, j + 1 + hashes));
        }
        j += 1;
    }
    Some((start, n, n))
}

fn is_ident(token: Option<&Token>, name: &str) -> bool {
    matches!(token, Some(Token::Ident(text)) if text == name)
}

fn is_punct(token: Option<&Token>, c: char) -> bool {
    token == Some(&Token::Punct(c))
}

/// Production tokens of a file, each tagged with the innermost named `fn`
/// around it. Test-only code (`test_spans`: test modules, test-only
/// helpers, fields, arms and statements) is blanked out first.
fn production_tokens(text: &str) -> Vec<(Token, String)> {
    let tokens = tokenize(&production_text(text));
    let mut out = Vec::new();
    // (fn name, brace depth its body opened at)
    let mut functions: Vec<(String, usize)> = Vec::new();
    let mut pending_fn: Option<String> = None;
    let mut depth = 0usize;
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i].clone();
        match &token {
            Token::Ident(word) if word == "fn" => {
                if let Some(Token::Ident(name)) = tokens.get(i + 1) {
                    pending_fn = Some(name.clone());
                }
            }
            Token::Punct(';') if pending_fn.is_some() => {
                // A body-less signature (a trait method declaration).
                if functions.last().map(|(_, d)| *d) != Some(depth) {
                    pending_fn = None;
                }
            }
            Token::Punct('{') => {
                depth += 1;
                if let Some(name) = pending_fn.take() {
                    functions.push((name, depth));
                }
            }
            Token::Punct('}') => {
                if functions.last().is_some_and(|(_, d)| *d == depth) {
                    functions.pop();
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        let owner = functions
            .last()
            .map(|(name, _)| name.clone())
            .unwrap_or_default();
        out.push((token, owner));
        i += 1;
    }
    out
}

/// A place in a source file: 1-based line, 0-based column in characters.
type Position = (usize, usize);

fn position(at: proc_macro2::LineColumn) -> Position {
    (at.line, at.column)
}

/// Where `node` starts and ends, outer attributes included.
fn span_of(node: &impl Spanned) -> (Position, Position) {
    let span = node.span();
    (position(span.start()), position(span.end()))
}

/// `text` parsed as a Rust file. Every file the scans read is one, and so
/// is every fixture.
fn parse(text: &str) -> syn::File {
    syn::parse_file(text).unwrap_or_else(|error| {
        let (line, column) = position(error.span().start());
        panic!(
            "not Rust at line {line}, column {}: {error}\n{text}",
            column + 1
        )
    })
}

/// `text` with its test-only code (`test_spans`) blanked to spaces, so
/// what is left keeps its lines and columns.
fn production_text(text: &str) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(
            chars
                .iter()
                .enumerate()
                .filter(|(_, c)| **c == '\n')
                .map(|(i, _)| i + 1),
        )
        .collect();
    let len = chars.len();
    let offset = |(line, column): Position| (line_starts[line - 1] + column).min(len);
    for (start, end) in test_spans(&parse(text)) {
        let (start, end) = (offset(start), offset(end));
        for c in &mut chars[start..end] {
            if *c != '\n' {
                *c = ' ';
            }
        }
    }
    chars.into_iter().collect()
}

/// Whether `attrs` mark test-only code: code that is never compiled when
/// `test` is off. Each attribute that can drop code is one condition:
/// `#[test]`, a `cfg`, and a `cfg_attr` (the attributes it applies,
/// conditioned on its predicate). The code compiles when all of them hold,
/// so it is test-only when that one formula cannot hold with `test` off,
/// whatever every other option is: `cfg(all(test, unix))`, or
/// `cfg(feature = "x")` beside `cfg_attr(feature = "x", cfg(test))`.
fn marks_test_code(attrs: &[syn::Attribute]) -> bool {
    !Cfg::All(attrs.iter().map(|attr| compiled_when(&attr.meta)).collect()).satisfiable()
}

/// A cfg condition with `test` off: a constant, a free option, or the
/// predicates' `all`, `any` and `not`.
enum Cfg {
    Const(bool),
    Option(String),
    All(Vec<Cfg>),
    Any(Vec<Cfg>),
    Not(Box<Cfg>),
}

impl Cfg {
    /// The most free options `satisfiable` tries every assignment of.
    /// Past it the formula is taken to hold, so code is kept as production
    /// code: a scan may read too much, never too little.
    const MAX_OPTIONS: usize = 16;

    fn options<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Cfg::Const(_) => {}
            Cfg::Option(name) => out.push(name),
            Cfg::All(all) | Cfg::Any(all) => all.iter().for_each(|cfg| cfg.options(out)),
            Cfg::Not(cfg) => cfg.options(out),
        }
    }

    fn holds(&self, set: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Cfg::Const(value) => *value,
            Cfg::Option(name) => set(name),
            Cfg::All(all) => all.iter().all(|cfg| cfg.holds(set)),
            Cfg::Any(any) => any.iter().any(|cfg| cfg.holds(set)),
            Cfg::Not(cfg) => !cfg.holds(set),
        }
    }

    /// Whether some setting of the free options makes the formula hold.
    fn satisfiable(&self) -> bool {
        let mut options = Vec::new();
        self.options(&mut options);
        options.sort();
        options.dedup();
        if options.len() > Self::MAX_OPTIONS {
            return true;
        }
        (0u32..1 << options.len())
            .any(|bits| self.holds(&|name| bits >> options.binary_search(&name).unwrap() & 1 == 1))
    }
}

/// The condition under which code carrying the attribute `meta` is
/// compiled with `test` off.
fn compiled_when(meta: &syn::Meta) -> Cfg {
    if meta.path().is_ident("test") {
        return Cfg::Const(false);
    }
    let syn::Meta::List(list) = meta else {
        return Cfg::Const(true);
    };
    if !list.path.is_ident("cfg") && !list.path.is_ident("cfg_attr") {
        return Cfg::Const(true);
    }
    let Ok(args) = list.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    ) else {
        // Not read: a condition of its own, free to hold.
        return Cfg::Option(list.tokens.to_string());
    };
    let mut args = args.iter();
    let Some(predicate) = args.next().map(cfg_predicate) else {
        return Cfg::Const(true);
    };
    if list.path.is_ident("cfg") {
        return predicate;
    }
    // `cfg_attr(C, a, b)`: compiled when `C` fails, or when every
    // attribute it applies lets the code compile.
    Cfg::Any(vec![
        Cfg::Not(Box::new(predicate)),
        Cfg::All(args.map(compiled_when).collect()),
    ])
}

/// A cfg predicate as a `Cfg`: `test` is off, `all`, `any` and `not` are
/// read, and any other option is free (named by its text, so the same
/// option written twice is one option).
fn cfg_predicate(predicate: &syn::Meta) -> Cfg {
    let operator = ["all", "any", "not"]
        .into_iter()
        .find(|op| predicate.path().is_ident(op));
    match (predicate, operator) {
        (syn::Meta::Path(path), _) if path.is_ident("test") => Cfg::Const(false),
        (syn::Meta::List(list), Some(operator)) => {
            let Ok(args) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return Cfg::Option(list.tokens.to_string());
            };
            let args: Vec<Cfg> = args.iter().map(cfg_predicate).collect();
            match operator {
                "all" => Cfg::All(args),
                "any" => Cfg::Any(args),
                _ => Cfg::Not(Box::new(Cfg::All(args))),
            }
        }
        _ => Cfg::Option(cfg_option_name(predicate)),
    }
}

/// An option's text: `unix`, `feature = "x"`.
fn cfg_option_name(predicate: &syn::Meta) -> String {
    let path = predicate
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    match predicate {
        syn::Meta::Path(_) => path,
        syn::Meta::List(list) => format!("{path}({})", list.tokens),
        syn::Meta::NameValue(pair) => match &pair.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => format!("{path} = {:?}", value.value()),
            // A value no cfg takes: an option no other is.
            other => format!("{path} = {other:p}"),
        },
    }
}

#[test]
fn test_only_cfgs_are_evaluated_without_test() {
    let marks = |attrs: &str| {
        let item: syn::ItemFn = syn::parse_str(&format!("{attrs}\nfn f() {{}}")).unwrap();
        marks_test_code(&item.attrs)
    };
    for attrs in [
        "#[test]",
        "#[cfg(test)]",
        "#[cfg(all(test, unix))]",
        "#[cfg(all(test, debug_assertions))]",
        "#[cfg(all(unix, any(test, any())))]",
        "#[cfg(not(not(test)))]",
        "#[cfg(any())]",
        "#[cfg_attr(not(test), cfg(any()))]",
        "#[cfg_attr(all(), cfg(test))]",
        // Test-only together, though neither is alone.
        "#[cfg(feature = \"fixtures\")]\n#[cfg_attr(feature = \"fixtures\", cfg(test))]",
        "#[cfg(unix)]\n#[cfg(not(unix))]",
        "#[cfg(any(test, unix))]\n#[cfg_attr(unix, test)]",
    ] {
        assert!(marks(attrs), "{attrs}");
    }
    for attrs in [
        "#[inline]",
        "#[cfg(unix)]",
        "#[cfg(not(test))]",
        "#[cfg(any(test, feature = \"x\"))]",
        "#[cfg(any(test, unix))]",
        "#[cfg(all())]",
        "#[cfg_attr(test, cfg(any()))]",
        "#[cfg_attr(unix, cfg(test))]",
        "#[cfg_attr(test, allow(dead_code))]",
        // The crate root's own attribute (src/lib.rs): production code.
        "#[cfg_attr(test, allow(clippy::disallowed_methods))]",
        "#[cfg(feature = \"a\")]\n#[cfg_attr(feature = \"b\", cfg(test))]",
        "#[cfg(unix)]\n#[cfg(windows)]",
    ] {
        assert!(!marks(attrs), "{attrs}");
    }
}

/// The lines a file's test modules cover: every `mod` marked test-only,
/// at any depth (inside an inline production module too), attributes and
/// doc comments included. The file budget counts the rest, a test-only
/// helper `fn` among them.
fn test_module_lines(text: &str) -> std::collections::BTreeSet<usize> {
    struct TestModules(std::collections::BTreeSet<usize>);
    impl<'ast> Visit<'ast> for TestModules {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if marks_test_code(&node.attrs) {
                let ((first, _), (last, _)) = span_of(node);
                self.0.extend(first..=last);
            } else {
                visit::visit_item_mod(self, node);
            }
        }
    }
    let mut modules = TestModules(Default::default());
    modules.visit_file(&parse(text));
    modules.0
}

#[test]
fn test_modules_are_found_at_any_depth() {
    let text = "mod inner {\n    #[cfg(test)]\n    mod tests {\n        fn t() {}\n    }\n    fn kept() {}\n}\n\
                #[cfg(test)]\nfn helper() {}\n#[cfg(test)]\nmod top {}\n";
    let lines: Vec<usize> = test_module_lines(text).into_iter().collect();
    // The nested test module and the top-level one; not the helper `fn`.
    assert_eq!(lines, [2, 3, 4, 5, 10, 11]);
}

/// The spans of a file's test-only code: each item, impl or trait member,
/// statement, expression, field, variant, match arm and field value marked
/// `#[cfg(test)]` or `#[test]`, and the whole file if it is marked so
/// inside. Found by attribute in the parsed file, so nothing inside a
/// test-only item (a `<` in `1 < 2`, say) can make it end early or late.
fn test_spans(file: &syn::File) -> Vec<(Position, Position)> {
    let mut spans = TestSpans(Vec::new());
    if marks_test_code(&file.attrs) {
        spans.0.push(span_of(file));
    } else {
        spans.visit_file(file);
    }
    spans.0
}

struct TestSpans(Vec<(Position, Position)>);

/// A syntax node's outer attributes.
trait Attrs {
    fn attrs(&self) -> &[syn::Attribute];
}

/// `Attrs` for node structs, which hold their attributes in `attrs`.
macro_rules! struct_attrs {
    ($($ty:ident),*) => {$(
        impl Attrs for syn::$ty {
            fn attrs(&self) -> &[syn::Attribute] {
                &self.attrs
            }
        }
    )*};
}

/// `Attrs` for node enums, whose variants each hold a struct with `attrs`
/// (a `Verbatim` variant has none).
macro_rules! enum_attrs {
    ($($ty:ident { $($variant:ident),* })*) => {$(
        impl Attrs for syn::$ty {
            fn attrs(&self) -> &[syn::Attribute] {
                match self {
                    $(syn::$ty::$variant(node) => &node.attrs,)*
                    _ => &[],
                }
            }
        }
    )*};
}

struct_attrs!(Local, Field, Variant, Arm, FieldValue, FieldPat, StmtMacro);
enum_attrs! {
    Item {
        Const, Enum, ExternCrate, Fn, ForeignMod, Impl, Macro, Mod, Static, Struct, Trait,
        TraitAlias, Type, Union, Use
    }
    ImplItem { Const, Fn, Type, Macro }
    TraitItem { Const, Fn, Type, Macro }
    ForeignItem { Fn, Static, Type, Macro }
    Expr {
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall,
        Paren, Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple,
        Unary, Unsafe, While, Yield
    }
}

/// `TestSpans` methods for nodes that carry attributes: record a test-only
/// node's span and do not look inside it, walk into any other.
macro_rules! skip_test_only {
    ($($method:ident($ty:ident);)*) => {$(
        fn $method(&mut self, node: &'ast syn::$ty) {
            if marks_test_code(node.attrs()) {
                self.0.push(span_of(node));
            } else {
                visit::$method(self, node);
            }
        }
    )*};
}

impl<'ast> Visit<'ast> for TestSpans {
    skip_test_only! {
        visit_item(Item);
        visit_impl_item(ImplItem);
        visit_trait_item(TraitItem);
        visit_foreign_item(ForeignItem);
        visit_expr(Expr);
        visit_local(Local);
        visit_field(Field);
        visit_variant(Variant);
        visit_arm(Arm);
        visit_field_value(FieldValue);
        visit_field_pat(FieldPat);
        visit_stmt_macro(StmtMacro);
    }

    /// An attribute on an expression statement belongs to the whole
    /// statement, but the parser hangs it on the leftmost operand
    /// (`#[cfg(test)] a = b;` marks `a`).
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Expr(expr, _) = node {
            let mut leftmost = expr;
            loop {
                leftmost = match leftmost {
                    syn::Expr::Assign(e) => &e.left,
                    syn::Expr::Binary(e) => &e.left,
                    syn::Expr::Cast(e) => &e.expr,
                    _ => break,
                };
            }
            if marks_test_code(leftmost.attrs()) {
                self.0.push(span_of(node));
                return;
            }
        }
        visit::visit_stmt(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        walk_macro_input(self, &macro_input(node));
    }
}

#[test]
fn test_code_is_found_by_attribute() {
    let owners = |text: &str| {
        let mut owners: Vec<String> = production_tokens(text)
            .into_iter()
            .map(|(_, owner)| owner)
            .filter(|owner| !owner.is_empty())
            .collect();
        owners.dedup();
        owners
    };
    // A `<` in a test-only item is no generic opener.
    assert_eq!(
        owners("#[cfg(test)]\nconst LESS: bool = 1 < 2;\nfn kept() { c.spawn(); }"),
        ["kept"]
    );
    let source = "#[cfg(test)]\nfn generic<A, B>() -> Map<A, B> { a() }\n\
             #[cfg(test)]\nmod tests { fn t() {} }\n\
             #[test]\nfn unit() {}\n\
             enum E { #[cfg(test)]\nTest(Vec<u8>), Kept }\n\
             fn kept(x: u8) {\n    #[cfg(test)]\n    let a = 1 < 2;\n    #[cfg(test)]\n    \
             hook = x > 1;\n    #[cfg(test)]\n    {\n        inner();\n    }\n    \
             match x {\n        #[cfg(test)]\n        0 => test_arm(),\n        _ => kept_arm(),\n    }\n}";
    assert_eq!(owners(source), ["kept"]);
    let idents: Vec<String> = production_tokens(source)
        .into_iter()
        .filter_map(|(token, _)| match token {
            Token::Ident(word) => Some(word),
            _ => None,
        })
        .collect();
    for gone in [
        "generic", "Map", "tests", "unit", "Test", "a", "hook", "inner", "test_arm",
    ] {
        assert!(
            !idents.iter().any(|word| word == gone),
            "{gone} is test code"
        );
    }
    for kept in ["E", "Kept", "kept", "x", "match", "kept_arm"] {
        assert!(
            idents.iter().any(|word| word == kept),
            "{kept} is production code"
        );
    }
    let text = production_text("fn a() {\n    #[cfg(test)]\n    hook = x > 1;\n    b();\n}");
    assert!(!text.contains("hook") && text.contains("b();"), "{text}");
    assert_eq!(text.lines().count(), 5);
    assert_eq!(
        owners("#![cfg(test)]\nfn t() { c.spawn(); }"),
        Vec::<String>::new()
    );
}

/// The names a file uses for `ty`: `ty` itself plus every `ty as Alias`
/// import, so `use std::process::Command as P; P::spawn(&mut c)` is seen,
/// and every `type Alias = path::to::ty;`.
///
/// The limit: one step only. An alias of an alias (`type A = ty;
/// type B = A;`, or `use` of a name another file aliased) is not followed,
/// so `B` is not a name for `ty` here. Nothing in `src/` spells a scanned
/// type that way.
fn names_for(tokens: &[(Token, String)], ty: &str) -> Vec<String> {
    let mut names = vec![ty.to_string()];
    for i in 0..tokens.len() {
        if is_ident(token_at(tokens, i), ty) && is_ident(token_at(tokens, i + 1), "as") {
            if let Some(Token::Ident(alias)) = token_at(tokens, i + 2) {
                names.push(alias.clone());
            }
        }
        // `type Alias = a::b::ty;`: the path's last segment, right before
        // the `;`, is the type. (`type R = Result<ty, E>;` ends in `>`.)
        if is_ident(token_at(tokens, i), "type") && is_punct(token_at(tokens, i + 2), '=') {
            let end = (i + 3..tokens.len()).find(|&j| is_punct(token_at(tokens, j), ';'));
            if let (Some(Token::Ident(alias)), Some(end)) = (token_at(tokens, i + 1), end) {
                if is_ident(token_at(tokens, end - 1), ty) {
                    names.push(alias.clone());
                }
            }
        }
    }
    names
}

/// `Name :: method` where `Name` is one of `types`: a path call
/// (`Command::spawn(&mut c)`, `Store::activity(&store, m)`) or a function
/// value passed on without calling it.
fn path_call(tokens: &[(Token, String)], i: usize, types: &[String], methods: &[&str]) -> bool {
    matches!(token_at(tokens, i), Some(Token::Ident(name)) if types.contains(name))
        && is_punct(token_at(tokens, i + 1), ':')
        && is_punct(token_at(tokens, i + 2), ':')
        && methods
            .iter()
            .any(|method| is_ident(token_at(tokens, i + 3), method))
}

/// `.method(` on any receiver.
fn method_call(tokens: &[(Token, String)], i: usize, methods: &[&str]) -> bool {
    is_punct(token_at(tokens, i), '.')
        && methods
            .iter()
            .any(|method| is_ident(token_at(tokens, i + 1), method))
        && is_punct(token_at(tokens, i + 2), '(')
}

const SPAWNS: &[&str] = &["status", "output", "spawn"];

/// The names one file gives the scanned types, aliases included.
struct Names {
    commands: Vec<String>,
    stores: Vec<String>,
    activities: Vec<String>,
}

impl Names {
    fn of(tokens: &[(Token, String)]) -> Names {
        Names {
            commands: names_for(tokens, "Command"),
            stores: names_for(tokens, "Store"),
            activities: names_for(tokens, "StoreActivity"),
        }
    }
}

/// A raw child: `.status()`/`.output()`/`.spawn()` (no arguments, so
/// `supervise::status(cmd, activity)` is not one), or a `Command` path call
/// under any alias.
fn raw_child_at(tokens: &[(Token, String)], i: usize, names: &Names) -> bool {
    (method_call(tokens, i, SPAWNS) && is_punct(token_at(tokens, i + 3), ')'))
        || path_call(tokens, i, &names.commands, SPAWNS)
}

/// A lease taken: `.activity(`/`.try_activity_exclusive(` (or its
/// `_unchecked` form), the same as a `Store` path, or
/// `StoreActivity::acquire`/`try_exclusive`, under any alias.
fn lease_at(tokens: &[(Token, String)], i: usize, names: &Names) -> bool {
    const STORE: &[&str] = &[
        "activity",
        "try_activity_shared",
        "try_activity_exclusive",
        "try_activity_exclusive_unchecked",
    ];
    method_call(tokens, i, STORE)
        || path_call(tokens, i, &names.stores, STORE)
        || path_call(
            tokens,
            i,
            &names.activities,
            &["acquire", "try_shared", "try_exclusive"],
        )
}

/// Per-function counts of `(file, fn)` sites matching `hit` at a token.
fn count_sites(
    skip: &[&str],
    hit: fn(&[(Token, String)], usize, &Names) -> bool,
) -> Vec<(String, String, usize)> {
    let mut counts: Vec<(String, String, usize)> = Vec::new();
    for (relative, text) in production_files() {
        if skip.contains(&relative.as_str()) {
            continue;
        }
        let tokens = production_tokens(&text);
        let names = Names::of(&tokens);
        for index in 0..tokens.len() {
            if !hit(&tokens, index, &names) {
                continue;
            }
            let owner = tokens[index].1.clone();
            match counts
                .iter_mut()
                .find(|(file, function, _)| *file == relative && *function == owner)
            {
                Some(entry) => entry.2 += 1,
                None => counts.push((relative.clone(), owner, 1)),
            }
        }
    }
    counts.sort();
    counts
}

fn expected_sites(list: &[(&str, &str, usize)]) -> Vec<(String, String, usize)> {
    let mut expected: Vec<(String, String, usize)> = list
        .iter()
        .map(|(file, function, count)| (file.to_string(), function.to_string(), *count))
        .collect();
    expected.sort();
    expected
}

fn token_at(tokens: &[(Token, String)], index: usize) -> Option<&Token> {
    tokens.get(index).map(|(token, _)| token)
}

/// A child process that reads or writes a store path runs through
/// `kernel::supervise` with the caller's activity lease, so protection is
/// provable at the call site. The only raw `.status()`, `.output()` or
/// `.spawn()` calls left in production code are counted here, per function;
/// each touches no store path, and the comment above each group says why.
/// A new raw child, even in a listed function, fails until it borrows a
/// lease or is added here with a reason.
const RAW_CHILD_SITES: &[(&str, &str, usize)] = &[
    // `None` arm of `Option<&StoreActivity>`: no store is involved.
    ("src/comforter/mod.rs", "clone_tree_for", 3),
    ("src/kernel/archive.rs", "list_names", 1),
    ("src/kernel/archive.rs", "status_for", 1),
    ("src/kernel/sandbox.rs", "run_preflight", 2),
    // The one unmanaged sandbox spawn: the `None` arm of every sandbox
    // entry point, for callers that consume no store.
    ("src/kernel/sandbox.rs", "spawn_unmanaged", 1),
    // Host probes, and the downloaded ward's `--version` before it is
    // installed.
    ("src/commands/selfupdate.rs", "smoke_test", 1),
    ("src/tailors/dotnet/mod.rs", "invoking_uid", 1),
    ("src/tailors/python/pypi.rs", "detect_host_glibc", 1),
    // The resolution relay starts the tool inside the resolution sandbox,
    // where no store is mounted writable and there is no lease to borrow.
    ("src/kernel/resolve/relay.rs", "spawn_tool", 1),
    // The forced removal of a resolution container: it must run after an
    // interrupt, when the supervisor refuses new children, and it names a
    // container, not a store path.
    ("src/kernel/resolve/container.rs", "remove", 1),
];

/// The functions allowed to take an activity lease (`.activity(`,
/// `try_activity_exclusive`, `StoreActivity::acquire`/`try_exclusive`),
/// with how many times. Each is an operation boundary: it owns the work its
/// lease protects and passes that lease down. A helper that receives a
/// store from a caller already holding a lease must take the caller's
/// `&StoreActivity` instead, because a nested acquisition under the
/// thread's own exclusive lease is refused.
const LEASE_BOUNDARIES: &[(&str, &str, usize)] = &[
    // The primitives themselves.
    ("src/kernel/store/mod.rs", "activity", 1),
    ("src/kernel/store/mod.rs", "try_activity_exclusive", 1),
    ("src/kernel/store/mod.rs", "try_activity_shared", 1),
    // `existing` with a shared lease, for a reader that only locates the
    // store and holds it while it reads (the local Rust tree cache, #434).
    ("src/kernel/store/mod.rs", "existing_shared", 1),
    // The one primitive that does not validate the format marker.
    (
        "src/kernel/store/mod.rs",
        "try_activity_exclusive_unchecked",
        1,
    ),
    // Command entry points: the shared lease every tailor command borrows
    // (`Context`), and the commands that open the store without one.
    ("src/kernel/context.rs", "open_with_project_dir", 1),
    ("src/commands/doctor.rs", "run", 1),
    // `store roots`: the lease its diagnostic read borrows.
    ("src/commands/store.rs", "list_roots", 1),
    ("src/commands/gc.rs", "run", 1),
    // `gc --reset` opens a store `run` cannot: one ward refuses to read.
    ("src/commands/gc.rs", "reset", 1),
    // `x --clean`, once per environment, on the store that owns it.
    ("src/commands/x/cleanup.rs", "clean_lease", 1),
    ("src/kernel/gc/mod.rs", "collect", 1),
    // Public root-registry calls for callers holding no lease (tests and
    // library users). Each has a `_with_activity` form that production uses.
    ("src/kernel/store/roots.rs", "register_root_record", 1),
    ("src/kernel/store/roots.rs", "register_root_from_project", 1),
    ("src/kernel/store/roots.rs", "remove_root_entry", 1),
    ("src/kernel/store/roots.rs", "forget_root", 1),
];

/// A call of one of `kernel::fetch`'s verified downloads or cache reads,
/// which admit a cache entry by its digest alone (a call, not the `fn`
/// that defines it). A call through a `use ... as` alias is not seen.
fn verified_fetch_at(tokens: &[(Token, String)], i: usize, _names: &Names) -> bool {
    const FETCHES: &[&str] = &[
        "download_verified_held",
        "download_verified_digest",
        "download_verified_digest_held",
        "download_toolchain_artifact_held",
        "download_verified_any_held",
        // The cache-only reads and the proxy's streaming insert: a hit is
        // admitted by digest the same way.
        "cache_verified_held",
        "cache_verified_digest_held",
        "read_cache_verified_digest",
        "cache_from_reader",
        "cache_from_reader_any",
    ];
    FETCHES
        .iter()
        .any(|name| is_ident(token_at(tokens, i), name))
        && is_punct(token_at(tokens, i + 1), '(')
        && !(i > 0 && is_ident(token_at(tokens, i - 1), "fn"))
}

/// Every caller of a verified download, per function, grouped by where its
/// expected digest comes from. A cache hit is admitted by digest alone,
/// whichever ecosystem wrote the entry: the bytes are the ones the digest
/// names, so the cache grants nothing the digest's source did not already
/// grant, and the trust decision is that source (#476, and the rule on
/// `fetch::download_verified_digest_held`). A new caller fails until it is
/// listed under its source, or under a new group that says why that source
/// is trusted.
///
/// The count is per function, so it sees a call added or removed, not one
/// replaced: a listed function that drops its call and gains another, with
/// a digest from somewhere else, keeps its count and passes. A function
/// that changes where its digest comes from has to move groups by hand.
const DIGEST_SOURCES: &[(&str, &str, usize)] = &[
    // A toolchain row: ward's catalog, or the project's toolchain lock
    // pinning one of its rows. `download_toolchain_artifact_held` also
    // authorizes the URL for the row's publisher, hit or miss.
    ("src/kernel/provider/cpython.rs", "realize_runtime", 1),
    ("src/kernel/provider/cpython.rs", "realize_uv", 1),
    ("src/kernel/provider/rust.rs", "realize_runtime", 1),
    ("src/kernel/provider/rust_extras.rs", "load_manifest", 1),
    ("src/kernel/provider/rust_extras.rs", "realize_component", 1),
    ("src/tailors/cargo/rustfmt.rs", "ensure_rustfmt", 1),
    ("src/tailors/dotnet/mod.rs", "realize_runtime", 1),
    ("src/tailors/elixir/mod.rs", "realize_runtime", 1),
    ("src/tailors/go/mod.rs", "realize_runtime", 1),
    ("src/tailors/node/mod.rs", "realize_runtime", 1),
    ("src/tailors/ruby/mod.rs", "realize_runtime", 1),
    // Compiled into ward: the native library table.
    ("src/kernel/provider/nativelibs.rs", "realize_staged", 1),
    // The publisher's own listing, read over TLS: rubygems.org's API (or
    // the store record ward wrote after checking a download against it), and
    // Electron's SHASUMS256.txt from its GitHub release (kept in the
    // store). Never a lock's claim.
    ("src/tailors/ruby/mod.rs", "verify_gem", 1),
    ("src/kernel/provider/artifacts.rs", "provision", 1),
    // The project's pin: its committed lock (Cargo.lock checksums, mix.lock
    // outer checksums, package-lock integrity, ward's Python lock) or a
    // `greyward.toml` declared artifact. ward honors the pin as the user's choice
    // of bytes, as cargo, npm and pip with hashes do. A pin the upstream URL
    // would not serve fails on a cold cache and installs the pinned bytes
    // on a warm one.
    ("src/kernel/provider/crates.rs", "realize_vendor_inner", 1),
    ("src/tailors/elixir/mod.rs", "realize_deps", 1),
    ("src/tailors/node/classify.rs", "fetch_tarball", 1),
    ("src/tailors/node/realize.rs", "plant_declared_artifacts", 1),
    (
        "src/tailors/python/build.rs",
        "build_sdist_wheel_at_depth",
        2,
    ),
    (
        "src/tailors/python/build.rs",
        "plan_sdist_identity_input",
        2,
    ),
    ("src/tailors/python/env.rs", "realize_artifacts", 1),
    ("src/tailors/python/env.rs", "realize_env_at_depth", 1),
    (
        "src/tailors/python/sdist_view.rs",
        "discard_failed_attempt",
        1,
    ),
    // Cache reads of a pin's bytes: go's plan carries the sha256 of each
    // module file ward itself inserted after checking it against go.sum's
    // h1, and Corepack's check reads the pnpm tarball the node lock's
    // integrity names before comparing it with `packageManager`'s hash.
    // A persisted native classification is reused only for the lock
    // integrity candidate whose tarball re-verifies in the cache.
    ("src/tailors/go/mod.rs", "stage_modcache_skeleton", 1),
    ("src/tailors/node/classify.rs", "archive_is_cached", 1),
    ("src/tailors/node/corepack.rs", "verify_corepack_hash", 1),
    // The registry's claim, read through the resolution proxy: the digest
    // a registry's metadata response (an npm packument's integrity, a
    // crates.io index checksum) states for an artifact the tool then
    // fetches. The proxy serves the claimed bytes only when they match, so
    // the tool sees what the registry promised, over TLS, as it would
    // without the proxy; a lock written from them then carries the same
    // digest as its pin.
    ("src/kernel/resolve/mirror.rs", "claimed_artifact", 1),
];

#[test]
fn every_verified_download_names_its_digest_source() {
    assert_eq!(
        count_sites(&["src/kernel/fetch.rs"], verified_fetch_at),
        expected_sites(DIGEST_SOURCES),
        "a verified download is called from a site not in DIGEST_SOURCES; \
         list it there with where its expected digest comes from (a cache \
         hit is trusted by that source, not by who wrote the cache)"
    );
}

/// A `Store` made without reading its format marker: the struct written
/// out (`Store { root }`) or `Store::handle(`, under any `use` or `type`
/// alias, and `Self { root }` / `Self::handle(` in a file with an
/// `impl Store` or `impl Trait for Store` block (the scan does not track
/// which `impl` a function is in, so `Self` counts anywhere in such a
/// file). Its limit: an alias of an alias (`use Store as A;` then
/// `type B = A;`) is not followed, so `B { root }` would go unseen. Extend
/// it if a real miss appears.
fn unchecked_store_at(tokens: &[(Token, String)], i: usize, names: &Names) -> bool {
    let mut stores = names.stores.clone();
    if is_ident(token_at(tokens, i), "Self") {
        let implements_store = (0..tokens.len()).any(|j| {
            (is_ident(token_at(tokens, j), "impl") || is_ident(token_at(tokens, j), "for"))
                && matches!(token_at(tokens, j + 1), Some(Token::Ident(name)) if names.stores.contains(name))
                && is_punct(token_at(tokens, j + 2), '{')
        });
        if implements_store {
            stores.push("Self".into());
        }
    }
    path_call(tokens, i, &stores, &["handle"])
        || (matches!(token_at(tokens, i), Some(Token::Ident(name)) if stores.contains(name))
            && is_punct(token_at(tokens, i + 1), '{')
            && is_ident(token_at(tokens, i + 2), "root"))
}

/// The seven functions allowed to make a `Store` without validating its
/// format marker, with how many times. Everything else goes through `Store::open`,
/// `Store::existing` or `Store::open_at`, which refuse a store this ward
/// does not read. A store made here is still validated before any record
/// is read, because every lease but `try_activity_exclusive_unchecked`
/// checks the marker once it is held. That last part is not something this
/// count proves: it is why the readers take a `&StoreActivity`, and why
/// `store_children_borrow_the_callers_lease` lists who may take a lease.
const UNCHECKED_STORES: &[(&str, &str, usize)] = &[
    // The constructors: `open_root` and `existing` have just validated or
    // written the marker, and `handle` is the unchecked form itself.
    ("src/kernel/store/mod.rs", "open_root", 1),
    ("src/kernel/store/mod.rs", "existing", 1),
    ("src/kernel/store/mod.rs", "handle", 1),
    // `gc --reset` empties a store ward refuses to read, and never reads a
    // record of it.
    ("src/commands/gc.rs", "reset", 1),
    // A store named by an x environment's own records, which may not be the
    // configured one: by its request record here, and by the object paths
    // in its closure in `store_from_object_path`. `x --clean` leases either
    // (validated) before it reads or removes anything.
    ("src/commands/x/cleanup.rs", "originating_store_in", 1),
    ("src/comforter/mod.rs", "store_from_object_path", 1),
    // Names an x environment's directory from the store's path alone, and
    // reads nothing in the store.
    ("src/commands/x/mod.rs", "environment_name", 1),
];

#[test]
fn stores_are_made_through_a_checked_constructor() {
    assert_eq!(
        count_sites(&[], unchecked_store_at),
        expected_sites(UNCHECKED_STORES),
        "a `Store` is made without validating its format marker; use \
         `Store::open`/`existing`/`open_at` (or, for a store that is leased \
         before any record is read, count it in UNCHECKED_STORES with the \
         reason)"
    );
}

#[test]
fn store_children_borrow_the_callers_lease() {
    assert_eq!(
        count_sites(&["src/kernel/supervise.rs"], raw_child_at),
        expected_sites(RAW_CHILD_SITES),
        "a production child runs without the caller's activity lease; pass \
         `&StoreActivity` to `kernel::supervise` (or, for a child that touches \
         no store path, count it in RAW_CHILD_SITES with the reason)"
    );
    assert_eq!(
        count_sites(&["src/kernel/activity.rs"], lease_at),
        expected_sites(LEASE_BOUNDARIES),
        "an activity lease is taken outside the reviewed operation boundaries; \
         take the caller's `&StoreActivity` instead (or, for a new operation \
         boundary, count it in LEASE_BOUNDARIES)"
    );
}

/// Every non-private `kernel::supervise` function (`pub`, `pub(crate)`,
/// `pub(super)`, `pub(in ...)`) that starts a `Command` is
/// fenced. Either it is a `local_*` form whose first statement is the
/// resolver tripwire, so a dependency tool is refused before anything
/// spawns, or it is an unrestricted primitive that clippy refuses outside
/// the reviewed sites (`disallowed-methods` in `clippy.toml`) and that has
/// a `local_*` form beside it. A new spawn function that is neither would
/// let a resolver start outside `kernel::resolve`'s door unseen.
#[test]
fn every_public_supervise_spawn_is_fenced() {
    let root = repo();
    let supervise = fs::read_to_string(root.join("src/kernel/supervise.rs")).unwrap();
    let clippy = fs::read_to_string(root.join("clippy.toml")).unwrap();
    // The scan's own control: every visibility wider than private counts.
    let sample = "\npub fn a(c: &mut Command) {\n}\n\npub(crate) fn b(c: &mut Command) {\n}\n\
                  \npub(super) fn c(c: &mut Command) {\n}\n\npub(in crate::kernel) fn d(c: &mut Command) {\n}\n\
                  \nfn private(c: &mut Command) {\n}\n";
    let sampled: Vec<String> = visible_command_fns(sample)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(sampled, ["a", "b", "c", "d"]);
    let spawners = visible_command_fns(&supervise);
    let names: Vec<&str> = spawners.iter().map(|(name, _)| name.as_str()).collect();
    // Positive control: the scan sees today's three primitives, so a
    // renamed or reformatted file fails here instead of passing with
    // nothing to check.
    for primitive in ["status", "status_with_stderr", "output"] {
        assert!(
            names.contains(&primitive),
            "the supervise scan no longer sees `{primitive}` (found {names:?}); it is passing vacuously"
        );
    }
    let mut unfenced = Vec::new();
    for (name, body) in &spawners {
        let fenced = match name.strip_prefix("local_") {
            Some(_) => body
                .trim_start()
                .starts_with("refuse_resolver(command, activity)?;"),
            None => {
                clippy.contains(&format!("path = \"greyward::kernel::supervise::{name}\""))
                    && names.contains(&format!("local_{name}").as_str())
            }
        };
        if !fenced {
            unfenced.push(name.as_str());
        }
    }
    assert!(
        unfenced.is_empty(),
        "non-private supervise spawn functions outside the resolution fence: {unfenced:?}. \
         A `local_*` form must start with `refuse_resolver(command, activity)?;`; any other \
         must be listed in clippy.toml's disallowed-methods and have a `local_*` form"
    );
}

/// The name and body of every non-private top-level function in `text`
/// (`pub`, `pub(crate)`, `pub(super)`, `pub(in ...)`) whose signature
/// mentions `Command`.
fn visible_command_fns(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (index, _) in text.match_indices("\npub") {
        let rest = &text[index + "\npub".len()..];
        let rest = match rest.strip_prefix('(') {
            Some(inner) => match inner.find(')') {
                Some(close) => &inner[close + 1..],
                None => continue,
            },
            None => rest,
        };
        let Some(rest) = rest.strip_prefix(" fn ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let open = rest.find('{').unwrap();
        if !rest[..open].contains("Command") {
            continue;
        }
        let body = &rest[open + 1..open + rest[open..].find("\n}\n").unwrap()];
        found.push((name, body.to_string()));
    }
    found
}

/// The functions of `text` with a site `hit` finds, one entry per site.
fn fixture_owners(text: &str, hit: fn(&[(Token, String)], usize, &Names) -> bool) -> Vec<String> {
    let tokens = production_tokens(text);
    let names = Names::of(&tokens);
    (0..tokens.len())
        .filter(|&i| hit(&tokens, i, &names))
        .map(|i| tokens[i].1.clone())
        .collect()
}

/// Every spelling the scan must see through, and the ones it must not count.
#[test]
fn the_scan_sees_every_spelling() {
    let children = "use std::process::Command as P;\n\
        fn comment() { c.status /* c */ (); }\n\
        fn line_break() { c\n  .output(\n  ); let s = \".spawn()\"; }\n\
        fn raw_ident() { c.r#spawn(); }\n\
        fn path_call() { std::process::Command::spawn(&mut c); }\n\
        fn alias() { P::r#output(&mut c); }\n\
        fn supervised() { supervise::status(&mut c, activity); }\n\
        #[cfg(test)]\nfn test_only() { c.spawn(); }";
    assert_eq!(
        fixture_owners(children, raw_child_at),
        ["comment", "line_break", "raw_ident", "path_call", "alias"]
    );

    let leases = "use crate::kernel::store::Store as S;\n\
        use crate::kernel::activity::StoreActivity as Lease;\n\
        fn method() { let x = 'a'; store . activity (m); }\n\
        fn raw_ident() { store.r#try_activity_exclusive(); }\n\
        fn path_call() { Store::activity(&store, m); }\n\
        fn alias() { S::activity(&store, m); }\n\
        fn value() { let f = S::try_activity_exclusive; }\n\
        fn acquire() { Lease::acquire(root, m); StoreActivity::try_exclusive(root); }\n\
        fn borrowed() { store.require_activity(activity, \"x\"); let activity = activity; }";
    assert_eq!(
        fixture_owners(leases, lease_at),
        [
            "method",
            "raw_ident",
            "path_call",
            "alias",
            "value",
            "acquire",
            "acquire"
        ]
    );

    let stores = "use crate::kernel::store::Store as S;\n\
        type Mine = crate::kernel::store::Store;\n\
        type Maybe = Option<Store>;\n\
        impl Store {\n\
        fn literal() -> Store { Store { root } }\n\
        fn spaced() -> Store { store::Store {\n    root: path.into(),\n} }\n\
        fn self_literal() -> Self { Self { root } }\n\
        fn self_handle() -> Self { Self::handle(root) }\n\
        }\n\
        fn alias() { S { root }; }\n\
        fn type_alias() { Mine { root }; Mine::handle(root); }\n\
        fn handle() { Store::handle(root); let f = S::handle; }\n\
        fn checked() -> io::Result<Store> { Store::open_at(root) }\n\
        fn other() { Maybe::handle(root); Other { root }; let s = \"Store { root }\"; }\n\
        #[cfg(test)]\nfn test_only() { Store { root }; }";
    assert_eq!(
        fixture_owners(stores, unchecked_store_at),
        [
            "literal",
            "spaced",
            "self_literal",
            "self_handle",
            "alias",
            "type_alias",
            "type_alias",
            "handle",
            "handle"
        ]
    );
    // The stated limit: an alias of an alias is not followed.
    let chained = "type A = Store;\ntype B = A;\n\
        fn first() { A { root }; }\nfn second() { B { root }; }";
    assert_eq!(fixture_owners(chained, unchecked_store_at), ["first"]);
    let trait_impl = "impl From<PathBuf> for Store {\n\
        fn from(root: PathBuf) -> Self { Self { root } }\n\
        }";
    assert_eq!(fixture_owners(trait_impl, unchecked_store_at), ["from"]);
    // `Self` in a file with no `impl Store` is some other type's.
    let elsewhere = "use crate::kernel::store::Store;\n\
        impl Project { fn new() -> Self { Self { root } } }\n\
        fn walk() { for store in stores { Self { root }; } }";
    assert!(fixture_owners(elsewhere, unchecked_store_at).is_empty());
}

/// Every word that names a tailor: its id and lock ecosystem, and the
/// command-line word and cache prefix of its registry tool. Read from the
/// registry, so a new tailor is covered without editing this test.
fn tailor_words() -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for tailor in greyward::tailors::registry() {
        words.push(tailor.id().into());
        words.push(tailor.lock_ecosystem().into());
        if let Ok(tool) = tailor.registry_tool() {
            words.push(tool.spelling().into());
            words.push(tool.cache_prefix().into());
        }
    }
    words.sort();
    words.dedup();
    words
}

/// Does a string literal name one of `words`: the whole literal, or, in a
/// literal without whitespace (a name or path, not prose), one `/`
/// component up to its first dot (`.greyward/closures/dotnet.json`,
/// `python.json`)? Prose that mentions a name is not a match.
fn names_a_word(literal: &str, words: &[String]) -> bool {
    let named = |text: &str| words.iter().any(|word| word == text);
    named(literal)
        || (!literal.chars().any(char::is_whitespace)
            && literal
                .split('/')
                .any(|part| named(part.split('.').next().unwrap_or(part))))
}

/// One naming site kind: (file, function, literal as written, count).
type LiteralSite = (String, String, String, usize);

/// Counts of string literals in `text` that name one of `words`
/// (`names_a_word`), per function and literal, outside `#[cfg(test)]`
/// items.
fn literal_sites(relative: &str, text: &str, words: &[String]) -> Vec<LiteralSite> {
    let mut counts: Vec<LiteralSite> = Vec::new();
    for (token, owner) in production_tokens(text) {
        let Token::Str(literal) = &token else {
            continue;
        };
        if !names_a_word(literal, words) {
            continue;
        }
        match counts
            .iter_mut()
            .find(|(_, function, text, _)| *function == owner && text == literal)
        {
            Some(entry) => entry.3 += 1,
            None => counts.push((relative.to_string(), owner, literal.clone(), 1)),
        }
    }
    counts
}

/// The command-file literals that still name a tailor, per function and
/// literal, with how many times, each row owned by the open issue that
/// removes it. The table only shrinks: the counts must match exactly, so
/// the fix that removes a literal also removes its row, and a new literal
/// fails even in a listed function, including a different name swapped in
/// for a listed one.
const TAILOR_NAMING_DEBT: &[(&str, &str, &str, usize)] = &[];

/// A command reaches an ecosystem through the `Tailor` trait and the
/// registry, never by spelling its name: a `"python"` or `"npm"` literal
/// in `src/commands/` is a branch or lookup the import scan above cannot
/// see, and it drifts back into tailor-specific code (layering rule 3).
/// Text that merely mentions a tailor inside a longer message is not a
/// match; only a literal that *is* the name, or names it as a path
/// component, counts.
#[test]
fn commands_do_not_name_tailors_by_string() {
    let words = tailor_words();
    let mut found: Vec<LiteralSite> = production_files()
        .into_iter()
        .filter(|(relative, _)| relative.starts_with("src/commands/"))
        .flat_map(|(relative, text)| literal_sites(&relative, &text, &words))
        .collect();
    found.sort();
    let mut expected: Vec<LiteralSite> = TAILOR_NAMING_DEBT
        .iter()
        .map(|(file, function, literal, count)| {
            (
                file.to_string(),
                function.to_string(),
                literal.to_string(),
                *count,
            )
        })
        .collect();
    expected.sort();
    assert_eq!(
        found, expected,
        "a command names a tailor by string ({words:?}); ask the tailor through a \
         `Tailor` or `RegistryTool` method instead (or, when a row's issue lands, \
         delete the row)"
    );
}

/// Every tar process comes from one helper, `kernel::archive::tar_command`
/// (the host's `/usr/bin/tar` with a scrubbed environment): extraction runs
/// only through the validated extractor (the single-member read,
/// `read_member`, runs no tar at all), and
/// packing (git sources) through its deterministic packer, so the user's
/// `TAR_OPTIONS` cannot reshape what lands in an object. The scan holds
/// the helper to that: tar is named in `tar_command` and nowhere else in
/// production code, in any spelling of a string literal (a `const`, an
/// `OsStr`, a renamed `Command`, an escaped `"t\x61r"`), except a bare
/// `"tar"` given to `with_extension` or `set_extension`, which names a
/// file, not a program (#524). The scan's limit is the literal: a name
/// assembled at compile time (`concat!("t", "ar")`) or at run time is
/// not one, so it is not seen. Test code is exempt (test-only extractors and fixture
/// builders): a test-only item by `production_tokens`, a test-only module
/// file (`kernel/testutil.rs`) by the module tree.
#[test]
fn tar_runs_only_in_kernel_archive() {
    const OWNER: &str = "src/kernel/archive.rs";
    const HELPER: &str = "tar_command";
    let mut sites = Vec::new();
    for (relative, text) in production_files() {
        if relative == OWNER {
            continue;
        }
        for owner in tar_sites(&text) {
            sites.push(format!("{relative}:{owner}"));
        }
    }
    // Inside the owner, the helper is the one site: a second spawn there
    // must go through it too. This is also the positive control: the scan
    // sees the helper's own `/usr/bin/tar`, so a refactor that moves tar
    // out of a string literal fails loudly here instead of passing.
    let root = repo();
    let owner_text = fs::read_to_string(root.join(OWNER)).unwrap();
    assert_eq!(
        tar_sites(&owner_text),
        [HELPER],
        "{OWNER} names tar outside {HELPER}, or the scan no longer sees \
         {HELPER}'s own /usr/bin/tar (and is passing vacuously)"
    );
    assert!(
        sites.is_empty(),
        "tar named outside kernel::archive::{HELPER} (route it through \
         archive::extract_validated_with_activity or archive::pack_ustar_with_activity, \
         or read one member in process with archive::read_member):\n  {}",
        sites.join("\n  ")
    );
}

/// A string literal that names a tar binary: any absolute path ending in
/// `tar`, `bsdtar`, `gtar` or `gnutar`, or one of the last three bare. A bare
/// `"tar"` is not matched here: it is also a file extension
/// (`with_extension`), and [`tar_sites`] tells the two apart.
fn names_a_tar(literal: &str) -> bool {
    const TARS: [&str; 4] = ["tar", "bsdtar", "gtar", "gnutar"];
    let base = literal.rsplit('/').next().unwrap_or(literal);
    (literal.starts_with('/') && TARS.contains(&base)) || TARS[1..].contains(&literal)
}

/// The owners of every production site in `text` that names tar: a literal
/// [`names_a_tar`] accepts, or a bare `"tar"` anywhere but as the argument
/// of `with_extension` or `set_extension`. Where the literal goes next (a
/// `const`, `OsStr::new`, a `Command` under another name) does not matter:
/// a bare `"tar"` that is not a file extension is a program name.
fn tar_sites(text: &str) -> Vec<String> {
    let tokens = production_tokens(text);
    let extension = |index: usize| {
        let before: Vec<&Token> = tokens[..index]
            .iter()
            .rev()
            .take(2)
            .map(|(token, _)| token)
            .collect();
        matches!(
            before.as_slice(),
            [Token::Punct('('), Token::Ident(method)]
                if method == "with_extension" || method == "set_extension"
        )
    };
    tokens
        .iter()
        .enumerate()
        .filter(|(index, (token, _))| match token {
            Token::Str(literal) => names_a_tar(literal) || (literal == "tar" && !extension(*index)),
            _ => false,
        })
        .map(|(_, (_, owner))| owner.clone())
        .collect()
}

#[test]
fn a_bare_tar_is_caught_as_a_program_and_not_as_an_extension() {
    assert_eq!(
        tar_sites(
            "fn a() { Command::new(\"tar\").arg(\"-x\"); }\n\
             fn b() { std::process::Command::new(\"tar\"); }\n\
             fn c() { Command::new( \"tar\" ); }\n\
             fn d() { path.with_extension(\"tar\"); }\n\
             fn e() { Command::new(\"gzip\").arg(\"tar\"); }\n\
             fn f() { Command::new(\"/usr/bin/tar\"); }\n\
             fn g() { buf.set_extension( \"tar\" ); }"
        ),
        ["a", "b", "c", "e", "f"]
    );
}

/// The spellings the first scan missed (review of #482): a `const`, an
/// `OsStr`, and `Command` under another name. The site is where the
/// literal is, so the `const` is owned by the module (`""`), not by the
/// function that uses it.
#[test]
fn tar_is_caught_through_a_const_an_osstr_and_a_renamed_command() {
    assert_eq!(
        tar_sites(
            "const TAR: &str = \"tar\";\n\
             fn a() { Command::new(TAR); }\n\
             fn b() { Command::new(OsStr::new(\"tar\")); }\n\
             fn c() { use std::process::Command as Cmd; Cmd::new(\"tar\"); }\n\
             fn d() { let p = \"/usr/local/bin/gtar\"; }"
        ),
        ["", "b", "c", "d"]
    );
}

/// Escapes spell the same name (review of #524): the scan sees the
/// literal as the program does. A raw string has no escapes, so its
/// backslashes are characters.
#[test]
fn tar_is_caught_through_escaped_spellings() {
    assert_eq!(
        tar_sites(
            "fn a() { Command::new(\"t\\x61r\"); }\n\
             fn b() { Command::new(\"\\u{74}ar\"); }\n\
             fn c() { Command::new(\"/usr/bin/\\x74\\u{0061}r\"); }\n\
             fn d() { Command::new(\"bsd\\\n                 tar\"); }\n\
             fn e() { Command::new(r\"t\\x61r\"); }\n\
             fn f() { path.with_extension(\"t\\x61r\"); }"
        ),
        ["a", "b", "c", "d"]
    );
    assert_eq!(
        unescape(&"a\\\"b\\\\c\\n\\q".chars().collect::<Vec<_>>()),
        "a\"b\\c\n\\q"
    );
}

#[test]
fn tar_names_are_recognised_in_every_spelling() {
    for literal in [
        "/usr/bin/tar",
        "/bin/tar",
        "/opt/homebrew/bin/gtar",
        "bsdtar",
        "gnutar",
    ] {
        assert!(names_a_tar(literal), "{literal}");
    }
    for literal in [
        "tar",
        "foo.tar",
        "/usr/bin/star",
        "contents.tar.gz",
        "/usr/bin/gzip",
    ] {
        assert!(!names_a_tar(literal), "{literal}");
    }
}

/// The literal scan reads string contents through every spelling and skips
/// comments, char literals, prose and test-only items.
#[test]
fn the_literal_scan_sees_every_spelling() {
    let words = vec!["node".to_string(), "py".to_string()];
    let text = "fn plain() { f(\"node\"); f(\"node\"); }\n\
        fn raw() { f(r#\"node\"#); f(r\"py\"); }\n\
        fn byte() { f(b\"py\"); }\n\
        fn escaped() { f(\"say \\\"node\\\"\"); f(\"node:\"); }\n\
        fn comment() { // \"node\"\n /* \"py\" */ f('n'); }\n\
        fn path() { f(\".greyward/closures/node.json\"); f(\"node.json\"); \
            f(\"node_modules/.bin\"); f(\"run node.js x\"); }\n\
        #[cfg(test)]\nfn test_only() { f(\"node\"); }";
    let site = |function: &str, literal: &str, count: usize| {
        (
            "f.rs".to_string(),
            function.to_string(),
            literal.to_string(),
            count,
        )
    };
    assert_eq!(
        literal_sites("f.rs", text, &words),
        [
            site("plain", "node", 2),
            site("raw", "node", 1),
            site("raw", "py", 1),
            site("byte", "py", 1),
            site("path", ".greyward/closures/node.json", 1),
            site("path", "node.json", 1),
        ]
    );
}

/// The files that may name the HTTP client: `kernel::fetch` and its pinned
/// resolver. Everything else fetches through them, so https-only, the
/// redirect and size caps and the user agent hold at every call site.
const HTTP_CLIENT_FILES: &[&str] = &["src/kernel/fetch.rs", "src/kernel/fetch/pinned.rs"];

/// The production lines of `text` that name the `ureq` crate.
fn http_client_sites(text: &str) -> Vec<String> {
    production_tokens(text)
        .into_iter()
        .filter(|(token, _)| is_ident(Some(token), "ureq"))
        .map(|(_, function)| function)
        .collect()
}

#[test]
fn http_goes_through_kernel_fetch() {
    let mut violations = Vec::new();
    for (relative, text) in production_files() {
        if HTTP_CLIENT_FILES.contains(&relative.as_str()) {
            continue;
        }
        for function in http_client_sites(&text) {
            violations.push(format!("{relative}: in fn {function}"));
        }
    }
    assert!(
        violations.is_empty(),
        "ureq named outside kernel::fetch (use fetch_text, fetch_text_or_missing, \
         download_file or download_unpinned):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_http_client_scan_sees_every_spelling() {
    let caught = [
        "fn a() { ureq::get(u).call(); }",
        "use ureq::Agent;\nfn a() {}",
        "fn a() { let x = ureq\n    ::AgentBuilder::new(); }",
        "fn a() -> Option<ureq::RequestUrl> { None }",
    ];
    for text in caught {
        assert!(!http_client_sites(text).is_empty(), "missed: {text}");
    }
    let ignored = [
        "// ureq::get in a comment\nfn a() {}",
        "fn a() { let s = \"ureq::get\"; }",
        "#[cfg(test)]\nmod tests { fn t() { ureq::get(u); } }",
    ];
    for text in ignored {
        assert!(http_client_sites(text).is_empty(), "flagged: {text}");
    }
}

/// The `watched` regex of heavy.yml's `gate` job: the files whose change
/// runs the heavy suite against real archives.
fn gate_watched_regex() -> String {
    let workflow = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/heavy.yml"),
    )
    .unwrap();
    let line = workflow
        .lines()
        .find_map(|line| line.trim().strip_prefix("watched='"))
        .expect("heavy.yml's gate sets watched='<regex>'");
    line.strip_suffix('\'')
        .expect("watched='<regex>' on one line")
        .to_string()
}

/// Which of `paths` the gate's regex matches, evaluated by `grep -E` as
/// the gate itself does.
fn gate_watches(paths: &[String]) -> std::collections::BTreeSet<String> {
    use std::io::Write;
    let mut child = std::process::Command::new("grep")
        .arg("-E")
        .arg("-e")
        .arg(gate_watched_regex())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("run grep");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(paths.join("\n").as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.code().is_some_and(|code| code <= 1),
        "grep failed"
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// Files that read or write archive bytes without waking the heavy suite,
/// each with its reason.
const ARCHIVE_GATE_EXEMPT: &[(&str, &str)] = &[(
    "src/kernel/gitsrc.rs",
    "hands a tree ward checked out at a pinned commit to \
     archive::pack_ustar_with_activity, which the gate watches; the file \
     changes often and its own end-to-end tests run when tests/git*.rs change",
)];

/// The crates whose business is archive bytes: naming one reads or writes
/// an archive, or the compressed stream one is carried in.
const ARCHIVE_CRATES: &[&str] = &["zip", "flate2", "bzip2", "liblzma"];

/// The production sites of `text` (the source of `relative`, under `src/`,
/// the module `module`) that read or write archive bytes: a path that
/// resolves into `kernel::archive` (`named_paths`: through `crate::`,
/// `super::`, `kernel` imported under any name, or a glob import of
/// `crate::kernel`), a path into a crate in `ARCHIVE_CRATES` (by path,
/// `::`-rooted, imported under any name, or `extern crate`), or an `unzip`
/// program.
fn archive_sites(relative: &str, module: &[String], text: &str) -> Vec<String> {
    let relative = relative.trim_start_matches("src/");
    let (named, _) = named_paths(relative, text, module, OPAQUE_MACRO_RULES);
    let mut sites: Vec<String> = named
        .iter()
        .filter_map(|Named { at, root, path, .. }| {
            let archive = match root {
                Root::Crate => path.len() >= 2 && path[0] == "kernel" && path[1] == "archive",
                Root::Other => ARCHIVE_CRATES.contains(&path[0].as_str()),
            };
            let prefix = if *root == Root::Crate { "crate::" } else { "" };
            archive.then(|| format!("line {}: {prefix}{}", at.0, path.join("::")))
        })
        .collect();
    for (token, owner) in production_tokens(text) {
        if let Token::Str(literal) = token {
            if literal == "unzip" || literal.ends_with("/unzip") {
                sites.push(format!("{literal:?} in fn {owner}"));
            }
        }
    }
    sites.sort();
    sites.dedup();
    sites
}

#[test]
fn archive_calls_live_where_the_heavy_gate_looks() {
    let sources = production_sources();
    let watched = gate_watches(
        &sources
            .iter()
            .map(|module| module.relative.clone())
            .collect::<Vec<_>>(),
    );
    let mut violations = Vec::new();
    for module in &sources {
        let relative = &module.relative;
        if watched.contains(relative)
            || ARCHIVE_GATE_EXEMPT.iter().any(|(path, _)| path == relative)
        {
            continue;
        }
        for site in archive_sites(relative, &module.path, &module.text) {
            violations.push(format!("{relative}: {site}"));
        }
    }
    assert!(
        violations.is_empty(),
        "archive bytes read or written in a file heavy.yml's gate does not watch; \
         move the call into the tailor's unpack.rs or unpack/ (or a watched kernel \
         file), so a change to it runs the heavy suite against real archives:\n  {}",
        violations.join("\n  ")
    );
    for (path, _) in ARCHIVE_GATE_EXEMPT {
        let module = sources
            .iter()
            .find(|module| module.relative == *path)
            .unwrap_or_else(|| panic!("{path} is exempt but gone"));
        assert!(
            !archive_sites(path, &module.path, &module.text).is_empty() && !watched.contains(*path),
            "{path} no longer needs its exemption"
        );
    }
}

#[test]
fn the_archive_scan_sees_every_spelling() {
    let go = module_path(Path::new("tailors/go/mod.rs"));
    let caught = [
        "fn a() { crate::kernel::archive::list(p, c); }",
        "use crate::kernel::archive::{self, Compression};",
        "use crate::kernel::{archive, store};",
        "use super::super::kernel::archive::Entry;",
        "use crate::kernel;\nfn a() { kernel::archive::list(p, c); }",
        "use crate::kernel::*;\nfn a() { archive::list(p, c); }",
        "use zip::ZipArchive;",
        "fn a() { let z = zip::ZipArchive::new(f); }",
        "fn a() { Command::new(\"/usr/bin/unzip\"); }",
        "fn a() { Command::new(\"unzip\"); }",
        "#[cfg(test)]\nmod tests {}\nfn a() { crate::kernel::archive::list(p, c); }",
        "fn a() { let z = ::zip::ZipArchive::new(f); }",
        "use ::zip::ZipArchive;",
        "use zip as z;\nfn a() { z::ZipArchive::new(f); }",
        "use {zip as z, std::io};",
        "extern crate zip as z;",
        "fn a() { flate2::GzBuilder::new(); }",
        "use flate2::write::GzEncoder;",
        "fn a() { bzip2::read::BzDecoder::new(f); }",
        "use liblzma::read::XzDecoder;",
        "use crate::kernel as k;\nfn a() { k::archive::list(p, c); }",
        "use crate::{kernel as k, store};\nfn a() { k::archive::list(p, c); }",
        "use crate::{kernel::*, store};\nfn a() { archive::list(p, c); }",
        "use crate::{kernel::{*, store}};\nfn a() { archive::list(p, c); }",
        // Macro input that is not code, opening with a `::`-rooted path.
        "fn a() { opaque! { ::zip::ok() => then } }",
    ];
    for text in caught {
        assert!(
            !archive_sites("src/tailors/go/mod.rs", &go, text).is_empty(),
            "{text}"
        );
    }
    // `super` counts the inline modules around it: in `mod inner` of
    // `kernel/foo.rs`, `super::super` is `kernel`.
    let inline = "mod inner {\n    use super::super::archive;\n}";
    assert!(!archive_sites(
        "src/kernel/foo.rs",
        &module_path(Path::new("kernel/foo.rs")),
        inline
    )
    .is_empty());
    let missed = [
        "fn a() { crate::kernel::fetch::download(u); }",
        "// see archive::list and zip::ZipArchive",
        "#[cfg(test)]\nmod tests { use crate::kernel::archive::list; use zip::ZipWriter; }",
        "use crate::kernel;\nfn a() { archive::list(p, c); }",
        "fn a() { let x = foo.zip(bar); }",
        "fn a() { foo::zip::pair(a, b); }",
        "use crate::kernel as k;\nfn a() { kernel2::archive::x(); k::store::x(); }",
        "use crate::{kernel::store::*};\nfn a() { archive::list(p, c); }",
    ];
    for text in missed {
        assert!(
            archive_sites("src/tailors/go/mod.rs", &go, text).is_empty(),
            "{text}"
        );
    }
}

#[test]
fn the_heavy_gate_watches_the_archive_homes() {
    let paths: Vec<String> = [
        "src/tailors/go/unpack.rs",
        "src/tailors/python/unpack/mod.rs",
        "src/tailors/python/unpack/wheel.rs",
        "src/kernel/archive.rs",
        "src/kernel/archive/validate.rs",
        "src/kernel/dirhash.rs",
        "src/kernel/provider/rust.rs",
        "src/commands/selfupdate.rs",
        "src/tailors/go/mod.rs",
        "src/tailors/go/x/unpack.rs",
        "src/commands/sync.rs",
        "src/kernel/gitsrc.rs",
    ]
    .map(str::to_string)
    .to_vec();
    let watched = gate_watches(&paths);
    for path in &paths[..8] {
        assert!(watched.contains(path), "{path} is not watched");
    }
    for path in &paths[8..] {
        assert!(!watched.contains(path), "{path} is watched");
    }
}
