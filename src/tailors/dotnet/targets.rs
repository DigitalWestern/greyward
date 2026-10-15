//! The newest .NET a layout targets, read the way MSBuild evaluates the
//! properties that name it, so the SDK selected without `global.json` is
//! one that builds every member.
//!
//! For each member the files are read in evaluation order: the
//! `Directory.Build.props` chain (the nearest one, and each one above it
//! that the one below imports), then the project file. Within them a
//! `<TargetFramework>` or `<TargetFrameworks>` declaration sets its
//! property and a later one replaces it, and a non-empty `TargetFramework`
//! wins over `TargetFrameworks`, as in the SDK (it builds that one
//! framework). A declaration MSBuild never applies is ignored: one whose
//! `Condition` (or an enclosing `PropertyGroup`'s or `When`'s) is a
//! constant false (`false`, `'a' == 'b'`), and one inside a `<Target>`,
//! which runs after restore has chosen the frameworks.
//!
//! A condition on project state (`'$(OS)' == 'Windows_NT'`) cannot be
//! evaluated without MSBuild. Such a declaration counts when it names an
//! older framework than the effective ones, since a newer SDK builds both.
//! When it names a newer one, the SDK the project needs depends on the
//! condition: [`Targets::unsure`] names it, and the caller refuses unless
//! the default SDK builds it anyway or `global.json` chooses the SDK.

use super::solution::Layout;
use super::{attribute_values, is_name_byte, strip_comments_and_cdata};
use crate::kernel::fsroot::ProjectRoot;
use std::io;
use std::path::{Path, PathBuf};

/// What [`newest_target_major`] read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Targets {
    /// The highest `netN.0` major any member's effective frameworks name.
    pub newest: Option<u64>,
    /// The highest major a declaration under an unevaluated condition
    /// names, above its member's effective frameworks, with the file
    /// that declares it.
    pub unsure: Option<(u64, PathBuf)>,
}

/// Whether MSBuild applies a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applies {
    Yes,
    No,
    Unknown,
}

impl Applies {
    fn and(self, other: Applies) -> Applies {
        match (self, other) {
            (Applies::No, _) | (_, Applies::No) => Applies::No,
            (Applies::Unknown, _) | (_, Applies::Unknown) => Applies::Unknown,
            _ => Applies::Yes,
        }
    }
}

/// One `<TargetFramework>` or `<TargetFrameworks>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Declaration {
    plural: bool,
    value: String,
    applies: Applies,
}

/// A `Condition` MSBuild evaluates without project state: empty or `true`
/// applies, `false` does not, and `'a' == 'b'` / `'a' != 'b'` over literals
/// compares them (case-insensitively, as MSBuild does; the text is already
/// lowercase). Anything naming a property, item or metadata is unknown.
fn constant(condition: &str) -> Applies {
    let condition = condition.trim();
    if condition.is_empty() || condition == "true" {
        return Applies::Yes;
    }
    if condition == "false" {
        return Applies::No;
    }
    if condition.contains(['$', '@', '%']) {
        return Applies::Unknown;
    }
    let (left, right, equal) = match condition.split_once("==") {
        Some((left, right)) => (left, right, true),
        None => match condition.split_once("!=") {
            Some((left, right)) => (left, right, false),
            None => return Applies::Unknown,
        },
    };
    let literal = |side: &str| {
        let side = side.trim();
        side.strip_prefix('\'')
            .and_then(|side| side.strip_suffix('\''))
            .filter(|inner| !inner.contains('\''))
            .map(str::to_string)
    };
    match (literal(left), literal(right)) {
        (Some(left), Some(right)) if (left == right) == equal => Applies::Yes,
        (Some(_), Some(_)) => Applies::No,
        _ => Applies::Unknown,
    }
}

/// The end of the tag that starts at `markup[0]` (`<`): the index of its
/// `>`, skipping quoted attribute values, which may hold `>`.
fn tag_end(markup: &str) -> Option<usize> {
    let mut quote = None;
    for (at, b) in markup.bytes().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if matches!(b, b'"' | b'\'') => quote = Some(b),
            None if b == b'>' => return Some(at),
            None => {}
        }
    }
    None
}

/// Every target framework declaration in one file (lowercase, comments
/// stripped), in document order, with whether MSBuild applies it.
fn declarations(markup: &str, path: &Path) -> io::Result<Vec<Declaration>> {
    // The open elements, each with whether its contents apply.
    let mut open: Vec<(String, Applies)> = Vec::new();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(start) = markup[at..].find('<').map(|found| at + found) {
        let tag = &markup[start..];
        let Some(end) = tag_end(tag) else {
            break;
        };
        at = start + end + 1;
        let inner = &tag[1..end];
        if inner.starts_with(['?', '!']) {
            continue;
        }
        if let Some(name) = inner.strip_prefix('/') {
            let name = name.trim();
            if let Some(index) = open.iter().rposition(|(open, _)| open == name) {
                open.truncate(index);
            }
            continue;
        }
        let name_end = inner
            .bytes()
            .position(|b| !is_name_byte(b) && !matches!(b, b'.' | b'-' | b':'));
        let name = &inner[..name_end.unwrap_or(inner.len())];
        let empty = inner.ends_with('/');
        let attributes = &inner[name.len()..];
        let own = attribute_values(attributes, "condition", path)?
            .first()
            .map(|condition| constant(condition))
            .unwrap_or(Applies::Yes);
        let parent = open
            .last()
            .map(|(_, applies)| *applies)
            .unwrap_or(Applies::Yes);
        // Properties set inside a target change nothing restore reads.
        let applies = if name == "target" {
            Applies::No
        } else {
            parent.and(own)
        };
        if matches!(name, "targetframework" | "targetframeworks") {
            let value = if empty {
                ""
            } else {
                let body = &markup[at..];
                &body[..body.find('<').unwrap_or(body.len())]
            };
            found.push(Declaration {
                plural: name == "targetframeworks",
                value: value.trim().to_string(),
                applies,
            });
        }
        if !empty {
            open.push((name.to_string(), applies));
        }
    }
    Ok(found)
}

/// `N` for `netN.0` with N of 5 or more (with or without a platform
/// suffix, `net10.0-windows`).
fn net_major(framework: &str) -> Option<u64> {
    let digits = framework.strip_prefix("net")?;
    let (major, _) = digits.split_once('.')?;
    let major: u64 = major.parse().ok()?;
    (major >= 5).then_some(major)
}

/// The highest major a framework list names.
fn list_major(value: &str) -> Option<u64> {
    value
        .split(';')
        .filter_map(|framework| net_major(framework.trim()))
        .max()
}

/// The file's text, lowercase with comments stripped; `None` when absent.
fn markup(project: &ProjectRoot, file: &Path) -> io::Result<Option<String>> {
    let Some(bytes) = project.read_file(file)? else {
        return Ok(None);
    };
    let text = super::decode_msbuild(&bytes)?;
    let text = strip_comments_and_cdata(&text, &project.path().join(file))?;
    Ok(Some(text.to_ascii_lowercase()))
}

/// Does a `Directory.Build.props` import the one above it? MSBuild reads
/// only the nearest; the template for chaining imports it through
/// `GetPathOfFileAbove` or by a relative path naming the file.
fn imports_above(markup: &str) -> bool {
    markup.contains("<import")
        && (markup.contains("getpathoffileabove") || markup.contains("directory.build.props"))
}

/// The `Directory.Build.props` files MSBuild evaluates before `member`,
/// outermost first, each with its markup.
fn props_chain(project: &ProjectRoot, member: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let mut chain = Vec::new();
    let mut dir = member.parent();
    while let Some(current) = dir {
        dir = current.parent();
        let props = current.join("Directory.Build.props");
        let Some(text) = markup(project, &props)? else {
            continue;
        };
        let more = imports_above(&text);
        chain.push((props, text));
        if !more {
            break;
        }
    }
    chain.reverse();
    Ok(chain)
}

/// One member's effective majors and its unsure ones above them.
fn member_targets(project: &ProjectRoot, member: &Path) -> io::Result<Targets> {
    let mut files = props_chain(project, member)?;
    if let Some(text) = markup(project, member)? {
        files.push((member.to_path_buf(), text));
    }
    // Per property (singular, plural): the applied value and the unsure
    // declarations since it.
    let mut value: [Option<String>; 2] = [None, None];
    let mut unsure: [Vec<(u64, PathBuf)>; 2] = [Vec::new(), Vec::new()];
    for (file, text) in &files {
        for declaration in declarations(text, &project.path().join(file))? {
            let slot = usize::from(declaration.plural);
            match declaration.applies {
                Applies::No => {}
                Applies::Yes => {
                    value[slot] = Some(declaration.value);
                    unsure[slot].clear();
                }
                Applies::Unknown => {
                    if let Some(major) = list_major(&declaration.value) {
                        unsure[slot].push((major, file.clone()));
                    }
                }
            }
        }
    }
    let single = value[0].as_deref().filter(|value| !value.is_empty());
    let (newest, candidates) = match single {
        Some(single) => (list_major(single), &unsure[0][..]),
        None => {
            let plural = value[1].as_deref().and_then(list_major);
            // Either property may still be set under its condition.
            let plural_unsure = std::mem::take(&mut unsure[1]);
            unsure[0].extend(plural_unsure);
            (plural, &unsure[0][..])
        }
    };
    let unsure = candidates
        .iter()
        .filter(|(major, _)| Some(*major) > newest)
        .max_by_key(|(major, _)| *major)
        .cloned();
    // An unsure framework no newer than the effective ones is built by the
    // same SDK, so it counts.
    let newest = newest.max(
        candidates
            .iter()
            .map(|(major, _)| *major)
            .filter(|major| Some(*major) <= newest)
            .max(),
    );
    Ok(Targets { newest, unsure })
}

/// The newest .NET the layout targets: the highest effective `netN.0`
/// major across members (module docs). An SDK builds its own major and
/// every older one, so this is the oldest SDK major that builds the whole
/// layout. `netstandard`, `netcoreapp`, .NET Framework (`net48`) and
/// property references name no such major.
pub(crate) fn newest_target_major(project: &ProjectRoot, layout: &Layout) -> io::Result<Targets> {
    let mut all = Targets::default();
    for member in &layout.members {
        let targets = member_targets(project, member)?;
        all.newest = all.newest.max(targets.newest);
        if targets.unsure.as_ref().map(|(major, _)| major)
            > all.unsure.as_ref().map(|(major, _)| major)
        {
            all.unsure = targets.unsure;
        }
    }
    if all.unsure.as_ref().map(|(major, _)| Some(*major)) <= Some(all.newest) {
        all.unsure = None;
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    fn effective(text: &str) -> (Option<u64>, Option<u64>) {
        let temp = TempDir::named("dotnet-targets-one");
        fs::write(temp.0.join("App.csproj"), text).unwrap();
        let root = ProjectRoot::open(&temp.0).unwrap();
        let targets = member_targets(&root, Path::new("App.csproj")).unwrap();
        (targets.newest, targets.unsure.map(|(major, _)| major))
    }

    fn group(body: &str) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>{body}</PropertyGroup></Project>"
        )
    }

    #[test]
    fn effective_declarations_choose_the_framework() {
        assert_eq!(
            effective(&group(
                "<TargetFrameworks>netstandard2.0;net8.0;net10.0-windows</TargetFrameworks>"
            )),
            (Some(10), None)
        );
        for none in [
            "<TargetFramework>net48</TargetFramework>",
            "<TargetFramework>netcoreapp3.1</TargetFramework>",
            "<TargetFramework>$(Tfm)</TargetFramework>",
            "<TargetFrameworkVersion>v4.8</TargetFrameworkVersion>",
            "",
        ] {
            assert_eq!(effective(&group(none)), (None, None), "{none}");
        }
        // A later declaration replaces an earlier one.
        assert_eq!(
            effective(&group(
                "<TargetFramework>net11.0</TargetFramework><TargetFramework>net8.0</TargetFramework>"
            )),
            (Some(8), None)
        );
        // A non-empty TargetFramework wins over TargetFrameworks.
        assert_eq!(
            effective(&group(
                "<TargetFrameworks>net11.0;net8.0</TargetFrameworks><TargetFramework>net8.0</TargetFramework>"
            )),
            (Some(8), None)
        );
    }

    #[test]
    fn inactive_branches_are_ignored() {
        // The review's case: a constant-false condition names an SDK the
        // project never asks for.
        assert_eq!(
            effective(&group(
                "<TargetFramework>net8.0</TargetFramework>\
                 <TargetFramework Condition=\"false\">net11.0</TargetFramework>"
            )),
            (Some(8), None)
        );
        assert_eq!(
            effective(
                "<Project><PropertyGroup Condition=\" 'a' == 'b' \"><TargetFramework>net11.0</TargetFramework></PropertyGroup>\
                 <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>"
            ),
            (Some(8), None)
        );
        assert_eq!(
            effective(&group(
                "<TargetFramework Condition=\"'x' != 'x'\">net11.0</TargetFramework>"
            )),
            (None, None)
        );
        assert_eq!(
            effective(&group(
                "<TargetFramework Condition=\"'x' == 'X'\">net10.0</TargetFramework>"
            )),
            (Some(10), None)
        );
        // A property set inside a target is past restore.
        assert_eq!(
            effective(
                "<Project><Target Name=\"T\"><PropertyGroup><TargetFramework>net11.0</TargetFramework>\
                 </PropertyGroup></Target><PropertyGroup><TargetFramework>net8.0</TargetFramework>\
                 </PropertyGroup></Project>"
            ),
            (Some(8), None)
        );
    }

    #[test]
    fn a_condition_on_project_state_is_unsure_only_above() {
        let windows = "<TargetFramework>net8.0</TargetFramework>\
             <TargetFramework Condition=\"'$(OS)' == 'Windows_NT'\">net10.0-windows</TargetFramework>";
        assert_eq!(effective(&group(windows)), (Some(8), Some(10)));
        let older = "<TargetFramework>net9.0</TargetFramework>\
             <TargetFramework Condition=\"'$(Legacy)' == 'true'\">net6.0</TargetFramework>";
        assert_eq!(effective(&group(older)), (Some(9), None));
        // An applied declaration after it settles it.
        let settled = "<TargetFramework Condition=\"'$(X)' != ''\">net11.0</TargetFramework>\
             <TargetFramework>net8.0</TargetFramework>";
        assert_eq!(effective(&group(settled)), (Some(8), None));
        // A Choose branch is a condition too, and `>` in it stays inside the tag.
        let choose = "<Project><Choose><When Condition=\"'$(V)' > '1'\"><PropertyGroup>\
             <TargetFrameworks>net10.0</TargetFrameworks></PropertyGroup></When></Choose></Project>";
        assert_eq!(effective(choose), (None, Some(10)));
    }

    #[test]
    fn the_props_chain_is_the_one_msbuild_imports() {
        let temp = TempDir::named("dotnet-targets-chain");
        fs::create_dir_all(temp.0.join("src/App")).unwrap();
        fs::write(
            temp.0.join("src/App/App.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><!-- <TargetFramework>net11.0</TargetFramework> --></Project>",
        )
        .unwrap();
        fs::write(
            temp.0.join("Directory.Build.props"),
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
        )
        .unwrap();
        let root = ProjectRoot::open(&temp.0).unwrap();
        let layout = Layout {
            solution: None,
            members: vec![PathBuf::from("src/App/App.csproj")],
            skipped: Vec::new(),
        };
        assert_eq!(
            newest_target_major(&root, &layout).unwrap().newest,
            Some(10)
        );
        // A nearer props file that does not import the outer one hides it.
        fs::write(
            temp.0.join("src/Directory.Build.props"),
            "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>",
        )
        .unwrap();
        assert_eq!(newest_target_major(&root, &layout).unwrap().newest, Some(8));
        // One that imports it is evaluated after it, so its value wins.
        fs::write(
            temp.0.join("src/Directory.Build.props"),
            "<Project><Import Project=\"$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))\" />\
             <PropertyGroup><TargetFrameworks>net8.0;net9.0</TargetFrameworks></PropertyGroup></Project>",
        )
        .unwrap();
        // TargetFramework from the outer file still wins over the plural.
        assert_eq!(
            newest_target_major(&root, &layout).unwrap().newest,
            Some(10)
        );
    }
}
