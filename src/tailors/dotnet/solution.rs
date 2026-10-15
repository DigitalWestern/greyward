//! Which projects a .NET checkout restores: the root solution's members, or
//! the single root project when there is no solution.
//!
//! A solution (`.sln` or `.slnx`) lists projects of every kind Visual
//! Studio knows. Restore runs once over the members it can run on Linux
//! with the store SDK, through a classic `.sln` ward generates (absolute
//! member paths, every SDK reads it), and each member gets its own
//! packages.lock.json beside it. A listed project restore cannot run is
//! skipped, and the skip is a `requirement-skipped` exception unless the
//! project has no NuGet dependencies to skip:
//!
//! | listed project | outcome |
//! |---|---|
//! | SDK-style `.csproj`/`.fsproj`/`.vbproj` on bundled SDKs | member |
//! | legacy project with `<PackageReference>` | member |
//! | legacy project with neither PackageReference nor packages.config | skipped silently (no NuGet dependencies) |
//! | shared project (`.shproj`) | skipped silently (compiled into the projects importing it) |
//! | legacy project with packages.config | skipped, recorded |
//! | a project on an MSBuild SDK NuGet fetches (`Sdk="X/1.0"`, Aspire) | skipped, recorded |
//! | any other kind (`.vcxproj`, `.wixproj`, `.sqlproj`, `.esproj`, ...) | skipped, recorded |
//! | a path missing from the checkout (an absent submodule) or outside it | skipped, recorded |
//!
//! When nothing restorable remains the project is refused.

use super::{err, root_names, strip_comments_and_cdata, LOCK_FILE};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use std::io;
use std::path::{Component, Path, PathBuf};

/// The project file extensions NuGet restores.
pub(crate) const PROJECT_EXTENSIONS: [&str; 3] = ["csproj", "fsproj", "vbproj"];

/// A solution folder's project type: a name in the tree, not a project.
const FOLDER_TYPE: &str = "2150E333-8FDC-42A3-9474-1A3956D46DE8";

/// One listed project restore does not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Skipped {
    pub path: String,
    pub why: String,
    /// Recorded as a `requirement-skipped` exception: the project may have
    /// dependencies ward does not lock.
    pub record: bool,
}

/// What restore covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    /// The root solution, project-relative; `None` for a single project.
    pub solution: Option<PathBuf>,
    /// The projects restore runs over, project-relative, in listing order.
    pub members: Vec<PathBuf>,
    pub skipped: Vec<Skipped>,
}

impl Layout {
    /// Each member's packages.lock.json, project-relative.
    pub fn member_locks(&self) -> Vec<PathBuf> {
        self.members
            .iter()
            .map(|member| lock_beside(member))
            .collect()
    }
}

/// The packages.lock.json beside a project file.
pub(crate) fn lock_beside(project_file: &Path) -> PathBuf {
    project_file
        .parent()
        .unwrap_or(Path::new(""))
        .join(LOCK_FILE)
}

/// Is `path` a project file NuGet restores?
pub(crate) fn is_project_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            PROJECT_EXTENSIONS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(extension))
        })
}

fn is_solution_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sln") || lower.ends_with(".slnx")
}

/// The project paths a classic `.sln` lists, as written (backslashes
/// turned to slashes). Solution folders are left out.
pub(crate) fn parse_sln(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if !line.starts_with("Project(") {
            continue;
        }
        // Project("{TYPE}") = "Name", "Path", "{GUID}"
        let quoted: Vec<&str> = line.split('"').collect();
        let (Some(kind), Some(path)) = (quoted.get(1), quoted.get(5)) else {
            continue;
        };
        if kind
            .trim_matches(|c| c == '{' || c == '}')
            .eq_ignore_ascii_case(FOLDER_TYPE)
        {
            continue;
        }
        paths.push(path.replace('\\', "/"));
    }
    paths
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The `Path` of every `<Project>` an `.slnx` lists. Folders hold
/// `<Project>` and `<File>` elements; only projects are listed.
pub(crate) fn parse_slnx(text: &str, path: &Path) -> io::Result<Vec<String>> {
    let markup = strip_comments_and_cdata(text, path)?;
    let mut paths = Vec::new();
    let mut rest = markup.as_str();
    while let Some(at) = rest.find("<Project") {
        let tag = &rest[at + "<Project".len()..];
        rest = tag;
        if !tag.starts_with(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>') {
            continue;
        }
        let end = tag.find('>').unwrap_or(tag.len());
        let attributes = &tag[..end];
        if let Some(value) = attribute(attributes, "Path") {
            paths.push(xml_unescape(value).replace('\\', "/"));
        }
    }
    Ok(paths)
}

/// The quoted value of `name=` among `attributes`, `name` a whole word.
fn attribute<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
    let bytes = attributes.as_bytes();
    let mut from = 0;
    while let Some(found) = attributes[from..].find(name) {
        let start = from + found;
        from = start + name.len();
        if start > 0 && !bytes[start - 1].is_ascii_whitespace() {
            continue;
        }
        let after = attributes[from..].trim_start();
        let Some(after) = after.strip_prefix('=') else {
            continue;
        };
        let after = after.trim_start();
        let quote = after.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let value = &after[1..];
        return value.find(quote).map(|end| &value[..end]);
    }
    None
}

/// A listed path inside the project, `..` resolved; `None` for an
/// absolute path or one that leaves the project.
fn inside(raw: &str) -> Option<PathBuf> {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(part) => parts.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.iter().collect())
}

/// The MSBuild SDK names `markup` (lowercase, comments stripped) uses: the
/// `Sdk` attributes (a root `Sdk="A;B"`, an `<Import Sdk=...>`) and the
/// `<Sdk Name=...>` elements, each with any `/version` kept.
pub(crate) fn sdk_names(markup: &str, path: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for value in super::attribute_values(markup, "sdk", path)? {
        names.extend(
            value
                .split(';')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string),
        );
    }
    let mut rest = markup;
    while let Some(at) = rest.find("<sdk") {
        let tag = &rest[at + 4..];
        rest = tag;
        if !tag.starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let end = tag.find('>').unwrap_or(tag.len());
        if let Some(name) = attribute(&tag[..end], "name") {
            let version = attribute(&tag[..end], "version");
            names.push(match version {
                Some(version) => format!("{}/{version}", name.trim()),
                None => name.trim().to_string(),
            });
        }
    }
    Ok(names)
}

/// Is `name` (lowercase) an MSBuild SDK the .NET SDK carries, so nothing
/// outside the store SDK is fetched to evaluate it? The `Microsoft.NET.Sdk`
/// family is; one named with a version, or any other, is resolved from
/// NuGet when MSBuild evaluates the project, which no lock pins.
pub(crate) fn bundled_sdk(name: &str) -> bool {
    !name.contains('/') && (name == "microsoft.net.sdk" || name.starts_with("microsoft.net.sdk."))
}

enum Listed {
    Member(PathBuf),
    Skipped(Skipped),
}

fn skipped(path: &str, why: impl Into<String>, record: bool) -> Listed {
    Listed::Skipped(Skipped {
        path: path.to_string(),
        why: why.into(),
        record,
    })
}

/// What one listed project is.
fn classify(project: &ProjectRoot, raw: &str) -> io::Result<Listed> {
    let Some(path) = inside(raw) else {
        return Ok(skipped(raw, "the path is outside the project", true));
    };
    let shown = path.to_string_lossy().into_owned();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if extension == "shproj" {
        return Ok(skipped(
            &shown,
            "a shared project is compiled into the projects that import it",
            false,
        ));
    }
    if !is_project_file(&path) {
        return Ok(skipped(
            &shown,
            format!("a .{extension} project is not one NuGet restores on this platform"),
            true,
        ));
    }
    match project.entry(&path)? {
        Entry::Regular => {}
        Entry::Absent => {
            return Ok(skipped(
                &shown,
                "the solution lists it, but the checkout has no such file (a submodule not \
                 checked out?)",
                true,
            ))
        }
        _ => {
            return Ok(skipped(
                &shown,
                "the listed path is not a regular file",
                true,
            ));
        }
    }
    let text = super::read_input_text(project, &path)?;
    let markup = strip_comments_and_cdata(&text, &path)?.to_ascii_lowercase();
    let sdks = sdk_names(&markup, &path)?;
    if let Some(fetched) = sdks.iter().find(|name| !bundled_sdk(name)) {
        return Ok(skipped(
            &shown,
            format!(
                "it uses the MSBuild SDK {fetched}, which NuGet fetches when MSBuild evaluates \
                 the project and no lock pins"
            ),
            true,
        ));
    }
    if sdks.is_empty() {
        // A legacy (non-SDK) project: NuGet restores it only through
        // PackageReference items.
        let config = path
            .parent()
            .unwrap_or(Path::new(""))
            .join("packages.config");
        if project.is_input_file(&config) {
            return Ok(skipped(
                &shown,
                "a packages.config project restores through nuget.exe, which has no lock",
                true,
            ));
        }
        if !super::opens_element(&markup, "packagereference") {
            return Ok(skipped(
                &shown,
                "a legacy project with no NuGet dependencies",
                false,
            ));
        }
    }
    Ok(Listed::Member(path))
}

/// The projects a solution lists, as written.
fn listed(project: &ProjectRoot, solution: &Path) -> io::Result<Vec<String>> {
    let text = super::read_input_text(project, solution)?;
    let text = text.trim_start_matches('\u{feff}');
    let is_slnx = solution
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("slnx"));
    if is_slnx {
        parse_slnx(text, &project.path().join(solution))
    } else {
        Ok(parse_sln(text))
    }
}

/// The root's layout. With several root solutions, the one listing the
/// most projects (ties by name) is restored: the others are usually a
/// subset (an installer, a filter of the same tree).
pub(crate) fn discover(project: &ProjectRoot) -> io::Result<Layout> {
    let mut solutions = Vec::new();
    let mut projects = Vec::new();
    for name in root_names(project)? {
        let path = PathBuf::from(&name);
        let text = name.to_string_lossy();
        if is_solution_name(&text) {
            solutions.push(path);
        } else if is_project_file(&path) {
            projects.push(path);
        }
    }
    solutions.sort();
    projects.sort();
    if solutions.is_empty() {
        return match projects.len() {
            1 => Ok(Layout {
                solution: None,
                members: projects,
                skipped: Vec::new(),
            }),
            0 => Err(err("no .csproj, .fsproj, .vbproj or solution file found")),
            _ => Err(err(format!(
                "several project files ({}) and no solution: add a .sln or .slnx that lists them",
                projects
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        };
    }
    let mut chosen: Option<(PathBuf, Vec<String>)> = None;
    for solution in solutions {
        if project.entry(&solution)? != Entry::Regular {
            return Err(err(format!(
                "{} must be a regular file",
                project.path().join(&solution).display()
            )));
        }
        let entries = listed(project, &solution)?;
        if chosen
            .as_ref()
            .is_none_or(|(_, best)| entries.len() > best.len())
        {
            chosen = Some((solution, entries));
        }
    }
    let (solution, entries) = chosen.expect("at least one solution");
    let mut members: Vec<PathBuf> = Vec::new();
    let mut skipped = Vec::new();
    for raw in entries {
        match classify(project, &raw)? {
            Listed::Member(path) => {
                if !members.contains(&path) {
                    members.push(path);
                }
            }
            Listed::Skipped(skip) => skipped.push(skip),
        }
    }
    if members.is_empty() {
        let reasons: Vec<String> = skipped
            .iter()
            .take(5)
            .map(|skip| format!("{}: {}", skip.path, skip.why))
            .collect();
        return Err(err(format!(
            "{} lists no project NuGet can restore here{}{}",
            solution.display(),
            if reasons.is_empty() { "" } else { "; " },
            reasons.join("; ")
        )));
    }
    for (index, member) in members.iter().enumerate() {
        if let Some(other) = members[..index]
            .iter()
            .find(|other| other.parent() == member.parent())
        {
            return Err(err(format!(
                "{} and {} share a directory, so restore would write both locks to one {}; \
                 move one into its own directory",
                other.display(),
                member.display(),
                lock_beside(member).display()
            )));
        }
    }
    Ok(Layout {
        solution: Some(solution),
        members,
        skipped,
    })
}

/// Characters MSBuild reads as syntax in a `-p:` value or a solution path.
fn plain_path(path: &Path) -> io::Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| err(format!("{} is not UTF-8", path.display())))?;
    if let Some(bad) = text
        .chars()
        .find(|c| matches!(c, ';' | ',' | '"' | '%' | '$' | '@' | '\'' | '\n' | '\r'))
    {
        return Err(err(format!(
            "{text}: the path holds {bad:?}, which MSBuild reads as syntax in a property or a \
             solution; restore a solution from a plainer path"
        )));
    }
    Ok(text)
}

/// A project type GUID by extension (what Visual Studio writes).
fn project_type(member: &Path) -> &'static str {
    match member
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("fsproj") => "F2A71F9B-5D33-465A-A702-920D77279786",
        Some("vbproj") => "F184B08F-C81C-45F6-A57F-5ABD9991F28F",
        _ => "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC",
    }
}

/// The classic `.sln` restore runs: `members` by absolute path under
/// `root`, with fixed GUIDs, a distinct name each, and Debug, Release and
/// any configuration a build names (`extra_configurations`). Every SDK in the catalog reads it, where `.slnx` needs 9.0.200.
pub(crate) fn generated_sln(
    root: &Path,
    members: &[PathBuf],
    extra_configurations: &[String],
) -> io::Result<String> {
    let mut text =
        String::from("\u{feff}\nMicrosoft Visual Studio Solution File, Format Version 12.00\n");
    let configurations = configurations(extra_configurations)?;
    let mut configs = String::new();
    let mut names = std::collections::BTreeSet::new();
    for (index, member) in members.iter().enumerate() {
        let absolute = root.join(member);
        let absolute = plain_path(&absolute)?;
        let stem = member
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("project");
        // MSBuild refuses a solution with two projects of one name (MSB5004);
        // the name is a label, references go by path.
        let name = if names.insert(stem.to_ascii_lowercase()) {
            stem.to_string()
        } else {
            format!("{stem}-{}", index + 1)
        };
        names.insert(name.to_ascii_lowercase());
        let guid = format!("{{00000000-0000-0000-0000-{:012X}}}", index + 1);
        text.push_str(&format!(
            "Project(\"{{{}}}\") = \"{name}\", \"{absolute}\", \"{guid}\"\nEndProject\n",
            project_type(member)
        ));
        for configuration in &configurations {
            configs.push_str(&format!(
                "\t\t{guid}.{configuration}|Any CPU.ActiveCfg = {configuration}|Any CPU\n\
                 \t\t{guid}.{configuration}|Any CPU.Build.0 = {configuration}|Any CPU\n"
            ));
        }
    }
    text.push_str("Global\n\tGlobalSection(SolutionConfigurationPlatforms) = preSolution\n");
    for configuration in &configurations {
        text.push_str(&format!(
            "\t\t{configuration}|Any CPU = {configuration}|Any CPU\n"
        ));
    }
    text.push_str(
        "\tEndGlobalSection\n\
         \tGlobalSection(ProjectConfigurationPlatforms) = postSolution\n",
    );
    text.push_str(&configs);
    text.push_str("\tEndGlobalSection\nEndGlobal\n");
    Ok(text)
}

/// Debug, Release, and any configuration a build names, each once: a
/// solution build with `-c X` fails unless the solution has X. A name
/// that could break the solution's lines is refused.
fn configurations(extra: &[String]) -> io::Result<Vec<String>> {
    let mut all = vec!["Debug".to_string(), "Release".to_string()];
    for name in extra {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            return Err(super::err(format!(
                "build configuration {name:?}: only letters, digits, '.', '-' and '_' are supported"
            )));
        }
        if !all.iter().any(|held| held.eq_ignore_ascii_case(name)) {
            all.push(name.clone());
        }
    }
    Ok(all)
}

/// The solution properties MSBuild would set building the user's own
/// solution, as global properties: the generated one lives in scratch, and
/// a project reading `$(SolutionDir)` must see the checkout.
pub(crate) fn solution_properties(root: &Path, solution: &Path) -> io::Result<Vec<String>> {
    let dir = plain_path(root)?;
    let path = root.join(solution);
    let path = plain_path(&path)?;
    let file = solution
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let stem = solution
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    let ext = solution
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();
    Ok(vec![
        format!("-p:SolutionDir={dir}/"),
        format!("-p:SolutionPath={path}"),
        format!("-p:SolutionName={stem}"),
        format!("-p:SolutionFileName={file}"),
        format!("-p:SolutionExt={ext}"),
    ])
}

/// The newest .NET the layout targets: the highest `netN.0` major named in
/// a `<TargetFramework>` or `<TargetFrameworks>` of a member or of a
/// `Directory.Build.props` in a member's directory or above it. An SDK
/// builds its own major and every older one, so this is the oldest SDK
/// major that can build the whole layout. `netstandard`, `netcoreapp`,
/// .NET Framework (`net48`) and property references name no such major.
pub(crate) fn newest_target_major(
    project: &ProjectRoot,
    layout: &Layout,
) -> io::Result<Option<u64>> {
    let mut files: Vec<PathBuf> = Vec::new();
    for member in &layout.members {
        files.push(member.clone());
        let mut dir = member.parent();
        while let Some(current) = dir {
            let props = current.join("Directory.Build.props");
            if !files.contains(&props) {
                files.push(props);
            }
            dir = current.parent();
        }
    }
    let mut newest = None;
    for file in files {
        let Some(bytes) = project.read_file(&file)? else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let text = strip_comments_and_cdata(&text, &project.path().join(&file))?;
        newest = newest.max(text_target_major(&text));
    }
    Ok(newest)
}

/// The highest `netN.0` major in one project file's target framework
/// elements ([`newest_target_major`]).
fn text_target_major(text: &str) -> Option<u64> {
    let lower = text.to_ascii_lowercase();
    let mut newest = None;
    let mut rest = lower.as_str();
    while let Some(start) = rest.find("<targetframework") {
        rest = &rest[start..];
        let Some(open_end) = rest.find('>') else {
            break;
        };
        let body = &rest[open_end + 1..];
        let end = body.find('<').unwrap_or(body.len());
        for framework in body[..end].split(';') {
            newest = newest.max(net_major(framework.trim()));
        }
        rest = &body[end..];
    }
    newest
}

/// `N` for `netN.0` with N of 5 or more (with or without a platform
/// suffix, `net10.0-windows`).
fn net_major(framework: &str) -> Option<u64> {
    let digits = framework.strip_prefix("net")?;
    let (major, _) = digits.split_once('.')?;
    let major: u64 = major.parse().ok()?;
    (major >= 5).then_some(major)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    #[test]
    fn newest_target_major_reads_members_and_build_props() {
        assert_eq!(
            text_target_major(
                "<TargetFrameworks>netstandard2.0;net8.0;net10.0-windows</TargetFrameworks>"
            ),
            Some(10)
        );
        for none in [
            "<TargetFramework>net48</TargetFramework>",
            "<TargetFramework>netcoreapp3.1</TargetFramework>",
            "<TargetFramework>$(Tfm)</TargetFramework>",
            "<TargetFrameworkVersion>v4.8</TargetFrameworkVersion>",
            "",
        ] {
            assert_eq!(text_target_major(none), None, "{none}");
        }
        let temp = TempDir::named("dotnet-target-major");
        fs::create_dir_all(temp.0.join("src/App")).unwrap();
        fs::write(
            temp.0.join("src/App/App.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><!-- <TargetFramework>net11.0</TargetFramework> -->\
             <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>",
        )
        .unwrap();
        let root = ProjectRoot::open(&temp.0).unwrap();
        let layout = Layout {
            solution: None,
            members: vec![PathBuf::from("src/App/App.csproj")],
            skipped: Vec::new(),
        };
        assert_eq!(newest_target_major(&root, &layout).unwrap(), Some(8));
        fs::write(
            temp.0.join("Directory.Build.props"),
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
        )
        .unwrap();
        assert_eq!(newest_target_major(&root, &layout).unwrap(), Some(10));
    }

    const SLN: &str = r#"
Microsoft Visual Studio Solution File, Format Version 12.00
Project("{9A19103F-16F7-4668-BE54-9A1E7A4F7556}") = "App", "src\App\App.csproj", "{11111111-0000-0000-0000-000000000001}"
EndProject
Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = ".Database", ".Database", "{11111111-0000-0000-0000-000000000002}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "Native", "native\Native.vcxproj", "{11111111-0000-0000-0000-000000000003}"
EndProject
"#;

    #[test]
    fn a_classic_solution_lists_projects_not_folders() {
        assert_eq!(
            parse_sln(SLN),
            ["src/App/App.csproj", "native/Native.vcxproj"]
        );
    }

    #[test]
    fn an_slnx_lists_its_projects_in_folders() {
        let text = r#"<Solution>
  <!-- <Project Path="commented/Out.csproj" /> -->
  <Folder Name="/src/">
    <File Path="README.md" />
    <Project Path="src\Lib\Lib.csproj" />
    <Project Path="src/A&amp;B/AB.fsproj" Type="Classic F#" />
  </Folder>
  <Project Path='tools/Tool.csproj'/>
  <Projects />
</Solution>"#;
        assert_eq!(
            parse_slnx(text, Path::new("x.slnx")).unwrap(),
            [
                "src/Lib/Lib.csproj",
                "src/A&B/AB.fsproj",
                "tools/Tool.csproj"
            ]
        );
    }

    fn sdk(body: &str) -> String {
        format!("<Project Sdk=\"Microsoft.NET.Sdk\">{body}</Project>")
    }

    #[test]
    fn every_listed_project_is_a_member_or_a_named_skip() {
        let temp = TempDir::named("dotnet-solution");
        let root = &temp.0;
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write("app/App.csproj", &sdk(""));
        write(
            "web/Web.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\" />",
        );
        write("fs/Lib.fsproj", &sdk(""));
        write(
            "legacy-refs/L.csproj",
            "<Project ToolsVersion=\"15.0\"><ItemGroup><PackageReference Include=\"X\" Version=\"1.0.0\" /></ItemGroup></Project>",
        );
        write("legacy-none/N.csproj", "<Project ToolsVersion=\"4.0\" />");
        write("legacy-config/C.csproj", "<Project ToolsVersion=\"4.0\" />");
        write("legacy-config/packages.config", "<packages />");
        write(
            "nuget-sdk/S.csproj",
            "<Project Sdk=\"Microsoft.Build.NoTargets/3.7.0\" />",
        );
        write(
            "aspire/A.csproj",
            &sdk("<Sdk Name=\"Aspire.AppHost.Sdk\" Version=\"9.0.0\" />"),
        );
        write("shared/Shared.shproj", "<Project />");
        write("native/Native.vcxproj", "<Project />");
        let entries = [
            "app/App.csproj",
            "web/Web.csproj",
            "fs/Lib.fsproj",
            "legacy-refs/L.csproj",
            "legacy-none/N.csproj",
            "legacy-config/C.csproj",
            "nuget-sdk/S.csproj",
            "aspire/A.csproj",
            "shared/Shared.shproj",
            "native/Native.vcxproj",
            "missing/M.csproj",
            "../outside/O.csproj",
            "app/../app/App.csproj",
        ];
        let sln: String = entries
            .iter()
            .map(|path| {
                format!("Project(\"{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}\") = \"x\", \"{path}\", \"{{0}}\"\nEndProject\n")
            })
            .collect();
        write("All.sln", &sln);
        write(
            "Small.slnx",
            "<Solution><Project Path=\"app/App.csproj\" /></Solution>",
        );
        let layout = discover(&ProjectRoot::open(root).unwrap()).unwrap();
        assert_eq!(layout.solution, Some(PathBuf::from("All.sln")));
        assert_eq!(
            layout.members,
            [
                PathBuf::from("app/App.csproj"),
                "web/Web.csproj".into(),
                "fs/Lib.fsproj".into(),
                "legacy-refs/L.csproj".into(),
            ]
        );
        let skips: Vec<(&str, bool)> = layout
            .skipped
            .iter()
            .map(|skip| (skip.path.as_str(), skip.record))
            .collect();
        assert_eq!(
            skips,
            [
                ("legacy-none/N.csproj", false),
                ("legacy-config/C.csproj", true),
                ("nuget-sdk/S.csproj", true),
                ("aspire/A.csproj", true),
                ("shared/Shared.shproj", false),
                ("native/Native.vcxproj", true),
                ("missing/M.csproj", true),
                ("../outside/O.csproj", true),
            ]
        );
        assert!(layout.skipped[2]
            .why
            .contains("microsoft.build.notargets/3.7.0"));
        assert!(layout.skipped[3].why.contains("aspire.apphost.sdk/9.0.0"));
        assert_eq!(
            layout.member_locks()[0],
            PathBuf::from("app/packages.lock.json")
        );
    }

    #[test]
    fn a_solution_with_nothing_restorable_is_refused() {
        let temp = TempDir::named("dotnet-solution-none");
        fs::write(
            temp.0.join("Native.sln"),
            "Project(\"{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}\") = \"N\", \"N.vcxproj\", \"{1}\"\nEndProject\n",
        )
        .unwrap();
        let why = discover(&ProjectRoot::open(&temp.0).unwrap())
            .unwrap_err()
            .to_string();
        assert!(why.contains("lists no project NuGet can restore"), "{why}");
        assert!(why.contains("N.vcxproj"), "{why}");
    }

    #[test]
    fn members_sharing_a_directory_are_refused() {
        let temp = TempDir::named("dotnet-solution-shared");
        fs::write(temp.0.join("A.csproj"), sdk("")).unwrap();
        fs::write(temp.0.join("B.csproj"), sdk("")).unwrap();
        fs::write(
            temp.0.join("Both.slnx"),
            "<Solution><Project Path=\"A.csproj\" /><Project Path=\"B.csproj\" /></Solution>",
        )
        .unwrap();
        let why = discover(&ProjectRoot::open(&temp.0).unwrap())
            .unwrap_err()
            .to_string();
        assert!(why.contains("A.csproj and B.csproj share"), "{why}");
    }

    #[test]
    fn without_a_solution_one_root_project_is_the_layout() {
        let temp = TempDir::named("dotnet-solution-single");
        fs::write(temp.0.join("app.csproj"), sdk("")).unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let layout = discover(&held).unwrap();
        assert_eq!(layout.solution, None);
        assert_eq!(layout.members, [PathBuf::from("app.csproj")]);
        fs::write(temp.0.join("other.fsproj"), sdk("")).unwrap();
        let why = discover(&held).unwrap_err().to_string();
        assert!(why.contains("no solution"), "{why}");
    }

    #[test]
    fn the_generated_solution_names_members_absolutely() {
        let text = generated_sln(
            Path::new("/work/repo"),
            &[
                "src/App/App.csproj".into(),
                "lib/Lib.fsproj".into(),
                "test/app.csproj".into(),
            ],
            &["Staging".into(), "release".into()],
        )
        .unwrap();
        assert!(text.contains(
            "Project(\"{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}\") = \"App\", \"/work/repo/src/App/App.csproj\", \"{00000000-0000-0000-0000-000000000001}\""
        ), "{text}");
        assert!(text.contains("\"/work/repo/lib/Lib.fsproj\""), "{text}");
        // A second project of one name gets another label (MSB5004).
        assert!(
            text.contains("= \"app-3\", \"/work/repo/test/app.csproj\""),
            "{text}"
        );
        for configuration in ["Debug", "Release", "Staging"] {
            assert!(
                text.contains(&format!(
                    "\t\t{configuration}|Any CPU = {configuration}|Any CPU\n"
                )),
                "{text}"
            );
            assert!(text.contains(&format!(
                "{{00000000-0000-0000-0000-000000000002}}.{configuration}|Any CPU.Build.0"
            )));
        }
        assert!(!text.contains("release|"), "{text}");
        assert_eq!(
            parse_sln(&text),
            [
                "/work/repo/src/App/App.csproj",
                "/work/repo/lib/Lib.fsproj",
                "/work/repo/test/app.csproj"
            ]
        );
        assert!(generated_sln(Path::new("/work/a;b"), &["A.csproj".into()], &[]).is_err());
        assert!(generated_sln(Path::new("/w"), &["A.csproj".into()], &["a|b".into()]).is_err());
        assert_eq!(
            solution_properties(Path::new("/work/repo"), Path::new("Repo.slnx")).unwrap(),
            [
                "-p:SolutionDir=/work/repo/",
                "-p:SolutionPath=/work/repo/Repo.slnx",
                "-p:SolutionName=Repo",
                "-p:SolutionFileName=Repo.slnx",
                "-p:SolutionExt=.slnx",
            ]
        );
    }

    #[test]
    fn only_the_microsoft_net_sdk_family_is_bundled() {
        for bundled in [
            "microsoft.net.sdk",
            "microsoft.net.sdk.web",
            "microsoft.net.sdk.windowsdesktop",
        ] {
            assert!(bundled_sdk(bundled), "{bundled}");
        }
        for fetched in [
            "microsoft.net.sdk/9.0.100",
            "microsoft.net.sdkx",
            "aspire.apphost.sdk",
            "microsoft.build.traversal/2.0.24",
        ] {
            assert!(!bundled_sdk(fetched), "{fetched}");
        }
    }
}
