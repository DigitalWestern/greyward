//! The locked-mode package verification's inputs: synthetic projects that
//! restore every locked package, under the framework its lock restored it
//! for, from a local feed of the fetched nupkgs.

use super::{err, solution, target_framework, NugetPackage, ParsedLock};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// One verifier project: per lock target framework (the key as NuGet
/// writes it), the packages restored for it, by lowercase id.
pub(super) type VerifierProject = BTreeMap<String, BTreeMap<String, NugetPackage>>;

/// Does `packages` hold `package`'s id at another version?
pub(super) fn conflicts(packages: &BTreeMap<String, NugetPackage>, package: &NugetPackage) -> bool {
    packages
        .get(&package.id.to_ascii_lowercase())
        .is_some_and(|held| held.version != package.version)
}

/// The verifier projects that restore every locked package under the
/// framework its lock restored it for. Each lock's targets of one
/// framework (the plain target and its runtime targets) form one group,
/// split only where they pin one id at two versions; groups merge into
/// the first project with no clashing version for that framework. A
/// project then pins every package of a framework at one version, which
/// the locks it came from already resolved together.
pub(super) fn verifier_projects(locks: &[&ParsedLock]) -> Vec<VerifierProject> {
    let mut projects: Vec<VerifierProject> = Vec::new();
    for lock in locks {
        let mut groups: Vec<(String, BTreeMap<String, NugetPackage>)> = Vec::new();
        for (target, packages) in &lock.by_target {
            let key = target.split('/').next().unwrap_or("").to_string();
            for package in packages {
                let slot = groups
                    .iter()
                    .position(|(framework, held)| *framework == key && !conflicts(held, package));
                let slot = match slot {
                    Some(slot) => slot,
                    None => {
                        groups.push((key.clone(), BTreeMap::new()));
                        groups.len() - 1
                    }
                };
                groups[slot]
                    .1
                    .insert(package.id.to_ascii_lowercase(), package.clone());
            }
            if !groups.iter().any(|(framework, _)| *framework == key) {
                groups.push((key, BTreeMap::new()));
            }
        }
        for (framework, packages) in groups {
            let fits = |project: &VerifierProject| {
                project
                    .get(&framework)
                    .is_none_or(|held| packages.values().all(|package| !conflicts(held, package)))
            };
            let at = match projects.iter().position(fits) {
                Some(at) => at,
                None => {
                    projects.push(VerifierProject::new());
                    projects.len() - 1
                }
            };
            projects[at].entry(framework).or_default().extend(packages);
        }
    }
    projects.retain(|project| project.values().any(|packages| !packages.is_empty()));
    projects
}

/// A verifier project's csproj: every framework it restores, and per
/// framework its packages at exact versions, each a direct reference.
///
/// The framework of the SDK's own major (`net10.0` under SDK 10) keeps
/// its implicit framework reference and adds ASP.NET Core's, whose
/// targeting packs the SDK carries: restore for that framework prunes
/// packages the shared frameworks provide (on by default from .NET 10),
/// so the user's lock leaves out a dependency ASP.NET Core supplies, and
/// the verifier must prune it too or look for a package the feed lacks.
/// Pruning never drops a direct reference, so a locked package the
/// user's project did take from NuGet is still restored and verified.
/// Every other framework, which would need a targeting pack downloaded,
/// restores with no framework reference at all (pruning is off for them
/// by default). No reference-assembly packages, which no lock names.
pub(super) fn synthetic_csproj(project: &VerifierProject, sdk_major: u64) -> io::Result<String> {
    let native = format!("net{sdk_major}.0");
    let mut frameworks = Vec::new();
    let mut groups = String::new();
    for (key, packages) in project {
        let tfm = target_framework(key)?;
        let mut refs = packages
            .values()
            .map(|p| {
                format!(
                    "    <PackageReference Include=\"{}\" Version=\"[{}]\" />\n",
                    p.id, p.version
                )
            })
            .collect::<String>();
        if tfm == native {
            refs.push_str("    <FrameworkReference Include=\"Microsoft.AspNetCore.App\" />\n");
        } else {
            let windows = if tfm.contains("-windows") {
                "\n    <EnableWindowsTargeting>true</EnableWindowsTargeting>"
            } else {
                ""
            };
            groups.push_str(&format!(
                "  <PropertyGroup Condition=\"'$(TargetFramework)' == '{tfm}'\">\n    \
                 <DisableImplicitFrameworkReferences>true</DisableImplicitFrameworkReferences>\
                 {windows}\n  </PropertyGroup>\n"
            ));
        }
        groups.push_str(&format!(
            "  <ItemGroup Condition=\"'$(TargetFramework)' == '{tfm}'\">\n{refs}  </ItemGroup>\n"
        ));
        frameworks.push(tfm);
    }
    Ok(format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
         <TargetFrameworks>{}</TargetFrameworks>\n    \
         <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n    \
         <NoAutoResponse>true</NoAutoResponse>\n    \
         <AutomaticallyUseReferenceAssemblyPackages>false</AutomaticallyUseReferenceAssemblyPackages>\n  \
         </PropertyGroup>\n\
         {groups}</Project>\n",
        frameworks.join(";")
    ))
}

/// The lock a verifier project restores in locked mode: every package
/// Direct at its exact version, under the framework key its lock used.
pub(super) fn synthetic_lock(project: &VerifierProject) -> serde_json::Value {
    let targets = project
        .iter()
        .map(|(key, packages)| {
            let entries = packages
                .values()
                .map(|p| {
                    (
                        p.id.clone(),
                        serde_json::json!({
                            "type": "Direct",
                            "requested": format!("[{}]", p.version),
                            "resolved": p.version,
                            "contentHash": p.content_hash,
                        }),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            (key.clone(), serde_json::Value::Object(entries))
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "version": 1,
        "dependencies": targets,
    })
}

pub(super) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(super) fn rewrite_metadata_source(path: &Path) -> io::Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        err(format!(
            "{}: invalid .nupkg.metadata JSON: {e}",
            path.display()
        ))
    })?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            err(format!(
                "{}: .nupkg.metadata is not an object",
                path.display()
            ))
        })?
        .insert(
            "source".to_string(),
            serde_json::Value::String("greyward-feed".to_string()),
        );
    fs::write(path, serde_json::to_vec(&value)?)
}

/// The verifier tree under `verifier`: one synthetic project and lock per
/// verifier project, their generated solution, and a `nuget.config` whose
/// one source is the local `feed`. Returns each project's `obj/`.
pub(super) fn write_verifier(
    verifier: &Path,
    feed: &Path,
    projects: &[VerifierProject],
    sdk_major: u64,
) -> io::Result<Vec<PathBuf>> {
    let mut members = Vec::new();
    let mut objs = Vec::new();
    for (index, project) in projects.iter().enumerate() {
        let dir = verifier.join(format!("v{index}"));
        fs::create_dir_all(dir.join("obj"))?;
        fs::write(
            dir.join("greyward-verifier.csproj"),
            synthetic_csproj(project, sdk_major)?,
        )?;
        fs::write(
            dir.join("packages.lock.json"),
            serde_json::to_vec_pretty(&synthetic_lock(project))?,
        )?;
        members.push(PathBuf::from(format!("v{index}/greyward-verifier.csproj")));
        objs.push(dir.join("obj"));
    }
    fs::write(
        verifier.join("greyward-verifier.sln"),
        solution::generated_sln(verifier, &members, &[])?,
    )?;
    fs::write(
        verifier.join("nuget.config"),
        format!(
            "<configuration><packageSources><clear /><add key=\"greyward-feed\" \
             value=\"{}\" /></packageSources><config><add key=\"updatePackageLastAccessTime\" \
             value=\"false\" /></config></configuration>",
            xml_escape(&feed.display().to_string())
        ),
    )?;
    Ok(objs)
}
