//! The registry list in force after the policy chain is merged
//! (docs/agent/DESIGNS.md §4 "Who may say what"). The machine scope declares
//! registries, credentials and its `[sources]` lists; a project or
//! `--policy` layer may only narrow a list, and any name outside the
//! machine list is a load error.

use super::config::{self, CredentialSpec, Ecosystem, Registry, RegistrySpec, PUBLIC};
use crate::kernel::policy::SourceOrigin;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The merged registry configuration of one policy chain. Holds references
/// only: no secret is ever read into it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sources {
    /// The machine scope's registries, in declaration order.
    registries: Vec<Registry>,
    credentials: BTreeMap<String, CredentialSpec>,
    /// The machine scope's `[sources]` lists.
    machine: BTreeMap<Ecosystem, Vec<String>>,
    /// Every ecosystem some layer named in `[sources]`: enforced.
    enforced: BTreeMap<Ecosystem, Enforced>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Enforced {
    names: Vec<String>,
    layers: Vec<Layer>,
}

/// One layer that set or narrowed an ecosystem's list, for error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub origin: SourceOrigin,
    pub path: PathBuf,
    pub names: Vec<String>,
}

/// One entry of an ecosystem's effective list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source<'a> {
    Public,
    Registry(&'a Registry),
}

impl Source<'_> {
    pub fn name(&self) -> &str {
        match self {
            Source::Public => PUBLIC,
            Source::Registry(registry) => &registry.name,
        }
    }
}

/// An ecosystem's effective list, and whether it is enforced.
#[derive(Debug, Clone)]
pub struct EcosystemSources<'a> {
    pub ecosystem: Ecosystem,
    /// Some layer named the ecosystem in `[sources]`: the list is the only
    /// set of registries ward uses for it, and anything else is a hard
    /// error.
    pub enforced: bool,
    pub list: Vec<Source<'a>>,
    pub layers: &'a [Layer],
}

impl<'a> EcosystemSources<'a> {
    pub fn includes_public(&self) -> bool {
        self.list
            .iter()
            .any(|source| matches!(source, Source::Public))
    }

    pub fn registries(&self) -> impl Iterator<Item = &'a Registry> + '_ {
        self.list.iter().filter_map(|source| match source {
            Source::Registry(registry) => Some(*registry),
            Source::Public => None,
        })
    }

    /// The first entry: the registry the ecosystem's tools are pointed at.
    /// For node, the first without `scopes`.
    pub fn default_source(&self) -> Option<Source<'a>> {
        self.list
            .iter()
            .find(|source| match source {
                Source::Registry(registry) => registry.scopes.is_empty(),
                Source::Public => true,
            })
            .copied()
    }

    /// The configured registry the ecosystem's tools are pointed at, `None`
    /// when that is the public registry or the list is empty.
    pub fn default_registry(&self) -> Option<&'a Registry> {
        match self.default_source()? {
            Source::Registry(registry) => Some(registry),
            Source::Public => None,
        }
    }

    /// The names in effect, for error text: `corp-pypi, public`.
    pub fn names(&self) -> String {
        if self.list.is_empty() {
            return "(empty)".into();
        }
        self.list
            .iter()
            .map(|source| source.name().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Where the list came from, for error text: one clause per layer.
    pub fn provenance(&self) -> String {
        if self.layers.is_empty() {
            return "no policy names this ecosystem in [sources], so it uses the public registry"
                .into();
        }
        self.layers
            .iter()
            .map(|layer| {
                format!(
                    "{} policy {} lists [{}]",
                    layer.origin,
                    layer.path.display(),
                    layer.names.join(", ")
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// The error for an ecosystem whose effective list is empty, or `Ok`.
    pub fn require_nonempty(&self) -> Result<(), String> {
        if !self.list.is_empty() {
            return Ok(());
        }
        Err(format!(
            "no registry is allowed for {}: {}\nfix: list at least one registry of the machine policy in each project or --policy [sources].{} that narrows it",
            self.ecosystem.as_str(),
            self.provenance(),
            self.ecosystem.as_str()
        ))
    }
}

/// The three registry tables of one policy file.
pub struct Tables<'a> {
    pub credentials: &'a BTreeMap<String, CredentialSpec>,
    pub registry: &'a [RegistrySpec],
    pub sources: &'a BTreeMap<String, Vec<String>>,
}

impl Tables<'_> {
    fn is_empty(&self) -> bool {
        self.credentials.is_empty() && self.registry.is_empty() && self.sources.is_empty()
    }
}

impl Sources {
    /// Check one file's tables before they are merged at `origin`: the
    /// grammar, the machine-only rule, and narrowing names against the
    /// machine list already merged into `self`.
    pub fn check(
        &self,
        tables: &Tables<'_>,
        origin: SourceOrigin,
        path: &Path,
    ) -> Result<(), String> {
        if tables.is_empty() {
            return Ok(());
        }
        let at = |what: String| format!("{}: {what}", path.display());
        config::validate_sources(tables.sources).map_err(at)?;
        match origin {
            SourceOrigin::Machine => {
                let registries =
                    config::validate_registries(tables.registry, tables.credentials).map_err(at)?;
                for registry in &registries {
                    unwired(
                        registry.ecosystem,
                        &format!("[[registry]] {}", registry.name),
                    )
                    .map_err(at)?;
                }
                for (eco, names) in tables.sources {
                    let eco = Ecosystem::parse(eco).expect("validated");
                    unwired(eco, &format!("[sources] {}", eco.as_str())).map_err(at)?;
                    for name in names {
                        if name == PUBLIC {
                            continue;
                        }
                        match registries.iter().find(|r| &r.name == name) {
                            Some(registry) if registry.ecosystem == eco => {}
                            Some(registry) => {
                                return Err(at(format!(
                                    "[sources] {} names {name}, a {} registry\nfix: list it under [sources].{} instead",
                                    eco.as_str(),
                                    registry.ecosystem.as_str(),
                                    registry.ecosystem.as_str()
                                )))
                            }
                            None => {
                                return Err(at(format!(
                                    "[sources] {} names {name}, which no [[registry]] declares\nfix: declare [[registry]] name = \"{name}\" in this file, or remove it from [sources].{}",
                                    eco.as_str(),
                                    eco.as_str()
                                )))
                            }
                        }
                    }
                }
                Ok(())
            }
            SourceOrigin::Project | SourceOrigin::Flag | SourceOrigin::Env => {
                if let Some(registry) = tables.registry.first() {
                    return Err(at(format!(
                        "declares [[registry]] {}; registries and credentials are declared only in machine policy\nfix: move the table to ~/.greyward/policy.toml (or the file GREYWARD_POLICY names), and keep only [sources] here",
                        registry.name
                    )));
                }
                if let Some(name) = tables.credentials.keys().next() {
                    return Err(at(format!(
                        "declares [credentials.{name}]; registries and credentials are declared only in machine policy\nfix: move the table to ~/.greyward/policy.toml (or the file GREYWARD_POLICY names), and keep only [sources] here"
                    )));
                }
                for (eco, names) in tables.sources {
                    let eco = Ecosystem::parse(eco).expect("validated");
                    unwired(eco, &format!("[sources] {}", eco.as_str())).map_err(at)?;
                    let machine = self.machine_list(eco);
                    for name in names {
                        if !machine.contains(name) {
                            return Err(at(format!(
                                "[sources] {} names {name}, which the machine policy does not list for {} (machine list: [{}]); a project or --policy file can only narrow that list\nfix: remove {name} from [sources].{} here, or add it to the machine policy's [sources].{}",
                                eco.as_str(),
                                eco.as_str(),
                                machine.join(", "),
                                eco.as_str(),
                                eco.as_str()
                            )));
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Merge one checked file's tables. The machine scope sets the
    /// declarations and its lists; any other layer intersects the lists in
    /// machine order.
    pub fn merge(&mut self, tables: &Tables<'_>, origin: SourceOrigin, path: &Path) {
        if tables.is_empty() {
            return;
        }
        if origin == SourceOrigin::Machine {
            // `check` validated these; a failure here is a caller that
            // skipped it, which merges nothing.
            let Ok(registries) = config::validate_registries(tables.registry, tables.credentials)
            else {
                return;
            };
            self.registries = registries;
            self.credentials = tables.credentials.clone();
            self.machine.clear();
            self.enforced.clear();
        }
        for (eco, names) in tables.sources {
            let Some(eco) = Ecosystem::parse(eco) else {
                continue;
            };
            let layer = Layer {
                origin,
                path: path.to_path_buf(),
                names: names.clone(),
            };
            if origin == SourceOrigin::Machine {
                self.machine.insert(eco, names.clone());
                self.enforced.insert(
                    eco,
                    Enforced {
                        names: names.clone(),
                        layers: vec![layer],
                    },
                );
                continue;
            }
            let current = match self.enforced.get(&eco) {
                Some(enforced) => enforced.names.clone(),
                None => self.machine_list(eco),
            };
            let entry = self.enforced.entry(eco).or_insert_with(|| Enforced {
                names: Vec::new(),
                layers: Vec::new(),
            });
            entry.names = current.into_iter().filter(|n| names.contains(n)).collect();
            entry.layers.push(layer);
        }
    }

    fn machine_list(&self, eco: Ecosystem) -> Vec<String> {
        self.machine
            .get(&eco)
            .cloned()
            .unwrap_or_else(|| vec![PUBLIC.to_string()])
    }

    /// The effective list of one ecosystem.
    pub fn ecosystem(&self, ecosystem: Ecosystem) -> EcosystemSources<'_> {
        match self.enforced.get(&ecosystem) {
            None => EcosystemSources {
                ecosystem,
                enforced: false,
                list: vec![Source::Public],
                layers: &[],
            },
            Some(enforced) => EcosystemSources {
                ecosystem,
                enforced: true,
                list: enforced
                    .names
                    .iter()
                    .filter_map(|name| self.source(name))
                    .collect(),
                layers: &enforced.layers,
            },
        }
    }

    fn source(&self, name: &str) -> Option<Source<'_>> {
        if name == PUBLIC {
            return Some(Source::Public);
        }
        self.registry(name).map(Source::Registry)
    }

    /// A machine-declared registry by name, listed or not.
    pub fn registry(&self, name: &str) -> Option<&Registry> {
        self.registries
            .iter()
            .find(|registry| registry.name == name)
    }

    /// A machine-declared credential by name.
    pub fn credential(&self, name: &str) -> Option<&CredentialSpec> {
        self.credentials.get(name)
    }

    /// Whether any ecosystem is enforced.
    pub fn any_enforced(&self) -> bool {
        !self.enforced.is_empty()
    }
}

/// Refuse an ecosystem this ward does not wire for private registries.
fn unwired(ecosystem: Ecosystem, what: &str) -> Result<(), String> {
    if ecosystem.wired() {
        return Ok(());
    }
    Err(format!(
        "{what}: private registries for {} are not supported by this ward\nfix: remove {} from [sources] and its [[registry]] entries, or upgrade ward",
        ecosystem.as_str(),
        ecosystem.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(name: &str, ecosystem: &str, url: &str) -> RegistrySpec {
        RegistrySpec {
            name: name.into(),
            ecosystem: ecosystem.into(),
            url: url.into(),
            credential: None,
            root: None,
            files: vec![],
            network: None,
            ca: None,
            scopes: vec![],
            mirror_of: None,
            nosumdb: vec![],
            sumdb: None,
            hex_public_key: None,
        }
    }

    struct File {
        credentials: BTreeMap<String, CredentialSpec>,
        registry: Vec<RegistrySpec>,
        sources: BTreeMap<String, Vec<String>>,
    }

    impl File {
        fn sources(pairs: &[(&str, &[&str])]) -> File {
            File {
                credentials: BTreeMap::new(),
                registry: vec![],
                sources: pairs
                    .iter()
                    .map(|(eco, names)| {
                        (
                            eco.to_string(),
                            names.iter().map(|n| n.to_string()).collect(),
                        )
                    })
                    .collect(),
            }
        }

        fn tables(&self) -> Tables<'_> {
            Tables {
                credentials: &self.credentials,
                registry: &self.registry,
                sources: &self.sources,
            }
        }
    }

    fn apply(sources: &mut Sources, file: &File, origin: SourceOrigin) -> Result<(), String> {
        let path = Path::new("/p/policy.toml");
        sources.check(&file.tables(), origin, path)?;
        sources.merge(&file.tables(), origin, path);
        Ok(())
    }

    fn machine() -> File {
        let mut file = File::sources(&[
            ("python", &["corp-pypi", "public"]),
            ("node", &["corp-npm"]),
        ]);
        file.registry = vec![
            registry(
                "corp-pypi",
                "python",
                "https://n.example/repository/pypi/simple/",
            ),
            registry("corp-npm", "node", "https://n.example/repository/npm/"),
            registry(
                "spare",
                "python",
                "https://n.example/repository/spare/simple/",
            ),
        ];
        file
    }

    fn names(sources: &Sources, eco: Ecosystem) -> Vec<String> {
        sources
            .ecosystem(eco)
            .list
            .iter()
            .map(|s| s.name().to_string())
            .collect()
    }

    #[test]
    fn no_sources_anywhere_is_public_and_not_enforced() {
        let sources = Sources::default();
        let python = sources.ecosystem(Ecosystem::Python);
        assert!(!python.enforced);
        assert!(python.includes_public());
        assert!(python.default_registry().is_none());
        assert!(!sources.any_enforced());
    }

    #[test]
    fn the_machine_list_is_enforced_in_order() {
        let mut sources = Sources::default();
        apply(&mut sources, &machine(), SourceOrigin::Machine).unwrap();
        let python = sources.ecosystem(Ecosystem::Python);
        assert!(python.enforced);
        assert_eq!(names(&sources, Ecosystem::Python), ["corp-pypi", "public"]);
        assert_eq!(python.default_registry().unwrap().name, "corp-pypi");
        assert_eq!(names(&sources, Ecosystem::Node), ["corp-npm"]);
        // Declared but unlisted: used for nothing.
        assert!(sources.registry("spare").is_some());
        assert!(!names(&sources, Ecosystem::Python).contains(&"spare".to_string()));
    }

    #[test]
    fn a_declared_registry_without_sources_changes_nothing() {
        let mut file = machine();
        file.sources.clear();
        let mut sources = Sources::default();
        apply(&mut sources, &file, SourceOrigin::Machine).unwrap();
        assert!(!sources.ecosystem(Ecosystem::Python).enforced);
        assert_eq!(names(&sources, Ecosystem::Python), ["public"]);
    }

    #[test]
    fn a_project_narrows_in_machine_order() {
        let mut sources = Sources::default();
        apply(&mut sources, &machine(), SourceOrigin::Machine).unwrap();
        let project = File::sources(&[("python", &["public", "corp-pypi"])]);
        apply(&mut sources, &project, SourceOrigin::Project).unwrap();
        assert_eq!(names(&sources, Ecosystem::Python), ["corp-pypi", "public"]);
        let project = File::sources(&[("python", &["corp-pypi"])]);
        apply(&mut sources, &project, SourceOrigin::Project).unwrap();
        assert_eq!(names(&sources, Ecosystem::Python), ["corp-pypi"]);
        let flag = File::sources(&[("python", &["public"])]);
        apply(&mut sources, &flag, SourceOrigin::Flag).unwrap();
        let python = sources.ecosystem(Ecosystem::Python);
        assert!(python.list.is_empty());
        assert_eq!(python.layers.len(), 4);
        let error = python.require_nonempty().unwrap_err();
        assert!(error.contains("flag policy"), "{error}");
        assert!(error.contains("fix:"), "{error}");
    }

    #[test]
    fn a_project_may_not_widen() {
        let mut sources = Sources::default();
        apply(&mut sources, &machine(), SourceOrigin::Machine).unwrap();
        let error = apply(
            &mut sources,
            &File::sources(&[("python", &["spare"])]),
            SourceOrigin::Project,
        )
        .unwrap_err();
        assert!(error.contains("does not list"), "{error}");
        assert!(error.contains("fix:"), "{error}");
        // Without a machine list the machine list is ["public"].
        let mut sources = Sources::default();
        apply(
            &mut sources,
            &File::sources(&[("python", &["public"])]),
            SourceOrigin::Project,
        )
        .unwrap();
        assert!(sources.ecosystem(Ecosystem::Python).enforced);
        assert!(apply(
            &mut sources,
            &File::sources(&[("python", &["corp-pypi"])]),
            SourceOrigin::Project,
        )
        .is_err());
    }

    #[test]
    fn only_the_machine_declares() {
        let mut file = machine();
        file.sources.clear();
        let error = apply(&mut Sources::default(), &file, SourceOrigin::Project).unwrap_err();
        assert!(error.contains("declares [[registry]] corp-pypi"), "{error}");
        let mut file = File::sources(&[]);
        file.credentials.insert(
            "corp".into(),
            CredentialSpec {
                env: Some("T".into()),
                ..Default::default()
            },
        );
        let error = apply(&mut Sources::default(), &file, SourceOrigin::Flag).unwrap_err();
        assert!(error.contains("[credentials.corp]"), "{error}");
    }

    #[test]
    fn unwired_ecosystems_are_refused() {
        let error = apply(
            &mut Sources::default(),
            &File::sources(&[("go", &["public"])]),
            SourceOrigin::Machine,
        )
        .unwrap_err();
        assert!(error.contains("not supported by this ward"), "{error}");
        let mut file = File::sources(&[]);
        file.registry = vec![registry("corp-go", "go", "https://n.example/go/")];
        assert!(apply(&mut Sources::default(), &file, SourceOrigin::Machine).is_err());
        assert!(apply(
            &mut Sources::default(),
            &File::sources(&[("cargo", &["public"])]),
            SourceOrigin::Project,
        )
        .is_err());
    }

    #[test]
    fn machine_sources_must_name_a_registry_of_that_ecosystem() {
        let mut file = machine();
        file.sources = File::sources(&[("python", &["corp-npm"])]).sources;
        assert!(apply(&mut Sources::default(), &file, SourceOrigin::Machine).is_err());
        file.sources = File::sources(&[("python", &["missing"])]).sources;
        assert!(apply(&mut Sources::default(), &file, SourceOrigin::Machine).is_err());
    }

    #[test]
    fn the_node_default_skips_scoped_registries() {
        let mut file = File::sources(&[("node", &["github", "corp-npm"])]);
        let mut github = registry("github", "node", "https://npm.pkg.github.com/");
        github.scopes = vec!["@digitalwestern".into()];
        file.registry = vec![
            github,
            registry("corp-npm", "node", "https://n.example/npm/"),
        ];
        let mut sources = Sources::default();
        apply(&mut sources, &file, SourceOrigin::Machine).unwrap();
        let node = sources.ecosystem(Ecosystem::Node);
        assert_eq!(node.default_registry().unwrap().name, "corp-npm");
    }
}
