//! Host platform detection (kernel layer): the only place that knows what
//! machine ward is running on. Everything else takes an explicit `Platform`.
//! Also the host's PATH as a child of ward inherits it ([`child_path`]).

use std::env::consts::{ARCH, OS};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    Aarch64AppleDarwin,
    X86_64UnknownLinuxGnu,
}

impl Platform {
    /// Host platform from std::env::consts::{OS, ARCH}. Cached (OnceLock).
    pub fn host() -> io::Result<Platform> {
        static HOST: OnceLock<Result<Platform, String>> = OnceLock::new();
        match HOST.get_or_init(|| match (OS, ARCH) {
            ("macos", "aarch64") => Ok(Platform::Aarch64AppleDarwin),
            ("linux", "x86_64") => {
                if Path::new("/lib64/ld-linux-x86-64.so.2").exists() {
                    Ok(Platform::X86_64UnknownLinuxGnu)
                } else {
                    Err("unsupported host: Linux x86_64 without glibc (musl?) — ward pins glibc toolchains (unsupported platform)".to_string())
                }
            }
            _ => Err(format!(
                "unsupported host platform {OS}/{ARCH}: ward is pinned for aarch64-apple-darwin and x86_64-unknown-linux-gnu (unsupported platform)"
            )),
        }) {
            Ok(platform) => Ok(*platform),
            Err(message) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                message.clone(),
            )),
        }
    }

    pub fn triple(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "aarch64-apple-darwin",
            Platform::X86_64UnknownLinuxGnu => "x86_64-unknown-linux-gnu",
        }
    }

    /// The platform a recorded triple names, if ward supports it.
    pub fn from_triple(triple: &str) -> Option<Platform> {
        Platform::ALL.iter().copied().find(|p| p.triple() == triple)
    }

    pub fn node_slug(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "darwin-arm64",
            Platform::X86_64UnknownLinuxGnu => "linux-x64",
        }
    }

    pub fn go_slug(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "darwin-arm64",
            Platform::X86_64UnknownLinuxGnu => "linux-amd64",
        }
    }

    pub fn dotnet_rid(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "osx-arm64",
            Platform::X86_64UnknownLinuxGnu => "linux-x64",
        }
    }

    pub fn npm_os(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "darwin",
            Platform::X86_64UnknownLinuxGnu => "linux",
        }
    }

    pub fn npm_cpu(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "arm64",
            Platform::X86_64UnknownLinuxGnu => "x64",
        }
    }

    pub fn is_macos(self) -> bool {
        matches!(self, Platform::Aarch64AppleDarwin)
    }

    pub const ALL: &'static [Platform] = &[
        Platform::Aarch64AppleDarwin,
        Platform::X86_64UnknownLinuxGnu,
    ];
}

/// Uniform "no pin" error used by every tailor.
pub fn no_pin(what: &str, platform: Platform) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "no {what} pinned for {} (unsupported platform)",
            platform.triple()
        ),
    )
}

pub fn require_host(platform: Platform, what: &str) -> io::Result<()> {
    let host = Platform::host()?;
    if platform == host {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot realize {what} for {} on host {} (unsupported platform)",
            platform.triple(),
            host.triple()
        ),
    ))
}

/// A set of host packages ward's native paths need but does not provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPackages {
    /// The compiler, linker, and helpers native builds link against.
    CToolchain,
    /// The Linux build sandbox.
    Bubblewrap,
}

/// Per-distro install commands, as `(manager binary, distro label, command)`.
/// The binary is what decides which one this host gets; the label is what a
/// host with none of them is shown instead.
const C_TOOLCHAIN_COMMANDS: &[(&str, &str, &str)] = &[
    (
        "apt",
        "Ubuntu/Debian",
        "sudo apt install build-essential pkg-config patch zlib1g-dev libxcrypt-dev",
    ),
    (
        "dnf",
        "Fedora",
        "sudo dnf install gcc gcc-c++ make binutils glibc-devel pkgconf-pkg-config patch \
         zlib-ng-compat-devel libxcrypt-devel",
    ),
    (
        "pacman",
        "Arch",
        "sudo pacman -S base-devel pkgconf patch zlib libxcrypt",
    ),
];

const BUBBLEWRAP_COMMANDS: &[(&str, &str, &str)] = &[
    ("apt", "Ubuntu/Debian", "sudo apt install bubblewrap"),
    ("dnf", "Fedora", "sudo dnf install bubblewrap"),
    ("pacman", "Arch", "sudo pacman -S bubblewrap"),
];

/// The command for the manager `present` names, or every distro's command
/// when this host has none of them (a container image, NixOS, a stripped
/// base): a wrong guess is worse than a short list.
fn install_command(present: Option<&str>, table: &[(&str, &str, &str)]) -> String {
    match present.and_then(|binary| table.iter().find(|(name, _, _)| *name == binary)) {
        Some((_, _, command)) => (*command).to_string(),
        None => table
            .iter()
            .map(|(_, label, command)| format!("{label}: {command}"))
            .collect::<Vec<_>>()
            .join("; "),
    }
}

fn manager_on_path(table: &[(&'static str, &str, &str)]) -> Option<&'static str> {
    let path = std::env::var_os("PATH")?;
    for (binary, _, _) in table {
        for directory in std::env::split_paths(&path) {
            if directory.join(binary).is_file() {
                return Some(binary);
            }
        }
    }
    None
}

/// How to install `packages` on this host, in one line, ready to paste.
pub fn install_hint(platform: Platform, packages: HostPackages) -> String {
    match (platform, packages) {
        (Platform::Aarch64AppleDarwin, HostPackages::CToolchain) => {
            "xcode-select --install".to_string()
        }
        // macOS sandboxes with /usr/bin/sandbox-exec, which ships with the
        // system: nothing to install.
        (Platform::Aarch64AppleDarwin, HostPackages::Bubblewrap) => String::new(),
        (Platform::X86_64UnknownLinuxGnu, HostPackages::CToolchain) => {
            install_command(manager_on_path(C_TOOLCHAIN_COMMANDS), C_TOOLCHAIN_COMMANDS)
        }
        (Platform::X86_64UnknownLinuxGnu, HostPackages::Bubblewrap) => {
            install_command(manager_on_path(BUBBLEWRAP_COMMANDS), BUBBLEWRAP_COMMANDS)
        }
    }
}

/// The PATH a child of ward runs with: `prefix` (an environment's bin
/// directories), then the host's PATH as ward inherited it, byte for byte.
pub fn child_path<P: AsRef<OsStr>>(prefix: &[P]) -> io::Result<OsString> {
    join_search_path(prefix, std::env::var_os("PATH").as_deref())
}

/// [`child_path`] over a given host PATH. A missing or empty host PATH adds
/// nothing: joined as text it would leave a trailing `:`, an empty entry
/// that every shell and `execvp` read as the current directory, so a
/// program in the project would run in place of the host's. An entry of
/// `prefix` that holds `:` cannot be one PATH entry, and is refused rather
/// than split into two that name other directories.
fn join_search_path<P: AsRef<OsStr>>(prefix: &[P], host: Option<&OsStr>) -> io::Result<OsString> {
    for entry in prefix {
        refuse_path_separator("the directory", Path::new(entry.as_ref()))?;
    }
    let mut path = std::env::join_paths(prefix.iter().map(AsRef::as_ref))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        if !path.is_empty() {
            path.push(":");
        }
        path.push(host);
    }
    Ok(path)
}

/// Refuse a directory whose path holds `:`, PATH's separator: `what` is how
/// the message names it (`the project`, `the store`). A bin directory under
/// it could never be put on a child's PATH as one entry.
pub fn refuse_path_separator(what: &str, path: &Path) -> io::Result<()> {
    if !path.as_os_str().as_encoded_bytes().contains(&b':') {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{what} {} has ':' in its path, and ':' separates PATH entries, so no program \
             could be found in it; move it to a path without ':'",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The child's PATH never gains an empty (current-directory) entry from
    /// a missing host PATH, keeps a host PATH that is not UTF-8 whole, and
    /// refuses a prefix entry that `:` would split.
    #[test]
    fn child_path_adds_no_current_directory_and_splits_nothing() {
        use std::os::unix::ffi::OsStrExt;
        let prefix = ["/p/node_modules/.bin", "/store/bin"];
        for host in [None, Some(OsStr::new(""))] {
            assert_eq!(
                join_search_path(&prefix, host).unwrap(),
                "/p/node_modules/.bin:/store/bin"
            );
        }
        let odd = OsStr::from_bytes(b"/usr/bin:/opt/\xff/bin");
        let mut expected = OsString::from("/p/node_modules/.bin:/store/bin:");
        expected.push(odd);
        assert_eq!(join_search_path(&prefix, Some(odd)).unwrap(), expected);
        assert_eq!(
            join_search_path::<&str>(&[], Some(OsStr::new("/usr/bin"))).unwrap(),
            "/usr/bin"
        );
        let error = join_search_path(&["/home/u/co:lon/node_modules/.bin"], None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("co:lon"), "{error}");
        assert!(error.to_string().contains("move it"), "{error}");
        assert!(refuse_path_separator("the store", Path::new("/a/b")).is_ok());
        let error = refuse_path_separator("the store", Path::new("/a:b")).unwrap_err();
        assert!(
            error.to_string().starts_with("the store /a:b has ':'"),
            "{error}"
        );
    }

    /// Every distro ward claims to run on gets its own command, and a host
    /// whose package manager ward does not recognize gets all of them rather
    /// than Fedora's.
    #[test]
    fn install_hints_are_per_distro_and_fall_back_to_every_distro() {
        assert_eq!(
            install_command(Some("apt"), BUBBLEWRAP_COMMANDS),
            "sudo apt install bubblewrap"
        );
        assert_eq!(
            install_command(Some("pacman"), BUBBLEWRAP_COMMANDS),
            "sudo pacman -S bubblewrap"
        );
        let unknown = install_command(None, BUBBLEWRAP_COMMANDS);
        for label in ["Ubuntu/Debian", "Fedora", "Arch"] {
            assert!(unknown.contains(label), "{unknown}");
        }
        // An unrecognized manager is the same as none: never guess dnf.
        assert_eq!(install_command(Some("apk"), BUBBLEWRAP_COMMANDS), unknown);

        let c = install_command(Some("apt"), C_TOOLCHAIN_COMMANDS);
        assert!(c.contains("build-essential"), "{c}");
        assert_eq!(
            install_hint(Platform::Aarch64AppleDarwin, HostPackages::CToolchain),
            "xcode-select --install"
        );
        assert!(install_hint(Platform::Aarch64AppleDarwin, HostPackages::Bubblewrap).is_empty());
    }

    #[test]
    fn host_matches_test_machine() {
        let expected = match (OS, ARCH) {
            ("macos", "aarch64") => Platform::Aarch64AppleDarwin,
            ("linux", "x86_64") => Platform::X86_64UnknownLinuxGnu,
            _ => panic!("unsupported test machine {OS}/{ARCH}"),
        };
        assert_eq!(Platform::host().unwrap(), expected);
    }

    #[test]
    fn from_triple_round_trips_and_refuses_strangers() {
        for platform in Platform::ALL {
            assert_eq!(Platform::from_triple(platform.triple()), Some(*platform));
        }
        // The darwin spelling is recorded in locks and must not drift.
        assert_eq!(
            Platform::from_triple("aarch64-apple-darwin"),
            Some(Platform::Aarch64AppleDarwin)
        );
        assert_eq!(Platform::from_triple("x86_64-apple-darwin"), None);
        assert_eq!(Platform::from_triple(""), None);
    }

    #[test]
    fn no_pin_names_platform() {
        let error = no_pin("nodejs", Platform::X86_64UnknownLinuxGnu);
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let text = error.to_string();
        assert!(text.contains("x86_64-unknown-linux-gnu"));
        assert!(text.contains("unsupported platform"));
    }
}
