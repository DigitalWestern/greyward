//! The store format marker (kernel store): `<root>/format`, one line naming
//! the layout every record in this store is written in.
//!
//! The marker is what lets a ward tell a store it can read from one it
//! cannot. It is written before the first namespace of a new store is
//! created, so a store that has namespaces and no marker was written by a
//! ward from before the marker existed. This ward has no reader for those
//! records, and neither that store nor one with a marker it does not know
//! is opened: `ward gc --reset` empties it, or the directory is moved aside.

use super::*;
use std::io::{Read as _, Write as _};

/// The marker's name under the store root.
pub const FORMAT_FILE: &str = "format";

/// The format this ward reads and writes.
pub const STORE_FORMAT: u32 = 1;

/// The word before the number on the marker's one line.
const FORMAT_WORD: &str = "greyward-store";

/// Every namespace `Store::open` creates under the root.
pub(super) const NAMESPACES: &[&str] = &[
    "objects",
    "meta",
    "cache/sha1",
    "cache/sha256",
    "cache/sha384",
    "cache/sha512",
    "tmp",
    "roots",
    "forests",
    "backups",
    "root-locks",
    "run-homes",
    "records",
    // What each held lease says about itself (`activity::JOBS`).
    "jobs",
];

/// What `ward gc --reset` removes from the root: everything written in the
/// store's record formats, and everything that only means something next to
/// those records. `tmp` is not removed (it holds the publication lock):
/// only the temporaries ward names there are, and the marker is rewritten.
///
/// Whatever is not listed stays: `cache/` (verified downloads, each named
/// by its own digest, which is what the store is rebuilt from), `backups/`
/// (directories that were the user's before ward moved them aside),
/// `run-homes/`, the planners' download caches, the first-run notices, the
/// lock files, and anything ward does not recognise.
pub(crate) const RESET_REMOVES: &[&str] = &[
    "objects",
    "meta",
    "roots",
    "records",
    "resolve",
    "forests",
    "root-locks",
    // What a ward from before the marker left when it could not finish its
    // metadata maintenance. Nothing reads it now.
    "maintenance-deferred",
];

/// What the marker says about a store directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFormat {
    /// The marker names the format this ward reads.
    Current,
    /// No marker and nothing only a ward writes: nothing has been stored
    /// here. `Store::open` creates the store with the marker in a directory
    /// that is empty, or holds only empty namespaces, and refuses any other
    /// (see `vacant`).
    Uninitialized,
    /// No marker, and what only a ward writes into a store (its lease
    /// files, an object, an object's record): written before the marker
    /// existed. Directory names alone are never this: `tmp`, `records` and
    /// `objects` are names anyone's directory may hold (#676).
    PreEpoch,
    /// A well-formed marker naming a later format than this ward knows.
    Newer(u32),
    /// A marker this ward cannot read as any format; the text says what is
    /// there instead.
    Unknown(String),
    /// A marker that is there and cannot be opened or read (its mode, an
    /// I/O error); the text is the system's reason. Nothing in the store is
    /// trusted without it, and `ward gc --reset` replaces it without reading
    /// it.
    Unreadable(String),
}

/// The error a refused store is reported with: the reason as its message,
/// and the one command that is the way out as a separate `fix`, so the
/// top level prints it on its own `fix:` line. The command acts on the
/// store that was refused: see `StoreFormat::fix_for`.
#[derive(Debug)]
pub struct Refused {
    pub message: String,
    pub fix: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refused {}

/// The `fix:` command of an error that is a store refusal, if it is one.
pub fn refusal_fix(error: &io::Error) -> Option<&str> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Refused>())
        .map(|refused| refused.fix.as_str())
        .or_else(|| crate::kernel::error::inner(error).and_then(refusal_fix))
}

/// `command` with `GREYWARD_STORE` set to exactly `root`, as a POSIX shell
/// reads it. The command empties a store, so the path is never
/// approximated: it is spelled from its bytes, in the plainest of three
/// forms that is exact.
///
/// - Every byte one no shell reads specially: the path as it is.
/// - Text with no control character: single quotes, each single quote
///   inside written as `'\''`.
/// - Anything else (bytes that are not UTF-8, which a `String` cannot
///   carry, or control characters, which a terminal may not show): the
///   bytes as octal escapes in a `printf` format. `$(...)` drops trailing
///   newlines, so a path that ends in one is printed with a `.` after it
///   that the command takes off again.
fn with_store(command: &str, root: &Path) -> String {
    let bytes = root.as_os_str().as_bytes();
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"/._-+:@,".contains(&byte);
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.is_empty() && bytes.iter().all(|&byte| plain(byte) || byte == b'%') => {
            format!("GREYWARD_STORE={text} {command}")
        }
        Ok(text) if !text.chars().any(char::is_control) => {
            format!("GREYWARD_STORE='{}' {command}", text.replace('\'', "'\\''"))
        }
        _ => {
            let mut format = String::new();
            for &byte in bytes {
                match byte {
                    byte if plain(byte) => format.push(char::from(byte)),
                    b'%' => format.push_str("%%"),
                    byte => format.push_str(&format!("\\{byte:03o}")),
                }
            }
            if bytes.last() == Some(&b'\n') {
                format!("(p=\"$(printf '{format}.')\"; GREYWARD_STORE=\"${{p%.}}\" {command})")
            } else {
                format!("GREYWARD_STORE=\"$(printf '{format}')\" {command}")
            }
        }
    }
}

/// `command`, made to act on the store at `root`. A bare `ward` acts on the
/// store `selected`: for any other store the command carries its own
/// `GREYWARD_STORE=`, with `root` absolute, so pasting it never empties the
/// wrong one. `selected` is `None` when what a bare `ward` selects cannot be
/// relied on: see `StoreFormat::fix_for`.
fn command_on(command: &str, root: &Path, selected: Option<&Path>) -> String {
    let root = root
        .canonicalize()
        .or_else(|_| std::path::absolute(root))
        .unwrap_or_else(|_| root.to_path_buf());
    match selected {
        Some(selected) if root == selected => command.to_string(),
        _ => with_store(command, &root),
    }
}

impl StoreFormat {
    /// The marker line for the current format, newline included.
    pub fn current_line() -> String {
        format!("{FORMAT_WORD} {STORE_FORMAT}\n")
    }

    /// Whether this ward may open the store.
    pub fn usable(&self) -> bool {
        matches!(self, StoreFormat::Current | StoreFormat::Uninitialized)
    }

    /// Why the store at `root` is not opened, or `None` for a store this
    /// ward may open. A sentence with no leading capital and no final
    /// period, so it reads after `ward: error: ` and inside a `doctor` row
    /// alike. The command that is the way out is `fix`, printed on its own
    /// line, so the prose names what it does and not how it is spelled.
    pub fn refusal(&self, root: &Path) -> Option<String> {
        let root = root.display();
        let reset = "Emptying it keeps its downloads, and the next `ward` in each project \
                     rebuilds what it needs (or move the directory aside)";
        match self {
            StoreFormat::Current | StoreFormat::Uninitialized => None,
            StoreFormat::PreEpoch => Some(format!(
                "the store at {root} has no format marker: an older ward wrote it, and this ward \
                 does not read its records. {reset}"
            )),
            StoreFormat::Newer(format) => Some(format!(
                "the store at {root} is format {FORMAT_WORD} {format} and this ward reads \
                 {FORMAT_WORD} {STORE_FORMAT}: a newer ward wrote it. Update this ward, or point \
                 GREYWARD_STORE at another directory"
            )),
            StoreFormat::Unknown(found) => Some(format!(
                "the store at {root} has a format marker this ward does not know ({found}; \
                 expected \"{FORMAT_WORD} {STORE_FORMAT}\"): the marker is damaged, or the \
                 directory is not a ward store. {reset}"
            )),
            StoreFormat::Unreadable(why) => Some(format!(
                "the store at {root} has a format marker this ward cannot read ({why}), so \
                 nothing in it is trusted. {reset}"
            )),
        }
    }

    /// The one command that is the way out of a refused store: update for
    /// a store a newer ward wrote, reset for the rest. This is the command
    /// for the store a bare `ward` selects; `fix_for` is the one to print.
    pub fn fix(&self) -> &'static str {
        match self {
            StoreFormat::Newer(_) => "ward update --self",
            _ => "ward gc --reset",
        }
    }

    /// `fix` as a `fix:` line prints it for the store at `root`. A reset
    /// empties whichever store the command selects, and the line is pasted
    /// into a shell, not into this process. So the bare command is printed
    /// only when it selects `root` wherever it is typed: `GREYWARD_STORE` is
    /// unset or absolute, and names `root`. In every other case the
    /// command names `root` itself, absolute:
    /// `GREYWARD_STORE=<root> ward gc --reset`. That covers a store other than
    /// the configured one (an x environment's own store), and a relative
    /// `GREYWARD_STORE`, which `ward -C <dir>` resolves from `<dir>` and the
    /// shell that pastes the fix resolves from somewhere else. Updating ward
    /// is the same command for every store.
    pub fn fix_for(&self, root: &Path) -> String {
        match self {
            StoreFormat::Newer(_) => self.fix().to_string(),
            _ => {
                let selected = Store::configured_root()
                    .ok()
                    .map(|(configured, _)| configured)
                    .filter(|configured| configured.is_absolute())
                    .and_then(|configured| configured.canonicalize().ok());
                command_on(self.fix(), root, selected.as_deref())
            }
        }
    }

    /// `refusal` as the error a command returns.
    pub(super) fn refuse(&self, root: &Path) -> io::Result<()> {
        match self.refusal(root) {
            Some(message) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                Refused {
                    message,
                    fix: self.fix_for(root),
                },
            )),
            None => Ok(()),
        }
    }
}

/// Hold the store root against a concurrent creation or reset: an
/// exclusive `flock` on the root directory itself, released when the
/// returned handle is dropped. `Store::open` holds it while it reads the
/// marker and creates what is missing, and `gc::reset` holds it from the
/// moment it removes the marker until the new one is published, so an open
/// never initialises namespaces inside a store that is being emptied and
/// never judges one that is half created.
///
/// The wait is never silent: when another ward holds the root, one line
/// says so before this one blocks. A filesystem with no `flock` on a
/// directory cannot hold a store, and the error says that.
pub(crate) fn lock_root(root: &Path) -> io::Result<fs::File> {
    let directory = open_real_directory(root, "store root")?;
    let unsupported = |error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "lock the store directory {}: {error}. ward takes a file lock (flock) on \
                 the store directory before it creates or empties a store, so the store has to \
                 be on a filesystem that supports one; point GREYWARD_STORE at a directory on a \
                 local disk",
                root.display()
            ),
        )
    };
    match directory.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            crate::kernel::ui::note(&format!(
                "waiting for another ward that is creating or emptying the store at {}",
                root.display()
            ));
            directory.lock().map_err(unsupported)?;
        }
        Err(fs::TryLockError::Error(error)) => return Err(unsupported(error)),
    }
    Ok(directory)
}

/// Read what the marker says about `root`, changing nothing. `root` must
/// exist.
pub fn probe(root: &Path) -> io::Result<StoreFormat> {
    if let Some(format) = read_marker(root)? {
        // A `format` this ward cannot read proves nothing by itself: anyone's
        // directory may hold a file or directory by that name. Without store
        // evidence beside it the root is no store, so nothing offers to
        // reset it (#676 review).
        if matches!(format, StoreFormat::Unknown(_) | StoreFormat::Unreadable(_))
            && !has_store_evidence(root)?
        {
            return Ok(StoreFormat::Uninitialized);
        }
        return Ok(format);
    }
    if !has_store_evidence(root)? {
        return Ok(StoreFormat::Uninitialized);
    }
    // A ward creating this store publishes the marker before anything else.
    // So store files seen after a missing marker may be a store being
    // created right now, whose marker has landed since: read it again
    // before calling the store unmarked.
    Ok(read_marker(root)?.unwrap_or(StoreFormat::PreEpoch))
}

/// What the marker file says, or `None` when there is no marker file.
fn read_marker(root: &Path) -> io::Result<Option<StoreFormat>> {
    let path = root.join(FORMAT_FILE);
    // Open first, then check what was opened, and never follow a symlink:
    // the marker decides whether every record under this root is trusted.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path);
    let file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            // A symlink (ELOOP) or a socket (ENXIO, EOPNOTSUPP) fails to
            // open: a marker nobody wrote. A regular file that fails to
            // open is a marker that cannot be read, which is an answer
            // about the store and not a reason to say nothing at all.
            return match fs::symlink_metadata(&path) {
                Ok(stat) if !stat.is_file() => Ok(Some(StoreFormat::Unknown(
                    "the marker is not a regular file".into(),
                ))),
                Ok(_) => Ok(Some(StoreFormat::Unreadable(error.to_string()))),
                Err(gone) if gone.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(error),
            };
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(Some(StoreFormat::Unknown(
            "the marker is not a regular file".into(),
        )));
    }
    // The marker is one short line. Anything longer is not a marker, and is
    // not read to its end to find that out.
    let mut bytes = Vec::new();
    match file.take(65).read_to_end(&mut bytes) {
        Ok(_) => Ok(Some(parse(&bytes))),
        Err(error) => Ok(Some(StoreFormat::Unreadable(error.to_string()))),
    }
}

/// What a marker holding `bytes` says.
fn parse(bytes: &[u8]) -> StoreFormat {
    let unknown = || {
        let shown: String = String::from_utf8_lossy(bytes)
            .chars()
            .take(40)
            .flat_map(char::escape_default)
            .collect();
        StoreFormat::Unknown(format!("it reads \"{shown}\""))
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return unknown();
    };
    let line = text.strip_suffix('\n').unwrap_or(text);
    let Some(number) = line
        .strip_prefix(FORMAT_WORD)
        .and_then(|rest| rest.strip_prefix(' '))
    else {
        return unknown();
    };
    // Digits only, and no leading zero: one spelling per format.
    if number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
    {
        return unknown();
    }
    match number.parse::<u32>() {
        Ok(STORE_FORMAT) => StoreFormat::Current,
        Ok(format) if format > STORE_FORMAT => StoreFormat::Newer(format),
        _ => unknown(),
    }
}

/// The files at the root only a ward's lease writes: never unlinked, so a
/// store any ward has worked in keeps them.
const LEASE_FILES: &[&str] = &["activity.lock", "gc.lock"];

/// Whether `root` holds anything only a ward writes into a store, read
/// through the held root without following a link: an empty regular lease
/// file (`activity.lock`, `gc.lock`, the first thing every ward writes, and
/// what an interrupted reset leaves), or an object record under `meta/`
/// that parses as one, named after the object id it records. Names alone
/// prove nothing: an object-shaped filename or a record-shaped directory is
/// anyone's, and so is a `tmp/` or a `records/` (#676). Nothing is read
/// through a link: a `meta` that is a symlink (`meta -> another-store/meta`)
/// holds no record of this root's, and a lease file that is a link is none.
pub(super) fn has_store_evidence(root: &Path) -> io::Result<bool> {
    let held = open_real_directory(root, "store root")?;
    let fd = held.as_raw_fd();
    let kind = |name: &str| -> io::Result<Option<libc::stat>> {
        match stat_at(fd, name.as_bytes()) {
            Ok(stat) => Ok(Some(stat)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    };
    for name in LEASE_FILES {
        if kind(name)?
            .is_some_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_size == 0)
        {
            return Ok(true);
        }
    }
    let meta = match open_file_at(
        fd,
        b"meta",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(meta) => meta,
        // Absent, not a directory, or a link: no record of this root's.
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(false)
        }
        Err(error) => return Err(error),
    };
    for name in read_dir_names_at(meta.as_raw_fd())? {
        let id = name.to_str().and_then(|name| name.strip_suffix(".json"));
        if id.is_some_and(|id| is_object_id(id) && is_object_record(meta.as_raw_fd(), &name, id)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The most of a candidate record `has_store_evidence` reads.
const EVIDENCE_RECORD_CAP: u64 = 4 << 20;

/// Whether `meta/<name>` is a regular file holding a ward's object record
/// for `id`: a JSON object that is either of an `object-meta/` schema (its
/// `id`, where it has one, `id`) or, as a ward before the record schema
/// wrote it, has no schema and names `id` as its `id`.
fn is_object_record(meta: RawFd, name: &std::ffi::OsStr, id: &str) -> bool {
    let Ok(file) = open_file_at(
        meta,
        name.as_bytes(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) else {
        return false;
    };
    if !file
        .metadata()
        .is_ok_and(|stat| stat.is_file() && stat.len() <= EVIDENCE_RECORD_CAP)
    {
        return false;
    }
    let mut text = String::new();
    if (&file)
        .take(EVIDENCE_RECORD_CAP)
        .read_to_string(&mut text)
        .is_err()
    {
        return false;
    }
    let Ok(record) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let names_id = record.get("id").map(|named| named.as_str() == Some(id));
    match record.get("schema") {
        Some(schema) => {
            schema
                .as_str()
                .is_some_and(|schema| schema.starts_with("object-meta/"))
                && names_id != Some(false)
        }
        None => names_id == Some(true),
    }
}

/// Whether `root` has nothing in it a store could lose or a user could:
/// no entry at all, or only namespace directories with no file anywhere
/// below them (a store whose creation stopped before its marker, made by a
/// ward from before the marker existed). `Store::open` creates a store only
/// in such a directory, and `ward gc --reset` treats one as nothing to
/// empty. Anything else without a marker or store evidence is someone
/// else's directory.
pub(super) fn vacant(root: &Path) -> io::Result<bool> {
    fn no_files_below(path: &Path) -> io::Result<bool> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() || !no_files_below(&entry.path())? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let namespace = NAMESPACES
            .iter()
            .any(|namespace| namespace.split('/').next() == name.to_str());
        if !namespace || !entry.file_type()?.is_dir() || !no_files_below(&entry.path())? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The refusal for a directory that holds files and is not a ward store,
/// for `Store::open` and `ward gc --reset` alike. It carries no `fix:`
/// command: the way out is the user's to pick, and a reset is exactly what
/// must not be run on someone else's files.
pub(crate) fn not_a_store(root: &Path, verb: &str) -> io::Error {
    crate::kernel::error::refused(
        io::ErrorKind::InvalidData,
        format!(
            "{} is not a ward store and is not empty: it has no recognized format marker and \
             no store evidence (no empty lease file, no object record that parses), so {verb}. Point GREYWARD_STORE at a new or empty directory, \
             or move what is there aside",
            root.display()
        ),
    )
}

/// Write the current marker into `root`. The bytes go to a temporary beside
/// the marker and are renamed into place, so a crash leaves either no
/// marker or a whole one, and two wards creating the same store at once both
/// rename the same line.
pub(super) fn write_marker(root: &Path) -> io::Result<()> {
    let root_dir = open_real_directory(root, "store root")?;
    let tmp = format!(".{FORMAT_FILE}.{}.{}.tmp", std::process::id(), nanos());
    let mut file = open_file_at(
        root_dir.as_raw_fd(),
        tmp.as_bytes(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o644,
    )?;
    let result = (|| {
        file.write_all(StoreFormat::current_line().as_bytes())?;
        file.sync_all()?;
        rename_at(root_dir.as_raw_fd(), tmp.as_bytes(), FORMAT_FILE.as_bytes())?;
        fsync_directory(root_dir.as_raw_fd())
    })();
    if result.is_err() {
        unlink_at(root_dir.as_raw_fd(), tmp.as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// What `bytes` as the marker of a used store reads as: one with a
    /// lease file, so a marker this ward cannot read is judged as one.
    fn marker(temp: &TempDir, bytes: &[u8]) -> StoreFormat {
        fs::write(temp.0.join("activity.lock"), b"").unwrap();
        fs::write(temp.0.join(FORMAT_FILE), bytes).unwrap();
        probe(&temp.0).unwrap()
    }

    #[test]
    fn the_marker_is_one_line_naming_the_current_format() {
        assert_eq!(StoreFormat::current_line(), "greyward-store 1\n");
        let temp = TempDir::new();
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Uninitialized);
        write_marker(&temp.0).unwrap();
        assert_eq!(
            fs::read(temp.0.join(FORMAT_FILE)).unwrap(),
            b"greyward-store 1\n"
        );
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Current);
        // Nothing but the marker is left behind.
        let names: Vec<_> = fs::read_dir(&temp.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(FORMAT_FILE)]);
    }

    #[test]
    fn what_only_a_ward_writes_without_a_marker_is_a_pre_epoch_store() {
        let id = format!("{}-test-kept-1", "a".repeat(40));
        let record = format!(r#"{{"schema": "object-meta/2", "id": "{id}"}}"#);
        let old_record = r#"{"schema": "object-meta/1"}"#.to_string();
        let schemaless = format!(r#"{{"id": "{id}", "refs": []}}"#);
        for (path, bytes) in [
            ("activity.lock".to_string(), String::new()),
            ("gc.lock".to_string(), String::new()),
            (format!("meta/{id}.json"), record),
            (format!("meta/{id}.json"), old_record),
            (format!("meta/{id}.json"), schemaless),
        ] {
            let temp = TempDir::new();
            let path = temp.0.join(&path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            assert_eq!(probe(&temp.0).unwrap(), StoreFormat::PreEpoch, "{path:?}");
        }
        // A directory holding only files ward never names is not a store yet.
        let temp = TempDir::new();
        fs::write(temp.0.join("notes.txt"), b"x").unwrap();
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Uninitialized);
        assert!(!vacant(&temp.0).unwrap());
    }

    /// The names of a store's namespaces are names anyone's directory may
    /// have. Holding them, and files in them, does not make a directory a
    /// store (#676), and it is not vacant either: a store is not created
    /// beside those files.
    #[test]
    fn namespace_names_alone_are_not_a_store() {
        let temp = TempDir::new();
        for namespace in ["objects", "meta", "cache", "roots", "records", "tmp"] {
            fs::create_dir(temp.0.join(namespace)).unwrap();
        }
        fs::create_dir_all(temp.0.join("cache/sha256")).unwrap();
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Uninitialized);
        // Empty namespaces are what a creation that stopped early leaves.
        assert!(vacant(&temp.0).unwrap());
        // Names that are no object id are the user's.
        fs::write(temp.0.join("meta/report.json"), b"{}").unwrap();
        fs::create_dir(temp.0.join("objects/photos")).unwrap();
        fs::write(temp.0.join("tmp/draft.txt"), b"draft").unwrap();
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Uninitialized);
        assert!(!vacant(&temp.0).unwrap());
        // A file at the root that is not a namespace is not vacant either.
        let temp = TempDir::new();
        fs::create_dir(temp.0.join("docs")).unwrap();
        assert!(!vacant(&temp.0).unwrap());
    }

    #[test]
    fn a_newer_marker_and_an_unreadable_one_are_told_apart() {
        let temp = TempDir::new();
        assert_eq!(marker(&temp, b"greyward-store 1\n"), StoreFormat::Current);
        assert_eq!(marker(&temp, b"greyward-store 1"), StoreFormat::Current);
        assert_eq!(marker(&temp, b"greyward-store 2\n"), StoreFormat::Newer(2));
        assert_eq!(
            marker(&temp, b"greyward-store 17\n"),
            StoreFormat::Newer(17)
        );
        for bytes in [
            &b""[..],
            b"\n",
            b"greyward-store\n",
            b"greyward-store 0\n",
            b"greyward-store 01\n",
            b"greyward-store +1\n",
            b"greyward-store 1 \n",
            b"greyward-store 1\n\n",
            b" greyward-store 1\n",
            b"greyward-store  1\n",
            b"greyward-store one\n",
            b"greyward-store 99999999999999999999\n",
            b"blanket-store 1\n",
            b"\xff\xfe",
        ] {
            assert!(
                matches!(marker(&temp, bytes), StoreFormat::Unknown(_)),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        // A marker far longer than a marker is not read to its end.
        assert!(matches!(
            marker(&temp, &b"greyward-store 1".repeat(1000)),
            StoreFormat::Unknown(_)
        ));
    }

    #[test]
    fn a_marker_that_is_not_a_regular_file_is_unknown_and_never_followed() {
        let temp = TempDir::new();
        fs::write(temp.0.join("activity.lock"), b"").unwrap();
        let elsewhere = temp.0.join("elsewhere");
        fs::write(&elsewhere, StoreFormat::current_line()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join(FORMAT_FILE)).unwrap();
        assert!(matches!(probe(&temp.0).unwrap(), StoreFormat::Unknown(_)));
        fs::remove_file(temp.0.join(FORMAT_FILE)).unwrap();
        fs::create_dir(temp.0.join(FORMAT_FILE)).unwrap();
        assert!(matches!(probe(&temp.0).unwrap(), StoreFormat::Unknown(_)));
    }

    #[test]
    fn every_refusal_names_the_store_and_both_ways_out() {
        let root = Path::new("/somewhere/store");
        assert_eq!(StoreFormat::Current.refusal(root), None);
        assert_eq!(StoreFormat::Uninitialized.refusal(root), None);
        for format in [
            StoreFormat::PreEpoch,
            StoreFormat::Unknown("it reads \"x\"".into()),
            StoreFormat::Unreadable("Permission denied (os error 13)".into()),
        ] {
            assert!(!format.usable());
            let message = format.refusal(root).unwrap();
            assert!(message.contains("/somewhere/store"), "{message}");
            assert!(message.contains("move the directory aside"), "{message}");
            // The command is the fix line's, never spelled in the prose.
            assert!(!message.contains("--reset"), "{message}");
            assert_eq!(format.fix(), "ward gc --reset");
            let error = format.refuse(root).unwrap_err();
            assert_eq!(error.to_string(), message);
            // `/somewhere/store` is not the store a bare `ward` selects.
            assert_eq!(
                refusal_fix(&error),
                Some("GREYWARD_STORE=/somewhere/store ward gc --reset")
            );
        }
        let newer = StoreFormat::Newer(2);
        assert!(!newer.usable());
        assert_eq!(newer.fix(), "ward update --self");
        // Updating ward is one command whatever store asked for it.
        assert_eq!(newer.fix_for(root), "ward update --self");
        let newer = newer.refusal(root).unwrap();
        assert!(newer.contains("a newer ward wrote it"), "{newer}");
        assert!(newer.contains("greyward-store 2"), "{newer}");
        let old = StoreFormat::PreEpoch.refusal(root).unwrap();
        assert!(old.contains("an older ward wrote it"), "{old}");
        let unreadable = StoreFormat::Unreadable("Permission denied".into())
            .refusal(root)
            .unwrap();
        assert!(unreadable.contains("Permission denied"), "{unreadable}");
        assert_eq!(refusal_fix(&io::Error::other("something else")), None);
    }

    /// A fix acts on the store that was refused: bare for the store a bare
    /// `ward` selects, and naming any other store in a form a shell reads
    /// back as exactly that path.
    #[test]
    fn a_fix_names_a_store_the_bare_command_would_not_select() {
        let reset = "ward gc --reset";
        let a = Path::new("/home/me/.greyward/store");
        assert_eq!(command_on(reset, a, Some(a)), reset);
        assert_eq!(
            command_on(reset, a, Some(Path::new("/elsewhere"))),
            "GREYWARD_STORE=/home/me/.greyward/store ward gc --reset"
        );
        assert_eq!(
            command_on(reset, a, None),
            "GREYWARD_STORE=/home/me/.greyward/store ward gc --reset"
        );
        // A selected store named through a symlink is the same store.
        let temp = TempDir::named("store-format-fix");
        let real = temp.0.join("real");
        fs::create_dir(&real).unwrap();
        let real = real.canonicalize().unwrap();
        let link = temp.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(command_on(reset, &link, Some(&real)), reset);
        assert_eq!(command_on(reset, &real, Some(&real)), reset);

        // Every spelling is exact: a shell that runs the command gives the
        // child the path's own bytes, whatever they are.
        let cases: [(&[u8], &str); 12] = [
            (
                b"/plain/path-1.0_x+y:z@h%,",
                "GREYWARD_STORE=/plain/path-1.0_x+y:z@h%, env",
            ),
            (
                b"/with space/store",
                "GREYWARD_STORE='/with space/store' env",
            ),
            (b"/it's/store", "GREYWARD_STORE='/it'\\''s/store' env"),
            (
                b"/a$b`c\"d\\e;f&g|h*i?j(k)l<m>n~o#p!q",
                "GREYWARD_STORE='/a$b`c\"d\\e;f&g|h*i?j(k)l<m>n~o#p!q' env",
            ),
            (
                "/caf\u{e9}/\u{fffd}".as_bytes(),
                "GREYWARD_STORE='/caf\u{e9}/\u{fffd}' env",
            ),
            (b"/-dash/~tilde", "GREYWARD_STORE='/-dash/~tilde' env"),
            // Not UTF-8: no `String` holds this path, so its bytes are
            // spelled out.
            (b"/st\xff", "GREYWARD_STORE=\"$(printf '/st\\377')\" env"),
            (
                b"/a b\xfe'%\\c",
                "GREYWARD_STORE=\"$(printf '/a\\040b\\376\\047%%\\134c')\" env",
            ),
            // Control characters, a newline inside among them.
            (
                b"/new\nline\x1b[0m",
                "GREYWARD_STORE=\"$(printf '/new\\012line\\033\\1330m')\" env",
            ),
            // Trailing newlines, which `$(...)` would drop.
            (
                b"/ends\n\n",
                "(p=\"$(printf '/ends\\012\\012.')\"; GREYWARD_STORE=\"${p%.}\" env)",
            ),
            (
                b"/x\xff\n",
                "(p=\"$(printf '/x\\377\\012.')\"; GREYWARD_STORE=\"${p%.}\" env)",
            ),
            (b"/9\x01", "GREYWARD_STORE=\"$(printf '/9\\001')\" env"),
        ];
        let shells = posix_shells();
        for (bytes, expected) in cases {
            use std::os::unix::ffi::OsStrExt as _;
            let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
            assert_eq!(with_store("env", path), expected, "{path:?}");
            // Every shell here that runs it hands the command a GREYWARD_STORE
            // of exactly these bytes.
            for shell in &shells {
                // The same shell reads the variable the prefix set.
                let inner = format!("{} -c 'printf %s \"$GREYWARD_STORE\"'", shell.join(" "));
                let command = with_store(&inner, path);
                let out = std::process::Command::new(&shell[0])
                    .args(&shell[1..])
                    .arg("-c")
                    .arg(&command)
                    .env_remove("GREYWARD_STORE")
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{shell:?}: {command}");
                assert_eq!(out.stdout, bytes, "{shell:?}: {command}");
            }
        }
    }

    /// The shells the printed commands are checked under: `/bin/sh`, and
    /// dash, busybox's `sh` and bash wherever they are installed (a
    /// Fedora `/bin/sh` is bash, an Ubuntu one dash).
    fn posix_shells() -> Vec<Vec<String>> {
        let found = |name: &str| {
            std::env::var_os("PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .map(|dir| dir.join(name))
                    .find(|candidate| candidate.is_file())
            })
        };
        let mut shells = vec![vec!["/bin/sh".to_string()]];
        for (name, args) in [
            ("dash", &[][..]),
            ("busybox", &["sh"][..]),
            ("bash", &[][..]),
        ] {
            if let Some(binary) = found(name) {
                let mut shell = vec![binary.to_string_lossy().into_owned()];
                shell.extend(args.iter().map(|arg| (*arg).to_string()));
                shells.push(shell);
            }
        }
        shells
    }

    /// The bare command is printed only for a store a bare `ward` selects
    /// from any directory. A relative selection is not that: the fix names
    /// the refused store, absolute.
    #[test]
    fn a_fix_for_a_store_selected_relatively_names_it_absolutely() {
        let temp = TempDir::named("store-format-relative");
        let root = temp.0.join("store");
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        // What `fix_for` passes when GREYWARD_STORE is relative: no selection.
        assert_eq!(
            command_on("ward gc --reset", &root, None),
            format!("GREYWARD_STORE={} ward gc --reset", root.display())
        );
        // A root that reaches here relative is printed absolute.
        let relative = Path::new("no-such-store-here");
        let command = command_on("ward gc --reset", relative, None);
        let absolute = std::path::absolute(relative).unwrap();
        assert_eq!(
            command,
            format!("GREYWARD_STORE={} ward gc --reset", absolute.display())
        );
    }

    /// Many wards creating one store at once: every one of them ends with
    /// the store open, and none takes the other's namespaces for a store
    /// written before the marker existed.
    #[test]
    fn concurrent_creation_never_reads_as_a_store_without_a_marker() {
        for round in 0..20 {
            let temp = TempDir::named(&format!("store-format-race-{round}"));
            let root = temp.0.join("store");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
            let threads: Vec<_> = (0..16)
                .map(|index| {
                    let root = root.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        // Half create the store, half only look at it.
                        if index % 2 == 0 {
                            Store::open_at(&root).map(|_| StoreFormat::Current)
                        } else {
                            Ok(Store::probe_at(&root)?
                                .map_or(StoreFormat::Uninitialized, |(_, format)| format))
                        }
                    })
                })
                .collect();
            for thread in threads {
                let seen = thread.join().unwrap().unwrap();
                assert!(seen.usable(), "round {round}: {seen:?}");
            }
            assert_eq!(probe(&root).unwrap(), StoreFormat::Current);
        }
    }

    /// Store evidence is what parses, read without following a link (#676
    /// review): a name shaped like an object, a lease name that is not an
    /// empty file, a record that is no record or names another object, and
    /// anything reached through a namespace that is a symlink to another
    /// store are all someone's files. Such a root is no store, so neither a
    /// marker beside it that ward cannot read nor a reset makes it one.
    #[test]
    fn evidence_must_parse_and_is_never_followed() {
        let id = format!("{}-test-kept-1", "a".repeat(40));
        let other = format!("{}-test-kept-1", "b".repeat(40));
        let real = TempDir::new();
        fs::create_dir_all(real.0.join("meta")).unwrap();
        fs::write(real.0.join("activity.lock"), b"").unwrap();
        let record = format!(r#"{{"schema": "object-meta/2", "id": "{id}"}}"#);
        fs::write(real.0.join(format!("meta/{id}.json")), &record).unwrap();
        type Plant = Box<dyn Fn(&Path)>;
        let cases: Vec<(&str, Plant)> = vec![
            (
                "an object-shaped directory",
                Box::new({
                    let id = id.clone();
                    move |root| fs::create_dir_all(root.join("objects").join(&id)).unwrap()
                }),
            ),
            (
                "an object-shaped file",
                Box::new({
                    let id = id.clone();
                    move |root| {
                        fs::create_dir_all(root.join("objects")).unwrap();
                        fs::write(root.join("objects").join(&id), b"x").unwrap();
                    }
                }),
            ),
            (
                "a record-shaped directory",
                Box::new({
                    let id = id.clone();
                    move |root| fs::create_dir_all(root.join(format!("meta/{id}.json"))).unwrap()
                }),
            ),
            (
                "a record that is not JSON",
                Box::new({
                    let id = id.clone();
                    move |root| {
                        fs::create_dir_all(root.join("meta")).unwrap();
                        fs::write(root.join(format!("meta/{id}.json")), b"a,b\n").unwrap();
                    }
                }),
            ),
            (
                "a record of another schema",
                Box::new({
                    let id = id.clone();
                    move |root| {
                        fs::create_dir_all(root.join("meta")).unwrap();
                        fs::write(root.join(format!("meta/{id}.json")), br#"{"schema":"x"}"#)
                            .unwrap();
                    }
                }),
            ),
            (
                "a schemaless JSON file without the id",
                Box::new({
                    let id = id.clone();
                    move |root| {
                        fs::create_dir_all(root.join("meta")).unwrap();
                        fs::write(root.join(format!("meta/{id}.json")), br#"{"title":"q1"}"#)
                            .unwrap();
                    }
                }),
            ),
            (
                "a record naming another object",
                Box::new({
                    let (id, other) = (id.clone(), other.clone());
                    move |root| {
                        fs::create_dir_all(root.join("meta")).unwrap();
                        let text = format!(r#"{{"schema": "object-meta/2", "id": "{other}"}}"#);
                        fs::write(root.join(format!("meta/{id}.json")), text).unwrap();
                    }
                }),
            ),
            (
                "a lease name that holds data",
                Box::new(|root| fs::write(root.join("activity.lock"), b"my notes").unwrap()),
            ),
            (
                "a lease name that is a directory",
                Box::new(|root| fs::create_dir(root.join("gc.lock")).unwrap()),
            ),
            (
                "a lease name that is a link to a store's",
                Box::new({
                    let target = real.0.join("activity.lock");
                    move |root| {
                        std::os::unix::fs::symlink(&target, root.join("activity.lock")).unwrap()
                    }
                }),
            ),
            (
                "meta linked to another store's",
                Box::new({
                    let target = real.0.join("meta");
                    move |root| std::os::unix::fs::symlink(&target, root.join("meta")).unwrap()
                }),
            ),
            (
                "objects linked to another store's",
                Box::new({
                    let target = real.0.join("objects");
                    move |root| std::os::unix::fs::symlink(&target, root.join("objects")).unwrap()
                }),
            ),
        ];
        for (what, plant) in &cases {
            let temp = TempDir::new();
            plant(&temp.0);
            fs::create_dir_all(temp.0.join("records")).unwrap();
            fs::write(temp.0.join("records/2026.csv"), b"q1,q2\n").unwrap();
            assert!(!has_store_evidence(&temp.0).unwrap(), "{what}");
            assert_eq!(
                probe(&temp.0).unwrap(),
                StoreFormat::Uninitialized,
                "{what}"
            );
            // A `format` of anyone's beside it does not make it a store.
            fs::write(temp.0.join(FORMAT_FILE), b"A4, portrait\n").unwrap();
            assert_eq!(
                probe(&temp.0).unwrap(),
                StoreFormat::Uninitialized,
                "{what}"
            );
            fs::remove_file(temp.0.join(FORMAT_FILE)).unwrap();
            fs::create_dir(temp.0.join(FORMAT_FILE)).unwrap();
            assert_eq!(
                probe(&temp.0).unwrap(),
                StoreFormat::Uninitialized,
                "{what}"
            );
            assert!(!vacant(&temp.0).unwrap(), "{what}");
        }
        assert!(has_store_evidence(&real.0).unwrap());
    }

    /// The window the re-read closes, held open by hand: the marker is
    /// absent on the first read and published, with its namespaces, by the
    /// time the namespaces are looked for.
    #[test]
    fn a_marker_published_between_the_two_reads_is_honoured() {
        let temp = TempDir::named("store-format-reread");
        assert_eq!(read_marker(&temp.0).unwrap(), None);
        write_marker(&temp.0).unwrap();
        fs::write(temp.0.join("activity.lock"), b"").unwrap();
        assert!(has_store_evidence(&temp.0).unwrap());
        assert_eq!(read_marker(&temp.0).unwrap(), Some(StoreFormat::Current));
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Current);
    }
}
