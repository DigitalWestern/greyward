//! Zip archives under the tar path's rules: wheels, zip sdists, the Elixir
//! release zip, Hex's `.ez`, and the outer layer of a `.conda` package.
//!
//! The `zip` crate reads the central directory and inflates members; this
//! module decides what may be read or written from them, so every zip
//! consumer refuses the same archives a tar consumer would (#675):
//!
//! - Names pass the listing rules: printable, no absolute name, no `..` or
//!   empty component, no two entries that name one file once `./` and a
//!   trailing `/` are dropped, and no two names APFS folds into one.
//! - Only regular files and directories: a symlink, device, FIFO or socket
//!   entry refuses the archive, and so does an encrypted one.
//! - The declared sizes of every file add up to at most the caller's
//!   budget before anything is read, and each member then yields exactly
//!   the bytes it declared. The crate bounds a deflate stream only by its
//!   compressed size, so a member that claims one byte could otherwise
//!   inflate without limit; here one byte past the claim refuses.
//! - Modes are pip's: a file with any execute bit is written 0o755, every
//!   other file 0o644, and directory modes are ignored. An archive cannot
//!   hide a file from other users, or leave a directory unwritable for the
//!   next archive to land in it.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use zip::ZipArchive;

use super::{check_name_text, err, validate, Entry, EntryKind, ExtractOptions};

/// One member of a validated zip listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipMember {
    /// The name exactly as stored (directories keep their trailing `/`).
    pub name: String,
    pub dir: bool,
    /// Any execute bit in the stored Unix mode.
    pub executable: bool,
    /// The uncompressed size the central directory declares; 0 for a
    /// directory. Reading the member yields exactly this many bytes.
    pub size: u64,
    index: usize,
}

impl ZipMember {
    /// The mode a file member is written with: pip's rule.
    pub fn file_mode(&self) -> u32 {
        if self.executable {
            0o755
        } else {
            0o644
        }
    }
}

/// An open zip whose listing passed every rule above. Members are read
/// through it, each bounded to its declared size.
pub struct ZipReader {
    path: PathBuf,
    archive: ZipArchive<File>,
    members: Vec<ZipMember>,
}

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;

impl ZipReader {
    /// Open `path` and validate its whole listing, refusing it when the
    /// files' declared sizes add up to more than `budget` bytes.
    pub fn open(path: &Path, budget: u64) -> io::Result<Self> {
        let refuse = |what: String| err(format!("zip archive {}: {what}", path.display()));
        let file = File::open(path)
            .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", path.display())))?;
        let mut archive =
            ZipArchive::new(file).map_err(|e| refuse(format!("not a readable zip: {e}")))?;
        // The crate keys its entries by name and keeps one entry per name,
        // so a name stored twice would reach this listing once. Python's
        // zipfile extracts both and the last wins: the two readers would
        // disagree about which bytes the archive holds. Count the records
        // themselves.
        let records = central_records(path, archive.central_directory_start())?;
        if records != archive.len() {
            return Err(refuse(format!(
                "the central directory holds {records} records for {} distinct names; \
                 an entry is written more than once, refusing",
                archive.len()
            )));
        }
        let mut members = Vec::with_capacity(archive.len());
        let mut total: u64 = 0;
        for index in 0..archive.len() {
            // The raw view reads the headers without starting decryption
            // or decompression, so an encrypted entry is seen, not failed on.
            let entry = archive
                .by_index_raw(index)
                .map_err(|e| refuse(format!("entry {index}: {e}")))?;
            let name = entry.name().to_string();
            check_name_text(&name, "").map_err(|e| refuse(e.to_string()))?;
            if entry.encrypted() {
                return Err(refuse(format!("entry {name:?} is encrypted")));
            }
            let mode = entry.unix_mode();
            let file_type = mode.map(|mode| mode & S_IFMT).unwrap_or(0);
            if !matches!(file_type, 0 | S_IFREG | S_IFDIR) {
                let what = if entry.is_symlink() {
                    "a symlink"
                } else {
                    "a special file"
                };
                return Err(refuse(format!("entry {name:?} is {what}")));
            }
            let dir = entry.is_dir();
            let size = if dir { 0 } else { entry.size() };
            if !dir {
                total = total
                    .checked_add(size)
                    .filter(|total| *total <= budget)
                    .ok_or_else(|| {
                        refuse(format!(
                            "entry {name:?} passes the {budget} byte budget; refusing to extract"
                        ))
                    })?;
            }
            members.push(ZipMember {
                executable: !dir && mode.is_some_and(|mode| mode & 0o111 != 0),
                name,
                dir,
                size,
                index,
            });
        }
        let entries: Vec<Entry> = members
            .iter()
            .map(|member| Entry {
                kind: if member.dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                name: member.name.clone(),
                link: None,
            })
            .collect();
        validate::validate_with_options(&entries, &ExtractOptions::stripped(0))
            .map_err(|e| refuse(e.to_string()))?;
        Ok(ZipReader {
            path: path.to_path_buf(),
            archive,
            members,
        })
    }

    /// Every member, in archive order.
    pub fn members(&self) -> &[ZipMember] {
        &self.members
    }

    /// The file member stored under exactly `name`, if there is one. The
    /// listing refused repeated names, so there is at most one.
    pub fn file(&self, name: &str) -> Option<&ZipMember> {
        self.members
            .iter()
            .find(|member| !member.dir && member.name == name)
    }

    /// Visit every member in archive order. A file member comes with a
    /// reader that yields exactly its declared bytes; whatever `visit`
    /// leaves unread is read afterwards, so a member that inflates past its
    /// claim, or whose bytes fail their CRC, refuses even when skipped.
    pub fn for_each(
        &mut self,
        mut visit: impl FnMut(&ZipMember, &mut dyn Read) -> io::Result<()>,
    ) -> io::Result<()> {
        for member in self.members.clone() {
            if member.dir {
                visit(&member, &mut io::empty())?;
                continue;
            }
            let path = &self.path;
            let entry = self.archive.by_index(member.index).map_err(|e| {
                err(format!(
                    "zip archive {}: {}: {e}",
                    path.display(),
                    member.name
                ))
            })?;
            let mut reader = Exact::new(entry, &member, path);
            visit(&member, &mut reader)?;
            io::copy(&mut reader, &mut io::sink())?;
        }
        Ok(())
    }

    /// Copy the file member `member` into `out`, refusing a member that
    /// declares more than `cap` bytes.
    pub fn copy(&mut self, member: &ZipMember, cap: u64, out: &mut dyn Write) -> io::Result<u64> {
        if member.dir {
            return Err(err(format!(
                "zip archive {}: entry {:?} is not a regular file",
                self.path.display(),
                member.name
            )));
        }
        if member.size > cap {
            return Err(err(format!(
                "zip archive {}: entry {:?} holds {} bytes, more than the {cap} byte read cap",
                self.path.display(),
                member.name,
                member.size
            )));
        }
        let path = &self.path;
        let entry = self.archive.by_index(member.index).map_err(|e| {
            err(format!(
                "zip archive {}: {}: {e}",
                path.display(),
                member.name
            ))
        })?;
        io::copy(&mut Exact::new(entry, member, path), out)
    }

    /// The bytes of the file member stored under exactly `name`, at most
    /// `cap` of them.
    pub fn read(&mut self, name: &str, cap: u64) -> io::Result<Vec<u8>> {
        let member = self.file(name).cloned().ok_or_else(|| {
            err(format!(
                "zip archive {} has no file {name:?}",
                self.path.display()
            ))
        })?;
        let mut bytes = Vec::new();
        self.copy(&member, cap, &mut bytes)?;
        Ok(bytes)
    }

    /// Write the members `place` keeps into `destination`, which must not
    /// hold any of them yet. `place` maps a member to its path relative to
    /// `destination`, or `None` to skip it. Files get [`ZipMember::file_mode`];
    /// directories are created with the default mode.
    pub fn extract(
        &mut self,
        destination: &Path,
        mut place: impl FnMut(&ZipMember) -> io::Result<Option<PathBuf>>,
    ) -> io::Result<()> {
        fs::create_dir_all(destination)?;
        self.for_each(|member, reader| {
            let Some(relative) = place(member)? else {
                return Ok(());
            };
            if relative.as_os_str().is_empty()
                || !relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(err(format!(
                    "zip entry {:?} maps to unsafe path {}",
                    member.name,
                    relative.display()
                )));
            }
            let output = destination.join(relative);
            if member.dir {
                return fs::create_dir_all(&output);
            }
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("write {}: {e}", output.display()))
                })?;
            io::copy(reader, &mut file)?;
            drop(file);
            set_mode(&output, member.file_mode())
        })
    }
}

/// Validate `path` and extract every member into `destination` as stored.
pub fn extract_zip(path: &Path, destination: &Path, budget: u64) -> io::Result<()> {
    ZipReader::open(path, budget)?.extract(destination, |member| {
        Ok(Some(PathBuf::from(member.name.trim_end_matches('/'))))
    })
}

/// How many central-directory file headers (`PK\x01\x02`) follow one
/// another from `start`, the offset the crate read them from.
fn central_records(path: &Path, start: u64) -> io::Result<usize> {
    use std::io::{BufReader, Seek, SeekFrom};
    let mut reader = BufReader::new(File::open(path)?);
    reader.seek(SeekFrom::Start(start))?;
    let mut records = 0;
    let mut header = [0u8; 46];
    loop {
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(records),
            Err(e) => return Err(e),
        }
        if &header[..4] != b"PK\x01\x02" {
            return Ok(records);
        }
        let field = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]) as i64;
        reader.seek_relative(field(28) + field(30) + field(32))?;
        records += 1;
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// A member's data, exactly as long as the member declared: a short stream
/// is truncation, and a byte past the declared size is refused rather than
/// written. The last read reaches the crate's own end of stream, where it
/// checks the CRC.
struct Exact<'a, R> {
    inner: R,
    left: u64,
    name: &'a str,
    archive: &'a Path,
}

impl<'a, R: Read> Exact<'a, R> {
    fn new(inner: R, member: &'a ZipMember, archive: &'a Path) -> Self {
        Exact {
            inner,
            left: member.size,
            name: &member.name,
            archive,
        }
    }
}

impl<R: Read> Read for Exact<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(err(format!(
                    "zip archive {}: entry {:?} inflates past its declared size; refusing",
                    self.archive.display(),
                    self.name
                ))),
            };
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buf[..want])?;
        if read == 0 {
            return Err(err(format!(
                "zip archive {}: entry {:?} holds fewer bytes than it declares",
                self.archive.display(),
                self.name
            )));
        }
        self.left -= read as u64;
        Ok(read)
    }
}

/// Header surgery for tests that need a zip no honest writer makes.
#[cfg(test)]
pub(crate) mod testing {
    /// Each header that stores `name`: the offset of its first byte and
    /// whether it is a central-directory record.
    fn headers(bytes: &[u8], name: &str) -> Vec<(usize, bool)> {
        let mut found = Vec::new();
        for at in 0..bytes.len().saturating_sub(46) {
            let (central, name_len_at, name_at) = match &bytes[at..at + 4] {
                b"PK\x03\x04" => (false, at + 26, at + 30),
                b"PK\x01\x02" => (true, at + 28, at + 46),
                _ => continue,
            };
            let len = u16::from_le_bytes([bytes[name_len_at], bytes[name_len_at + 1]]) as usize;
            if bytes.get(name_at..name_at + len) == Some(name.as_bytes()) {
                found.push((at, central));
            }
        }
        assert_eq!(found.len(), 2, "{name} headers");
        found
    }

    /// Rewrite the uncompressed size `name` declares, in its local header
    /// and its central-directory record, to `claimed`.
    pub(crate) fn claim_size(bytes: &mut [u8], name: &str, claimed: u32) {
        for (at, central) in headers(bytes, name) {
            let field = if central { at + 24 } else { at + 22 };
            bytes[field..field + 4].copy_from_slice(&claimed.to_le_bytes());
        }
    }

    /// Rename `from` to `to`, a name of the same length, in both headers:
    /// the only way to write a name twice, since the writer refuses that.
    pub(crate) fn rename(bytes: &mut [u8], from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        for (at, central) in headers(bytes, from) {
            let name_at = if central { at + 46 } else { at + 30 };
            bytes[name_at..name_at + to.len()].copy_from_slice(to.as_bytes());
        }
    }

    /// Store `mode` (file type bits included) as `name`'s Unix mode.
    pub(crate) fn set_unix_mode(bytes: &mut [u8], name: &str, mode: u32) {
        for (at, central) in headers(bytes, name) {
            if central {
                bytes[at + 38..at + 42].copy_from_slice(&(mode << 16).to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    const BUDGET: u64 = 1 << 30;

    /// A zip of `(name, mode, bytes)` members; a name ending in `/` is a
    /// directory.
    fn zip_bytes(members: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()));
        for (name, mode, bytes) in members {
            let options = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(*mode);
            if name.ends_with('/') {
                writer.add_directory(*name, options).unwrap();
            } else {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
        }
        writer.finish().unwrap().into_inner()
    }

    fn write_zip(temp: &TempDir, members: &[(&str, u32, &[u8])]) -> PathBuf {
        let path = temp.0.join("archive.zip");
        fs::write(&path, zip_bytes(members)).unwrap();
        path
    }

    fn refused(path: &Path, needle: &str) {
        let error = ZipReader::open(path, BUDGET)
            .err()
            .unwrap_or_else(|| panic!("{needle}: opened"));
        assert!(
            error.to_string().contains(needle),
            "{needle:?} not in {error}"
        );
    }

    #[test]
    fn a_member_that_inflates_past_its_declared_size_is_refused() {
        let temp = TempDir::named("zip-overrun");
        let mut bytes = zip_bytes(&[("pkg/big.bin", 0o644, &vec![0u8; 1 << 20])]);
        testing::claim_size(&mut bytes, "pkg/big.bin", 1);
        let path = temp.0.join("archive.zip");
        fs::write(&path, bytes).unwrap();
        let mut reader = ZipReader::open(&path, BUDGET).unwrap();
        assert_eq!(reader.members()[0].size, 1);
        let error = reader
            .extract(&temp.0.join("out"), |m| Ok(Some(PathBuf::from(&m.name))))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("inflates past its declared size"),
            "{error}"
        );
        // Nothing past the claim reached the disk.
        let written = fs::metadata(temp.0.join("out/pkg/big.bin")).unwrap().len();
        assert!(written <= 1, "{written}");
        // Skipped, it still refuses: the visitor drains every member.
        let mut reader = ZipReader::open(&path, BUDGET).unwrap();
        let error = reader.for_each(|_, _| Ok(())).unwrap_err();
        assert!(error.to_string().contains("inflates past"), "{error}");
        // And a read by name refuses too.
        let mut reader = ZipReader::open(&path, BUDGET).unwrap();
        assert!(reader.read("pkg/big.bin", 16).is_err());
    }

    #[test]
    fn declared_sizes_past_the_budget_refuse_before_anything_is_read() {
        let temp = TempDir::named("zip-budget");
        let path = write_zip(
            &temp,
            &[("a", 0o644, &[1u8; 600]), ("b", 0o644, &[2u8; 600])],
        );
        assert!(ZipReader::open(&path, 1200).is_ok());
        let error = ZipReader::open(&path, 1000).err().unwrap();
        assert!(error.to_string().contains("byte budget"), "{error}");
    }

    #[test]
    fn a_read_past_its_cap_is_refused() {
        let temp = TempDir::named("zip-cap");
        let path = write_zip(&temp, &[("a", 0o644, &[1u8; 64])]);
        let mut reader = ZipReader::open(&path, BUDGET).unwrap();
        assert_eq!(reader.read("a", 64).unwrap(), vec![1u8; 64]);
        let error = reader.read("a", 63).unwrap_err();
        assert!(error.to_string().contains("read cap"), "{error}");
        assert!(reader.read("missing", 64).is_err());
    }

    #[test]
    fn two_spellings_of_one_name_are_refused() {
        let temp = TempDir::named("zip-twice");
        for (first, second) in [
            ("pkg/pyproject.toml", "pkg/./pyproject.toml"),
            ("pkg/a", "pkg/a/"),
            ("pkg/README", "pkg/readme"),
        ] {
            let path = write_zip(&temp, &[(first, 0o644, b"1"), (second, 0o644, b"2")]);
            refused(&path, "refusing");
        }
        // The very same name twice, which the writer will not produce.
        let mut bytes = zip_bytes(&[("pkg/a", 0o644, b"1"), ("pkg/b", 0o644, b"2")]);
        testing::rename(&mut bytes, "pkg/b", "pkg/a");
        let path = temp.0.join("twice.zip");
        fs::write(&path, bytes).unwrap();
        let error = ZipReader::open(&path, BUDGET).err().unwrap();
        assert!(
            error.to_string().contains("written more than once"),
            "{error}"
        );
        // A repeated directory carries no bytes and stays allowed.
        let path = write_zip(&temp, &[("pkg/", 0o755, b""), ("pkg/./", 0o755, b"")]);
        assert!(ZipReader::open(&path, BUDGET).is_ok());
    }

    #[test]
    fn names_that_leave_the_destination_or_hide_text_are_refused() {
        let temp = TempDir::named("zip-names");
        for (name, needle) in [
            ("/abs", "absolute member name"),
            ("pkg/../x", "`..` path component"),
            ("pkg//x", "empty path component"),
            ("pkg/\u{202E}txt", "bidirectional"),
            ("pkg/a\nb", "control character"),
        ] {
            let path = write_zip(&temp, &[(name, 0o644, b"x")]);
            refused(&path, needle);
        }
    }

    #[test]
    fn symlinks_and_special_files_are_refused() {
        let temp = TempDir::named("zip-kinds");
        let path = temp.0.join("archive.zip");
        let mut writer = ZipWriter::new(fs::File::create(&path).unwrap());
        writer
            .add_symlink("pkg/link", "../../etc/passwd", SimpleFileOptions::default())
            .unwrap();
        writer.finish().unwrap();
        refused(&path, "is a symlink");
        let mut bytes = zip_bytes(&[("pkg/fifo", 0o644, b"")]);
        testing::set_unix_mode(&mut bytes, "pkg/fifo", 0o010_644);
        let path = temp.0.join("archive.zip");
        fs::write(&path, bytes).unwrap();
        refused(&path, "is a special file");
    }

    #[test]
    fn modes_are_pips_and_directory_modes_are_ignored() {
        let temp = TempDir::named("zip-modes");
        let path = write_zip(
            &temp,
            &[
                ("pkg/", 0o555, b""),
                ("pkg/private", 0o600, b"p"),
                ("pkg/group", 0o660, b"g"),
                ("pkg/owner-exec", 0o700, b"x"),
                ("pkg/tool", 0o755, b"t"),
                ("locked/", 0o000, b""),
                ("locked/a", 0o644, b"a"),
            ],
        );
        let out = temp.0.join("out");
        extract_zip(&path, &out, BUDGET).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = |name: &str| fs::metadata(out.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("pkg/private"), 0o644);
        assert_eq!(mode("pkg/group"), 0o644);
        assert_eq!(mode("pkg/owner-exec"), 0o755);
        assert_eq!(mode("pkg/tool"), 0o755);
        // The 0o555 and 0o000 directories were not applied: a later file
        // could be written into each, and both stay listable.
        assert_ne!(mode("pkg") & 0o200, 0);
        assert_ne!(mode("locked") & 0o500, 0);
        fs::write(out.join("pkg/later"), b"").unwrap();
        assert_eq!(fs::read(out.join("locked/a")).unwrap(), b"a");
    }

    #[test]
    fn extraction_writes_only_where_place_maps_and_never_over_a_file() {
        let temp = TempDir::named("zip-place");
        let path = write_zip(&temp, &[("root/a", 0o644, b"a"), ("root/b", 0o644, b"b")]);
        let out = temp.0.join("out");
        let mut reader = ZipReader::open(&path, BUDGET).unwrap();
        reader
            .extract(&out, |m| {
                Ok((m.name == "root/a").then(|| PathBuf::from("a")))
            })
            .unwrap();
        assert_eq!(fs::read(out.join("a")).unwrap(), b"a");
        assert!(!out.join("b").exists());
        let mut reader = ZipReader::open(&path, BUDGET).unwrap();
        let error = reader
            .extract(&out, |_| Ok(Some(PathBuf::from("../x"))))
            .unwrap_err();
        assert!(error.to_string().contains("unsafe path"), "{error}");
        // A second extraction into the same tree refuses to overwrite.
        assert!(extract_zip(&path, &out, BUDGET).is_ok());
        assert!(extract_zip(&path, &out, BUDGET).is_err());
    }
}
