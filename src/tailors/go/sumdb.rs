//! Go's checksum database, read for `young-package`: its signed tree
//! heads and its lookup answers.
//!
//! Go's module proxy records no upload time: a version's `.info` time is
//! its commit's, which whoever made the commit sets. The checksum database
//! (sum.golang.org) is an append-only transparency log, and its lookup
//! answer gives the version's record number in it. A tree head the
//! database signed says how many records the log held then, so ward judges
//! a Go version by where it sits in the log ([`crate::kernel::resolve::tlog`]).
//!
//! The formats are Go's own (`golang.org/x/mod/sumdb/note` and `tlog`):
//!
//! - A signed note is text ending in a newline, a blank line, then one
//!   line per signature, `— <name> <base64(key hash ‖ signature)>`. The
//!   key hash is the first four bytes of SHA-256 over `<name>\n`, the
//!   algorithm byte (1, Ed25519) and the public key. The signature covers
//!   the text.
//! - A tree head's text is `go.sum database tree\n<size>\n<root hash>\n`.
//! - A lookup answer is the record number, a newline, the record's go.sum
//!   lines, a blank line, then the signed tree head.
//!
//! The record number is authenticated by the TLS connection to the
//! database only: ward checks it is below the signed size of the head the
//! same answer carries, but does not fetch the tiles that would prove the
//! record sits there.

use crate::kernel::resolve::tlog::{Checkpoint, Head, Log};
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

/// sum.golang.org's verifier key, as Go's `GOSUMDB` default spells it.
pub const SUMDB_KEY: &str = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";
const TREE_TEXT: &str = "go.sum database tree\n";
/// Go's note format allows at most this many signatures.
const MAX_SIGNATURES: usize = 100;
/// The checkpoint the binary carries: `observed <unix seconds>`, then
/// sum.golang.org's signed tree head, written by `tools/sumdb_seed.py`.
const SEED: &str = include_str!("sumdb-seed.txt");

/// One verifier key: the signer's name, its key hash, its Ed25519 key.
struct Verifier {
    name: &'static str,
    hash: [u8; 4],
    key: [u8; 32],
}

fn verifier() -> Result<Verifier, String> {
    let bad = || format!("the verifier key {SUMDB_KEY:?} is malformed");
    let (name, rest) = SUMDB_KEY.split_once('+').ok_or_else(bad)?;
    let (hash, key) = rest.split_once('+').ok_or_else(bad)?;
    let hash: [u8; 4] = hex::decode(hash)
        .ok()
        .and_then(|hash| hash.try_into().ok())
        .ok_or_else(bad)?;
    let key = crate::kernel::base64::decode_padded(key).ok_or_else(bad)?;
    let [1, public @ ..] = key.as_slice() else {
        return Err(bad());
    };
    let public: [u8; 32] = public.try_into().map_err(|_| bad())?;
    if key_hash(name, &key) != hash {
        return Err(bad());
    }
    Ok(Verifier {
        name,
        hash,
        key: public,
    })
}

/// The first four bytes of SHA-256 over `<name>\n` and the key (with its
/// algorithm byte).
fn key_hash(name: &str, key: &[u8]) -> [u8; 4] {
    let digest = Sha256::new()
        .chain_update(name.as_bytes())
        .chain_update(b"\n")
        .chain_update(key)
        .finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The tree a signed tree head names (its size and root hash), once sum.golang.org's
/// signature over it verifies. Read as Go's `note.Open` reads a note: any
/// other signer's line is skipped, only the first of sum.golang.org's lines
/// is checked (Go drops repeats by one verifier), and signatures are padded
/// standard base64. A note with none of sum.golang.org's, a bad one, or a
/// malformed line is refused.
pub fn verify_tree(note: &[u8]) -> Result<Head, String> {
    let note = std::str::from_utf8(note).map_err(|_| "the tree head is not UTF-8".to_string())?;
    let split = note
        .rfind("\n\n")
        .ok_or("the tree head has no signature block")?;
    let (text, signatures) = (&note[..=split], &note[split + 2..]);
    let signatures = signatures
        .strip_suffix('\n')
        .ok_or("the tree head's signatures do not end in a newline")?;
    let verifier = verifier()?;
    let mut verified = false;
    for (count, line) in signatures.split('\n').enumerate() {
        if count >= MAX_SIGNATURES {
            return Err("the tree head carries too many signatures".into());
        }
        let malformed = || format!("the tree head's signature line {line:?} is malformed");
        let (name, signature) = line
            .strip_prefix("\u{2014} ")
            .and_then(|line| line.split_once(' '))
            .filter(|(name, _)| !name.is_empty() && !name.contains(char::is_whitespace))
            .filter(|(name, _)| !name.contains('+'))
            .ok_or_else(malformed)?;
        let signature = crate::kernel::base64::decode_padded(signature)
            .filter(|signature| signature.len() > 4)
            .ok_or_else(malformed)?;
        if name != verifier.name || signature[..4] != verifier.hash || verified {
            continue;
        }
        UnparsedPublicKey::new(&ED25519, verifier.key)
            .verify(text.as_bytes(), &signature[4..])
            .map_err(|_| format!("the tree head's signature by {name} does not verify"))?;
        verified = true;
    }
    if !verified {
        return Err(format!("the tree head is not signed by {}", verifier.name));
    }
    tree_size(text)
}

/// The size and root hash in a verified tree head's text, read as Go's `tlog.ParseTree`
/// reads it: the header line, the size, the root hash (32 bytes of padded
/// standard base64), each ending in a newline. Lines after the hash are
/// ignored, as Go ignores them for forward compatibility.
fn tree_size(text: &str) -> Result<Head, String> {
    let malformed = || "the signed text is not a go.sum database tree".to_string();
    let rest = text.strip_prefix(TREE_TEXT).ok_or_else(malformed)?;
    let lines: Vec<&str> = rest.splitn(3, '\n').collect();
    let [size, hash, _later] = lines.as_slice() else {
        return Err(malformed());
    };
    let root: [u8; 32] = crate::kernel::base64::decode_padded(hash)
        .and_then(|hash| hash.try_into().ok())
        .ok_or_else(malformed)?;
    let size = go_count(size).ok_or_else(malformed)?;
    Ok(Head { size, root })
}

/// A count as Go's `strconv.ParseInt(text, 10, 64)` reads one, not
/// negative: an optional sign, then decimal digits.
fn go_count(text: &str) -> Option<u64> {
    let count: i64 = text.parse().ok()?;
    u64::try_from(count).ok()
}

/// A lookup answer: its record number, the record's text, and the signed
/// tree head it ends with.
#[derive(Debug)]
pub struct Answer<'a> {
    pub record: u64,
    pub text: &'a str,
    pub tree: &'a [u8],
}

/// Split a lookup answer as Go's `tlog.ParseRecord` does.
pub fn split_lookup(body: &[u8]) -> Result<Answer<'_>, String> {
    let malformed = || "the lookup answer is not a record and a tree head".to_string();
    let newline = body
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(malformed)?;
    let record = std::str::from_utf8(&body[..newline])
        .ok()
        .and_then(go_count)
        .ok_or_else(malformed)?;
    let rest = &body[newline + 1..];
    let blank = rest
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(malformed)?;
    let text = std::str::from_utf8(&rest[..=blank]).map_err(|_| malformed())?;
    Ok(Answer {
        record,
        text,
        tree: &rest[blank + 2..],
    })
}

/// The answer to a lookup of `module@version` (both in the escaped
/// spelling the lookup URL carries), once the tree head it carries
/// verifies, the record sits below that tree's size, and the record is
/// exactly that version's two go.sum lines; and the tree. Anything
/// else in a validly signed answer is refused like a bad signature: the
/// record number would otherwise date a version it was never given for.
pub fn verify_lookup<'a>(
    body: &'a [u8],
    module: &str,
    version: &str,
) -> Result<(Answer<'a>, Head), String> {
    let answer = split_lookup(body)?;
    let head = verify_tree(answer.tree)?;
    let size = head.size;
    if answer.record >= size {
        return Err(format!(
            "the lookup answer's record {} is not in the tree of {size} it carries",
            answer.record
        ));
    }
    check_record(answer.text, module, version)?;
    Ok((answer, head))
}

/// A lookup record for `module@version`: exactly the lines
/// `<module> <version> h1:<hash>` and `<module> <version>/go.mod h1:<hash>`,
/// in that order, each hash 32 bytes of padded standard base64, the module
/// and version spelled as Go spells them before escaping.
fn check_record(text: &str, module: &str, version: &str) -> Result<(), String> {
    let lines: Vec<&str> = text.lines().collect();
    let refused = |why: String| format!("the lookup answer for {module}@{version} {why}");
    let [zip, go_mod] = lines.as_slice() else {
        return Err(refused(format!(
            "holds {} record lines, not the version's two",
            lines.len()
        )));
    };
    for (line, suffix) in [(zip, ""), (go_mod, "/go.mod")] {
        let words: Vec<&str> = line.split(' ').collect();
        let [named_module, named_version, hash] = words.as_slice() else {
            return Err(refused(format!("has the malformed line {line:?}")));
        };
        let escape = |word: &str| crate::tailors::go::escape_go_path(word).ok();
        let named = named_version
            .strip_suffix(suffix)
            .filter(|_| !suffix.is_empty() || !named_version.ends_with("/go.mod"));
        if escape(named_module).as_deref() != Some(module)
            || named.and_then(escape).as_deref() != Some(version)
        {
            return Err(refused(format!("names another version: {line:?}")));
        }
        let hash_ok = hash
            .strip_prefix("h1:")
            .and_then(crate::kernel::base64::decode_padded)
            .is_some_and(|hash| hash.len() == 32);
        if !hash_ok {
            return Err(refused(format!("has no h1: hash in {line:?}")));
        }
    }
    Ok(())
}

/// The checksum database as a log, with the seed checkpoint the binary
/// carries (dropped, should it not verify).
pub fn log() -> Log {
    Log {
        name: super::registry::SUMDB_NAME,
        seed: seed(SEED),
    }
}

fn seed(text: &str) -> Option<Checkpoint> {
    let (first, note) = text.split_once('\n')?;
    let observed = first.strip_prefix("observed ")?.parse().ok()?;
    let head = verify_tree(note.as_bytes()).ok()?;
    Some(Checkpoint::new(head, observed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = "github.com/google/uuid";
    const VERSION: &str = "v1.6.0";
    const UUID: &[u8] = include_bytes!(
        "../../../tests/fixtures/proxy/registry/go/sum.golang.org/lookup/github.com/google/uuid@v1.6.0.body"
    );

    /// `tools/sumdb_seed.py` runs this after it writes the seed, and keeps
    /// the seed only when it passes.
    #[test]
    fn the_seed_verifies() {
        let seed = seed(SEED).expect("src/tailors/go/sumdb-seed.txt verifies");
        let size: u64 = SEED.lines().nth(2).unwrap().parse().unwrap();
        assert_eq!(seed.size, size);
        assert!(seed.observed > 1_760_000_000, "{seed:?}");
        assert_eq!(log().seed, Some(seed));
    }

    #[test]
    fn the_verifier_key_is_sum_golang_orgs() {
        let verifier = verifier().unwrap();
        assert_eq!(verifier.name, "sum.golang.org");
        assert_eq!(verifier.hash, [0x03, 0x3d, 0xe0, 0xae]);
    }

    #[test]
    fn a_recorded_lookup_verifies_and_names_its_record() {
        let (answer, head) = verify_lookup(UUID, MODULE, VERSION).unwrap();
        let size = head.size;
        assert_eq!(
            crate::kernel::base64::encode(&head.root),
            "mjjTG8zqUwpbOnYRsjT2HvgQnf1VWnISago9r8LcR1k="
        );
        assert_eq!(answer.record, 22_152_757);
        assert_eq!(size, 64_828_441);
        assert!(answer.text.starts_with("github.com/google/uuid v1.6.0 h1:"));
    }

    #[test]
    fn a_changed_head_or_signature_is_refused() {
        let text = std::str::from_utf8(UUID).unwrap();
        // The size changed: the signature no longer covers the text.
        let grown = text.replace("64828441", "94828441");
        let error = verify_lookup(grown.as_bytes(), MODULE, VERSION).unwrap_err();
        assert!(error.contains("does not verify"), "{error}");
        // One signature byte changed.
        let signature = text.rsplit_once(' ').unwrap().1;
        let mut bytes = crate::kernel::base64::decode(signature.trim_end()).unwrap();
        bytes[10] ^= 1;
        let forged = text.replace(signature.trim_end(), &crate::kernel::base64::encode(&bytes));
        let error = verify_lookup(forged.as_bytes(), MODULE, VERSION).unwrap_err();
        assert!(error.contains("does not verify"), "{error}");
        // Another signer only.
        let other = text.replace("— sum.golang.org ", "— sum.example.org ");
        let error = verify_lookup(other.as_bytes(), MODULE, VERSION).unwrap_err();
        assert!(error.contains("not signed by sum.golang.org"), "{error}");
        // A record past the tree's size.
        let late = text.replacen("22152757", "64828441", 1);
        let error = verify_lookup(late.as_bytes(), MODULE, VERSION).unwrap_err();
        assert!(error.contains("not in the tree"), "{error}");
        for broken in [
            "",
            "22152757\n",
            "x\nmod v1 h1:a=\n\nnote",
            "022152757\na\n\nb",
        ] {
            assert!(
                verify_lookup(broken.as_bytes(), MODULE, VERSION).is_err(),
                "{broken:?}"
            );
        }
        assert!(verify_tree(b"go.sum database tree\n1\nAA==\n\n").is_err());
    }

    /// The record checks run on what a validly signed answer says, so the
    /// record text is checked on its own here; the signature covers only
    /// the tree head.
    #[test]
    fn a_lookup_record_must_be_exactly_the_versions_two_lines() {
        let text = std::str::from_utf8(UUID).unwrap();
        let (record, _) = text.split_once("\n\n").unwrap();
        let record = record.split_once('\n').unwrap().1.to_string() + "\n";
        assert_eq!(check_record(&record, MODULE, VERSION), Ok(()));
        // The same answer, fetched for another version or module.
        let error = check_record(&record, MODULE, "v1.5.0").unwrap_err();
        assert!(error.contains("names another version"), "{error}");
        let error = check_record(&record, "github.com/google/other", VERSION).unwrap_err();
        assert!(error.contains("names another version"), "{error}");
        // The escaped spelling of an uppercase module matches its record.
        let azure = "github.com/Azure/x v1.0.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=\n\
                     github.com/Azure/x v1.0.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n";
        assert_eq!(check_record(azure, "github.com/!azure/x", "v1.0.0"), Ok(()));
        let error = check_record(azure, "github.com/azure/x", "v1.0.0").unwrap_err();
        assert!(error.contains("names another version"), "{error}");
        let zip = record.lines().next().unwrap();
        let go_mod = record.lines().nth(1).unwrap();
        for (broken, why) in [
            // A missing h1, a malformed hash, an unknown hash kind.
            (record.replacen(" h1:", " ", 1), "no h1: hash"),
            (record.replacen("F0=", "F0", 1), "no h1: hash"),
            (record.replacen(" h1:", " h2:", 1), "no h1: hash"),
            // An extra line, of this version or another.
            (format!("{record}{zip}\n"), "record lines"),
            (
                format!("{record}golang.org/x/text v0.1.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=\n"),
                "record lines",
            ),
            // One line missing, or the two in the other order.
            (format!("{zip}\n"), "record lines"),
            (format!("{go_mod}\n{zip}\n"), "names another version"),
            // A trailing word.
            (record.replacen("F0=", "F0= extra", 1), "malformed line"),
        ] {
            let error = check_record(&broken, MODULE, VERSION).unwrap_err();
            assert!(error.contains(why), "{broken:?}: {error}");
        }
    }

    #[test]
    fn notes_and_trees_read_as_go_reads_them() {
        let text = std::str::from_utf8(UUID).unwrap();
        let (_, note) = text.split_once("\n\n").unwrap();
        let line = note.lines().last().unwrap();
        let encoded = line.rsplit_once(' ').unwrap().1;
        // A repeat of sum.golang.org's line is dropped unchecked, as Go
        // drops it, even when its signature is bad.
        let mut bytes = crate::kernel::base64::decode(encoded).unwrap();
        bytes[10] ^= 1;
        let bad = crate::kernel::base64::encode(&bytes);
        let repeated = format!("{note}\u{2014} sum.golang.org {bad}\n");
        assert_eq!(
            verify_tree(repeated.as_bytes()).map(|head| head.size),
            Ok(64_828_441)
        );
        // A bad first line is not rescued by a good repeat.
        let first_bad = note.replace(encoded, &bad) + line + "\n";
        assert!(verify_tree(first_bad.as_bytes()).is_err());
        // Signatures are padded base64.
        let unpadded = note.replace(encoded, encoded.trim_end_matches('='));
        assert!(verify_tree(unpadded.as_bytes()).is_err());
        // ParseTree ignores lines after the hash, and reads the size as
        // ParseInt does.
        let hash = "mjjTG8zqUwpbOnYRsjT2HvgQnf1VWnISago9r8LcR1k=";
        let tree = |rest: &str| tree_size(&format!("{TREE_TEXT}{rest}")).map(|head| head.size);
        assert_eq!(tree(&format!("5\n{hash}\n")), Ok(5));
        assert_eq!(tree(&format!("5\n{hash}\nlater\nlines\n")), Ok(5));
        assert_eq!(tree(&format!("007\n{hash}\n")), Ok(7));
        assert_eq!(tree(&format!("+7\n{hash}\n")), Ok(7));
        for broken in [
            format!("-1\n{hash}\n"),
            format!("x\n{hash}\n"),
            format!("5\n{}\n", hash.trim_end_matches('=')),
            "5\nAA==\n".to_string(),
            format!("5\n{hash}"),
        ] {
            assert!(tree(&broken).is_err(), "{broken:?}");
        }
    }
}
