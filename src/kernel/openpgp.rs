//! A detached OpenPGP signature check, as far as an upstream that signs
//! with an RSA key needs one: armored v4 public keys (primary and subkeys),
//! an armored v4 binary-document signature, RSA PKCS#1 v1.5 over SHA-256 or
//! SHA-512 (RFC 4880 sections 4, 5.2, 5.5 and 12.2).
//!
//! What it trusts is the keyring it is handed, and in it only the keys its
//! owner certified for signing, as `gpgv --keyring` does. The primary key
//! signs when its newest self-certification of a user ID (verified)
//! carries the sign key flag. A subkey signs when its newest binding
//! signature from the primary (verified) carries the sign flag and embeds
//! the subkey's own back-signature (verified), so an encryption-only
//! subkey never signs, nor does a subkey another party attached. A
//! revocation of the primary key or of a subkey removes it, whether or not
//! its signature can be read. Self-signatures may use SHA-1, as keys made
//! in 2013 do; a document signature must use SHA-256 or SHA-512. Nothing
//! else is accepted: another packet version, algorithm, signature class or
//! a signature whose issuer is not a signing key of the keyring is refused.
//! Key expiry is not read: the keyrings handed here are files checked into
//! the repository, and replacing one is the way to retire a key.

use ring::signature::{RsaParameters, RsaPublicKeyComponents};
use ring::signature::{
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA512,
};
use sha1::{Digest as _, Sha1};
use std::io;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// Packet tags this reader knows (RFC 4880 section 4.3).
const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_USER_ID: u8 = 13;
const TAG_PUBLIC_SUBKEY: u8 = 14;
const TAG_USER_ATTRIBUTE: u8 = 17;

/// Public-key algorithm 1: RSA (Encrypt or Sign).
const ALGO_RSA: u8 = 1;
/// Hash algorithms 2, 8 and 10: SHA-1 (self-signatures only), SHA-256 and
/// SHA-512.
const HASH_SHA1: u8 = 2;
const HASH_SHA256: u8 = 8;
const HASH_SHA512: u8 = 10;
/// Signature classes (RFC 4880 section 5.2.1).
const CLASS_BINARY: u8 = 0x00;
const CLASS_CERTIFICATIONS: std::ops::RangeInclusive<u8> = 0x10..=0x13;
const CLASS_SUBKEY_BINDING: u8 = 0x18;
const CLASS_PRIMARY_BINDING: u8 = 0x19;
const CLASS_KEY_REVOCATION: u8 = 0x20;
const CLASS_SUBKEY_REVOCATION: u8 = 0x28;
/// Signature subpackets: creation time, issuer key ID, key flags, embedded
/// signature, issuer fingerprint.
const SUBPACKET_CREATED: u8 = 2;
const SUBPACKET_ISSUER: u8 = 16;
const SUBPACKET_KEY_FLAGS: u8 = 27;
const SUBPACKET_EMBEDDED_SIGNATURE: u8 = 32;
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;
/// Key flag 0x02: this key may sign data.
const FLAG_SIGN: u8 = 0x02;

/// One RSA public key of a keyring: its v4 fingerprint and its numbers.
#[derive(Clone, Debug)]
struct RsaKey {
    fingerprint: [u8; 20],
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RsaKey {
    fn key_id(&self) -> &[u8] {
        &self.fingerprint[12..]
    }
}

/// The bytes a key packet is hashed as inside a signature: 0x99, the
/// two-byte body length, the body.
fn key_frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x99);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A key packet of a keyring while it is read, with what its signatures
/// have shown so far.
struct Candidate<'a> {
    body: &'a [u8],
    key: RsaKey,
    /// The newest verified self-signature's (creation time, key flags).
    newest: Option<(u32, u8)>,
    revoked: bool,
}

impl<'a> Candidate<'a> {
    fn new(body: &'a [u8]) -> io::Result<Candidate<'a>> {
        Ok(Candidate {
            body,
            key: rsa_key(body)?,
            newest: None,
            revoked: false,
        })
    }

    fn offer(&mut self, signature: &Signature) {
        let flags = signature.key_flags.unwrap_or(0);
        if self
            .newest
            .is_none_or(|(created, _)| signature.created >= created)
        {
            self.newest = Some((signature.created, flags));
        }
    }

    fn signs(&self) -> bool {
        !self.revoked && self.newest.is_some_and(|(_, flags)| flags & FLAG_SIGN != 0)
    }
}

/// Where the reader is in a transferable public key: what the signature
/// packets that follow are about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After<'a> {
    Primary,
    UserId(&'a [u8]),
    Subkey,
    Other,
}

/// The public keys a signature may come from.
#[derive(Clone, Debug)]
pub struct Keyring {
    keys: Vec<RsaKey>,
}

impl Keyring {
    /// The signing keys of an armored public key block (see the module
    /// documentation). A key packet this reader cannot use is refused, so
    /// a keyring never silently loses a key; a signature packet it cannot
    /// read grants nothing and is passed over.
    pub fn from_armored(text: &str) -> io::Result<Keyring> {
        Keyring::from_packets(&dearmor(text, "PGP PUBLIC KEY BLOCK")?)
    }

    fn from_packets(bytes: &[u8]) -> io::Result<Keyring> {
        let mut keys = Vec::new();
        let mut primary: Option<Candidate> = None;
        let mut subkeys: Vec<Candidate> = Vec::new();
        let mut after = After::Other;
        let flush =
            |primary: Option<Candidate>, subkeys: &mut Vec<Candidate>, keys: &mut Vec<RsaKey>| {
                let Some(primary) = primary else { return };
                let usable = !primary.revoked;
                if primary.signs() {
                    keys.push(primary.key);
                }
                keys.extend(
                    subkeys
                        .drain(..)
                        .filter(|subkey| usable && subkey.signs())
                        .map(|subkey| subkey.key),
                );
            };
        for (tag, body) in packets(bytes)? {
            match tag {
                TAG_PUBLIC_KEY => {
                    flush(primary.take(), &mut subkeys, &mut keys);
                    primary = Some(Candidate::new(body)?);
                    after = After::Primary;
                }
                TAG_USER_ID => after = After::UserId(body),
                TAG_USER_ATTRIBUTE => after = After::Other,
                TAG_PUBLIC_SUBKEY => {
                    if primary.is_none() {
                        return Err(invalid("OpenPGP subkey packet precedes its primary key"));
                    }
                    subkeys.push(Candidate::new(body)?);
                    after = After::Subkey;
                }
                TAG_SIGNATURE => {
                    let Some(primary) = primary.as_mut() else {
                        continue;
                    };
                    // A revocation counts unread: refusing a key is safe.
                    match body.get(1).copied() {
                        Some(CLASS_KEY_REVOCATION) => {
                            primary.revoked = true;
                            continue;
                        }
                        Some(CLASS_SUBKEY_REVOCATION) if after == After::Subkey => {
                            if let Some(subkey) = subkeys.last_mut() {
                                subkey.revoked = true;
                            }
                            continue;
                        }
                        _ => {}
                    }
                    let Ok(signature) = Signature::parse(body) else {
                        continue;
                    };
                    match after {
                        After::UserId(user_id)
                            if CLASS_CERTIFICATIONS.contains(&signature.class) =>
                        {
                            let mut prefix = key_frame(primary.body);
                            prefix.push(0xb4);
                            prefix.extend_from_slice(&(user_id.len() as u32).to_be_bytes());
                            prefix.extend_from_slice(user_id);
                            if signature.verifies(&primary.key, &prefix) {
                                primary.offer(&signature);
                            }
                        }
                        After::Subkey if signature.class == CLASS_SUBKEY_BINDING => {
                            let subkey = subkeys.last_mut().expect("a subkey was read");
                            let mut prefix = key_frame(primary.body);
                            prefix.extend_from_slice(&key_frame(subkey.body));
                            if !signature.verifies(&primary.key, &prefix) {
                                continue;
                            }
                            // A signing subkey must also sign the primary
                            // back: without that, anyone's key could be
                            // bound as a signer of this one's.
                            let signs = signature.key_flags.unwrap_or(0) & FLAG_SIGN != 0;
                            let backed = signature
                                .embedded
                                .and_then(|bytes| Signature::parse(bytes).ok())
                                .is_some_and(|back| {
                                    back.class == CLASS_PRIMARY_BINDING
                                        && back.verifies(&subkey.key, &prefix)
                                });
                            if !signs || backed {
                                subkey.offer(&signature);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        flush(primary.take(), &mut subkeys, &mut keys);
        if keys.is_empty() {
            return Err(invalid("the OpenPGP keyring holds no signing key"));
        }
        Ok(Keyring { keys })
    }

    /// The upper-case hex v4 fingerprints of every signing key, primary
    /// first.
    #[cfg(test)]
    pub fn fingerprints(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|key| hex::encode_upper(key.fingerprint))
            .collect()
    }

    /// Check an armored detached signature over `data`. Answers the
    /// fingerprint of the key that made it.
    pub fn verify_detached(&self, data: &[u8], armored: &str) -> io::Result<String> {
        let bytes = dearmor(armored, "PGP SIGNATURE")?;
        let packets = packets(&bytes)?;
        let [(TAG_SIGNATURE, body)] = packets.as_slice() else {
            return Err(invalid(
                "a detached OpenPGP signature must be exactly one signature packet",
            ));
        };
        let signature = Signature::parse(body)?;
        if signature.class != CLASS_BINARY {
            return Err(invalid(format!(
                "OpenPGP signature class {:#04x} is not a binary-document signature",
                signature.class
            )));
        }
        if signature.hash != HASH_SHA256 && signature.hash != HASH_SHA512 {
            return Err(invalid(format!(
                "OpenPGP signature hash algorithm {} is not supported; only SHA-256 and SHA-512 are",
                signature.hash
            )));
        }
        let issuer = signature
            .issuer
            .as_deref()
            .ok_or_else(|| invalid("the OpenPGP signature names no issuer"))?;
        let key = self
            .keys
            .iter()
            .find(|key| signature.issued_by(key))
            .ok_or_else(|| {
                invalid(format!(
                    "the OpenPGP signature was made by key {}, which is not a signing key of the pinned keyring",
                    hex::encode_upper(issuer)
                ))
            })?;
        if !signature.verifies(key, data) {
            return Err(invalid(format!(
                "the OpenPGP signature does not verify with key {}",
                hex::encode_upper(key.fingerprint)
            )));
        }
        Ok(hex::encode_upper(key.fingerprint))
    }
}

/// The binary packets inside one ASCII-armored block of `kind`: the lines
/// after the header block's blank line, up to the CRC line or the footer.
fn dearmor(text: &str, kind: &str) -> io::Result<Vec<u8>> {
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let mut lines = text.lines().map(str::trim_end);
    if !lines.any(|line| line == begin) {
        return Err(invalid(format!("not an armored OpenPGP block: no {begin}")));
    }
    // Armor headers (`Version: ...`) run to the first blank line.
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
    }
    let mut body = String::new();
    let mut ended = false;
    for line in lines {
        if line == end {
            ended = true;
            break;
        }
        if line.starts_with('=') {
            // The CRC-24 line: the signature or key check below is what
            // proves the bytes, so it is not recomputed.
            continue;
        }
        body.push_str(line);
    }
    if !ended {
        return Err(invalid(format!("armored OpenPGP block has no {end}")));
    }
    crate::kernel::base64::decode(&body)
        .ok_or_else(|| invalid("armored OpenPGP block is not base64"))
}

/// Split binary OpenPGP data into (tag, body) packets. Both header formats
/// are read; partial and indeterminate lengths are refused, since none of
/// the packets read here uses them.
fn packets(mut bytes: &[u8]) -> io::Result<Vec<(u8, &[u8])>> {
    let truncated = || invalid("OpenPGP packet is truncated");
    let mut out = Vec::new();
    while let Some((&header, rest)) = bytes.split_first() {
        if header & 0x80 == 0 {
            return Err(invalid("OpenPGP packet header lacks its marker bit"));
        }
        let (tag, length, rest) = if header & 0x40 != 0 {
            let tag = header & 0x3f;
            let (&first, rest) = rest.split_first().ok_or_else(truncated)?;
            match first {
                0..=191 => (tag, first as usize, rest),
                192..=223 => {
                    let (&second, rest) = rest.split_first().ok_or_else(truncated)?;
                    (
                        tag,
                        ((first as usize - 192) << 8) + second as usize + 192,
                        rest,
                    )
                }
                255 => {
                    let (len, rest) = rest.split_at_checked(4).ok_or_else(truncated)?;
                    (
                        tag,
                        u32::from_be_bytes(len.try_into().unwrap()) as usize,
                        rest,
                    )
                }
                _ => return Err(invalid("OpenPGP partial body lengths are not supported")),
            }
        } else {
            let tag = (header >> 2) & 0x0f;
            let width = match header & 0x03 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(invalid("OpenPGP indeterminate lengths are not supported")),
            };
            let (len, rest) = rest.split_at_checked(width).ok_or_else(truncated)?;
            let length = len.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (tag, length, rest)
        };
        let (body, rest) = rest.split_at_checked(length).ok_or_else(truncated)?;
        out.push((tag, body));
        bytes = rest;
    }
    Ok(out)
}

/// One multiprecision integer: a two-byte bit count, then the bytes.
fn mpi(bytes: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let (bits, rest) = bytes
        .split_at_checked(2)
        .ok_or_else(|| invalid("OpenPGP MPI is truncated"))?;
    let bits = u16::from_be_bytes([bits[0], bits[1]]) as usize;
    rest.split_at_checked(bits.div_ceil(8))
        .ok_or_else(|| invalid("OpenPGP MPI is truncated"))
}

/// A v4 RSA public key packet body, with its fingerprint: SHA-1 over 0x99,
/// the two-byte body length and the body.
fn rsa_key(body: &[u8]) -> io::Result<RsaKey> {
    let [4, _, _, _, _, algo, numbers @ ..] = body else {
        return Err(invalid("only version 4 OpenPGP keys are supported"));
    };
    if *algo != ALGO_RSA {
        return Err(invalid(format!(
            "OpenPGP key algorithm {algo} is not supported; only RSA is"
        )));
    }
    let (n, rest) = mpi(numbers)?;
    let (e, _) = mpi(rest)?;
    let length = u16::try_from(body.len()).map_err(|_| invalid("OpenPGP key packet too long"))?;
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(length.to_be_bytes());
    hasher.update(body);
    Ok(RsaKey {
        fingerprint: hasher.finalize().into(),
        n: n.to_vec(),
        e: e.to_vec(),
    })
}

/// The parts of a v4 signature packet the check reads.
struct Signature<'a> {
    class: u8,
    hash: u8,
    /// From the version byte through the hashed subpackets: what the
    /// signature covers after the data.
    hashed: &'a [u8],
    /// The issuer: a key ID (8 bytes) or a v4 fingerprint (20 bytes).
    issuer: Option<Vec<u8>>,
    /// The hashed creation time (0 when absent).
    created: u32,
    /// The hashed key flags' first byte, on a self-signature.
    key_flags: Option<u8>,
    /// An embedded signature (a signing subkey's back-signature).
    embedded: Option<&'a [u8]>,
    value: &'a [u8],
}

impl<'a> Signature<'a> {
    fn parse(body: &'a [u8]) -> io::Result<Signature<'a>> {
        let [4, class, algo, hash, a, b, rest @ ..] = body else {
            return Err(invalid("only version 4 OpenPGP signatures are supported"));
        };
        if *algo != ALGO_RSA {
            return Err(invalid(format!(
                "OpenPGP signature algorithm {algo} is not supported; only RSA is"
            )));
        }
        if ![HASH_SHA1, HASH_SHA256, HASH_SHA512].contains(hash) {
            return Err(invalid(format!(
                "OpenPGP signature hash algorithm {hash} is not supported"
            )));
        }
        let truncated = || invalid("OpenPGP signature packet is truncated");
        let hashed_len = u16::from_be_bytes([*a, *b]) as usize;
        let (hashed_subpackets, rest) = rest.split_at_checked(hashed_len).ok_or_else(truncated)?;
        let hashed = &body[..6 + hashed_len];
        let (len, rest) = rest.split_at_checked(2).ok_or_else(truncated)?;
        let unhashed_len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let (unhashed_subpackets, rest) =
            rest.split_at_checked(unhashed_len).ok_or_else(truncated)?;
        // Two bytes of the digest, a quick-reject hint the check below makes
        // redundant.
        let (_, rest) = rest.split_at_checked(2).ok_or_else(truncated)?;
        let (value, _) = mpi(rest)?;
        // The issuer may sit in either area: it only names a key, and the
        // RSA check proves the key.
        let mut issuer = None;
        let mut created = 0;
        let mut key_flags = None;
        let mut embedded = None;
        // Creation time and key flags count only when signed.
        for (kind, data) in subpackets(hashed_subpackets)? {
            match (kind, data) {
                (SUBPACKET_CREATED, [a, b, c, d]) => created = u32::from_be_bytes([*a, *b, *c, *d]),
                (SUBPACKET_KEY_FLAGS, [flags, ..]) => key_flags = Some(*flags),
                _ => {}
            }
        }
        // The embedded back-signature proves itself, so it may sit in
        // either area, as gpg allows.
        for (kind, data) in subpackets(hashed_subpackets)?
            .into_iter()
            .chain(subpackets(unhashed_subpackets)?)
        {
            match (kind, data) {
                (SUBPACKET_EMBEDDED_SIGNATURE, data) if embedded.is_none() => {
                    embedded = Some(data);
                }
                (SUBPACKET_ISSUER_FINGERPRINT, [4, fingerprint @ ..])
                    if fingerprint.len() == 20 =>
                {
                    issuer = Some(fingerprint.to_vec());
                }
                (SUBPACKET_ISSUER, id) if id.len() == 8 && issuer.is_none() => {
                    issuer = Some(id.to_vec());
                }
                _ => {}
            }
        }
        Ok(Signature {
            class: *class,
            hash: *hash,
            hashed,
            issuer,
            created,
            key_flags,
            embedded,
            value,
        })
    }

    fn issued_by(&self, key: &RsaKey) -> bool {
        match self.issuer.as_deref() {
            Some(issuer) if issuer.len() == 20 => issuer == key.fingerprint,
            Some(issuer) => issuer == key.key_id(),
            None => false,
        }
    }

    /// Whether `key` made this signature over `data` (the document, or a
    /// self-signature's key and user ID frames).
    fn verifies(&self, key: &RsaKey, data: &[u8]) -> bool {
        let mut message = Vec::with_capacity(data.len() + self.hashed.len() + 6);
        message.extend_from_slice(data);
        message.extend_from_slice(self.hashed);
        // The v4 trailer: version, 0xFF, and the hashed portion's length.
        message.extend_from_slice(&[4, 0xff]);
        message.extend_from_slice(&(self.hashed.len() as u32).to_be_bytes());
        // An MPI drops leading zero bytes; PKCS#1 wants the modulus length.
        let mut padded = vec![0; key.n.len().saturating_sub(self.value.len())];
        padded.extend_from_slice(self.value);
        let algorithm: &RsaParameters = match self.hash {
            HASH_SHA1 => &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            HASH_SHA256 => &RSA_PKCS1_2048_8192_SHA256,
            _ => &RSA_PKCS1_2048_8192_SHA512,
        };
        RsaPublicKeyComponents {
            n: &key.n,
            e: &key.e,
        }
        .verify(algorithm, &message, &padded)
        .is_ok()
    }
}

/// Signature subpackets as (type without the critical bit, data).
fn subpackets(mut bytes: &[u8]) -> io::Result<Vec<(u8, &[u8])>> {
    let truncated = || invalid("OpenPGP signature subpacket is truncated");
    let mut out = Vec::new();
    while let Some((&first, rest)) = bytes.split_first() {
        let (length, rest) = match first {
            0..=191 => (first as usize, rest),
            192..=254 => {
                let (&second, rest) = rest.split_first().ok_or_else(truncated)?;
                (((first as usize - 192) << 8) + second as usize + 192, rest)
            }
            255 => {
                let (len, rest) = rest.split_at_checked(4).ok_or_else(truncated)?;
                (u32::from_be_bytes(len.try_into().unwrap()) as usize, rest)
            }
        };
        let (packet, rest) = rest.split_at_checked(length).ok_or_else(truncated)?;
        let [kind, data @ ..] = packet else {
            return Err(invalid("OpenPGP signature subpacket is empty"));
        };
        out.push((kind & 0x7f, data));
        bytes = rest;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    const RUST_KEY: &str = include_str!("../../tools/keys/rust-release-signing-key.asc");
    const MANIFEST_XZ: &[u8] = include_bytes!("../../tools/keys/channel-rust-1.96.1.toml.xz");
    const MANIFEST_ASC: &str = include_str!("../../tools/keys/channel-rust-1.96.1.toml.asc");

    fn manifest() -> Vec<u8> {
        let mut out = Vec::new();
        liblzma::read::XzDecoder::new(MANIFEST_XZ)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn the_rust_keyring_signs_with_its_primary_key_and_its_signing_subkey_only() {
        // Its first subkey, 8E9AA3F7AB3F5826, is bound for encryption only
        // (key flags 0x0C), and gpgv will not take a signature from it.
        let keyring = Keyring::from_armored(RUST_KEY).unwrap();
        let fingerprints = keyring.fingerprints();
        assert_eq!(fingerprints.len(), 2, "{fingerprints:?}");
        assert_eq!(fingerprints[0], "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE");
        assert!(fingerprints[1].ends_with("5CB4A9347B3B09DC"));
        assert!(!fingerprints
            .iter()
            .any(|fingerprint| fingerprint.ends_with("8E9AA3F7AB3F5826")));
    }

    // A generated keyring (testdata/openpgp/make_fixture.py): a primary key
    // certified to sign, an encryption-only subkey and a signing subkey
    // with its back-signature, each having signed one document. gpgv takes
    // the primary's and the signing subkey's signatures and has no public
    // key for the encryption-only one's.
    const FIXTURE_KEYRING: &str = include_str!("testdata/openpgp/keyring.asc");
    const FIXTURE_DOCUMENT: &[u8] = include_bytes!("testdata/openpgp/document.txt");
    const BY_PRIMARY: &str = include_str!("testdata/openpgp/by-primary.asc");
    const BY_SIGNING_SUBKEY: &str = include_str!("testdata/openpgp/by-signing-subkey.asc");
    const BY_ENCRYPT_ONLY: &str = include_str!("testdata/openpgp/by-encrypt-only.asc");
    const FIXTURE_PRIMARY: &str = "340A0550CD93D89CAEF838052D42F4455D5F5D31";
    const FIXTURE_SIGNING: &str = "520C6B0CBBCB71F340CE6975F46A975FF0519798";

    #[test]
    fn the_primary_key_and_a_signing_subkey_sign() {
        let keyring = Keyring::from_armored(FIXTURE_KEYRING).unwrap();
        assert_eq!(
            keyring.fingerprints(),
            vec![FIXTURE_PRIMARY.to_string(), FIXTURE_SIGNING.to_string()]
        );
        assert_eq!(
            keyring
                .verify_detached(FIXTURE_DOCUMENT, BY_PRIMARY)
                .unwrap(),
            FIXTURE_PRIMARY
        );
        assert_eq!(
            keyring
                .verify_detached(FIXTURE_DOCUMENT, BY_SIGNING_SUBKEY)
                .unwrap(),
            FIXTURE_SIGNING
        );
    }

    #[test]
    fn a_signature_by_an_encryption_only_subkey_is_refused() {
        let keyring = Keyring::from_armored(FIXTURE_KEYRING).unwrap();
        let error = keyring
            .verify_detached(FIXTURE_DOCUMENT, BY_ENCRYPT_ONLY)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("1217D17ACD1336BE6411B676FBC211CB3589FB43, which is not a signing key"),
            "{error}"
        );
    }

    /// The fixture keyring's packets, with `edit` applied.
    fn edited_keyring(edit: impl FnOnce(&mut Vec<(u8, Vec<u8>)>)) -> io::Result<Keyring> {
        let bytes = dearmor(FIXTURE_KEYRING, "PGP PUBLIC KEY BLOCK").unwrap();
        let mut list: Vec<(u8, Vec<u8>)> = packets(&bytes)
            .unwrap()
            .into_iter()
            .map(|(tag, body)| (tag, body.to_vec()))
            .collect();
        edit(&mut list);
        let mut out = Vec::new();
        for (tag, body) in list {
            out.push(0xc0 | tag);
            out.push(0xff);
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(&body);
        }
        Keyring::from_packets(&out)
    }

    #[test]
    fn a_signing_subkey_without_a_valid_binding_does_not_sign() {
        // The signing subkey's binding is the last packet. A changed byte
        // in its signed part breaks the primary's signature over it.
        let keyring = edited_keyring(|list| {
            let (_, binding) = list.last_mut().unwrap();
            binding[8] ^= 1;
        })
        .unwrap();
        assert_eq!(keyring.fingerprints(), vec![FIXTURE_PRIMARY.to_string()]);
        // A binding with no back-signature: the embedded signature is in
        // the unhashed area, so dropping that area leaves the primary's
        // signature valid and the subkey's consent missing.
        let keyring = edited_keyring(|list| {
            let (_, binding) = list.last_mut().unwrap();
            let hashed = u16::from_be_bytes([binding[4], binding[5]]) as usize;
            let at = 6 + hashed;
            let unhashed = u16::from_be_bytes([binding[at], binding[at + 1]]) as usize;
            binding.splice(at..at + 2 + unhashed, [0, 0]);
        })
        .unwrap();
        assert_eq!(keyring.fingerprints(), vec![FIXTURE_PRIMARY.to_string()]);
    }

    #[test]
    fn a_revocation_removes_the_key_it_names() {
        // A subkey revocation after the signing subkey, unreadable: it is
        // honoured anyway.
        let keyring = edited_keyring(|list| {
            list.push((TAG_SIGNATURE, vec![4, CLASS_SUBKEY_REVOCATION]));
        })
        .unwrap();
        assert_eq!(keyring.fingerprints(), vec![FIXTURE_PRIMARY.to_string()]);
        // A key revocation takes the primary and every subkey with it.
        let error = edited_keyring(|list| {
            list.insert(1, (TAG_SIGNATURE, vec![4, CLASS_KEY_REVOCATION]));
        })
        .unwrap_err();
        assert!(error.to_string().contains("no signing key"), "{error}");
    }

    #[test]
    fn a_published_rust_manifest_verifies() {
        let keyring = Keyring::from_armored(RUST_KEY).unwrap();
        assert_eq!(
            keyring.verify_detached(&manifest(), MANIFEST_ASC).unwrap(),
            "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
        );
    }

    #[test]
    fn one_changed_byte_fails() {
        let keyring = Keyring::from_armored(RUST_KEY).unwrap();
        let mut data = manifest();
        let middle = data.len() / 2;
        data[middle] ^= 1;
        let error = keyring.verify_detached(&data, MANIFEST_ASC).unwrap_err();
        assert!(error.to_string().contains("does not verify"), "{error}");
    }

    #[test]
    fn a_signature_from_a_key_outside_the_keyring_is_refused() {
        // The same keyring without the primary key, the one that signed.
        let mut keyring = Keyring::from_armored(RUST_KEY).unwrap();
        keyring.keys.remove(0);
        let error = keyring
            .verify_detached(&manifest(), MANIFEST_ASC)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("85AB96E6FA1BE5FE, which is not a signing key"),
            "{error}"
        );
    }

    #[test]
    fn what_is_not_one_armored_signature_is_refused() {
        let keyring = Keyring::from_armored(RUST_KEY).unwrap();
        for text in [
            "",
            "not armor",
            "-----BEGIN PGP SIGNATURE-----\n\n!!!!\n-----END PGP SIGNATURE-----\n",
            "-----BEGIN PGP SIGNATURE-----\n\nwsFc\n",
            RUST_KEY,
        ] {
            assert!(
                keyring.verify_detached(&manifest(), text).is_err(),
                "{text}"
            );
        }
    }

    #[test]
    fn both_length_forms_and_both_header_formats_read() {
        // New format, one-octet length; old format, two-octet length.
        let new = [0xc0 | TAG_SIGNATURE, 2, 0xaa, 0xbb];
        let old = [0x80 | (TAG_PUBLIC_KEY << 2) | 1, 0, 1, 0xcc];
        assert_eq!(
            packets(&new).unwrap(),
            vec![(TAG_SIGNATURE, &[0xaa, 0xbb][..])]
        );
        assert_eq!(packets(&old).unwrap(), vec![(TAG_PUBLIC_KEY, &[0xcc][..])]);
        assert!(packets(&[0xc2, 5, 0]).is_err());
        assert!(packets(&[0x02]).is_err());
    }
}
