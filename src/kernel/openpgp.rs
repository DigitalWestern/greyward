//! A detached OpenPGP signature check, as far as an upstream that signs
//! with an RSA key needs one: armored v4 public keys (primary and subkeys),
//! an armored v4 binary-document signature, RSA PKCS#1 v1.5 over SHA-256 or
//! SHA-512 (RFC 4880 sections 4, 5.2, 5.5 and 12.2).
//!
//! What it trusts is the keyring it is handed: every key packet in it, the
//! primary key and each subkey, signs. That is how `gpgv --keyring` treats
//! a keyring too, and the keyrings handed here are files checked into the
//! repository and embedded in the binary, so their contents are the trust
//! decision. Nothing else is accepted: another packet version, algorithm,
//! signature class or a signature whose issuer is not in the keyring is
//! refused.

use ring::signature::{RsaParameters, RsaPublicKeyComponents};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512};
use sha1::{Digest as _, Sha1};
use std::io;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// Packet tags this reader knows (RFC 4880 section 4.3).
const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_PUBLIC_SUBKEY: u8 = 14;

/// Public-key algorithm 1: RSA (Encrypt or Sign).
const ALGO_RSA: u8 = 1;
/// Hash algorithms 8 and 10: SHA-256 and SHA-512.
const HASH_SHA256: u8 = 8;
const HASH_SHA512: u8 = 10;
/// Signature class 0x00: a signature of a binary document.
const CLASS_BINARY: u8 = 0x00;
/// Signature subpackets 16 and 33: issuer key ID, issuer fingerprint.
const SUBPACKET_ISSUER: u8 = 16;
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;

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

/// The public keys a signature may come from.
#[derive(Clone, Debug)]
pub struct Keyring {
    keys: Vec<RsaKey>,
}

impl Keyring {
    /// Every v4 RSA key packet (primary and subkey) of an armored public
    /// key block. Packets of other kinds (user IDs, their certifications)
    /// are skipped; a key packet this reader cannot use is refused, so a
    /// keyring never silently loses a key.
    pub fn from_armored(text: &str) -> io::Result<Keyring> {
        let bytes = dearmor(text, "PGP PUBLIC KEY BLOCK")?;
        let mut keys = Vec::new();
        for (tag, body) in packets(&bytes)? {
            if tag != TAG_PUBLIC_KEY && tag != TAG_PUBLIC_SUBKEY {
                continue;
            }
            keys.push(rsa_key(body)?);
        }
        if keys.is_empty() {
            return Err(invalid("the OpenPGP keyring holds no public key"));
        }
        Ok(Keyring { keys })
    }

    /// The upper-case hex v4 fingerprints of every key, primary first.
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
        let key = self
            .keys
            .iter()
            .find(|key| signature.issued_by(key))
            .ok_or_else(|| {
                invalid(format!(
                    "the OpenPGP signature was made by key {}, which is not in the pinned keyring",
                    hex::encode_upper(&signature.issuer)
                ))
            })?;
        let mut message = Vec::with_capacity(data.len() + signature.hashed.len() + 6);
        message.extend_from_slice(data);
        message.extend_from_slice(signature.hashed);
        // The v4 trailer: version, 0xFF, and the hashed portion's length.
        message.extend_from_slice(&[4, 0xff]);
        message.extend_from_slice(&(signature.hashed.len() as u32).to_be_bytes());
        // An MPI drops leading zero bytes; PKCS#1 wants the modulus length.
        let mut padded = vec![0; key.n.len().saturating_sub(signature.value.len())];
        padded.extend_from_slice(signature.value);
        let algorithm: &RsaParameters = match signature.hash {
            HASH_SHA256 => &RSA_PKCS1_2048_8192_SHA256,
            _ => &RSA_PKCS1_2048_8192_SHA512,
        };
        let public = RsaPublicKeyComponents {
            n: &key.n,
            e: &key.e,
        };
        public.verify(algorithm, &message, &padded).map_err(|_| {
            invalid(format!(
                "the OpenPGP signature does not verify with key {}",
                hex::encode_upper(key.fingerprint)
            ))
        })?;
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
    hash: u8,
    /// From the version byte through the hashed subpackets: what the
    /// signature covers after the data.
    hashed: &'a [u8],
    /// The issuer: a key ID (8 bytes) or a v4 fingerprint (20 bytes).
    issuer: Vec<u8>,
    value: &'a [u8],
}

impl<'a> Signature<'a> {
    fn parse(body: &'a [u8]) -> io::Result<Signature<'a>> {
        let [4, class, algo, hash, a, b, rest @ ..] = body else {
            return Err(invalid("only version 4 OpenPGP signatures are supported"));
        };
        if *class != CLASS_BINARY {
            return Err(invalid(format!(
                "OpenPGP signature class {class:#04x} is not a binary-document signature"
            )));
        }
        if *algo != ALGO_RSA {
            return Err(invalid(format!(
                "OpenPGP signature algorithm {algo} is not supported; only RSA is"
            )));
        }
        if *hash != HASH_SHA256 && *hash != HASH_SHA512 {
            return Err(invalid(format!(
                "OpenPGP signature hash algorithm {hash} is not supported; only SHA-256 and SHA-512 are"
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
        for (kind, data) in subpackets(hashed_subpackets)?
            .into_iter()
            .chain(subpackets(unhashed_subpackets)?)
        {
            match (kind, data) {
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
            hash: *hash,
            hashed,
            issuer: issuer.ok_or_else(|| invalid("the OpenPGP signature names no issuer"))?,
            value,
        })
    }

    fn issued_by(&self, key: &RsaKey) -> bool {
        match self.issuer.len() {
            20 => self.issuer == key.fingerprint,
            _ => self.issuer == key.key_id(),
        }
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
    fn the_rust_keyring_is_its_primary_key_and_both_subkeys() {
        let keyring = Keyring::from_armored(RUST_KEY).unwrap();
        assert_eq!(
            keyring.fingerprints()[0],
            "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
        );
        assert_eq!(keyring.fingerprints().len(), 3);
        assert!(keyring.fingerprints()[2].ends_with("5CB4A9347B3B09DC"));
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
                .contains("85AB96E6FA1BE5FE, which is not in"),
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
