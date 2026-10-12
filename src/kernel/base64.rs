//! The crate's one base64 codec (RFC 4648, standard alphabet). Store paths,
//! SRI values and test auth headers all go through here, so the alphabet and
//! the padding rules cannot drift between copies.

/// Minimal RFC 4648 standard-alphabet base64 encoder (with padding).
/// The single encoder the crate uses: store paths, SRI values, and test
/// auth headers all encode through here so the alphabet cannot drift.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let acc = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(acc >> 18) as usize & 63] as char);
        out.push(ALPHABET[(acc >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(acc >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[acc as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// RFC 4648 base64 (standard alphabet) with padding optional: registries
/// publish SRI values in both forms. Only the canonical spelling of each
/// byte string decodes: padding, when present, is exactly what `encode`
/// writes (one `=` or two, to a multiple of four), and the bits a short
/// final group leaves over are zero. So two different texts never decode to
/// the same bytes ("Zh" is refused where "Zg" is `f`), and a caller may
/// compare encoded text as safely as decoded bytes.
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let body = s.trim_end_matches('=');
    let padding = s.len() - body.len();
    if padding > 0 && (padding > 2 || !s.len().is_multiple_of(4)) {
        return None;
    }
    let s = body.as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let n = chunk.len();
        // The bits below the last whole byte must be zero: two characters
        // carry one byte and four spare bits, three carry two and two.
        let spare = match n {
            1 => return None,
            2 => acc & 0xffff,
            3 => acc & 0xff,
            _ => 0,
        };
        if spare != 0 {
            return None;
        }
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Strict base64 for bytes ward wrote itself (stored path bytes): the input
/// must be padded to a multiple of four, with padding only at the end.
pub(crate) fn decode_padded(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(4) {
        return None;
    }
    let body = value
        .strip_suffix("==")
        .or_else(|| value.strip_suffix('='))
        .unwrap_or(value);
    if body.contains('=') {
        return None;
    }
    decode(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_optional_for_decode_and_required_for_decode_padded() {
        for (bytes, padded) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"\xff\xfe\x00", "//4A"),
        ] {
            assert_eq!(encode(bytes), padded);
            assert_eq!(decode(padded).as_deref(), Some(bytes));
            assert_eq!(decode_padded(padded).as_deref(), Some(bytes));
            let unpadded = padded.trim_end_matches('=');
            assert_eq!(decode(unpadded).as_deref(), Some(bytes));
            if unpadded != padded {
                assert_eq!(decode_padded(unpadded), None, "{unpadded}");
            }
        }
        for bad in ["Z", "Zg=A", "Zg==Zg==", "Z===", "Zm9v!"] {
            assert_eq!(decode_padded(bad), None, "{bad}");
        }
        assert_eq!(decode("Z"), None);
    }

    /// One byte string has one spelling: leftover bits must be zero and
    /// padding must be exactly what `encode` writes.
    #[test]
    fn only_the_canonical_spelling_decodes() {
        // "Zh" and "Zm9" carry the same bytes as "Zg" and "Zm8" plus
        // nonzero leftover bits.
        for bad in [
            "Zh", "Zh==", "Zm9=", "Zm9", "Zg===", "Zm8==", "Zg=", "Zm9v=", "Zm9v==",
        ] {
            assert_eq!(decode(bad), None, "{bad}");
            assert_eq!(decode_padded(bad), None, "{bad}");
        }
        for good in ["Zg", "Zg==", "Zm8", "Zm8=", "Zm9v", "//4A"] {
            assert!(decode(good).is_some(), "{good}");
        }
    }
}
