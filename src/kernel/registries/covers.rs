//! The one prefix test every registry check asks: does this root (a
//! registry's root, or a `files` origin) cover this URL?
//!
//! Routing, the sync checks, ward's own fetches, every redirect hop and
//! closure attribution all call [`covers`], so they cannot disagree about
//! which registry a URL belongs to. It works on the raw spelling, before
//! any parsing: the `url` crate removes dot segments and turns `\` into `/`
//! while parsing, which would hide exactly the spellings this test refuses.
//! A `%2f` is a separator for the dot and empty checks, so npm's
//! `@scope%2fname` passes while `@s%2f..%2f..%2fother` does not, whether or
//! not the server decodes `%2f`. There is no per-ecosystem exception.

use url::Url;

/// Whether `root` (`https://host[:port]/path/`, already validated) covers
/// `url`, as spelled. Query and fragment are ignored for the path test; the
/// URL must also re-serialize to the same path ([`same_path_after_parse`]).
pub fn covers(root: &str, url: &str) -> bool {
    let Some((root_authority, root_path)) = split(root) else {
        return false;
    };
    let Some((authority, path)) = split(url) else {
        return false;
    };
    if !same_authority(root_authority, authority) {
        return false;
    }
    let path = path.split(['?', '#']).next().unwrap_or("");
    if !path_is_clean(path) || !same_path_after_parse(url) {
        return false;
    }
    let root_path = root_path.trim_end_matches('/');
    root_path.is_empty() || path == root_path || path.starts_with(&format!("{root_path}/"))
}

/// The length of the root's path, for choosing the longest root that covers
/// a URL.
pub fn root_len(root: &str) -> usize {
    split(root).map_or(0, |(_, path)| path.trim_end_matches('/').len())
}

/// Split `https://authority/path` into its authority and path (the path
/// keeps its leading `/`, empty when there is none).
fn split(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let path = if path.starts_with('/') { path } else { "" };
    Some((authority, path))
}

/// Host compared case-insensitively, `:443` the same as no port.
fn same_authority(a: &str, b: &str) -> bool {
    normalize_authority(a) == normalize_authority(b)
}

fn normalize_authority(authority: &str) -> String {
    let lower = authority.to_ascii_lowercase();
    match lower.strip_suffix(":443") {
        Some(host) => host.to_string(),
        None => lower,
    }
}

/// Every piece between `/` or `%2f` separators is non-empty (after the
/// leading `/`), neither `.` nor `..`, holds no backslash or `;` (a Java
/// server drops a `;` path parameter before it normalizes, so `..;` would
/// climb), and carries no escape that decodes to `\`, `.`, `%` or `;`.
/// Escapes must be well formed.
pub(crate) fn path_is_clean(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    // A trailing `/` ends a directory URL (a simple index page), so the last
    // piece may be empty; every other piece may not.
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    for piece in pieces(rest) {
        if piece.is_empty()
            || piece == "."
            || piece == ".."
            || piece.contains('\\')
            || piece.contains(';')
        {
            return false;
        }
        if !escapes_are_inert(piece) {
            return false;
        }
    }
    true
}

/// Split at `/` and at every case of `%2f`.
fn pieces(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = path.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            out.push(&path[start..i]);
            i += 1;
            start = i;
        } else if bytes[i] == b'%'
            && bytes.get(i + 1) == Some(&b'2')
            && matches!(bytes.get(i + 2), Some(b'f' | b'F'))
        {
            out.push(&path[start..i]);
            i += 3;
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(&path[start..]);
    out
}

/// Every `%XX` is well formed and decodes to a byte that cannot change which
/// directory the path names once a server decodes it. (`%2f` never reaches
/// here: [`pieces`] split on it.)
fn escapes_are_inert(piece: &str) -> bool {
    let bytes = piece.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let Some(hex) = bytes.get(i + 1..i + 3) else {
                return false;
            };
            let Ok(hex) = std::str::from_utf8(hex) else {
                return false;
            };
            let Ok(decoded) = u8::from_str_radix(hex, 16) else {
                return false;
            };
            if matches!(decoded, b'/' | b'\\' | b'.' | b'%' | b';') || !hex.is_ascii() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// The URL ward sends is the parsed, re-serialized form: it must name the
/// same path as the raw spelling the checks ran on.
pub fn same_path_after_parse(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let Some((_, raw)) = split(url) else {
        return false;
    };
    let raw = raw.split(['?', '#']).next().unwrap_or("");
    let raw = if raw.is_empty() { "/" } else { raw };
    parsed.path() == raw
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "https://nexus.corp.example/repository/npm-proxy/";

    #[test]
    fn a_path_under_the_root_at_a_segment_boundary_is_covered() {
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/left-pad"
        ));
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/"
        ));
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy"
        ));
        assert!(covers(
            ROOT,
            "https://NEXUS.corp.example:443/repository/npm-proxy/left-pad/-/left-pad-1.3.0.tgz"
        ));
        assert!(!covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy-other/x"
        ));
        assert!(!covers(ROOT, "https://nexus.corp.example/repository/"));
        assert!(!covers(
            ROOT,
            "https://other.corp.example/repository/npm-proxy/x"
        ));
        assert!(!covers(
            ROOT,
            "https://nexus.corp.example:8443/repository/npm-proxy/x"
        ));
        assert!(!covers(
            ROOT,
            "http://nexus.corp.example/repository/npm-proxy/x"
        ));
        assert!(!covers(
            ROOT,
            "https://u:p@nexus.corp.example/repository/npm-proxy/x"
        ));
    }

    #[test]
    fn a_scoped_packument_passes_and_an_encoded_escape_does_not() {
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/@corp%2fwidget"
        ));
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/@corp%2Fwidget"
        ));
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/@corp/widget"
        ));
        for escape in [
            "https://nexus.corp.example/repository/npm-proxy/@s%2f..%2f..%2fother/x.tgz",
            "https://nexus.corp.example/repository/npm-proxy/@s%2F..%2Fx",
            "https://nexus.corp.example/repository/npm-proxy/%2e%2e/other",
            "https://nexus.corp.example/repository/npm-proxy/%2E%2E/other",
            "https://nexus.corp.example/repository/npm-proxy/a%5c..%5cb",
            "https://nexus.corp.example/repository/npm-proxy/a%252f",
            "https://nexus.corp.example/repository/npm-proxy/../npm-other/x",
            "https://nexus.corp.example/repository/npm-proxy/./x",
            "https://nexus.corp.example/repository/npm-proxy/a\\..\\b",
            "https://nexus.corp.example/repository/npm-proxy/a//b",
            "https://nexus.corp.example/repository/npm-proxy/a%2f%2fb",
            "https://nexus.corp.example/repository/npm-proxy/a%zz",
            "https://nexus.corp.example/repository/npm-proxy/..;/npm-private/x.tgz",
            "https://nexus.corp.example/repository/npm-proxy/..%3b/npm-private/x.tgz",
            "https://nexus.corp.example/repository/npm-proxy/..%3B/npm-private/x.tgz",
        ] {
            assert!(!covers(ROOT, escape), "{escape}");
        }
    }

    #[test]
    fn query_and_fragment_do_not_change_the_answer() {
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/x.tgz?X-Amz-Signature=abc"
        ));
        assert!(covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/x.whl#sha256=00"
        ));
        assert!(!covers(
            ROOT,
            "https://nexus.corp.example/repository/npm-proxy/../x?a=b"
        ));
    }

    #[test]
    fn an_origin_root_covers_every_clean_path_on_it() {
        let files = "https://cdn.corp.example/";
        assert!(covers(files, "https://cdn.corp.example/blobs/sha256/ab"));
        assert!(!covers(files, "https://cdn.corp.example/a/../b"));
        assert!(!covers(files, "https://cdn.corp.example.evil/x"));
    }

    #[test]
    fn root_len_ranks_longer_roots_first() {
        assert!(root_len(ROOT) > root_len("https://nexus.corp.example/repository/"));
        assert_eq!(root_len("https://cdn.corp.example/"), 0);
    }
}
