//! The closure records a project committed under `.greyward/closures`, read as
//! they are: the envelope, its body, and the exceptions it carries. Nothing
//! here judges freshness, which asks the tailors (`commands::inspect`).

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy::{self, Exception, OptionalGroupSkipped};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// One `.greyward/closures/<ecosystem>.json`, envelope fields lifted out.
#[derive(Debug, Clone)]
pub struct ClosureFile {
    pub ecosystem: String,
    pub platform: Option<String>,
    pub projected_at: Option<u64>,
    pub body: Value,
    /// The complete envelope as parsed from the one file read, unknown
    /// fields included: what a signature covers, and what `audit` verifies
    /// before it trusts any field lifted above.
    pub envelope: Value,
    /// Where the envelope was read from.
    pub path: PathBuf,
    /// sha256 of the envelope bytes as read: names the exact record an
    /// audit verdict was computed over.
    pub record_sha256: String,
}

/// Every closure record in `project`, in directory order: the listing and
/// every record are read through its descriptor, ward state read strictly
/// (a symlinked record is refused, never followed). Foreign-platform
/// closures are included (the caller decides what they mean), unlike
/// [`super::read_closure`], which refuses them.
pub fn closure_files(project: &ProjectRoot) -> io::Result<Vec<ClosureFile>> {
    let mut out = Vec::new();
    let dir = Path::new(".greyward/closures");
    let Some(names) = project.read_dir(dir)? else {
        return Ok(out);
    };
    for name in names {
        if closure_stem(&name.to_string_lossy()).is_none() {
            continue;
        }
        let text = name.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid UTF-8 closure filename in {}",
                    project.path().join(dir).display()
                ),
            )
        })?;
        let relative = dir.join(&name);
        let Some(bytes) = project.read_file(&relative)? else {
            continue;
        };
        out.push(closure_file(text, project.path().join(&relative), &bytes)?);
    }
    Ok(out)
}

/// The project in `dir`, held for one report command: `None` when it is
/// absent or not a directory (nothing to report), as detection reads it.
pub fn open_project(dir: &Path) -> io::Result<Option<ProjectRoot>> {
    match ProjectRoot::open(dir) {
        Ok(project) => Ok(Some(project)),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::InvalidData =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The ecosystem stem of a closure file name: `<stem>.json`, not hidden,
/// and not a retired record (`store::RETIRED_CLOSURES`), so a leftover never
/// reads as an orphaned or unknown closure in listing, status, or audit.
fn closure_stem(name: &str) -> Option<&str> {
    name.strip_suffix(".json").filter(|stem| {
        !stem.starts_with('.') && !crate::kernel::store::RETIRED_CLOSURES.contains(stem)
    })
}

fn closure_file(name: &str, path: PathBuf, bytes: &[u8]) -> io::Result<ClosureFile> {
    let stem = closure_stem(name).expect("caller filtered closure names");
    let value: Value = parse_envelope(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{:?}: {error}; run 'ward'", path.to_string_lossy()),
        )
    })?;
    Ok(ClosureFile {
        ecosystem: value["ecosystem"].as_str().unwrap_or(stem).to_string(),
        platform: value["platform"].as_str().map(str::to_string),
        projected_at: value["projected_at"].as_u64(),
        body: value["body"].clone(),
        envelope: value,
        path,
        record_sha256: hex::encode(Sha256::digest(bytes)),
    })
}

/// A closure or resolution-record envelope parsed as JSON that names every
/// object key once. `serde_json` keeps the last of two equal keys, so a
/// record with an extra `"exceptions": []` ahead of the real list still
/// verifies (the signature covers the parsed value) while a person reading
/// the file, or a parser that keeps the first key, sees an empty list. What
/// ward judges must be what everyone reads, so a repeated key is refused.
pub(crate) fn parse_envelope(bytes: &[u8]) -> serde_json::Result<Value> {
    use serde::Deserialize;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueKeys(value) = UniqueKeys::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// A JSON value whose objects, at every depth, have no repeated key.
struct UniqueKeys(Value);

impl<'de> serde::Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(UniqueKeysVisitor)
            .map(UniqueKeys)
    }
}

struct UniqueKeysVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueKeysVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(UniqueKeys(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let UniqueKeys(value) = map.next_value()?;
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "the key {key:?} appears twice in one object"
                )));
            }
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

/// The recorded exceptions, or `None` when the closure carries no exception
/// record at all (absence is not evidence of a clean sync).
pub fn recorded_exceptions(closure: &ClosureFile) -> io::Result<Option<Vec<Exception>>> {
    match closure.body.get("exceptions") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{:?}: malformed exception record: {error}; run 'ward'",
                        closure.path.to_string_lossy()
                    ),
                )
            }),
    }
}

/// The optional groups the sync left out because nobody requested them
/// (`optional_groups_skipped`, #71). Informational: absence means none,
/// or a closure written before the list existed.
pub fn optional_groups_skipped(closure: &ClosureFile) -> io::Result<Vec<OptionalGroupSkipped>> {
    match closure.body.get("optional_groups_skipped") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{:?}: malformed optional_groups_skipped: {error}; run 'ward'",
                    closure.path.to_string_lossy()
                ),
            )
        }),
    }
}

/// The exceptions of the resolution record the closure joined, or none. A
/// `resolution` field that is not a record object, or whose exception list
/// does not parse, is refused like a malformed exception record.
pub fn resolution_exceptions(closure: &ClosureFile) -> io::Result<Vec<Exception>> {
    let malformed = |what: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{:?}: malformed resolution record: {what}; run 'ward'",
                closure.path.to_string_lossy()
            ),
        )
    };
    let Some(resolution) = closure.body.get("resolution") else {
        return Ok(Vec::new());
    };
    let Some(record) = resolution.as_object() else {
        return Err(malformed("not a JSON object".into()));
    };
    match record.get("exceptions") {
        None => Err(malformed("no exception list".into())),
        Some(list) => {
            serde_json::from_value(list.clone()).map_err(|error| malformed(error.to_string()))
        }
    }
}

/// What `exceptions` found in one closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionList {
    /// Whether the closure carries an exception record at all
    /// (`body.exceptions`). Absence is not evidence of a clean sync:
    /// `audit` calls such a record outdated, whatever the joined
    /// resolution record says.
    pub recorded: bool,
    /// The recorded list, then whatever the joined resolution record adds
    /// that the list does not already name, each kind spelled the one way
    /// this binary judges and prints (`policy::canonical_kind`).
    pub exceptions: Vec<Exception>,
}

/// Every exception the closure carries, from both places it can record one.
/// Both are read even when the top-level list is absent, so a malformed
/// resolution record is refused the same way whichever list is missing,
/// and `status` still shows what the joined record says.
pub fn exceptions(closure: &ClosureFile) -> io::Result<ExceptionList> {
    let recorded = recorded_exceptions(closure)?;
    let joined = resolution_exceptions(closure)?;
    let canonical = |mut exception: Exception| {
        exception.kind = policy::canonical_kind(&exception.kind).to_string();
        exception
    };
    let mut exceptions: Vec<Exception> = recorded
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(canonical)
        .collect();
    for exception in joined.into_iter().map(canonical) {
        if !exceptions.contains(&exception) {
            exceptions.push(exception);
        }
    }
    Ok(ExceptionList {
        recorded: recorded.is_some(),
        exceptions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A closure with a second `exceptions` key ahead of the real one is
    /// refused rather than read as whichever key a parser keeps.
    #[test]
    fn a_repeated_key_in_an_envelope_is_refused() {
        let doubled = br#"{"schema":"closure/1","body":{"exceptions":[],"n":1,
            "exceptions":[{"kind":"git-dependency","subject":"x","detail":""}]}}"#;
        let error = closure_file("node.json", PathBuf::from("node.json"), doubled).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("\"exceptions\" appears twice"),
            "{error}"
        );
        // At any depth, in an array too, and at the top level.
        for text in [r#"{"a":1,"a":1}"#, r#"{"body":[{"k":{"x":1,"x":2}}]}"#] {
            assert!(parse_envelope(text.as_bytes()).is_err(), "{text}");
        }
        // The same key in two different objects is no repeat, and every
        // JSON type reads back as serde_json reads it.
        let text = r#"{"a":{"k":1},"b":{"k":-2},"c":[1.5,true,null,"s",18446744073709551615]}"#;
        assert_eq!(
            parse_envelope(text.as_bytes()).unwrap(),
            serde_json::from_str::<Value>(text).unwrap()
        );
        // Trailing text after the document is refused as serde_json does.
        assert!(parse_envelope(b"{} {}").is_err());
    }
}
