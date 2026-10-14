//! `young-package`: a locked registry version published fewer than
//! `[packages] min_age_days` days before the resolution that locked it.
//!
//! A malicious version is usually found and pulled within days of its
//! upload, so a resolution that waits out that window rarely locks one.
//! The door judges this once its tool has run and the lock is final, for
//! each registry package the lock names (the tailor's [`LockedPackage`]
//! list): the exact locked version's publish time against the resolution
//! time.
//!
//! The publish time comes from the metadata the tool's own traffic carried
//! when its protocol records one ([`RegistryProtocol::published`]: npm's
//! packument `time`, PyPI's `upload-time`, a crates.io index line's
//! `pubtime`, a Go `.info`, a RubyGems compact index line). A version the
//! traffic did not describe (pnpm reads abbreviated packuments, Hex's signed
//! registry and NuGet's flat container carry no time, and a tool skips the
//! documents of packages its lock already pins) is looked up by ward itself
//! in a second proxy session ([`RegistryProtocol::lookup`]), through the
//! same cache, resolver, permitted set and ledger. A version whose time is
//! still unknown is a fact too: under a policy that denies the kind it is
//! refused like a young one (fail closed); otherwise it is recorded.
//!
//! The fact's detail carries the publish time, the resolution time and the
//! minimum in force, so the signed record says what was judged, and
//! `ward audit` and every later sync replay the same fact offline.
//!
//! [`RegistryProtocol::published`]: super::routes::RegistryProtocol::published
//! [`RegistryProtocol::lookup`]: super::routes::RegistryProtocol::lookup

use super::proxy::{LookupAnswer, Proxy};
use super::routes::{file_key, Lookup};
use super::session::{Fact, PublishTimes, SessionConfig, SessionReport};
use crate::kernel::policy::{self, Policy, SourceOrigin, YOUNG_PACKAGE};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const SECONDS_PER_DAY: i64 = 86_400;

/// Lookups in flight at once. Registries rate-limit unauthenticated API
/// reads (hex.pm allows 100 a minute), so this stays small.
const LOOKUP_WORKERS: usize = 4;

/// One registry package version a lock names, spelled as the lock spells
/// it. The protocol's [`package_key`] compares it with the metadata's
/// spelling.
///
/// [`package_key`]: super::routes::RegistryProtocol::package_key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    /// The version's files the lock names (a uv.lock's wheels and sdist),
    /// when it names them. A registry may add a file to an old version, so
    /// these are judged by the latest of their own upload times rather than
    /// the version's first. Empty: the version is judged.
    pub files: Vec<String>,
}

impl LockedPackage {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            files: Vec::new(),
        }
    }

    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files;
        self
    }
}

/// One package the check flagged: its fact, and when it becomes old enough
/// (`None` when its publish time is unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Young {
    pub fact: Fact,
    pub ready: Option<i64>,
}

/// What the check found: the flagged packages, and the lookup session's
/// report when ward fetched anything itself.
#[derive(Debug)]
pub(super) struct Judged {
    pub young: Vec<Young>,
    pub lookups: Option<SessionReport>,
}

/// Judge `packages` against `policy`'s minimum age at `now`. `observed` is
/// what the tool's session read; anything it did not read is looked up in
/// a session opened from `config` (same routes, policy, mode and store).
pub(super) fn judge(
    proxy: &Proxy,
    config: SessionConfig,
    observed: &PublishTimes,
    packages: &[LockedPackage],
    now: SystemTime,
    policy: &Policy,
) -> io::Result<Judged> {
    let days = policy.min_age_days();
    // A run with no route reached no registry, so it chose nothing new.
    if days == 0 || packages.is_empty() || config.routes.is_empty() {
        return Ok(Judged {
            young: Vec::new(),
            lookups: None,
        });
    }
    let packages: BTreeSet<&LockedPackage> = packages.iter().collect();
    // Why a package's time is unknown, for those that stay unknown.
    let mut causes: BTreeMap<&LockedPackage, String> = BTreeMap::new();
    // One lookup per document, however many locked versions it times.
    let mut wanted: BTreeMap<(String, String), Wanted> = BTreeMap::new();
    let mut asks: BTreeMap<&LockedPackage, (String, String)> = BTreeMap::new();
    for package in &packages {
        let untimed = config
            .routes
            .iter()
            .find_map(|route| route.protocol.untimed(&package.name, &package.version));
        if let Some(why) = untimed {
            causes.insert(package, why);
            continue;
        }
        if published_at(&config, observed, package).is_some() {
            continue;
        }
        let found = config.routes.iter().find_map(|route| {
            let lookup =
                route
                    .protocol
                    .lookup(&route.endpoints, &package.name, &package.version)?;
            Some((route.protocol.route_id().to_string(), lookup))
        });
        let Some((route, lookup)) = found else {
            causes.insert(
                package,
                "the metadata the tool read named none, and the registry has no document \
                 ward can ask"
                    .to_string(),
            );
            continue;
        };
        let key = (route.clone(), lookup.url.to_string());
        let entry = wanted.entry(key.clone()).or_insert_with(|| Wanted {
            route,
            lookup,
            versions: Vec::new(),
            answer: None,
        });
        entry
            .versions
            .push((package.name.clone(), package.version.clone()));
        for file in &package.files {
            entry
                .versions
                .push((package.name.clone(), file_key(&package.version, file)));
        }
        asks.insert(package, key);
    }
    let mut wanted: Vec<Wanted> = wanted.into_values().collect();
    let lookups = if wanted.is_empty() {
        None
    } else {
        Some(look_up(proxy, &config, &mut wanted)?)
    };
    let answers: BTreeMap<(String, String), &LookupAnswer> = wanted
        .iter()
        .filter_map(|wanted| {
            let key = (wanted.route.clone(), wanted.lookup.url.to_string());
            Some((key, wanted.answer.as_ref()?))
        })
        .collect();
    let mut times = observed.clone();
    if let Some(report) = &lookups {
        for (key, at) in &report.published {
            times
                .entry(key.clone())
                .and_modify(|known| *known = (*known).min(*at))
                .or_insert(*at);
        }
    }
    let now = unix_seconds(now);
    let minimum = days as i64 * SECONDS_PER_DAY;
    let source = match policy.min_age_origin {
        Some(SourceOrigin::Machine) => "set by the machine policy",
        Some(SourceOrigin::Project) => "set by a project policy",
        Some(SourceOrigin::Flag) => "set by the --policy file",
        Some(SourceOrigin::Env) => "set by the environment",
        None => "the default",
    };
    let young = packages
        .into_iter()
        .filter_map(|package| {
            let subject = format!("{}@{}", package.name, package.version);
            let rule = format!("the minimum age is {days} days ({source})");
            let timed = if causes.contains_key(package) {
                None
            } else {
                published_at(&config, &times, package)
            };
            match timed {
                Some((at, _)) if now - at >= minimum => None,
                Some((at, note)) => Some(Young {
                    fact: Fact {
                        kind: YOUNG_PACKAGE,
                        subject,
                        detail: format!(
                            "published {}{}, {} this resolution at {}; {rule}",
                            format_utc(at),
                            note.map(|note| format!(" ({note})")).unwrap_or_default(),
                            describe_age(now - at),
                            format_utc(now)
                        ),
                    },
                    ready: Some(at + minimum),
                }),
                None => {
                    let cause = causes.get(package).cloned().unwrap_or_else(|| {
                        let answer = asks.get(package).and_then(|key| answers.get(key));
                        unknown_cause(answer.copied())
                    });
                    Some(Young {
                        fact: Fact {
                            kind: YOUNG_PACKAGE,
                            subject,
                            detail: format!(
                                "its publish time is unknown at this resolution at {}: \
                                 {cause}; {rule}",
                                format_utc(now)
                            ),
                        },
                        ready: None,
                    })
                }
            }
        })
        .collect();
    Ok(Judged { young, lookups })
}

/// One document ward fetches itself, the versions it is fetched for, and
/// how it was answered.
struct Wanted {
    route: String,
    lookup: Lookup,
    versions: Vec<(String, String)>,
    answer: Option<LookupAnswer>,
}

/// Why a looked-up version's time is still unknown, from how its lookup
/// was answered.
fn unknown_cause(answer: Option<&LookupAnswer>) -> String {
    let Some(answer) = answer else {
        return "the lookup was not answered".to_string();
    };
    match (answer.status, &answer.reason) {
        (200..=299, _) => "the registry's answer names no publish time for it".to_string(),
        (429, _) => "the registry rate-limited the lookup (429), twice".to_string(),
        (_, Some(reason)) => reason.clone(),
        (status, None) => format!("the registry answered the lookup with {status}"),
    }
}

/// Record the flagged packages under `policy`, on the attribution's
/// thread. Allowed, each is its own exception (and its own fact in the
/// record). Denied, one refusal names every package, how to get past it
/// (an older version, or a later resolution), and the knob that refused.
pub(super) fn record(policy: &Policy, young: &[Young]) -> io::Result<Vec<Fact>> {
    if young.is_empty() {
        return Ok(Vec::new());
    }
    if policy::denied(policy, YOUNG_PACKAGE) {
        let subject = young
            .iter()
            .map(|young| young.fact.subject.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let detail = young
            .iter()
            .map(|young| format!("{} {}", young.fact.subject, young.fact.detail))
            .collect::<Vec<_>>()
            .join("; ");
        let them = if young.len() == 1 { "it" } else { "each" };
        let later = if young.iter().all(|young| young.ready.is_some()) {
            young
                .iter()
                .filter_map(|young| young.ready)
                .max()
                .map(|ready| format!(", or resolve again after {}", format_utc(ready)))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let fix = format!(
            "pin an older version of {them}{later}; {}",
            policy::refusal_fix(policy, YOUNG_PACKAGE)
        );
        policy::record_with_fix(policy, YOUNG_PACKAGE, &subject, &detail, Some(&fix))?;
        // `record_with_fix` refuses a denied kind; nothing reaches here.
        return Err(io::Error::other("young-package was denied"));
    }
    for young in young {
        policy::record_with(
            policy,
            young.fact.kind,
            &young.fact.subject,
            &young.fact.detail,
        )?;
    }
    Ok(young.iter().map(|young| young.fact.clone()).collect())
}

/// The publish time `times` holds for `package` under any route's key,
/// and that route's note on what the time is. When the lock names the
/// version's files and every one has a time, the latest of those is the
/// package's time; otherwise the version's.
fn published_at(
    config: &SessionConfig,
    times: &PublishTimes,
    package: &LockedPackage,
) -> Option<(i64, Option<&'static str>)> {
    config.routes.iter().find_map(|route| {
        let protocol = route.protocol;
        let route_id = protocol.route_id().to_string();
        let time = |version: &str| {
            let (name, version) = protocol.package_key(&package.name, version);
            times.get(&(route_id.clone(), name, version)).copied()
        };
        let files: Option<Vec<i64>> = package
            .files
            .iter()
            .map(|file| time(&file_key(&package.version, file)))
            .collect();
        let at = match files {
            Some(files) if !files.is_empty() => files.into_iter().max(),
            _ => time(&package.version),
        }?;
        Some((at, protocol.time_note()))
    })
}

/// How long ward waits before asking a rate-limited registry once more,
/// when the registry names no wait, and the longest wait it honors.
const RATE_LIMIT_WAIT: u64 = 2;
const RATE_LIMIT_MAX_WAIT: u64 = 10;

/// Fetch every lookup in one session, a few at a time, and record how
/// each was answered. A rate-limited lookup is asked once more, after the
/// registry's `Retry-After` (capped).
fn look_up(
    proxy: &Proxy,
    config: &SessionConfig,
    wanted: &mut [Wanted],
) -> io::Result<SessionReport> {
    let session = proxy.open_session(SessionConfig {
        ecosystem: config.ecosystem.clone(),
        door: config.door.clone(),
        routes: config.routes.clone(),
        intercept: config.intercept,
        policy: config.policy.clone(),
        mode: config.mode,
        store: config.store.clone(),
        activity: config.activity.clone(),
        permitted: config.permitted.clone(),
    })?;
    let next = AtomicUsize::new(0);
    let failure: Mutex<Option<io::Error>> = Mutex::new(None);
    let slots: Vec<Mutex<&mut Wanted>> = wanted.iter_mut().map(Mutex::new).collect();
    std::thread::scope(|scope| {
        for _ in 0..LOOKUP_WORKERS.min(slots.len()) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::SeqCst);
                let Some(slot) = slots.get(index) else {
                    break;
                };
                let mut wanted = slot.lock().unwrap_or_else(|e| e.into_inner());
                let ask = || session.lookup(&wanted.route, &wanted.lookup, &wanted.versions);
                let answer = ask().and_then(|answer| {
                    if answer.status != 429 {
                        return Ok(answer);
                    }
                    let wait = answer
                        .retry_after
                        .unwrap_or(RATE_LIMIT_WAIT)
                        .min(RATE_LIMIT_MAX_WAIT);
                    std::thread::sleep(std::time::Duration::from_secs(wait));
                    ask()
                });
                match answer {
                    Ok(answer) => wanted.answer = Some(answer),
                    Err(error) => {
                        let mut slot = failure.lock().unwrap_or_else(|e| e.into_inner());
                        slot.get_or_insert(error);
                        break;
                    }
                }
            });
        }
    });
    let report = session.finish();
    match failure.into_inner().unwrap_or_else(|e| e.into_inner()) {
        Some(error) => Err(error),
        None => Ok(report),
    }
}

/// `at` as seconds since the Unix epoch (negative before it).
pub fn unix_seconds(at: SystemTime) -> i64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    }
}

/// How long before the resolution a version was published, in days, or
/// hours under two days, ending in the word that leads into "this
/// resolution". A publish time after the resolution's clock reads as such.
fn describe_age(seconds: i64) -> String {
    if seconds < 0 {
        return "later than".to_string();
    }
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if seconds < 2 * SECONDS_PER_DAY {
        format!("{} before", plural(seconds / 3600, "hour"))
    } else {
        format!("{} before", plural(seconds / SECONDS_PER_DAY, "day"))
    }
}

/// An RFC 3339 timestamp (`2026-10-14T05:06:07Z`, with optional fractional
/// seconds and a `Z` or `±hh:mm` offset; a space for the `T`, as RubyGems
/// writes it, is accepted too) as unix seconds. `None` for anything else.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let text = text.trim();
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !bytes.is_ascii() {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let end = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        if end == 0 {
            return None;
        }
        rest = &fraction[end..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let zone = &rest[1..];
            if zone.len() != 5 || zone.as_bytes()[2] != b':' {
                return None;
            }
            let (hours, minutes): (i64, i64) = (zone[..2].parse().ok()?, zone[3..].parse().ok()?);
            if !zone[..2].bytes().all(|b| b.is_ascii_digit())
                || !zone[3..].bytes().all(|b| b.is_ascii_digit())
                || hours > 23
                || minutes > 59
            {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
    };
    let days = days_from_civil(year, month, day);
    Some(days * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second.min(59) - offset)
}

/// `seconds` since the epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registry_timestamp_format_parses() {
        // crates.io `pubtime`, Go `.info`, RubyGems `created_at`.
        assert_eq!(parse_rfc3339("2024-02-12T23:43:59Z"), Some(1_707_781_439));
        // Hex `inserted_at`, PyPI `upload-time`: fractional seconds.
        assert_eq!(
            parse_rfc3339("2024-02-12T23:43:59.963093Z"),
            Some(1_707_781_439)
        );
        // NuGet `published`: milliseconds and an offset.
        assert_eq!(
            parse_rfc3339("2022-01-29T15:14:14.207+00:00"),
            Some(1_643_469_254)
        );
        assert_eq!(
            parse_rfc3339("2022-01-29T17:14:14+02:00"),
            Some(1_643_469_254)
        );
        assert_eq!(
            parse_rfc3339("2022-01-29T10:14:14-05:00"),
            Some(1_643_469_254)
        );
        // npm `time`: milliseconds and Z.
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_rfc3339("1900-01-01T00:00:00+00:00"),
            Some(-2_208_988_800)
        );
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for bad in [
            "",
            "2024-02-12",
            "2024-02-12T23:43:59",
            "2024-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-02-12T24:00:00Z",
            "2024-02-12T23:43:59.Z",
            "2024-02-12T23:43:59+0000",
            "2024-02-12T23:43:59+00:0x",
            "2024-02-12T23:43:59Zjunk",
            "２024-02-12T23:43:59Z",
            "+024-02-12T23:43:59Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn formatting_round_trips_through_parsing() {
        for seconds in [0, 1_707_781_439, -2_208_988_800, 951_782_400, 4_102_444_799] {
            let text = format_utc(seconds);
            assert_eq!(parse_rfc3339(&text), Some(seconds), "{text}");
        }
        assert_eq!(format_utc(1_643_469_254), "2022-01-29T15:14:14Z");
    }

    #[test]
    fn ages_read_in_hours_then_days() {
        assert_eq!(describe_age(3600), "1 hour before");
        assert_eq!(describe_age(47 * 3600), "47 hours before");
        assert_eq!(describe_age(2 * SECONDS_PER_DAY), "2 days before");
        assert_eq!(describe_age(-1), "later than");
    }

    use crate::kernel::resolve::session::Mode;
    use crate::kernel::resolve::testing::Harness;
    use crate::kernel::testutil::upstream::{Behavior, Reply};

    /// 2026-10-12T00:00:00Z.
    const NOW: i64 = 1_791_763_200;

    fn at(seconds: i64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64)
    }

    fn serve(harness: &Harness, name: &str, version: &str, published: i64) {
        let body = format!(
            r#"{{"published": {{"{name}@{version}": "{}"}}}}"#,
            format_utc(published)
        );
        harness.upstream.set(
            &format!("/meta/{name}.json"),
            Behavior::Reply(
                Reply::new(200, body.as_bytes()).header("Content-Type", "application/json"),
            ),
        );
    }

    #[test]
    fn unobserved_versions_are_looked_up_and_judged_against_the_minimum() {
        let harness = Harness::new("age-judge");
        serve(&harness, "young", "1.0", NOW - 2 * SECONDS_PER_DAY);
        serve(&harness, "old", "2.0", NOW - 30 * SECONDS_PER_DAY);
        // `seen` was described by the tool's own traffic: no lookup.
        let observed = PublishTimes::from([(
            ("fixture".to_string(), "seen".to_string(), "3.0".to_string()),
            NOW - 400 * SECONDS_PER_DAY,
        )]);
        let packages = [
            LockedPackage::new("young", "1.0"),
            LockedPackage::new("old", "2.0"),
            LockedPackage::new("seen", "3.0"),
            LockedPackage::new("gone", "4.0"),
            LockedPackage::new("young", "1.0"),
        ];
        let policy = Policy::default();
        let config = harness.config(policy.clone(), Mode::Online);
        let judged = judge(
            &harness.proxy,
            config,
            &observed,
            &packages,
            at(NOW),
            &policy,
        )
        .unwrap();
        let subjects: Vec<&str> = judged
            .young
            .iter()
            .map(|young| young.fact.subject.as_str())
            .collect();
        assert_eq!(subjects, ["gone@4.0", "young@1.0"]);
        let gone = &judged.young[0];
        assert_eq!(gone.ready, None);
        assert_eq!(
            gone.fact.detail,
            "its publish time is unknown at this resolution at 2026-10-12T00:00:00Z: the \
             registry answered the lookup with 404; the minimum age is 7 days (the default)"
        );
        let young = &judged.young[1];
        assert_eq!(young.ready, Some(NOW + 5 * SECONDS_PER_DAY));
        assert_eq!(
            young.fact.detail,
            "published 2026-10-10T00:00:00Z, 2 days before this resolution at \
             2026-10-12T00:00:00Z; the minimum age is 7 days (the default)"
        );
        assert_eq!(harness.upstream.hits("/meta/seen.json"), 0);
        assert_eq!(harness.upstream.hits("/meta/young.json"), 1);
        let report = judged.lookups.unwrap();
        let classes: BTreeSet<String> = report
            .ledger
            .entries()
            .map(|entry| entry.class.clone())
            .collect();
        assert_eq!(
            classes,
            BTreeSet::from([super::super::mirror::PUBLISH_TIME_CLASS.to_string()])
        );
        assert_eq!(report.ledger.entries().count(), 3);
        assert!(report.facts.hard_failures.is_empty());
    }

    #[test]
    fn the_tools_own_metadata_records_publish_times_and_lookups_stay_on_the_route() {
        use crate::kernel::resolve::testing::{get, mirror};
        let harness = Harness::new("age-observed");
        serve(&harness, "young", "1.0", NOW - SECONDS_PER_DAY);
        let (session, address) = harness.session();
        let response = get(&address, &mirror(&address, "/meta/young.json"), "");
        assert_eq!(response.status, 200, "{}", response.text());
        let off_route = Lookup {
            url: url::Url::parse("https://elsewhere.test/meta/young.json").unwrap(),
            accept: "application/json",
        };
        let error = session.lookup("fixture", &off_route, &[]).unwrap_err();
        assert!(error.to_string().contains("on no endpoint"), "{error}");
        let report = session.finish();
        assert_eq!(
            report.published,
            PublishTimes::from([(
                (
                    "fixture".to_string(),
                    "young".to_string(),
                    "1.0".to_string()
                ),
                NOW - SECONDS_PER_DAY,
            )])
        );
        // The tool's own fetch keeps its class.
        assert!(report
            .ledger
            .entries()
            .all(|entry| entry.class != super::super::mirror::PUBLISH_TIME_CLASS));
    }

    #[test]
    fn nothing_is_judged_at_zero_days_or_without_a_route() {
        let harness = Harness::new("age-off");
        let packages = [LockedPackage::new("gone", "4.0")];
        let off = Policy {
            packages: Some(crate::kernel::policy::Packages {
                min_age_days: Some(0),
            }),
            ..Policy::default()
        };
        let judged = judge(
            &harness.proxy,
            harness.config(off.clone(), Mode::Online),
            &PublishTimes::new(),
            &packages,
            at(NOW),
            &off,
        )
        .unwrap();
        assert!(judged.young.is_empty() && judged.lookups.is_none());
        let mut offline = harness.config(Policy::default(), Mode::Online);
        offline.routes.clear();
        let judged = judge(
            &harness.proxy,
            offline,
            &PublishTimes::new(),
            &packages,
            at(NOW),
            &Policy::default(),
        )
        .unwrap();
        assert!(judged.young.is_empty() && judged.lookups.is_none());
        assert!(harness.upstream.seen().is_empty());
    }

    #[test]
    fn a_denied_kind_refuses_once_naming_every_package_and_the_way_out() {
        let _serial = policy::attribution_test_lock();
        let attribution = policy::Attribution::open("fixture").unwrap();
        let policy = Policy {
            deny: BTreeSet::from([YOUNG_PACKAGE.to_string()]),
            ..Policy::default()
        };
        let young = |subject: &str, ready| Young {
            fact: Fact {
                kind: YOUNG_PACKAGE,
                subject: subject.to_string(),
                detail: "published recently".to_string(),
            },
            ready,
        };
        let error = record(
            &policy,
            &[young("a@1", Some(NOW)), young("b@2", Some(NOW + 60))],
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("a@1, b@2"), "{text}");
        assert!(text.contains("pin an older version of each"), "{text}");
        assert!(
            text.contains("resolve again after 2026-10-12T00:01:00Z"),
            "{text}"
        );
        let unknown = record(&policy, &[young("c@3", None)])
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("pin an older version of it;"), "{unknown}");
        assert!(!unknown.contains("resolve again"), "{unknown}");
        assert!(attribution.recorded().is_empty());
        attribution.discard();
    }

    fn deny() -> Policy {
        Policy {
            deny: BTreeSet::from([YOUNG_PACKAGE.to_string()]),
            ..Policy::default()
        }
    }

    /// Judge `packages` with nothing observed, under `policy` and `mode`.
    fn judge_unobserved(
        harness: &Harness,
        policy: &Policy,
        mode: Mode,
        packages: &[LockedPackage],
    ) -> Judged {
        judge(
            &harness.proxy,
            harness.config(policy.clone(), mode),
            &PublishTimes::new(),
            packages,
            at(NOW),
            policy,
        )
        .unwrap()
    }

    #[test]
    fn one_document_is_fetched_once_and_a_cached_answer_is_not_asked_again() {
        let harness = Harness::new("age-dedup");
        let body = format!(
            r#"{{"published": {{"pkg@1.0": "{}", "pkg@1.1": "{}"}}}}"#,
            format_utc(NOW - 30 * SECONDS_PER_DAY),
            format_utc(NOW - 20 * SECONDS_PER_DAY)
        );
        harness.upstream.set(
            "/meta/pkg.json",
            Behavior::Reply(
                Reply::new(200, body.as_bytes()).header("Content-Type", "application/json"),
            ),
        );
        let packages = [
            LockedPackage::new("pkg", "1.0"),
            LockedPackage::new("pkg", "1.1"),
        ];
        let judged = judge_unobserved(&harness, &deny(), Mode::Online, &packages);
        assert!(judged.young.is_empty(), "{:?}", judged.young);
        assert_eq!(harness.upstream.hits("/meta/pkg.json"), 1);
        // A later resolution finds both times in the cache: no request.
        let judged = judge_unobserved(&harness, &deny(), Mode::Online, &packages);
        assert!(judged.young.is_empty(), "{:?}", judged.young);
        assert_eq!(harness.upstream.hits("/meta/pkg.json"), 1);
        let dispositions: Vec<String> = judged
            .lookups
            .unwrap()
            .diagnostics
            .requests
            .iter()
            .map(|row| row.disposition.clone())
            .collect();
        assert_eq!(dispositions, ["hit"]);
        // A version the cached copy does not time is asked about.
        let judged = judge_unobserved(
            &harness,
            &deny(),
            Mode::Online,
            &[LockedPackage::new("pkg", "1.2")],
        );
        assert_eq!(judged.young.len(), 1);
        assert_eq!(harness.upstream.hits("/meta/pkg.json"), 2);
    }

    /// A lookup the registry does not answer leaves the time unknown, the
    /// detail says why, and a policy that denies the kind refuses it.
    fn refused_unanswered(harness: &Harness, mode: Mode, cause: &str) {
        let packages = [LockedPackage::new("pkg", "1.0")];
        let judged = judge_unobserved(harness, &deny(), mode, &packages);
        assert_eq!(judged.young.len(), 1, "{:?}", judged.young);
        let detail = &judged.young[0].fact.detail;
        assert!(detail.contains(cause), "{detail}");
        let _serial = policy::attribution_test_lock();
        let attribution = policy::Attribution::open("fixture").unwrap();
        let error = record(&deny(), &judged.young).unwrap_err().to_string();
        assert!(error.contains("pkg@1.0"), "{error}");
        assert!(attribution.recorded().is_empty());
        attribution.discard();
    }

    #[test]
    fn a_rate_limited_lookup_is_asked_once_more_then_refused_when_denied() {
        let harness = Harness::new("age-429");
        harness.upstream.set(
            "/meta/pkg.json",
            Behavior::Reply(Reply::new(429, b"slow down").header("Retry-After", "0")),
        );
        refused_unanswered(&harness, Mode::Online, "rate-limited the lookup (429)");
        assert_eq!(harness.upstream.hits("/meta/pkg.json"), 2);
    }

    #[test]
    fn an_unreachable_registry_is_refused_when_denied() {
        let harness = Harness::new("age-503");
        harness
            .upstream
            .set("/meta/pkg.json", Behavior::Reply(Reply::new(503, b"down")));
        refused_unanswered(&harness, Mode::Online, "upstream answered 503");
        let harness = Harness::new("age-drop");
        harness.upstream.set("/meta/pkg.json", Behavior::Drop);
        refused_unanswered(&harness, Mode::Online, "is unreachable");
    }

    #[test]
    fn an_offline_miss_is_refused_when_denied() {
        let harness = Harness::new("age-offline");
        refused_unanswered(&harness, Mode::Offline, "offline, and");
        assert!(harness.upstream.seen().is_empty());
    }
}
