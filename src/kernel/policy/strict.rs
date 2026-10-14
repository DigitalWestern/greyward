//! Strictness asked for outside the policy files: `GREYWARD_STRICT` and
//! the command line's `--strict`.

use super::{Policy, PolicySource, SourceOrigin, StrictSource, NEXT_SCOPE_ID};
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

/// The values `GREYWARD_STRICT` takes, as its refusal names them.
pub const STRICT_VALUES: &str = "1, true or yes to refuse every policy exception; 0, false, no \
or empty for none (any case)";

/// What `GREYWARD_STRICT` asks for: `1`, `true` or `yes` is strict, and
/// unset, empty, `0`, `false` or `no` is not, in any case and with
/// surrounding blanks ignored, the set `CI` is read with. Any other value is
/// an error: a typo in a setting that only ever tightens policy must not
/// read as permissive (#681).
pub fn env_strict() -> Result<bool, String> {
    parse_strict(std::env::var_os("GREYWARD_STRICT").as_deref())
}

pub(super) fn parse_strict(value: Option<&std::ffi::OsStr>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    let text = value.to_string_lossy();
    let word = text.trim();
    if word.is_empty()
        || ["0", "false", "no"]
            .iter()
            .any(|v| word.eq_ignore_ascii_case(v))
    {
        return Ok(false);
    }
    if ["1", "true", "yes"]
        .iter()
        .any(|v| word.eq_ignore_ascii_case(v))
    {
        return Ok(true);
    }
    Err(format!(
        "GREYWARD_STRICT={text:?} is not a value ward knows: use {STRICT_VALUES}"
    ))
}

/// Apply the strictness requested outside the policy files: `GREYWARD_STRICT`
/// and `--strict` (`cli_strict`). Shared by every loader and by the
/// fallback in `current`, so a policy is never built without them. A value
/// `env_strict` refuses counts as strict here: `commands::dispatch` refuses
/// it before any verb runs, and anything that reads the policy without
/// passing through there fails closed.
pub(super) fn apply_requested_strictness(
    policy: &mut Policy,
    sources: &mut Vec<PolicySource>,
    cli_strict: bool,
) {
    let env_strict = env_strict().unwrap_or(true);
    // A file that already set `strict = true` keeps the attribution: it is
    // the source that outlives the command, so dropping --strict or
    // unsetting GREYWARD_STRICT would not lift the refusal and a message that
    // said so would be wrong. Only when no file asked for strictness is
    // the flag or the variable the thing to change, flag first because it
    // is the one on the line the reader just typed.
    // Between the two, the variable outlives the command as well: with
    // both set, dropping --strict leaves GREYWARD_STRICT=1 refusing, so the
    // flag is named only when it is the whole reason.
    if policy.strict_source.is_none() {
        if env_strict {
            policy.strict_source = Some(StrictSource::Env);
        } else if cli_strict {
            policy.strict_source = Some(StrictSource::Flag);
        }
    }
    policy.strict |= cli_strict || env_strict;
    if cli_strict {
        sources.push(PolicySource {
            origin: SourceOrigin::Flag,
            path: None,
            strict: true,
            deny: BTreeSet::new(),
            trusted: None,
            min_age_days: None,
        });
    }
    if env_strict {
        sources.push(PolicySource {
            origin: SourceOrigin::Env,
            path: None,
            strict: true,
            deny: BTreeSet::new(),
            trusted: None,
            min_age_days: None,
        });
    }
}

thread_local! {
    static STRICT_SCOPES: std::cell::RefCell<Vec<(u64, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The command-line strict flag for one dispatch on the creating thread.
/// Policy loads snapshot it while this guard is held. Nested dispatches
/// restore their enclosing flag, and workers receive explicit policies.
///
/// ```compile_fail
/// let guard = greyward::kernel::policy::request_strict(true);
/// std::thread::spawn(move || drop(guard));
/// ```
///
/// ```compile_fail
/// let guard = greyward::kernel::policy::request_strict(true);
/// std::thread::scope(|scope| { scope.spawn(|| println!("{guard:?}")); });
/// ```
#[must_use = "the strict flag is in force only while its dispatch guard is held"]
#[derive(Debug)]
pub struct StrictScope {
    id: u64,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for StrictScope {
    fn drop(&mut self) {
        STRICT_SCOPES.with(|scopes| scopes.borrow_mut().retain(|(id, _)| *id != self.id));
    }
}

/// Install `--strict` for this dispatch, including an explicit false flag.
/// A later dispatch loads its own flag rather than inheriting the first one.
pub fn request_strict(strict: bool) -> StrictScope {
    let id = NEXT_SCOPE_ID.fetch_add(1, Ordering::Relaxed);
    STRICT_SCOPES.with(|scopes| scopes.borrow_mut().push((id, strict)));
    StrictScope {
        id,
        _thread_bound: std::marker::PhantomData,
    }
}

pub(super) fn requested_strict() -> bool {
    STRICT_SCOPES.with(|scopes| scopes.borrow().last().is_some_and(|(_, strict)| *strict))
}
