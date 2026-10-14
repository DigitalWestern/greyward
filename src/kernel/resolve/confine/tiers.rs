//! Isolation tiers: which engine can isolate a resolution tool on this
//! machine, and the refusal when none can (part of [`super`]).

use crate::kernel::activity::StoreActivity;
use crate::kernel::sandbox;
use std::io;

/// An engine that can isolate a resolution tool on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Bubblewrap,
    /// Rootless podman (`super::container`), where bubblewrap cannot make
    /// a user namespace.
    Podman,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Engine::Bubblewrap => "bubblewrap",
            Engine::Podman => "podman",
        }
    }
}

/// One engine that is usable here, and whether it can fence the network
/// to the proxy (the `confined` tier) or only isolate files and processes
/// (the `isolated` tier, which records `unconfined-resolution`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierOffer {
    pub engine: Engine,
    pub fenced: bool,
}

impl TierOffer {
    /// The record's `isolation` field.
    pub fn isolation(self) -> &'static str {
        if self.fenced {
            "confined"
        } else {
            "isolated"
        }
    }

    /// The exception kinds a run in this tier records.
    pub fn exceptions(self) -> &'static [&'static str] {
        if self.fenced {
            &[]
        } else {
            &[crate::kernel::policy::UNCONFINED_RESOLUTION]
        }
    }
}

/// A capability this machine lacks, why, and how to get it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    pub capability: &'static str,
    pub reason: String,
    pub fix: String,
}

/// Every engine this build of ward can try, probed: what is usable and
/// what is not. An interrupt during a probe is returned as the error it is.
pub fn probe_tiers(activity: &StoreActivity) -> io::Result<(Vec<TierOffer>, Vec<Missing>)> {
    #[cfg(test)]
    if let Some(tiers) = TIERS_FOR_TEST.with(|tiers| tiers.borrow().clone()) {
        return Ok(tiers);
    }
    if cfg!(target_os = "macos") {
        return Ok((Vec::new(), vec![macos_gap()]));
    }
    tiers_from(
        sandbox::bwrap_preflight_with_activity(Some(activity)).map(|_| ()),
        || crate::kernel::resolve::container::preflight(activity).map(|_| ()),
    )
}

/// The one gap on macOS, where no engine can isolate a resolution tool
/// yet. Bubblewrap and podman are Linux engines (podman would mount this
/// Mach-O binary as the relay in a Linux container), so neither is probed
/// and no Linux fix is offered (#732).
pub fn macos_gap() -> Missing {
    Missing {
        capability: "macOS isolation",
        reason: "ward has no isolation engine for macOS yet".to_string(),
        fix: "run commands that need a resolution tool on a Linux machine or in Linux CI"
            .to_string(),
    }
}

/// The offers and gaps the preflights make: bubblewrap first, and the
/// container engine only where bubblewrap is unusable, so a host with the
/// native sandbox never pays for a podman probe. An interrupt is no
/// verdict: it stops the command (exit 130), so it is passed through
/// rather than reported as a missing engine (#289).
fn tiers_from(
    bwrap: io::Result<()>,
    podman: impl FnOnce() -> io::Result<()>,
) -> io::Result<(Vec<TierOffer>, Vec<Missing>)> {
    let mut offers = Vec::new();
    let mut missing = Vec::new();
    let interrupted = |error: &io::Error| crate::kernel::supervise::stop_signal(error).is_some();
    match bwrap {
        Ok(()) => {
            offers.push(TierOffer {
                engine: Engine::Bubblewrap,
                fenced: true,
            });
            return Ok((offers, missing));
        }
        Err(error) if interrupted(&error) => return Err(error),
        Err(error) => missing.push(Missing {
            capability: "bubblewrap",
            reason: error.to_string(),
            fix: "install bubblewrap and allow it unprivileged user namespaces".to_string(),
        }),
    }
    match podman() {
        Ok(()) => offers.push(TierOffer {
            engine: Engine::Podman,
            fenced: true,
        }),
        Err(error) if interrupted(&error) => return Err(error),
        Err(error) => missing.push(Missing {
            capability: "container engine",
            reason: error.to_string(),
            fix: "install podman, with subordinate IDs for this user in /etc/subuid and \
                  /etc/subgid and cgroup v2"
                .to_string(),
        }),
    }
    Ok((offers, missing))
}

#[cfg(test)]
thread_local! {
    /// What `probe_tiers` reports on this thread instead of probing, for
    /// the door's tier tests. The run itself still uses bubblewrap.
    pub(crate) static TIERS_FOR_TEST: std::cell::RefCell<Option<(Vec<TierOffer>, Vec<Missing>)>> =
        const { std::cell::RefCell::new(None) };
}

/// The isolation rule: the strongest offer wins; a fenced one always
/// beats an unfenced one. An unfenced offer is refused when policy denies
/// `unconfined-resolution`. With no usable offer, the refusal names the
/// tool, why it needs isolation, and every missing capability with its fix.
pub fn choose_tier(
    offers: &[TierOffer],
    missing: &[Missing],
    unconfined_denied: bool,
    tool: &str,
    why: &str,
) -> io::Result<TierOffer> {
    choose_tier_on(
        cfg!(target_os = "macos"),
        offers,
        missing,
        unconfined_denied,
        tool,
        why,
    )
}

/// [`choose_tier`] with the host named, so the macOS refusal is testable
/// anywhere.
fn choose_tier_on(
    macos: bool,
    offers: &[TierOffer],
    missing: &[Missing],
    unconfined_denied: bool,
    tool: &str,
    why: &str,
) -> io::Result<TierOffer> {
    if let Some(offer) = offers.iter().find(|offer| offer.fenced) {
        return Ok(*offer);
    }
    let unfenced = offers.iter().find(|offer| !offer.fenced);
    if let (Some(offer), false) = (unfenced, unconfined_denied) {
        return Ok(*offer);
    }
    let mut message = format!("{tool} {why}, so it runs only in isolation, and ");
    match unfenced {
        Some(offer) => message.push_str(&format!(
            "the only isolation here ({}) cannot fence its network to ward's proxy, which \
             policy denies (unconfined-resolution)",
            offer.engine.name()
        )),
        None => message.push_str("this machine cannot isolate it"),
    }
    for gap in missing {
        message.push_str(&format!(
            ". {}: {} (fix: {})",
            gap.capability, gap.reason, gap.fix
        ));
    }
    message.push_str(if macos {
        MACOS_UNSUPPORTED
    } else {
        ". This build of ward has no isolation helper (greyward-isolate), so enable one of the \
         above and run the command again (`ward doctor --isolation` shows each)"
    });
    // An engine is here and the policy turned it down: a refusal. No
    // engine at all: something this machine does not support.
    Err(match unfenced {
        Some(_) => crate::kernel::error::refused(io::ErrorKind::Unsupported, message),
        None => io::Error::new(io::ErrorKind::Unsupported, message),
    })
}

/// How a macOS refusal ends: what cannot run there, said plainly. Not a
/// list of commands: a sync that has to plan reaches the door too.
const MACOS_UNSUPPORTED: &str = ". ward cannot run resolution tools on macOS yet, so any command \
     that needs one is refused here";

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(fenced: bool) -> TierOffer {
        TierOffer {
            engine: Engine::Bubblewrap,
            fenced,
        }
    }

    fn missing() -> Vec<Missing> {
        vec![Missing {
            capability: "bubblewrap",
            reason: "setting up uid map: Permission denied".to_string(),
            fix: "install bubblewrap and allow it unprivileged user namespaces".to_string(),
        }]
    }
    #[test]
    fn a_fenced_engine_is_chosen_first() {
        let chosen = choose_tier(&[offer(false), offer(true)], &[], true, "npm", "x").unwrap();
        assert!(chosen.fenced);
        assert_eq!(chosen.isolation(), "confined");
        assert!(chosen.exceptions().is_empty());
    }

    #[test]
    fn an_unfenced_engine_records_unconfined_resolution_unless_denied() {
        let chosen = choose_tier(&[offer(false)], &[], false, "npm", "x").unwrap();
        assert_eq!(chosen.isolation(), "isolated");
        assert_eq!(chosen.exceptions(), &["unconfined-resolution"]);
        let refused = choose_tier(&[offer(false)], &missing(), true, "npm", "x")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("unconfined-resolution"), "{refused}");
    }

    /// An interrupt during the bubblewrap probe stops the command: it is
    /// returned as the interrupt (main exits 130), with no "install
    /// bubblewrap" advice (#289). Any other failure is a missing engine.
    #[test]
    fn an_interrupted_probe_is_no_missing_engine() {
        use std::os::unix::process::ExitStatusExt;
        let interrupt = io::Error::new(
            io::ErrorKind::Interrupted,
            crate::kernel::supervise::Interrupted {
                signal: libc::SIGINT,
                status: std::process::ExitStatus::from_raw(libc::SIGINT),
            },
        );
        let unavailable = || io::Error::new(io::ErrorKind::Unsupported, "no bwrap");
        let no_podman = || {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "podman not found",
            ))
        };
        let error = tiers_from(Err(interrupt), no_podman).unwrap_err();
        assert_eq!(
            crate::kernel::supervise::stop_signal(&error),
            Some(libc::SIGINT)
        );
        assert!(!error.to_string().contains("install bubblewrap"), "{error}");

        let (offers, missing) = tiers_from(Err(unavailable()), no_podman).unwrap();
        assert!(offers.is_empty());
        assert_eq!(missing.len(), 2);
        assert_eq!(missing[0].reason, "no bwrap");
        assert_eq!(missing[1].capability, "container engine");
        assert_eq!(missing[1].reason, "podman not found");
        let (offers, missing) = tiers_from(Ok(()), || panic!("probed podman")).unwrap();
        assert_eq!(offers, vec![offer(true)]);
        assert!(missing.is_empty());
    }

    /// Without bubblewrap, a working podman is the fenced tier; an
    /// interrupt during its probe is the interrupt.
    #[test]
    fn podman_is_the_fenced_tier_where_bubblewrap_is_missing() {
        use std::os::unix::process::ExitStatusExt;
        let unavailable = || Err(io::Error::new(io::ErrorKind::Unsupported, "no bwrap"));
        let (offers, missing) = tiers_from(unavailable(), || Ok(())).unwrap();
        assert_eq!(
            offers,
            vec![TierOffer {
                engine: Engine::Podman,
                fenced: true
            }]
        );
        assert_eq!(missing.len(), 1);
        let tier = choose_tier(&offers, &missing, true, "Bundler", "evaluates").unwrap();
        assert_eq!(tier.isolation(), "confined");
        let error = tiers_from(unavailable(), || {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                crate::kernel::supervise::Interrupted {
                    signal: libc::SIGTERM,
                    status: std::process::ExitStatus::from_raw(libc::SIGTERM),
                },
            ))
        })
        .unwrap_err();
        assert_eq!(
            crate::kernel::supervise::stop_signal(&error),
            Some(libc::SIGTERM)
        );
    }

    #[test]
    fn no_engine_names_the_tool_why_and_every_missing_capability() {
        let error =
            choose_tier(&[], &missing(), false, "Bundler", "evaluates the Gemfile").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let message = error.to_string();
        for needle in [
            "Bundler evaluates the Gemfile",
            "bubblewrap: setting up uid map: Permission denied",
            "fix: install bubblewrap",
            "no isolation helper",
        ] {
            assert!(message.contains(needle), "{needle}: {message}");
        }
    }

    /// On macOS the refusal names the missing macOS engine and gives no
    /// Linux repair steps; the Linux refusal is unchanged (#732).
    #[test]
    fn a_macos_refusal_gives_no_linux_advice() {
        let error =
            choose_tier_on(true, &[], &[macos_gap()], false, "npm", "runs scripts").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let message = error.to_string();
        for needle in [
            "bubblewrap",
            "podman",
            "subuid",
            "subgid",
            "cgroup",
            "namespaces",
        ] {
            assert!(!message.contains(needle), "{needle}: {message}");
        }
        for needle in [
            "npm runs scripts",
            "macOS isolation: ward has no isolation engine for macOS yet",
            "cannot run resolution tools on macOS yet",
        ] {
            assert!(message.contains(needle), "{needle}: {message}");
        }
        let linux = choose_tier_on(false, &[], &missing(), false, "Bundler", "evaluates")
            .unwrap_err()
            .to_string();
        assert_eq!(
            linux,
            "Bundler evaluates, so it runs only in isolation, and this machine cannot isolate \
             it. bubblewrap: setting up uid map: Permission denied (fix: install bubblewrap and \
             allow it unprivileged user namespaces). This build of ward has no isolation helper \
             (greyward-isolate), so enable one of the above and run the command again (`ward \
             doctor --isolation` shows each)"
        );
    }
}
