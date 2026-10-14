# FOLLOW-UPS — open work and decisions

The one ordered to-do list. Every item here is open, and each is one line
(or a short paragraph) pointing at the GitHub issue that holds the detail:
the file paths, the options, and the pick. "Next up, in order" is the order
of work; decisions block their items until the owner makes them; everything
else is under "Open work", where the quality-review list (#264) is ordered
and the macOS gate is last by the owner's choice. When an item ships, delete
its line; its pull request description is the record of what was done and
how it was reviewed. Designs for work not yet built live in
`docs/agent/DESIGNS.md`; known, accepted gaps live in
`docs/human/LIMITATIONS.md`. Code comments cite an item by its title, never
by position.

## Next up, in order

The resolution proxy (#68) is built: every ecosystem resolves confined
through it, and the door has no unsandboxed mode (#208). Left of it:

1. **#201: docker and `greyward-isolate`.** The podman backend and `ward doctor
   --isolation` are built. Docker cannot pass the relay's descriptors
   into a container, and the setuid `greyward-isolate` helper needs a root
   install to build and test.

The macOS door (Seatbelt rules, the Mach allow-list from one run of
`tools/proxy_spike/macos_mach.sh` on a Mac, tree freeze) is not one of
these; it waits with the macOS gate below.

Next: what is left of the quality review (#264), under "Open
work", in its listed order.

## Decisions waiting on the owner

None open.

## Open work, each its own pull request

- **#655: hand-hashed Python adoption.** Test the documented conversion to a compiled lock and signed receipt, then consider an explicit adoption command.

- **#634: safe uv configuration.** Preserve a reviewed scalar allowlist from the signed resolution snapshot while keeping mandatory interpreter, keyring, download and index restrictions.
- **#635: Python metadata retry evidence.** Add a replayable real allowed backend proving the accepted fetch ledger and policy facts survive retries and metadata cache reuse.
- **Found in the review of #567 to #610 (2026-10-06).** One checklist issue per theme:
  - #615 remaining design questions: SRI candidate choice, cargo's symlinked members, the `hard_link_target` doc. The issue is closed; its closing comment keeps these three open under their original conditions.
- **Found in #617 and #618 (2026-10-07).** One checklist issue per theme:
  - #620 test gaps: the dev-files hook for tailors other than Ruby, to add with the next tailor whose host-header fallback changes.
- **#464: macOS supervision: deferred notification-pipe initialization and validation.** Deferred by the owner on 2026-10-04.
- **macOS batch from a MacBook run (#728 to #735).** #742 made the crate compile for macOS, gave macOS refusals their own wording, and made published files follow the umask (#732 closed). Each item below needs a run on a Mac:
  - #728 compile and `cargo test` on a Mac (the fix was type-checked from Linux only).
  - #730 `ward doctor --isolation` and refusal wording, read on a Mac.
  - #733 published-file modes under a Mac umask.
  - #729, #731, #734, #735: rename swap, `F_GETPATH` after a rename, search-only directories, APFS clone. Not started: each needs Mac runtime behavior to build against.
- **#495: explicit Python package sources.** Define per-package source and metadata-build trust rules for PyTorch-style indexes. Keep undeclared indexes refused until that design ships.
- **Action leftovers (#427).** Left: the first tag that carries
  `action.yml` (at that tag, change `@main` in `action.yml`'s header and in
  CLI.md to it). The opt-in store cache shipped.
- **A shared system store at `/opt/greyward/store`: review, then build (#69).**
  The design is DESIGNS.md §7 (2026-10-05). Next: an independent review
  round, then its four implementation PRs in order.

- **Adversarial audit of 2026-10-12.** A whole-codebase review by parallel
  auditors; every item below was demonstrated or traced in the code. One
  issue and one PR each, most severe first:
  - #704 tailors: drift between the seven copies (run env, attest without a lock, atomic edits).
  - #706 architecture test skips production code below a test module.
  - #707 tests: podman cancellation under load, nss3 on Ubuntu, orphan fixture.
  - #710 maintainability: split read/write functions, one test env helper.
- **Follow-ups from the 2026-10-12 audit PRs.** One issue each, with the options and the pick:
  - #717 build and fmt arguments must still be UTF-8 (from #700).
  - #718 resolution receipts accept duplicate JSON keys (from #709).
  - #719 tests: end-to-end for plan's stdout redirect and `-q` with a package.json script (from #701).
  - #721 the remaining direct HOME reads go through the shared resolver.
  - #726 sandbox: bubblewrap fd binds and the `--args` descriptor (from #724).
  - #727 dirhash: Go module zips through the kernel zip reader (from #725).
  - #739 cargo: cached sdist lock exceptions, `cargo_locks` scope, plan-time cargo (from #737).
  - #740 node: link-site rename race, contained manifest reads, npm's host view (from #736).
- **Quality review of 2026-09-24 (#264).** A whole-codebase review after
  the 09-20 to 09-24 run. #264 (closed) holds the overall verdict. What
  is left, one issue and one PR each, in order:
  - #258: failure classes. `kernel::error` carries Refused, Stale, Unsupported and Network to exit statuses 3 to 6 (a signal is already `128 + n`). Left: moving the `io::Error::new(e.kind(), format!(..))` re-wraps to `error::context` as each is touched.
  - #243 sandbox: the macOS Seatbelt profile reads all of /opt, its timezone rule is dead, and CI never runs it.
- **Found in the #399 release work (2026-10-03).** One issue and one PR each:
  - #330 sandbox: HostView::RuntimeOnly is a no-op on macOS.
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
  - #300 heavy: the Elixir end-to-end test cannot run on ubuntu-22.04 (OTP needs glibc 2.43).
  - #307 archive: a tarball with macOS AppleDouble (`._name`) members is refused on macOS but extracted on Linux. The extraction carries `--no-mac-metadata`; the listing carries no restore flag (bsdtar documents them for other modes). On the Mac, try `/usr/bin/tar --no-mac-metadata -tf` on such a tarball: if it accepts the flag and prints the `._` members, add it to `TAR_LIST_FLAGS` and close.
- **The release catalog and the company layer (#404, #405).** Key and
  credential policy decided 2026-10-03 (#72): trusted keys are entries in
  the files of the machine/home policy chain, rotation is a commit to that
  policy, and revocation is removal from the list, after which `ward audit`
  fails any record the removed key signed. The private-registry test
  account is a GitHub Packages registry under the DigitalWestern org. This
  unblocks the authenticated parts of `docs/agent/DESIGNS.md` §2 (WP3,
  #404) and §4 (WP5, #405). §2 PR 0, the provider evidence spike, is done
  (2026-10-14: §2 "PR 0 evidence", fixtures in `tests/fixtures/catalog/`).
  Next is PR 1 with Rust as the first provider, once the owner approves
  the trust root and the §2 proposal on snapshot expiry, rollback
  rejection and offline policy freshness.
- **macOS arm64 gate. Last, by the owner's choice.** The suites
  below and the two-machine lock diff passed on the Mac on 2026-09-25
  (after #305); `tests/supervise_signals.rs` (#57) and the Mach allow-list
  are what is left. Run on the Mac:
  `cargo test`, `cargo test --test gc -- --ignored`,
  `cargo test --test cli audit`, and
  `cargo test --test toolchain_lock -- --ignored`, including the
  case-insensitive-filesystem paths the root-key code relies on. Darwin
  identity goldens must stay byte-identical. It also covers
  `cargo test --test supervise_signals` for the per-operation signal
  sessions (#57; everything but the `/proc` cases runs there), and the
  resolution proxy's Mach allow-list (`tools/proxy_spike/macos_mach.sh`). Nothing Linux-side
  clears this.

- **#637: configurable Ruby and Elixir manifest inputs.** Design narrower explicit declarations with conservative coverage as the default.
- **#638: authenticated Hex cache.** Keep private homes until a data-only persistent cache has reviewed integrity and tenant boundaries.
- **#639: resolution publication concurrency.** Add deterministic full planner-to-closure race tests for Ruby and Elixir.
- **#754: Ruby's toolchain source.** The portable-ruby channel `tools/catalog.py` reads has stopped moving, and the default Ruby it pins, 3.4.6, is a prerelease.

- #640: Define independent .NET lock semantic verification for executable MSBuild projects.
- #641: Design policy-owned NuGet feeds, credentials, signatures and cache boundaries.
- #642: Design declared MSBuild resolution inputs with conservative fallback.

- #645: Design Docker relay descriptor transport and the privileged helper installation boundary.
- #646: Design policy-owned Podman runtime and storage configuration with tenant boundaries.
- #647: Design persisted owned-container recovery and stopped-process proof after crashes.
- #648: Require a supported-Podman CI lane and forced-backend real ecosystem coverage.

- #649: Validate the documented signing workflow on fresh Linux runners and adversarial inputs.
- #650: Publish trusted admission results on the exact verified candidate commit.

- #257: Finish explicit Context ownership and independent attribution. Thread-bound policy, key and strictness scopes support synchronous operations.

- #651: carry explicit operation Context settings and independently owned attribution through the CLI, completing #257.

- **#652: finish typed resolution failures and retained error categories.** Separate policy refusal, byte-validation and offline failures in resolution Facts, then migrate remaining wrappers with real CLI coverage.

- #653: detect ecosystem comparisons across Rust line boundaries with a bounded token scan and adversarial fixtures.
