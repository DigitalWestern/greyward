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
- **#656: harness HOME containment.** Add alternate-spelling coverage and define physical containment with the existing offline exceptions in the next shared-harness change.
- **#657: native_libs probe target directory.** Give the Rust probe build an explicit `--target-dir` so an inherited `CARGO_TARGET_DIR` cannot hide its output, and list `GREYWARD_STORE` in the local e2e recipe.

- **#634: safe uv configuration.** Preserve a reviewed scalar allowlist from the signed resolution snapshot while keeping mandatory interpreter, keyring, download and index restrictions.
- **#635: Python metadata retry evidence.** Add a replayable real allowed backend proving the accepted fetch ledger and policy facts survive retries and metadata cache reuse.
- **#636: long TMPDIR proxy tests.** Give the Unix-listener test a short, separately owned socket directory while keeping large stores under the caller's TMPDIR.
- **Found in the review of #567 to #610 (2026-10-06).** One checklist issue per theme:
  - #615 remaining design questions: SRI candidate choice, cargo's symlinked members, the `hard_link_target` doc. The issue is closed; its closing comment keeps these three open under their original conditions.
- **Found in #617 and #618 (2026-10-07).** One checklist issue per theme:
  - #620 test gaps: the dev-files hook for tailors other than Ruby, to add with the next tailor whose host-header fallback changes.
- **#464: macOS supervision: deferred notification-pipe initialization and validation.** Deferred by the owner on 2026-10-04.
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
  - #669 sandbox: build scripts read ward's whole environment through bwrap's PID 1 (`/proc/1/environ`).
  - #670 policy: a reused Node object drops the three artifact exception kinds, so `--strict` and deny lists pass.
  - #671 cargo: a `.cargo/config.toml` `paths` override replaces a verified crate, and attest signs it.
  - #682 resolve: transaction recovery treats any error as a missing folder and releases the originals.
  - #687 python: uv.lock sources classified by substring drop GitLab and Gitea index packages.
  - #672 ci: heavy-unlabel.yml puts a fork's branch name into a jq program with a write token.
  - #673 python: `--frozen` can re-lock `requirements.lock.txt` (the #223 fix missed Python).
  - #674 archive: extraction as root keeps setuid bits and archive owners.
  - #675 zip extraction misses the tar path's size, duplicate-name and mode rules.
  - #676 store: `gc --reset` deletes user files in a directory that is not a store.
  - #684 resolve: git-shaped requests to any host record no policy exception.
  - #685 cargo: a replacement source runs a project-chosen credential provider.
  - #688 closure and SBOM: package names are never checked against the installed bytes.
  - #689 python: a malformed or md5 hash triggers a re-lock that drops the user's pins.
  - #690 python: `setup.cfg` reading disagrees with setuptools.
  - #692 node: importers differ on link containment, workspace keys and skipped optional deps.
  - #693 node: the project's own lifecycle scripts never run, unrecorded.
  - #694 node: npm lock stays fresh when a workspace member is added; shrinkwrap is never read.
  - #679 sandbox: a host-view setup error triggers a lasting host fallback.
  - #681 policy: `GREYWARD_STRICT=true`, a dangling policy symlink and an empty HOME load as permissive.
  - #683 resolve: transaction undo can lose a concurrent edit.
  - #696 dotnet: every build downloads every nupkg again; no offline build.
  - #677 store: whole-filesystem `syncfs` under the publish lock.
  - #700 cli: a non-UTF-8 argument or a deleted working directory panics.
  - #701 cli: `-q` discards the user program's stderr; `plan --json` stdout.
  - #702 cli: the child PATH adds the cwd when PATH is unset and splits paths containing `:`.
  - #698 release: ward's binary is checked only against a same-release checksum; install.sh replaces first.
  - #704 tailors: drift between the seven copies (run env, attest without a lock, atomic edits).
  - #706 architecture test skips production code below a test module.
  - #695 node: nested bins, `gypfile`, empty `install`, bin dotfiles.
  - #699 catalog: CI re-checks sampled rows only; CDN first hops; nativelibs source policy.
  - #678 store: run holds the lease, crash temps, a gc doc sentence.
  - #680 sandbox: read-only bind under a writable bind; relative PATH bwrap lookup.
  - #686 resolve: tokens in URL paths reach records; unbounded cache and buffers.
  - #691 python: launcher shebangs with a space or over 255 bytes.
  - #697 cargo, ruby, elixir, gitsrc smaller gaps.
  - #703 cli: completion script names and error text.
  - #705 ui and fsops: fd restore and close-on-exec.
  - #707 tests: podman cancellation under load, nss3 on Ubuntu, orphan fixture.
  - #708 archive: bzip2/xz streams, dirhash zip, conda zstd cap.
  - #709 audit and action: duplicate JSON keys, base64, the Action policy input warning.
  - #710 maintainability: split read/write functions, one test env helper.
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
  #404) and §4 (WP5, #405); §2 PR 0, the provider evidence spike, comes
  first.
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

- #640: Define independent .NET lock semantic verification for executable MSBuild projects.
- #641: Design policy-owned NuGet feeds, credentials, signatures and cache boundaries.
- #642: Design declared MSBuild resolution inputs with conservative fallback.
- #643: Cover unsupported future-tailor attest guards with focused unit tests.

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

- #662: recapture `docs/human/GETTING-STARTED.md` with v0.2.0. Its blocks still say they are 0.1.0 output, but the rename changed the names in them.
