# Greyward limitations ledger

A standing, honest record of what Greyward fails to address or does not get
right. Items leave this list only when fixed and regression-tested. Each
entry says what breaks, for whom, and whether it fails loud or silent.

Platforms: macOS arm64 and Linux x86_64 (glibc). All GC-safety work
(Packages A–D, merged 2026-09-10) was validated on Linux only — **no macOS
validation since**. Linux claims are verified on Fedora 44; other glibc
distros are untested. Intel macOS, aarch64 Linux, and musl/Alpine are
unported (a pin-table row plus a wheel-tag band each, not a port).

## Kernel-wide

- **`ward fmt` is Rust-only**; other ecosystems fail clearly (the locked Rust release's
  rustfmt, or a local toolchain's own, no `Cargo.lock`). It writes no closure, so nothing
  roots the rustfmt object: `ward gc` between two runs can reclaim it, and the next
  `ward fmt` realizes it again (a download when gc also cleared the archive cache).
- **`ward audit` vouches for who wrote a record only under a `[signing]` policy.** Without
  a `[signing]` table in the machine policy it judges records on their contents, says that
  signatures were not checked, and `--signed` refuses to run. Under CI (`CI` set, not
  `false` or `0`) a plain audit refuses too, unless `--allow-unsigned` is passed. With
  one, a pass proves that
  every closure file in
  the working tree carries a valid signature from a key the machine policy trusts, that
  every detected ecosystem has its primary closure, that each record is current for the
  inputs on disk, and that no recorded exception is denied or unknown. It reads `greyward-toolchain.toml` the way
  `status` does: a missing lock, a missing section, a stale lock row, or a record built from
  another bundle than the lock names is `stale`. It does not prove the signer's sync was
  honest or safe to run. Every door that changes a lock (`add`/`remove`/`update`,
  missing-lock generation during `sync`/`plan`, `attest`) runs the ecosystem's tool confined
  through Greyward's proxy, and the signed resolution record says which ledger saw its traffic,
  but audit judges the record, not the run. Nor does it re-verify store bytes, re-check
  object metadata, or judge what
  `ward run`/`x` executed. A job that runs untrusted project code must not hold a signing
  key. The machine policy is whatever `GREYWARD_POLICY` or `$HOME` selects: the gate's
  workflow, environment, binary, and machine policy must be controlled outside the
  untrusted checkout, and pointing `GREYWARD_POLICY` at a checkout-controlled file gives that
  file machine authority. `projected_at` is authenticated metadata, not an expiry: a genuine
  old record whose recorded inputs still match passes. Any record the gate cannot believe or
  compare (no signature, no recorded inputs, no recorded platform, no exception record)
  fails as `outdated` rather than passing, so pre-signing projects need one `ward`
  under a trusted key before the gate is
  useful. An exception kind this binary does not know (a record written by a newer Greyward)
  fails as `unknown` rather than being permitted. Loud.
- **GC is conservative around what it cannot read.** Store jobs hold a shared activity
  lease; GC skips while work is active (older binaries do not know the protocol). `root/2`
  records survive moves, but a pathname-only root (the form before them) and an unreadable
  object record block the sweep — an unreadable registry record blocks it too. `ward gc
  --forget <key>` and `ward gc --drop-object <id>` are the give-up valves.
- **The GC safety guarantee has a stated boundary.** It covers cooperating Greyward processes
  on a local filesystem with working locks and atomic rename. Not covered: older binaries;
  programs run directly from store paths; malicious same-user modification; descendants
  outliving the awaited child; orphans after SIGKILL of the supervising Greyward; network
  filesystems, where `flock` is advisory in name only.
- **Signal delivery has three edges.** Parent-directed TERM is forwarded to the direct child;
  a group-directed TERM reaches parent and child independently and is forwarded too
  (at-least-once). Parent-only INT/QUIT/HUP are caught and waited on after startup, not
  forwarded — terminal process-group delivery (`^C`) is the supported path. A cancellation
  across the spawn boundary is never dropped. `128 + signal` is a shell-visible exit code, not
  a wait status. An inherited ignored SIGCHLD (`SIG_IGN` or `SA_NOCLDWAIT`) is overridden from
  Greyward's first supervised child on, for the life of the process, so no exit status is
  auto-reaped away; the child still execs with the inherited `SIG_IGN`. A TERM that reaches no
  child (it arrives after the child was reaped, while its output still drains) is re-raised
  when the last supervision ends, so Greyward stops as the inherited disposition says. Code that
  installs its own TERM/INT/HUP/QUIT handler after Greyward's first supervised child replaces Greyward's
  for good, and supervision stops forwarding that signal (debug builds assert against it).
- **The tools a sync runs find the project by pathname.** A sync holds the project
  directory open from its first read to its last write: detection, the project's own
  `.greyward/policy.toml`, manifests, locks, closures (including the ones root registration
  imports), `.venv`/`node_modules` links and `.greyward` all go through that one descriptor. The GC
  root and the per-project lock are keyed on the canonical path the project was opened at,
  never resolved again, and the sync refuses once that path stops naming the held directory
  (after the store wait, before each ecosystem, before a root is registered, and after the
  closure is renamed into place). The host-local ecosystem tools a sync starts outside the
  resolution sandbox (offline helpers of uv, npm, cargo, go, mix, bundle, dotnet, git) start
  in the held directory: the child enters it
  through the descriptor (`fchdir`), not the path. A sandboxed child (the `setup.py` probe,
  a sandboxed build in the project) has the held directory bound in through its descriptor
  and starts there, and a confined resolution snapshots the held directory. The inputs a
  tool is handed (a member manifest, a requirements file, `BUNDLE_GEMFILE`) are named
  relative to the directory it entered, or read from a held snapshot when they lie outside
  the project, so the tool opens them in the held directory too. The one absolute input
  left is `ward run`'s `BUNDLE_GEMFILE`: the user's command may start in a subdirectory and
  still needs the root Gemfile, so it is named by its full path, and Bundler in that
  command resolves the path when it reads it. Files above the project (a Cargo workspace
  root, a parent `go.work`, .NET `Directory.*` files, a parent `.greyward/policy.toml`) are read
  from the directories that contain the held one (`..` from its descriptor), not from the
  path's parents. Policy loading verifies each held ancestor still has its original name and
  refuses a changed chain, so a temporary move cannot lift a parent policy.
  The machine policy is read by path. `status`, `doctor` and the environment `run`
  and `env` build open the project once and read it through that descriptor. `audit` uses the same held project for policy, closures,
  detection, freshness, and resolution evidence. `gc --register` still opens it by path.
- **CLI exit statuses distinguish classified failures.** See the
  [CLI status table](CLI.md#conventions) for ordinary errors, usage errors,
  refusals (3), stale locks (4), unsupported requests (5) and signals.
  Completed `audit`, `status` and `doctor` reports retain their verdict codes.
  `run`, `x` and `fmt` pass the program's status through. A tool argument that is spelled like one of Greyward's
  own options needs `--` first: `-h`/`--help` for all four, and for `fmt` and `x` also the
  global options (`-C`, `-q`, `-v`, `--no-color`) while they precede the tool's first
  non-option word. `run` and `build` never take one, so they need no `--` for those.
- **`ward status` compares recorded inputs only.** `-r` includes, `requirements/` members,
  and workspace-member package.json are not recorded. Cargo/Ruby/Elixir/.NET compare the lock
  hash only; Go catches `require`/`replace` only via `go.sum`; a closure written before those
  fields were recorded is reported `unchecked` and fails the command, since nothing about it
  can be compared.
- **One toolchain per lock root.** Toolchain discovery is anchored at the project root
  where `greyward-toolchain.toml` sits, not at the current directory, so every developer, CI
  job and subdirectory produces the same consulted-path list and the same staleness
  verdict. The cost is that a toolchain source in a subdirectory — `web/.node-version`
  under a root-level lock — is not a toolchain source for Greyward, though uv or `nvm` would
  honor it. Per-subproject toolchains would need per-subproject sections and are not
  designed.
- **The two-machine lock diff has been run once, by hand.** A lock carries a row per
  platform and is written from the intersection of releases complete on both. On
  2026-09-25 a seven-ecosystem lock written on Linux synced unchanged on an arm64 Mac, the
  Mac wrote the same bytes from scratch, and `ward status` matched. No CI job repeats it, so
  a change after that date is proven by test, not by two machines.
- **A committed lock is a set of URLs to review.** A lock row's URL must sit under an
  endpoint the source policy admits for the row's own `provider`, and so must every
  redirect. GitHub's asset CDN (`objects.githubusercontent.com`,
  `release-assets.githubusercontent.com`) is admitted only as the target of a redirect
  from the publisher's own `github.com/<repo>/releases/download/` URL, never as the URL
  a row names, so every GitHub-hosted row says which repository it comes from. The
  conda-forge native libraries Python and npm builds link against go through the same
  policy, as the `conda-forge` publisher. A hostile lock can still name another file
  under that publisher's endpoints, or name a different shipped publisher as its provider. Reviewing a lock
  diff is reviewing its URLs and providers. A downloaded toolchain row can no longer
  name `file://` (a Rust `source = "path"` row names a local tree and downloads
  nothing); the generic fetch helper that package-registry downloads use still
  accepts it.
- **Greyward's own binary is trusted through one release key.** `install.sh`, `ward
  update --self` and the GitHub Action install a release only when its archive carries an
  Ed25519 signature by the release key, whose public half is compiled into ward and
  written into `install.sh`. The private half never reaches CI: release.yml makes a draft,
  and `tools/release-sign.sh` signs and publishes it on the maintainer's machine, so a
  token that can write releases cannot ship a binary those three accept. Before signing,
  it checks each archive's provenance attestation names the release workflow, the tag and
  the commit the repository's tag points at, so an older release's archive uploaded into a
  new draft is not signed. Each installer also requires the binary to report the release's
  own version, and only a named version replaces a newer ward. `install.sh` finds the
  latest release in the signed `LATEST` asset (one line, the tag) that
  `tools/release-sign.sh` keeps on the highest signed stable release only, and marks
  that release GitHub's latest. A writer of releases can point it only at a
  release the key signed: an older one installs on a machine with no ward, and the
  downgrade check refuses it over a newer one. Without curl, `install.sh` leaves the
  redirect to wget: busybox wget reads a relative `Location` as a host name, so behind a
  mirror that sends relative redirects, install curl or a full wget (GitHub's own
  redirect is absolute). Whoever holds the
  key can, and a lost key means a new one ships in a new `install.sh` and a new ward,
  which every existing ward must reach by `install.sh` once. The installer needs OpenSSL
  3.0 or newer to check the signature, and refuses without it. The `.sha256` beside each
  archive comes from the same release, so it only catches a corrupt download; the build
  provenance attestation (`gh attestation verify`) is a second check for people who use
  `gh`, not one any installer runs.
- **Frozen validation reads declarative files only.** A project whose only statement of
  its runtime version is computed — `setup.py` metadata, `mix.exs` compatibility, a
  Gemfile `ruby` directive — cannot be validated under `--frozen` and is refused with the
  declarative file to add. Reading those sources means running project code, which is
  exactly what frozen promises not to do.
- **A Python `requirements.lock.txt` is compiled for one platform and interpreter.**
  Greyward runs `uv pip compile` without `--universal`, so uv resolves for the machine it
  runs on, and the header names that platform, the Python version, and a digest of the
  requirements it came from. The platform is part of the check because the lock really
  is that platform's: a different machine can need different packages. `--frozen` never
  compiles the lock: on another platform, under another Python, or after the
  requirements changed (removing the last one included), it is refused as stale, exit 4,
  naming which of the three differs. A team that syncs on macOS and Linux commits the
  lock from the platform CI runs on. A `uv.lock` is universal and has no such limit. For
  a setup.py that computes its requirements, the digest covers the files that declare
  them: setup.py, setup.cfg, pyproject.toml, the files setup.cfg names with `file:`, and
  the requirements file the probe falls back on. `--frozen` checks it without running
  setup.py, and plans from a matching lock with no probe at all. A file setup.py opens by
  a path of its own is not covered: change it, and the lock is not stale until one of
  those files changes too. When the probe fails and the lock is compiled from the
  requirements file it falls back on, the header names that file (`source=`), and a
  reused lock reads its hash pins from it. setup.py still runs, confined and in memory,
  when there is no lock (it alone says whether there is anything to lock) and when the
  lock has no header. A direct reference in a matching lock is recorded from setup.py's
  metadata cache when `prepare` wrote one, and from the lock as it is otherwise (a
  fresh checkout under `--frozen`), so its wording can be uv's. A lock compiled before ward wrote that header names no source, so `--frozen`
  holds it to the requirements instead: every package they need here must be in it at
  a version they allow. An edit the locked version still satisfies (`six>=1.16` to
  `six>=1.15`) passes that check. One `ward` without `--frozen` writes the header.
- **`add` / `remove` / `update` run the ecosystem's tool in the resolution sandbox**, with
  no network of its own, through Greyward's resolution proxy: Go, Cargo, Node (npm and the pinned
  pnpm), Python (uv), Ruby (Bundler) and Elixir `update` (Mix). There is no unsandboxed fallback: a host where
  neither bubblewrap nor rootless podman can isolate the tool refuses the edit and names
  what is missing (`ward doctor --isolation`). macOS has no such engine yet, so every command
  that needs a resolution tool is refused there: run it on Linux.
  Refusal rows: Poetry/PDM, setup.py, `requirements/` dirs, Elixir add/remove, Yarn, .NET.
- **A Node `file:` or `link:` dependency outside the project is refused** by every door
  (edits, a missing lock, `attest`), naming the manifest and the path: the confined npm or
  pnpm reads the project alone, and a resolution record names files inside the project only.
  Move it inside the project, or depend on it from a registry. A Ruby `path:` gem outside
  the project is refused the same way at sync. A scoped registry in `.npmrc`
  and a direct-URL tarball are fetched through interception and recorded as
  `unattested-index`, which the company policy denies.
- **pnpm edits require a root `packageManager` field** with an exact pinned version.
  Membership is the `pnpm-lock.yaml` `importers` list and nothing else. **A member added since
  the last `pnpm install` is not in the lock and cannot be distinguished from a deliberate
  exclusion**, so edits refuse loudly with two remedies: `pnpm install` at the root, or a
  `.greyward` directory in it.
- **pnpm patches are resolution inputs only when `package.json` names them.** The patch
  files `pnpm.patchedDependencies` lists are in the resolution basis and the record, so a
  patch edited after signing reads as a change. The same setting in `pnpm-workspace.yaml`
  (pnpm 10) is not read: Greyward reads that file's `packages` alone.
- **An npm workspace member is edited at the root.** `ward add` in a member whose root
  `package.json` names it in `workspaces` runs npm in the member with the root as the lock
  root, so the root's `package-lock.json` (created there if it has none) and resolution record
  are what change. A pnpm member whose root has `pnpm-workspace.yaml` naming it but no
  `pnpm-lock.yaml` yet is placed at the root the same way. A member with a lock or a `.greyward`
  directory of its own is its own root. A sync run in a member (npm or pnpm) that has no lock
  of its own refuses, naming the root: run `ward` there.
- **Yarn classic edits remain a refusal** (no lockfile-only edit mode); run the Yarn command
  Greyward names. Yarn Berry is not imported (cache-zip checksums are not tarball integrity
  values).
- **`ward x` covers PyPI and npm**. A removed *node* environment orphans its node_modules
  forest under `<store>/forests/`, which plain `ward gc` never visits: only `ward gc
  --project` reclaims it. Cleanup stops with an error when a root's recorded originating
  store is unavailable, and skips a root with no request record whose owning store its
  closure does not name.
- **A store is never migrated.** The store carries a format marker (`<store>/format`), and
  this Greyward reads exactly one format. A store written before the marker existed, or by a
  newer Greyward, or whose marker is damaged or unreadable, is refused by every command that
  reads or writes the store. `ward store path` and `ward doctor` still report on it, and
  `ward gc --reset` empties it (the download cache is kept), after which every project
  syncs again. Nothing carries old objects across a format change. A directory with
  no marker and nothing a ward stores is not a store: it is refused, never reset, and
  a store is created only in an empty directory.
- **Unpinned host build inputs.** The Linux host C toolchain (gcc, binutils, glibc headers)
  and the macOS Xcode/clang/SDK are not in build identity — two hosts can produce different
  "identical" objects. The Linux OTP artifact needs glibc 2.43 and host `libcrypto.so.3`.
  Linux gem native extensions build against the host C runtime alone (glibc, kernel headers,
  libxcrypt, the compiler's own files): every other host header, `-l` library, static
  archive and pkg-config file is absent from the compiler's and linker's default search
  paths and from pkg-config in that sandbox. Other host shared libraries stay loadable so
  the compiler and linker themselves run: they are moved into a `.greyward-host-runtime`
  subdirectory of their library directory, which `ld` does not search, and reached through
  the sandbox's own copy of the loader cache (`/etc/ld.so.cache`), which names them there.
  The loader searches that cache after a program's own `DT_RUNPATH`, so a program a gem
  bundles and runs during its build loads its own copy of a library before the host's
  (#332). A library subdirectory
  with headers, static or libtool archives, `pkgconfig` or `cmake` under it
  (`/usr/lib64/perl5/CORE`, a Python package's CFFI headers, `/usr/lib64/libnl`), or that
  Greyward cannot list, is curated the same way, so an explicit `-I` or `-L` into it finds no
  header, archive, object, `lib*.so` symlink or linker script (#331); the compiler's own
  `gcc` and `clang` directories are kept whole, as are a versioned LLVM tree's
  (`llvm-<N>`) `bin` and `lib/clang`, where Ubuntu keeps clang's own headers; the rest
  of that tree, LLVM's own headers and archives, is curated. A `lib*.so` symlink or linker
  script marks a subdirectory for curation like a header does, except in a known plugin
  directory (`bfd-plugins`, `dri`, `sasl2`, `xtables`, `libibverbs`, `gtk-<N>`, any
  `modules` or `plugins`, and the rest of `PLUGIN_DIRS` in `src/kernel/hostview.rs`), where
  programs load those names and they stay. Two gaps: a regular ELF `lib*.so` in a curated
  subdirectory stays where it is (plugins and extension modules there are loaded by that
  path), so `-L` into it can link it; and a plugin directory missing from that list loses
  its `lib*.so` symlinks, so a program that loads one by that name fails in the build
  sandbox until the directory is added. Kept files are symlinks into
  one read-only bind of each whole curated host directory under `/.greyward-host-files` (#334),
  so every file the view hides is still readable there by that path: no default search
  path, pkg-config directory or symlink in the view names it, but a build that names
  `/.greyward-host-files` on purpose reads the host's development files. A build that
  resolves a kept file's real path reaches that copy too: `readlink -f
  /usr/lib64/libssl.so.3` names it under `/.greyward-host-files`, and a `-L` into that
  directory finds `libssl.so`. For the same reason `find -type f` in a curated directory
  does not list the libraries it kept, which are symlinks there (#559). Native
  gems also build with Greyward's pinned native library set mounted (zlib, openssl, libffi,
  libxml2, sqlite, ncurses and the rest of `nativelibs.rs`), and load it at run time through
  their rpath (#329); every Linux gems object with a native gem names that set, so those
  objects rebuild once after the change. An extconf that ignores pkg-config, `CPATH`,
  `LIBRARY_PATH` and mkmf's flags does not see the set. A gem
  that needs another host library fails that build, is rebuilt against the whole host, and
  records `host-build-inputs`, which a policy can deny. The build that failed may only have
  left its own gem and extension directories behind; anything else it changed in the gem
  home refuses the retry, and its HOME and TMPDIR are deleted before the retry starts. The
  object is then committed under its own `build_view = "host-fallback/1"` identity, keyed by
  which gems fell back and by a fingerprint of the host build inputs (`host_inputs`): every
  header, library, `pkgconfig` or `cmake` entry the C-runtime-only view hides or relocates,
  for each such symlink the file its chain finally resolves to (so a dropped `liblzma.so`
  covers the kept `liblzma.so.5.8.1` behind it), where `/usr/bin/cc` and `/usr/bin/c++`
  resolve, and every file under `/usr/lib/gcc` and `/usr/libexec/gcc`. The fingerprint is
  stat-based, never a hash of file contents: each entry counts by path, type, size,
  modification time and symlink target, and a resolved target by its inode and device too.
  A development package installed, removed or upgraded is detected through those file
  details; a file rewritten with bytes of the same size and its modification time put back
  is not. A directory it cannot read fails the sync rather than counting as empty. It is
  taken right before and right after each build against the whole host (about 12 ms on a
  Fedora 44 workstation); if the two differ, or two gems of one object fell back against
  different host states, the sync fails ("host development files changed during the build
  of <gem>; re-run Greyward"). A store record keyed by the runtime-only id and that build-time
  fingerprint lets a later sync over the same store, on any host whose build inputs
  fingerprint the same, reuse the object instead of rebuilding; the lookup fingerprints the
  host again, only when the runtime-only object is missing, and a host in another state
  misses the record and builds. What the fingerprint cannot see (file contents, anything
  outside the curated directories and the compiler) can still make two hosts with the same
  fingerprint build different bytes.
  Pure-Ruby gems compile nothing and install against the whole host. Setting the view up
  costs about a quarter of a second per native gem on a Fedora 44 workstation (about 300
  mounts), against about ten milliseconds for the whole host.
  Python sdist builds that compile Rust or mount the native-library set, and npm install
  scripts, follow the same rule (#328): they run against the C runtime alone first and fall
  back to the whole host with a `host-build-inputs` exception. A failed sdist attempt's
  output, log and (for Rust) unpacked source are reset before the retry; a failed npm
  attempt's package tree and scratch HOME go back to their snapshots. The wheel, and the
  Python or Node environment holding it, are committed under `host-fallback/1` identities
  that name what fell back (the sdist; `pkg:` entries for the environment). Every Linux
  Python environment with such an sdist and every Linux Node environment carries
  `build_view = "runtime-only/3"`, as does every Linux gems object. `/3` invalidates
  older objects that could link a lone `lib*.so` name outside the plugin directories
  (#559). The next sync rebuilds these objects once under the tighter view.
  One gap: when a build-requirement sdist falls back, its build environment is committed
  under a host-fallback id, and the wheel built in that environment names that realized id
  in its own `build_env` input. The parent environment is planned before any build runs, so
  its `pkg:` entry for the wheel names the planned sdist id, whose `build_env` is the build
  environment's runtime-only id: no committed wheel has that id. Unless the wheel's own
  build also fell back, the parent is committed under its runtime-only id, which does not
  change with the host state the build environment fell back against. Python
  sdists with no native or Rust input, and macOS builds, still see the whole host.
- **Pinned native-library objects are store-root-specific**: `native-libs/libset/3` includes
  the canonical `GREYWARD_STORE` root in its identity; moving a store requires re-realizing the
  libset. **Linux sandbox roots are canonical paths** (a symlink alias root is invisible).
  Both matter only to new callers.
- **Greyward's security claim is provenance, not runtime containment.** Acquisition and build
  happen behind one door, builds cannot reach the network, and every closure lists what went
  in and every exception waved through. A hostile package can still put its payload in its
  build output and run it at `ward run` time with full network. Do not describe Greyward
  as stopping malicious code from running.
- **Sandboxes are cooperative hermeticity, not hostile-code containment.** On Linux, Greyward scans
  every declared root, the cwd, the scratch and the fixed `/etc` entries it binds for Unix
  sockets before invoking bubblewrap. The build sandbox trusts `/usr` unscanned; the
  resolution sandbox scans `/usr` and the other system roots once per process. A socket created
  after the scan is not caught (the fmt host-socket scan is Linux-only too); build daemons can
  outlive a run. **Store objects are trusted from permissions + metadata**: same-user
  content replacement after commit is undetected.
- **No toolchain download is signature-checked when ward uses it.** ward compares each
  download with the digest in the catalog embedded in the binary, so that digest is as
  trustworthy as the Greyward release that ships it. When the catalogs are generated,
  `tools/catalog.py` checks the signature of each Rust release's channel manifest (not yet of
  `channel-rust-stable.toml`, which names the newest) and of Node's `SHASUMS256.txt`; every
  other source is **TOFU** (trust on first use: a checksum taken when the
  row was pinned, with no signature behind it), one row each in the sections below. What each
  upstream publishes is in `docs/agent/DESIGNS.md` §2 "PR 0 evidence"; checking it is WP3.
- **The conda-forge native libraries are TOFU.** `src/kernel/provider/nativelibs.rs` pins
  their sha256 from conda-forge's repodata, taken once. ward checks nothing signed for them,
  and PR 0 did not examine what conda-forge publishes.
- **Delegated planning runs in the resolution sandbox.** A Gemfile, a mix.exs and a
  csproj are code, and Go's, Cargo's, Node's, Python's (uv), Ruby's (Bundler), Elixir's
  (mix) and .NET's (restore) resolvers all run confined, reaching their registry only
  through Greyward's proxy.
- **Every tar archive is unpacked through the pre-materialization extractor**
  (`src/kernel/archive.rs`, #236). It reads every entry from the
  archive's own headers (ustar names and the POSIX prefix field, PAX `path`/`linkpath`/`size`,
  GNU long names), cross-checks that listing against `tar -t`, refuses the whole archive on an
  absolute name, `..`, a special file, an escaping symlink, a hard link to anything but an
  earlier regular file that survives `--strip-components` (#317), a hard link to itself, any
  name written twice (two files, a file and a hard link, a second spelling such as `pkg/./a`,
  or two names the strip folds into one; a repeated directory entry is fine, #542, #613), a name that is not
  UTF-8 or carries a control, bidirectional-override or zero-width character, two names that
  APFS would fold into one (by case or by Unicode normalization; for a per-platform build such
  as a toolchain or conda package, only on macOS, since Linux CPython and ncurses ship
  terminfo names like `2621A` beside `2621a`), or a layout it cannot model
  (sparse members, a global header that renames, a PAX key it does not know, unknown type
  letters, bad checksums), refuses past a 1 GiB running member-data budget before anything
  is written, and extracts with `TAR_OPTIONS` unset and tar told to restore no
  extended attributes, ACLs, file flags or AppleDouble metadata: an object holds names, bytes
  and the executable bit, nothing else. The one `tar -c` in the tree (git-source packing)
  lives there too, so no other production code names `/usr/bin/tar` at all — an
  architecture test fails the build if it does. PAX values other than `path`, `linkpath` and `size`
  may be any bytes and are never read. The `tar -t` listing carries only `--numeric-owner`:
  it writes nothing, and bsdtar documents the restore flags for other modes, so on `-t`
  they could only fail. That leaves a Mac-packed tarball's `._name` companions refused on
  macOS by the cross-check, as before, rather than extracted as the wrong tree (#307 stays
  open until a macOS run shows whether `--no-mac-metadata` on `-t` lifts it). Single
  manifests read out of an sdist come from the same validated in-process stream, never a
  second tar child. Zip archives (wheels, zip sdists, the Elixir release zip, Hex's own
  `.ez` archive and the outer zip of a `.conda` package) are read in process by one kernel
  reader under the tarball's name rules: no unsafe, invisible or twice-written name, no
  symlink or special file, no encrypted entry, and no ZIP64 or Unicode-name extra field
  that two zip readers would read differently. An sdist is built by pip from the tree ward
  unpacked, never from the archive. Each member must inflate to exactly the size
  it declares, and the declared sizes count against a budget (4 GiB for a wheel, 1 GiB for
  the rest) before anything is written. Modes follow pip: a file with any execute bit is
  0755, every other file 0644, and directory modes are ignored.
- When a store path holds a space, tab or newline, or puts an environment's interpreter
  past Linux's 256-byte `#!` limit, a wheel's own `#!python` script is installed unchanged
  under its own name in a private `bin/.ward-scripts/` directory, and `bin/<name>` is a
  `/bin/sh` wrapper that runs the interpreter on it. Its name in `sys.argv[0]` and
  `__file__` is the shipped one, but `__file__`'s directory is the private one, so such a
  script does not see data files placed beside it in `bin/`. Under an ordinary store path
  the script is installed in `bin/` with its `#!` line rewritten, as pip does.
- **`young-package` is judged once, when the lock is written.** The publish time and the
  resolution time are fixed in the resolution record then. A `min_age_days` raised later does
  not judge an already-locked version again; resolving again (`ward update`, or deleting the
  lock and syncing) does. A package the resolution tool fetched no metadata for is looked up
  by ward itself through the same proxy, one request per registry document (a package's
  page, a NuGet version's own document, or a Go version's checksum-database record), so a
  first lock of a large project makes up to one extra request per locked package. A cached
  copy that already holds the time of every version asked about is used without asking the
  registry again. A rate-limited lookup is asked once more after the registry's
  `Retry-After` (at most 10 seconds). A lookup that still fails (rate limit, server error, timeout, offline with nothing cached) leaves the
  publish time unknown, and the detail says which: with the kind denied that refuses the
  resolution, otherwise it is recorded as unknown. Hex's API allows 100 unauthenticated
  requests a minute, so a mix project with more locked packages than that, and no metadata
  already fetched for them, can hit it. Resolve again a minute later: the answers the first
  run got are cached, so the second asks only for the rest.
- **Go is judged by its place in the checksum database, not by a time.** Go's module proxy
  serves no upload time: `.info`'s `Time` is the commit's own, which whoever made the commit
  sets, so a fresh tag can claim any date. ward never reads it. Every Go version, tagged or a
  pseudo-version, is judged by its record number in `sum.golang.org`'s append-only log. Each
  signed tree head ward sees (go's own checksum-database traffic and ward's lookups) is checked
  against sum.golang.org's key and kept in the store with the local time it was seen. A version
  passes when its record is below the largest head (the one of the most records) seen at
  least `min_age_days` before the resolution. Otherwise its age is unknown ("logged after the
  largest checkpoint older than 7 days"): recorded, or refused under a policy that denies the
  kind. What follows:
  - A fresh store has only the head this ward carries. It is checked into the source
    (`src/tailors/go/sumdb-seed.txt`) and regenerated by hand before a release with
    `tools/sumdb_seed.py`, and the release workflow refuses a seed taken more than 60 days
    before the release commit. Until that head is `min_age_days` old, every Go version's age
    is unknown, so a policy that denies the kind refuses every Go resolution on a new machine
    for the first week after a release. After that, a version logged after the built-in head
    stays unknown until the store has seen a larger head that is old enough. A store that
    resolves Go regularly keeps its own.
  - The time the built-in head was taken sits beside the signed head, outside the signature:
    it is as trustworthy as ward's source, not as the log.
  - The heads are dated by the local clock. A clock set back when a head was seen dates it too
    early, and a version logged after it can then pass too soon.
  - The history (`<store>/resolve/tlog/sum.golang.org`) is trusted only as far as the store's
    permissions: whoever can write the store can add a head to it.
  - The record number comes from the lookup answer over TLS. ward checks the answer's signed
    head, that the record lies inside it, and that the record is exactly the asked version's
    two go.sum lines (anything else refuses the resolution), but fetches no proof that the
    record is in the log at that place.
  - ward checks no consistency proof between heads. A head with the size of one it holds but
    another root is refused as a fork of the log; two heads of different sizes are not proven
    to be the same log.
  - A module the checksum database does not log has no record number, so its age is unknown.
- **A requirements file is judged by each version's first file.** PyPI lets a file be added to
  an existing version later. A `uv.lock` names the files it locked, and each version is judged
  by the latest upload time among them; one named file the index gives no upload time leaves
  the version's age unknown. A compiled requirements file names only versions, so
  a version is judged by its earliest file, and a wheel added to an old version yesterday is
  not caught there.
- **A lock `young-package` cannot read refuses the run.** Its reader must account for every
  entry: a git, path or other-source entry it recognizes is left out, and anything it does not
  recognize (an npm entry with no `resolved`, a Cargo.lock crate without a version, a
  requirements line that is not an exact pin) refuses the run, so a package it skipped is
  never passed unjudged. That includes a `Gemfile.lock` from an old multi-source Gemfile,
  whose one `GEM` section lists several `remote:` lines and does not say which gem came from
  which: with the check on, such a lock is refused until the Gemfile gives each source its
  own `source` block and the lock is written again. A run that leaves no lock refuses too,
  except where the tool writes none for a project without dependencies: go writes no `go.sum`
  for a module that requires nothing, and mix writes no `mix.lock` for a project with no
  dependencies (mix.exs is code ward does not run, so a missing `mix.lock` is read as locking
  nothing).
- **`lookalike-name` is a name heuristic.** It compares against a fixed list of each registry's
  2,000 most popular names, checked in with the binary (`tools/popular.py` regenerates it), so a
  package that became popular since is not on it, and a legitimate package one edit from a
  popular one (a fork, a plugin named after its host) trips it. Go publishes no download counts,
  so its list ranks modules by how many other packages depend on them (packages.ecosyste.ms).
  Only registry packages are judged: git, path and other-index packages are not.
- **Records carrying the new kinds need this ward to read them.** A ward built before
  `young-package` existed reads a resolution record that carries it as malformed and records
  `unrecorded-resolution` instead of joining it, and its `ward audit` counts either new kind in a
  closure as of unknown kind. Update every machine that syncs or audits the project.

- **Private registries cover Python and npm only.** A `[sources]` entry or a
  `[[registry]]` for Go, Cargo, Ruby, .NET or Elixir is refused at load; those
  ecosystems use their public registries. In an enforced Python list uv gets one
  index, the default registry: a package that lives only on a later registry in the
  list is not found at resolution, though a lock that names that registry still syncs.
  Poetry's dependency-level `source = "..."` is not matched to a listed registry, so it
  stays an `unattested-index` exception. A pnpm lock entry with no tarball URL is
  fetched from `<registry><name>/-/<name>-<version>.tgz` under its scope's registry,
  which a registry with another tarball layout (GitHub Packages) does not serve.
  The SBOM's purl `repository_url` still comes from the file's host, not the
  recorded registry. The machine policy that declares registries and credentials is
  whatever `GREYWARD_POLICY` or `$HOME` selects, the same gap as `[signing]`: whoever
  controls the environment can replace it (#757). Artifacts a project declares for
  its install scripts (a `greyward` artifact with its own sha256 in `package.json`)
  are fetched from the URL the project names, not through the registry list: they are
  not registry packages, and the declared hash pins them. The `.npmrc` check before
  npm or pnpm starts reads the lock root's and the member's `.npmrc`, not registry
  settings in `pnpm-workspace.yaml`; a scope pointed elsewhere there still fails, at
  the proxy, with a less specific error. A wrong password on a configured registry
  surfaces as the tool's own 401, with no `fix:` line. `young-package` reads a
  configured registry's publish times where PyPI's and npm's are read: a Python
  index's JSON project page (PEP 691) and an npm registry's full packument. An index
  that serves HTML pages only, or a packument with no `time` map, gives none, so each
  package's age is unknown: recorded, or refused where the policy denies the kind.

## Python

Selection covers every patch of each maintained CPython minor that python-build-standalone
  published a checksummed build of for both platforms. A few patches never got one (3.10.0,
  3.10.1, 3.10.10, 3.11.0, 3.11.2; `tools/catalog.py python` reports them) and are refused. A
  two-part `.python-version` picks the default (3.12.14) on its minor, else the newest pinned
  patch; a three-part request must match a pin exactly.
- **python-build-standalone builds are TOFU.** Their digests come from the release's
  `SHA256SUMS` and GitHub's asset digest, neither signed. The project publishes GitHub
  artifact attestations (Sigstore) from release 20250317 on, which ward does not check yet; 33
  of the 73 shipped CPython releases come from older releases that have none.
- **uv is TOFU.** Its digest comes from the `.sha256` beside the archive and GitHub's asset
  digest. uv publishes artifact attestations, which ward does not check yet.
- **RECORD files are left as shipped**: not verified on install; importlib listings can lie;
  project-local/editable and direct requirements are skipped (`requirement-skipped`). **Sdists
  with dynamic build requirements** (PEP 517 `get_requires_for_build_wheel`) are unsupported —
  inspection is non-executing. Static backends are supported; `setup_requires` in legacy
  setup.py is unhandled — declare it in `pyproject.toml`. Rust sdists without a shipped
  `Cargo.lock` get a store-Cargo lock recorded `unattested-cargo-lock`; that lock is
  generated confined, through the resolution proxy, like a project's.
- **Immutable venvs are not drop-in venvs**: no activate scripts, and pip cannot mutate them.
  `ward run pip ...` and `ward run activate` are refused with the verb that replaces them
  (`ward add`, `ward run <command>`) rather than left to report a missing file, but **no pip
  shim and no `activate` script are planned**: a shim that accepted `pip install` would have
  to either mutate a read-only store object or silently rewrite the manifest, and an
  `activate` script inside the projection would have to be written into a read-only object.
  For a shell, `ward env` prints the environment as exports and `eval "$(ward env)"` applies
  it; that environment is then **ambient** for that shell — every later command sees it,
  Greyward's or not, and it outlives a `cd` out of the project. direnv is the way to scope it back
  to a directory (`echo 'eval "$(ward env)"' > .envrc && direnv allow`), which is why Greyward
  prints the environment instead of activating anything itself.
  No bytecode precompilation — slower cold starts.
- **macOS deployment-target wheel tags are not compared** — theoretical silent wrong-wheel
  risk. Markers/extras in a pinned file trigger a full uv re-lock; versions can shift.
  Every `--hash` the requirements write, in any file of their include tree and beside
  unpinned lines too, must still be in the lock for that package, or the plan is refused
  naming the file and line, and the plan uses only the files those hashes name. A line
  pins the versions its specifier allows as PEP 440 reads it (`==1.*`, `==1.17` for
  1.17.0), and only where its marker is true: another platform's line pins nothing here,
  and a marker Greyward cannot evaluate is refused by line. A hash that is not a
  well-formed sha256 (`md5:`, a short hex) is refused by line before any re-lock.
  **Resolving can build a source distribution that has no wheel** (its build backend runs,
  confined, through the resolution door): it is recorded as `resolution-build`, which a
  policy can deny to refuse it. This also covers metadata preparation by
  the project's own backend because it can request third-party source builds.
  sdist build-requirement resolution never builds.
- **Lock markers are read as PEP 508 and `packaging` 25 read them, with these
  refusals.** Each is a marker Greyward will not guess at, so a lock that uses one fails
  to import, naming it:
  - `platform_release` and `platform_version` are the running kernel's `uname -r` and
    `uname -v`, so a marker using them is evaluated only when the target is this host,
    and refused for a cross target. A project whose `uv.lock` names either records the
    kernel in its closure, so `ward status` reports a change and the next sync re-reads
    the lock after a kernel update. A Linux release such as `6.8.0-45-generic` is not a
    PEP 440 version, so ordering it (`platform_release >= '5.0'`) is refused by the next
    rule. `==`, `!=` and `in` work.
  - An ordering operator (`<`, `>=`, `~=`, ...) on a value that is not a PEP 440 version
    (`sys_platform > 'darwin'`) is refused, where `packaging` compares the strings.
  - A backslash or control character in a quoted value is refused, where `packaging`
    decodes it as a Python escape (`'lin\x75x'` is `linux`). No lock generator emits one.
  - A version segment past 2^64 (`18446744073709551616`) is refused.
  - A non-ASCII local version (`1.0+K` with the Kelvin sign) is refused, where
    `packaging`'s case-insensitive match folds some of them.
  - `extra` compares by normalized name with `==` and `!=` only, as uv does
    (`extra == '01'` does not match the extra `1`, where `packaging` compares versions).
    Every other operator on `extra`, `in` and `not in` included, is refused. uv ignores
    them with a warning, so ignoring one could install what the marker excludes.

  One divergence evaluates differently: `python_full_version ~= '3.12.0c1'` follows
  PEP 440 (`>=3.12.0c1, ==3.12.*`) and is true for 3.12.5, where `packaging` 25 keeps an
  extra release component for the `c`/`pre`/`preview` spellings and answers false.
- **Entry-point names are checked against Greyward's Unicode version, not the interpreter's.** The
  identifier tables come from the ICU data Greyward is built with, so a letter added in a newer
  Unicode than the target CPython knows is accepted by Greyward and is a SyntaxError in the
  generated launcher.

## JavaScript / npm

- **`npm install` is refused, not prevented.** `ward run npm install` is refused with an
  explanation, but npm run directly in the project still replaces the `node_modules` symlink
  with a real directory. Nothing enforces the projection at the filesystem level. `ward status`
  reports it as a real directory written over the projection and the next sync moves it
  aside and re-projects, so it is recoverable, not prevented.
- **Install scripts needing network for logic** are permissive with `install-script-failed`
  (declared-artifacts covers only matching cache locations; Electron-class needs per-version
  declarations). **Git sources are realized only when pinned to a full commit.**
  Branch/tag/bare URLs and ambient Git config fail closed. npm runs a git dep's `prepare`
  script; Greyward does not. Python and Cargo git deps work the same way, but Cargo's are not
  re-verified against the project's Cargo.lock at `run` — a post-sync lock edit is caught by
  cargo, not Greyward. Git sources are fetched on the host, not through the sandbox: an
  `ssh://` source offers the user's ssh agent keys to the host the lock names, and a `file://`
  source reads a path on the machine. Both record `host-git-transport` before the fetch, which
  a policy can deny, and so does each `ssh://` or `file://` submodule, at any depth, before its
  level is fetched.
- **The project's own lifecycle scripts do not run.** npm runs the root's `preinstall`,
  `install`, `postinstall`, `prepublish`, `preprepare`, `prepare` and `postprepare` on install,
  and every workspace member's or linked directory's `preinstall`, `prepare`, `install` and
  `postinstall` (with `node-gyp rebuild` as the default `install` beside a `binding.gyp`). Greyward runs only
  dependencies' scripts, because these write the project's source and the sandbox has no
  writable view of it yet. A `"postinstall": "patch-package"` leaves `patches/` unapplied, and a
  member's `prepare` that builds `dist/` leaves it unbuilt. Each skipped script is recorded as
  `project-script-skipped` (subject the directory, detail the phase and command), so a policy
  can deny it and `ward audit` counts it. Run the script with `ward run <name>` after the sync.
- **A required package for another platform is installed only from a pnpm lock.** pnpm
  installs a non-optional package whose `os`/`cpu`/`libc` excludes the host (with a warning);
  npm refuses the same lock with `EBADPLATFORM`, and Greyward follows whichever tool wrote the
  lock. From a pnpm lock the package is placed as verified files, recorded as
  `foreign-platform-package`, and its install scripts are not run. From a `package-lock.json`
  the sync stops and says to make the dependency optional. `yarn.lock` records no
  restrictions, so nothing is filtered there at all. pnpm's `supportedArchitectures` setting
  (install optional packages for other platforms too) is not read: an optional package for
  another platform is always left out.
- **Two Node packages that claim one bin name: the first keeps it.** Each package's bins are
  linked into the `.bin` of the `node_modules` that holds it, a nested package's into its
  parent's, as npm links them, and an install script's PATH lists every `.bin` from its own
  package outwards. When two packages in one `node_modules` claim the same name (playwright and
  @playwright/test both ship `playwright`), the first in lock order keeps it, as with npm, and
  the closure records `file-collision` for the link with both package paths.
- **An optional Node dependency Greyward cannot verify is left out, and recorded.** An
  optional package with no integrity, a non-https tarball, or a local reference the lock cannot
  place is not installed, whichever of `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`
  names it, and the closure records `requirement-skipped` for it, so `ward audit` and the SBOM
  show it is missing. npm would install it unverified. A required one stops the sync.
- **A `pnpm-workspace.yaml` whose `packages` Greyward cannot read refuses sync, edits, and
  `attest`** (an anchor, an alias, a block scalar, a mapping item): a resolution record names
  every workspace member's `package.json`, so a members list Greyward cannot read would leave a
  member uncovered. The refusal comes in preflight, before anything is realized; write
  `packages` as a plain list of patterns.
- **An npm lock's `overrides` are not checked against package.json.** Before planning,
  Greyward refuses a `package-lock.json` or `npm-shrinkwrap.json` whose dependency maps or root
  `workspaces` disagree with the package.json files, or that misses a workspace member npm
  itself finds for the root `workspaces` patterns. npm keeps no copy of `overrides` in the lock, so a changed
  override is not seen until the lock is regenerated, as with `npm ci`.
- **A pnpm lock is checked against the manifests, but not through `.pnpmfile.cjs`.** Before
  planning, Greyward refuses a `pnpm-lock.yaml` that is missing a workspace member
  `pnpm-workspace.yaml` names, or whose importers disagree with a package.json, applying the
  lock's `overrides` by pnpm's selector rules (`name@range`, `parent>name`). A
  `.pnpmfile.cjs` `readPackage` hook that rewrites a project's own dependencies is not run,
  since that is project code, so such a lock reads as stale. A member that has only a
  `package.yaml` or `package.json5` is not found by the member check. A `pnpm-workspace.yaml`
  with no `packages` key (one that only holds settings) is read as naming no members, and a
  `packages` value that is not a plain list (an anchor, an alias) skips the member check with
  a note.
- **Reading npm workspace members runs Node, and it sees the whole host read-only.**
  Greyward does not match `workspaces` patterns itself: it asks the npm bundled with the
  store Node (`@npmcli/map-workspaces`), so the member set is npm's own, extglobs, classes
  and symlink rules included. Any command that reads a project whose root `package.json`
  has a `workspaces` list (sync, `ward add`, `inspect`, `audit`, `join`, `attest`) realizes
  that Node first, a download the first time. npm runs in the sandbox with no network and
  nothing writable but its scratch directory, and with the whole host filesystem
  read-only, so a symlink to anywhere resolves as it would unconfined. That view shows
  every host file Greyward's own user can read except Greyward's signing keys, and every
  host Unix socket: no socket scan can cover `/`, so the trust is in the tool, which is the
  store's hash-checked npm reading the project's patterns as data and running none of the
  project's code. The project itself is bound from the directory Greyward holds; a project
  whose path was pointed elsewhere after Greyward opened it is refused. Nothing npm prints
  reaches the terminal or a CI log: its output goes nowhere. Greyward keeps nothing npm
  returns unchecked: for each directory npm names, Greyward reads that member's
  `package.json` itself, beneath the project and the member's own directory, takes the
  member's name from those bytes, and refuses if npm's name differs. Every failure (an npm
  error of any kind, a directory or a `package.json` outside the project or the member, a
  name that disagrees) gives one fixed message, "workspace members of
  `<project>/package.json` could not be determined inside the project", followed by the
  project's own declared patterns and nothing else: no npm code, no path npm found, no name.
  So two failures that differ only in what a host file holds print the same bytes. Setting
  `GREYWARD_DEBUG_NPM_MEMBERS=1` adds the reason, and that reason can quote a host file a
  member's symlink reaches, so it is for debugging on your own machine, not for a shared CI
  log. One signal remains: whether npm's patterns match anything outside the project at all
  decides whether the members are determined, since a pattern that matches nothing there is
  not an error. npm runs again for every question, and if its answer changes while one
  command runs (a member added, removed or renamed during a sync, or listed in another
  order), the command refuses rather than publish a record for the old set.
- **A workspace member reached through a symlink out of the project is refused.** npm takes
  a directory its `workspaces` patterns find through a symlink, wherever the symlink leads.
  Greyward refuses the whole member set when npm returns one that leads outside the project
  (or a pattern such as `../other/*` that climbs out of it), with the fixed message above,
  since a resolution record names files inside the project only and what npm read there is
  host data. Point the symlink inside the project, or remove the pattern that matches it. A
  symlink out of the project that no pattern matches changes nothing.
- **Workspace links are checked when they are planted and right before publication, not
  afterwards.** A `node_modules` link to a workspace package is planted to the target's
  symlink-free path, resolved through the held project descriptor. Every check of a link is
  one step: the link's text, read in the store directory Greyward holds open for it, must
  still be the text planted; that directory, walked down again with no symlink followed from
  the deepest directory it shares with the project's path, must still be the one held (so a
  forest moved and replaced with a symlink, which would make the same text climb from
  somewhere else, is refused); the project must still be at its path; and the target is opened once from the held descriptor with `openat2`
  (`RESOLVE_BENEATH`, so a symlink on the way that leads out of the project fails the open);
  the directory opened must be the very one recorded when the link was planted. So a
  directory on the way that a concurrent writer swapped for a symlink out of
  the project, or moved out of the project and replaced with a symlink to its new place,
  is caught, and the link is removed and the sync refused, and so is a directory moved out
  and moved back in its place. The same check runs again as the last step before the store
  registers the closure and signs it, after every npm run and every other ecosystem's
  resolution has finished. The link itself cannot be opened from the project descriptor in one
  step: it lives in the store, outside the project, and reaches the target by the project's
  path. A link whose target no longer exists is removed and refused the same way. On a Linux
  kernel older than 5.6 (no `openat2`) and on macOS, the target is walked one component at
  a time from the held descriptor instead, which a concurrent swap between two steps can
  outrun. Edits the project's owner makes to their own
  tree after the sync (replacing a member directory with a symlink elsewhere) are outside
  Greyward's guarantee: the link points at the project's own source, which its owner
  controls, and the next sync checks it again.
- **A workspace member whose `node_modules` holds files git tracks is not projected.** Some
  repositories commit a fixture `node_modules` (vite does). Greyward moves an npm-made
  `node_modules` into the store's backups before projecting, but moving a tracked one would
  delete committed source, so that member keeps its directory, gets no projected
  dependencies, and the sync prints a warning naming it (`ward status` counts that member
  synced while its directory is there). A tracked `node_modules` at the project root stops
  the sync instead, even when the only tracked file is a `.gitkeep` or `.gitignore`: untrack
  it (`git rm -r --cached node_modules`) and sync again. Each workspace's own repository
  is checked, including submodules and repositories inside `node_modules`. A failed index
  read stops sync before projection.
  Outside a repository nothing counts as tracked, including when Git is unavailable.
- **A registry package that depends on a workspace package makes `node_modules` a copy.**
  A plugin whose peer dependency is the package the repository itself develops has to
  resolve that package from the project's own source. Node looks dependencies up from a
  package's real path, and a store object cannot hold a link into a project, so for such a
  project the whole tree is copied into the projection (copy-on-write where the filesystem
  has reflinks: XFS, Btrfs, APFS; a full copy on ext4) instead of linked. The copy is
  writable and Greyward does not re-verify it, so each such package records
  `unattested-mutable-state`, which the company policy template denies. Copying only the
  packages that need it is not built.
- **Skipped install-time downloads are not in the closure**: puppeteer- and cypress-class
  packages record `artifact-not-provisioned`, fetched unverified only when the user runs that
  command. Electron's zip is provisioned instead, and a failed provisioning fails the sync.
- **Prebuilt binaries are compiled instead of downloaded; the result can differ from what npm
  would install. Wheel file-path collisions (`file-collision`), SHA-1 npm integrity, and pnpm 9
  MD5 patch hashes (`weak-integrity`) are permissive; strict via policy. Lifecycle scripts run in lockfile
  order, not dependency order (rarely bites, silent), and process-tree quiescence is not
  enforced: a postinstall daemon can outlive realization.

## Rust / cargo

- **Cargo resolves in the sandbox, through TLS interception** (`add`/`remove`/`update`, a
  missing `Cargo.lock`, `attest`, and an sdist's missing lock). Cargo has no network of its
  own: Greyward's proxy answers the crates.io index and download hosts and pinned git fetches,
  and records each request. Known edges: a project cargo configuration is refused by name
  before cargo starts, in resolution, `ward`, `ward build` and `ward run`, when it (or a file
  it includes) sets any of these, since no setting Greyward can force undoes them:
  - `paths`, which builds a local directory in place of a locked crate with `Cargo.lock`
    unchanged (use a `[patch]` table in Cargo.toml, which the lock records);
  - `registry.global-credential-providers`, any `credential-provider`, or
    `[credential-alias]`: cargo runs the global provider list for a replacement source after
    Greyward's own `cargo:token` finds no token (keep providers in your own
    `~/.cargo/config.toml`);
  - `[source.greyward-vendor]` or a `replace-with` naming it, a `directory` or
    `local-registry` source, or a `replace-with` chain that ends at one. Cargo trusts the
    checksums a directory source writes about itself, so it can serve any code under a
    locked name. A project vendored with `cargo vendor` must drop that config: Greyward
    vendors the lock itself. A network mirror (`[source.<name>] registry`, a chain of them)
    stays allowed, since cargo checks each downloaded crate against the lock's checksum;
  - a registry, index or source URL that is not `https://` or `sparse+https://`, or a git
    index over `ssh://` or `git://`: a `file://` or path index (and the archives its
    `config.json` points at) is read without Greyward's proxy, so its index and git checks never
    run. `http://` mirrors are refused too. An index or mirror over `ssh://` or `git://`
    records `host-git-transport`, as an ssh git dependency does, and the record `ward attest`
    signs carries it, even for a mirror replacing crates.io;
  - an `[alias]` whose expansion holds `--config` or `-Z`, which `ward run`'s wrapper would
    not see (it refuses `--config` on the command line);
  - an `[env]` entry for a dynamic-loader variable (`LD_*`, `DYLD_*`), a git variable
    (`GIT_*`, since git reads `GIT_CONFIG_PARAMETERS` after the settings Greyward forces),
    `RUSTC_BOOTSTRAP` (or `RUSTC_BOOTSTRAP_*`), or a variable Greyward forces for cargo (`CARGO_HOME`, `PATH`,
    `RUSTC_WRAPPER`, ...): cargo sets `[env]` for every program it starts, the compiler probe
    in resolution included;
  - compiler flags (`build.rustflags`, `build.rustdocflags`, `host.rustflags`,
    `target.<triple or cfg>.rustflags` or `rustdocflags`, and `RUSTFLAGS`, `RUSTDOCFLAGS` or
    `CARGO_ENCODED_*` in `[env]`) holding a `-Z` flag, a `codegen-backend` or an `@file`
    argument file: cargo passes them to the compiler probe, and rustc loads a codegen backend
    library, running its code, before checking it.

  The same URL rule holds for every package source in the lock cargo leaves: after each
  cargo run (lock generation, an update, `ward attest`), before anything is published or a
  resolution record is written, Greyward refuses a lock that resolves a package from a
  `file://` or path registry, `http://`, or any source that is not a network registry or a
  git repository. Every lock the run may leave is checked: the root's, the one beside a
  `--manifest-path` manifest (a Python sdist's `native/Cargo.toml`), and a cached generated
  lock before it is reused. A git dependency read from a path on this machine or over ssh,
  and an ssh registry index, record `host-git-transport` from that lock, so a policy that
  denies it refuses the run before anything is published. That is the guarantee. A dependency's `registry-index` can sit in any
  manifest, including a git dependency's own, which cargo fetches mid-run. As an earlier,
  clearer refusal, Greyward also checks `registry-index` before cargo starts in the
  manifests it can see: the root, the workspace members cargo finds (hidden directories
  included), path dependencies, and every dependency table including `target.*`, build
  and dev ones and each `[patch]` entry.

  `ward attest` also refuses a lock when `cargo metadata` shows a crate the lock pins to a
  registry or a commit read from anywhere but cargo's own download of it. Metadata prints no
  checksum and keeps the registry's source id for a directory replacement, so where cargo
  read the crate is the check. It also refuses a lock whose registry is not a network one,
  since a manifest's `registry-index = "file://..."` reaches a file index with no config.
  Each locked package is matched by name, version and source, so a crates.io download does
  not stand for a same-named package from another registry. `ward run` checks from the directory it starts in up to the
  workspace root, and the project's `.greyward/cargo-home` config, which is cargo's home
  there, not the directories above the workspace. Authenticated alternative registries fail, as the
  sandbox gets no token. Path dependencies outside the workspace root are found from the
  manifests (dependency tables, `[patch]`, `[replace]`, `target.*`, `[workspace]`) and
  snapshotted read-only; one named only through a `[lib] path`, a build script or a
  symlinked directory is not, and cargo reports it missing. They must lie inside the
  project's repository (the nearest directory holding `.git`), or beside the workspace when
  there is no repository, never in a hidden directory, and that bound may not be `/` or the
  home directory: anything else is refused before cargo starts, naming the manifest. A
  resolution record names files inside the workspace only, so a workspace with a path
  dependency outside it is not attested (`ward attest` refuses it by name) and its edits and
  generated lock carry no record (`unrecorded-resolution` at sync). `attest` runs at the
  workspace root only. Greyward finds that root itself, reading the manifests the way cargo does;
  no cargo runs on the host. A project file that is the signing key under another name (a
  symlink, a hard link, an `include`) is refused before cargo reads it, and no message Greyward
  prints carries the key. A workspace member reached through a symlinked directory is refused
  for lock generation, edits and attest: the confined cargo would not see it. A `members`
  entry outside the workspace root (`../x`, an absolute path elsewhere) is treated like a
  path dependency outside it: the same location rules, `ward attest` refuses it by name, and
  edits and generated locks carry no record. Config `include`s are followed for the registries they declare and recorded as inputs; one
  that leads out of the workspace is refused. A git dependency resolved through the proxy
  has no offline test yet (the fixture registry holds no upload-pack body), only the git
  row's unit test.
- **Pinned Git dependencies work for standalone crates**; workspace-inherited manifests and
  escaping symlinks fail closed, and workspace metadata is not rewritten into vendor
  manifests. **Fail-closed rows**: alternative registries; beta/nightly channels. Loud.
  Cross `targets` get their standard library from the release's signed channel manifest,
  but Greyward provides no linker or C sysroot for them, so a crate that links for another
  platform still needs one on the machine. A custom toolchain works as a local directory
  (`path =` in rust-toolchain.toml), below.
- **A local toolchain (`[toolchain] path`) is trusted by content, not by origin.** The lock
  records its `rustc -vV`/`cargo -V` lines and a hash of the whole tree, so it proves the
  tree did not change, not who built it; every use records `external-toolchain`, which the
  company template denies. Locking runs the tree's own `bin/rustc` and `bin/cargo` for their
  versions (in the build sandbox, so it needs bubblewrap on Linux). The tree is re-hashed on every sync, build and
  fmt: the walk and link checks run in full, but a file whose device, inode, size and times
  are unchanged is not read again (its sum is cached in the store), so only the first
  hash of a full toolchain costs seconds. That key is the file's device, inode, size,
  mtime and ctime (seconds and nanoseconds), so a write that leaves all of them as they
  were (an NFS mount with coarse or cached attributes, or a write through a shared `mmap`
  that never updates the times) is not seen until the import's copy, hashed from the
  bytes, disagrees. That refusal re-reads the whole tree and rewrites the cache. Locking
  (`ward update --toolchain rust`) always reads every file. The lock row names
  an absolute path on one machine and one host platform, so a checkout elsewhere needs
  `ward update --toolchain rust`. As in rustup, a path cannot be combined with a channel,
  components, targets or a profile. A symlink in the tree is resolved against the tree
  itself, through any links it passes, and a tree with one that leads outside is refused.
- **No `profile` in rust-toolchain means rustc, cargo and the host std** (rustup's
  `minimal`), not rustup's configured default; ask for `profile = "default"` to get
  clippy, rustfmt and the docs. **No channel means the catalog's default release**
  (rustup's would be its configured default toolchain).
- **`profile = "complete"` fails on releases that did not build all of it** (1.96.1 lists
  `miri` and `rustc-codegen-cranelift` for Linux and macOS and marks both unavailable), as
  rustup's does; name the components instead.
  **`ward build` covers `build` only** — no sandboxed test/clippy/doc; those run via
  `ward run cargo ...` offline but unsandboxed. target/ is unmanaged scratch (no shared
  build cache). **`cargo install` through the wrapper is unmanaged** (lands in
  `.greyward/cargo-home/bin`, outside the closure).

## Go

- **Go archives are TOFU.** The digest comes from go.dev's release JSON, cross-checked with
  the `.sha256` on dl.google.com, neither signed. A `.asc` signature by Google's Linux
  packaging key sits beside every archive, which ward does not check yet; go.dev does not
  document it, and the JSON that lists releases is unsigned.
- **Only the Go lines go.dev lists as supported are realizable** (every release of each). An
  unmatched `go.mod` selection fails before store or network access. A non-default
  `toolchain` directive is exact; `go` alone is a minimum that takes the default (1.27.0) when
  it satisfies, else the newest release, where go itself would take the lowest.
  **Fail-closed rows**: go.work workspaces (including ancestor detection);
  local-path replace directives. Loud.
- **Module zips come from Google Cloud Storage.** proxy.golang.org redirects most `.zip`
  downloads to `storage.googleapis.com`, which is not a registry host. The one exception
  the Go route adds is that hop: only when go asked for a `.zip`, only from a `.zip` URL
  on proxy.golang.org, only to that host over https on port 443, and it is the last hop
  (any redirect after it, back to a registry host included, is refused). `list`,
  `@latest`, `.info` and `.mod` responses receive no storage-handoff exception, even
  when they redirect through a zip URL first. The storage host is trusted with
  nothing, since go checks every zip against go.sum and the checksum database as before;
  it sees go's user agent, and its signed URL is recorded redacted. The hop is judged the
  same through the mirror and through interception. Module paths with uppercase letters
  (`!azure`, sent by go as `%21azure`) are percent-decoded once and then held to go's
  escaped spelling.
- **Graph-only modules are excluded from the closure**, so modgraph introspection can hit
  GOPROXY=off errors. **Private modules are unsupported**: GOPROXY forced to proxy.golang.org,
  GOVCS off, GOPRIVATE scrubbed.
- **The planner runs `go mod tidy` on out-of-sync manifests automatically**, mutating
  go.mod/go.sum. **`ward build` stages outputs then moves them**: `-o`-dependent workflows
  differ from plain `go build`; `-mod`/`-toolexec`/`-o` are rejected. The plan-cache key
  includes only `*.go` sources — go:embed and non-.go inputs do not invalidate it.

## Ruby

- **portable-ruby, and the Bundler inside it, are TOFU.** Homebrew publishes no checksum file,
  signature or attestation for the bottles; the digest is the bottle hashed at pin time,
  compared with GitHub's own asset digest. Nothing can be checked later. The default
  (3.4.6) is a release Homebrew marked prerelease and reverted in brew.
- **Path and git gems.** A `PATH` gem (a Gemfile's `gemspec`, or `path:`) must sit
  inside the project: one outside it, or reached through a symlink that leads out, is
  refused, naming the gem and the path. Bundler loads it from the project at run time, so
  it adds nothing to the gems object; the closure lists it and the SBOM names its
  directory, with no registry purl. A `GIT` gem is fetched at the lock's revision by ward's
  own git code, records `git-dependency` (plus `host-git-transport` over ssh, `git://` or
  a local path) before the fetch, and is installed into the gems object where Bundler
  reads it, `bundler/gems/<repo>-<commit prefix>`, by Bundler's own installer in the
  sandbox. Its gemspecs are only known once evaluated, so every git checkout builds as a
  native gem does: against the C runtime first on Linux, with ward's native library set
  mounted. Submodules are checked out whatever the lock's `submodules:` says. Several
  `GIT` sections of one repository at one commit (one per `glob:`, or a mirror's URL) share
  one checkout, as in Bundler. A gemspec may list its files with `git ls-files`: ward
  indexes the fetched tree in a throwaway repository while Bundler evaluates it, then
  removes it, so the object holds no git data. A remote that is an absolute path is read
  as a local repository (`file://`); a relative one is refused. A `glob:` may use `*`, `?`
  and plain path segments only: one with braces, a character class (`[...]`) or a
  backslash is refused, since Ruby expands those before matching (`{.}{.}` reads as `..`),
  and so is one containing `..` or starting with `/` or `~`. A git gem's executables are checked against every other gem's, as rubygems.org
  gems' are. Like after `bundle install`, a git gem's executables run through `bundle
  exec` (`ward run bundle exec <exe>`); RubyGems alone does not know the gem.
- **Sources other than rubygems.org, path and git fail closed.** So do gems whose
  installers need network or absent host libraries (mysql2/rmagick-class) — no
  declared-artifacts mechanism for gems yet. psych needs libyaml's headers, which ward's
  native library set does not carry, so a lock naming psych fails on a host without them.
- **A newer Bundler is provisioned only from the lock.** A lock `BUNDLED WITH` a Bundler
  newer than the store Ruby's (2.6.9) gets that exact release from rubygems.org, checked
  against the lock's CHECKSUMS entry for it, or else rubygems.org's API digest (recorded as
  `unpinned-digest`, as for any gem). It is its own store object, planned, installed and
  run with; no other version is ever picked. A lock no newer keeps the shipped Bundler. A
  project with no lock is resolved by the shipped Bundler, which writes its own version.
- **Git sources while the lock is written.** `bundle lock` (and `ward add`/`update`/
  `remove`) reaches git only for the hosts the Gemfile's git options name (`git:`, a
  `git "..." do` block, `git_source`, and the `github:`, `gist:` and `bitbucket:`
  shorthands), read from its text without evaluating it, and only git fetches are served
  there; each records `git-dependency` in the receipt. A remote built by interpolation, or
  named in a file `eval_gemfile` loads, is not read, and Bundler's clone of it is refused,
  naming the host. A gemspec's `git ls-files` sees a throwaway index of the project copy
  (`git add -A`, so `.gitignore` applies), removed after the run: a file the project's
  `.gitignore` drops but its repository tracks is missing from that list.
- **Default/bundled-gem preactivation edge**: a
  locked json/psych/openssl older than the toolchain's default can Gem::LoadError if something
  activates the default before Bundler setup. Untested matrix; potentially silent.
- **`bundle exec` compatibility is unproven**: env-based GEM_HOME activation works for
  `ward run ruby/rake`; full bundler runtime activation has not been exercised on a real
  Rails-class app.
- **System /etc/gemrc is still read** (GEMRC=/dev/null blocks only the user file).
  **Portable-ruby is a Homebrew-internal artifact**: relocation is probed to work but is not a
  contract, and its builds trail ruby-lang: the newest 3.4 build (3.4.6, the default) lacks
  the 3.4.10 security fixes in bundled gems, and Ruby 4.0 has no build at all. **CHECKSUMS-section locks fail closed if bundler's checksum registry API
  drifts**; new bundler formats need code updates. A lock without a CHECKSUMS section is
  verified against rubygems.org's API digests on first use and records `unpinned-digest` per
  gem, so `--strict`, or a policy that denies the kind, needs `bundle lock --add-checksums`.

## Elixir

- **Every BEAM toolchain row is TOFU.** The Darwin OTP build (erlef/otp_builds) has a
  Sigstore provenance bundle beside it, which ward does not check yet. The Linux OTP build
  (greyward-toolchains) has only an unsigned `.sha256`. The Elixir zip has a `.sha256sum`;
  the `.sigstore` file beside it attests the release's SBOM files, not the zip. Hex and
  rebar3 digests come from builds.hex.pm's install CSVs, whose `.signed` RSA signatures ward
  does not check yet (Mix stopped checking them in 2025).
- **Two OTP steps run outside the sandbox on Linux**: the `Install -cross -minimal` relocation
  and the OTP runtime probe (`src/tailors/elixir/mod.rs`). They touch only the staged object — the one
  non-sandboxed build step in the kernel. **OTP cache hits skip the runtime probe**: the OTP
  object was built on Fedora 44 (glibc 2.43 floor, OpenSSL 3.x); a store copied to an
  incompatible host fails only at execution time. Loud, but late.
- **Fail-closed rows**: git deps; non-hexpm repos; legacy mix.lock entry shapes (3/6/7-field —
  "refresh the lock"). **Umbrella projects are untested**. **Only OTP releases with a Linux build in
  `greyward-toolchains` are realizable** (OTP 29.0.5 today, with each Elixir 1.20 patch); erlef
  publishes the Darwin builds for many more. **No rebar3 build for OTP 29 exists
  yet**: the pinned otp-28 escript runs on the 29 VM — a version-skew impurity until upstream
  ships otp-29 builds. **Mix's compilation lock is disabled in-sandbox**, so concurrent
  unsandboxed `mix compile` against one build root is unprotected; `ward build` runs
  MIX_ENV=dev only. **mix.exs elixir requirements are not consulted**: the OTP and Elixir
  entries in `.tool-versions` are the declarative sources the toolchain lock reads, because
  reading mix.exs means evaluating an Elixir program. **The deps projection is whole-tree
  writable**: one
  dep's build can modify a sibling dep, recorded unattested in the closure.

## .NET

- **Only an exact `global.json` selects the SDK.** `sdk.rollForward` must be `"disable"`;
  there is no second source and no roll-forward, so a mismatch is a hard error rather than a
  quiet upgrade.
- **Strictest v0 boundary of any tailor** (all loud): one SDK-style .csproj only — no .sln, no
  ProjectReference lock entries, no Central Package Management, no
  packages.config/PackageDownload, no workloads, no custom MSBuild SDKs, nuget.org only.
  Ancestor SDK inputs (global.json, Directory.Packages.props, Directory.Build.rsp,
  packages.config) fail closed.
- **Build-capable dotnet verbs are refused at `ward run`**; everything compiling goes
  through `ward build dotnet`, which covers build only (no test/publish verbs). The guard
  is advisory — `sh -c` can bypass it. Missing-lock restore runs in the resolution
  sandbox through Greyward's NuGet mirror, so the project's MSBuild code never runs on the host.
  **Preflight is a fail-closed text scan, not an XML parse**:
  exotic-but-legitimate projects can be refused; nothing banned can hide (XML cannot
  entity-encode element names) — the build sandbox, not preflight, is the security boundary.
- **Output publication has a microsecond non-atomic window**: a reader during the rename sees
  no output; the last good build survives a failed publication. `/tmp/.dotnet` is a bounded,
  local-only sandbox write allowance. **The .NET SDK is TOFU in ward today, though
  Microsoft signs what would cover it.** The SDK's sha512 comes from `releases.json`, which
  carries a CMS signature (a `.p7s` file chaining to DigiCert's code-signing root) and a signed
  expiry date; ward does not check it yet (WP3). The `.sig` files beside the metadata are
  stale and made by an unpublished key, so they prove nothing. **The lock does not cover asset selection**: project.assets.json is re-derived
  and attested but not diffed; a NuGet behavior change across SDK pins changes builds under
  the same lock, silently.

## Real-project proof gaps (all ecosystems)

- Python/npm were proven on Ethan's real projects (CX-Games, deja, Financial-Filing…). Cargo
  was proven on Greyward itself. **Go and Ruby have only been proven on small
  synthetic-but-real-dependency projects** — Go on a hello-world module pulling `rsc.io/quote`
  plus a cgo build; Ruby on rake/racc/nokogiri with nokogiri's native build. No large
  real-world Go service or Rails app has run under Greyward yet.
