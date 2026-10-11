# Getting started

Install Greyward, check the host, and take one Python project and one npm project
from a bare checkout to a running command. Half an hour, most of it reading.

Every block below is real output from Greyward 0.1.0 on Linux x86_64, captured in
one session. Two notes on what you will see in it. The session pointed
`GREYWARD_STORE` at a throwaway directory so it could show a genuinely first
sync; on your machine that path reads `~/.greyward/store`. And the two projects
are this repository's own test fixtures: `tests/fixtures/proj-a` (a
uv-compiled `requirements.txt` pinning markupsafe) copied to `api/`, and
`tests/fixtures/proj-npm` (is-odd and wrappy, with a `package-lock.json`)
copied to `web/`. Object ids are hashes of the inputs, so yours will differ.

The words below — store, realize, project, closure, exception, permissive —
are defined in the six-row table at the top of [the README](../../README.md).

## 1. Install

On Linux x86_64 the installer is one line:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalWestern/greyward/main/install.sh | sh
```

It downloads the release binary for your machine, checks its sha256, puts it
in `~/.local/bin`, installs bash and zsh completions (and fish's too, but
only when fish is on PATH or is your `$SHELL`), and tells you where the
store will be and roughly how large it gets. A script cannot change the
PATH of the terminal that ran it, so the last thing it prints is the one
command that fixes that terminal:

```sh
source "$HOME/.greyward/env"
```

New terminals have `ward` without it. To undo the whole thing later, run the
same script with `--uninstall`: it removes the binary, the env file, the
completions and the PATH blocks it added, and leaves the store, which is
downloaded data rather than part of the program. On another platform, or
to run the current `main`, build from source with a Rust toolchain:
`cargo install --git https://github.com/DigitalWestern/greyward --locked`; the
[README](../../README.md#from-source) has the details.

On Linux you also want bubblewrap and a C toolchain, because the build
sandbox and native builds need them; the
[README](../../README.md#host-prerequisites) has the package list, and
`doctor` tells you if one is missing.

## 2. Check the host

```
$ ward doctor
ok    version      ward 0.1.0 (7688cfd 2026-09-21); newer release not checked (no published release at https://api.github.com/repos/DigitalWestern/greyward/releases/latest; the server answered 404)
ok    platform     x86_64-unknown-linux-gnu
ok    store        /tmp/greyward-demo/store (0 objects, 0 cached artifacts)
ok    disk         12.1 GiB free under the store
ok    toolchains   none realized yet; the first 'ward' downloads what the project needs
ok    sandbox      bubblewrap at /usr/bin/bwrap
ok    c-toolchain  cc, c++, make, pkg-config, patch on PATH
ok    policy       permissive (no policy file, GREYWARD_STRICT unset)
ok    project      python found; not synced yet: python (run 'ward')
```

Nine rows, exit 0 when none says `fail`. The first row is the build you
are running and whether a newer release exists (`warn`, with `ward update
--self` as the fix; `ok` with `no build for this machine` when that release
has nothing `update --self` could install here; `not checked` when offline
or, as in this transcript, recorded while the repository was still private
and GitHub answered 404). This is the command to run
before you file a bug and the output to paste into it. The `store` row
answers "where does all this go": one directory per machine, shared by every
project on it, created the first time something needs it.

## 3. A Python project

Nothing to configure and nothing to initialize. A directory with a
`requirements.txt` is already a Greyward project:

```
$ cd api
$ ward
ward: python inputs: requirements.txt
synced: .venv -> /tmp/greyward-demo/store/objects/4002574e4e21aab52a9e4abe4ff2b2c6e9158b48-env-3.12.14
ward: warning: closures are written unsigned, which is fine until you want 'ward audit' to vouch for them; the fix sets a key for this shell, and a shell profile keeps it. Said once per store
ward:     fix: ward keygen ~/.greyward/signing.key && export GREYWARD_SIGNING_KEY=~/.greyward/signing.key

NEXT:
  ward run <command>     run something inside that environment
  ward add <package>     add a dependency, re-lock, sync
  ward build             build in the sandbox (cargo | go | elixir | dotnet)
  ward doctor            check this machine when something looks wrong
  ward --help            every command and option
```

5.1 seconds from an empty store, most of it downloading CPython. On a
terminal the download draws a progress line; this transcript was piped to a
file, so it has none. You did not install Python: Greyward fetched a pinned,
hash-verified 3.12.14 into the store and built the venv out of it.

The warning is about CI, not about this sync. Records are written unsigned
until you hand Greyward a key, the only command that notices is `ward audit`, which
still judges them and says it did not check signatures (under CI it refuses
unless you pass `--allow-unsigned`), and the line is said
once per store rather than on every sync — you will not see it again below.

That one word is the whole setup step: it builds the environment from the
lockfiles and then prints a short footer: the commands most likely to come
next, and `ward --help` for the full list. There is no `install` or `sync` to remember, and you
rarely need even `ward`: `ward run`, `ward env`, `ward build` and
`ward <script>` set the project up first whenever it is not set up or its
inputs changed. In CI, `ward --frozen` checks the locks are current without
writing them, and prints no footer after it.

Run something in it:

```
$ ward run python -c "import markupsafe; print(markupsafe.escape('<b>'))"
&lt;b&gt;
$ ward run sh -c 'command -v python'
/tmp/greyward-demo/api/.venv/bin/python
```

`run` puts the projected environment on PATH for one command. The venv is a
real venv and activating it the usual way works, but `ward run` is the form
that means the same thing in every ecosystem.

See what is in it:

```
$ ward ls
python  (cpython 3.12.14; 2 packages)
  markupsafe  3.0.2
  six         1.17.0
```

## 4. An npm project

Same command. A `package-lock.json` is enough:

```
$ cd ../web
$ ward
synced: node_modules -> /tmp/greyward-demo/store/objects/9d0333722d78ff1fa9a845b3693f9794be556d7c-env-24.20.0
```

3.7 seconds, including downloading Node 24.20.0. A directory holding both a
`requirements.txt` and a `package-lock.json` gets both ecosystems out of one
`ward`, with no flags and no ordering. (The footer after it is left out of
this transcript from here on.)

This project's `package.json` declares one script:

```
$ cat package.json
{
  "name": "proj-npm",
  "version": "1.0.0",
  "dependencies": {
    "is-odd": "3.0.1",
    "wrappy": "1.0.2"
  },
  "scripts": {
    "dev": "node index.js"
  }
}
```

Scripts run without the `run`:

```
$ ward dev
ward: > dev: node index.js
is-odd(3): true
```

`ward <script>` is the short form of `ward run <script>` for any script whose
name is not one of Greyward's own commands. Arguments after the name go to the
script unchanged, so there is no npm-style separator to remember: `ward test
--watch`, not `ward test -- --watch`. A built-in always wins, which means
`ward build` is the sandboxed build; `ward run build` reaches a script called
build.

A source file works the same way: `ward app.py` runs it with the project's
Python, `ward index.js` with its Node, by the extension. The file has to
belong to an ecosystem this project has.

## 5. What is on disk now

Three things, in three places.

**`.venv` and `node_modules` are symlinks**, not directories:

```
$ readlink api/.venv
/tmp/greyward-demo/store/objects/4002574e4e21aab52a9e4abe4ff2b2c6e9158b48-env-3.12.14
$ readlink web/node_modules
/tmp/greyward-demo/store/forests/476f1751b2805ac57131c269d4a83bd7/c7b7235a2865f09767fa5aeb81256888/node_modules
```

What they point at is read-only. Switching locks, or rolling back to an old
one, is a symlink swap, which is why a sync you have done before is instant
instead of a reinstall. (Node gets a per-project forest rather than a plain
object so that scratch writes inside `node_modules` have somewhere to go;
package contents are still read-only store objects.)

**`.greyward/` is small, and part of the project:**

```
$ find .greyward | sort          # in api/
.greyward
.greyward/closures
.greyward/closures/python.json
.greyward/plan.json
```

`closures/python.json` is the record of this sync — which inputs, which
objects, which exceptions — and it is meant to be committed. `plan.json` is
a cache keyed by the hash of your inputs, so an unchanged lock never touches
the network again; it is machine-local, so ignore it. The README has the
[full table and the matching `.gitignore`
stanza](../../README.md#what-greyward-holds-and-what-to-commit); `ward audit`
cannot pass in a repository that ignores all of `.greyward/`.

**The store holds everything else.** Both projects above, from nothing:

```
$ ward store path
/tmp/greyward-demo/store
$ du -sh /tmp/greyward-demo/store
706M	/tmp/greyward-demo/store
```

That is two toolchains plus the verified download cache they came from. It
does not grow per project: a second project on the same lock is a store hit
on the same object id, in a tenth of a second.

```
$ cd ../api2 && ward
ward: python inputs: requirements.txt
synced: .venv -> /tmp/greyward-demo/store/objects/4002574e4e21aab52a9e4abe4ff2b2c6e9158b48-env-3.12.14
```

`ward gc --dry-run` shows what could be reclaimed and changes nothing:

```
$ ward gc --dry-run
ward: gc would free 0 MB (0 objects, 0 cached artifacts)
```

## 6. Day two

`ward status` answers one question: is what is projected still what the files
on disk say? It compares three things per ecosystem — the manifest and lock
inputs the closure recorded, the closure itself, and the `.venv` or
`node_modules` symlink in this directory — and exits 0 only when every
detected ecosystem is `synced`. It is offline and read-only, and it needs a
projection: on a fresh checkout that has never synced it reports `missing`
and exits 1, so it is a "is my working copy current" check rather than a
records-only verifier that CI could run on its own. The CI shape is in
[CLI.md](CLI.md#gating-a-pull-request-with-sync-and-audit).

```
$ ward status
node  synced      (node 24.20.0; 3 packages)

1 of 1 synced.
```

Add a second script to `package.json` and it says so, naming the file:

```
$ ward status
node  changed     package.json since the last sync; run 'ward'

0 of 1 synced; 1 changed.
Exit status is 0 only when every ecosystem is synced.
```

Exit 1. Run `ward`, and it is back to `synced`. Add and remove dependencies
through Greyward so that the manifest, the lock and the closure move together:

```sh
ward add requests          # uv, npm, cargo, go, bundler: whichever owns this project
ward remove requests
ward update                # re-lock within the manifest's constraints
```

`--json` is there on `status`, `ls`, `audit`, `doctor` and `plan` for when
something other than a person reads the answer.

If typing `ward run` before everything gets old, `eval "$(ward env)"` puts the
environment in the current shell, and
`echo 'eval "$(ward env)"' > .envrc && direnv allow` scopes it to this
directory instead; for VS Code and PyCharm, [EDITORS.md](EDITORS.md) has the
interpreter path and the two editor buttons that cannot work against a
read-only projection.

## 7. When it goes wrong

Two you will hit first.

```
$ ward
ward: no project in /tmp/greyward-demo/scratch: nothing to sync, so here is the help
```

No manifest here, so there was nothing to set up: Greyward prints the help after
that line and exits 0, because a bare `ward` outside a project is a request
for orientation. The files it looks for, per ecosystem, are in
`ward help inputs`. (Asking for a specific verb in the same directory —
`ward plan`, say — is a command that failed, and exits 1; so does
`ward --frozen`, so CI pointed at the wrong directory fails.)

```
$ cd ../api && ward run python --version
ward: syncing first: python changed (requirements.txt)
ward: python inputs: requirements.txt
synced: .venv -> /tmp/greyward-demo/store/objects/9b1c0e7d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e-env-3.12.14
Python 3.12.14
```

Not an error, though it used to be one. A manifest exists but nothing was
synced yet, or `requirements.txt` changed since the last sync: `ward run`
(and `ward env`, and `ward <script>`) syncs first, says so in one line, and
runs the command. It is the same sync a bare `ward` runs, so anything that
sync would refuse is refused here in the same words. In a directory with no
manifest, `ward run` fails like `ward plan` does, exit 1, saying there is no
manifest to sync from.

For anything else: `ward doctor` first, `-v` second. Verbose mode prints
every decision and every subprocess command line, which is what a bug report
needs.

## Next

- [CLI.md](CLI.md) — every command, and the conventions that hold across all
  of them: stdout is results, stderr is narration, pass-through is sacred.
- [LIMITATIONS.md](LIMITATIONS.md) — what Greyward honestly cannot do yet. Read
  it before adopting Greyward for something that matters.
- [ARCHITECTURE.md](ARCHITECTURE.md) — the store model, and why the rest is
  shaped the way it is.
