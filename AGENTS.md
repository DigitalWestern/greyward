# Working in this repo

- The owner deferred all macOS checks and macOS-only findings on
  2026-10-04. They do not block review or merge until the owner revisits
  that decision. Continue required Linux validation.

- The license is Apache-2.0, and every commit carries a `Signed-off-by`
  line (`git commit -s`): the Developer Certificate of Origin in
  CONTRIBUTING.md, checked on every pull request by the `dco` job in
  dco.yml (`tools/dco.sh origin/main HEAD` runs the same check here).
  The author and the sign-off are the owner's git identity, never an
  agent's address: a commit authored or signed off by
  noreply@anthropic.com fails the check. There is no contributor license
  agreement.

- What is open and what is not (owner decision, 2026-10-05). This
  repository is the whole CLI, open source, and everything a developer
  or a CI job runs on its own machine belongs here: every ecosystem, the
  store, the sandbox, the policy gate, signing, the SBOM, the GitHub
  Action. Not in this repository, and not to be started here: anything
  that receives closures from many customers over a network (the
  cross-repo dashboard), the hosted toolchain catalog and publisher-key
  service, and a hosted package mirror. The CLI may grow the client side
  of each (a command that posts a closure, a configurable catalog source)
  as long as it works without the hosted service. Product and business
  discussion stays out of this repository: its files, commits, issues and
  pull requests.

- After a pull request you worked on is merged, open a GitHub issue for
  every exception, problem, or needed fix you found along the way and did
  not ship in that PR: review findings, design questions raised in the
  discussion, missing tests. One issue per item, with the file paths, the
  options, and the one you would pick. Add a short pointer to each in
  FOLLOW-UPS.md so the repo's to-do list and the tracker agree.

- Cross-review. Before you push, have the other agent family review the
  change through T3 Code's `delegate_task` tool (the `t3-code` MCP
  server), with `role: "review"` and `mode: "async"`.
  - If you are Claude, the reviewer is Muse: target
    `{"providerInstanceId": "muse", "model": "muse-wonder-full-1.0",
    "options": {"reasoningEffort": "xhigh"}}`.
  - If you are Muse, the reviewer is Claude: target
    `{"providerInstanceId": "claudeAgent", "model": "claude-opus-5-5",
    "options": {"effort": "high"}}`.
  - The reviewer has no memory of your session. Put the diff, the file
    paths, and what to check in `task`.
  - After you delegate, end your turn. T3 wakes you when the review
    finishes. Do not poll.
  - A second round is a new `delegate_task` call that includes the first
    findings and what you changed.
  - Treat the review as advisory. Fix what is real, and say what you
    declined and why.

- Keep CI runs few. The repository is public (since 2026-10-06), so
  Actions minutes are free on the standard runners, but the heavy suite
  is slow: one e2e run took 47 minutes, every push to a pull request
  re-runs the whole suite, and every merge runs it again on main, so an
  extra push that wakes the heavy suite is a 47-minute wait and a queue
  behind it. Before the first push:
  - Run clippy (`-D warnings`), the tests and the cross-review locally,
    so the branch goes up once, finished.
  - If main has moved, merge it into the branch locally, then push. A
    merge from main after the PR is open costs a second full run.
  - Batch related work into one pull request, one commit per piece,
    rather than one pull request per piece.
  - Know whether your change wakes the heavy suite. heavy.yml runs the
    47-minute e2e job on a pull request when it changes any file its
    `gate` job watches: `src/kernel/archive*`, `src/kernel/fetch*`,
    `src/kernel/sandbox*`, `src/kernel/dirhash*`, anything under
    `src/kernel/provider/`, a tailor's `unpack.rs` or `unpack/`,
    `src/commands/selfupdate.rs`, any
    `catalog.toml`, `Cargo.lock`, `heavy.yml`, or `tests/acceptance.sh`.
    It also runs for any file under `tests/` other than a top-level
    `tests/*.rs`, `tests/size_baseline.txt` or `tests/install.sh`
    (`tests/common/`, fixtures). A changed top-level `tests/<name>.rs`
    only runs that file's ignored tests. The `gate` job in `heavy.yml`
    is the authority. Once it is woken, every later push
    to that pull request runs it again. So do not touch those files in
    passing (a comment fix, a test-only helper): put that in a pull
    request that has to touch them anyway. When a pull request must
    touch them, run the e2e suites it affects locally before the first
    push (see the local equivalents below). #409 woke the suite twice
    with a one-line test-only change to `src/kernel/provider/rust.rs`.
  Never push only to retrigger CI. A pull request that only adds a
  FOLLOW-UPS.md pointer or a one-line doc change is allowed now that
  minutes are free, but batching it into the next real pull request is
  still better. A pull request touching only FOLLOW-UPS.md or STATUS.md
  skips ci.yml entirely, but dco.yml still checks its sign-off. Run
  `gh pr list --state open` first, so you do not duplicate a pull
  request another agent already opened.

- When CI fails on a pull request, reproduce and fix it on this machine,
  not in the cloud. You have permission to run any CI job locally,
  including the slow ones. Read the failing job's log (`gh run view
  <run-id> --log-failed`), run that job's commands from
  `.github/workflows/` here, fix the code, and re-run them until they
  pass. Then push once. Do not push a guess and wait for CI to tell you
  whether it worked: that spends a full cloud run to learn what a local
  run would have told you. The local equivalents:
  - `test` (ci.yml): `cargo fmt --check`, `cargo clippy --locked
    --all-targets -- -D warnings`, `cargo test --locked`,
    `bash tests/install.sh`, `python3 tools/test_catalog.py`,
    `python3 tools/popular.py --check`.
  - `e2e` (heavy.yml): `cargo test --locked --no-fail-fast -- --ignored
    --test-threads=2`, or only the failing suite with `--test <name>`,
    then `bash tests/acceptance.sh`. Point `TMPDIR` at a scratch directory
    under `/home/ethan/repos/greyward-repo/tmp/` first (see below): these tests leave large
    stores behind and fill the `/tmp` quota. Set `GREYWARD_STORE` to a throwaway store under the same
    directory, as heavy.yml does: with `GREYWARD_SANDBOX_TESTS=required`,
    suites that open the store in-process (`native_libs`) panic without it.
  Never save temp files, scratch directories, or test stores in the home
  directory (`/home/ethan/greyward-tmp`, `/home/ethan/tmp` and the like).
  They go under `/home/ethan/repos/greyward-repo/tmp/`, inside the `greyward-repo` folder
  one level up from the git checkout, so nothing lands in the repository
  itself. Use that path even when you work from a worktree elsewhere.
  Clean up after yourself. Give each run its own fresh scratch directory,
  for example `TMPDIR=/home/ethan/repos/greyward-repo/tmp/<branch-name>` (write the path
  out, see the shell-command rule below). Once the checks pass, delete that
  directory (`rm -rf /home/ethan/repos/greyward-repo/tmp/<branch-name>`), and any
  `/home/ethan/repos/greyward-repo/tmp/run-*` directory you created. Do this before you
  report the work as done, so nobody has to clear disk space later.
  Delete only directories you created in this task: never
  `/home/ethan/repos/greyward-repo/tmp` itself, and never another agent's directory, which may
  still be in use. Also delete the `/tmp/greyward-*` stores your own test
  runs left, and only those. Use `find /tmp -mindepth 1 -maxdepth 1
  -name 'greyward-*' -user "$USER" -mmin -<minutes since you started>`, and
  read the list before deleting anything. A `find` without `-mindepth 1`
  can match the parent directory itself, and once deleted a whole tree
  that way.
  Never re-run a failed job in the cloud (the Actions "Re-run jobs"
  button, `gh run rerun`, or an empty commit) to see whether a fix
  worked. The local run is the re-run, and you have permission to do it
  without asking, however long it takes. Run long suites in the
  background so other work goes on meanwhile.
  If a failure only happens on the runner (a different Ubuntu version,
  AppArmor, the runner's disk) and cannot be reproduced here, say so in
  the pull request. Then one push to test the fix in the cloud is fine.

- Write shell commands the worktree guard can check. A Claude subagent
  started with `isolation: "worktree"` refuses any command it cannot
  prove stays inside its worktree, and it refused 615 commands in 98
  sessions between 2026-09-01 and 2026-10-13. What it refuses:
  - A variable inside a path or an environment value:
    `export TMPDIR=$HOME/repos/greyward-repo/tmp/x`, `GREYWARD_STORE=$T/store`,
    `sed -n "$a,${b}p" "$f"`. Write the absolute path instead:
    `export TMPDIR=/home/ethan/repos/greyward-repo/tmp/x && cargo test --locked`
    passes.
  - Setting `HOME` (81% refused), `bash -c '...'` (always refused),
    `for`/`while` loops, shell functions, and process substitution
    `<(...)`.
  - Long one-liners that chain many commands with `;` around `git` or
    `gh`, such as a loop over issue numbers with `echo` separators.
  Plain `git -C <dir> ...` and `cd <dir> && git ...` pass. Run one plain
  command per Bash call, or a short `&&` chain. A recipe
  you need more than twice goes in `tools/*.sh` as a script with literal
  arguments. If a command is refused, rewrite it in this form. Do not
  retry variations of the same form.

- Source paths move. `src/kernel/store.rs` is now the directory
  `src/kernel/store/`, and other files have been split since the rename
  from tog. Do not open a path from memory, an old issue, or an old
  review. Find it first with `rg --files | rg <name>`. A missed path was
  the most common failed read, 202 times in the same window.

- Do not wait with `sleep`. Claude Code blocks `sleep N` polling, and a
  sleep loop holds a turn open for nothing. Instead:
  - A long local command (tests, the e2e suite, a build): run it in the
    background (`run_in_background: true`). You are notified when it
    exits.
  - CI or review on a pull request: call T3's `watch_pull_request` and
    end your turn. T3 wakes you when checks finish, someone comments, or
    the branch conflicts.
  - A delegated task or subagent: end your turn. T3 wakes you when it
    finishes.
  Do not chain short sleeps or `gh pr checks --watch` to get around this.

# About Ethan

My name is Ethan. I work in finance at a private credit firm doing capital markets and origination, and software engineering is something I’ve taken up as a hobby on the side. I’ve built a number of smaller projects before this—mostly Python/data analysis, HTML/CSS, scripts, and other relatively straightforward projects—but Greyward is my first large-scale backend/systems project. I am still very much a newcomer to Rust, systems programming, package managers, CI infrastructure, toolchains, dependency resolution, security, and many of the architectural concepts that appear throughout this codebase.

When working with me, do not assume that I understand terminology, conventions, or abstractions simply because they already exist in the codebase or because I have successfully built complicated parts of Greyward. Much of this project has been written with substantial help from coding agents, so the sophistication of the code is significantly ahead of my own software-engineering knowledge. When explaining something, optimize for helping me actually understand it rather than sounding technically complete. Start with the simple mental model: what the thing is, why it exists, what problem it solves, and how it fits into Greyward. Define unfamiliar terminology in plain English as you introduce it, and use concrete examples or analogies when they help. Then go deeper technically if necessary. I would much rather receive an explanation that initially feels almost embarrassingly simple than one that assumes background knowledge I don’t have.
