#!/usr/bin/env bash
# Time ward on three fixture sizes and print one table (#744).
#
# A local tool, run by hand before and after a performance change, with
# the numbers quoted in the pull request. It is not a CI gate and has no
# thresholds: network variance alone has moved a toolchain-only run
# (12.3s) above a full cold sync of a bigger project (11.3s) on the same
# morning. Compare runs from one machine and one sitting, and read
# seconds-level differences under about 20% as noise.
#
# Fixtures (locks committed, so a sync time excludes resolution):
#   P1  tests/fixtures/proj-poly                 Python six + npm is-odd/wrappy
#   P2  tools/perf-bench/fixtures/npm-express    express + lodash, package-lock.json
#   P3  tools/perf-bench/fixtures/py-fastapi     FastAPI stack, pyproject + uv.lock
#
# What it measures, each against throwaway stores under $TMPDIR:
#   cold sync        empty store, locks present
#   deps-only sync   both toolchains already in the store (P2, P3)
#   warm --fresh     re-realize a synced project
#   medians          status, bare ward (no-op), env, run, over --reps runs
#   add              `ward add` of a tiny package (then removed), P2 and P3
#
# Needs the network. Usage:
#   cargo build --release --locked
#   TMPDIR=/path/to/scratch tools/perf-bench.sh [--json] [--reps N]
#       [--add-reps N] [--ward PATH] [--keep]
# Progress goes to stderr, the table (or --json) to stdout. The scratch
# directory is made writable and deleted at the end (store objects are
# read-only, so a plain `rm -rf` would fail half way); --keep leaves it.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec python3 -I "$here/perf-bench/bench.py" "$@"
