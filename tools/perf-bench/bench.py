#!/usr/bin/env python3
"""The timing half of tools/perf-bench.sh: run ward against throwaway
stores and fixture copies and print one table (or JSON) of wall and CPU
times. See perf-bench.sh for what it measures and why it is not a CI gate.

Every store and fixture copy lives under one scratch directory below
TMPDIR, deleted at the end. Store objects are read-only, so the scratch is
made writable before it is removed: a plain `rm -rf` fails on the objects
and can leave a store ward refuses to open.
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURES = {
    # name: (source directory, the command `ward run` times, a tiny package
    # `ward add` times)
    "P1 proj-poly": (
        REPO / "tests/fixtures/proj-poly",
        ["python", "-c", "pass"],
        None,
    ),
    "P2 npm-express": (
        REPO / "tools/perf-bench/fixtures/npm-express",
        ["node", "-e", "0"],
        "is-odd",
    ),
    "P3 py-fastapi": (
        REPO / "tools/perf-bench/fixtures/py-fastapi",
        ["python", "-c", "pass"],
        "six",
    ),
}


class Failed(Exception):
    pass


def run(ward, args, cwd, store, check=True):
    """One ward run: (wall seconds, user+sys CPU seconds of ward and every
    process it waited for). Output goes to a file, not a pipe, so the
    child is reaped with wait4 and its own rusage is exact."""
    env = dict(os.environ, GREYWARD_STORE=str(store))
    with tempfile.TemporaryFile() as err:
        started = time.perf_counter()
        child = subprocess.Popen(
            [str(ward), *args],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=err,
        )
        _, status, usage = os.wait4(child.pid, 0)
        wall = time.perf_counter() - started
        child.returncode = os.waitstatus_to_exitcode(status)
        if check and child.returncode != 0:
            err.seek(0)
            tail = err.read().decode(errors="replace")[-2000:]
            raise Failed(f"ward {' '.join(args)} in {cwd} exited {child.returncode}:\n{tail}")
    return wall, usage.ru_utime + usage.ru_stime


def median_ms(ward, args, cwd, store, reps):
    walls = [run(ward, args, cwd, store)[0] for _ in range(reps)]
    return statistics.median(walls) * 1000.0


def make_writable_and_remove(path):
    if not path.exists():
        return
    subprocess.run(["chmod", "-R", "u+w", str(path)], check=False)
    shutil.rmtree(path, ignore_errors=True)


def copy_fixture(source, into):
    shutil.copytree(source, into, symlinks=True)
    return into


def bench(ward, scratch, reps, add_reps, log):
    rows = []

    def record(fixture, measure, wall, cpu=None, unit="s"):
        rows.append(
            {
                "fixture": fixture,
                "measure": measure,
                "wall": round(wall, 4),
                "cpu": None if cpu is None else round(cpu, 3),
                "unit": unit,
            }
        )
        cpu_text = "" if cpu is None else f" cpu {cpu:.2f}s"
        log(f"{fixture:<15} {measure:<22} {wall:.3f}{unit}{cpu_text}")

    # One store shared by P1's cold sync and the deps-only syncs: once P1
    # has run in it, both toolchains are cached and none of P2's or P3's
    # packages are, so their syncs there time dependencies alone.
    shared = scratch / "store-shared"
    names = list(FIXTURES)
    synced = {}
    for name in names:
        source, _, _ = FIXTURES[name]
        store = shared if name.startswith("P1") else scratch / f"store-{name.split()[0]}"
        project = copy_fixture(source, scratch / f"cold-{name.split()[0]}")
        wall, cpu = run(ward, [], project, store)
        record(name, "cold sync", wall, cpu)
        synced[name] = (project, store)
    for name in names[1:]:
        source, _, _ = FIXTURES[name]
        project = copy_fixture(source, scratch / f"deps-{name.split()[0]}")
        wall, cpu = run(ward, [], project, shared)
        record(name, "deps-only sync", wall, cpu)
    for name in names:
        project, store = synced[name]
        program = FIXTURES[name][1]
        wall, cpu = run(ward, ["--fresh"], project, store)
        record(name, "warm --fresh", wall, cpu)
        for label, args in (
            ("status", ["status"]),
            ("bare ward (no-op)", []),
            ("env", ["env"]),
            ("run", ["run", *program]),
        ):
            record(name, f"{label} median", median_ms(ward, args, project, store, reps), unit="ms")
    for name in names:
        package = FIXTURES[name][2]
        if package is None or add_reps == 0:
            continue
        project, store = synced[name]
        walls = []
        cpus = []
        for _ in range(add_reps):
            wall, cpu = run(ward, ["add", package], project, store)
            walls.append(wall)
            cpus.append(cpu)
            run(ward, ["remove", package], project, store)
        record(
            name,
            f"add {package} median",
            statistics.median(walls),
            statistics.median(cpus),
        )
    return rows


def table(rows, reps, add_reps):
    lines = [
        f"{'fixture':<15} {'measure':<24} {'wall':>10} {'cpu':>8}",
    ]
    for row in rows:
        wall = (
            f"{row['wall']:.1f}ms" if row["unit"] == "ms" else f"{row['wall']:.2f}s"
        )
        cpu = "" if row["cpu"] is None else f"{row['cpu']:.2f}s"
        lines.append(f"{row['fixture']:<15} {row['measure']:<24} {wall:>10} {cpu:>8}")
    lines.append(f"(medians over {reps} runs; add over {add_reps}; cpu is user+sys of ward and its children)")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ward", default=str(REPO / "target/release/ward"))
    parser.add_argument("--json", action="store_true", help="print JSON instead of the table")
    parser.add_argument("--reps", type=int, default=15, help="runs per millisecond median")
    parser.add_argument("--add-reps", type=int, default=3, help="`ward add` runs per fixture (0 skips)")
    parser.add_argument("--keep", action="store_true", help="leave the scratch directory in place")
    options = parser.parse_args()
    ward = Path(options.ward).resolve()
    if not os.access(ward, os.X_OK):
        sys.exit(f"perf-bench: no ward binary at {ward}; run `cargo build --release --locked`")
    scratch = Path(tempfile.mkdtemp(prefix="perf-bench-", dir=os.environ.get("TMPDIR")))

    def log(line):
        print(f"perf-bench: {line}", file=sys.stderr, flush=True)

    log(f"scratch: {scratch}")
    version = subprocess.run([str(ward), "--version"], capture_output=True, text=True).stdout.strip()
    try:
        rows = bench(ward, scratch, options.reps, options.add_reps, log)
    except Failed as error:
        sys.exit(f"perf-bench: {error}")
    finally:
        if options.keep:
            log(f"kept {scratch}")
        else:
            make_writable_and_remove(scratch)
    if options.json:
        print(
            json.dumps(
                {
                    "ward": version,
                    "date": time.strftime("%Y-%m-%d"),
                    "reps": options.reps,
                    "add_reps": options.add_reps,
                    "rows": rows,
                },
                indent=2,
            )
        )
    else:
        print(f"{version}, {time.strftime('%Y-%m-%d')}")
        print(table(rows, options.reps, options.add_reps))


if __name__ == "__main__":
    main()
