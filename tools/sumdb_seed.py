#!/usr/bin/env python3
"""Write the Go checksum database checkpoint the binary carries.

`young-package` judges a Go module version by its record number in the
checksum database's append-only log (see src/kernel/resolve/tlog.rs): a
version passes when its record is below the size of a signed tree ward saw
at least the minimum age before the resolution. A fresh store has seen no
tree yet, so the binary carries one: `src/tailors/go/sumdb-seed.txt`, the
tree head https://sum.golang.org/latest served when this script ran.

The file is one line `observed <unix seconds>` and then the signed note,
byte for byte. The downloaded note is untrusted: this script checks its
shape, then runs the Rust test that verifies the note's Ed25519 signature
against sum.golang.org's key (the same code ward runs on every head it
serves). A note that does not verify is not kept: the old file is restored
and the script fails.

Usage, from the repository root:

    python3 tools/sumdb_seed.py

Regenerate before a release, so a fresh store's seed is recent, and commit
the file. The `observed` line is not covered by the note's signature: it is
as trustworthy as the source it is checked into. The release workflow runs

    python3 tools/sumdb_seed.py --check

which refuses a seed whose `observed` time is later than the commit that
last changed the file (plus a day), or more than 60 days before the commit
being released. Standard library only.
"""
import os
import re
import subprocess
import sys
import time
import urllib.request

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SEED = os.path.join(REPO, "src", "tailors", "go", "sumdb-seed.txt")
URL = "https://sum.golang.org/latest"
USER_AGENT = "greyward-sumdb-seed (https://github.com/DigitalWestern/greyward)"
NOTE = re.compile(
    rb"\Ago\.sum database tree\n[0-9]{1,19}\n[A-Za-z0-9+/]{43}=\n\n"
    rb"(\xe2\x80\x94 [!-~]+ [A-Za-z0-9+/]+=*\n)+\Z"
)
TEST = "tailors::go::sumdb::tests::the_seed_verifies"
MAX_AGE_DAYS = 60
DAY = 86_400


def commit_time(*paths):
    """The committer time of the latest commit (touching `paths`, if any)."""
    out = subprocess.run(
        ["git", "log", "-1", "--format=%ct", "HEAD", "--", *paths],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.strip()
    return int(out) if out else None


def stale(observed, seed_commit, release_commit):
    """Why the seed may not ship, or None."""
    if seed_commit is None:
        return "the seed is not committed"
    if observed > seed_commit + DAY:
        return f"the seed claims it was taken at {observed}, after its commit at {seed_commit}"
    if release_commit - observed > MAX_AGE_DAYS * DAY:
        days = (release_commit - observed) // DAY
        return (f"the seed was taken {days} days before the release commit (at most "
                f"{MAX_AGE_DAYS}); run python3 tools/sumdb_seed.py and commit it")
    return None


def check():
    with open(SEED, "rb") as handle:
        first = handle.readline()
    match = re.fullmatch(rb"observed ([0-9]{1,19})\n", first)
    if not match:
        raise SystemExit("sumdb_seed.py: the seed has no observed line")
    observed = int(match.group(1))
    why = stale(observed, commit_time(os.path.relpath(SEED, REPO)), commit_time())
    if why:
        raise SystemExit(f"sumdb_seed.py: {why}")
    print(f"sumdb_seed.py: the seed, taken at {observed}, is recent enough")
    return 0


def main():
    request = urllib.request.Request(URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        note = response.read(4096)
    if not NOTE.match(note):
        raise SystemExit(f"sumdb_seed.py: {URL} did not answer a signed tree note")
    observed = int(time.time())
    try:
        with open(SEED, "rb") as handle:
            old = handle.read()
    except FileNotFoundError:
        old = None
    with open(SEED, "wb") as handle:
        handle.write(b"observed %d\n" % observed + note)
    test = ["cargo", "test", "--locked", "--quiet", "--lib", TEST, "--", "--exact"]
    if subprocess.run(test, cwd=REPO).returncode != 0:
        if old is None:
            os.remove(SEED)
        else:
            with open(SEED, "wb") as handle:
                handle.write(old)
        raise SystemExit("sumdb_seed.py: the fetched note does not verify; the seed is unchanged")
    size = note.split(b"\n")[1].decode()
    print(f"sum.golang.org tree {size}, observed {observed} -> {os.path.relpath(SEED, REPO)}")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        sys.exit(check())
    if sys.argv[1:]:
        raise SystemExit("usage: tools/sumdb_seed.py [--check]")
    sys.exit(main())
