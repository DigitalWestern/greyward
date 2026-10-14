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

Regenerate before a release, so a fresh store's seed is recent. Standard
library only.
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
    sys.exit(main())
