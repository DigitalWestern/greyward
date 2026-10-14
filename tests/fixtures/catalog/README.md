# Provider evidence fixtures (WP3 PR 0)

The checksum files, signatures, attestation bundles and public keys each
toolchain provider publishes, captured on 2026-10-14 for
`docs/agent/DESIGNS.md` §2 "PR 0 evidence (2026-10-14)". That table says
what each file proves; this file says where each one came from and how to
check it again. No code reads these files yet: WP3 PR 1's verification
tests will.

Every file is the exact bytes served at its URL, except where an entry says
it is compressed (`.xz`: decompress with `xz -dk`, then the stated
decompressed sha256 is the upstream file's), exported (one key out of a
keyring) or written here (`hex-installs.pem`, copied from an HTML page).
Another xz version may compress differently, so for `.xz` files check the
decompressed digest.

The artifacts themselves (tens of MB each) are not here. Each entry names
the artifact's URL and digest, which match the shipped catalogs
(`src/tailors/<eco>/catalog.toml`, `src/kernel/provider/*.catalog.toml`).
Commands below take the downloaded artifact as `<archive>`.

GnuPG: use a throwaway home, never your own keyring.

```sh
export GNUPGHOME=$(mktemp -d)
gpg --batch --import <key file>
gpg --batch --status-fd 1 --verify <signature> <signed file>
```

`VALIDSIG <signing key> ... <primary key>` is the line that counts: the last
field is the primary key the signature chains to.

GitHub attestations: `gh attestation verify` (gh 2.97.0 was used). It needs
network access for Sigstore's trusted root even with `--bundle`.

## rust/ (static.rust-lang.org)

| File | Source URL | sha256 |
|---|---|---|
| `channel-rust-1.98.1.toml.xz` | `https://static.rust-lang.org/dist/channel-rust-1.98.1.toml` (898,637 bytes), xz-compressed. Decompressed sha256 `a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e`, the catalog's `channel-manifest` digest | `2da8ce2047c430c747778d5648f7fdf47d6cc43c2c3f67b4cd1ca9d7dd8a436f` |
| `channel-rust-1.98.1.toml.asc` | `https://static.rust-lang.org/dist/channel-rust-1.98.1.toml.asc` | `a9fed69b47daaaf29a6207af9df13aedb66d502ab0acc4ea557602edf87fd1aa` |
| `channel-rust-1.98.1.toml.sha256` | `https://static.rust-lang.org/dist/channel-rust-1.98.1.toml.sha256` | `48632299e2889ef236ef5411123148c86baef9816a662af28e98784771484260` |
| `channel-rust-stable.toml.xz` | `https://static.rust-lang.org/dist/channel-rust-stable.toml` (943,486 bytes; `date = "2026-10-01"`, rustc 1.99.0), xz-compressed. Decompressed sha256 `ce6dddc886364f8d786514771212cebe9b731ba82d6b859951c6b0ccc516b6a2` | `fcc8ac69e9fdfbfe46adb2ea4b9a2f9bb319ebabfd9d07495c869d2c25ed4013` |
| `channel-rust-stable.toml.asc` | `https://static.rust-lang.org/dist/channel-rust-stable.toml.asc` | `b0647bc5c19f6cc3258cfa58c10053ed44ac82c00433f04e31a0b81b2b142f46` |
| `rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz.asc` | `https://static.rust-lang.org/dist/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz.asc` | `b8a3758f43a60ae37a7c608133cfcc5891f4881a3e6c0871266c592a20b88d7e` |
| `rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz.sha256` | `https://static.rust-lang.org/dist/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz.sha256` | `bc57d0c2d62f4b51e38ee1ceef467c70d8ce049edb03b6da0e9f26d61ac1e93b` |

Key: `tools/keys/rust-release-signing-key.asc`, byte-identical to
`https://static.rust-lang.org/rust-key.gpg.ascii` on 2026-10-14 (sha256
`e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b`), so it is
not copied here. Primary key `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`
("Rust Language (Tag and Release Signing Key)"), RSA 4096, created
2013-09-26, no expiry. All three signatures verify and name the primary key
itself. The archive signature was checked against the downloaded
`https://static.rust-lang.org/dist/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz`
(sha256 `e974f036b28565f37c0f3bd92ddefa809bee16c04f9dcf07b9ed96e05aaaf7c4`).

```sh
xz -dk channel-rust-1.98.1.toml.xz channel-rust-stable.toml.xz
gpg --import ../../../../tools/keys/rust-release-signing-key.asc
gpg --verify channel-rust-1.98.1.toml.asc channel-rust-1.98.1.toml
gpg --verify channel-rust-stable.toml.asc channel-rust-stable.toml
gpg --verify rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz.asc <archive>
```

## go/ (go.dev)

| File | Source URL | sha256 |
|---|---|---|
| `go1.27.0.linux-amd64.tar.gz.asc` | `https://dl.google.com/go/go1.27.0.linux-amd64.tar.gz.asc` | `37ca9b2f4bf2189dafc9608d0e53d34808eb385aa4735704c6f746544efa0572` |
| `go1.27.0.darwin-arm64.tar.gz.asc` | `https://dl.google.com/go/go1.27.0.darwin-arm64.tar.gz.asc` | `eb1619d9a21bd3855e05054ea4c1295de6137926effd9b2d1f16db4689a57fd5` |
| `go1.27.0.linux-amd64.tar.gz.sha256` | `https://dl.google.com/go/go1.27.0.linux-amd64.tar.gz.sha256` | `6eeb32e73aafb5da54ed6f56834142ede586ccb9e72faaa031e7c83c0d87d560` |
| `linux_signing_key.pub` | `https://dl.google.com/linux/linux_signing_key.pub` | `54dea5f6c2a26091578cf52a999cebc6b64df478d37ad4dce96376b711e3b27c` |
| `dl-mode-json-at-capture.json` | `https://go.dev/dl/?mode=json`, the unsigned listing of the supported lines as served at capture time (go1.27.2 and go1.26.9, not the catalog default 1.27.0) | `1c4adcd4a38044b2ee040eb1a640c06f8d76b3afa59fd117f5fb633ba6651f78` |
| `sumdb-lookup-toolchain-go1.27.0.linux-amd64.txt` | `https://sum.golang.org/lookup/golang.org/toolchain@v0.0.1-go1.27.0.linux-amd64` | `512c62f38bd52f09df062562cfe09da3da03543d250ee3cea5408af2e47e14ad` |

Not kept: `https://go.dev/dl/?mode=json&include=all`, the listing
`tools/catalog.py` reads to name every release (2,233,984 bytes, sha256
`e69a2c3effdcfb9f41c15305b1d959524f1ff5f8e8500bac4548e6e355bda0dc`, 366 KB
even compressed). It is unsigned, so a copy proves nothing a test could
check, and the smaller listing above shows the same format.

The archives (`https://go.dev/dl/go1.27.0.linux-amd64.tar.gz`, a redirect to
`https://dl.google.com/go/`, sha256
`675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685`; and
`go1.27.0.darwin-arm64.tar.gz`, sha256
`90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e`) were
downloaded and both `.asc` files verify. They chain to "Google Inc. (Linux
Packages Signing Authority)", primary key
`EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796`, through signing subkey
`0E225917414670F4442C250DFD533C07C264648F` (created 2025-01-07, expires
2028-01-07). The key file carries two other signing subkeys (expiring
2027-01-29 and 2029-03-09). go.dev/dl does not mention these signatures.

```sh
gpg --import linux_signing_key.pub
gpg --verify go1.27.0.linux-amd64.tar.gz.asc <go1.27.0.linux-amd64.tar.gz>
gpg --verify go1.27.0.darwin-arm64.tar.gz.asc <go1.27.0.darwin-arm64.tar.gz>
```

The sumdb lookup is a signed note from the Go checksum database. Its tree
head signature (Ed25519) verifies against the `sum.golang.org` verifier key
compiled into the go command (`src/cmd/go/internal/modfetch/key.go` in the
go1.27.0 archive):
`sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8`. To
check it: the note text is the lines from `go.sum database tree` through the
root hash, plus a newline; the signature line's base64 decodes to a 4-byte
key hash (`033de0ae`) and the 64-byte signature; the key's base64 decodes to
`0x01` and the 32-byte public key. It covers the `golang.org/toolchain`
module zip (an `h1:` hash of the module's files), not the `.tar.gz`
Greyward downloads. The record's inclusion proof in the tree was not
checked.

## node/ (nodejs.org)

| File | Source URL | sha256 |
|---|---|---|
| `SHASUMS256.txt` | `https://nodejs.org/dist/v24.20.0/SHASUMS256.txt` | `c614a913a302d35d1c3a1348d07d84c52e28dceb0b97fd91e4ade05906ca2bd7` |
| `SHASUMS256.txt.sig` | `https://nodejs.org/dist/v24.20.0/SHASUMS256.txt.sig` (detached, binary) | `5a7fc9409213d5b08c232c683cae2c018b8985fecd4fdeed5c2314a1f902607b` |
| `SHASUMS256.txt.asc` | `https://nodejs.org/dist/v24.20.0/SHASUMS256.txt.asc` (clearsigned) | `8cc4c2dc94d07c7bfd4898ff1ca641d09e65e465becb50baecb4578ed93d95dc` |
| `node-releaser-5BE8A3F6.asc` | Exported (`gpg --export --armor`) from `https://raw.githubusercontent.com/nodejs/release-keys/main/gpg/pubring.kbx` (sha256 `610b8d249da3d5733f5a128def2dd0294dbbf5b5713e6ca2529db8db419dee00`), only the key that signed this release | `5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a` |

Both signatures verify and name primary key
`5BE8A3F6C8A5C01D106C0AD820B1A390B168D356` (Antoine du Hamel, Ed25519),
which `tools/keys/node-releasers.txt` pins. `SHASUMS256.txt` lists
`node-v24.20.0-linux-x64.tar.gz` as
`855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec` and
`node-v24.20.0-darwin-arm64.tar.gz` as
`40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8`, the
catalog's digests.

```sh
gpg --import node-releaser-5BE8A3F6.asc
gpg --verify SHASUMS256.txt.sig SHASUMS256.txt
gpg --verify SHASUMS256.txt.asc
grep -E 'node-v24.20.0-(linux-x64|darwin-arm64).tar.gz$' SHASUMS256.txt
```

## python-build-standalone/ (astral-sh/python-build-standalone)

| File | Source | sha256 |
|---|---|---|
| `SHA256SUMS.xz` | `https://github.com/astral-sh/python-build-standalone/releases/download/20260825/SHA256SUMS` (124,665 bytes, 870 lines), xz-compressed. Decompressed sha256 `8644ec401c0bb488cc4b9a051a53eae293e1c775cf45574aa3791c5f3556b680` | `0e0adbd3958ed9e7deef71a4bcb531fced0779f859daa706787479c6ea97edbf` |
| `cpython-3.12.14+20260825.provenance.sigstore.jsonl.xz` | The SLSA provenance line of `gh attestation download <archive> --repo astral-sh/python-build-standalone` for sha256 `cbdd2f0cf02f941bc5c81e546f377275e322733abffe805ac29d2b7e8a58f7e3` (API `https://api.github.com/repos/astral-sh/python-build-standalone/attestations/sha256:cbdd2f0c...`), xz-compressed. Decompressed sha256 `6eedc2d4b8ba9701129504d9d997e7f84dcf8278076f8921ad6fd9115f5147f0` | `10195d88a88b1ee49930f2b86b01d45d95b977d81d4be619c80676584a06eedc` |

One Sigstore bundle (Rekor log index 2584463306) whose in-toto statement
names 870 subjects of release 20260825, including both catalog rows
(`...-x86_64-unknown-linux-gnu-install_only` `cbdd2f0c...` and
`...-aarch64-apple-darwin-install_only` `62eef3fc...`; the subject names
carry a build timestamp, `-20260825T0845.tar.gz`, but the digests are the
release assets'). Certificate identity:
`https://github.com/astral-sh/python-build-standalone/.github/workflows/release.yml@refs/heads/main`,
issuer `https://token.actions.githubusercontent.com`. The API lists a
second attestation, GitHub's release attestation
(`https://in-toto.io/attestation/release/v0.2`). That one has a different
trust root: GitHub's own Fulcio, certificate `CN=Attester, O=GitHub, Inc.`
with SAN `https://dotcom.releases.github.com`. It says GitHub served the
asset, not who built it. It is not kept here, and
`gh release verify-asset` checks it online.

```sh
xz -dk SHA256SUMS.xz cpython-3.12.14+20260825.provenance.sigstore.jsonl.xz
gh attestation verify <archive> --repo astral-sh/python-build-standalone \
  --bundle cpython-3.12.14+20260825.provenance.sigstore.jsonl \
  --signer-workflow astral-sh/python-build-standalone/.github/workflows/release.yml
gh release verify-asset 20260825 <archive> -R astral-sh/python-build-standalone
```

## uv/ (astral-sh/uv)

| File | Source | sha256 |
|---|---|---|
| `uv-x86_64-unknown-linux-gnu.tar.gz.sha256` | `https://github.com/astral-sh/uv/releases/download/0.12.7/uv-x86_64-unknown-linux-gnu.tar.gz.sha256` | `139856b4ff4284e6f9af8b512b66acdba6456025f8518476f5b64cd84da65bd5` |
| `uv-0.12.7-x86_64-unknown-linux-gnu.attestations.sigstore.jsonl` | `gh attestation download <archive> --repo astral-sh/uv` for sha256 `788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21`: two bundles, GitHub's release attestation (43 subjects) and the SLSA provenance (22 subjects, Rekor log index 2619507376) | `6e6c49e0132e4077b59b95d06b0b54dbe833bb15736bf3945a49a11cacc6d151` |

The provenance names both catalog rows (`uv-x86_64-unknown-linux-gnu.tar.gz`
and `uv-aarch64-apple-darwin.tar.gz`, sha256 `127ebdda...`). Certificate
identity `https://github.com/astral-sh/uv/.github/workflows/release.yml@refs/heads/main`,
source commit `61291a8ca5477a9ca653f14d2ac5665587c263fa` (the 0.12.7 tag).
The release attestation (the file's first line) is signed by GitHub's
Attester (`https://dotcom.releases.github.com`), as for
python-build-standalone.

```sh
gh attestation verify <archive> --repo astral-sh/uv \
  --bundle uv-0.12.7-x86_64-unknown-linux-gnu.attestations.sigstore.jsonl \
  --signer-workflow astral-sh/uv/.github/workflows/release.yml
gh release verify-asset 0.12.7 <archive> -R astral-sh/uv
```

## ruby/ (Homebrew portable-ruby, Bundler inside it)

| File | Source | sha256 |
|---|---|---|
| `github-api-release-3.4.6.json` | `https://api.github.com/repos/Homebrew/homebrew-portable-ruby/releases/tags/3.4.6`, the full API response | `8dc3ff0e61ef422fda884e79c885fed1c9d47449a17457337e9b10081a21bd48` |
| `brew-vendor-portable-ruby-x86_64-linux-5bc7184` | `Library/Homebrew/vendor/portable-ruby-x86_64-linux` in Homebrew/brew at commit `5bc7184d3c571a7a2f38f46301a59fbb8104bd55` ("Portable Ruby 3.4.6") | `0b7a735dc8a3b72df93c97eaa938751f030f0dc7befb708fb7063c0f8431fbd5` |

Evidence of absence. The release's four assets are the bottles: no
signature, checksum file or attestation. The attestations API returns 404
for both catalog bottles (`40932a39...` Linux, `62fe925f...` Darwin). The
only second source is the Linux digest in the Homebrew/brew commit above, a
git commit, not a signature on the bottle. The release is marked
`prerelease: true`, and Homebrew reverted that brew commit on 2025-09-22
(`ff930b9b`).

```sh
jq -r '.prerelease, (.assets[] | .name + " " + .digest)' github-api-release-3.4.6.json
gh api repos/Homebrew/homebrew-portable-ruby/attestations/sha256:40932a3950ccc8bf9d13d98e692e5518427cc66b4f9520956cec349629d25259   # 404
```

## erlang-otp/ (erlef/otp_builds for Darwin, DigitalWestern/greyward-toolchains for Linux)

| File | Source URL | sha256 |
|---|---|---|
| `otp-aarch64-apple-darwin.tar.gz.sigstore` | `https://github.com/erlef/otp_builds/releases/download/OTP-29.0.5/otp-aarch64-apple-darwin.tar.gz.sigstore` | `8c23c31f84e75b3aaf3ed843e731ca990c63c994c2f6303d9fddf317186dfbba` |
| `OTP-29.0.5-x86_64-unknown-linux-gnu-fedora44.tar.gz.sha256` | `https://github.com/DigitalWestern/greyward-toolchains/releases/download/otp-29.0.5-x86_64-unknown-linux-gnu-fedora44/OTP-29.0.5-x86_64-unknown-linux-gnu-fedora44.tar.gz.sha256` | `d7da57ed81f3add22f2fc28d569eb3fd43f3b92359e80748401cfbfa7a9c903d` |
| `OTP-29.0.5-x86_64-unknown-linux-gnu-fedora44.provenance.txt` | Same release, `...fedora44.provenance.txt` | `88dcc7253c4f8c038c00e3eac3b2578354d094e30762a64dbe168158f9be4141` |

The erlef `.sigstore` file is a Sigstore bundle (SLSA provenance, one
subject `otp.tar.gz` with sha256
`24b9e00da2b9ad25b1f182e2efd73ff316e46ec4b143c0cc3c69dbd27d5a594d`, the
catalog's Darwin OTP digest; Rekor log index 2340042505). Certificate
identity
`https://github.com/erlef/otp_builds/.github/workflows/build.yaml@refs/heads/main`.
gh refuses a bundle whose name does not end in `.json` or `.jsonl`, so copy
it first:

```sh
cp otp-aarch64-apple-darwin.tar.gz.sigstore /tmp/otp-bundle.json
gh attestation verify <otp-aarch64-apple-darwin.tar.gz> --repo erlef/otp_builds \
  --bundle /tmp/otp-bundle.json \
  --signer-workflow erlef/otp_builds/.github/workflows/build.yaml
```

The greyward-toolchains Linux build has a checksum and a plain-text
provenance note, neither signed, and no attestation (API 404). There is
nothing to verify beyond `sha256sum` of the archive.

## elixir/ (elixir-lang/elixir)

| File | Source URL | sha256 |
|---|---|---|
| `elixir-otp-29.zip.sha256sum` | `https://github.com/elixir-lang/elixir/releases/download/v1.20.4/elixir-otp-29.zip.sha256sum` | `37b92a97277301498685dc7b6a81445dca02817004ac9fef7cfada322430899b` |
| `elixir-otp-29.zip.sigstore.xz` | `https://github.com/elixir-lang/elixir/releases/download/v1.20.4/elixir-otp-29.zip.sigstore` (325,735 bytes), xz-compressed. Decompressed sha256 `778d36693c04e2bf48f5dcd0d99656c5085c8648840573305c4cf1fa8b65fd70` | `beaba916ddf19f96e24c1193b016cc4dc1f7a29f25ada065b2680b25166a4bef` |

Every `.sigstore` asset of v1.20.4 has that same digest: an SPDX attestation
(`https://spdx.dev/Document/v2.2`) whose four subjects are the release's
`bom.*` files, signed by
`https://github.com/elixir-lang/elixir/.github/workflows/release.yml@refs/tags/v1.20.4`.
It verifies against `bom.spdx.json` (sha256 `aae9a123...`) and fails against
`elixir-otp-29.zip`, and the SBOM does not contain the zip's digest. The
attestations API returns 404 for the zip (`7863c546...`).

```sh
xz -dk elixir-otp-29.zip.sigstore.xz
cp elixir-otp-29.zip.sigstore /tmp/elixir-bundle.json
gh attestation verify <bom.spdx.json> --repo elixir-lang/elixir \
  --bundle /tmp/elixir-bundle.json --predicate-type https://spdx.dev/Document/v2.2   # passes
gh attestation verify <elixir-otp-29.zip> --repo elixir-lang/elixir \
  --bundle /tmp/elixir-bundle.json --predicate-type https://spdx.dev/Document/v2.2   # fails
```

## hex/ (builds.hex.pm: Hex and rebar3)

| File | Source URL | sha256 |
|---|---|---|
| `hex.csv` | `https://builds.hex.pm/installs/hex.csv` | `99c65fad5934b6ca2b4b9daae23d24aa33fd17cd29d0f352409895a366817d01` |
| `hex.csv.signed` | `https://builds.hex.pm/installs/hex.csv.signed` | `e0d5e7ec411dd765c372dac458cd57e044220bd67cc62e334e26bc311ab187a6` |
| `rebar.csv` | `https://builds.hex.pm/installs/rebar.csv` | `cb85d0b735d9dc820d276478288ffc85ddf8dbc752ea3e921a1a7956b52590e0` |
| `rebar.csv.signed` | `https://builds.hex.pm/installs/rebar.csv.signed` | `87f9323257d757b0a0c919a493cf5664fea06015aab6b9249be338e515c256c4` |
| `hex-1.x.csv` | `https://builds.hex.pm/installs/hex-1.x.csv` | `f97d2bd064325cdf91b7ad1bfa419bcf165a7a6edf47dfcf0dd38bd5890a8033` |
| `hex-1.x.csv.signed` | `https://builds.hex.pm/installs/hex-1.x.csv.signed` | `da2feb13670d45ea7be29b85ccc3b2dc34fd60ddf3a6b8c4415d1303744eab43` |
| `rebar-1.x.csv` | `https://builds.hex.pm/installs/rebar-1.x.csv` | `6636972d8d3e577f6cb6cdb7fc744dbdcc3d0aecaaaa938725d1e1c134b65a7c` |
| `rebar-1.x.csv.signed` | `https://builds.hex.pm/installs/rebar-1.x.csv.signed` | `71c5fdc30f00fa3c7f29b4deb258f4b7b61ca229323ed4b24985aaa9a0e69133` |
| `hex-installs.pem` | Written here: the "Elixir v1.1" key on `https://builds.hex.pm/installs/public_keys.html`, identical to the key Mix carried in `lib/mix/lib/mix/local.ex` until elixir-lang/elixir commit `d403bb9187` (2025-04-06) | `5abca012818198c28d036f3a358b789832942d11a931c9c98170eb9cb9d47f20` |

The `.signed` files are base64 RSA PKCS#1 v1.5 signatures over SHA-512 of
the CSV. All four verify. The key is RSA 2048; sha256 of its DER
SubjectPublicKeyInfo
`e9d3fad460cab15f3d520298782ff31061a15de930c56aa4efbdaf45d089c1ee`. Each CSV
row is `version,sha512,elixir,otp`; the catalog's rows are `hex.csv` line 90
(`2.5.1,6629f4b4...,1.20.0,29`) and `rebar.csv` line 6
(`3.25.1,992fd755...,1.18.4,28`). `tools/catalog.py` reads `hex.csv` and
`rebar.csv`; Mix reads the `-1.x` ones.

```sh
base64 -d < hex.csv.signed > /tmp/hex.csv.sig
openssl dgst -sha512 -verify hex-installs.pem -signature /tmp/hex.csv.sig hex.csv
```

(the same for `rebar.csv`, `hex-1.x.csv` and `rebar-1.x.csv`).

## dotnet/ (builds.dotnet.microsoft.com)

| File | Source URL | sha256 |
|---|---|---|
| `releases-index.json` | `https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json` | `8ec642275dad5940d6313b70fc192e53e8ba383866701a851831392e8e1ae931` |
| `releases-index.json.20261013194811.p7s` | `https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json.20261013194811.p7s`, the file the index's own `signature.file` names | `6f05831f7c9fcadb1b2162784168fce67977e9aa19e909786e2689e2fb61abab` |
| `9.0-releases.json.xz` | `https://builds.dotnet.microsoft.com/dotnet/release-metadata/9.0/releases.json` (1,167,465 bytes, Last-Modified 2026-10-13), xz-compressed. Decompressed sha256 `ffbd9fb69f1a05af0e7cb73b13cd2872c4cc8c403c6e016a4eb03ef8b15d8afb` | `5840223165dd5c1c1e61d9ef823eb8a3d39b5659ce4e314dc84334e5d4941ecb` |
| `9.0-releases.json.20261013194811.p7s` | `https://builds.dotnet.microsoft.com/dotnet/release-metadata/9.0/releases.json.20261013194811.p7s` | `3f7251fb4d9d13f65e4c5e982fdb48270b6d4a407b25cded2c273d19931004eb` |
| `dotnet-sdk-9.0.317-linux-x64.tar.gz.sha512` | `https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/dotnet-sdk-9.0.317-linux-x64.tar.gz.sha512` | `190c9d2809610eaa652fe583ece990a7449969f7182b9e35a0dd25971bae7d54` |
| `releases-index.json.sig` | `https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json.sig` | `2af53036ac2bda05afe9ab9ed48f43200c87f9fd66df671ddeda859efdedae39` |
| `9.0-releases.json.sig` | `https://builds.dotnet.microsoft.com/dotnet/release-metadata/9.0/releases.json.sig` | `92a70a36b5c8a215a5f38e7fd51d731131867e5aeee0af099ed5df66b4ee951e` |

The `.p7s` files are detached CMS (PKCS#7) signatures, signing time
2026-10-13, with an RFC 3161 timestamp from DigiCert. Both verify against
their JSON. Signer: `CN=Microsoft Corporation, OU=.NET Release,
O=Microsoft Corporation`, certificate serial
`08728983286CAE83AE10F212DAC51212`, sha256 fingerprint
`DA5E0590839DD2EA55ED3895800B2E7A9F44BD0C495506BE18A0B9CA6D7CBE81`, Code
Signing usage, valid 2026-02-16 to 2027-02-15; issued by "DigiCert Trusted
G4 Code Signing RSA4096 SHA384 2021 CA1" under "DigiCert Trusted Root G4"
(from the system trust store; the bundle carries the leaf and the
intermediate). Each signed JSON also carries `signature.expiration`
(`2027-01-11T19:48:11.9190600+00:00`), inside the signed bytes.
`9.0/releases.json` lists `dotnet-sdk-linux-x64.tar.gz` and
`dotnet-sdk-osx-arm64.tar.gz` of SDK 9.0.317 with the catalog's sha512
digests (`145bf69d...`, `f707a1c7...`).

`openssl cms -verify ... -purpose any` against the system bundle proves
only that some certificate under a public root signed the JSON, not that
Microsoft's .NET release certificate did. Printing the signer is part of
the check, not optional: compare its subject (`O=Microsoft Corporation`,
`OU=.NET Release`), its Code Signing extended key usage and its sha256
fingerprint with the values above. A future verifier must pin those, not
only the root.

```sh
xz -dk 9.0-releases.json.xz
openssl cms -verify -binary -inform DER -purpose any \
  -in releases-index.json.20261013194811.p7s -content releases-index.json \
  -CAfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem -out /dev/null
openssl cms -verify -binary -inform DER -purpose any \
  -in 9.0-releases.json.20261013194811.p7s -content 9.0-releases.json \
  -CAfile /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem -out /dev/null \
  -signer /tmp/dotnet-signer.pem
openssl x509 -in /tmp/dotnet-signer.pem -noout -subject -serial \
  -ext extendedKeyUsage -fingerprint -sha256
```

`-signer` writes the certificate that actually signed (not the first one
in the bundle, which is the intermediate). Expect `O=Microsoft
Corporation, OU=.NET Release`, serial `08728983286CAE83AE10F212DAC51212`,
`Code Signing`, and fingerprint `DA:5E:05:90:83:9D:D2:EA:55:ED:38:95:80:0B:2E:7A:9F:44:BD:0C:49:55:06:BE:18:A0:B9:CA:6D:7C:BE:81`. Do the same
for `releases-index.json`.

(`-CAfile` is Fedora's bundle path; on Debian it is
`/etc/ssl/certs/ca-certificates.crt`.) After the leaf certificate expires
(2027-02-15), a plain `openssl cms -verify` fails; the check then needs the
embedded timestamp, which `openssl cms` does not evaluate.

The two `.sig` files are orphans: OpenPGP signatures made 2026-03-25 by key
ID `FDBF53C24DB4872E`, which is not among the keys at
`https://packages.microsoft.com/keys/` nor on keyserver.ubuntu.com or
keys.openpgp.org, and older than the files beside them, so they cannot
cover the current bytes. They are kept to record that, not as evidence:

```sh
gpg --list-packets 9.0-releases.json.sig   # keyid FDBF53C24DB4872E, created 2026-03-25
```

The SDK archive itself has no `.sig`, `.asc`, `.p7s` or `.sigstore` beside it
(all 404).
