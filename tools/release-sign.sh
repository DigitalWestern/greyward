#!/bin/bash
# Sign a ward release with the release key and publish it (#698).
#
# release.yml builds every platform, attests each archive's build provenance
# and creates the GitHub Release as a draft. Nothing installs a draft:
# GitHub's `releases/latest` and its download URLs skip drafts. This script,
# run on the maintainer's machine where the release key lives, is the one
# step that makes a release installable, so a token that can write releases
# (a stolen one, or any `contents: write` job) cannot ship a binary that
# `ward update --self` or install.sh accepts.
#
#   GREYWARD_RELEASE_KEY=<key file> tools/release-sign.sh v0.3.0
#
#   1. downloads the release's archives and their .sha256 files;
#   2. checks each archive against its .sha256 and against its build
#      provenance attestation (`gh attestation verify`: built by this
#      repository's release workflow, from refs/tags/<tag> at the commit
#      the repository's tag names);
#   3. signs each archive (Ed25519 over its bytes, one line of base64 in
#      <archive>.sig) and checks the signature;
#   4. uploads the .sig files, and publishes the release when it is still
#      a draft, never marked latest;
#   5. reconciles the latest release (below).
#
#   tools/release-sign.sh --reconcile-latest   step 5 alone
#
# LATEST is how install.sh finds the latest release: it downloads
# releases/latest/download/LATEST, which GitHub redirects to the LATEST of
# whichever release is latest, checks LATEST.sig, and installs that tag.
# Reconciling makes the latest release the one with the highest SemVer 2.0
# tag (install.sh's own comparison) among every release that is published,
# no pre-release and signed, whatever order they were created or signed in,
# and makes it the only release that carries LATEST and LATEST.sig (the
# one line <tag>, signed like the archives). It runs under a lock and is
# idempotent: signing v0.1.0 after v0.2.0, or both at once, leaves v0.2.0
# the latest. A latest release without LATEST is one install.sh refuses to
# resolve.
#
# A release published before signing existed (v0.1.0, v0.2.0) has no
# attestation: `--without-attestation` signs it on its .sha256 alone, after
# its archives were checked some other way, and then reconciles like any
# other run. A release that already carries a .sig, or a LATEST, is
# refused: nothing is ever replaced.
#
#   tools/release-sign.sh --sign <file>...   write <file>.sig only, offline
#                                            (tests/install.sh uses it)
#
# The key file is the one line `ed25519:<64 hex seed>` that `ward keygen`
# writes, mode 0600. Its public key must be the RELEASE_PUBLIC_KEY in
# install.sh (the same value src/commands/selfupdate.rs compiles in); any
# other key is refused. GREYWARD_RELEASE_PUBLIC_KEY names another expected key,
# for the tests' throwaway one. Needs OpenSSL 3.0 or newer, and gh for a
# release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="DigitalWestern/greyward"

say() { printf 'release-sign: %s\n' "$*" >&2; }
die() { printf 'release-sign: error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
}

# The bytes the hex string $1 spells.
hex_to_bin() { printf '%b' "$(sed 's/../\\x&/g' <<<"$1")"; }
hex_of() { od -An -v -tx1 | tr -d ' \n'; }

attest=1
mode=release
case "${1:-}" in
    --sign) mode=sign; shift ;;
    --without-attestation) attest=0; shift ;;
    --reconcile-latest) mode=reconcile; shift ;;
    -h | --help | "") usage ;;
esac
[ "$#" -ge 1 ] || [ "$mode" = reconcile ] || usage
command -v openssl >/dev/null || die "needs openssl (3.0 or newer)"

# --- the key ----------------------------------------------------------------
key_file="${GREYWARD_RELEASE_KEY:-}"
[ -n "$key_file" ] || die "set GREYWARD_RELEASE_KEY to the release key file"
[ -f "$key_file" ] && [ ! -L "$key_file" ] || die "$key_file is not a regular file"
perm="$(stat -c %a "$key_file" 2>/dev/null || stat -f %Lp "$key_file")"
case "$perm" in
    *00) ;;
    *) die "$key_file has mode $perm, readable by group or other; run 'chmod 600' on it" ;;
esac
line="$(head -c 200 "$key_file")"
seed="${line#ed25519:}"
[ "$seed" != "$line" ] && [ "${#seed}" = 64 ] && [[ "$seed" =~ ^[0-9a-f]+$ ]] \
    || die "$key_file is not one line 'ed25519:<64 hex>'"

work="$(mktemp -d "${TMPDIR:-/tmp}/greyward-release-sign.XXXXXX")"
trap 'rm -rf "$work"' EXIT
umask 077
# The seed as PKCS#8 DER: the fixed Ed25519 prefix, then the 32 bytes.
hex_to_bin "302e020100300506032b657004220420$seed" >"$work/key.der"
public="ed25519:$(openssl pkey -inform DER -in "$work/key.der" -pubout -outform DER | tail -c 32 | hex_of)"
openssl pkey -inform DER -in "$work/key.der" -pubout -outform DER -out "$work/public.der"
expected="${GREYWARD_RELEASE_PUBLIC_KEY:-$(sed -n 's/^RELEASE_PUBLIC_KEY="\(.*\)"$/\1/p' "$ROOT/install.sh")}"
[ "$public" = "$expected" ] \
    || die "$key_file is the key $public, not the release key $expected"

# Sign $1 into $1.sig and check the result the way install.sh will.
sign_file() {
    openssl pkeyutl -sign -keyform DER -inkey "$work/key.der" -rawin \
        -in "$1" -out "$work/signature.bin"
    openssl base64 -A -in "$work/signature.bin" -out "$1.sig"
    printf '\n' >>"$1.sig"
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/public.der" -rawin \
        -in "$1" -sigfile "$work/signature.bin" >/dev/null \
        || die "the signature just made for $1 does not verify"
    say "signed $(basename "$1")"
}

# The same grammar and precedence install.sh holds a LATEST to, read out
# of install.sh.
eval "$(sed -n '/^# >>> semver/,/^# <<< semver/p' "$ROOT/install.sh")"

# --- the latest release -------------------------------------------------------
# Make GitHub's latest release, and its LATEST, the highest SemVer 2.0 tag
# among the releases that are published, no pre-release, and signed (they
# carry a greyward-*.tar.gz.sig: install.sh installs nothing else). Every
# release is listed through the API, page by page, so neither a count nor
# the order releases were created in decides anything. That release gets
# LATEST and LATEST.sig (written again only when they are not already its
# tag under a valid signature) and GitHub's latest mark; every other
# release loses any LATEST it carries. A lock under the user's runtime (or
# cache) directory keeps two runs from interleaving, and running it again
# changes nothing, so a run cut short is finished by
# `tools/release-sign.sh --reconcile-latest`.
reconcile_latest() {
    local lock_dir="${XDG_RUNTIME_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}}"
    mkdir -p "$lock_dir"
    exec 9>"$lock_dir/greyward-release-sign.lock"
    if command -v flock >/dev/null; then
        flock 9
    else
        # No flock (macOS): a directory is created atomically or not at all.
        until mkdir "$lock_dir/greyward-release-sign.lock.d" 2>/dev/null; do sleep 1; done
        trap 'rm -rf "$work"; rmdir "$lock_dir/greyward-release-sign.lock.d" 2>/dev/null' EXIT
    fi
    # One line per release, `release <tag> <draft> <prerelease> <signed>`,
    # and one per LATEST asset, `asset <tag> <name>`.
    local listing
    listing="$(gh api --paginate "repos/$REPO/releases?per_page=100" --jq '.[] |
        ("release \(.tag_name) \(.draft) \(.prerelease) \([.assets[].name | select(startswith("greyward-") and endswith(".tar.gz.sig"))] | length > 0)"),
        (.tag_name as $t | .assets[] | select(.name == "LATEST" or .name == "LATEST.sig") | "asset \($t) \(.name)")')" \
        || die "cannot list the releases of $REPO"
    local top="" kind name draft prerelease signed
    while read -r kind name draft prerelease signed; do
        [ "$kind" = release ] && [ "$draft" = false ] && [ "$prerelease" = false ] || continue
        if [ "$signed" != true ]; then
            say "release $name carries no signature, so it is never the latest one"
            continue
        fi
        if ! [[ "$name" == v* ]] || ! semver_valid "$name"; then
            say "ignoring release $name: its tag is no v<SemVer 2.0 version>"
            continue
        fi
        if [ -z "$top" ] || [ "$(semver_cmp "$name" "$top")" = 1 ]; then top="$name"; fi
    done <<<"$listing"
    [ -n "$top" ] || { say "no published, signed release yet: nothing is the latest one"; return 0; }

    # LATEST on the latest release: kept when it already says $top under a
    # valid signature, written otherwise.
    mkdir -p "$work/latest"
    rm -f "$work/latest/"*
    if grep -qx "asset $top LATEST" <<<"$listing" && grep -qx "asset $top LATEST.sig" <<<"$listing"; then
        gh release download "$top" --repo "$REPO" --dir "$work/latest" --pattern LATEST --pattern LATEST.sig
    fi
    if [ -f "$work/latest/LATEST" ] && [ "$(cat "$work/latest/LATEST")" = "$top" ] \
        && [ "$(wc -l <"$work/latest/LATEST")" = 1 ] \
        && openssl base64 -d -A -in "$work/latest/LATEST.sig" -out "$work/latest/sig.bin" 2>/dev/null \
        && openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/public.der" -rawin \
            -in "$work/latest/LATEST" -sigfile "$work/latest/sig.bin" >/dev/null 2>&1; then
        say "$top already carries its LATEST"
    else
        rm -f "$work/latest/"*
        printf '%s\n' "$top" >"$work/latest/LATEST"
        sign_file "$work/latest/LATEST"
        gh release upload "$top" --repo "$REPO" --clobber "$work/latest/LATEST" "$work/latest/LATEST.sig"
    fi
    if [ "$(gh api "repos/$REPO/releases/latest" --jq .tag_name 2>/dev/null || true)" != "$top" ]; then
        gh release edit "$top" --repo "$REPO" --latest
    fi
    # Then, and only then, no other release names itself the latest.
    local tag_of
    while read -r kind tag_of name _; do
        [ "$kind" = asset ] && [ "$tag_of" != "$top" ] || continue
        gh release delete-asset "$tag_of" "$name" --repo "$REPO" --yes
        say "removed $name from $tag_of"
    done <<<"$listing"
    say "$top is the latest release, and the only one with a LATEST"
}

if [ "$mode" = reconcile ]; then
    command -v gh >/dev/null || die "needs gh, signed in with write access to $REPO"
    reconcile_latest
    exit 0
fi

if [ "$mode" = sign ]; then
    for file in "$@"; do
        [ -f "$file" ] || die "$file is not a file"
        [ ! -e "$file.sig" ] || die "$file.sig exists; nothing is replaced"
        sign_file "$file"
    done
    exit 0
fi

# --- a release ----------------------------------------------------------------
[ "$#" = 1 ] || usage
tag="$1"
[[ "$tag" == v* ]] && semver_valid "$tag" \
    || die "'$tag' is not a release tag (v<SemVer 2.0 version>)"
command -v gh >/dev/null || die "needs gh, signed in with write access to $REPO"
names="$(gh release view "$tag" --repo "$REPO" --json assets -q '.assets[].name')" \
    || die "no release $tag in $REPO"
if grep -q '\.sig$' <<<"$names"; then
    die "release $tag already carries .sig files; nothing is replaced"
fi
if grep -qx 'LATEST' <<<"$names"; then
    die "release $tag already carries a LATEST; nothing is replaced"
fi
archives="$(grep -E '^greyward-[A-Za-z0-9_.-]+\.tar\.gz$' <<<"$names" || true)"
[ -n "$archives" ] || die "release $tag has no greyward-<triple>.tar.gz"
# The commit the tag names, read from the repository, never from the draft:
# whoever can write releases can point a draft at any commit, or upload an
# older release's attested archive into it. The attestation must say the
# archive was built from this tag at this commit. GREYWARD_RELEASE_REMOTE
# names another repository for tests/install.sh.
remote="${GREYWARD_RELEASE_REMOTE:-https://github.com/$REPO.git}"
refs="$(git ls-remote --tags "$remote" "refs/tags/$tag" "refs/tags/$tag^{}")" \
    || die "cannot read the tags of $remote"
# An annotated tag lists its object and, as <tag>^{}, the commit it peels to.
commit="$(awk -v ref="refs/tags/$tag^{}" '$2 == ref { print $1 }' <<<"$refs")"
[ -n "$commit" ] || commit="$(awk -v ref="refs/tags/$tag" '$2 == ref { print $1 }' <<<"$refs")"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "$remote has no tag $tag"

mkdir "$work/assets"
gh release download "$tag" --repo "$REPO" --dir "$work/assets" \
    --pattern 'greyward-*.tar.gz' --pattern 'greyward-*.tar.gz.sha256'
while read -r archive; do
    file="$work/assets/$archive"
    [ -f "$file.sha256" ] || die "$archive has no .sha256 next to it"
    want="$(cut -d' ' -f1 "$file.sha256" | tr -d '\r\n')"
    got="$( (sha256sum "$file" 2>/dev/null || shasum -a 256 "$file") | cut -d' ' -f1)"
    [ "$want" = "$got" ] || die "$archive does not match its .sha256 ($want, got $got)"
    if [ "$attest" = 1 ]; then
        gh attestation verify "$file" --repo "$REPO" \
            --signer-workflow "$REPO/.github/workflows/release.yml" \
            --source-ref "refs/tags/$tag" --source-digest "$commit" >/dev/null \
            || die "$archive has no build provenance attestation from $REPO's release workflow for tag $tag at $commit"
    fi
    sign_file "$file"
done <<<"$archives"


# Published, and never marked latest here: which release is the latest one
# is decided once every signing run is done, by reconcile_latest.
gh release upload "$tag" --repo "$REPO" "$work"/assets/*.sig
if [ "$(gh release view "$tag" --repo "$REPO" --json isDraft -q .isDraft)" = true ]; then
    gh release edit "$tag" --repo "$REPO" --draft=false --latest=false
    say "published $tag"
fi
say "every archive of $tag is signed by $public"
reconcile_latest
