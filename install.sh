#!/bin/sh
# ward installer: download the release binary for this machine, put it on
# PATH, and wire shell completions. POSIX sh on purpose; it must run under
# dash, bash, zsh, and macOS /bin/sh.
#
#   curl -fsSL https://raw.githubusercontent.com/DigitalWestern/greyward/main/install.sh | sh
#
# Options (as arguments, or environment variables):
#   --version=<v>       release tag to install (GREYWARD_VERSION; default: latest)
#   --dir=<path>        where the binary goes (GREYWARD_INSTALL_DIR; default ~/.local/bin)
#   --no-modify-path    never edit shell startup files (GREYWARD_NO_MODIFY_PATH=1)
#   --no-completions    skip shell completions
#   --uninstall         remove everything this script installed (not the store)
#   --help
#
# What it changes on disk, and nothing else:
#   <dir>/ward                          the binary
#   ~/.greyward/env                         POSIX snippet that prepends <dir> to PATH
#   ~/.greyward/completions/_ward        zsh completion (autoloaded via fpath)
#   ~/.local/share/bash-completion/completions/ward
#   ~/.config/fish/completions/ward.fish
#   ~/.config/fish/conf.d/ward.fish     fish PATH hook
#   one marked block appended to ~/.profile, ~/.bashrc, ~/.bash_profile,
#   and ~/.zshrc when they exist (or the one your $SHELL reads), only when
#   <dir> is not already on PATH.
#
# What it never touches: the store (~/.greyward/store, or GREYWARD_STORE), ~/.greyward/x,
# and ~/.greyward/forests. Those hold downloaded toolchains and realized
# environments, they can be several GiB, and --uninstall leaves them alone
# and says so.
#
# What it trusts: the archive must be signed by the release key below
# (RELEASE_PUBLIC_KEY), checked with openssl 3.0 or newer, and the new binary
# must run here before it replaces the old one: `ward --version` exits 0 and
# prints exactly the version of the tag being installed. The latest release
# is the tag in its LATEST asset, signed by the same key. Without
# --version, a ward newer than the latest release (SemVer 2.0 precedence),
# or one whose --version is not the one line `ward <version>`, is left
# alone; naming an older version installs it, and says it is a downgrade.
#
# A script cannot change the PATH of the shell that piped it in. The last
# line it prints is the one command that finishes the job for the current
# terminal; every new terminal picks it up on its own.

set -eu

# Every path below hangs off HOME, and `set -u` would report it as a bare
# "unbound variable" with no hint about what to do.
if [ -z "${HOME:-}" ]; then
    printf 'greyward-install: error: %s\n' \
        "HOME is not set; run this as a real user, or pass --dir=<path> with HOME=<path> set" >&2
    exit 1
fi

REPO="DigitalWestern/greyward"
# The release key. Every greyward-<triple>.tar.gz is signed by its private
# half, which never leaves the maintainer's machine (tools/release-sign.sh),
# in <asset>.sig next to it; the .sha256 beside it comes from the same
# release, so it only catches a corrupt download. `ward update --self`
# compiles in the same value (src/commands/selfupdate.rs).
RELEASE_PUBLIC_KEY="ed25519:ba1310b1b3eb6bc182ee4aef6058aaa2d643eaa71699ab87a2f6d02009fd32dd"
# Test hook, like GREYWARD_DOWNLOAD_BASE: tests/install.sh signs its release
# with a throwaway key.
RELEASE_KEY="${GREYWARD_RELEASE_PUBLIC_KEY:-$RELEASE_PUBLIC_KEY}"
VERSION="${GREYWARD_VERSION:-latest}"
INSTALL_DIR="${GREYWARD_INSTALL_DIR:-$HOME/.local/bin}"
# Only a real value turns PATH editing off: GREYWARD_NO_MODIFY_PATH=0 used to
# disable it, which is the opposite of what it reads like.
MODIFY_PATH=1
case "${GREYWARD_NO_MODIFY_PATH:-}" in
    '' | 0 | false | no) ;;
    *) MODIFY_PATH=0 ;;
esac
COMPLETIONS=1
UNINSTALL=0
GREYWARD_HOME="$HOME/.greyward"
STORE="${GREYWARD_STORE:-$GREYWARD_HOME/store}"
MARK_BEGIN="# >>> ward >>>"
MARK_END="# <<< ward <<<"
shell_name="$(basename "${SHELL:-sh}")"
zdotdir="${ZDOTDIR:-$HOME}"

say()  { printf 'greyward-install: %s\n' "$*" >&2; }
fail() { printf 'greyward-install: error: %s\n' "$*" >&2; exit 1; }

# $1 single-quoted for a shell, with embedded apostrophes escaped, so a path
# printed as a command to run is safe to paste whatever is in it. Done with
# parameter expansion rather than sed: the sed program for this has to carry
# backslashes through the shell's quoting and then through sed's replacement
# rules, and getting that wrong is silent -- a path with two apostrophes came
# out as a valid command for the wrong directory.
shquote() {
    _sq_rest="$1"
    _sq_out=""
    _sq_q="'"
    while :; do
        case "$_sq_rest" in
            *"$_sq_q"*) ;;
            *) break ;;
        esac
        _sq_out=$_sq_out${_sq_rest%%"$_sq_q"*}$_sq_q\\$_sq_q$_sq_q
        _sq_rest=${_sq_rest#*"$_sq_q"}
    done
    printf '%s%s%s' "$_sq_q" "$_sq_out$_sq_rest" "$_sq_q"
}

# $1 single-quoted for fish, whose single quotes treat a backslash as an
# escape: every backslash and apostrophe gets one in front of it. One byte at
# a time, with parameter expansion, for the same reason as shquote.
fishquote() {
    _fq_rest="$1"
    _fq_out=""
    while [ -n "$_fq_rest" ]; do
        _fq_c="${_fq_rest%"${_fq_rest#?}"}"
        _fq_rest="${_fq_rest#?}"
        case "$_fq_c" in
            "'" | \\) _fq_out="$_fq_out\\$_fq_c" ;;
            *) _fq_out="$_fq_out$_fq_c" ;;
        esac
    done
    printf "'%s'" "$_fq_out"
}

# Write the bytes the hex string $1 spells, two digits a byte. POSIX printf
# has no \x escape, so each byte goes out as the octal one it does have.
hex_to_bin() {
    _hb_rest="$1"
    while [ -n "$_hb_rest" ]; do
        _hb_byte="${_hb_rest%"${_hb_rest#??}"}"
        _hb_rest="${_hb_rest#??}"
        # shellcheck disable=SC2059 # the format is the escape being written
        printf "\\$(printf '%03o' "$((0x$_hb_byte))")"
    done
}

usage() {
    cat <<'EOF'
Usage: install.sh [--version=<tag>] [--dir=<path>] [--no-modify-path] [--no-completions]
       install.sh --uninstall [--dir=<path>]

  --version=<tag>    release to install (default: latest; also GREYWARD_VERSION)
  --dir=<path>       where the binary goes (default ~/.local/bin; also GREYWARD_INSTALL_DIR)
  --no-modify-path   never edit shell startup files (also GREYWARD_NO_MODIFY_PATH=1)
  --no-completions   skip bash/zsh/fish completions
  --uninstall        remove the binary, the env file, the completions, and the
                     PATH blocks this script wrote; the store is left alone
EOF
}

for arg in "$@"; do
    case "$arg" in
        --version=*) VERSION="${arg#--version=}" ;;
        --dir=*)
            INSTALL_DIR="${arg#--dir=}"
            [ -n "$INSTALL_DIR" ] || fail "--dir= needs a path (e.g. --dir=\$HOME/bin)"
            ;;
        --no-modify-path) MODIFY_PATH=0 ;;
        --no-completions) COMPLETIONS=0 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown option '$arg' (try --help)" ;;
    esac
done
# GREYWARD_INSTALL_DIR= (set but empty) reaches here the same way --dir= does.
[ -n "$INSTALL_DIR" ] || fail "install directory is empty; set GREYWARD_INSTALL_DIR or pass --dir=<path>"

# --- paths and probes -------------------------------------------------------
# The real path of $1: follow the leaf's symlink chain (bounded, so a loop
# cannot hang the script), then resolve the directory with `cd -P` so a
# symlinked parent collapses too. Lexical comparison is not enough:
# `bin/ward -> ../elsewhere/ward` is inside the directory only on paper.
resolve_path() {
    _rs_path="$1"
    _rs_hops=0
    while [ -L "$_rs_path" ] && [ "$_rs_hops" -lt 40 ]; do
        _rs_target="$(readlink "$_rs_path")" || return 1
        case "$_rs_target" in
            /*) _rs_path="$_rs_target" ;;
            *) _rs_path="$(dirname "$_rs_path")/$_rs_target" ;;
        esac
        _rs_hops=$((_rs_hops + 1))
    done
    [ "$_rs_hops" -lt 40 ] || return 1
    _rs_dir="$(cd -P "$(dirname "$_rs_path")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s' "$_rs_dir" "$(basename "$_rs_path")"
}

# `<path> --version`, bounded. Whatever sits at that path is an unknown
# program: it may block on a tty, a socket, or a lock. `timeout` is not in
# POSIX and stock macOS does not ship it, so where it is missing the probe
# runs unbounded -- which is what every version of this script did before.
# run_version keeps the program's exit status; probe_version reports empty
# output, or a non-zero exit, as no version at all.
run_version() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 5 "$1" --version 2>/dev/null
    else
        "$1" --version 2>/dev/null
    fi
}
probe_version() { run_version "$1" || true; }
# version_of <path>: its --version output in version_out, and its exit
# status. The output goes to a file first, every byte of it: a command
# substitution would drop trailing newlines and NUL bytes. Over 512 bytes,
# or holding a NUL, it is no version. Otherwise, when it is exactly one
# version line and its newline, the line goes in version_seen; else that is
# empty. Needs $tmp.
NL='
'
version_of() {
    _vo_file="$tmp/version-output"
    _vo_status=0
    run_version "$1" >"$_vo_file" || _vo_status=$?
    version_seen=""
    _vo_bytes="$(wc -c <"$_vo_file")"
    if [ "$((_vo_bytes))" -gt 512 ] || ! tr -d '\000' <"$_vo_file" | cmp -s - "$_vo_file"; then
        # Shown, never read: its first bytes without the NULs.
        version_out="$(dd if="$_vo_file" bs=80 count=1 2>/dev/null | tr -d '\000')"
        return "$_vo_status"
    fi
    version_out="$(cat "$_vo_file"; printf x)"
    version_out="${version_out%x}"
    case "$version_out" in
        *"$NL") version_line "${version_out%"$NL"}" && version_seen="${version_out%"$NL"}" ;;
    esac
    return "$_vo_status"
}
# The first line of version_out, at most 80 bytes, for a message.
version_shown() { printf '%s\n' "$version_out" | head -n 1 | cut -c 1-80; }

# >>> semver (tests/install.sh reads this block out of the script)
# SemVer 2.0 precedence of version $1 against version $2: prints -1, 0 or 1,
# or `bad` when either is not a version. Both are first held to the full
# SemVer 2.0 grammar (semver.org's regular expression, plus an optional
# leading `v`): no leading zeros in a number, no empty identifier, build
# metadata well formed when present. Then the `v` and the build metadata
# (which precedence ignores) are dropped, major.minor.patch compare, a
# release sorts above its pre-releases, and pre-release identifiers compare
# dot by dot: an all-digit identifier below any other, two all-digit ones
# by length and then digit by digit (so any size compares exactly), others
# in ASCII order, and a shorter list below a longer one it is a prefix of.
# No arithmetic anywhere: 0.3.0-alpha < 0.3.0-alpha.1 < 0.3.0-alpha.beta <
# 0.3.0-beta < 0.3.0-rc.9 < 0.3.0-rc.10 < 0.3.0, and 1.0.0--1 < 1.0.0--2.
# A version longer than 256 bytes is no version: nothing past the cap is
# ever compared. (The grammar is ASCII only, so a string of at most 256
# characters that matches it is also at most 256 bytes.)
SEMVER_ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER_BODY="v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-$SEMVER_ID(\\.$SEMVER_ID)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?"
SEMVER_MAX=256
semver_valid() {
    case "$1" in
        "" | *"
"*) return 1 ;;
    esac
    [ "${#1}" -le "$SEMVER_MAX" ] || return 1
    printf '%s\n' "$1" | LC_ALL=C grep -Eq "^$SEMVER_BODY\$"
}
# The one line an installed ward's --version must print to be read:
# `ward <version>`, or `ward <version> (<commit> <date>)` the way ward
# prints it (`(unknown unknown)` for a build outside git). Two lines, a
# word after it, or an over-long version is no version line.
version_line() {
    case "$1" in
        *"
"*) return 1 ;;
    esac
    [ "${#1}" -le $((SEMVER_MAX + 90)) ] || return 1
    printf '%s\n' "$1" | LC_ALL=C grep -Eq "^ward $SEMVER_BODY( \\([0-9A-Za-z.-]{1,40} [0-9A-Za-z.-]{1,40}\\))?\$"
}
# 0 when $1 sorts before $2 byte by byte: awk compares two strings (never
# numbers, the "" forces it) in the C locale's byte order.
semver_before() {
    _sb_a="$1" _sb_b="$2" LC_ALL=C awk 'BEGIN { exit !((ENVIRON["_sb_a"] "") < (ENVIRON["_sb_b"] "")) }'
}
# Two identifiers (never empty): -1, 0 or 1.
semver_id_cmp() {
    case "$1" in *[!0-9]*) _si_kind=w ;; *) _si_kind=n ;; esac
    case "$2" in *[!0-9]*) _si_kind="${_si_kind}w" ;; *) _si_kind="${_si_kind}n" ;; esac
    case "$_si_kind" in
        nw) echo -1; return ;;
        wn) echo 1; return ;;
        nn)
            # No leading zeros, so the longer number is the larger one.
            if [ "${#1}" -lt "${#2}" ]; then echo -1; return; fi
            if [ "${#1}" -gt "${#2}" ]; then echo 1; return; fi
            ;;
    esac
    if [ "$1" = "$2" ]; then
        echo 0
    elif semver_before "$1" "$2"; then
        echo -1
    else
        echo 1
    fi
}
# Two dot-separated identifier lists, left to right: -1, 0 or 1.
semver_list_cmp() {
    _sl_a="$1"; _sl_b="$2"
    while [ -n "$_sl_a" ] && [ -n "$_sl_b" ]; do
        _sl_x="${_sl_a%%.*}"; _sl_y="${_sl_b%%.*}"
        case "$_sl_a" in *.*) _sl_a="${_sl_a#*.}" ;; *) _sl_a="" ;; esac
        case "$_sl_b" in *.*) _sl_b="${_sl_b#*.}" ;; *) _sl_b="" ;; esac
        _sl_c="$(semver_id_cmp "$_sl_x" "$_sl_y")"
        if [ "$_sl_c" != 0 ]; then echo "$_sl_c"; return; fi
    done
    if [ -n "$_sl_a" ]; then echo 1
    elif [ -n "$_sl_b" ]; then echo -1
    else echo 0
    fi
}
semver_cmp() {
    if ! semver_valid "$1" || ! semver_valid "$2"; then echo bad; return; fi
    _sc_a="${1#v}"; _sc_a="${_sc_a%%+*}"
    _sc_b="${2#v}"; _sc_b="${_sc_b%%+*}"
    # The core holds no `-`; everything after the first one is the pre-release.
    _sc_c="$(semver_list_cmp "${_sc_a%%-*}" "${_sc_b%%-*}")"
    if [ "$_sc_c" != 0 ]; then echo "$_sc_c"; return; fi
    case "$_sc_a" in *-*) _sc_ap="${_sc_a#*-}" ;; *) _sc_ap="" ;; esac
    case "$_sc_b" in *-*) _sc_bp="${_sc_b#*-}" ;; *) _sc_bp="" ;; esac
    if [ -z "$_sc_ap" ] && [ -z "$_sc_bp" ]; then echo 0
    elif [ -z "$_sc_ap" ]; then echo 1
    elif [ -z "$_sc_bp" ]; then echo -1
    else semver_list_cmp "$_sc_ap" "$_sc_bp"
    fi
}
# <<< semver

# --- uninstall --------------------------------------------------------------
# Removes exactly what the header says this script writes, and nothing else.
# The store is data, not an installation: it is named, sized, and left behind.
# Never fatal: a file that will not go is reported, and the rest still runs.
drop_file() {
    [ -e "$1" ] || [ -L "$1" ] || return 0
    if rm -f "$1"; then
        say "removed $1"
    else
        say "could not remove $1"
    fi
    return 0
}

# Is there exactly one well-formed ward block in $1? Whole-line comparison,
# so a marker quoted inside a longer line is not a marker; and the state
# machine catches what counting cannot: an end before its begin, a begin
# inside an open block, or a block still open at EOF.
#   0 = one or more well-formed blocks   1 = no marker at all   2 = malformed
scan_markers() {
    awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
        $0 == begin { if (open) { bad = 1; exit } open = 1; seen = 1; next }
        $0 == end   { if (!open) { bad = 1; exit } open = 0; next }
        END { if (bad || open) exit 2; if (!seen) exit 1; exit 0 }
    ' "$1" 2>/dev/null
}

# Delete the marked block. A startup file is somebody's shell, so: refuse on
# anything that is not a clean begin/end pair, edit the file the path really
# resolves to rather than a symlink standing in for it, keep a .greyward.bak, and
# swap the rewrite in by rename so an interrupted uninstall leaves no
# half-file.
strip_block() {
    file="$1"
    [ -f "$file" ] || return 0

    # A dotfile is often a symlink into a dotfiles repo (stow, chezmoi). Edit
    # the file it points at: renaming over the link would replace the link
    # with a regular file and leave the real rc untouched.
    target="$(resolve_path "$file")" \
        || { say "could not resolve $file (left as it is)"; return 0; }
    [ -f "$target" ] || return 0

    status=0
    scan_markers "$target" || status=$?
    [ "$status" = 1 ] && return 0
    if [ "$status" != 0 ]; then
        say "$target has a malformed ward block (an end marker before its begin, a nested begin, or no end at all); refusing to edit it. Remove the block by hand."
        return 0
    fi

    backup="$target.greyward.bak"
    if [ -L "$backup" ]; then
        say "$backup is a symlink; refusing to write a backup through it. Remove it and run --uninstall again."
        return 0
    fi
    # mktemp reserves an unpredictable name next to the file; cp then
    # recreates it so the scratch carries the rc file's mode and the rename
    # cannot change the file's bits.
    scratch="$(mktemp "$target.greyward-uninstall.XXXXXX" 2>/dev/null)" \
        || { say "could not create a scratch file next to $target (left as it is)"; return 0; }
    rm -f "$scratch"
    cp "$target" "$backup" 2>/dev/null \
        || { say "could not back up $target (left as it is)"; return 0; }
    cp "$target" "$scratch" 2>/dev/null \
        || { say "could not rewrite $target (left as it is)"; return 0; }
    if awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
        $0 == begin { skip = 1; next }
        $0 == end   { skip = 0; next }
        skip { next }
        { print }
    ' "$target" >"$scratch" 2>/dev/null && mv -f "$scratch" "$target"; then
        say "removed the ward block from $target (previous copy: $backup)"
    else
        say "could not rewrite $target (left as it is)"
        rm -f "$scratch"
    fi
}

# Is <path> a file this script would have installed? Two questions, both
# answered before anything is deleted: does it really live in the install
# directory -- resolved, not spelled, so `bin/ward -> ../elsewhere/ward` is
# refused -- and does running it say "ward "?
removable() {
    [ -f "$1" ] || return 1
    real="$(resolve_path "$1")" \
        || { say "could not resolve $1; leaving it alone"; return 1; }
    real_dir="$(cd -P "$INSTALL_DIR" 2>/dev/null && pwd -P)" \
        || { say "could not resolve $INSTALL_DIR; leaving $1 alone"; return 1; }
    if [ "${real%/*}" != "$real_dir" ]; then
        say "$1 resolves to $real, outside $real_dir; leaving it alone"
        return 1
    fi
    version="$(probe_version "$1")"
    case "$version" in
        "ward "*) return 0 ;;
        *)
            say "$1 does not identify itself as ward; leaving it alone"
            return 1
            ;;
    esac
}

uninstall() {
    if [ ! -e "$INSTALL_DIR/ward" ] && [ ! -L "$INSTALL_DIR/ward" ]; then
        say "no ward binary at $INSTALL_DIR/ward (use --dir=<path> if it is elsewhere)"
    elif [ -L "$INSTALL_DIR/ward" ] && [ ! -e "$INSTALL_DIR/ward" ]; then
        # Dangling: nothing to ask for a version, and nothing to be sure of.
        say "$INSTALL_DIR/ward is a symlink to $(readlink "$INSTALL_DIR/ward"), which does not exist; leaving it alone"
    elif removable "$INSTALL_DIR/ward"; then
        gone="$version"
        if rm -f "$INSTALL_DIR/ward"; then
            say "removed $gone from $INSTALL_DIR/ward"
        else
            say "could not remove $INSTALL_DIR/ward"
        fi
    fi
    drop_file "$GREYWARD_HOME/env"
    drop_file "$GREYWARD_HOME/completions/_ward"
    rmdir "$GREYWARD_HOME/completions" 2>/dev/null || true
    drop_file "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/ward"
    drop_file "${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/ward.fish"
    drop_file "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/ward.fish"
    strip_block "$HOME/.profile"
    strip_block "$HOME/.bashrc"
    strip_block "$HOME/.bash_profile"
    strip_block "$zdotdir/.zshrc"

    say "not removed, because it is your data and not the installation:"
    if [ -d "$STORE" ]; then
        size="$(du -sh "$STORE" 2>/dev/null | cut -f1)"
        say "  $STORE (${size:-size unknown}) - toolchains, packages, environments"
    else
        say "  $STORE (does not exist) - toolchains, packages, environments"
    fi
    for extra in "$GREYWARD_HOME/x" "$GREYWARD_HOME/forests"; do
        if [ -d "$extra" ]; then say "  $extra"; fi
    done
    say "to reclaim that space:  rm -rf $(shquote "$STORE")"
    say "projects keep their own .venv, node_modules and .greyward/ until you delete them"
    say "done. The current terminal may still have ward cached; run 'hash -r'"
}

if [ "$UNINSTALL" = 1 ]; then
    uninstall
    exit 0
fi

# --- platform ---------------------------------------------------------------
# Same two rows as src/kernel/platform.rs; anything else must build from source.
# release.yml builds Linux x86_64 only until the macOS gate (FOLLOW-UPS.md); the Darwin
# row stays so a release that carries the asset again needs no script change.
os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
    Linux/x86_64) triple="x86_64-unknown-linux-gnu" ;;
    Darwin/arm64) triple="aarch64-apple-darwin" ;;
    *)
        fail "no prebuilt binary for $os/$arch (releases are built for Linux x86_64).
  Build from source instead:  cargo install --git https://github.com/$REPO --locked"
        ;;
esac
if [ "$triple" = "x86_64-unknown-linux-gnu" ] && [ ! -e /lib64/ld-linux-x86-64.so.2 ]; then
    fail "this Linux has no glibc loader at /lib64/ld-linux-x86-64.so.2 (musl or Alpine?); ward pins glibc toolchains"
fi

# --- download ---------------------------------------------------------------
asset="greyward-$triple.tar.gz"

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
else
    fail "need curl or wget to download the $asset release asset"
fi

if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    fail "need sha256sum or shasum to verify the download"
fi

# The signature check needs OpenSSL 3.0 or newer (`pkeyutl -rawin`, Ed25519).
command -v openssl >/dev/null 2>&1 \
    || fail "need openssl (3.0 or newer) to verify the release signature. Install it, or download
  the release by hand and check it with:  gh attestation verify <asset> --repo $REPO"
key_hex="${RELEASE_KEY#ed25519:}"
case "$RELEASE_KEY" in ed25519:*) ;; *) key_hex="" ;; esac
case "$key_hex" in *[!0-9a-f]*) key_hex="" ;; esac
[ "${#key_hex}" = 64 ] || fail "release key '$RELEASE_KEY' is not ed25519:<64 lower-case hex>"

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t greyward-install)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# A signature: Ed25519 over a file's bytes, one line of base64 in its .sig.
# The public key goes to openssl as DER, the fixed SubjectPublicKeyInfo
# prefix for Ed25519 followed by the key's 32 bytes. verify_sig <file> <sig>
# fails for a .sig that is not base64 or not by the release key.
hex_to_bin "302a300506032b6570032100$key_hex" >"$tmp/release-key.der"
verify_sig() {
    openssl base64 -d -A -in "$2" -out "$2.bin" 2>/dev/null || return 1
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp/release-key.der" -rawin \
        -in "$1" -sigfile "$2.bin" >/dev/null 2>&1
}

# The exact release this run installs, as a tag, and whether it was named.
# A named version may replace a newer installed ward (a downgrade, said as
# one); `latest` never does. `latest` is the tag in the newest release's
# LATEST asset: one line, signed by the release key like the archives
# (tools/release-sign.sh writes it), fetched from GitHub's
# releases/latest/download/LATEST, whose redirects curl or wget follow on
# their own. It is read before anything else is downloaded, so the binary
# is held to that tag below: an older release's validly signed assets,
# uploaded into a newer release, do not install. GREYWARD_LATEST_TAG names
# the tag for a caller that resolved it already (action.yml, with its
# token), and GREYWARD_LATEST_URL another LATEST to read (tests/install.sh).
case "$VERSION" in
    latest)
        named=0
        tag="${GREYWARD_LATEST_TAG:-}"
        if [ -z "$tag" ]; then
            latest_url="${GREYWARD_LATEST_URL:-https://github.com/$REPO/releases/latest/download/LATEST}"
            # Twice at most: the latest release can change between the two
            # downloads (another release becoming latest), and then the
            # pair is read again from the start.
            latest_signed=0
            for _ in 1 2; do
                fetch "$latest_url" "$tmp/LATEST" \
                    || fail "cannot read the latest release from $latest_url; name one with --version=<tag>"
                fetch "$latest_url.sig" "$tmp/LATEST.sig" \
                    || fail "$latest_url has no signature next to it; refusing to trust it. Name a release with --version=<tag>"
                if verify_sig "$tmp/LATEST" "$tmp/LATEST.sig"; then
                    latest_signed=1
                    break
                fi
            done
            [ "$latest_signed" = 1 ] \
                || fail "$latest_url is not signed by ward's release key ($RELEASE_KEY); refusing to trust it. Name a release with --version=<tag>"
            # Exactly one line, the tag and its newline, and the tag a
            # v-prefixed SemVer 2.0 version: anything else is refused.
            latest_bytes="$(wc -c <"$tmp/LATEST")"
            [ "$((latest_bytes))" -le $((SEMVER_MAX + 2)) ] \
                || fail "$latest_url is not one release tag; name one with --version=<tag>"
            tag="$(cat "$tmp/LATEST")"
            case "$tag" in *"
"*) tag="" ;; esac
            [ -n "$tag" ] && printf '%s\n' "$tag" | cmp -s - "$tmp/LATEST" \
                || fail "$latest_url is not one release tag on one line; name one with --version=<tag>"
            case "$tag" in
                v*) semver_valid "$tag" || tag="" ;;
                *) tag="" ;;
            esac
            [ -n "$tag" ] \
                || fail "$latest_url does not name a release tag (v<SemVer 2.0 version>); name one with --version=<tag>"
        fi
        ;;
    v*) named=1; tag="$VERSION" ;;
    *)  named=1; tag="v$VERSION" ;;
esac
case "$tag" in
    v[0-9]*) ;;
    *) fail "'$tag' is not a release tag (v<major>.<minor>.<patch>)" ;;
esac
case "$tag" in
    *[!A-Za-z0-9.+-]*) fail "'$tag' is not a release tag (v<major>.<minor>.<patch>)" ;;
esac
want="${tag#v}"
base="https://github.com/$REPO/releases/download/$tag"
# Test hook: serve the three asset files (the archive, its .sha256 and its
# .sig) from anywhere (tests/install.sh and action.yml use it). The files are
# still verified against the release key, and the binary against $tag, so
# the hook moves where they come from, never what is trusted.
base="${GREYWARD_DOWNLOAD_BASE:-$base}"

say "downloading $base/$asset"
fetch "$base/$asset" "$tmp/$asset" \
    || fail "download failed. Is there a release at https://github.com/$REPO/releases with $asset?
  Releases are built for Linux x86_64 only for now.
  Build from source instead:  cargo install --git https://github.com/$REPO --locked"
fetch "$base/$asset.sha256" "$tmp/$asset.sha256" \
    || fail "checksum file missing next to the release asset; refusing to install an unverified binary"

expected="$(cut -d' ' -f1 "$tmp/$asset.sha256" | tr -d '\r\n')"
actual="$(digest "$tmp/$asset")"
[ -n "$expected" ] || fail "empty checksum file"
[ "$expected" = "$actual" ] || fail "sha256 mismatch for $asset
  expected $expected
  got      $actual"

fetch "$base/$asset.sig" "$tmp/$asset.sig" \
    || fail "signature file missing next to the release asset; refusing to install an unverified binary"
verify_sig "$tmp/$asset" "$tmp/$asset.sig" \
    || fail "$asset is not signed by ward's release key ($RELEASE_KEY); refusing to install it.
  (This needs OpenSSL 3.0 or newer; 'openssl version' says: $(openssl version 2>&1))"

tar -xzf "$tmp/$asset" -C "$tmp" || fail "cannot extract $asset"
[ -f "$tmp/ward" ] || fail "archive did not contain a 'ward' binary"

# --- install ----------------------------------------------------------------
# What is being replaced, if anything: read it before the file is overwritten.
previous=""
existing=0
probed=""
if [ -x "$INSTALL_DIR/ward" ]; then
    existing=1
    # A --version that fails or times out tells nothing, like no output.
    # Only one exact version line and its newline is read: a second line,
    # a blank one, or anything after the version is no version at all.
    if version_of "$INSTALL_DIR/ward"; then
        probed="$version_out"
        previous="$version_seen"
    fi
fi
# `ward 0.3.0 (abc1234 2026-10-13)`: the version is the second word.
previous_version="${previous#ward }"
previous_version="${previous_version%% *}"
downgrade=0
if [ "$existing" = 1 ]; then
    # An installed ward whose version cannot be read might be newer, so it
    # counts as unreadable: latest leaves it alone, a named version does not.
    if [ -n "$previous" ]; then
        order="$(semver_cmp "$want" "$previous_version")"
        seen="it says '$previous'"
    else
        order=bad
        if [ -n "$probed" ]; then
            # At most 80 bytes of its first line: it may print anything.
            seen="its '--version' printed '$(version_shown)'"
            case "${probed%"$NL"}" in *"$NL"*) seen="$seen and more lines" ;; esac
        else
            seen="its '--version' printed nothing, failed or timed out"
        fi
    fi
    case "$order" in
        -1)
            [ "$named" = 1 ] || fail "$INSTALL_DIR/ward is $previous, newer than the latest release ($tag); it is untouched.
  To install the older release anyway, name it:  --version=$tag"
            downgrade=1
            ;;
        0 | 1) ;;
        *)
            # Unreadable, so it might be newer: latest leaves it alone.
            [ "$named" = 1 ] || fail "cannot tell whether $INSTALL_DIR/ward is older than the latest release ($tag): $seen, which is not the one line 'ward <SemVer 2.0 version>'. It is untouched.
  To replace it anyway, name the release:  --version=$tag"
            ;;
    esac
fi
mkdir -p "$INSTALL_DIR" || fail "cannot create $INSTALL_DIR"
# Copy to a sibling, run it there, and only then rename it over the old
# binary: a running `ward` never sees a half-written file, and a release that
# cannot run here (another glibc, a broken build) never replaces one that
# can. It is run from the install directory, not $tmp, because that is
# where it will run from (and $tmp may be mounted noexec).
staged="$INSTALL_DIR/.greyward.tmp.$$"
trap 'rm -rf "$tmp"; rm -f "$staged"' EXIT
trap 'rm -rf "$tmp"; rm -f "$staged"; exit 1' INT TERM
cp "$tmp/ward" "$staged" || fail "cannot write to $INSTALL_DIR"
chmod 755 "$staged"
version_of "$staged" \
    || fail "the downloaded ward does not run on this machine ('--version' failed); $INSTALL_DIR/ward is untouched"
# The same one version line the installed ward is held to, and the version
# is the tag's: a release whose archive is another release's binary is
# refused, the way `ward update --self` refuses it.
installed="$version_seen"
case "$installed" in
    "ward $want" | "ward $want ("*")") ;;
    *) fail "the downloaded ward says '$(version_shown)', not the one line 'ward $want'; the release's asset does not match its tag $tag, and $INSTALL_DIR/ward is untouched" ;;
esac
mv -f "$staged" "$INSTALL_DIR/ward" || fail "cannot replace $INSTALL_DIR/ward"
if [ -z "$previous" ] && [ "$existing" = 1 ]; then
    say "replaced $INSTALL_DIR/ward, whose version could not be read, with $installed (--version=$tag was named)"
elif [ -z "$previous" ]; then
    say "installed $installed to $INSTALL_DIR/ward"
elif [ "$downgrade" = 1 ]; then
    say "downgraded $previous -> $installed in $INSTALL_DIR (--version=$tag was named)"
elif [ "$previous" = "$installed" ]; then
    say "reinstalled $installed to $INSTALL_DIR/ward (same version)"
else
    say "upgraded $previous -> $installed in $INSTALL_DIR"
fi
shadow="$(command -v ward 2>/dev/null || true)"
if [ -n "$shadow" ] && [ "$shadow" != "$INSTALL_DIR/ward" ]; then
    say "note: '$shadow' comes first on this PATH and will keep winning"
fi

# --- PATH -------------------------------------------------------------------
on_path=0
case ":$PATH:" in
    *":$INSTALL_DIR:"*) on_path=1 ;;
esac

mkdir -p "$GREYWARD_HOME"
# The install directory as the startup code spells it: quoted, so a --dir
# holding `"`, `$(...)` or a backtick is a path at every shell start and
# never a command.
dir_sh="$(shquote "$INSTALL_DIR")"
dir_fish="$(fishquote "$INSTALL_DIR")"
# ~/.greyward/env is POSIX sh: it is read by sh, bash, and zsh alike. Idempotent
# so sourcing it twice does not grow PATH.
cat >"$GREYWARD_HOME/env" <<EOF
# ward: put the ward binary on PATH. Written by install.sh; safe to source repeatedly.
case ":\${PATH}:" in
    *:$dir_sh:*) ;;
    *) export PATH=$dir_sh:"\$PATH" ;;
esac
EOF

# Append one marked block to a startup file, once.
append_block() {
    file="$1"
    body="$2"
    if [ -f "$file" ] && grep -Fq "$MARK_BEGIN" "$file" 2>/dev/null; then
        return 0
    fi
    [ -f "$file" ] || [ "$3" = "create" ] || return 0
    printf '\n%s\n%s\n%s\n' "$MARK_BEGIN" "$body" "$MARK_END" >>"$file" \
        || { say "could not write $file (skipped)"; return 0; }
    say "added PATH setup to $file"
}

posix_line=". \"\$HOME/.greyward/env\""
zsh_block="$posix_line
fpath=(\"\$HOME/.greyward/completions\" \$fpath)
if (( \$+functions[compdef] )); then autoload -Uz _ward && compdef _ward ward; fi"

if [ "$MODIFY_PATH" = 1 ] && [ "$on_path" = 0 ]; then
    # The file the user's login shell reads is created if missing; the others
    # are only touched when they already exist.
    case "$shell_name" in
        zsh)  append_block "$zdotdir/.zshrc" "$zsh_block" create ;;
        bash) if [ "$os" = Darwin ]; then
                  append_block "$HOME/.bash_profile" "$posix_line" create
              else
                  append_block "$HOME/.bashrc" "$posix_line" create
              fi ;;
        fish) : ;;
        *)    append_block "$HOME/.profile" "$posix_line" create ;;
    esac
    append_block "$HOME/.profile" "$posix_line" existing
    append_block "$HOME/.bashrc" "$posix_line" existing
    append_block "$HOME/.bash_profile" "$posix_line" existing
    append_block "$zdotdir/.zshrc" "$zsh_block" existing
    # fish does not read POSIX files; conf.d snippets are auto-sourced.
    if command -v fish >/dev/null 2>&1 || [ "$shell_name" = fish ]; then
        fish_confd="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d"
        mkdir -p "$fish_confd" 2>/dev/null && cat >"$fish_confd/ward.fish" <<EOF
# ward: put the ward binary on PATH. Written by install.sh.
if not contains -- $dir_fish \$PATH
    set -gx PATH $dir_fish \$PATH
end
EOF
        say "added PATH setup to $fish_confd/ward.fish"
    fi
elif [ "$MODIFY_PATH" = 1 ] && [ "$shell_name" = zsh ] && [ "$COMPLETIONS" = 1 ]; then
    # Already on PATH, but zsh still needs the fpath entry for completions.
    append_block "$zdotdir/.zshrc" "$zsh_block" existing
fi

# --- completions ------------------------------------------------------------
# Generate to a scratch file and only keep it when it has content: a failed
# `ward completions` used to leave a zero-byte file that the shell sources
# happily and that breaks completion with no error anywhere.
write_completion() { # <shell> <destination>
    scratch="$2.greyward-install.$$"
    if "$bin" completions "$1" >"$scratch" 2>/dev/null && [ -s "$scratch" ]; then
        mv -f "$scratch" "$2"
        return 0
    fi
    rm -f "$scratch"
    say "could not generate the $1 completion (skipped)"
    return 1
}

if [ "$COMPLETIONS" = 1 ]; then
    bin="$INSTALL_DIR/ward"
    wired=""
    if mkdir -p "$GREYWARD_HOME/completions" 2>/dev/null \
        && write_completion zsh "$GREYWARD_HOME/completions/_ward"; then
        wired="zsh"
    fi
    bash_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
    if mkdir -p "$bash_dir" 2>/dev/null && write_completion bash "$bash_dir/ward"; then
        wired="${wired:+$wired, }bash"
    fi
    if command -v fish >/dev/null 2>&1 || [ "$shell_name" = fish ]; then
        fish_dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
        if mkdir -p "$fish_dir" 2>/dev/null \
            && write_completion fish "$fish_dir/ward.fish"; then
            wired="${wired:+$wired, }fish"
        fi
    fi
    if [ -n "$wired" ]; then
        say "shell completions installed ($wired)"
    else
        say "no shell completions installed"
    fi
fi

# --- done -------------------------------------------------------------------
# Where the disk goes. The only size hint ward gave before this line was a
# low-free-space warning, which arrives long after the decision matters.
say "store: $STORE (every toolchain, package and environment; projects share it)"
if [ -d "$STORE" ]; then
    size="$(du -sh "$STORE" 2>/dev/null | cut -f1)"
    say "  ${size:-size unknown} so far; 'ward doctor' reports it, 'ward gc' reclaims it"
else
    say "  created by the first sync; budget ~700 MiB for a Python plus a Node project"
fi
say "to undo all of this later: sh install.sh --uninstall (it keeps the store)"

if [ "$on_path" = 1 ]; then
    say "done. '$INSTALL_DIR' is already on PATH: try 'ward --version'"
elif [ "$MODIFY_PATH" = 0 ]; then
    say "done. '$INSTALL_DIR' is not on PATH and --no-modify-path was given; add it yourself:"
    printf '\n    export PATH=%s:"$PATH"\n\n' "$dir_sh" >&2
else
    say "done. New terminals already have ward. For this one, run:"
    if [ "$shell_name" = fish ]; then
        printf '\n    set -gx PATH %s $PATH\n\n' "$dir_fish" >&2
    else
        printf '\n    source "$HOME/.greyward/env"\n\n' >&2
    fi
fi
