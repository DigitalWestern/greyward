#!/bin/bash
# End-to-end test of install.sh with no network: package the locally built
# binary the way release.yml does, serve it from a local HTTP server, and run
# the installer into throwaway HOMEs. Run after `cargo build`:
#
#   bash tests/install.sh
#
# The binary under test is the debug build, the one `cargo build` and
# `cargo test` keep current. A leftover target/release/ward is never picked up
# on its own: name another binary with GREYWARD_BIN (release.yml's build does).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${GREYWARD_BIN:-$ROOT/target/debug/ward}"
[ -x "$BIN" ] || { echo "no ward binary at $BIN: run cargo build first, or set GREYWARD_BIN" >&2; exit 1; }

# Resolved, because the installer prints resolved paths and macOS's TMPDIR
# sits under /var, a symlink to /private/var.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/greyward-install-test.XXXXXX")"
WORK="$(cd -P "$WORK" && pwd -P)"
SERVER=""
trap '[ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null; rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  ok: $1"; }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
# Bash-native, because `sh` is dash on Ubuntu and has no here-strings.
absent() { ! grep -Fq "$1" <<<"$2"; }
count_marks() { grep -c '# >>> ward >>>' "$1" 2>/dev/null || true; }

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) triple=x86_64-unknown-linux-gnu ;;
    Darwin/arm64) triple=aarch64-apple-darwin ;;
    *) echo "unsupported test host" >&2; exit 1 ;;
esac

# --- a release directory laid out exactly like the GitHub Release assets ----
asset="greyward-$triple.tar.gz"
mkdir -p "$WORK/release" "$WORK/stage"
# A throwaway release key, made the way the real one was (`ward keygen`) and
# used the way the real one is (tools/release-sign.sh). The installer is
# pointed at its public half with GREYWARD_RELEASE_PUBLIC_KEY.
RELEASE_KEY_FILE="$WORK/release.key"
TEST_RELEASE_KEY="$("$BIN" keygen "$RELEASE_KEY_FILE" 2>/dev/null | sed -n 's/^trusted = \["\(.*\)"\]$/\1/p')"
[ -n "$TEST_RELEASE_KEY" ] || { echo "ward keygen printed no public key" >&2; exit 1; }
# The .sha256 and .sig of whatever release/$asset holds now.
publish_sidecars() {
    rm -f "$WORK/release/$asset.sig"
    ( cd "$WORK/release" && { sha256sum "$asset" 2>/dev/null || shasum -a 256 "$asset"; } > "$asset.sha256" )
    GREYWARD_RELEASE_KEY="$RELEASE_KEY_FILE" GREYWARD_RELEASE_PUBLIC_KEY="$TEST_RELEASE_KEY" \
        "$ROOT/tools/release-sign.sh" --sign "$WORK/release/$asset" 2>/dev/null
}
# Pack the `ward` in directory $1 as release.yml packs it (no macOS
# AppleDouble or xattr members), then checksum and sign it.
publish_asset() {
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$1" -czf "$WORK/release/$asset" ward
    publish_sidecars
}
cp "$BIN" "$WORK/stage/ward"
publish_asset "$WORK/stage"

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$WORK/release" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$port/$asset.sha256" >/dev/null 2>&1 && break
    sleep 0.1
done
export GREYWARD_DOWNLOAD_BASE="http://127.0.0.1:$port"
BASE_PATH="/usr/bin:/bin"
run_installer() { # HOME SHELL PATH [args...]
    local home="$1" shell="$2" path="$3"; shift 3
    mkdir -p "$home"
    env -i HOME="$home" SHELL="$shell" PATH="$path" TERM=dumb \
        GREYWARD_DOWNLOAD_BASE="$GREYWARD_DOWNLOAD_BASE" \
        GREYWARD_RELEASE_PUBLIC_KEY="${RELEASE_KEY_OVERRIDE-$TEST_RELEASE_KEY}" \
        sh "$ROOT/install.sh" "$@"
}

echo "== 1. zsh user, install dir not on PATH"
H="$WORK/h1"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "binary installed and runs"         "$H/.local/bin/ward" --version
check "env file exists"                   test -f "$H/.greyward/env"
check "sourcing env puts ward on PATH" sh -c ". '$H/.greyward/env' && command -v ward | grep -q '$H/.local/bin/ward'"
check "sourcing env twice does not grow PATH" sh -c ". '$H/.greyward/env'; . '$H/.greyward/env'; [ \"\$(echo \"\$PATH\" | tr : '\n' | grep -c '$H/.local/bin')\" = 1 ]"
check ".zshrc created with one block"     test "$(count_marks "$H/.zshrc")" = 1
check ".zshrc sources env"                grep -Fq '. "$HOME/.greyward/env"' "$H/.zshrc"
check ".zshrc adds fpath"                 grep -Fq 'fpath=("$HOME/.greyward/completions" $fpath)' "$H/.zshrc"
check "zsh completion is an fpath file"   sh -c "head -1 '$H/.greyward/completions/_ward' | grep -q '^#compdef ward'"
check "bash completion installed"         test -s "$H/.local/share/bash-completion/completions/ward"
check "no .bashrc invented for a zsh user" test ! -e "$H/.bashrc"
check "final hint names the env file"     grep -Fq 'source "$HOME/.greyward/env"' <<<"$out"
if command -v zsh >/dev/null 2>&1; then
    check "zsh loads .zshrc and completes without error" \
        env -i HOME="$H" TERM=dumb zsh -ic 'autoload -Uz compinit && compinit -u -D && source ~/.zshrc && command -v ward && whence -w _ward | grep -q function'
fi
run_installer "$H" /bin/zsh "$BASE_PATH" >/dev/null 2>&1 || bad "second run exited non-zero"
check "second run is idempotent (one block)" test "$(count_marks "$H/.zshrc")" = 1

echo "== 2. bash user, install dir already on PATH"
H="$WORK/h2"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "binary installed"                  "$H/.local/bin/ward" --version
check "no startup file touched"           sh -c "! ls '$H'/.bashrc '$H'/.profile '$H'/.bash_profile '$H'/.zshrc 2>/dev/null | grep -q ."
check "reports already on PATH"           grep -q 'already on PATH' <<<"$out"

echo "== 3. bash user, existing .bashrc and .profile, dir off PATH"
H="$WORK/h3"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; echo '# mine' > "$H/.profile"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check ".bashrc got one block"             test "$(count_marks "$H/.bashrc")" = 1
check ".profile got one block"            test "$(count_marks "$H/.profile")" = 1
check "user content preserved"            grep -q '^# mine' "$H/.bashrc"
check "bash -l sees ward via .profile" env -i HOME="$H" PATH="$BASE_PATH" bash -lc 'command -v ward'
check "bash -i sees ward via .bashrc"  env -i HOME="$H" PATH="$BASE_PATH" TERM=dumb bash -ic 'command -v ward'

echo "== 4. --no-modify-path and --dir"
H="$WORK/h4"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" --no-modify-path "--dir=$H/bin" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "installed into --dir"              "$H/bin/ward" --version
check "no .zshrc written"                 test ! -e "$H/.zshrc"
check "prints the export line"            grep -Fq "export PATH='$H/bin':\"\$PATH\"" <<<"$out"

echo "== 5. tampered checksum is refused"
H="$WORK/h5"
cp "$WORK/release/$asset.sha256" "$WORK/good.sha256"
printf '%064d  %s\n' 0 "$asset" > "$WORK/release/$asset.sha256"
if run_installer "$H" /bin/zsh "$BASE_PATH" >/dev/null 2>&1; then bad "installer accepted a bad checksum"; else ok "installer refused a bad checksum"; fi
check "nothing installed after refusal"   test ! -e "$H/.local/bin/ward"
cp "$WORK/good.sha256" "$WORK/release/$asset.sha256"

echo "== 6. --no-completions"
H="$WORK/h6"
run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" --no-completions >/dev/null 2>&1 || bad "installer exited non-zero"
check "no completion files"               test ! -e "$H/.greyward/completions/_ward" -a ! -e "$H/.local/share/bash-completion/completions/ward"

echo "== 7. the store is named and sized before the PATH hint"
H="$WORK/h7"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "names the store path"              grep -Fq "store: $H/.greyward/store" <<<"$out"
check "says what will fill it"            grep -Eq 'created by the first sync|so far' <<<"$out"
check "names the uninstall command"       grep -Fq 'install.sh --uninstall' <<<"$out"
check "a written completion is never empty" sh -c "[ -s '$H/.greyward/completions/_ward' ] && [ -s '$H/.local/share/bash-completion/completions/ward' ]"

echo "== 8. replacing an existing ward reports old -> new"
H="$WORK/h8"
mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "ward 0.0.1-old"\n' > "$H/.local/bin/ward"
chmod 755 "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "names both versions"               grep -Fq 'upgraded ward 0.0.1-old -> ' <<<"$out"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "a same-version rerun says so"      grep -Fq '(same version)' <<<"$out"

echo "== 9. --uninstall removes what it installed and keeps the store"
H="$WORK/h9"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; echo '# mine' > "$H/.profile"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
mkdir -p "$H/.greyward/store/objects"; echo keep > "$H/.greyward/store/objects/an-object"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "binary removed"                    test ! -e "$H/.local/bin/ward"
check "env file removed"                  test ! -e "$H/.greyward/env"
check "zsh completion removed"            test ! -e "$H/.greyward/completions/_ward"
check "bash completion removed"           test ! -e "$H/.local/share/bash-completion/completions/ward"
check ".bashrc block removed"             test "$(count_marks "$H/.bashrc")" = 0
check ".bashrc user content preserved"    grep -q '^# mine' "$H/.bashrc"
check ".profile block removed"            test "$(count_marks "$H/.profile")" = 0
check ".profile user content preserved"   grep -q '^# mine' "$H/.profile"
check "store kept"                        test -f "$H/.greyward/store/objects/an-object"
check "names the store it kept"           grep -Fq "$H/.greyward/store" <<<"$out"
check "prints how to remove the store"    grep -Fq "rm -rf '$H/.greyward/store'" <<<"$out"
check "a second uninstall is harmless" run_installer "$H" /bin/bash "$BASE_PATH" --uninstall

echo "== 10. --uninstall with nothing installed"
H="$WORK/h10"; mkdir -p "$H"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "says there is no binary"           grep -Fq 'no ward binary at' <<<"$out"
if grep -Fq downloading <<<"$out"; then bad "--uninstall downloaded something"; else ok "--uninstall never downloads"; fi

echo "== 11. --uninstall refuses a startup file whose markers do not pair"
H="$WORK/h12"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
# Somebody edited the block out by hand and left the opening marker behind.
grep -v '^# <<< ward <<<$' "$H/.bashrc" > "$H/.bashrc.tmp" && mv "$H/.bashrc.tmp" "$H/.bashrc"
echo '# after the unclosed block' >> "$H/.bashrc"
before="$(cat "$H/.bashrc")"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "refuses the unbalanced file"       grep -Fq 'refusing to edit it' <<<"$out"
check "leaves the unbalanced file byte-identical" test "$before" = "$(cat "$H/.bashrc")"
check "content after the marker survives" grep -Fq '# after the unclosed block' "$H/.bashrc"
check "no backup written for a refusal"   test ! -e "$H/.bashrc.greyward.bak"
check "the binary still went"             test ! -e "$H/.local/bin/ward"

echo "== 12. a balanced strip keeps a backup and the file's mode"
H="$WORK/h13"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; chmod 600 "$H/.bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
mode_before="$(ls -l "$H/.bashrc" | cut -c1-10)"
run_installer "$H" /bin/bash "$BASE_PATH" --uninstall >/dev/null 2>&1 || bad "--uninstall exited non-zero"
check "backup kept"                       grep -Fq '# >>> ward >>>' "$H/.bashrc.greyward.bak"
check "block gone from the live file"     test "$(count_marks "$H/.bashrc")" = 0
check "mode preserved across the rewrite" test "$mode_before" = "$(ls -l "$H/.bashrc" | cut -c1-10)"

echo "== 13. --uninstall does not delete something that is not ward"
H="$WORK/h14"; mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "someone-elses-tool 2.0"\n' > "$H/.local/bin/ward"
chmod 755 "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "imposter left in place"            test -x "$H/.local/bin/ward"
check "says why it left it"               grep -Fq 'does not identify itself as ward' <<<"$out"
# A symlink out of the install directory is a package manager's, not ours.
H="$WORK/h15"; mkdir -p "$H/.local/bin" "$H/opt"
cp "$BIN" "$H/opt/greyward"
ln -s "$H/opt/greyward" "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "outside symlink left in place"     test -L "$H/.local/bin/ward"
check "says it is a symlink elsewhere"    grep -Fq 'outside' <<<"$out"

echo "== 14. empty --dir and missing HOME are usage errors, not surprises"
if run_installer "$WORK/h16" /bin/bash "$BASE_PATH" --dir= >/dev/null 2>&1; then
    bad "--dir= was accepted"
else ok "--dir= is refused"; fi
if env -i PATH="$BASE_PATH" TERM=dumb GREYWARD_DOWNLOAD_BASE="$GREYWARD_DOWNLOAD_BASE" \
    sh "$ROOT/install.sh" >/dev/null 2>&1; then
    bad "installer ran with no HOME"
else ok "no HOME is refused"; fi
out="$(env -i PATH="$BASE_PATH" TERM=dumb sh "$ROOT/install.sh" 2>&1 || true)"
check "the no-HOME message names HOME"    grep -Fq 'HOME is not set' <<<"$out"

echo "== 15. the printed 'rm -rf' survives an apostrophe in the store path"
H="$WORK/h17"; mkdir -p "$H"
STORE_ODD="$H/it's a \"weird\" store"
mkdir -p "$STORE_ODD"
out="$(env -i HOME="$H" SHELL=/bin/bash PATH="$BASE_PATH" TERM=dumb \
    GREYWARD_STORE="$STORE_ODD" GREYWARD_DOWNLOAD_BASE="$GREYWARD_DOWNLOAD_BASE" \
    sh "$ROOT/install.sh" --uninstall 2>&1)"
# Take the argument the script told the user to run and feed it back to a
# shell: it has to name the directory it started from, byte for byte.
printed="$(sed -n 's/^greyward-install: to reclaim that space:  rm -rf //p' <<<"$out")"
back="$(eval "printf '%s' $printed" 2>/dev/null || echo '<eval failed>')"
check "the rm line round-trips through a shell" test "$back" = "$STORE_ODD"

echo "== 16. a broken symlink at the install path is reported, not ignored"
H="$WORK/h18"; mkdir -p "$H/.local/bin"
ln -s "$H/nowhere/ward" "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "broken symlink left in place"      test -L "$H/.local/bin/ward"
check "says the target does not exist"    grep -Fq 'which does not exist' <<<"$out"
check "does not claim there is no ward"    absent 'no ward binary at' "$out"

echo "== 17. a relative symlink that escapes the install dir is refused"
H="$WORK/h19"; mkdir -p "$H/.local/bin" "$H/elsewhere"
cp "$BIN" "$H/elsewhere/ward"
# Spelled inside the install directory, resolving outside it.
ln -s "../../elsewhere/ward" "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "escaping relative symlink kept"    test -L "$H/.local/bin/ward"
check "its target kept"                   test -f "$H/elsewhere/ward"
check "says where it really resolves"     grep -Fq "$H/elsewhere/ward, outside" <<<"$out"

echo "== 18. malformed marker blocks are refused, substrings are not markers"
# (a) an end marker before its begin: counts match, ordering does not.
H="$WORK/h20"; mkdir -p "$H"
{ echo '# mine'; echo '# <<< ward <<<'; echo '# stray'; echo '# >>> ward >>>'; } > "$H/.bashrc"
before="$(cat "$H/.bashrc")"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "end-before-begin refused"          grep -Fq 'malformed ward block' <<<"$out"
check "end-before-begin file untouched"   test "$before" = "$(cat "$H/.bashrc")"
check "no backup written for a refusal"   test ! -e "$H/.bashrc.greyward.bak"
# (b) a marker quoted inside a longer line is not a marker.
H="$WORK/h21"; mkdir -p "$H"
echo 'echo "# >>> ward >>> is the marker we look for"' > "$H/.bashrc"
before="$(cat "$H/.bashrc")"
run_installer "$H" /bin/bash "$BASE_PATH" --uninstall >/dev/null 2>&1 || bad "--uninstall exited non-zero"
check "substring line is not a marker"    test "$before" = "$(cat "$H/.bashrc")"
check "no backup written for a non-block" test ! -e "$H/.bashrc.greyward.bak"

echo "== 19. a symlinked rc file is edited through, not replaced"
H="$WORK/h22"; mkdir -p "$H/dotfiles"
echo '# mine' > "$H/dotfiles/bashrc"
ln -s "$H/dotfiles/bashrc" "$H/.bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
check "the block landed in the real file" grep -Fq '# >>> ward >>>' "$H/dotfiles/bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" --uninstall >/dev/null 2>&1 || bad "--uninstall exited non-zero"
check ".bashrc is still a symlink"        test -L "$H/.bashrc"
check "it still points at the dotfile"    test "$(readlink "$H/.bashrc")" = "$H/dotfiles/bashrc"
check "the real file lost the block"      test "$(count_marks "$H/dotfiles/bashrc")" = 0
check "the real file kept its content"    grep -q '^# mine' "$H/dotfiles/bashrc"
check "the backup sits next to the real file" test -f "$H/dotfiles/bashrc.greyward.bak"

echo "== 20. a symlinked backup path is refused"
H="$WORK/h23"; mkdir -p "$H" "$H/bait"
echo '# mine' > "$H/.bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
echo 'do not clobber me' > "$H/bait/precious"
ln -s "$H/bait/precious" "$H/.bashrc.greyward.bak"
before="$(cat "$H/.bashrc")"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "symlinked backup refused"          grep -Fq 'refusing to write a backup through it' <<<"$out"
check "the rc file is untouched"          test "$before" = "$(cat "$H/.bashrc")"
check "the bait file is untouched"        grep -Fqx 'do not clobber me' "$H/bait/precious"

echo "== 21. GREYWARD_NO_MODIFY_PATH only turns PATH editing off when it means it"
for value in 0 1; do
    H="$WORK/h11-$value"; mkdir -p "$H"
    env -i HOME="$H" SHELL=/bin/bash PATH="$BASE_PATH" TERM=dumb \
        GREYWARD_NO_MODIFY_PATH="$value" GREYWARD_DOWNLOAD_BASE="$GREYWARD_DOWNLOAD_BASE" \
        GREYWARD_RELEASE_PUBLIC_KEY="$TEST_RELEASE_KEY" \
        sh "$ROOT/install.sh" >/dev/null 2>&1 || bad "installer exited non-zero"
    # A bash user's file is .bash_profile on macOS, whose terminals start
    # login shells, and .bashrc elsewhere.
    rc=.bashrc; [ "$(uname -s)" = Darwin ] && rc=.bash_profile
    if [ "$value" = 0 ]; then
        check "GREYWARD_NO_MODIFY_PATH=0 still edits $rc" test "$(count_marks "$H/$rc")" = 1
    else
        check "GREYWARD_NO_MODIFY_PATH=1 edits nothing"   test ! -e "$H/.bashrc" -a ! -e "$H/.bash_profile"
    fi
done

echo "== 22. a release that does not run here never replaces a ward that does"
H="$WORK/h24"
run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
working="$("$H/.local/bin/ward" --version)"
mkdir -p "$WORK/broken"
cp -f "$WORK/release/$asset" "$WORK/good.tar.gz"
printf '#!/bin/sh\necho "cannot run here" >&2\nexit 1\n' > "$WORK/broken/ward"
chmod 755 "$WORK/broken/ward"
publish_asset "$WORK/broken"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" \
    && bad "installer accepted a binary that does not run" || ok "installer refused a binary that does not run"
check "says the old binary is untouched"  grep -Fq 'is untouched' <<<"$out"
check "the working ward is still there"   test "$("$H/.local/bin/ward" --version)" = "$working"
check "no staged file left behind"        sh -c "! ls -a '$H/.local/bin' | grep -q '^\\.greyward\\.tmp'"
cp -f "$WORK/good.tar.gz" "$WORK/release/$asset"
publish_sidecars

echo "== 23. an install dir with shell syntax in it stays a path in startup code"
H="$WORK/h25"; mkdir -p "$H"
odd="$H/bin \"\$(touch $H/pwned)\" \`touch $H/pwned2\` it's"
run_installer "$H" /bin/bash "$BASE_PATH" "--dir=$odd" >/dev/null 2>&1 || bad "installer exited non-zero"
check "installed into the odd dir"        "$odd/ward" --version
found="$(env -i HOME="$H" PATH="$BASE_PATH" sh -c '. "$HOME/.greyward/env" && command -v ward')"
check "the PATH entry is the dir, byte for byte" test "$found" = "$odd/ward"
env -i HOME="$H" PATH="$BASE_PATH" TERM=dumb bash -ic 'true' >/dev/null 2>&1 || true
check "no command ran from the dir name"  test ! -e "$H/pwned" -a ! -e "$H/pwned2"
check "sourcing env twice does not grow PATH" env -i HOME="$H" PATH="$BASE_PATH" sh -c '. "$HOME/.greyward/env"; . "$HOME/.greyward/env"; [ "$(printf %s "$PATH" | tr : "\n" | grep -c "pwned2")" = 1 ]'
if command -v fish >/dev/null 2>&1; then
    found="$(env -i HOME="$H" PATH="$BASE_PATH" fish -c 'command -v ward' 2>/dev/null || true)"
    check "fish finds ward in the odd dir" test "$found" = "$odd/ward"
    check "no command ran from fish either" test ! -e "$H/pwned" -a ! -e "$H/pwned2"
fi

echo "== 24. only an archive signed by the release key is installed"
# Signed by the test key, checked against the shipped release key.
H="$WORK/h26"
out="$(RELEASE_KEY_OVERRIDE="" run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" \
    && bad "installer accepted another key's signature" || ok "installer refused another key's signature"
check "names the release key"             grep -Fq "not signed by ward's release key" <<<"$out"
check "nothing installed (other key)"     test ! -e "$H/.local/bin/ward"
# A different archive whose .sha256 was rewritten to match, still carrying
# the old archive's signature: what a writer of release assets without the
# key could publish.
cp -f "$WORK/release/$asset" "$WORK/good.tar.gz"
cp -f "$WORK/release/$asset.sig" "$WORK/good.sig"
mkdir -p "$WORK/swapped"
printf '#!/bin/sh\necho "ward 99.0.0 (not ours)"\n' > "$WORK/swapped/ward"
chmod 755 "$WORK/swapped/ward"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$WORK/swapped" -czf "$WORK/release/$asset" ward
( cd "$WORK/release" && { sha256sum "$asset" 2>/dev/null || shasum -a 256 "$asset"; } > "$asset.sha256" )
cp -f "$WORK/good.sig" "$WORK/release/$asset.sig"
H="$WORK/h27"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" \
    && bad "installer accepted a swapped archive" || ok "installer refused a swapped archive"
check "nothing installed (swapped)"       test ! -e "$H/.local/bin/ward"
cp -f "$WORK/good.tar.gz" "$WORK/release/$asset"
publish_sidecars
# No .sig at all.
mv "$WORK/release/$asset.sig" "$WORK/good.sig"
H="$WORK/h28"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" \
    && bad "installer accepted an unsigned archive" || ok "installer refused an unsigned archive"
check "says the signature is missing"     grep -Fq 'signature file missing' <<<"$out"
check "nothing installed (unsigned)"      test ! -e "$H/.local/bin/ward"
mv "$WORK/good.sig" "$WORK/release/$asset.sig"
# No openssl: refused before anything is downloaded.
mkdir -p "$WORK/no-openssl"
for tool in /usr/bin/* /bin/*; do
    name="${tool##*/}"
    [ "$name" = openssl ] || [ -e "$WORK/no-openssl/$name" ] || ln -s "$tool" "$WORK/no-openssl/$name"
done
H="$WORK/h29"
out="$(run_installer "$H" /bin/bash "$WORK/no-openssl" 2>&1)" \
    && bad "installer ran without openssl" || ok "installer refused to run without openssl"
check "says it needs openssl"             grep -Fq 'need openssl' <<<"$out"
check "downloaded nothing without openssl" absent 'downloading' "$out"
# The good release still installs.
H="$WORK/h30"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer refused the signed release"
check "the signed release installs"       "$H/.local/bin/ward" --version

echo
echo "install.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
