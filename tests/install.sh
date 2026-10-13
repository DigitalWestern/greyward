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
# The shell install.sh runs under: `sh` on PATH, or another POSIX shell
# named by path (INSTALL_SHELL=/usr/bin/dash bash tests/install.sh).
INSTALL_SHELL="${INSTALL_SHELL:-sh}"
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
# A file server that also answers /redirect/<path> with a 302 to /<path>,
# the way GitHub's releases/latest/download/<name> redirects to the latest
# release's asset: curl and wget must follow it on their own.
cat > "$WORK/serve.py" <<'PY'
import functools, http.server, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redirect/"):
            self.send_response(302)
            self.send_header("Location", self.path[len("/redirect"):])
            self.end_headers()
            return
        super().do_GET()
    def log_message(self, *args):
        pass
handler = functools.partial(Handler, directory=sys.argv[2])
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), handler).serve_forever()
PY
python3 "$WORK/serve.py" "$port" "$WORK/release" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$port/$asset.sha256" >/dev/null 2>&1 && break
    sleep 0.1
done
export GREYWARD_DOWNLOAD_BASE="http://127.0.0.1:$port"
BASE_PATH="/usr/bin:/bin"
# The release served here is the binary under test, so "latest" is its tag.
TEST_VERSION="$("$BIN" --version | sed -n '1s/^ward \([^ ]*\).*$/\1/p')"
[ -n "$TEST_VERSION" ] || { echo "$BIN --version printed no version" >&2; exit 1; }
TEST_TAG="v$TEST_VERSION"
# LATEST_TAG_OVERRIDE="" makes the installer resolve latest from LATEST_URL.
run_installer() { # HOME SHELL PATH [args...]
    local home="$1" shell="$2" path="$3"; shift 3
    mkdir -p "$home"
    env -i HOME="$home" SHELL="$shell" PATH="$path" TERM=dumb \
        GREYWARD_DOWNLOAD_BASE="$GREYWARD_DOWNLOAD_BASE" \
        GREYWARD_RELEASE_PUBLIC_KEY="${RELEASE_KEY_OVERRIDE-$TEST_RELEASE_KEY}" \
        GREYWARD_LATEST_TAG="${LATEST_TAG_OVERRIDE-$TEST_TAG}" \
        GREYWARD_LATEST_URL="${LATEST_URL-}" \
        "$INSTALL_SHELL" "$ROOT/install.sh" "$@"
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
        GREYWARD_RELEASE_PUBLIC_KEY="$TEST_RELEASE_KEY" GREYWARD_LATEST_TAG="$TEST_TAG" \
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

echo "== 25. the new binary must be the tag's version, and exit 0 saying so"
cp -f "$WORK/release/$asset" "$WORK/good.tar.gz"
# An older release's binary, validly signed, served as the latest release:
# what a writer of release assets could replay.
mkdir -p "$WORK/replayed"
printf '#!/bin/sh\necho "ward 0.0.9 (0000000 2026-01-01)"\n' > "$WORK/replayed/ward"
chmod 755 "$WORK/replayed/ward"
publish_asset "$WORK/replayed"
H="$WORK/h31"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" \
    && bad "installer accepted another version's binary" || ok "installer refused another version's binary"
check "names both versions (replayed)"    grep -Fq "says 'ward 0.0.9 (0000000 2026-01-01)', not ward $TEST_VERSION" <<<"$out"
check "nothing installed (replayed)"      test ! -e "$H/.local/bin/ward"
# The same, when that version was named: it must be the named one.
out="$(run_installer "$H" /bin/bash "$BASE_PATH" "--version=$TEST_TAG" 2>&1)" \
    && bad "installer accepted another version's binary for --version" || ok "installer refused another version's binary for --version"
# The right version line, but --version fails.
mkdir -p "$WORK/failing"
printf '#!/bin/sh\necho "ward %s"\nexit 1\n' "$TEST_VERSION" > "$WORK/failing/ward"
chmod 755 "$WORK/failing/ward"
publish_asset "$WORK/failing"
H="$WORK/h32"
run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" >/dev/null 2>&1 || true
mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "ward 0.0.1-old"\n' > "$H/.local/bin/ward"
chmod 755 "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" \
    && bad "installer accepted a binary whose --version fails" || ok "installer refused a binary whose --version fails"
check "says --version failed"             grep -Fq "'--version' failed" <<<"$out"
check "the old ward is untouched"         test "$("$H/.local/bin/ward" --version)" = "ward 0.0.1-old"
cp -f "$WORK/good.tar.gz" "$WORK/release/$asset"
publish_sidecars
# A ward newer than the latest release stays, unless a version is named.
H="$WORK/h33"
mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "ward 99.0.0 (1111111 2026-12-01)"\n' > "$H/.local/bin/ward"
chmod 755 "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" \
    && bad "latest replaced a newer ward" || ok "latest refused to replace a newer ward"
check "says the installed ward is newer"  grep -Fq "newer than the latest release ($TEST_TAG)" <<<"$out"
check "the newer ward is untouched"       test "$("$H/.local/bin/ward" --version)" = "ward 99.0.0 (1111111 2026-12-01)"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" "--version=$TEST_VERSION" 2>&1)" \
    || { echo "$out"; bad "a named older version was refused"; }
check "a named older version is a downgrade" grep -Fq "downgraded ward 99.0.0 (1111111 2026-12-01) -> ward $TEST_VERSION" <<<"$out"
check "the named version is installed"    sh -c "'$H/.local/bin/ward' --version | grep -q '^ward $TEST_VERSION'"

echo "== 26. versions compare by SemVer 2.0 precedence"
# install.sh's own functions, read out of the script under test.
eval "$(sed -n '/^# >>> semver/,/^# <<< semver/p' "$ROOT/install.sh")"
long="$(head -c 140000 /dev/zero | tr '\0' z)"
if ! command -v semver_cmp >/dev/null 2>&1; then
    bad "install.sh defines semver_cmp"
else
    two63=9223372036854775808   # 2^63: past any 64-bit integer and any double's precision
    two63p1=9223372036854775809
    ascending="0.3.0-alpha 0.3.0-alpha.1 0.3.0-alpha.beta 0.3.0-beta 0.3.0-beta.2 0.3.0-beta.11 0.3.0-rc.1 0.3.0-rc.9 0.3.0-rc.10 0.3.0 0.3.1 0.10.0 1.0.0"
    set -- $ascending
    while [ "$#" -ge 2 ]; do
        check "$1 < $2" test "$(semver_cmp "$1" "$2")" = -1
        check "$2 > $1" test "$(semver_cmp "$2" "$1")" = 1
        shift
    done
    # Pairs, the first lower: identifiers with a `-` or an `e` are words
    # (ASCII order), and numbers of any size compare exactly.
    for pair in "1.0.0--1 1.0.0--2" "1.0.0-1e3 1.0.0-2e2" "1.0.0-alpha-1 1.0.0-alpha-2" \
        "1.0.0-rc.$two63 1.0.0-rc.$two63p1" "$two63.0.0 $two63p1.0.0" "1.$two63.0 1.$two63p1.0" \
        "1.0.$two63 1.0.$two63p1" "1.0.0-99999999999999999999 1.0.0-a" "1.0.0-Z 1.0.0-a"; do
        set -- $pair
        check "$1 < $2" test "$(semver_cmp "$1" "$2")" = -1
        check "$2 > $1" test "$(semver_cmp "$2" "$1")" = 1
    done
    check "a version equals itself"            test "$(semver_cmp 0.3.0-rc.10 0.3.0-rc.10)" = 0
    check "a huge one equals itself"           test "$(semver_cmp "1.0.0-rc.$two63" "1.0.0-rc.$two63")" = 0
    check "build metadata is ignored"          test "$(semver_cmp 0.3.1+build.7 0.3.1)" = 0
    check "build metadata on a pre-release"    test "$(semver_cmp 0.3.1-rc.2+b.1 0.3.1-rc.10)" = -1
    check "a v prefix is ignored"              test "$(semver_cmp v0.3.1 0.3.1)" = 0
    check "a v prefix with metadata"           test "$(semver_cmp 0.2.0 v0.3.1+build.7)" = -1
    for odd in banana 1.2 1.2.3.4 01.2.3 1.02.3 1.2.03 1.2.3- 1.2.3-a..b 1.2.3-01 1.2.3-.a \
        0.2.0+ 0.2.0+build..7 0.2.0+.7 0.2.0+b+c "0.2.0+b_7" vv0.2.0 V0.2.0 "" "1.2.3 x" \
        "$(printf '1.2.3\n4.5.6')" "$(printf '1.2.3\r')"; do
        check "'$odd' is no version"           test "$(semver_cmp 0.2.0 "$odd")" = bad
        check "'$odd' is no version (second)"  test "$(semver_cmp "$odd" 0.2.0)" = bad
    done
    # Nothing past 256 bytes is compared: 140,000 z's are no version (and
    # never reach a tool with an argument limit), 256 bytes still are.
    check "a 140,000-byte pre-release is no version"   test "$(semver_cmp 1.0.0-a "1.0.0-$long")" = bad
    check "a 140,000-byte pre-release is no version (first)" test "$(semver_cmp "1.0.0-$long" 1.0.0-a)" = bad
    a250="$(head -c 250 /dev/zero | tr '\0' a)"
    check "a 256-byte version compares"        test "$(semver_cmp "1.0.0-$a250" 1.0.0)" = -1
    check "a 257-byte version is none"         test "$(semver_cmp "1.0.0-${a250}b" 1.0.0)" = bad
    # The one line an installed ward's --version must print.
    for line in "ward 0.2.0" "ward 0.2.0 (abc1234 2026-10-13)" "ward 0.2.0 (unknown unknown)" "ward v1.0.0-rc.1+b.2"; do
        check "'$line' is a version line"      version_line "$line"
    done
    for line in "$(printf 'ward 0.2.0\nward 99.0.0')" "ward 0.2.0 extra" "ward 0.2.0 (abc1234 2026-10-13) x" \
        "ward  0.2.0" " ward 0.2.0" "ward 0.2.0 (abc1234)" "ward banana" "wardx 0.2.0" "ward 1.0.0-$long"; do
        if version_line "$line"; then bad "'${line:0:40}' read as a version line"; else ok "'${line:0:40}' is no version line"; fi
    done
fi
# A newer installed ward, its version line spelled the ways the guard must
# read: with build metadata, and with a v. The metadata one shares the
# tested release's major and minor, so its patch field is what decides.
core="${TEST_VERSION%%-*}"
next_patch="${core%.*}.$(( ${core##*.} + 1 ))+build.7"
for line in "ward $next_patch (abc1234 2026-12-01)" "ward v99.0.0"; do
    H="$WORK/h-semver-$(printf '%s' "$line" | tr -c 'A-Za-z0-9' _)"
    mkdir -p "$H/.local/bin"
    printf '#!/bin/sh\necho "%s"\n' "$line" > "$H/.local/bin/ward"
    chmod 755 "$H/.local/bin/ward"
    out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" \
        && bad "latest replaced '$line'" || ok "latest left '$line' alone"
    check "it is untouched: $line"         test "$("$H/.local/bin/ward" --version)" = "$line"
    check "says it is newer: $line"        grep -Fq "newer than the latest release" <<<"$out"
done
# A build outside git says `(unknown unknown)`, and is still read.
H="$WORK/h-semver-unknown"
mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "ward 0.0.1 (unknown unknown)"\n' > "$H/.local/bin/ward"
chmod 755 "$H/.local/bin/ward"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "latest refused to upgrade a ward built outside git"; }
check "upgrades a ward built outside git"  grep -Fq "upgraded ward 0.0.1 (unknown unknown) -> ward $TEST_VERSION" <<<"$out"
# Unreadable: latest cannot tell it is older, so it fails closed, and a
# named version still replaces it. Each stand-in is a `ward` script body.
n=0
for body in 'echo "ward banana"' 'echo "ward 0.2.0+build..7"' 'echo "ward 0.2.0+"' \
    'exit 0' 'exit 1' 'echo "ward 0.2.0"; exit 1' 'echo "something else 9.9.9"' 'exec sleep 30' \
    'echo "ward 0.0.1"; echo "ward 99.0.0"' 'echo "ward 0.0.1 and more"' "echo \"ward 1.0.0-$long\""; do
    n=$((n+1))
    label="${body:0:60}"
    H="$WORK/h-unparseable-$n"
    mkdir -p "$H/.local/bin"
    printf '#!/bin/sh\n%s\n' "$body" > "$H/.local/bin/ward"
    chmod 755 "$H/.local/bin/ward"
    out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" \
        && bad "latest replaced an unreadable ward ($label)" || ok "latest left an unreadable ward alone ($label)"
    check "says it cannot tell ($label)"    grep -Fq "cannot tell whether" <<<"$out"
    # The builtin test: a 140,000-byte body is past the kernel's limit on
    # one argument to another program.
    check "it is untouched ($label)"        test "$(sed -n 2p "$H/.local/bin/ward")" = "$body"
    out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" "--version=$TEST_TAG" 2>&1)" \
        || { echo "$out"; bad "a named version did not replace an unreadable ward ($label)"; }
    check "a named version replaces it ($label)" sh -c "'$H/.local/bin/ward' --version | grep -q '^ward $TEST_VERSION'"
done

echo "== 27. latest is the tag in the latest release's signed LATEST"
# Each LATEST sits in release/l-<name>/ and is read through /redirect/, the
# way GitHub's releases/latest/download/LATEST redirects to the latest
# release's own LATEST.
latest_case() { # NAME CONTENT (printf %b), signed by the test key
    local dir="$WORK/release/l-$1"
    rm -rf "$dir"; mkdir -p "$dir"
    printf '%b' "$2" > "$dir/LATEST"
    GREYWARD_RELEASE_KEY="$RELEASE_KEY_FILE" GREYWARD_RELEASE_PUBLIC_KEY="$TEST_RELEASE_KEY" \
        "$ROOT/tools/release-sign.sh" --sign "$dir/LATEST" 2>/dev/null
}
latest_url() { printf '%s/redirect/l-%s/LATEST' "$GREYWARD_DOWNLOAD_BASE" "$1"; }
latest_installs() { # DESC NAME PATH
    local home="$WORK/h-latest-$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _)"
    out="$(LATEST_TAG_OVERRIDE="" LATEST_URL="$(latest_url "$2")" run_installer "$home" /bin/bash "$3" 2>&1)" \
        || { echo "$out"; bad "latest from LATEST failed ($1)"; }
    check "$1: latest is the tag LATEST names" sh -c "'$home/.local/bin/ward' --version 2>/dev/null | grep -q '^ward $TEST_VERSION'"
}
latest_refused() { # DESC NAME MESSAGE
    local home="$WORK/h-latest-$2"
    out="$(LATEST_TAG_OVERRIDE="" LATEST_URL="$(latest_url "$2")" run_installer "$home" /bin/bash "$BASE_PATH" 2>&1)" \
        && bad "latest took $1" || ok "latest refused $1"
    check "says why ($1)"                  grep -Fq "$3" <<<"$out"
    check "downloaded nothing ($1)"        absent 'downloading' "$out"
    check "installed nothing ($1)"         test ! -e "$home/.local/bin/ward"
}
latest_case good "$TEST_TAG\n"
latest_installs "curl" good "$BASE_PATH"
# wget, and busybox wget when there is one, with no curl on PATH: each
# follows the redirect on its own.
for kind in wget busybox; do
    real="$(command -v "$kind" || true)"
    if [ -z "$real" ]; then echo "  skip: no $kind here"; continue; fi
    dir="$WORK/no-curl-$kind"
    mkdir -p "$dir"
    for tool in /usr/bin/* /bin/*; do
        name="${tool##*/}"
        case "$name" in curl | wget) continue ;; esac
        [ -e "$dir/$name" ] || ln -s "$tool" "$dir/$name"
    done
    ln -s "$real" "$dir/wget"
    latest_installs "$kind" good "$dir"
done
# The bytes changed after signing.
latest_case tampered "$TEST_TAG\n"
printf 'v99.0.0\n' > "$WORK/release/l-tampered/LATEST"
latest_refused "a LATEST changed after signing" tampered "is not signed by ward's release key"
# Signed by some other key.
OTHER_KEY_FILE="$WORK/other.key"
OTHER_KEY="$("$BIN" keygen "$OTHER_KEY_FILE" 2>/dev/null | sed -n 's/^trusted = \["\(.*\)"\]$/\1/p')"
mkdir -p "$WORK/release/l-otherkey"
printf '%s\n' "$TEST_TAG" > "$WORK/release/l-otherkey/LATEST"
GREYWARD_RELEASE_KEY="$OTHER_KEY_FILE" GREYWARD_RELEASE_PUBLIC_KEY="$OTHER_KEY" \
    "$ROOT/tools/release-sign.sh" --sign "$WORK/release/l-otherkey/LATEST" 2>/dev/null
latest_refused "a LATEST signed by another key" otherkey "is not signed by ward's release key"
# Validly signed, and still not one release tag.
latest_case two "$TEST_TAG\nv99.0.0\n"
latest_refused "a LATEST of two lines" two "not one release tag on one line"
latest_case blank "$TEST_TAG\n\n"
latest_refused "a LATEST with a blank line after it" blank "not one release tag on one line"
latest_case nonewline "$TEST_TAG"
latest_refused "a LATEST with no newline" nonewline "not one release tag on one line"
latest_case notsemver "v1.2\n"
latest_refused "a LATEST that is not SemVer" notsemver "does not name a release tag"
latest_case noprefix "$TEST_VERSION\n"
latest_refused "a LATEST without its v" noprefix "does not name a release tag"
latest_case path "v0.2.0/../../x\n"
latest_refused "a LATEST holding a path" path "does not name a release tag"
# Missing, and missing its signature.
latest_refused "a missing LATEST" missing "cannot read the latest release"
latest_case nosig "$TEST_TAG\n"
rm -f "$WORK/release/l-nosig/LATEST.sig"
latest_refused "a LATEST with no .sig" nosig "has no signature next to it"

echo "== 28. release-sign.sh signs only what the tag's own commit built"
# A stand-in for gh: the release's assets in a directory, and an attestation
# that records the ref and commit the archive was built from. Like gh, it
# checks --source-ref and --source-digest only when they are passed.
FAKE="$WORK/fake-gh"
mkdir -p "$FAKE/bin" "$FAKE/assets" "$FAKE/uploaded"
cat > "$FAKE/bin/gh" <<'GH'
#!/bin/bash
set -euo pipefail
state="$FAKE_GH"
echo "$*" >> "$state/calls"
case "$1 $2" in
    "release view")
        case "$*" in
            *"--json assets"*) command ls "$state/assets" ;;
            *"--json isDraft"*) echo true ;;
        esac ;;
    "release download")
        dir=""; prev=""
        for arg in "$@"; do [ "$prev" = --dir ] && dir="$arg"; prev="$arg"; done
        cp "$state"/assets/* "$dir"/ ;;
    "release upload") shift 5; cp "$@" "$state/uploaded/" ;;
    "release edit") ;;
    "attestation verify")
        read -r built_ref built_commit < "$state/provenance"
        prev=""
        for arg in "$@"; do
            [ "$prev" = --source-ref ] && [ "$arg" != "$built_ref" ] && exit 1
            [ "$prev" = --source-digest ] && [ "$arg" != "$built_commit" ] && exit 1
            prev="$arg"
        done
        exit 0 ;;
    *) echo "fake gh: unexpected: $*" >&2; exit 1 ;;
esac
GH
chmod 755 "$FAKE/bin/gh"
REMOTE="$WORK/remote"
git init -q "$REMOTE"
gitc() { git -C "$REMOTE" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
gitc commit -q --allow-empty -m old
gitc tag v0.0.9
old_commit="$(git -C "$REMOTE" rev-parse HEAD)"
gitc commit -q --allow-empty -m new
gitc tag -a -m "release" v0.1.0
new_commit="$(git -C "$REMOTE" rev-parse HEAD)"
cp "$WORK/release/$asset" "$WORK/release/$asset.sha256" "$FAKE/assets/"
sign_release() { # TAG
    PATH="$FAKE/bin:$PATH" FAKE_GH="$FAKE" GREYWARD_RELEASE_REMOTE="$REMOTE" \
        GREYWARD_RELEASE_KEY="$RELEASE_KEY_FILE" GREYWARD_RELEASE_PUBLIC_KEY="$TEST_RELEASE_KEY" \
        "$ROOT/tools/release-sign.sh" "$@"
}
# An older tag's attested archive, uploaded into the new release.
echo "refs/tags/v0.0.9 $old_commit" > "$FAKE/provenance"
out="$(sign_release v0.1.0 2>&1)" \
    && bad "release-sign.sh signed another tag's build" || ok "release-sign.sh refused another tag's build"
check "says which tag and commit it wanted" grep -Fq "for tag v0.1.0 at $new_commit" <<<"$out"
check "nothing uploaded (another build)"  test -z "$(command ls "$FAKE/uploaded")"
# A tag the repository does not have.
out="$(sign_release v0.2.0 2>&1)" \
    && bad "release-sign.sh signed a release with no tag" || ok "release-sign.sh refused a release with no tag"
check "says the tag is missing"           grep -Fq "has no tag v0.2.0" <<<"$out"
# The tag's own build: the annotated tag peels to its commit.
echo "refs/tags/v0.1.0 $new_commit" > "$FAKE/provenance"
out="$(sign_release v0.1.0 2>&1)" || { echo "$out"; bad "release-sign.sh refused the tag's own build"; }
check "the archive's .sig is uploaded"    test -s "$FAKE/uploaded/$asset.sig"
check "the attestation was held to the tag" grep -Fq -- "--source-ref refs/tags/v0.1.0 --source-digest $new_commit" "$FAKE/calls"
check "LATEST is uploaded, naming the tag" test "$(cat "$FAKE/uploaded/LATEST")" = v0.1.0
check "LATEST is one line"                 test "$(wc -l < "$FAKE/uploaded/LATEST")" = 1
# The uploaded LATEST is one install.sh trusts: it reads v0.1.0 from it and
# then holds the binary (the one under test, not 0.1.0) to that tag.
mkdir -p "$WORK/release/l-signed"
cp "$FAKE/uploaded/LATEST" "$FAKE/uploaded/LATEST.sig" "$WORK/release/l-signed/"
H="$WORK/h-latest-signed"
out="$(LATEST_TAG_OVERRIDE="" LATEST_URL="$(latest_url signed)" run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" || true
check "install.sh reads the signed LATEST" grep -Fq "not ward 0.1.0" <<<"$out"
# A release published before signing existed gets its LATEST too.
rm -f "$FAKE/uploaded"/* "$FAKE/calls"
out="$(sign_release --without-attestation v0.0.9 2>&1)" || { echo "$out"; bad "release-sign.sh --without-attestation failed"; }
check "--without-attestation signs the archive" test -s "$FAKE/uploaded/$asset.sig"
check "--without-attestation uploads LATEST" test "$(cat "$FAKE/uploaded/LATEST")" = v0.0.9
check "--without-attestation signs LATEST" test -s "$FAKE/uploaded/LATEST.sig"
check "--without-attestation asks for no attestation" absent "attestation verify" "$(cat "$FAKE/calls")"
# A release that already carries a LATEST is not touched.
rm -f "$FAKE/uploaded"/*
printf 'v0.1.0\n' > "$FAKE/assets/LATEST"
out="$(sign_release v0.1.0 2>&1)" \
    && bad "release-sign.sh replaced a LATEST" || ok "release-sign.sh refused a release with a LATEST"
check "says LATEST is there"               grep -Fq "already carries a LATEST" <<<"$out"
check "nothing uploaded (LATEST there)"    test -z "$(command ls "$FAKE/uploaded")"
rm -f "$FAKE/assets/LATEST"
# A tag LATEST could not carry.
out="$(sign_release v1.2 2>&1)" \
    && bad "release-sign.sh took tag v1.2" || ok "release-sign.sh refused tag v1.2"
check "says it is no release tag"          grep -Fq "'v1.2' is not a release tag" <<<"$out"

echo
echo "install.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
