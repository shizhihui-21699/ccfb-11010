#!/usr/bin/env bash
# End-to-end scenarios: real filesystem activity -> real binaries.
#
# These tests run the actual `ransomwatch` binary against the actual
# `ransom-sim` binary writing to a scratch directory.  They are slower than the
# unit tests (a few minutes) and need macOS/Linux process introspection, so
# `cargo test` does not run them by default.
#
#   ./scripts/e2e.sh          run every scenario
#   ./scripts/e2e.sh gzip     run scenarios whose name matches the pattern
#
# Every scenario is isolated under a fresh directory and the watcher runs with
# --exit-after-incident.  Benign scenarios run with --dry-run so a false
# positive cannot suspend anything before it is reported.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
RW="$ROOT/target/release/ransomwatch"
SIM="$ROOT/target/release/ransom-sim"
FILTER="${1:-.}"

if [[ ! -x "$RW" || ! -x "$SIM" ]]; then
  echo "building release binaries..."
  cargo build --release --offline >/dev/null || cargo build --release >/dev/null || {
    echo "build failed"; exit 1; }
fi

BASE=$(mktemp -d "${TMPDIR:-/tmp}/rw-e2e-test.XXXXXX")
PASS=0; FAIL=0; SKIP=0
cleanup() {
  pkill -CONT -f "$BASE" 2>/dev/null || true
  pkill -KILL -f "$BASE" 2>/dev/null || true
  pkill -KILL -f "release/ransomwatch" 2>/dev/null || true
  rm -rf "$BASE"
}
trap cleanup EXIT

report() { # name expect got
  local name=$1 expect=$2 got=$3
  if [[ "$expect" == "$got" ]]; then
    printf '  \033[32mPASS\033[0m %s (%s)\n' "$name" "$got"
    PASS=$((PASS+1))
  else
    printf '  \033[31mFAIL\033[0m %s (expected %s, got %s)\n' "$name" "$expect" "$got"
    FAIL=$((FAIL+1))
    echo "    --- signals ---"
    grep -E "SIGNAL|INCIDENT|DECOY" "$BASE/$name/watch.log" 2>/dev/null | sed 's/^/    /' | head -8
  fi
}

scenario() { # name expect populate_fn workload_fn
  local name=$1 expect=$2 populate=$3 workload=$4
  [[ "$name" =~ $FILTER ]] || { SKIP=$((SKIP+1)); return; }
  local dir="$BASE/$name/tree"
  mkdir -p "$dir" "$BASE/$name/ev"
  $populate "$dir"
  local flags=""
  [[ "$expect" == clear ]] && flags="--dry-run"
  # shellcheck disable=SC2086
  "$RW" --path "$dir" --evidence-dir "$BASE/$name/ev" \
        --exit-after-incident $flags > "$BASE/$name/watch.log" 2>&1 &
  local wpid=$!
  sleep 2.5
  ( "$workload" "$dir" ) &
  local wlpid=$!
  # Give the detector time to fire, then wind everything down.  Suspended
  # writers must be continued before they can be killed.
  sleep 6
  pkill -CONT -f "$dir" 2>/dev/null || true
  pkill -KILL -f "$dir" 2>/dev/null || true
  wait "$wlpid" 2>/dev/null
  kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
  if grep -q INCIDENT "$BASE/$name/watch.log" 2>/dev/null; then
    report "$name" "$expect" detect
  else
    report "$name" "$expect" clear
  fi
}

pop_default()  { "$SIM" --allow-any-dir --dir "$1" populate --files 140 >/dev/null 2>&1; }
pop_small()    { "$SIM" --allow-any-dir --dir "$1" populate --files 20  >/dev/null 2>&1; }
pop_none()     { :; }

# ---------------------------------------------------------------- malicious
enc_inplace()    { "$SIM" --allow-any-dir --dir "$1" inplace --files 110 --delay-ms 40 >/dev/null 2>&1; }
enc_rename()     { "$SIM" --allow-any-dir --dir "$1" encrypt-rename --files 110 --delay-ms 40 --ext locked >/dev/null 2>&1; }
enc_shred()      { "$SIM" --allow-any-dir --dir "$1" inplace --files 110 --delay-ms 20 --shred >/dev/null 2>&1; }
ext_only()       { "$SIM" --allow-any-dir --dir "$1" ext-only --files 110 --ext wncry >/dev/null 2>&1; }
probe_then_enc() {
  "$SIM" --allow-any-dir --dir "$1" decoy-probe --rounds 1 --delay-ms 5 >/dev/null 2>&1
  "$SIM" --allow-any-dir --dir "$1" inplace --files 80 --delay-ms 40 >/dev/null 2>&1
}
write_decoys()   { "$SIM" --allow-any-dir --dir "$1" encrypt-decoys --ext locked >/dev/null 2>&1; }
notes_only()     {
  # A note alone, with no encryption, is ambiguous; a note plus renaming is not.
  "$SIM" --allow-any-dir --dir "$1" drop-note >/dev/null 2>&1
  "$SIM" --allow-any-dir --dir "$1" encrypt-rename --files 60 --delay-ms 2 --ext enc --note false >/dev/null 2>&1
}
delete_all()     { "$SIM" --allow-any-dir --dir "$1" delete --files 110 >/dev/null 2>&1; }

# ------------------------------------------------------------------- benign
w_gzip()    { ( cd "$1" && gzip -kr docs ) 2>/dev/null; }
w_zip()     { ( cd "$1" && zip -qr backup.zip docs ) 2>/dev/null; }
w_tar()     { tar czf "$1/archive.tgz" -C "$1" docs 2>/dev/null; }
w_bzip2()   { ( cd "$1" && bzip2 -kr docs/*/*/* 2>/dev/null ); }
w_ditto()   { ditto -c -k --sequesterRsrc "$1/docs" "$1/docs.zip" 2>/dev/null; }
w_rsync()   { rsync -a "$1/" "$BASE/$(basename "$(dirname "$1")")-copy/" 2>/dev/null; }
w_gitclone() {
  local repo="$BASE/repo-$(basename "$(dirname "$1")")"
  rm -rf "$repo"; mkdir -p "$repo"
  ( cd "$repo" && git init -q && git config user.email a@b.c && git config user.name t
    for i in $(seq 1 80); do head -c 3000 /dev/urandom | base64 > "f$i.txt"; done
    head -c 300000 /dev/urandom > bin.bin
    git add -A && git commit -qm x ) >/dev/null 2>&1
  git clone -q "$repo" "$1/cloned" >/dev/null 2>&1
}
w_build()   {
  mkdir -p "$1/node_modules/pkg" "$1/src" "$1/target/debug"
  for i in $(seq 1 250); do echo "module.exports = $i" > "$1/node_modules/pkg/f$i.js"; done
  for i in $(seq 1 60);  do echo "fn f$i() {}" > "$1/src/m$i.rs"; done
  for i in $(seq 1 40);  do head -c 40000 /dev/urandom > "$1/target/debug/obj$i.o"; done
}
w_media()   {
  # A video editor writing large opaque frames into a project directory.
  mkdir -p "$1/render"
  for i in $(seq 1 12); do head -c 2000000 /dev/urandom > "$1/render/frame$i.raw"; done
}
w_editor()  {
  for i in $(seq 1 30); do
    printf 'revision %s\n' "$i" >> "$1/docs/2020/1/report_0000.txt" 2>/dev/null || true
    sleep 0.02
  done
}
w_batchjob() {
  # Touch every document the job was *given*, not the whole tree: honeytokens
  # live outside a normal application's working set.
  find "$1/docs" -type f -name '*.txt' -print0 2>/dev/null \
    | xargs -0 -n1 sh -c 'echo "processed" >> "$0"' 2>/dev/null
}
w_download() {
  # Browser-style partial downloads: temp suffix then atomic rename.
  mkdir -p "$1/Downloads"
  for i in $(seq 1 25); do
    head -c 400000 /dev/urandom > "$1/Downloads/file$i.zip.crdownload"
    mv "$1/Downloads/file$i.zip.crdownload" "$1/Downloads/file$i.zip"
  done
}
w_photo()   {
  # Photo export: many new high-entropy JPEGs with valid headers.
  mkdir -p "$1/export"
  for i in $(seq 1 40); do
    { printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00'; head -c 60000 /dev/urandom; } > "$1/export/DSC$i.jpg"
  done
}
w_encrypted_archive() {
  # A password-protected archive's output looks like ciphertext but is one
  # file; the user is *saving* something, not shredding the tree.
  ( cd "$1" && tar czf - docs 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:x -out docs.enc ) 2>/dev/null
}

echo "== malicious (must detect) =="
scenario m_inplace       detect pop_default enc_inplace
scenario m_encrename     detect pop_default enc_rename
scenario m_shred         detect pop_default enc_shred
scenario m_extonly       detect pop_default ext_only
scenario m_probe_then_enc detect pop_default probe_then_enc
scenario m_decoywrite    detect pop_small   write_decoys
scenario m_note_and_enc  detect pop_default notes_only

echo "== benign (must stay clear) =="
scenario b_gzip          clear  pop_default w_gzip
scenario b_zip           clear  pop_default w_zip
scenario b_tar           clear  pop_default w_tar
scenario b_bzip2         clear  pop_default w_bzip2
scenario b_ditto         clear  pop_default w_ditto
scenario b_rsync         clear  pop_default w_rsync
scenario b_gitclone      clear  pop_none    w_gitclone
scenario b_build         clear  pop_none    w_build
scenario b_media         clear  pop_default w_media
scenario b_editor        clear  pop_none    w_editor
scenario b_batchjob      clear  pop_default w_batchjob
scenario b_download      clear  pop_none    w_download
scenario b_photo         clear  pop_none    w_photo
scenario b_enc_archive   clear  pop_default w_encrypted_archive
scenario b_delete_some   clear  pop_default delete_all

echo
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
