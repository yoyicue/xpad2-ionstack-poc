#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOCK="$ROOT/xpad3s-release.lock.json"

for command in git jq make shasum zip; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 1
  }
done

if test -n "$(git -C "$ROOT" status --porcelain)"; then
  printf 'release build requires a clean worktree\n' >&2
  exit 1
fi

COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT=$(git -C "$ROOT" rev-parse --short=12 HEAD)
NAME="xpad3s-pd3s-338-$SHORT"
OUT=${1:-"$ROOT/dist/$NAME"}
ZIP="$ROOT/dist/$NAME.zip"

case "$OUT" in
  "$ROOT"/dist/*) ;;
  *)
    printf 'release output must be below %s/dist: %s\n' "$ROOT" "$OUT" >&2
    exit 2
    ;;
esac

make -C "$ROOT" PROFILE=xpad3s -j4

rm -rf "$OUT"
rm -f "$ZIP" "$ZIP.sha256"
mkdir -p "$OUT/build"

jq -r '.artifacts[] | [.source,.filename,(.size|tostring),.sha256] | @tsv' \
  "$LOCK" | while IFS="$(printf '\t')" read -r source filename expected_size expected_sha; do
    input="$ROOT/$source"
    test -f "$input" || {
      printf 'locked artifact missing: %s\n' "$input" >&2
      exit 1
    }
    actual_size=$(wc -c < "$input" | tr -d ' ')
    actual_sha=$(shasum -a 256 "$input" | awk '{print $1}')
    test "$actual_size" = "$expected_size" || {
      printf 'size mismatch for %s: expected=%s actual=%s\n' \
        "$source" "$expected_size" "$actual_size" >&2
      exit 1
    }
    test "$actual_sha" = "$expected_sha" || {
      printf 'SHA-256 mismatch for %s: expected=%s actual=%s\n' \
        "$source" "$expected_sha" "$actual_sha" >&2
      exit 1
    }
    cp "$input" "$OUT/build/$filename"
  done

cp "$ROOT/README.md" "$ROOT/PORTING_XPAD3S.md" "$ROOT/LICENSE" \
  "$ROOT/NOTICE" "$ROOT/SECURITY.md" "$ROOT/xpad3s-release.lock.json" "$OUT/"

jq -n \
  --arg release "$NAME" \
  --arg commit "$COMMIT" \
  --arg branch "$(git -C "$ROOT" branch --show-current)" \
  --argjson profile "$(jq -c '.profile' "$LOCK")" \
  '{schema:1,release:$release,source_commit:$commit,source_branch:$branch,profile:$profile}' \
  > "$OUT/release.json"

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done > SHA256SUMS
  shasum -a 256 -c SHA256SUMS >/dev/null
)

mkdir -p "$ROOT/dist"
(
  cd "$ROOT/dist"
  COPYFILE_DISABLE=1 zip -X -q -r "$ZIP" "$NAME"
)
shasum -a 256 "$ZIP" > "$ZIP.sha256"

printf 'XPAD3S_RELEASE_OK directory=%s zip=%s commit=%s\n' \
  "$OUT" "$ZIP" "$COMMIT"
