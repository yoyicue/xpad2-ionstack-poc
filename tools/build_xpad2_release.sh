#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOCK="$ROOT/xpad2-release.lock.json"

for command in git jq make shasum zip; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 1
  }
done

if test -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)"; then
  printf 'release build requires a clean tracked worktree and index\n' >&2
  exit 1
fi

COMMIT=$(git -C "$ROOT" rev-parse HEAD)
SHORT=$(git -C "$ROOT" rev-parse --short=12 HEAD)
VERSION=${1:-$(git -C "$ROOT" describe --tags --exact-match 2>/dev/null || printf '%s' "$SHORT")}
PLATFORM=${2:-darwin-arm64}
HOST_CONTROLLER=${3:-"$ROOT/build/xpad2-ionstack-reroot"}
NAME="xpad2-ionstack-poc-$VERSION-$PLATFORM"
OUT="$ROOT/dist/$NAME"
ZIP="$ROOT/dist/$NAME.zip"

case "$VERSION" in
  *[!A-Za-z0-9._-]*|'')
    printf 'invalid release version: %s\n' "$VERSION" >&2
    exit 2
    ;;
esac
case "$PLATFORM" in
  *[!A-Za-z0-9._-]*|'')
    printf 'invalid release platform: %s\n' "$PLATFORM" >&2
    exit 2
    ;;
esac

make -C "$ROOT" PROFILE=xpad2 -j4

test -f "$HOST_CONTROLLER" || {
  printf 'host controller not found: %s\n' "$HOST_CONTROLLER" >&2
  exit 1
}

rm -rf "$OUT"
rm -f "$ZIP" "$ZIP.sha256"
mkdir -p "$OUT/build/xpad2" "$OUT/profiles" "$OUT/tools"

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
    cp "$input" "$OUT/build/xpad2/$filename"
  done

printf 'xpad2\n' > "$OUT/build/xpad2/.profile"
case "$PLATFORM" in
  windows-*) host_name="xpad2-ionstack-reroot.exe" ;;
  *) host_name="xpad2-ionstack-reroot" ;;
esac
cp "$HOST_CONTROLLER" "$OUT/$host_name"
chmod 0755 "$OUT/$host_name"
cp "$ROOT/profiles/xpad2_profiles.json" "$OUT/profiles/"
cp "$ROOT/tools/ionstack_auto_poc.py" \
  "$ROOT/tools/ionstack_profile_diag.py" "$OUT/tools/"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/SECURITY.md" \
  "$ROOT/xpad2-release.lock.json" "$OUT/"

jq -n \
  --arg release "$NAME" \
  --arg version "$VERSION" \
  --arg platform "$PLATFORM" \
  --arg commit "$COMMIT" \
  --arg branch "$(git -C "$ROOT" branch --show-current)" \
  --argjson profile "$(jq -c '.profile' "$LOCK")" \
  '{schema:1,release:$release,version:$version,platform:$platform,source_commit:$commit,source_branch:$branch,profile:$profile}' \
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

printf 'XPAD2_RELEASE_OK directory=%s zip=%s commit=%s platform=%s\n' \
  "$OUT" "$ZIP" "$COMMIT" "$PLATFORM"
