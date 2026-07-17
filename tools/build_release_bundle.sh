#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/dist/xpad2-19-260"}
PROFILES="xpad2-v19-a xpad2-v19-b xpad2-v260"

case "$OUT" in
  "$ROOT"/dist/*) ;;
  *)
    printf 'release output must be below %s/dist: %s\n' "$ROOT" "$OUT" >&2
    exit 2
    ;;
esac

rm -rf "$OUT"
mkdir -p "$OUT/profiles" "$OUT/tools"

for profile in $PROFILES; do
  make -C "$ROOT" PROFILE="$profile" test all
  destination="$OUT/profiles/$profile"
  mkdir -p "$destination"
  cp "$ROOT/build/ionstack_reroot_device" "$destination/"
  cp "$ROOT/build/ionstack_preload.so" "$destination/"
  cp "$ROOT/build/ionstack_perf_target" "$destination/"
  cp "$ROOT/build/cve_2026_43499_chainwalk_probe_arm32" "$destination/"
done

cp "$ROOT/tools/ionstack_profile_diag.py" "$OUT/tools/"
cp "$ROOT/tools/ionstack_crash_harvest.py" "$OUT/tools/"
cp "$ROOT/tools/ionstack_auto_poc.py" "$OUT/tools/"
python3 - "$ROOT/profiles/xpad2_profiles.json" \
  "$OUT/profiles/xpad2_profiles.json" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    catalog = json.load(stream)
catalog["profiles"] = [item for item in catalog["profiles"] if item["release"]]
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(catalog, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done > SHA256SUMS
)

if find "$OUT" \( -type f -o -type d \) | grep -q 'v231227' || \
   grep -R -a -q -E 'xpad2-v231227|1703659196' "$OUT"; then
  printf 'release bundle unexpectedly contains v231227\n' >&2
  exit 1
fi

printf 'release bundle ready: %s\n' "$OUT"
