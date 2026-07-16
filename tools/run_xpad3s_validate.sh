#!/system/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

base=/data/local/tmp
rm -f "$base/xpad3s_validate.log" "$base/xpad3s_validate.exit"
(
  "$base/ionstack_reroot_device" --validate-only \
    --target-hold-sec=240 --page-hold-sec=60 \
    >"$base/xpad3s_validate.log" 2>&1
  echo "$?" >"$base/xpad3s_validate.exit"
) </dev/null &
echo "$!" >"$base/xpad3s_validate.pid"
