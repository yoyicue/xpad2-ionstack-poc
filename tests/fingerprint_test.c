// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#include <stdio.h>
#include <string.h>

#include "../src/fingerprint.h"

static int failures;

static void check(const char *name, const char *fingerprint, int expected_ok,
                  int expected_incremental) {
  int incremental = -1;
  const int ok = ionstack_fingerprint_matches(fingerprint, &incremental);

  if (ok != expected_ok || incremental != expected_incremental) {
    fprintf(stderr,
            "FAIL %s: ok=%d incremental=%d, expected ok=%d incremental=%d\n",
            name, ok, incremental, expected_ok, expected_incremental);
    ++failures;
  }
}

static void check_incremental(unsigned incremental, int expected_ok) {
  char fingerprint[256];
  const int written = snprintf(fingerprint, sizeof(fingerprint), "%s%u%s",
                               EXPECTED_FINGERPRINT_PREFIX, incremental,
                               EXPECTED_FINGERPRINT_SUFFIX);
  if (written < 0 || (size_t)written >= sizeof(fingerprint)) {
    fprintf(stderr, "FAIL could not construct fingerprint for %u\n",
            incremental);
    ++failures;
    return;
  }
  check(fingerprint, fingerprint, expected_ok, (int)incremental);
}

int main(void) {
  check_incremental(18, 0);
  for (unsigned incremental = RELEASE_FINGERPRINT_INCREMENTAL_MIN;
       incremental <= RELEASE_FINGERPRINT_INCREMENTAL_MAX; ++incremental) {
    check_incremental(incremental, 1);
  }
  check_incremental(261, 0);
  check_incremental(1703659195U, 0);
  check_incremental(1703659196U, 0);
  check_incremental(1703659197U, 0);

  check("leading zero",
        EXPECTED_FINGERPRINT_PREFIX "019" EXPECTED_FINGERPRINT_SUFFIX, 0, -1);
  check("plus sign",
        EXPECTED_FINGERPRINT_PREFIX "+19" EXPECTED_FINGERPRINT_SUFFIX, 0, -1);
  check("missing incremental",
        EXPECTED_FINGERPRINT_PREFIX EXPECTED_FINGERPRINT_SUFFIX, 0, -1);
  check("trailing character",
        EXPECTED_FINGERPRINT_PREFIX "19x" EXPECTED_FINGERPRINT_SUFFIX, 0, -1);
  check("wrong device",
        "alps/vnd_ls14_mt8797_wifi_64/ls12_mt8797_wifi_64:13/"
        "TP1A.220624.014/19:user/release-keys",
        0, -1);
  check("wrong suffix", EXPECTED_FINGERPRINT_PREFIX "19:user/debug-keys", 0,
        -1);
  check("overflow",
        EXPECTED_FINGERPRINT_PREFIX "42949672960" EXPECTED_FINGERPRINT_SUFFIX,
        0, -1);

  if (failures != 0) {
    fprintf(stderr, "%d fingerprint test(s) failed\n", failures);
    return 1;
  }
  puts("fingerprint tests passed");
  return 0;
}
