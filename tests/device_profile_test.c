// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/device/fingerprint.h"
#include "../src/device/profile_match.h"

static int expect_string(const char *name, const char *actual,
                         const char *expected) {
  if (strcmp(actual, expected) == 0) {
    return 0;
  }
  fprintf(stderr, "%s mismatch:\n  actual:   %s\n  expected: %s\n",
          name, actual, expected);
  return 1;
}

static int expect_tuple(const char *name, const char *kernel_version,
                        const char *fingerprint,
                        enum ionstack_profile_tuple_match expected) {
  enum ionstack_profile_tuple_match actual =
      ionstack_profile_tuple_matches(kernel_version, fingerprint);
  if (actual == expected) {
    return 0;
  }
  fprintf(stderr, "%s tuple mismatch: actual=%s expected=%s\n", name,
          ionstack_profile_tuple_name(actual),
          ionstack_profile_tuple_name(expected));
  return 1;
}

static int expect_compatible_fingerprint(const char *name,
                                         const char *fingerprint,
                                         int expected_match,
                                         int expected_incremental) {
  int incremental = -1;
  int actual =
      ionstack_compatible_fingerprint_matches(fingerprint, &incremental);
  if (actual == expected_match && incremental == expected_incremental) {
    return 0;
  }
  fprintf(stderr,
          "%s compatible fingerprint mismatch: match=%d incremental=%d "
          "expected_match=%d expected_incremental=%d\n",
          name, actual, incremental, expected_match, expected_incremental);
  return 1;
}

int main(void) {
  int failures = 0;

#if defined(IONSTACK_PROFILE_XPAD3S)
  failures += expect_string("profile", IONSTACK_PROFILE_NAME,
                            "xpad3s-talih-pd3s-gki-5.10.198");
  failures += expect_string("device", EXPECTED_DEVICE, "TALIH-PD3S");
  failures += expect_string(
      "fingerprint", EXPECTED_FINGERPRINT,
      "alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/"
      "338:user/release-keys");
  failures += expect_tuple(
      "xpad3s alternate", EXPECTED_KERNEL_VERSION,
      "alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/"
      "371:user/release-keys",
      IONSTACK_PROFILE_TUPLE_ALTERNATE);
#elif defined(IONSTACK_PROFILE_XPAD2P)
  failures += expect_string("profile", IONSTACK_PROFILE_NAME,
                            "xpad2p-talih-pd2p-mt8797-4.19.191");
  failures += expect_string("device", EXPECTED_DEVICE,
                            "ls14_mt8797_wifi_64");
  failures += expect_string(
      "fingerprint", EXPECTED_FINGERPRINT,
      "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
      "TP1A.220624.014/272:user/release-keys");
  failures += expect_string(
      "kernel version", EXPECTED_KERNEL_VERSION,
      "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026");
  failures += expect_string(
      "alternate fingerprint", EXPECTED_FINGERPRINT_ALT,
      "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
      "TP1A.220624.014/262:user/release-keys");
  failures += expect_string(
      "alternate kernel version", EXPECTED_KERNEL_VERSION_ALT,
      "#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026");
  failures += expect_tuple("xpad2p /272", EXPECTED_KERNEL_VERSION,
                           EXPECTED_FINGERPRINT,
                           IONSTACK_PROFILE_TUPLE_PRIMARY);
  failures += expect_tuple("xpad2p /262", EXPECTED_KERNEL_VERSION_ALT,
                           EXPECTED_FINGERPRINT_ALT,
                           IONSTACK_PROFILE_TUPLE_ALTERNATE);
  failures += expect_tuple("xpad2p crossed /262 fingerprint",
                           EXPECTED_KERNEL_VERSION,
                           EXPECTED_FINGERPRINT_ALT,
                           IONSTACK_PROFILE_TUPLE_NONE);
  failures += expect_tuple("xpad2p crossed /272 fingerprint",
                           EXPECTED_KERNEL_VERSION_ALT,
                           EXPECTED_FINGERPRINT,
                           IONSTACK_PROFILE_TUPLE_NONE);
  failures += expect_compatible_fingerprint(
      "xpad2p lower bound",
      "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
      "TP1A.220624.014/19:user/release-keys",
      1, 19);
  failures += expect_compatible_fingerprint(
      "xpad2p upper bound", EXPECTED_FINGERPRINT, 1, 272);
  failures += expect_compatible_fingerprint(
      "xpad2p below range",
      "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
      "TP1A.220624.014/18:user/release-keys",
      0, 18);
  failures += expect_compatible_fingerprint(
      "xpad2p above range",
      "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
      "TP1A.220624.014/273:user/release-keys",
      0, 273);
  failures += expect_compatible_fingerprint(
      "xpad2p rejects LS12",
      "alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/"
      "TP1A.220624.014/260:user/release-keys",
      0, -1);
  if (IONSTACK_PROFILE_CHAIN_VALIDATED != 0) {
    fputs("PD2P historical full-chain marker must remain unset\n",
          stderr);
    ++failures;
  }
  if (IONSTACK_PROFILE_AUTO_ARM_AFTER_VALIDATION != 1) {
    fputs("PD2P must auto-arm only after current-run validation\n", stderr);
    ++failures;
  }
#else
  failures += expect_string("profile", IONSTACK_PROFILE_NAME,
                            "xpad2-talih-pd2-mt8797-4.19.191");
  failures += expect_string("device", EXPECTED_DEVICE,
                            "ls12_mt8797_wifi_64");
  failures += expect_string(
      "fingerprint", EXPECTED_FINGERPRINT,
      "alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/"
      "TP1A.220624.014/260:user/release-keys");
  failures += expect_tuple("xpad2 /260", EXPECTED_KERNEL_VERSION,
                           EXPECTED_FINGERPRINT,
                           IONSTACK_PROFILE_TUPLE_PRIMARY);
  failures += expect_tuple(
      "xpad2 rejects LS14 /262",
      "#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026",
      "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
      "TP1A.220624.014/262:user/release-keys",
      IONSTACK_PROFILE_TUPLE_NONE);
#endif

  if (!IONSTACK_PROFILE_VALIDATE_ENABLED) {
    fputs("profile validation path must be enabled\n", stderr);
    ++failures;
  }
#if !defined(IONSTACK_PROFILE_XPAD2P)
  if (IONSTACK_PROFILE_AUTO_ARM_AFTER_VALIDATION != 0) {
    fputs("only PD2P may use conditional current-run write arming\n", stderr);
    ++failures;
  }
  failures += expect_compatible_fingerprint(
      "non-PD2P compatibility disabled", EXPECTED_FINGERPRINT, 0, -1);
#else
  if (!IONSTACK_PROFILE_COMPAT_ENABLED) {
    fputs("PD2P compatible profile path must be enabled\n", stderr);
    ++failures;
  }
#endif

  if (failures != 0) {
    return 1;
  }
  printf("%s profile contract passed\n", IONSTACK_PROFILE_NAME);
  return 0;
}
