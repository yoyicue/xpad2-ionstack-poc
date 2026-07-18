// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#ifndef IONSTACK_DEVICE_PROFILE_H
#define IONSTACK_DEVICE_PROFILE_H

#if defined(IONSTACK_PROFILE_XPAD3S)

#define IONSTACK_PROFILE_NAME "xpad3s-talih-pd3s-gki-5.10.198"
#define EXPECTED_DEVICE "TALIH-PD3S"
#define EXPECTED_KERNEL_RELEASE \
  "5.10.198-android12-9-00019-g6efebf1322d6-ab11471183"
#define EXPECTED_KERNEL_VERSION \
  "#1 SMP PREEMPT Mon Feb 19 21:20:42 UTC 2024"
#define EXPECTED_SDK "33"
#define EXPECTED_FINGERPRINT \
  "alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/338:user/release-keys"
#define EXPECTED_FINGERPRINT_ALT \
  "alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/371:user/release-keys"
#define IONSTACK_INIT_TASK_OFF UINT64_C(0x0278bec0)

/*
 * The holder/reclaim validation path is enabled after static layout, KASLR,
 * direct-map and SLUB geometry validation.  The fops capture/write/restore
 * chain was dynamically validated on the exact profile on 2026-07-18.
 */
#define IONSTACK_PROFILE_VALIDATE_ENABLED 1
#define IONSTACK_PROFILE_CHAIN_VALIDATED 1

#else

#define IONSTACK_PROFILE_NAME "xpad2-talih-pd2-mt8797-4.19.191"
#define EXPECTED_DEVICE "ls12_mt8797_wifi_64"
#define EXPECTED_KERNEL_RELEASE "4.19.191"
#define EXPECTED_KERNEL_VERSION \
  "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026"
#define EXPECTED_SDK "33"
#define EXPECTED_FINGERPRINT \
  "alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/" \
  "TP1A.220624.014/260:user/release-keys"
#define EXPECTED_FINGERPRINT_ALT ""
#define IONSTACK_INIT_TASK_OFF UINT64_C(0x016cc780)
#define IONSTACK_PROFILE_VALIDATE_ENABLED 1
#define IONSTACK_PROFILE_CHAIN_VALIDATED 1

#endif

#endif
