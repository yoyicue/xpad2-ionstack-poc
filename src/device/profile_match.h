// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#ifndef IONSTACK_DEVICE_PROFILE_MATCH_H
#define IONSTACK_DEVICE_PROFILE_MATCH_H

#include <string.h>

#include "profile.h"

enum ionstack_profile_tuple_match {
  IONSTACK_PROFILE_TUPLE_NONE = 0,
  IONSTACK_PROFILE_TUPLE_PRIMARY = 1,
  IONSTACK_PROFILE_TUPLE_ALTERNATE = 2,
};

static inline enum ionstack_profile_tuple_match
ionstack_profile_tuple_matches(const char *kernel_version,
                               const char *fingerprint) {
  if (!kernel_version || !fingerprint) {
    return IONSTACK_PROFILE_TUPLE_NONE;
  }
  if (strcmp(kernel_version, EXPECTED_KERNEL_VERSION) == 0 &&
      strcmp(fingerprint, EXPECTED_FINGERPRINT) == 0) {
    return IONSTACK_PROFILE_TUPLE_PRIMARY;
  }
  if (EXPECTED_KERNEL_VERSION_ALT[0] != '\0' &&
      EXPECTED_FINGERPRINT_ALT[0] != '\0' &&
      strcmp(kernel_version, EXPECTED_KERNEL_VERSION_ALT) == 0 &&
      strcmp(fingerprint, EXPECTED_FINGERPRINT_ALT) == 0) {
    return IONSTACK_PROFILE_TUPLE_ALTERNATE;
  }
  return IONSTACK_PROFILE_TUPLE_NONE;
}

static inline const char *ionstack_profile_tuple_name(
    enum ionstack_profile_tuple_match match) {
  switch (match) {
    case IONSTACK_PROFILE_TUPLE_PRIMARY:
      return "primary";
    case IONSTACK_PROFILE_TUPLE_ALTERNATE:
      return "alternate";
    default:
      return "none";
  }
}

#endif
