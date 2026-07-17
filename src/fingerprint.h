// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#ifndef IONSTACK_FINGERPRINT_H
#define IONSTACK_FINGERPRINT_H

#include <limits.h>
#include <string.h>

#include "profile.h"

static inline int ionstack_fingerprint_matches(const char *fingerprint,
                                               int *incremental_out) {
  const size_t prefix_len = strlen(EXPECTED_FINGERPRINT_PREFIX);
  const char *cursor;
  unsigned incremental = 0;

  if (incremental_out != NULL) {
    *incremental_out = -1;
  }
  if (fingerprint == NULL ||
      strncmp(fingerprint, EXPECTED_FINGERPRINT_PREFIX, prefix_len) != 0) {
    return 0;
  }

  cursor = fingerprint + prefix_len;
  if (*cursor < '0' || *cursor > '9') {
    return 0;
  }
  if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9') {
    return 0;
  }

  do {
    const unsigned digit = (unsigned)(*cursor - '0');
    if (incremental > (UINT_MAX - digit) / 10U) {
      return 0;
    }
    incremental = incremental * 10U + digit;
    ++cursor;
  } while (*cursor >= '0' && *cursor <= '9');

  if (strcmp(cursor, EXPECTED_FINGERPRINT_SUFFIX) != 0) {
    return 0;
  }
  if (incremental_out != NULL && incremental <= (unsigned)INT_MAX) {
    *incremental_out = (int)incremental;
  }
  return incremental >= PROFILE_FINGERPRINT_INCREMENTAL_MIN &&
         incremental <= PROFILE_FINGERPRINT_INCREMENTAL_MAX;
}

#endif
