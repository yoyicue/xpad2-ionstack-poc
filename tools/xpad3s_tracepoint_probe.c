// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_ID 512
#define SEND_SIZE 36480

static int perf_open(unsigned id) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.size = sizeof(attr);
  attr.config = id;
  attr.disabled = 1;
  return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1,
                      PERF_FLAG_FD_CLOEXEC);
}

static void probe_filters(void) {
  const char *filters[] = {
      "order == 3", "gfp_flags != 0", "pfn != 0", "page != 0",
      "migratetype >= 0", "alloc_order >= 0"};
  for (unsigned id = 240; id <= 290; ++id) {
    unsigned mask = 0;
    for (unsigned i = 0; i < sizeof(filters) / sizeof(filters[0]); ++i) {
      int fd = perf_open(id);
      if (fd >= 0) {
        if (ioctl(fd, PERF_EVENT_IOC_SET_FILTER, filters[i]) == 0) {
          mask |= 1U << i;
        }
        close(fd);
      }
    }
    if (mask) {
      printf("TRACE_FILTER id=%u mask=0x%x\n", id, mask);
    }
  }
}

static uint64_t read_count(int fd) {
  uint64_t value = 0;
  return read(fd, &value, sizeof(value)) == sizeof(value) ? value : 0;
}

static void set_enabled(int *fds, int enabled) {
  for (unsigned id = 1; id <= MAX_ID; ++id) {
    if (fds[id] >= 0) {
      ioctl(fds[id], enabled ? PERF_EVENT_IOC_ENABLE : PERF_EVENT_IOC_DISABLE,
            0);
    }
  }
}

static void report(const char *phase, int *fds, uint64_t *before) {
  for (unsigned id = 1; id <= MAX_ID; ++id) {
    if (fds[id] < 0) {
      continue;
    }
    uint64_t after = read_count(fds[id]);
    if (after != before[id]) {
      printf("TRACE_DELTA phase=%s id=%u delta=%llu\n", phase, id,
             (unsigned long long)(after - before[id]));
    }
    before[id] = after;
  }
}

int main(void) {
  int *fds = malloc((MAX_ID + 1) * sizeof(*fds));
  uint64_t *counts = calloc(MAX_ID + 1, sizeof(*counts));
  char *data = malloc(SEND_SIZE);
  if (!fds || !counts || !data) {
    return 1;
  }
  memset(data, 'A', SEND_SIZE);
  unsigned opened = 0;
  for (unsigned id = 0; id <= MAX_ID; ++id) {
    fds[id] = -1;
  }
  for (unsigned id = 1; id <= MAX_ID; ++id) {
    fds[id] = perf_open(id);
    if (fds[id] >= 0) {
      opened++;
      counts[id] = read_count(fds[id]);
    }
  }
  printf("TRACE_PROBE opened=%u max_id=%u send_size=%u\n", opened, MAX_ID,
         SEND_SIZE);
  probe_filters();

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    return 1;
  }
  int sndbuf = 73088;
  setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  set_enabled(fds, 1);
  ssize_t sent = send(sv[0], data, SEND_SIZE, 0);
  set_enabled(fds, 0);
  printf("TRACE_ACTION send=%zd errno=%d\n", sent, errno);
  report("alloc", fds, counts);

  set_enabled(fds, 1);
  close(sv[0]);
  close(sv[1]);
  usleep(100000);
  set_enabled(fds, 0);
  report("free", fds, counts);

  for (unsigned id = 1; id <= MAX_ID; ++id) {
    if (fds[id] >= 0) close(fds[id]);
  }
  free(data);
  free(counts);
  free(fds);
  return 0;
}
