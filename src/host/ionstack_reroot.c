// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#ifndef PATH_MAX
#define PATH_MAX 32768
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#define open _open
#define close _close
#define read _read
#define write _write
#define getcwd _getcwd
#else
#include <libgen.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define REMOTE_DEVICE_RUNNER "/data/local/tmp/ionstack_reroot_device"
#define REMOTE_TARGET        "/data/local/tmp/ionstack_perf_target"
#define REMOTE_PRELOAD       "/data/local/tmp/ionstack_preload.so"
#define REMOTE_PROBE         "/data/local/tmp/cve43499_chainwalk_probe_arm32"
#define REMOTE_SU            "/data/local/tmp/su"

struct options {
  const char *serial;
  const char *repo_root;
  const char *result_dir;
  const char *device_runner;
  const char *target;
  const char *preload;
  const char *probe;
  int force;
  int no_deploy;
  int preflight_only;
  int validate_only;
};

struct run_result {
  int exit_code;
  int timed_out;
  char *output;
  size_t output_len;
};

static volatile sig_atomic_t interrupted;
#ifdef _WIN32
static HANDLE active_job;
#else
static volatile sig_atomic_t active_child = -1;
#endif

static void on_signal(int signo) {
  interrupted = signo;
#ifdef _WIN32
  if (active_job) {
    TerminateJobObject(active_job, 128U + (UINT)signo);
  }
#else
  pid_t child = (pid_t)active_child;
  if (child > 0) {
    kill(-child, signo);
  }
#endif
}

static uint64_t monotonic_ms(void) {
#ifdef _WIN32
  return (uint64_t)GetTickCount64();
#else
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
#endif
}

#ifdef _WIN32
static int write_all(int fd, const void *data, size_t length);

static int dprintf(int fd, const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  va_list measure;
  va_copy(measure, ap);
  int length = vsnprintf(NULL, 0, format, measure);
  va_end(measure);
  if (length < 0) {
    va_end(ap);
    return -1;
  }
  char *buffer = malloc((size_t)length + 1U);
  if (!buffer) {
    va_end(ap);
    return -1;
  }
  vsnprintf(buffer, (size_t)length + 1U, format, ap);
  va_end(ap);
  int result = write_all(fd, buffer, (size_t)length) == 0 ? length : -1;
  free(buffer);
  return result;
}

static int make_directory(const char *path, mode_t mode) {
  (void)mode;
  return _mkdir(path);
}
#else
static int make_directory(const char *path, mode_t mode) {
  return mkdir(path, mode);
}
#endif

static int mkdir_p(const char *path, mode_t mode) {
  char copy[PATH_MAX];
  if (strlen(path) >= sizeof(copy)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(copy, path);
  size_t len = strlen(copy);
  while (len > 1 && copy[len - 1] == '/') {
    copy[--len] = '\0';
  }
  for (char *p = copy + 1; *p; ++p) {
    if (*p != '/' && *p != '\\') {
      continue;
    }
    if (p == copy + 2 && copy[1] == ':') {
      continue;
    }
    char separator = *p;
    *p = '\0';
    if (make_directory(copy, mode) != 0 && errno != EEXIST) {
      return -1;
    }
    *p = separator;
  }
  if (make_directory(copy, mode) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int append_bytes(char **buffer, size_t *used, size_t *capacity,
                        const void *data, size_t length) {
  if (!buffer) {
    return 0;
  }
  if (*used + length + 1 > *capacity) {
    size_t next = *capacity ? *capacity : 4096;
    while (next < *used + length + 1) {
      if (next > SIZE_MAX / 2) {
        errno = ENOMEM;
        return -1;
      }
      next *= 2;
    }
    char *grown = realloc(*buffer, next);
    if (!grown) {
      return -1;
    }
    *buffer = grown;
    *capacity = next;
  }
  memcpy(*buffer + *used, data, length);
  *used += length;
  (*buffer)[*used] = '\0';
  return 0;
}

static int write_all(int fd, const void *data, size_t length) {
  const unsigned char *cursor = data;
  while (length > 0) {
    ssize_t wrote = write(fd, cursor, length);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      return -1;
    }
    cursor += wrote;
    length -= (size_t)wrote;
  }
  return 0;
}

#ifdef _WIN32
static int append_command_arg(char *command, size_t capacity, size_t *used,
                              const char *arg) {
  int quote = !*arg || strpbrk(arg, " \t\"") != NULL;
  size_t needed = (*used ? 1U : 0U) + (quote ? 2U : 0U) + strlen(arg) * 2U + 1U;
  if (*used + needed > capacity) {
    errno = E2BIG;
    return -1;
  }
  if (*used) {
    command[(*used)++] = ' ';
  }
  if (quote) {
    command[(*used)++] = '"';
  }
  size_t slashes = 0;
  for (const char *p = arg;; ++p) {
    if (*p == '\\') {
      slashes++;
      continue;
    }
    if (*p == '"') {
      for (size_t i = 0; i < slashes * 2U + 1U; ++i) {
        command[(*used)++] = '\\';
      }
      command[(*used)++] = '"';
    } else {
      if (!*p && quote) {
        slashes *= 2U;
      }
      for (size_t i = 0; i < slashes; ++i) {
        command[(*used)++] = '\\';
      }
      if (!*p) {
        break;
      }
      command[(*used)++] = *p;
    }
    slashes = 0;
  }
  if (quote) {
    command[(*used)++] = '"';
  }
  command[*used] = '\0';
  return 0;
}

static struct run_result run_process(char *const argv[], int log_fd,
                                     unsigned timeout_ms, int echo) {
  struct run_result result;
  memset(&result, 0, sizeof(result));
  result.exit_code = -1;

  char command[32768];
  size_t command_len = 0;
  command[0] = '\0';
  for (size_t i = 0; argv[i]; ++i) {
    if (append_command_arg(command, sizeof(command), &command_len,
                           argv[i]) != 0) {
      return result;
    }
  }

  SECURITY_ATTRIBUTES security = {
      .nLength = sizeof(security), .lpSecurityDescriptor = NULL,
      .bInheritHandle = TRUE};
  HANDLE pipe_read = NULL;
  HANDLE pipe_write = NULL;
  if (!CreatePipe(&pipe_read, &pipe_write, &security, 0)) {
    return result;
  }
  SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOA startup;
  PROCESS_INFORMATION process;
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = pipe_write;
  startup.hStdError = pipe_write;

  HANDLE job = CreateJobObjectA(NULL, NULL);
  if (job) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                            sizeof(limits));
  }
  BOOL created = CreateProcessA(NULL, command, NULL, NULL, TRUE,
                                CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                                NULL, NULL, &startup, &process);
  CloseHandle(pipe_write);
  pipe_write = NULL;
  if (!created) {
    CloseHandle(pipe_read);
    if (job) {
      CloseHandle(job);
    }
    return result;
  }
  if (job) {
    AssignProcessToJobObject(job, process.hProcess);
  }
  active_job = job;

  char *output = NULL;
  size_t output_len = 0;
  size_t output_capacity = 0;
  uint64_t deadline = monotonic_ms() + timeout_ms;
  int exited = 0;
  for (;;) {
    DWORD available = 0;
    while (PeekNamedPipe(pipe_read, NULL, 0, NULL, &available, NULL) &&
           available > 0) {
      char chunk[8192];
      DWORD want = available < sizeof(chunk) ? available : sizeof(chunk);
      DWORD got = 0;
      if (!ReadFile(pipe_read, chunk, want, &got, NULL) || got == 0) {
        break;
      }
      if (echo) {
        write_all(STDOUT_FILENO, chunk, (size_t)got);
      }
      if (log_fd >= 0) {
        write_all(log_fd, chunk, (size_t)got);
      }
      append_bytes(&output, &output_len, &output_capacity, chunk,
                   (size_t)got);
      available -= got;
    }
    DWORD wait = WaitForSingleObject(process.hProcess, 20);
    if (wait == WAIT_OBJECT_0) {
      exited = 1;
      if (!PeekNamedPipe(pipe_read, NULL, 0, NULL, &available, NULL) ||
          available == 0) {
        break;
      }
    }
    if (interrupted ||
        (timeout_ms > 0 && monotonic_ms() >= deadline)) {
      result.timed_out = !interrupted;
      if (job) {
        TerminateJobObject(job, interrupted ? 128U + interrupted : 124U);
      } else {
        TerminateProcess(process.hProcess,
                         interrupted ? 128U + interrupted : 124U);
      }
      WaitForSingleObject(process.hProcess, 3000);
      exited = 1;
    }
    if (exited && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
      continue;
    }
  }

  DWORD exit_code = 255;
  GetExitCodeProcess(process.hProcess, &exit_code);
  result.exit_code = (int)exit_code;
  result.output = output ? output : calloc(1, 1);
  result.output_len = output_len;
  active_job = NULL;
  CloseHandle(pipe_read);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  if (job) {
    CloseHandle(job);
  }
  return result;
}
#else
static struct run_result run_process(char *const argv[], int log_fd,
                                     unsigned timeout_ms, int echo) {
  struct run_result result;
  memset(&result, 0, sizeof(result));
  result.exit_code = -1;

  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    return result;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return result;
  }
  if (pid == 0) {
    setpgid(0, 0);
    dup2(pipe_fds[1], STDOUT_FILENO);
    dup2(pipe_fds[1], STDERR_FILENO);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    execvp(argv[0], argv);
    dprintf(STDERR_FILENO, "exec %s failed: %s\n", argv[0], strerror(errno));
    _exit(127);
  }
  close(pipe_fds[1]);
  setpgid(pid, pid);
  active_child = pid;
  int flags = fcntl(pipe_fds[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
  }

  char *output = NULL;
  size_t output_len = 0;
  size_t output_capacity = 0;
  uint64_t deadline = monotonic_ms() + timeout_ms;
  int exited = 0;
  int status = 0;
  int eof = 0;
  while (!interrupted && (!exited || !eof)) {
    uint64_t now = monotonic_ms();
    if (timeout_ms > 0 && now >= deadline) {
      result.timed_out = 1;
      kill(-pid, SIGTERM);
      break;
    }
    struct pollfd pfd = {.fd = pipe_fds[0], .events = POLLIN | POLLHUP};
    poll(&pfd, 1, 200);
    for (;;) {
      char chunk[8192];
      ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
      if (got > 0) {
        if (echo) {
          write_all(STDOUT_FILENO, chunk, (size_t)got);
        }
        if (log_fd >= 0) {
          write_all(log_fd, chunk, (size_t)got);
        }
        append_bytes(&output, &output_len, &output_capacity, chunk,
                     (size_t)got);
        continue;
      }
      if (got == 0) {
        eof = 1;
      }
      break;
    }
    if (!exited) {
      pid_t got = waitpid(pid, &status, WNOHANG);
      if (got == pid) {
        exited = 1;
      }
    }
  }

  if (!exited) {
    uint64_t grace = monotonic_ms() + 3000U;
    while (monotonic_ms() < grace) {
      pid_t got = waitpid(pid, &status, WNOHANG);
      if (got == pid) {
        exited = 1;
        break;
      }
      usleep(25000);
    }
    if (!exited) {
      kill(-pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      exited = 1;
    }
  }
  for (;;) {
    char chunk[8192];
    ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
    if (got <= 0) {
      break;
    }
    if (echo) {
      write_all(STDOUT_FILENO, chunk, (size_t)got);
    }
    if (log_fd >= 0) {
      write_all(log_fd, chunk, (size_t)got);
    }
    append_bytes(&output, &output_len, &output_capacity, chunk, (size_t)got);
  }
  close(pipe_fds[0]);
  active_child = -1;

  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    result.exit_code = 128 + WTERMSIG(status);
  } else {
    result.exit_code = 255;
  }
  if (!output) {
    output = calloc(1, 1);
  }
  result.output = output;
  result.output_len = output_len;
  return result;
}
#endif

static void free_run_result(struct run_result *result) {
  free(result->output);
  result->output = NULL;
  result->output_len = 0;
}

static struct run_result run_adb(const struct options *options, int log_fd,
                                 unsigned timeout_ms, int echo,
                                 const char *first, ...) {
  char *argv[32];
  size_t used = 0;
  argv[used++] = "adb";
  if (options->serial && *options->serial) {
    argv[used++] = "-s";
    argv[used++] = (char *)options->serial;
  }
  va_list ap;
  va_start(ap, first);
  const char *item = first;
  while (item && used + 1 < sizeof(argv) / sizeof(argv[0])) {
    argv[used++] = (char *)item;
    item = va_arg(ap, const char *);
  }
  va_end(ap);
  argv[used] = NULL;
  return run_process(argv, log_fd, timeout_ms, echo);
}

static int file_is_regular(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int join_path(char *output, size_t size, const char *root,
                     const char *relative) {
  int wrote = snprintf(output, size, "%s/%s", root, relative);
  return wrote >= 0 && (size_t)wrote < size ? 0 : -1;
}

static char *resolve_path(const char *input, char *output, size_t size) {
#ifdef _WIN32
  DWORD length = GetFullPathNameA(input, (DWORD)size, output, NULL);
  if (length == 0 || length >= size) {
    errno = ENAMETOOLONG;
    return NULL;
  }
  return output;
#else
  (void)size;
  return realpath(input, output);
#endif
}

static int derive_repo_root(const char *argv0, char *output, size_t size) {
  char executable[PATH_MAX];
#ifdef _WIN32
  (void)argv0;
  DWORD length = GetModuleFileNameA(NULL, executable, sizeof(executable));
  if (length == 0 || length >= sizeof(executable)) {
    return -1;
  }
#else
  if (!realpath(argv0, executable)) {
    return -1;
  }
#endif
  char *slash = strrchr(executable, '\\');
  char *forward = strrchr(executable, '/');
  if (!slash || (forward && forward > slash)) {
    slash = forward;
  }
  if (!slash) {
    return -1;
  }
  *slash = '\0';

  char packaged_artifact[PATH_MAX];
  if (join_path(packaged_artifact, sizeof(packaged_artifact), executable,
                "build/ionstack_reroot_device") == 0 &&
      file_is_regular(packaged_artifact)) {
    return resolve_path(executable, output, size) ? 0 : -1;
  }

  char candidate[PATH_MAX];
  if (snprintf(candidate, sizeof(candidate), "%s/..", executable) >=
      (int)sizeof(candidate)) {
    return -1;
  }
  return resolve_path(candidate, output, size) ? 0 : -1;
}

static void make_default_result_dir(char *output, size_t size) {
  time_t now = time(NULL);
  struct tm local;
#ifdef _WIN32
  localtime_s(&local, &now);
#else
  localtime_r(&now, &local);
#endif
  strftime(output, size,
           "results/%Y-%m-%d/reroot_%Y%m%d_%H%M%S", &local);
}

static void usage(const char *program) {
  fprintf(stderr,
          "usage: %s [-s SERIAL] [--repo-root=DIR] [--result-dir=DIR] "
          "[--force] [--preflight-only|--validate-only] [--no-deploy]\n"
          "       optional artifact overrides: --device-runner=FILE "
          "--target=FILE --preload=FILE --probe=FILE\n",
          program);
}

static int parse_options(int argc, char **argv, struct options *options) {
  memset(options, 0, sizeof(*options));
  options->serial = getenv("ANDROID_SERIAL");
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      options->serial = argv[++i];
    } else if (strncmp(argv[i], "--serial=", 9) == 0) {
      options->serial = argv[i] + 9;
    } else if (strncmp(argv[i], "--repo-root=", 12) == 0) {
      options->repo_root = argv[i] + 12;
    } else if (strncmp(argv[i], "--result-dir=", 13) == 0) {
      options->result_dir = argv[i] + 13;
    } else if (strncmp(argv[i], "--device-runner=", 16) == 0) {
      options->device_runner = argv[i] + 16;
    } else if (strncmp(argv[i], "--target=", 9) == 0) {
      options->target = argv[i] + 9;
    } else if (strncmp(argv[i], "--preload=", 10) == 0) {
      options->preload = argv[i] + 10;
    } else if (strncmp(argv[i], "--probe=", 8) == 0) {
      options->probe = argv[i] + 8;
    } else if (strcmp(argv[i], "--force") == 0) {
      options->force = 1;
    } else if (strcmp(argv[i], "--no-deploy") == 0) {
      options->no_deploy = 1;
    } else if (strcmp(argv[i], "--preflight-only") == 0) {
      options->preflight_only = 1;
    } else if (strcmp(argv[i], "--validate-only") == 0) {
      options->validate_only = 1;
    } else if (strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      exit(0);
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return -1;
    }
  }
  if (options->preflight_only && options->validate_only) {
    fprintf(stderr, "--preflight-only and --validate-only are mutually exclusive\n");
    return -1;
  }
  if (options->force && (options->preflight_only || options->validate_only)) {
    fprintf(stderr, "--force cannot be combined with diagnostic-only modes\n");
    return -1;
  }
  return 0;
}

static int remote_root_check(const struct options *options, int log_fd,
                             char **output_out) {
  struct run_result check =
      run_adb(options, log_fd, 10000, 0, "shell", REMOTE_SU, "-c", "id",
              NULL);
  int ok = check.exit_code == 0 && check.output &&
           strstr(check.output, "uid=0(root)");
  if (output_out) {
    *output_out = check.output;
    check.output = NULL;
  }
  free_run_result(&check);
  return ok;
}

static int push_artifact(const struct options *options, int log_fd,
                         const char *local, const char *remote) {
  printf("[host] push %s -> %s\n", local, remote);
  dprintf(log_fd, "[host] push %s -> %s\n", local, remote);
  struct run_result push =
      run_adb(options, log_fd, 120000, 1, "push", local, remote, NULL);
  int ok = push.exit_code == 0 && !push.timed_out;
  free_run_result(&push);
  return ok ? 0 : -1;
}

int main(int argc, char **argv) {
  struct options options;
  if (parse_options(argc, argv, &options) != 0) {
    usage(argv[0]);
    return 2;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
#ifndef _WIN32
  signal(SIGHUP, on_signal);
#endif

  char repo_root[PATH_MAX];
  if (options.repo_root) {
    if (!resolve_path(options.repo_root, repo_root, sizeof(repo_root))) {
      perror("realpath repo root");
      return 2;
    }
  } else if (derive_repo_root(argv[0], repo_root, sizeof(repo_root)) != 0) {
    if (!getcwd(repo_root, sizeof(repo_root))) {
      perror("getcwd");
      return 2;
    }
  }

  char result_dir[PATH_MAX];
  if (options.result_dir) {
    if (strlen(options.result_dir) >= sizeof(result_dir)) {
      fprintf(stderr, "result directory too long\n");
      return 2;
    }
    strcpy(result_dir, options.result_dir);
  } else {
    char relative[PATH_MAX];
    make_default_result_dir(relative, sizeof(relative));
    if (join_path(result_dir, sizeof(result_dir), repo_root, relative) != 0) {
      fprintf(stderr, "result directory too long\n");
      return 2;
    }
  }
  if (mkdir_p(result_dir, 0755) != 0) {
    perror("mkdir result dir");
    return 2;
  }
  char log_path[PATH_MAX];
  snprintf(log_path, sizeof(log_path), "%s/reroot.log", result_dir);
  int log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (log_fd < 0) {
    perror("open log");
    return 2;
  }

  char default_device_runner[PATH_MAX];
  char default_target[PATH_MAX];
  char default_preload[PATH_MAX];
  char default_probe[PATH_MAX];
  join_path(default_device_runner, sizeof(default_device_runner), repo_root,
            "build/ionstack_reroot_device");
  join_path(default_target, sizeof(default_target), repo_root,
            "build/ionstack_perf_target");
  join_path(default_preload, sizeof(default_preload), repo_root,
            "build/ionstack_preload.so");
  join_path(default_probe, sizeof(default_probe), repo_root,
            "build/cve_2026_43499_chainwalk_probe_arm32");
  const char *device_runner =
      options.device_runner ? options.device_runner : default_device_runner;
  const char *target = options.target ? options.target : default_target;
  const char *preload = options.preload ? options.preload : default_preload;
  const char *probe = options.probe ? options.probe : default_probe;

  printf("[host] xpad2-ionstack-poc pure-C one-click re-root\n");
  printf("[host] result_dir=%s\n", result_dir);
  dprintf(log_fd, "[host] repo_root=%s\n[host] result_dir=%s\n", repo_root,
          result_dir);

  struct run_result state =
      run_adb(&options, log_fd, 10000, 1, "get-state", NULL);
  if (state.exit_code != 0 || !state.output || !strstr(state.output, "device")) {
    fprintf(stderr, "[host] adb device is not ready\n");
    free_run_result(&state);
    close(log_fd);
    return 1;
  }
  free_run_result(&state);

  struct run_result boot_before = run_adb(
      &options, log_fd, 10000, 0, "shell",
      "cat /proc/sys/kernel/random/boot_id", NULL);
  printf("[host] boot_id=%s", boot_before.output ? boot_before.output : "?\n");

  char *existing_output = NULL;
  if (!options.force && !options.preflight_only && !options.validate_only &&
      remote_root_check(&options, log_fd, &existing_output)) {
    printf("[host] already rooted: %s", existing_output);
    printf("[host] SUCCESS already_root=1 log=%s\n", log_path);
    dprintf(log_fd, "[host] SUCCESS already_root=1\n");
    free(existing_output);
    free_run_result(&boot_before);
    close(log_fd);
    return 0;
  }
  free(existing_output);

  if (!options.no_deploy) {
    const char *locals[] = {device_runner, target, preload, probe};
    const char *remotes[] = {REMOTE_DEVICE_RUNNER, REMOTE_TARGET,
                             REMOTE_PRELOAD, REMOTE_PROBE};
    for (size_t i = 0; i < sizeof(locals) / sizeof(locals[0]); ++i) {
      if (!file_is_regular(locals[i])) {
        fprintf(stderr, "[host] missing local artifact: %s\n", locals[i]);
        free_run_result(&boot_before);
        close(log_fd);
        return 1;
      }
      if (push_artifact(&options, log_fd, locals[i], remotes[i]) != 0) {
        fprintf(stderr, "[host] push failed: %s\n", locals[i]);
        free_run_result(&boot_before);
        close(log_fd);
        return 1;
      }
    }
    struct run_result chmod_result = run_adb(
        &options, log_fd, 10000, 1, "shell", "chmod", "755",
        REMOTE_DEVICE_RUNNER, REMOTE_TARGET, REMOTE_PROBE, NULL);
    if (chmod_result.exit_code != 0) {
      fprintf(stderr, "[host] remote chmod failed\n");
      free_run_result(&chmod_result);
      free_run_result(&boot_before);
      close(log_fd);
      return 1;
    }
    free_run_result(&chmod_result);
  }

  printf("[host] starting device orchestrator\n");
  dprintf(log_fd, "[host] starting device orchestrator\n");
  struct run_result reroot;
  if (options.preflight_only) {
    reroot = run_adb(&options, log_fd, 120000, 1, "shell",
                     REMOTE_DEVICE_RUNNER, "--preflight-only", NULL);
  } else if (options.validate_only) {
    reroot = run_adb(&options, log_fd, 1200000, 1, "shell",
                     REMOTE_DEVICE_RUNNER, "--validate-only", NULL);
  } else if (options.force) {
    reroot = run_adb(&options, log_fd, 1200000, 1, "shell",
                     REMOTE_DEVICE_RUNNER, "--force", NULL);
  } else {
    reroot = run_adb(&options, log_fd, 1200000, 1, "shell",
                     REMOTE_DEVICE_RUNNER, NULL);
  }

  struct run_result boot_after = run_adb(
      &options, log_fd, 10000, 0, "shell",
      "cat /proc/sys/kernel/random/boot_id", NULL);
  int same_boot = boot_before.output && boot_after.output &&
                  strcmp(boot_before.output, boot_after.output) == 0;
  char *verify_output = NULL;
  int root_ok = 0;
  const char *expected_marker = "[reroot] SUCCESS";
  if (options.preflight_only) {
    expected_marker = "[reroot] PREFLIGHT_OK";
  } else if (options.validate_only) {
    expected_marker = "[reroot] VALIDATION_OK";
  } else {
    root_ok = remote_root_check(&options, log_fd, &verify_output);
  }
  int marker_ok = reroot.output && strstr(reroot.output, expected_marker);

  printf("[host] device_rc=%d timed_out=%d same_boot=%d\n", reroot.exit_code,
         reroot.timed_out, same_boot);
  if (verify_output && *verify_output) {
    printf("[host] verify: %s", verify_output);
  }
  int root_requirement_ok =
      options.preflight_only || options.validate_only || root_ok;
  int success = reroot.exit_code == 0 && !reroot.timed_out && marker_ok &&
                root_requirement_ok && same_boot;
  printf("[host] %s log=%s\n", success ? "SUCCESS" : "FAIL", log_path);
  dprintf(log_fd,
          "[host] final success=%d device_rc=%d timed_out=%d marker=%d "
          "root=%d same_boot=%d\n",
          success, reroot.exit_code, reroot.timed_out, marker_ok, root_ok,
          same_boot);

  free(verify_output);
  free_run_result(&state);
  free_run_result(&boot_before);
  free_run_result(&boot_after);
  free_run_result(&reroot);
  close(log_fd);
  if (interrupted) {
    return 128 + interrupted;
  }
  return success ? 0 : 1;
}
