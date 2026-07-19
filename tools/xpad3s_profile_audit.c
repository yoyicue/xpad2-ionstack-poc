// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/exploit/profiles/xpad3s_layout.h"
#include "../src/exploit/profiles/xpad3s_symbols.h"

#define STATIC_ASSERT_EQ(a, b) _Static_assert((a) == (b), #a " != " #b)

STATIC_ASSERT_EQ(XPAD3S_PAGE_SHIFT, 12);
STATIC_ASSERT_EQ(XPAD3S_STRUCT_PAGE_SIZE, 0x40);
STATIC_ASSERT_EQ(XPAD3S_ARCH_VMEMMAP_START, 0xfffffffeffe00000ULL);
STATIC_ASSERT_EQ(XPAD3S_VMEMMAP_PFN0_BASE, 0xfffffffefee00000ULL);
STATIC_ASSERT_EQ(XPAD3S_ARCH_VMEMMAP_END, 0xffffffffffe00000ULL);
STATIC_ASSERT_EQ(XPAD3S_IMAGE_TEXT_OFFSET, 0);
STATIC_ASSERT_EQ(XPAD3S_IMAGE_SIZE, 0x02a80000);
STATIC_ASSERT_EQ(XPAD3S_KERNEL_PHYS_LOAD, XPAD3S_PHYS_OFFSET);
STATIC_ASSERT_EQ(XPAD3S_HAVE_KERNEL_PHYS_LOAD, 1);
STATIC_ASSERT_EQ(XPAD3S_WAITER_SIZE, 0x50);
STATIC_ASSERT_EQ(XPAD3S_WAITER_TASK_OFF, 0x30);
STATIC_ASSERT_EQ(XPAD3S_TASK_CRED_OFF, 0x780);
STATIC_ASSERT_EQ(XPAD3S_TASK_TGID_OFF, XPAD3S_TASK_PID_OFF + 4);
STATIC_ASSERT_EQ(XPAD3S_TASK_GROUP_LEADER_OFF, 0x608);
STATIC_ASSERT_EQ(XPAD3S_TASK_THREAD_GROUP_OFF, 0x678);
STATIC_ASSERT_EQ(XPAD3S_TASK_PI_BLOCKED_ON_OFF, 0x898);
STATIC_ASSERT_EQ(XPAD3S_PIPE_BUFFER_SIZE, 0x28);
STATIC_ASSERT_EQ(XPAD3S_CFG_NEEDS_READ_FILL_OFF, 0x50);
STATIC_ASSERT_EQ(XPAD3S_CFG_BIN_BUFFER_OFF, 0x58);
STATIC_ASSERT_EQ(XPAD3S_CFG_BIN_BUFFER_SIZE_OFF, 0x60);
STATIC_ASSERT_EQ(XPAD3S_CFG_CB_MAX_SIZE_OFF, 0x64);
STATIC_ASSERT_EQ(XPAD3S_CFG_BIN_BUFFER_ALIGN, 0x01000000ULL);
STATIC_ASSERT_EQ(XPAD3S_CFG_BIN_BUFFER_WINDOW_SIZE, 0x02020202U);
STATIC_ASSERT_EQ(XPAD3S_USERCOPY_FALLBACK_OFF, 0x022e7418ULL);
STATIC_ASSERT_EQ(XPAD3S_CONFIGFS_WRITE_BIN_FILE_OFF, 0x00684988ULL);
STATIC_ASSERT_EQ(XPAD3S_CONFIGFS_WRITE_BIN_FILE_CFI_JT_OFF, 0x0182f830ULL);
STATIC_ASSERT_EQ(XPAD3S_ALLOCATE_SLAB_OFF, 0x004e0e54ULL);
STATIC_ASSERT_EQ(XPAD3S_KMEM_CACHE_ALLOC_OFF, 0x004e1f6cULL);
STATIC_ASSERT_EQ(XPAD3S_ASHMEM_OPEN_OFF, 0x0118a59cULL);
STATIC_ASSERT_EQ(XPAD3S_SIMPLE_ATTR_READ_CFI_JT_OFF, 0x0182f250ULL);
STATIC_ASSERT_EQ(XPAD3S_DEBUGFS_U64_GET_CFI_JT_OFF, 0x0182bb38ULL);
STATIC_ASSERT_EQ(XPAD3S_KMEM_CACHE_SIZE_OFF, 0x18);
STATIC_ASSERT_EQ(XPAD3S_KMEM_CACHE_USEROFFSET_OFF, 0xf4);
STATIC_ASSERT_EQ(XPAD3S_KMEM_CACHE_USERSIZE_OFF, 0xf8);
STATIC_ASSERT_EQ(XPAD3S_PAGE_FLAGS_OFF, 0x00);
STATIC_ASSERT_EQ(XPAD3S_PAGE_FLAG_SLAB_BIT, 9);
STATIC_ASSERT_EQ(XPAD3S_ASHMEM_AREA_SLAB_ORDER, 1);
STATIC_ASSERT_EQ(XPAD3S_CRED_SLAB_STRIDE, 0xc0);
_Static_assert(XPAD3S_FAKE_KMEM_CACHE_OFF + 0x100 <=
                   XPAD3S_FAKE_READ_FMT_OFF,
               "fake kmem_cache overlaps read format");
STATIC_ASSERT_EQ(XPAD3S_SELINUX_STATE_ENFORCING_OFF, 0);
STATIC_ASSERT_EQ(XPAD3S_MISCDEVICE_FOPS_OFF, 0x10);
STATIC_ASSERT_EQ(XPAD3S_FOPS_IOCTL_OFF, 0x50);
STATIC_ASSERT_EQ(XPAD3S_FOPS_COMPAT_IOCTL_OFF, 0x58);
STATIC_ASSERT_EQ(XPAD3S_FOPS_MMAP_OFF, 0x60);
STATIC_ASSERT_EQ(XPAD3S_FOPS_OPEN_OFF, 0x70);
STATIC_ASSERT_EQ(XPAD3S_FOPS_RELEASE_OFF, 0x80);
STATIC_ASSERT_EQ(XPAD3S_FOPS_SPLICE_READ_OFF, 0xc8);
STATIC_ASSERT_EQ(XPAD3S_FOPS_SHOW_FDINFO_OFF, 0xe0);

static int canonical_kernel_pointer(uint64_t value) {
  return (value >> 40) == UINT64_C(0xffffff) &&
         value < UINT64_C(0xfffffffffffff001);
}

static uint64_t parse_u64(const char *text) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 0);
  if (errno || !end || *end) {
    fprintf(stderr, "invalid address: %s\n", text);
    exit(2);
  }
  return (uint64_t)value;
}

int main(int argc, char **argv) {
  uint64_t runtime_base = XPAD3S_KIMAGE_TEXT_BASE;
  if (argc == 2) {
    runtime_base = parse_u64(argv[1]);
  } else if (argc != 1) {
    fprintf(stderr, "usage: %s [runtime-kimage-base]\n", argv[0]);
    return 2;
  }

  if (!canonical_kernel_pointer(runtime_base) ||
      (runtime_base & UINT64_C(0x1fffff)) != 0) {
    fprintf(stderr, "PROFILE_AUDIT_FAIL invalid runtime base 0x%016" PRIx64
                    "\n", runtime_base);
    return 1;
  }

  uint64_t slide = runtime_base - XPAD3S_KIMAGE_TEXT_BASE;
  uint64_t first_phys_page = XPAD3S_PHYS_OFFSET >> XPAD3S_PAGE_SHIFT;
  uint64_t first_page = XPAD3S_VMEMMAP_PFN0_BASE +
                        first_phys_page * XPAD3S_STRUCT_PAGE_SIZE;
  uint64_t init_task = runtime_base + XPAD3S_INIT_TASK_OFF;
  uint64_t kmalloc_caches = runtime_base + XPAD3S_KMALLOC_CACHES_OFF;
  uint64_t selinux_state = runtime_base + XPAD3S_SELINUX_STATE_OFF;
  uint64_t selinux_enforcing = selinux_state +
                              XPAD3S_SELINUX_STATE_ENFORCING_OFF;
  uint64_t init_task_direct = XPAD3S_PAGE_OFFSET +
                              (XPAD3S_KERNEL_PHYS_LOAD - XPAD3S_PHYS_OFFSET) +
                              XPAD3S_INIT_TASK_OFF;

  if (first_phys_page != XPAD3S_PHYS_PFN_OFFSET ||
      first_page != XPAD3S_ARCH_VMEMMAP_START ||
      !canonical_kernel_pointer(init_task) ||
      !canonical_kernel_pointer(init_task_direct) ||
      !canonical_kernel_pointer(kmalloc_caches) ||
      !canonical_kernel_pointer(selinux_state)) {
    fprintf(stderr, "PROFILE_AUDIT_FAIL geometry or symbol range\n");
    return 1;
  }

  printf("PROFILE_AUDIT_OK base=0x%016" PRIx64 " slide=0x%016" PRIx64
         " phys_pfn=0x%" PRIx64 " vmemmap_first=0x%016" PRIx64 "\n",
         runtime_base, slide, first_phys_page, first_page);
  printf("PROFILE_SYMBOLS init_task=0x%016" PRIx64
         " kmalloc_caches=0x%016" PRIx64
         " selinux_state=0x%016" PRIx64
         " enforcing=0x%016" PRIx64 "\n",
         init_task, kmalloc_caches, selinux_state, selinux_enforcing);
  printf("PROFILE_LAYOUT task_cred=0x%x task_pi_lock=0x%x"
         " task_pi_blocked_on=0x%x page_slab_cache=0x%x"
         " fops_ioctl=0x%x fops_open=0x%x fops_release=0x%x\n",
         XPAD3S_TASK_CRED_OFF, XPAD3S_TASK_PI_LOCK_OFF,
         XPAD3S_TASK_PI_BLOCKED_ON_OFF, XPAD3S_PAGE_SLAB_CACHE_OFF,
         XPAD3S_FOPS_IOCTL_OFF, XPAD3S_FOPS_OPEN_OFF,
         XPAD3S_FOPS_RELEASE_OFF);
  printf("PROFILE_GATE kernel_phys_load=%s image_size=0x%llx\n",
         XPAD3S_HAVE_KERNEL_PHYS_LOAD ? "validated" : "unvalidated",
         (unsigned long long)XPAD3S_IMAGE_SIZE);
  printf("PROFILE_ALIAS init_task_direct=0x%016" PRIx64 "\n",
         init_task_direct);
  return 0;
}
