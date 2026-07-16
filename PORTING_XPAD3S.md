# Xpad3S experimental port

Status snapshot: 2026-07-16

This work belongs on `experimental/xpad3s`. The verified Xpad2 release remains
the default `PROFILE=xpad2` build on `main`.

| Milestone | Status |
| --- | --- |
| Exact kernel/profile recovery | Passed |
| Xpad3S preflight and profile audit | Passed |
| KASLR and credential sampling | Passed |
| Order-3/PFN/content holder validation | Passed on the physical unit |
| targetSdk 27 compat32 `/dev/ashmem` trigger | Installed and smoke-tested |
| Dynamic check-and-restore chain validation | Not passed |
| Verified `su -c id` root | Not reached |
| Full-run gate | Closed (`IONSTACK_PROFILE_CHAIN_VALIDATED=0`) |

The current APK contains a second, final `pselect6` stack repair. It was built
and installed, but its first test was interrupted by an external device
shutdown during holder preparation, before `HOLDER_OK` or application launch.
It therefore remains unverified; that shutdown is not evidence of a kernel
panic or of chain success.

## Target profile

```text
device:      TALIH-PD3S
Android:     13 / SDK 33
fingerprint: alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/338:user/release-keys
OTA profile: alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/371:user/release-keys
kernel:      5.10.198-android12-9-00019-g6efebf1322d6-ab11471183
version:     #1 SMP PREEMPT Mon Feb 19 21:20:42 UTC 2024
```

The physical V260423 device and V260629 OTA `boot.img` contain the same GKI
kernel build. Static kallsyms recovery from the OTA produced
`src/exploit/profiles/xpad3s_symbols.h`. The matching AOSP commit is
`6efebf1322d6e6bedae2eb867caecdcf4474bc27`; its GKI ABI data, device config,
and runtime observations produced `xpad3s_layout.h` and `xpad3s_offset.h`.

The arm64 Image uses `text_offset=0` and `image_size=0x02a80000`. The matching
vendor boot header places the kernel at physical `0x40000000`, equal to
`PHYS_OFFSET`. The runtime direct map is
`0xffffff8000000000-0xffffffc000000000`; vmemmap begins at
`0xffffff7f00000000`.

The kernel has Clang LTO/CFI enabled. Fake `file_operations` entries therefore
use the exact `.cfi_jt` symbols recovered from the matching vmlinux.

## Repository layout

The port shares the host controller, device runner, perf leak, reclaim, fops
capture, and CVE trigger with Xpad2. Device differences are selected at build
time and kept in these locations:

```text
src/device/profile.h
src/device/perf_profile.h
src/exploit/profiles/xpad3s_*.h
src/trigger/app/
tools/xpad3s_*
```

Build selection:

```sh
make PROFILE=xpad2 -j4
make PROFILE=xpad3s -j4
```

Shared device artifact names are guarded by `build/.active-profile`. Changing
`PROFILE` invalidates and rebuilds the profile-dependent runner, perf target,
and preload, so a no-clean switch cannot silently deploy the other device's
binary.

## Validated observations

- The non-chain-walking EDEADLK stage passed: `FUTEX_CMP_REQUEUE_PI` returned
  `-EDEADLK`, the waiter returned with `ETIMEDOUT`, and the Boot ID stayed
  unchanged.
- Independent perf targets recovered one consistent randomized kernel base
  and their own canonical `cred` pointers. `task_hits=0` is acceptable because
  the current write path consumes the credential address, not that diagnostic
  task sample.
- A read-only KernelSnitch probe recovered the current `mm_struct` and
  confirmed direct-map geometry.
- Runtime tracepoint discovery identified `mm_page_alloc=255`,
  `mm_page_alloc_extfrag=256`, and `mm_page_free=258`. Xpad3S uses
  per-process order/PFN filters instead of the Xpad2 GFP mask.
- The device config has `CONFIG_SECURITY_SELINUX_DEVELOP=y`; enforcing is the
  byte at `selinux_state + 1`.
- Multiple holder attempts passed fresh-candidate, order-3, PFN equality, and
  content gates and reached `HOLDER_OK`.

## Application-domain trigger

The shell domain can see `/dev/ashmem` but SELinux denies opening it. A
debuggable, arm32, targetSdk 27 APK runs as `untrusted_app_27`, where the device
policy permits the open. Its smoke test confirmed:

```text
ABI:       armeabi-v7a
SELinux:   u:r:untrusted_app_27:s0:...
ashmem:    open succeeded
```

ADB package installation is denied on this firmware. The APK was installed
through `xpad-installer` 0.2.4 using its managed 0044 direct backend. `rish`
is useful as the Shizuku control plane, but it is not the private package
installation broker and cannot replace that install path.

The current waiter-side sequence is:

```text
FUTEX_WAIT_REQUEUE_PI returns stale waiter
  -> pselect6 exception bitmap lays out the waiter head
  -> ASHMEM_SET_NAME writes task/lock/prio
  -> final pselect6 repairs rb_left after the ioctl stack frame
  -> userspace-only busy hold preserves the stale kernel stack
  -> another thread calls sched_setattr to start adjust-PI
```

Probe output is synchronously written to the app's `files/probe.log` so it
survives a kernel panic as often as the filesystem permits.

## Dynamic chain history

1. A shell-domain run reached a valid holder, then stopped because opening
   `/dev/ashmem` returned `EACCES`. No final kernel trigger was issued.
2. The first app-domain chain used `getuidloop` as waiter hold. It entered
   `rt_mutex_adjust_prio_chain+0x188`, but repeated waiter-side `getuid`
   syscalls overwrote the stale stack: `waiter->lock` became NULL and the
   kernel panicked.
3. Replacing that hold with a pure userspace `busy` loop preserved
   `waiter->lock`. The chain advanced to `rb_erase+0x90`, proving the fake lock
   was consumed, but the ioctl caller frame had left a stack canary in
   `tree_entry.rb_left`, causing another panic.
4. The trigger now repeats `pselect6` after `ASHMEM_SET_NAME` to repair the
   first 40 bytes after ioctl return. This build is installed but has not yet
   reached an application launch on the physical unit.

The two recorded panics are expected experimental evidence, not validation.
Neither produced root, and neither permits opening the full-run gate.

## Safety boundary

The following modes are distinct:

- `--preflight-only`: profile check only;
- `--validate-only`: leak plus holder/reclaim gates, without adjust-PI;
- `--chain-validate-only`: dangerous adjust-PI trigger with fops
  check-and-restore capture;
- default/full run: disabled for Xpad3S until the chain gate is explicitly
  changed after successful dynamic validation.

Build and non-chain checks:

```sh
make PROFILE=xpad3s -j4
./build/xpad3s-ionstack-reroot -s SERIAL --preflight-only
./build/xpad3s-ionstack-reroot -s SERIAL --validate-only
```

Do not enable a full run merely because `HOLDER_OK` is observed. A valid
chain-only result must satisfy all of the following in one unchanged boot:

- app log reports both pselect calls returning `EBADF` (`errno=9`);
- at least one fops capture reports successful check and restore;
- device runner prints `CHAIN_VALIDATION_OK`;
- SELinux remains enforcing;
- starting and ending Boot IDs match;
- no new `SYSTEM_KERNEL_PANIC` entry is created.

Only after that result should `IONSTACK_PROFILE_CHAIN_VALIDATED` be changed to
`1`, followed by a clean full run and independent verification:

```sh
adb -s SERIAL shell /data/local/tmp/su -c id
```

The required terminal result is `uid=0`. The presence of an old `su` file or
socket is not evidence of root.

## Resume checklist

When the physical unit returns:

1. Record kernel release/version, build fingerprint, Boot ID, and current
   DropBox panic list before testing.
2. Confirm the installed trigger APK matches the current branch build.
3. Run one logged `--chain-validate-only --page-hold-sec=60` attempt.
4. If it panics, preserve `probe.log`, the complete runner log, Boot IDs, and
   the newest `SYSTEM_KERNEL_PANIC` entry before changing the waiter layout.
5. If it passes, repeat chain-only once on a clean boot before opening the
   full-run gate.

Do not commit physical device identifiers, private firmware images, DropBox
crash dumps, generated APK signing keys, or local agent/session directories.
