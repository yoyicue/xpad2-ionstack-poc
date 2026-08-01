# xpad2-ionstack-poc

Host-assisted re-root proof of concept for explicitly locked XPad2 and XPad3S
firmware profiles. It packages the IonStack chain into a single,
independently buildable source tree while keeping each kernel layout behind a
separate compile-time profile.

The default `xpad2` build uses native C/ELF components only. The
`experimental/xpad3s` branch contains the dynamically validated XPad3S port.
That profile uses a small targetSdk 27, compat32 trigger APK because the
XPad3S SELinux policy denies shell access to `/dev/ashmem`. See
[PORTING_XPAD3S.md](PORTING_XPAD3S.md) before building or testing it.

## XPad2 `/260` and `/272` profile

This POC intentionally fails closed unless all profile checks match:

```text
device:      ls12_mt8797_wifi_64
Android:     13 / SDK 33
/260:        alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/260:user/release-keys
kernel:      4.19.191+ / #1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026
/272:        alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/272:user/release-keys
kernel:      4.19.191+ / #1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026
```

The LS12 V260629 `/260` and V260723 `/272` boot images have identical
IKCONFIG and absolute kallsyms. Their uncompressed Images differ in only 48
build-metadata bytes, and all compiled IonStack offsets are unchanged. Static
validation also found no missing KSU/SUU imports, a unique matching
`module_layout` CRC, Android 13 / SDK 33 / `zygote64_32`, and byte-identical
ART, Binder, Bionic and linker files used by the Hook stack.

The runner binds each fingerprint to its matching kernel build string and
rejects crossed tuples. Other canonical LS12 fingerprints from `/19` through
`/272` remain evidence-gated: at least two unique runtime offset anchors plus
same-run preflight, validation, leak, holder, PFN, content, direct-map and
Boot-ID checks are required before a write can auto-arm.

The exploit can panic or reboot the device. Use it only on hardware you own
or are explicitly authorized to test, with a recovery path available.

Build and run the PD2 evidence-gated controller with:

```sh
make PROFILE=xpad2 -j4
python3 tools/ionstack_auto_poc.py diagnose \
  --build build/xpad2 --catalog profiles/xpad2_profiles.json --serial SERIAL
python3 tools/ionstack_auto_poc.py validate \
  --build build/xpad2 --catalog profiles/xpad2_profiles.json --serial SERIAL
python3 tools/ionstack_auto_poc.py root \
  --build build/xpad2 --catalog profiles/xpad2_profiles.json --serial SERIAL
```

### XPad2 release bundle

From a clean release checkout:

```sh
make release-xpad2
```

The release lock keeps PD2 artifacts under `build/xpad2/`; it never packages
or selects the separate PD2P/LS14 offset profile.

## XPad2P `/262` and `/272` profile

PD2P is a separate compile-time profile because its LS14 kernel has
hardware-driver layout differences from the LS12 PD2 kernel. The profile was
recovered from the V260723 full OTA and audited against the V260629 LS14 OTA.
It accepts these exact fingerprint and kernel-version pairs:

```text
device:      ls14_mt8797_wifi_64
Android:     13 / SDK 33
/262:        alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/TP1A.220624.014/262:user/release-keys
kernel:      4.19.191+ / #1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026
/272:        alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/TP1A.220624.014/272:user/release-keys
kernel:      4.19.191+ / #1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026
```

Build it with:

```sh
make PROFILE=xpad2p -j4
```

The two LS14 Images have identical size and kernel configuration. Their only
46 differing bytes are build timestamps, GNU build ID, and built-in cpio
timestamps, so they share the dedicated ashmem, SLUB, SELinux, pipe,
task-group, and boot-ID offsets. The runner matches the two build tuples as
pairs and rejects crossed fingerprint/kernel combinations.

For other LS14 fingerprints, the diagnostic scope is `/19` through `/272`.
Being inside that numeric range is not sufficient for compatibility. The
read-only perf diagnostic must observe at least two different offsets from
the LS14 catalog before the build is classified as `compatible`; duplicated
names or repeated observations of one address count as one anchor.

Preflight and validation modes are enabled. The historical full-chain marker
remains unset, but a normal run follows the same evidence-gated compatibility
policy: it starts with writes disarmed and emits `WRITE_ARMED auto=1` only
after exact-tuple or compatible-anchor evidence plus the current-run leak,
holder, PFN, content, direct-map, and same-Boot-ID gates have all passed.

`--preflight-only` and `--validate-only` never arm a write. The
evidence-gated controller deliberately repeats current-boot checks before
automatically arming the write stage. No approval token is persisted across
processes or reboots, and the ordinary C host runner remains exact-tuple only.

Use the evidence-gated controller for both exact and compatible PD2P builds:

```sh
python3 tools/ionstack_auto_poc.py diagnose --serial SERIAL
python3 tools/ionstack_auto_poc.py validate --serial SERIAL
python3 tools/ionstack_auto_poc.py root --serial SERIAL
```

The `root` action repeats diagnosis, preflight, and non-writing validation in
one workflow. A compatible build advances to the write stage only when it is
an LS14 `/19`–`/272` fingerprint, has the expected ABI/SDK/kernel release,
matches at least two unique runtime offset anchors, and retains the same Boot
ID through every stage.

### XPad2P release bundle

From a clean `release/xpad2p-19-272` checkout:

```sh
make release-xpad2p
```

The command rebuilds the isolated PD2P payload, verifies every device
artifact against `xpad2p-release.lock.json`, and writes the host-specific ZIP,
unpacked bundle, SHA-256 manifest, and ZIP checksum under `dist/`. Release
archives contain `xpad2p-ionstack-reroot` (or `.exe`) and keep the locked
device payload under `build/xpad2p/`.

## Verified XPad3S profile

XPad3S is kept in this repository because it shares the leak, reclaim,
capture, and controller code with XPad2, but it remains fail closed behind a
separate compile-time profile. On 2026-07-18 the exact PD3S `/338` profile
completed dynamic fops capture/write/restore validation, produced a root
daemon independently verified by `su -c id`, restored SELinux Enforcing, and
subsequently loaded the matching Android 12 / 5.10 KernelSU module.

```text
device:      TALIH-PD3S
Android:     13 / SDK 33
fingerprint: alps/TALIH-PD3S/TALIH-PD3S:13/TP1A.220624.014/338:user/release-keys
kernel:      5.10.198-android12-9-00019-g6efebf1322d6-ab11471183
version:     #1 SMP PREEMPT Mon Feb 19 21:20:42 UTC 2024
```

The `/371` OTA fingerprint is accepted because its boot image contains the
same locked GKI build, but full Root was physically validated on `/338`.
Neither fingerprint permits reuse on another device or kernel build.

The app-domain trigger must be installed before a full run. A successful run
can leave that trigger parked for the rest of the boot; do not replace or
force-stop it until after an ordinary reboot.

### XPad3S release bundle

From a clean `experimental/xpad3s` checkout with the locked trigger APK
already built:

```sh
make release-xpad3s
```

The command verifies every device artifact against
`xpad3s-release.lock.json`, then writes a commit-addressed ZIP, unpacked
bundle, SHA-256 manifest, and ZIP checksum under `dist/`.

## Quick start

1. Download and extract the archive for your host platform from the latest
   [GitHub Release](https://github.com/yoyicue/xpad2-ionstack-poc/releases/latest).
2. Install the official Android SDK Platform Tools and connect the supported
   device with USB debugging enabled.
3. Open a terminal in the extracted directory and confirm that ADB sees it:

```sh
adb devices -l
```

On macOS or Linux:

```sh
./xpad2p-ionstack-reroot -s SERIAL --preflight-only
./xpad2p-ionstack-reroot -s SERIAL --validate-only
./xpad2p-ionstack-reroot -s SERIAL
```

On Windows PowerShell:

```powershell
.\xpad2p-ionstack-reroot.exe -s SERIAL --preflight-only
.\xpad2p-ionstack-reroot.exe -s SERIAL --validate-only
.\xpad2p-ionstack-reroot.exe -s SERIAL
```

After the host reports `SUCCESS`, verify root and open a shell:

```sh
adb -s SERIAL shell /data/local/tmp/su -c id
adb -s SERIAL shell /data/local/tmp/su
```

Enjoy the temporary root shell. Use `exit` to leave it; rebooting the device
removes root.

### Continue with KernelSU late-load

The temporary root produced here can load the matching runtime KernelSU port
without modifying the boot image. See
[yoyicue/xpad2-ksu-lateload](https://github.com/yoyicue/xpad2-ksu-lateload)
for the exact XPad2 Linux 4.19 module, `ksud`, build instructions and verified
late-load/unload workflow.

The repositories intentionally remain separate: this POC is the ephemeral
re-root entry point, while `xpad2-ksu-lateload` consumes that authorized root
to provide KernelSU UAPI and `su` for the current boot.

## Build

Requirements:

- macOS or Linux host with `clang`, `make`, and `adb`;
- Android NDK r29 (API 35 is the default build API);
- an arm64/compat32 target matching the profile above.

The XPad3S APK additionally requires JDK 17 and Android SDK
Build Tools 34 plus `platforms/android-34/android.jar`.

```sh
make PROFILE=xpad2 -j4
```

For XPad2 `/272`, use the same `PROFILE=xpad2` artifact; the exact
fingerprint/kernel tuple selects the shared LS12 `/260`–`/272` offsets.

For XPad2P `/272`:

```sh
make PROFILE=xpad2p -j4
```

On the XPad3S branch:

```sh
make PROFILE=xpad3s -j4
```

Override discovery when needed:

```sh
make PROFILE=xpad2 NDK_ROOT=/path/to/android-ndk API=35 -j4
```

All artifacts are emitted under `build/`; the build has no source dependency
outside this repository. PD2 device payloads live under `build/xpad2/` and
PD2P payloads under `build/xpad2p/`. The two host controllers are compiled
with those paths respectively, so building one profile cannot change what an
already-built controller deploys. XPad3S keeps its release-locked layout
directly under `build/`.

### Host platforms

The host controller supports macOS arm64, Linux x86_64, and Windows x86_64.
The Android device artifacts are identical across host platforms.

Build only the native macOS or Linux host controller:

```sh
make host
```

Build the Windows x86_64 controller with LLVM-MinGW:

```sh
make host-windows \
  WINDOWS_CC=/path/to/llvm-mingw/bin/x86_64-w64-mingw32-clang
```

On Windows, install the official Android SDK Platform Tools and ensure
`adb.exe` is on `PATH`. In release archives, the host executable is at the
top level and its profile-owned Android artifacts remain under
`build/xpad2/` or `build/xpad2p/`.

## Run

Run commands from the extracted release root and keep the `build/` directory
intact. `-s SERIAL` is optional when exactly one ADB device is connected.

### macOS and Linux

Start with the non-exploit profile check:

```sh
./xpad2-ionstack-reroot -s SERIAL --preflight-only
```

Exercise discovery and the order-3/PFN/content gates without the final
adjust-PI trigger or kernel write:

```sh
./xpad2-ionstack-reroot -s SERIAL --validate-only
```

Run the full chain:

```sh
./xpad2-ionstack-reroot -s SERIAL
```

If a device runner returns exit 75, it records the current Boot ID and refuses
another unsafe run until an ordinary reboot changes that ID.
`--preflight-only` and `--validate-only` remain available in the meantime.

### Windows PowerShell

Install the official Android SDK Platform Tools first and confirm that
`adb.exe` is available:

```powershell
adb version
adb devices -l
```

Then run the same sequence with the Windows host controller:

```powershell
.\xpad2-ionstack-reroot.exe -s SERIAL --preflight-only
.\xpad2-ionstack-reroot.exe -s SERIAL --validate-only
.\xpad2-ionstack-reroot.exe -s SERIAL
```

The Windows controller creates logs under
`results\YYYY-MM-DD\reroot_YYYYMMDD_HHMMSS\reroot.log`.

Logs are written below `results/YYYY-MM-DD/` by default. Root is ephemeral:
the POC does not modify AVB, boot images, or system partitions and must be
run again after reboot.

## Using `su` after a successful run

The supported user-facing client is installed at `/data/local/tmp/su`. It
connects to the temporary root daemon through
`/data/local/tmp/temp_su.sock`. Do not move it into `/system/bin`, and do not
rely on the internal `/apex/com.android.virt/bin/su` mount-namespace path.

Run one command as root from any host platform:

```sh
adb -s SERIAL shell /data/local/tmp/su -c id
adb -s SERIAL shell /data/local/tmp/su -c 'cat /proc/kallsyms | head'
```

Open an interactive root shell:

```sh
adb -s SERIAL shell /data/local/tmp/su
```

Use `exit` to leave the interactive shell. The daemon log is stored at
`/data/local/tmp/su_daemon.log`.

Root and the daemon are ephemeral and stop working after reboot. Files under
`/data/local/tmp` may remain, so the existence of `su` or the socket is not a
root check. Verify with `su -c id`; if desired, remove stale files after a
reboot:

```sh
adb -s SERIAL shell rm -f /data/local/tmp/su \
  /data/local/tmp/temp_su.sock /data/local/tmp/su_daemon.log
```

## Troubleshooting

The reclaim stage is probabilistic. A rejected attempt does not necessarily
indicate a build or compatibility regression, and the order-3 safety gate
prevents the final kernel write unless all required observations agree.

| Log or result | Meaning |
| --- | --- |
| `accepted=0` | The current reclaim attempt did not capture the required target fragment. The final kernel write is refused. |
| `order3_success=N` | Order-3 allocation events were observed. This alone does not mean that the target fragment or PFN matched. |
| `prepare_kernel_page retry N/72` | The current holder process is still retrying internally. |
| `HOLDER_REJECT` | One outer holder attempt failed its combined fresh/order/PFN/content checks; another outer attempt may follow. |
| `holder attempts exhausted` | All configured outer holder attempts failed. No final write was performed. |
| `device_rc=130` | The device-side process received `SIGINT`, normally because the run was interrupted externally. It is not a natural retry exhaustion. |
| `same_boot=0` | The Boot ID changed during the run, indicating that the device rebooted or panicked. |

Start with `--preflight-only`, then use `--validate-only` to exercise discovery
and reclaim gates without the final trigger. Do not infer that root survived a
reboot from the presence of an old socket path: independently verify the
daemon with the host command's `su -c id` check. Preserve the complete run log
and its starting and ending Boot IDs when reporting a failure.

Retry and success observations in this repository apply only to the listed
development firmware and hardware unit. Memory pressure, device uptime, and
other workload can affect reclaim behavior even on the same device.

## Verified behavior

The release runner deliberately uses three capture workers. Historical runs
of the otherwise identical six-worker runner showed excessive contention and
materially more adjust-PI panics; reducing the capture pool to three retained
the write window while making the trigger substantially more repeatable on the
development unit. Successful trials independently verified `su -c id`,
`/proc/kpageflags` access, and restoration of the temporarily replaced fops.
This measures repeatability on one physical unit; it is not a claim that every
device sold under the same model name is compatible.

## Licensing

Copyright (C) 2026 yoyicue.

The combined project is released under `GPL-3.0-or-later`; see `LICENSE`.
Third-party IonStack-derived files retain their Apache-2.0 provenance and
license; see `NOTICE` and `licenses/Apache-2.0.txt`.

## Security reports

Please do not include device identifiers, private firmware images, crash dumps,
or other sensitive data in a public issue. See `SECURITY.md` for the reporting
guidelines.

## Acknowledgements

Special thanks to TALPAD-BOOM Group.
