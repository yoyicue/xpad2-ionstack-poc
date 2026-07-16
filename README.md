# xpad2-ionstack-poc

Host-assisted re-root proof of concept for the verified XPad2 firmware
profile. It packages the verified IonStack chain into a single,
independently buildable source tree.

The default `xpad2` build uses native C/ELF components only. The
`experimental/xpad3s` branch also contains an unverified Xpad3S port. That
profile uses a small targetSdk 27, compat32 trigger APK because the Xpad3S
SELinux policy denies shell access to `/dev/ashmem`. See
[PORTING_XPAD3S.md](PORTING_XPAD3S.md) before building or testing it.

## Verified Xpad2 profile

This POC intentionally fails closed unless all profile checks match:

```text
device:      ls12_mt8797_wifi_64
Android:     13 / SDK 33
fingerprint: alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/260:user/release-keys
kernel:      4.19.191+ / #1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026
```

The exploit can panic or reboot the device. Use it only on hardware you own
or are explicitly authorized to test, with a recovery path available.

This repository is narrowly scoped to the firmware profile above. It is not a
general-purpose rooting tool, and offsets or assumptions must not be reused on
other devices without independent validation.

## Experimental Xpad3S profile

Xpad3S is kept in this repository because it shares the leak, reclaim,
capture, and controller code with Xpad2, but it remains fail closed behind a
separate compile-time profile. It has not completed dynamic chain validation
and has not produced a verified root shell. Full Xpad3S runs are disabled by
`IONSTACK_PROFILE_CHAIN_VALIDATED=0`.

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
./xpad2-ionstack-reroot -s SERIAL --preflight-only
./xpad2-ionstack-reroot -s SERIAL --validate-only
./xpad2-ionstack-reroot -s SERIAL
```

On Windows PowerShell:

```powershell
.\xpad2-ionstack-reroot.exe -s SERIAL --preflight-only
.\xpad2-ionstack-reroot.exe -s SERIAL --validate-only
.\xpad2-ionstack-reroot.exe -s SERIAL
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

The experimental Xpad3S APK additionally requires JDK 17 and Android SDK
Build Tools 34 plus `platforms/android-34/android.jar`.

```sh
make PROFILE=xpad2 -j4
```

On the experimental branch only:

```sh
make PROFILE=xpad3s -j4
```

Override discovery when needed:

```sh
make PROFILE=xpad2 NDK_ROOT=/path/to/android-ndk API=35 -j4
```

All artifacts are emitted under `build/`; the build has no source dependency
outside this repository. A profile stamp invalidates shared device artifacts
when `PROFILE` changes, preventing a no-clean switch from reusing binaries
compiled for the other device.

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
top level and the shared Android artifacts remain under `build/`.

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
