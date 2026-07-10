# xpad2-ionstack-poc

Pure-C, host-assisted re-root proof of concept for the explicitly supported
XPad2 firmware profile. It packages the verified IonStack chain into a
single, independently buildable source tree.

The runtime chain uses native C/ELF components only. It does not require
Python, Java, DEX, `app_process`, or a JVM on the Android target. ADB is used
for deployment and verification.

## Supported profile

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

## Build

Requirements:

- macOS or Linux host with `clang`, `make`, and `adb`;
- Android NDK r29 (API 35 is the default build API);
- an arm64/compat32 target matching the profile above.

```sh
make -j4
```

Override discovery when needed:

```sh
make NDK_ROOT=/path/to/android-ndk API=35 -j4
```

All artifacts are emitted under `build/`; the build has no source dependency
outside this repository.

## Run

Start with the non-exploit profile check:

```sh
./build/xpad2-ionstack-reroot -s SERIAL --preflight-only
```

Exercise discovery and the order-3/PFN/content gates without the final
adjust-PI trigger or kernel write:

```sh
./build/xpad2-ionstack-reroot -s SERIAL --validate-only
```

Run the full chain:

```sh
./build/xpad2-ionstack-reroot -s SERIAL
```

Logs are written below `results/YYYY-MM-DD/` by default. Root is ephemeral:
the POC does not modify AVB, boot images, or system partitions and must be
run again after reboot.

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

The final six-worker version completed five independent normal-reboot trials
on the development unit: 5/5 successful, with no panic or unexpected Boot-ID
change. Every trial independently verified `su -c id`, `/proc/kpageflags`
access, and restoration of the temporarily replaced fops. This measures
repeatability on one physical unit; it is not a claim that every device sold
under the same model name is compatible.

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
