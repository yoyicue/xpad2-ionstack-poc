#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ionstack_profile_diag", ROOT / "tools" / "ionstack_profile_diag.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)
CATALOG = MODULE.load_profiles()
PD2_CATALOG = MODULE.load_profiles(
    ROOT / "profiles" / "xpad2_profiles.json"
)
OFFSET_MACROS = {
    "ashmem_llseek": "ASHMEM_LLSEEK_OFF",
    "ashmem_read_iter": "ASHMEM_READ_ITER_OFF",
    "ashmem_ioctl": "ASHMEM_IOCTL_OFF",
    "ashmem_compat_ioctl": "ASHMEM_COMPAT_IOCTL_OFF",
    "ashmem_mmap": "ASHMEM_MMAP_OFF",
    "ashmem_open": "ASHMEM_OPEN_OFF",
    "ashmem_release": "ASHMEM_RELEASE_OFF",
    "ashmem_show_fdinfo": "ASHMEM_SHOW_FDINFO_OFF",
    "ashmem_fops": "ASHMEM_FOPS_OFF",
    "ashmem_misc_fops": "ASHMEM_MISC_FOPS_OFF",
    "anon_pipe_buf_ops": "ANON_PIPE_BUF_OPS_OFF",
    "security_hook_heads": "SECURITY_HOOK_HEADS_OFF",
    "kmalloc_caches": "KMALLOC_CACHES_OFF",
    "root_task_group": "ROOT_TASK_GROUP_OFF",
    "selinux_enforcing": "SELINUX_ENFORCING_OFF",
}


def identity(incremental=262, kernel_version=None, device=None):
    versions = {
        262: "#1 SMP PREEMPT Mon Jun 29 05:28:07 CST 2026",
        272: "#1 SMP PREEMPT Thu Jul 23 20:38:25 CST 2026",
    }
    return {
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "device": device or "ls14_mt8797_wifi_64",
        "fingerprint": (
            "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
            f"TP1A.220624.014/{incremental}:user/release-keys"
        ),
        "kernel_release": "4.19.191+",
        "kernel_version": kernel_version or versions.get(
            incremental, "#1 SMP PREEMPT unknown compatible build"
        ),
        "machine": "aarch64",
        "sdk": "33",
    }


def discovery(offset, hits=7, workload="ashmem-ioctl"):
    return (
        f"[perf-target] DISCOVERY workload={workload} "
        "base=0xffffff9e36280000 samples=20 image_ips=20 "
        "image_regs=2 direct_regs=2\n"
        "[perf-target] DISCOVERY_IP rank=1 "
        f"value=0xffffff9e36e60c68 off={offset} hits={hits}\n"
    )


class ProfileDiagTest(unittest.TestCase):
    def test_catalog_offsets_match_compiled_profile(self):
        header = (
            ROOT / "src" / "exploit" / "profiles" / "xpad2p_offset.h"
        ).read_text(encoding="utf-8")
        values = {
            name: f"0x{int(value, 16):08x}"
            for name, value in re.findall(
                r"^#define\s+([A-Z0-9_]+)\s+"
                r"(0x[0-9a-fA-F]+)ULL$",
                header,
                re.MULTILINE,
            )
        }
        catalog_offsets = CATALOG["profile"]["offsets"]
        self.assertEqual(set(catalog_offsets), set(OFFSET_MACROS))
        for name, macro in OFFSET_MACROS.items():
            self.assertEqual(catalog_offsets[name].lower(), values[macro])

    def test_exact_tuples(self):
        for incremental in (262, 272):
            report = MODULE.analyze(identity(incremental), {}, CATALOG)
            self.assertEqual(report["status"], "exact")
            self.assertTrue(report["release_scope_19_272"])
            self.assertTrue(report["write_eligible"])

    def test_compatible_requires_two_unique_offsets(self):
        raw = {
            "ashmem-ioctl": discovery("0x00be0c68"),
            "ashmem-open-close": discovery(
                "0x00be1760", workload="ashmem-open-close"
            ),
        }
        report = MODULE.analyze(identity(197), raw, CATALOG)
        self.assertEqual(report["status"], "compatible")
        self.assertEqual(report["candidate"]["anchor_matches"], 2)
        self.assertFalse(report["write_eligible"])

    def test_duplicate_offset_counts_once(self):
        raw = {
            "first": discovery("0x00be0c68"),
            "second": discovery("0x00be0c68", workload="getuid"),
        }
        report = MODULE.analyze(identity(197), raw, CATALOG)
        self.assertEqual(report["status"], "unknown")
        self.assertEqual(report["candidate"]["anchor_matches"], 1)

    def test_scope_and_technical_identity_are_independent_gates(self):
        raw = {
            "one": discovery("0x00be0c68"),
            "two": discovery("0x00be1760"),
        }
        outside = MODULE.analyze(identity(273), raw, CATALOG)
        self.assertEqual(outside["status"], "compatible")
        self.assertFalse(outside["release_scope_19_272"])
        wrong_device = MODULE.analyze(
            identity(197, device="ls12_mt8797_wifi_64"), raw, CATALOG
        )
        self.assertFalse(wrong_device["technical_identity"]["device"])

    def test_fingerprint_parser_is_strict(self):
        valid = (
            "alps/vnd_ls14_mt8797_wifi_64/ls14_mt8797_wifi_64:13/"
            "TP1A.220624.014/19:user/release-keys"
        )
        self.assertEqual(
            MODULE.fingerprint_incremental(valid, CATALOG), 19
        )
        self.assertIsNone(
            MODULE.fingerprint_incremental(
                valid.replace("/19:", "/019:"), CATALOG
            )
        )
        self.assertIsNone(
            MODULE.fingerprint_incremental(
                valid.replace("ls14", "ls12"), CATALOG
            )
        )

    def test_pd2_exact_and_compatible_scope(self):
        versions = {
            260: "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            272: "#1 SMP PREEMPT Thu Jul 23 20:40:43 CST 2026",
        }
        for incremental, kernel_version in versions.items():
            pd2_identity = identity(
                incremental,
                kernel_version=kernel_version,
                device="ls12_mt8797_wifi_64",
            )
            pd2_identity["fingerprint"] = (
                "alps/vnd_ls12_mt8797_wifi_64/"
                "ls12_mt8797_wifi_64:13/"
                f"TP1A.220624.014/{incremental}:user/release-keys"
            )
            report = MODULE.analyze(pd2_identity, {}, PD2_CATALOG)
            self.assertEqual(report["status"], "exact")
            self.assertTrue(report["release_scope_19_272"])

        compatible_identity = identity(
            197,
            kernel_version="#1 SMP PREEMPT compatible LS12 build",
            device="ls12_mt8797_wifi_64",
        )
        compatible_identity["fingerprint"] = (
            "alps/vnd_ls12_mt8797_wifi_64/"
            "ls12_mt8797_wifi_64:13/"
            "TP1A.220624.014/197:user/release-keys"
        )
        raw = {
            "ashmem-ioctl": discovery("0x00be4d98"),
            "ashmem-open-close": discovery(
                "0x00be5890", workload="ashmem-open-close"
            ),
        }
        report = MODULE.analyze(
            compatible_identity, raw, PD2_CATALOG
        )
        self.assertEqual(report["status"], "compatible")
        self.assertEqual(report["candidate"]["anchor_matches"], 2)


if __name__ == "__main__":
    unittest.main()
