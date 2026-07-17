#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads(
    (ROOT / "profiles" / "xpad2_profiles.json").read_text(encoding="utf-8")
)
DEFINES = {
    "xpad2-v231227": "IONSTACK_PROFILE_XPAD2_V231227",
    "xpad2-v260": "IONSTACK_PROFILE_XPAD2_V260",
    "xpad2-v19-a": "IONSTACK_PROFILE_XPAD2_V19_A",
    "xpad2-v19-b": "IONSTACK_PROFILE_XPAD2_V19_B",
}
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
    "selinux_enforcing": "SELINUX_ENFORCING_OFF",
}


def macros(profile: str) -> dict[str, str]:
    proc = subprocess.run(
        [
            "clang", "-dM", "-E", f"-D{DEFINES[profile]}=1",
            "-include", str(ROOT / "src" / "exploit" / "offset.h"),
            "-x", "c", "/dev/null",
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    result = {}
    for line in proc.stdout.splitlines():
        match = re.match(r"#define\s+(\w+)\s+(.+)$", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result


def macro_int(value: str) -> int:
    return int(re.sub(r"[uUlL]+$", "", value), 0)


class ProfileCatalogTest(unittest.TestCase):
    def test_catalog_matches_compiled_offsets(self):
        for profile in CATALOG["profiles"]:
            compiled = macros(profile["name"])
            for catalog_name, macro_name in OFFSET_MACROS.items():
                self.assertEqual(
                    int(profile["offsets"][catalog_name], 0),
                    macro_int(compiled[macro_name]),
                    f"{profile['name']}:{catalog_name}",
                )

    def test_selinux_state_precedes_enforcing_byte(self):
        for profile in CATALOG["profiles"]:
            offsets = profile["offsets"]
            self.assertEqual(
                int(offsets["selinux_state"], 0) + 1,
                int(offsets["selinux_enforcing"], 0),
            )


if __name__ == "__main__":
    unittest.main()
