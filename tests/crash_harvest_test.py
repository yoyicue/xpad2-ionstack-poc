#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ionstack_crash_harvest", ROOT / "tools" / "ionstack_crash_harvest.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class CrashHarvestTest(unittest.TestCase):
    def test_correlates_boot_pid_and_comm(self):
        texts = {
            "dropbox": (
                "Unable to handle kernel paging request\n"
                "CPU: 1 PID: 4242 Comm: ionstk197\n"
                "Kernel panic - not syncing\n"
            ),
            "protected_aee": "AEE record persisted",
        }
        report = MODULE.analyze_evidence(
            texts, 4242, "ionstk197",
            "11111111-2222-3333-4444-555555555555",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        self.assertEqual(report["freshness"], "fresh-marker-match")
        self.assertTrue(report["reboot_observed"])
        self.assertTrue(report["marker_match"])
        self.assertGreaterEqual(report["crash_anchor_count"], 2)

    def test_warns_that_aee_may_need_normal_reboot(self):
        report = MODULE.analyze_evidence(
            {"logcat": "no crash here"}, None, None,
            "11111111-2222-3333-4444-555555555555",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        self.assertEqual(report["freshness"], "no-crash-anchor")
        self.assertEqual(len(report["hints"]), 1)

    def test_manifest_marks_duplicate_content(self):
        with tempfile.TemporaryDirectory() as temp:
            round_dir = Path(temp)
            (round_dir / "same.log").write_text("same")
            digest = MODULE.sha256(round_dir / "same.log")
            state = {"hashes": {digest: "older/same.log"}}
            records = MODULE.record_files(round_dir, state)
            self.assertEqual(records[0]["duplicate_of"], "older/same.log")


if __name__ == "__main__":
    unittest.main()
