#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ionstack_profile_diag", ROOT / "tools" / "ionstack_profile_diag.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ProfileDiagTest(unittest.TestCase):
    def test_v197_fixture_selects_v19_b(self):
        fixture = ROOT / "tests" / "fixtures" / "profile_diag_v197"
        identity = MODULE.json.loads((fixture / "identity.json").read_text())
        logs = {
            path.stem: path.read_text()
            for path in (fixture / "raw").glob("*.log")
        }
        report = MODULE.analyze(identity, logs, MODULE.load_profiles())
        self.assertEqual(report["status"], "exact")
        self.assertEqual(report["selected_profile"], "xpad2-v19-b")
        self.assertEqual(report["fingerprint_incremental"], 197)
        self.assertTrue(report["release_scope_19_260"])
        self.assertTrue(report["write_eligible"])
        self.assertEqual(report["kaslr_base"], "0xffffff9e36280000")

    def test_fingerprint_is_scope_not_profile_selector(self):
        data = MODULE.load_profiles()
        identity = {
            "machine": "aarch64", "device": data["device"], "sdk": data["sdk"],
            "kernel_release": data["kernel_release"],
            "kernel_version": data["profiles"][0]["kernel_version"],
            "fingerprint": "broken/197",
        }
        report = MODULE.analyze(identity, {}, data)
        self.assertEqual(report["selected_profile"], "xpad2-v260")
        self.assertFalse(report["release_scope_19_260"])
        self.assertFalse(report["write_eligible"])

    def test_bundle_emits_manifest(self):
        fixture = ROOT / "tests" / "fixtures" / "profile_diag_v197"
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            (bundle / "raw").mkdir()
            (bundle / "identity.json").write_bytes((fixture / "identity.json").read_bytes())
            for source in (fixture / "raw").glob("*.log"):
                (bundle / "raw" / source.name).write_bytes(source.read_bytes())
            MODULE.analyze_bundle(bundle)
            self.assertTrue((bundle / "report.json").is_file())
            self.assertIn("report.json", (bundle / "SHA256SUMS").read_text())


if __name__ == "__main__":
    unittest.main()
