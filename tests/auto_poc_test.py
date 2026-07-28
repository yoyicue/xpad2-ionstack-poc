#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ionstack_auto_poc", ROOT / "tools" / "ionstack_auto_poc.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def report(status="exact", anchors=0, scope=True, technical=True):
    return {
        "status": status,
        "selected_profile": "xpad2p-v262-v272",
        "release_scope_19_272": scope,
        "technical_identity": {
            "machine": technical,
            "device": technical,
            "sdk": technical,
            "kernel_release": technical,
        },
        "candidate": {
            "name": "xpad2p-v262-v272",
            "release": True,
            "anchor_matches": anchors,
        },
    }


class AutoPocTest(unittest.TestCase):
    def test_default_build_is_the_isolated_xpad2p_payload_directory(self):
        self.assertEqual(MODULE.DEFAULT_BUILD, ROOT / "build" / "xpad2p")

    def test_build_gate_requires_xpad2p_stamp_and_complete_payload_set(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            (build / ".profile").write_text("xpad2p\n", encoding="utf-8")
            for filename in MODULE.REMOTE:
                (build / filename).write_bytes(b"test")
            MODULE.require_build(build)
            (build / ".profile").write_text("xpad2\n", encoding="utf-8")
            with self.assertRaises(MODULE.AutoPocError):
                MODULE.require_build(build)

    def test_exact_tuple_can_advance(self):
        decision = MODULE.decide(report(), "root")
        self.assertFalse(decision["compatible"])
        self.assertEqual(decision["effective_action"], "root")

    def test_compatible_two_anchor_profile_can_advance(self):
        decision = MODULE.decide(
            report("compatible", anchors=2), "root"
        )
        self.assertTrue(decision["compatible"])
        self.assertEqual(decision["anchor_matches"], 2)

    def test_compatible_one_anchor_is_rejected(self):
        with self.assertRaises(MODULE.AutoPocError):
            MODULE.decide(report("compatible", anchors=1), "validate")

    def test_scope_and_identity_are_required(self):
        with self.assertRaises(MODULE.AutoPocError):
            MODULE.decide(report(scope=False), "root")
        with self.assertRaises(MODULE.AutoPocError):
            MODULE.decide(report(technical=False), "root")

    def test_unknown_is_rejected(self):
        with self.assertRaises(MODULE.AutoPocError):
            MODULE.decide(report("unknown", anchors=4), "root")


if __name__ == "__main__":
    unittest.main()
