#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ionstack_auto_poc", ROOT / "tools" / "ionstack_auto_poc.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def report(status="exact", anchors=3, scope=True):
    return {
        "status": status,
        "selected_profile": "xpad2-v260",
        "release_scope_19_260": scope,
        "technical_identity": {
            "machine": True, "device": True, "sdk": True,
            "kernel_release": True,
        },
        "candidates": [{
            "name": "xpad2-v260", "release": True,
            "anchor_matches": anchors,
        }],
    }


class AutoPocTest(unittest.TestCase):
    def test_exact_profile_can_root(self):
        decision = MODULE.decide(report(), "root", False)
        self.assertEqual(decision["effective_action"], "root")
        self.assertFalse(decision["allow_version_mismatch"])

    def test_compatible_defaults_to_validation(self):
        decision = MODULE.decide(report("compatible"), "root", False)
        self.assertEqual(decision["effective_action"], "validate")
        self.assertTrue(decision["root_deferred"])
        accepted = MODULE.decide(report("compatible"), "root", True)
        self.assertEqual(accepted["effective_action"], "root")

    def test_unknown_and_out_of_scope_stop(self):
        with self.assertRaises(MODULE.AutoPocError):
            MODULE.decide(report("unknown"), "validate", False)
        with self.assertRaises(MODULE.AutoPocError):
            MODULE.decide(report(scope=False), "validate", False)

    def test_state_parser(self):
        states = MODULE.parse_states(
            "[reroot] STATE seq=1 from=init to=preflight reason=files-present\n"
            "[reroot] STATE seq=2 from=preflight to=profile reason=technical-gates-ok\n"
        )
        self.assertEqual([item["to"] for item in states], ["preflight", "profile"])


if __name__ == "__main__":
    unittest.main()
