#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue
"""Diagnose, select, and advance the XPad2 POC through gated states."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = (
    ROOT
    if (ROOT / "profiles" / "xpad2-v260" / "ionstack_reroot_device").is_file()
    else ROOT / "dist" / "xpad2-19-260"
)
DEFAULT_OUTPUT = ROOT / "results" / "auto-poc"
REMOTE = {
    "ionstack_reroot_device": "/data/local/tmp/ionstack_reroot_device",
    "ionstack_perf_target": "/data/local/tmp/ionstack_perf_target",
    "ionstack_preload.so": "/data/local/tmp/ionstack_preload.so",
    "cve_2026_43499_chainwalk_probe_arm32": (
        "/data/local/tmp/cve43499_chainwalk_probe_arm32"
    ),
}
STATE_RE = re.compile(
    r"\[reroot\] STATE seq=(\d+) from=([a-z-]+) to=([a-z-]+) reason=([^\s]+)"
)


class AutoPocError(RuntimeError):
    pass


def run(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, text=True, errors="replace", capture_output=True,
        timeout=timeout, check=False,
    )


def adb_prefix(serial: str) -> list[str]:
    return ["adb"] + (["-s", serial] if serial else [])


def candidate(report: dict[str, Any]) -> dict[str, Any] | None:
    selected = report.get("selected_profile")
    return next(
        (item for item in report.get("candidates", []) if item["name"] == selected),
        None,
    )


def decide(report: dict[str, Any], action: str,
           accept_compatible: bool) -> dict[str, Any]:
    status = report.get("status")
    selected = report.get("selected_profile")
    selected_candidate = candidate(report)
    if status not in {"exact", "compatible"} or not selected or not selected_candidate:
        raise AutoPocError(f"profile diagnosis is {status}; refusing POC progression")
    if not report.get("release_scope_19_260"):
        raise AutoPocError("fingerprint is outside the /19-/260 release scope")
    if not all(report.get("technical_identity", {}).values()):
        raise AutoPocError("device/ABI/SDK/kernel-release technical identity mismatch")
    if not selected_candidate.get("release"):
        raise AutoPocError(f"profile {selected} is not in the release catalog")
    allow_version_mismatch = status == "compatible"
    if allow_version_mismatch and selected_candidate.get("anchor_matches", 0) < 2:
        raise AutoPocError("compatible profile lacks two independent offset anchors")
    if action == "root" and allow_version_mismatch and not accept_compatible:
        return {
            "profile": selected,
            "allow_version_mismatch": True,
            "effective_action": "validate",
            "root_deferred": True,
            "reason": "compatible evidence requires --accept-compatible after validation",
        }
    return {
        "profile": selected,
        "allow_version_mismatch": allow_version_mismatch,
        "effective_action": action,
        "root_deferred": False,
        "reason": "exact profile" if status == "exact" else "accepted compatible evidence",
    }


def parse_states(text: str) -> list[dict[str, Any]]:
    return [
        {"sequence": int(seq), "from": before, "to": after, "reason": reason}
        for seq, before, after, reason in STATE_RE.findall(text)
    ]


def require_runner_result(stage: str, proc: subprocess.CompletedProcess[str],
                          log_path: Path, final_state: str) -> list[dict[str, Any]]:
    text = proc.stdout
    if proc.stderr:
        text += "\n=== stderr ===\n" + proc.stderr
    log_path.write_text(text, encoding="utf-8")
    states = parse_states(text)
    if proc.returncode != 0:
        raise AutoPocError(f"{stage} failed rc={proc.returncode}; see {log_path}")
    if not states or states[-1]["to"] != final_state:
        raise AutoPocError(f"{stage} emitted no terminal {final_state} state")
    return states


def run_runner(serial: str, arguments: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return run(
        adb_prefix(serial) + ["exec-out", REMOTE["ionstack_reroot_device"]] + arguments,
        timeout=timeout,
    )


def push_profile(serial: str, bundle: Path, profile: str) -> None:
    directory = bundle / "profiles" / profile
    for filename, remote in REMOTE.items():
        source = directory / filename
        if not source.is_file():
            raise AutoPocError(f"release artifact missing: {source}")
        proc = run(adb_prefix(serial) + ["push", str(source), remote], timeout=120)
        if proc.returncode != 0:
            raise AutoPocError(f"adb push failed for {filename}: {proc.stderr}")
    proc = run(
        adb_prefix(serial) + ["shell", "chmod", "0700"] + list(REMOTE.values()),
        timeout=30,
    )
    if proc.returncode != 0:
        raise AutoPocError(f"chmod artifacts failed: {proc.stderr}")


def collect_diagnosis(args: argparse.Namespace, output: Path) -> tuple[Path, dict[str, Any]]:
    diag_dir = output / "profile-diag"
    diag_tool = args.bundle / "tools" / "ionstack_profile_diag.py"
    catalog = args.bundle / "profiles" / "xpad2_profiles.json"
    perf_target = (
        args.bundle / "profiles" / "xpad2-v260" / "ionstack_perf_target"
    )
    command = [
        sys.executable, str(diag_tool), "collect", "--target", str(perf_target),
        "--profiles", str(catalog), "--output", str(diag_dir),
        "--sample-ms", str(args.sample_ms), "--freq", str(args.freq),
        "--attempts", str(args.attempts), "--workload-timeout", str(args.diag_timeout),
    ]
    if args.serial:
        command += ["--serial", args.serial]
    proc = run(command, timeout=args.diag_timeout * 5)
    (output / "profile-diag-command.log").write_text(
        proc.stdout + ("\n=== stderr ===\n" + proc.stderr if proc.stderr else ""),
        encoding="utf-8",
    )
    report_path = diag_dir / "report.json"
    if not report_path.is_file():
        raise AutoPocError("profile diagnostic produced no report.json")
    return diag_dir, json.loads(report_path.read_text(encoding="utf-8"))


def execute(args: argparse.Namespace) -> int:
    timestamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S%z")
    output = args.output / timestamp
    output.mkdir(parents=True, exist_ok=False)
    _, report = collect_diagnosis(args, output)
    if args.action == "diagnose":
        decision = {
            "profile": report.get("selected_profile"),
            "status": report.get("status"),
            "effective_action": "diagnose",
            "root_deferred": False,
        }
    else:
        decision = decide(report, args.action, args.accept_compatible)
    (output / "decision.json").write_text(
        json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.action == "diagnose":
        print(output)
        print(
            f"status={decision['status']} profile={decision['profile']} "
            "action=diagnose"
        )
        return 0

    push_profile(args.serial, args.bundle, decision["profile"])
    profile_args = (
        ["--allow-profile-version-mismatch"]
        if decision["allow_version_mismatch"] else []
    )
    stages: dict[str, Any] = {}
    preflight = run_runner(
        args.serial, ["--preflight-only"] + profile_args, args.stage_timeout
    )
    stages["preflight"] = require_runner_result(
        "preflight", preflight, output / "preflight.log", "complete"
    )

    if decision["effective_action"] == "validate":
        validation = run_runner(
            args.serial, ["--validate-only"] + profile_args, args.stage_timeout
        )
        stages["validation"] = require_runner_result(
            "validation", validation, output / "validation.log", "complete"
        )
        write = False
    else:
        if decision["allow_version_mismatch"]:
            validation = run_runner(
                args.serial, ["--validate-only"] + profile_args, args.stage_timeout
            )
            stages["validation"] = require_runner_result(
                "validation", validation, output / "validation.log", "complete"
            )
        root_args = profile_args + (
            ["--accept-compatible-write"]
            if decision["allow_version_mismatch"] else []
        )
        root = run_runner(args.serial, root_args, args.root_timeout)
        stages["root"] = require_runner_result(
            "root", root, output / "root.log", "complete"
        )
        if "[reroot] SUCCESS" not in root.stdout:
            raise AutoPocError("runner completed without SUCCESS marker")
        write = True
    (output / "state-trace.json").write_text(
        json.dumps(stages, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output)
    print(
        f"profile={decision['profile']} action={decision['effective_action']} "
        f"write_attempted={int(write)} root_deferred={int(decision['root_deferred'])}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("diagnose", "validate", "root"))
    parser.add_argument("--serial", default="")
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--accept-compatible", action="store_true")
    parser.add_argument("--sample-ms", type=int, default=2500)
    parser.add_argument("--freq", type=int, default=4000)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--diag-timeout", type=int, default=180)
    parser.add_argument("--stage-timeout", type=int, default=1200)
    parser.add_argument("--root-timeout", type=int, default=1200)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return execute(args)
    except (AutoPocError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"ionstack-auto-poc: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
