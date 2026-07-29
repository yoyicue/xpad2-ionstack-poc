#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue
"""Collect and analyze read-only PD2/PD2P offset-anchor evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILES = ROOT / "profiles" / "xpad2p_profiles.json"
DEFAULT_TARGET = ROOT / "build" / "ionstack_perf_target"
DEFAULT_OUTPUT = ROOT / "results" / "profile-diag"
REMOTE_TARGET = "/data/local/tmp/ionstack_perf_target_diag"
DISCOVERY_RE = re.compile(
    r"DISCOVERY_(IP|IMAGE_REG)\s+rank=\d+\s+value=0x[0-9a-fA-F]+\s+"
    r"off=(0x[0-9a-fA-F]+)\s+hits=(\d+)"
)
BASE_RE = re.compile(
    r"DISCOVERY\s+workload=getuid\s+base=(0x[0-9a-fA-F]+)"
)


class CommandError(RuntimeError):
    pass


def run(command: list[str], timeout: int = 120,
        check: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        command, text=True, errors="replace", capture_output=True,
        timeout=timeout, check=False,
    )
    if check and proc.returncode != 0:
        raise CommandError(
            f"command failed ({proc.returncode}): {' '.join(command)}\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    return proc


def adb_prefix(serial: str) -> list[str]:
    return ["adb"] + (["-s", serial] if serial else [])


def adb(serial: str, args: list[str], timeout: int = 120,
        check: bool = False) -> subprocess.CompletedProcess[str]:
    return run(adb_prefix(serial) + args, timeout=timeout, check=check)


def clean(text: str) -> str:
    return text.replace("\r", "").strip()


def shell_value(serial: str, command: str) -> str:
    return clean(adb(serial, ["shell", command], timeout=30).stdout)


def load_profiles(path: Path = DEFAULT_PROFILES) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fingerprint_incremental(value: str,
                            profiles_data: dict[str, Any]) -> int | None:
    prefix = str(profiles_data["fingerprint_prefix"])
    suffix = str(profiles_data["fingerprint_suffix"])
    if not value.startswith(prefix) or not value.endswith(suffix):
        return None
    digits = value[len(prefix):len(value) - len(suffix)]
    if not digits or not digits.isascii() or not digits.isdecimal():
        return None
    if len(digits) > 1 and digits[0] == "0":
        return None
    parsed = int(digits)
    return parsed if parsed <= 0xFFFFFFFF else None


def parse_discovery(text: str) -> dict[str, Any]:
    base_match = BASE_RE.search(text)
    observations: dict[str, dict[str, int]] = {"IP": {}, "IMAGE_REG": {}}
    for kind, offset, hits in DISCOVERY_RE.findall(text):
        normalized = f"0x{int(offset, 16):08x}"
        observations[kind][normalized] = max(
            observations[kind].get(normalized, 0), int(hits)
        )
    return {
        "base": base_match.group(1).lower() if base_match else None,
        "observations": observations,
    }


def analyze(identity: dict[str, Any], raw_logs: dict[str, str],
            profiles_data: dict[str, Any]) -> dict[str, Any]:
    parsed = {name: parse_discovery(text) for name, text in raw_logs.items()}
    observed: dict[str, dict[str, Any]] = {}
    for workload, result in parsed.items():
        for rows in result["observations"].values():
            for offset, hits in rows.items():
                row = observed.setdefault(
                    offset, {"hits": 0, "workloads": set()}
                )
                row["hits"] = max(int(row["hits"]), hits)
                row["workloads"].add(workload)

    incremental = fingerprint_incremental(
        str(identity.get("fingerprint", "")), profiles_data
    )
    release_scope = (
        incremental is not None
        and profiles_data["release_incremental_min"] <= incremental
        <= profiles_data["release_incremental_max"]
    )
    technical_identity = {
        "machine": identity.get("machine") == "aarch64",
        "device": identity.get("device") == profiles_data["device"],
        "sdk": identity.get("sdk") == profiles_data["sdk"],
        "kernel_release": str(identity.get("kernel_release", "")).startswith(
            profiles_data["kernel_release"]
        ),
    }

    profile = profiles_data["profile"]
    names_by_offset: dict[str, list[str]] = {}
    for name, offset in profile["offsets"].items():
        normalized = f"0x{int(offset, 16):08x}"
        names_by_offset.setdefault(normalized, []).append(name)
    anchors = []
    for offset, names in sorted(names_by_offset.items()):
        observation = observed.get(offset)
        if observation:
            anchors.append({
                "offset": offset,
                "names": sorted(names),
                "hits": int(observation["hits"]),
                "workloads": sorted(observation["workloads"]),
            })

    exact_tuple = next(
        (
            item for item in profile["exact_tuples"]
            if incremental == item["incremental"]
            and identity.get("kernel_version") == item["kernel_version"]
        ),
        None,
    )
    if exact_tuple:
        status = "exact"
    elif len(anchors) >= 2:
        status = "compatible"
    else:
        status = "unknown"

    all_technical = all(technical_identity.values())
    write_eligible = (
        status == "exact" and all_technical and release_scope
        and bool(profile["release"])
    )
    candidate = {
        "name": profile["name"],
        "release": bool(profile["release"]),
        "exact_tuple": bool(exact_tuple),
        "anchor_matches": len(anchors),
        "anchor_space": len(names_by_offset),
        "anchors": anchors,
    }
    return {
        "schema": 1,
        "mode": "read-only",
        "catalog": profiles_data["name"],
        "fingerprint_incremental": incremental,
        "release_scope": release_scope,
        "release_scope_19_272": release_scope,
        "release_incremental_min": profiles_data["release_incremental_min"],
        "release_incremental_max": profiles_data["release_incremental_max"],
        "technical_identity": technical_identity,
        "status": status,
        "selected_profile": profile["name"] if status != "unknown" else None,
        "write_eligible": write_eligible,
        "write_eligibility_rule": (
            f"exact tuple may advance directly; a non-exact "
            f"{profiles_data['device']} /19-/272 "
            "build requires at least two unique runtime offset anchors, "
            "then preflight and validation before compatible write"
        ),
        "kaslr_base": next(
            (item["base"] for item in parsed.values() if item["base"]), None
        ),
        "candidate": candidate,
        "workloads": parsed,
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_report(bundle: Path, report: dict[str, Any]) -> None:
    candidate = report["candidate"]
    lines = [
        f"ionstack {report['catalog']} profile diagnosis",
        f"status={report['status']}",
        f"selected_profile={report['selected_profile'] or '-'}",
        f"release_scope_19_272={int(report['release_scope_19_272'])}",
        f"fingerprint_incremental={report['fingerprint_incremental']}",
        f"kaslr_base={report['kaslr_base'] or '-'}",
        f"anchor_matches={candidate['anchor_matches']}",
        f"write_eligible={int(report['write_eligible'])}",
        "",
        "anchors:",
    ]
    for item in candidate["anchors"]:
        lines.append(
            f"  {item['offset']}: names={','.join(item['names'])} "
            f"hits={item['hits']} workloads={','.join(item['workloads'])}"
        )
    lines += ["", report["write_eligibility_rule"]]
    (bundle / "report.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def write_sums(bundle: Path) -> None:
    rows = []
    for path in sorted(bundle.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(f"{digest}  {path.relative_to(bundle)}")
    (bundle / "SHA256SUMS").write_text(
        "\n".join(rows) + "\n", encoding="utf-8"
    )


def analyze_bundle(bundle: Path,
                   profiles_path: Path = DEFAULT_PROFILES) -> dict[str, Any]:
    identity = json.loads(
        (bundle / "identity.json").read_text(encoding="utf-8")
    )
    raw_logs = {
        path.stem: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted((bundle / "raw").glob("*.log"))
    }
    report = analyze(identity, raw_logs, load_profiles(profiles_path))
    write_json(bundle / "report.json", report)
    write_report(bundle, report)
    write_sums(bundle)
    return report


def collect(args: argparse.Namespace) -> int:
    timestamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S%z")
    bundle = (
        Path(args.output)
        if args.output
        else DEFAULT_OUTPUT / timestamp
    )
    raw = bundle / "raw"
    raw.mkdir(parents=True, exist_ok=False)
    target = Path(args.target)
    if not target.is_file():
        raise CommandError(f"missing target binary: {target}; run make first")
    adb(args.serial, ["wait-for-device"], timeout=args.boot_timeout, check=True)
    adb(args.serial, ["push", str(target), REMOTE_TARGET], check=True)
    adb(
        args.serial, ["shell", "chmod", "0755", REMOTE_TARGET],
        check=True,
    )
    identity = {
        "serial": clean(adb(args.serial, ["get-serialno"]).stdout),
        "collected_at": dt.datetime.now().astimezone().isoformat(),
        "boot_id": shell_value(
            args.serial, "cat /proc/sys/kernel/random/boot_id"
        ),
        "machine": shell_value(args.serial, "uname -m"),
        "kernel_release": shell_value(args.serial, "uname -r"),
        "kernel_version": shell_value(args.serial, "uname -v"),
        "device": shell_value(args.serial, "getprop ro.product.device"),
        "sdk": shell_value(
            args.serial, "getprop ro.build.version.sdk"
        ),
        "fingerprint": shell_value(
            args.serial, "getprop ro.build.fingerprint"
        ),
        "selinux_enforce": shell_value(
            args.serial, "cat /sys/fs/selinux/enforce"
        ),
    }
    write_json(bundle / "identity.json", identity)

    common = [
        REMOTE_TARGET, "--discover", f"--sample-ms={args.sample_ms}",
        f"--freq={args.freq}", f"--attempts={args.attempts}",
    ]
    getuid = adb(
        args.serial, ["shell"] + common + ["--workload=getuid"],
        timeout=args.workload_timeout,
    )
    getuid_text = getuid.stdout
    if getuid.stderr:
        getuid_text += "\n=== stderr ===\n" + getuid.stderr
    (raw / "getuid.log").write_text(getuid_text, encoding="utf-8")
    base_match = BASE_RE.search(getuid_text)
    if getuid.returncode != 0 or not base_match:
        analyze_bundle(bundle, Path(args.profiles))
        raise CommandError(
            f"getuid discovery failed; bundle retained at {bundle}"
        )

    base = base_match.group(1)
    for workload in (
        "ashmem-open-close", "ashmem-ioctl", "selinux-enforce"
    ):
        proc = adb(
            args.serial,
            ["shell"] + common
            + [f"--kaslr-base={base}", f"--workload={workload}"],
            timeout=args.workload_timeout,
        )
        text = proc.stdout
        if proc.stderr:
            text += "\n=== stderr ===\n" + proc.stderr
        (raw / f"{workload}.log").write_text(text, encoding="utf-8")

    report = analyze_bundle(bundle, Path(args.profiles))
    print(bundle)
    print(
        f"status={report['status']} "
        f"profile={report['selected_profile']} "
        f"anchors={report['candidate']['anchor_matches']}"
    )
    return 0 if report["status"] in {"exact", "compatible"} else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser(
        "collect", help="collect a read-only device evidence bundle"
    )
    collect_parser.add_argument("--serial", default="")
    collect_parser.add_argument("--target", default=str(DEFAULT_TARGET))
    collect_parser.add_argument("--profiles", default=str(DEFAULT_PROFILES))
    collect_parser.add_argument("--output")
    collect_parser.add_argument("--sample-ms", type=int, default=2500)
    collect_parser.add_argument("--freq", type=int, default=4000)
    collect_parser.add_argument("--attempts", type=int, default=8)
    collect_parser.add_argument("--boot-timeout", type=int, default=180)
    collect_parser.add_argument("--workload-timeout", type=int, default=180)
    collect_parser.set_defaults(handler=collect)
    analyze_parser = sub.add_parser(
        "analyze", help="reanalyze an existing evidence bundle"
    )
    analyze_parser.add_argument("bundle", type=Path)
    analyze_parser.add_argument(
        "--profiles", type=Path, default=DEFAULT_PROFILES
    )
    analyze_parser.set_defaults(
        handler=lambda args: (
            print(json.dumps(
                analyze_bundle(args.bundle, args.profiles), indent=2
            )),
            0,
        )[1]
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.handler(args))
    except (
        CommandError,
        subprocess.TimeoutExpired,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"ionstack-profile-diag: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
