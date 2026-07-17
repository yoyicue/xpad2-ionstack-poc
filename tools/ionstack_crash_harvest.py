#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue
"""Collect, correlate, and deduplicate XPad2 crash evidence across reboots.

The collector never triggers the vulnerability.  It can use a surviving
ionstack su daemon or a caller-supplied privileged reader prefix for protected
AEE paths.  Some AEE files are only flushed by a later normal reboot, so watch
mode intentionally supports more than one boot transition.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "results" / "crash-harvest"
STATE_FILE = ".harvest-state.json"
DEFAULT_SU = "/data/local/tmp/su -c"
BOOT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
CRASH_ANCHOR_RE = re.compile(
    r"Unable to handle kernel|Internal error: Oops|Kernel panic|"
    r"BUG: unable to handle|Fatal exception|watchdog.*lockup",
    re.IGNORECASE,
)
PID_RE = re.compile(r"(?:CPU:\s*\d+\s+PID:\s*(\d+)|\[(\d+):[^\]]+\])")
COMM_RE = re.compile(r"(?:Comm:\s*(\S+)|\[\d+:([^\]]+)\])")
MARKER_PID_RE = re.compile(r"\bpid=(\d+)\b")
MARKER_COMM_RE = re.compile(r"\bcomm_marker=([A-Za-z0-9_.-]+)")


TEXT_CHANNELS = {
    "properties": "getprop",
    "boot_identity": (
        "printf 'boot_id='; cat /proc/sys/kernel/random/boot_id; "
        "printf 'uptime='; cat /proc/uptime; "
        "printf 'cmdline='; cat /proc/cmdline; "
        "printf 'bootreason='; getprop ro.boot.bootreason; "
        "printf 'sys_boot_reason='; getprop sys.boot.reason; "
        "printf 'last_boot_reason='; getprop sys.boot.reason.last"
    ),
    "dropbox_system_last_kmsg": "dumpsys dropbox --print SYSTEM_LAST_KMSG",
    "dropbox_system_server_crash": "dumpsys dropbox --print system_server_crash",
    "logcat_all": "logcat -b all -d -v threadtime",
    "logcat_previous": "logcat -L -b all -d -v threadtime",
    "pstore": (
        "for f in /sys/fs/pstore/*; do [ -f \"$f\" ] || continue; "
        "printf '\\n===== %s =====\\n' \"$f\"; cat \"$f\"; done"
    ),
    "proc_last_kmsg": "cat /proc/last_kmsg",
    "aee_plain": (
        "for d in /data/aee_exp /data/vendor/aee_exp /mnt/vendor/aee_exp; do "
        "[ -d \"$d\" ] || continue; find \"$d\" -type f 2>/dev/null | "
        "sort | tail -200 | while IFS= read -r f; do "
        "printf '\\n===== %s =====\\n' \"$f\"; head -c 4194304 \"$f\"; done; done"
    ),
    "aplog_last_kmsg": (
        "find /sdcard/debuglogger/mobilelog /data/debuglogger/mobilelog "
        "/data/tal_log -type f -name '*last_kmsg*' 2>/dev/null | sort | "
        "tail -20 | while IFS= read -r f; do "
        "printf '\\n===== %s =====\\n' \"$f\"; head -c 8388608 \"$f\"; done"
    ),
    "vendor_log_index": (
        "find /data/debuglogger /data/tal_log /data/vendor  -type f "
        "2>/dev/null | sort | tail -2000"
    ),
    "tombstone_anr_index": (
        "find /data/tombstones /data/anr -type f 2>/dev/null | sort | tail -500"
    ),
}

PROTECTED_TEXT_COMMAND = (
    "for d in /data/aee_exp /data/vendor/aee_exp /mnt/vendor/aee_exp "
    "/data/tombstones /data/anr; do [ -d \"$d\" ] || continue; "
    "find \"$d\" -type f 2>/dev/null | sort | tail -500 | "
    "while IFS= read -r f; do printf '\\n===== %s =====\\n' \"$f\"; "
    "head -c 8388608 \"$f\"; done; done"
)
PROTECTED_ARCHIVE_COMMAND = (
    "set --; for p in /data/aee_exp /data/vendor/aee_exp /mnt/vendor/aee_exp "
    "/data/tombstones /data/anr; do [ ! -e \"$p\" ] || set -- \"$@\" \"$p\"; "
    "done; [ \"$#\" -gt 0 ] && toybox tar -cf - \"$@\""
)


class HarvestError(RuntimeError):
    pass


def run_bytes(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, capture_output=True, timeout=timeout, check=False)


def adb_prefix(serial: str) -> list[str]:
    return ["adb"] + (["-s", serial] if serial else [])


def adb_text(serial: str, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        adb_prefix(serial) + args, text=True, errors="replace",
        capture_output=True, timeout=timeout, check=False,
    )


def remote_bytes(serial: str, command: str, timeout: int,
                 privileged_prefix: str | None = None) -> subprocess.CompletedProcess[bytes]:
    remote = command
    if privileged_prefix:
        remote = f"{privileged_prefix} {shlex.quote(command)}"
    return run_bytes(
        adb_prefix(serial) + ["exec-out", "sh", "-c", remote], timeout=timeout
    )


def limited(command: str, maximum_bytes: int) -> str:
    if maximum_bytes <= 0:
        return command
    return f"( {command} ) | head -c {maximum_bytes}"


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\r", "")


def boot_id(serial: str) -> str | None:
    proc = adb_text(
        serial, ["shell", "cat /proc/sys/kernel/random/boot_id"], timeout=15
    )
    value = proc.stdout.replace("\r", "").strip()
    return value if BOOT_ID_RE.fullmatch(value) else None


def wait_for_boot(serial: str, timeout: int) -> str:
    proc = adb_text(serial, ["wait-for-device"], timeout=timeout)
    if proc.returncode != 0:
        raise HarvestError(f"adb wait-for-device failed: {proc.stderr}")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        complete = adb_text(
            serial, ["shell", "getprop sys.boot_completed"], timeout=15
        ).stdout.replace("\r", "").strip()
        current = boot_id(serial)
        if complete == "1" and current:
            return current
        time.sleep(2)
    raise HarvestError(f"boot did not complete within {timeout}s")


def detect_privileged_prefix(serial: str, requested: str | None,
                             auto_root: bool) -> tuple[str | None, str]:
    candidates: list[tuple[str, str]] = []
    if requested:
        candidates.append((requested, "requested"))
    if auto_root and requested != DEFAULT_SU:
        candidates.append((DEFAULT_SU, "ionstack-su"))
    for prefix, label in candidates:
        proc = remote_bytes(serial, "id", timeout=15, privileged_prefix=prefix)
        if proc.returncode == 0 and b"uid=0(root)" in proc.stdout:
            return prefix, label
    return None, "plain-only"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_state(output: Path) -> dict[str, Any]:
    path = output / STATE_FILE
    if not path.exists():
        return {"schema": 1, "last_boot_id": None, "rounds": [], "hashes": {}}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schema": 1, "last_boot_id": None, "rounds": [], "hashes": {}}
    state.setdefault("rounds", [])
    state.setdefault("hashes", {})
    return state


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def marker_values(marker_log: Path | None) -> tuple[int | None, str | None]:
    if not marker_log or not marker_log.is_file():
        return None, None
    text = marker_log.read_text(encoding="utf-8", errors="replace")
    pid_match = MARKER_PID_RE.search(text)
    comm_match = MARKER_COMM_RE.search(text)
    return (
        int(pid_match.group(1)) if pid_match else None,
        comm_match.group(1) if comm_match else None,
    )


def analyze_evidence(texts: dict[str, str], marker_pid: int | None,
                     marker_comm: str | None, previous_boot_id: str | None,
                     current_boot_id: str) -> dict[str, Any]:
    anchors: list[dict[str, Any]] = []
    pids: set[int] = set()
    comms: set[str] = set()
    aee_nonempty = False
    for channel, text in texts.items():
        if channel.startswith("aee") or channel.startswith("protected_aee"):
            aee_nonempty = aee_nonempty or "===== " in text
        channel_anchors = len(CRASH_ANCHOR_RE.findall(text))
        if channel_anchors:
            anchors.append({"channel": channel, "count": channel_anchors})
        for match in PID_RE.finditer(text):
            value = match.group(1) or match.group(2)
            if value:
                pids.add(int(value))
        for match in COMM_RE.finditer(text):
            value = match.group(1) or match.group(2)
            if value:
                comms.add(value)
    reboot_observed = bool(previous_boot_id and previous_boot_id != current_boot_id)
    marker_match = (
        (marker_pid is not None and marker_pid in pids)
        or (marker_comm is not None and marker_comm in comms)
    )
    if marker_match:
        freshness = "fresh-marker-match"
    elif reboot_observed and anchors:
        freshness = "post-reboot-unattributed"
    elif anchors:
        freshness = "crash-found-boot-unknown"
    else:
        freshness = "no-crash-anchor"
    hints = []
    if reboot_observed and not aee_nonempty:
        hints.append(
            "AEE evidence may require one additional normal reboot before it is flushed"
        )
    return {
        "crash_channels": anchors,
        "crash_anchor_count": sum(item["count"] for item in anchors),
        "crash_pids": sorted(pids),
        "crash_comms": sorted(comms),
        "marker_pid": marker_pid,
        "marker_comm": marker_comm,
        "marker_match": marker_match,
        "previous_boot_id": previous_boot_id,
        "current_boot_id": current_boot_id,
        "reboot_observed": reboot_observed,
        "freshness": freshness,
        "hints": hints,
    }


def record_files(round_dir: Path, state: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    known_hashes: dict[str, str] = state["hashes"]
    for path in sorted(round_dir.rglob("*")):
        if not path.is_file() or path.name in {"SHA256SUMS", "manifest.json"}:
            continue
        digest = sha256(path)
        relative = str(path.relative_to(round_dir))
        duplicate_of = known_hashes.get(digest)
        records.append({
            "file": relative,
            "bytes": path.stat().st_size,
            "sha256": digest,
            "duplicate_of": duplicate_of,
        })
        known_hashes.setdefault(digest, f"{round_dir.name}/{relative}")
    return records


def collect_round(args: argparse.Namespace, previous_boot_id: str | None = None) -> Path:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    current = wait_for_boot(args.serial, args.boot_timeout)
    now = dt.datetime.now().astimezone()
    round_name = args.round_name or f"{now.strftime('%Y%m%d-%H%M%S%z')}-{current[:8]}"
    round_dir = output / round_name
    raw_dir = round_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=False)

    state = read_state(output)
    if previous_boot_id is None:
        previous_boot_id = args.previous_boot_id or state.get("last_boot_id")
    privileged_prefix, reader = detect_privileged_prefix(
        args.serial, args.privileged_prefix, not args.no_auto_root
    )
    identity = {
        "schema": 1,
        "serial": args.serial or decode(run_bytes(["adb", "get-serialno"], 15).stdout).strip(),
        "collected_at": now.isoformat(),
        "boot_id": current,
        "previous_boot_id": previous_boot_id,
        "reader": reader,
        "privileged": privileged_prefix is not None,
    }
    write_json(round_dir / "identity.json", identity)

    texts: dict[str, str] = {}
    command_results: dict[str, Any] = {}
    for channel, command in TEXT_CHANNELS.items():
        proc = remote_bytes(
            args.serial, limited(command, args.max_channel_bytes),
            args.channel_timeout,
        )
        text = decode(proc.stdout)
        if proc.stderr:
            text += "\n=== stderr ===\n" + decode(proc.stderr)
        (raw_dir / f"{channel}.log").write_text(text, encoding="utf-8")
        texts[channel] = text
        command_results[channel] = {"returncode": proc.returncode, "reader": "plain"}

    if privileged_prefix:
        proc = remote_bytes(
            args.serial,
            limited(PROTECTED_TEXT_COMMAND, args.max_protected_text_bytes),
            args.protected_timeout,
            privileged_prefix=privileged_prefix,
        )
        text = decode(proc.stdout)
        if proc.stderr:
            text += "\n=== stderr ===\n" + decode(proc.stderr)
        (raw_dir / "protected_aee_tombstone_anr.log").write_text(
            text, encoding="utf-8"
        )
        texts["protected_aee_tombstone_anr"] = text
        command_results["protected_aee_tombstone_anr"] = {
            "returncode": proc.returncode, "reader": reader,
        }
        if args.protected_archive and not args.no_protected_archive:
            archive = remote_bytes(
                args.serial, PROTECTED_ARCHIVE_COMMAND, args.protected_timeout,
                privileged_prefix=privileged_prefix,
            )
            if archive.stdout:
                (round_dir / "protected-crash-files.tar").write_bytes(archive.stdout)
            (raw_dir / "protected_archive.stderr.log").write_text(
                decode(archive.stderr), encoding="utf-8"
            )
            command_results["protected_archive"] = {
                "returncode": archive.returncode, "reader": reader,
                "bytes": len(archive.stdout),
            }

    marker_pid, marker_comm = marker_values(args.marker_log)
    summary = analyze_evidence(
        texts, marker_pid, marker_comm, previous_boot_id, current
    )
    summary.update({
        "schema": 1,
        "reader": reader,
        "privileged": privileged_prefix is not None,
        "commands": command_results,
    })
    write_json(round_dir / "summary.json", summary)
    report_lines = [
        "ionstack crash harvest",
        f"boot_id={current}",
        f"previous_boot_id={previous_boot_id or '-'}",
        f"reader={reader}",
        f"freshness={summary['freshness']}",
        f"crash_anchor_count={summary['crash_anchor_count']}",
        f"marker_match={int(summary['marker_match'])}",
    ]
    report_lines.extend(f"hint={hint}" for hint in summary["hints"])
    (round_dir / "summary.txt").write_text(
        "\n".join(report_lines) + "\n", encoding="utf-8"
    )

    records = record_files(round_dir, state)
    write_json(round_dir / "manifest.json", {"schema": 1, "files": records})
    (round_dir / "SHA256SUMS").write_text(
        "\n".join(f"{item['sha256']}  {item['file']}" for item in records) + "\n",
        encoding="utf-8",
    )
    state["last_boot_id"] = current
    state["rounds"].append({
        "path": round_name,
        "boot_id": current,
        "collected_at": now.isoformat(),
        "freshness": summary["freshness"],
        "crash_anchor_count": summary["crash_anchor_count"],
    })
    write_json(output / STATE_FILE, state)
    print(round_dir)
    print(
        f"freshness={summary['freshness']} anchors={summary['crash_anchor_count']} "
        f"reader={reader}"
    )
    return round_dir


def watch(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    state = read_state(output)
    baseline = state.get("last_boot_id") or wait_for_boot(args.serial, args.boot_timeout)
    print(f"armed boot_id={baseline} rounds={args.rounds}", flush=True)
    for index in range(args.rounds):
        while True:
            current = boot_id(args.serial)
            if current and current != baseline:
                break
            time.sleep(args.poll_interval)
        wait_for_boot(args.serial, args.boot_timeout)
        args.round_name = f"round-{index + 1:02d}-{dt.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S%z')}-{current[:8]}"
        collected = collect_round(args, previous_boot_id=baseline)
        collected_identity = json.loads(
            (collected / "identity.json").read_text(encoding="utf-8")
        )
        baseline = collected_identity["boot_id"]
        print(f"rearmed boot_id={baseline} remaining={args.rounds - index - 1}", flush=True)
    return 0


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--serial", default="")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--previous-boot-id")
    parser.add_argument("--round-name")
    parser.add_argument("--marker-log", type=Path)
    parser.add_argument(
        "--privileged-prefix",
        help="remote prefix that accepts one shell command, e.g. '/data/local/tmp/su -c'",
    )
    parser.add_argument("--no-auto-root", action="store_true")
    parser.add_argument(
        "--protected-archive", action="store_true",
        help="also stream a potentially large tar archive of protected crash files",
    )
    parser.add_argument("--no-protected-archive", action="store_true")
    parser.add_argument("--max-channel-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument(
        "--max-protected-text-bytes", type=int, default=128 * 1024 * 1024
    )
    parser.add_argument("--boot-timeout", type=int, default=300)
    parser.add_argument("--channel-timeout", type=int, default=120)
    parser.add_argument("--protected-timeout", type=int, default=300)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect", help="collect the current boot")
    add_common(collect_parser)
    collect_parser.set_defaults(handler=lambda args: (collect_round(args), 0)[1])
    watch_parser = sub.add_parser("watch", help="collect after each boot-ID change")
    add_common(watch_parser)
    watch_parser.add_argument("--rounds", type=int, default=2)
    watch_parser.add_argument("--poll-interval", type=float, default=2.0)
    watch_parser.set_defaults(handler=watch)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.handler(args))
    except (HarvestError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"ionstack-crash-harvest: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
