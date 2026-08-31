#!/usr/bin/env python3
"""Extract a privacy-safe enrollment command window from a private macOS log."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat


MAX_BYTES = 256 * 1024 * 1024
MAX_LINES = 2_000_000
MAX_LINE_BYTES = 1024 * 1024
WINDOW_RADIUS = 16
ENTRY_TEMPLATE = (
    "performCommand:version:inValue:inData:inSize:outData:outSize: "
    "%u, %u, %u, %p, %zu, %p, %p"
)
EXIT_TEMPLATE = (
    "performCommand:version:inValue:inData:inSize:outData:outSize: -> err:0x%x"
)
ENROLL_TEMPLATE = "enroll:forUser:withOptions:withClient: %d, %u, %@, %@"
ENROLL_EXIT_TEMPLATE = "enroll:forUser:withOptions:withClient: -> err:0x%x"
POINTER = r"(?:0x[0-9a-fA-F]+|\(null\)|0x0)"
ENTRY_PATTERN = re.compile(
    rf"performCommand:version:inValue:inData:inSize:outData:outSize: "
    rf"([0-9]+), ([0-9]+), ([0-9]+), {POINTER}, ([0-9]+), "
    rf"{POINTER}, {POINTER}"
)
EXIT_PATTERN = re.compile(
    r"performCommand:version:inValue:inData:inSize:outData:outSize: "
    r"-> err:0x([0-9a-fA-F]+)"
)
ENROLL_PATTERN = re.compile(
    r"enroll:forUser:withOptions:withClient: (-?[0-9]+), ([0-9]+), .*?, .*",
    re.DOTALL,
)
ENROLL_EXIT_PATTERN = re.compile(
    r"enroll:forUser:withOptions:withClient: -> err:0x([0-9a-fA-F]+)"
)


class LogSanitizerError(ValueError):
    pass


def _signed_status(value: str) -> int:
    parsed = int(value, 16)
    if parsed >= 1 << 31:
        parsed -= 1 << 32
    return parsed


def _open_private(path: Path):
    if not isinstance(path, Path):
        raise LogSanitizerError("private log path must be a Path")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LogSanitizerError("private log must be a readable non-symlink file") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
        or metadata.st_uid not in {0, os.getuid()}
        or not 0 < metadata.st_size <= MAX_BYTES
    ):
        os.close(descriptor)
        raise LogSanitizerError(
            "private log must be bounded, owner-only, and owned by root or this user"
        )
    return os.fdopen(descriptor, "rb")


def _is_biometrickitd(record: dict[str, object]) -> bool:
    image = record.get("processImagePath")
    return isinstance(image, str) and Path(image).name == "biometrickitd"


def sanitize(path: Path) -> dict[str, object]:
    commands: list[dict[str, object]] = []
    enrollment_calls: list[dict[str, object]] = []
    pending_commands: dict[object, list[int]] = {}
    pending_enrollment: dict[object, list[int]] = {}

    with _open_private(path) as stream:
        for line_number, raw_line in enumerate(stream, 1):
            if line_number > MAX_LINES:
                raise LogSanitizerError("private log exceeds the record bound")
            if len(raw_line) > MAX_LINE_BYTES:
                raise LogSanitizerError("private log contains an oversized record")
            try:
                record = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict) or not _is_biometrickitd(record):
                continue
            template = record.get("formatString")
            message = record.get("eventMessage")
            thread = record.get("threadID")
            if (
                not isinstance(template, str)
                or not isinstance(message, str)
                or isinstance(thread, bool)
                or not isinstance(thread, (int, str))
            ):
                continue
            template = template.rstrip("\n")
            message = message.rstrip("\n")

            if template == ENTRY_TEMPLATE:
                match = ENTRY_PATTERN.fullmatch(message)
                if match is None:
                    continue
                command, version, value, input_length = map(int, match.groups())
                commands.append(
                    {
                        "command": f"0x{command:02x}",
                        "version": version,
                        "value": value,
                        "input_length": input_length,
                    }
                )
                pending_commands.setdefault(thread, []).append(len(commands) - 1)
            elif template == EXIT_TEMPLATE:
                match = EXIT_PATTERN.fullmatch(message)
                indexes = pending_commands.get(thread)
                if match is not None and indexes:
                    commands[indexes.pop()]["status"] = _signed_status(match.group(1))
            elif template == ENROLL_TEMPLATE:
                match = ENROLL_PATTERN.fullmatch(message)
                if match is None:
                    continue
                enrollment_calls.append(
                    {"mode": int(match.group(1)), "user_id": int(match.group(2))}
                )
                pending_enrollment.setdefault(thread, []).append(
                    len(enrollment_calls) - 1
                )
            elif template == ENROLL_EXIT_TEMPLATE:
                match = ENROLL_EXIT_PATTERN.fullmatch(message)
                indexes = pending_enrollment.get(thread)
                if match is not None and indexes:
                    enrollment_calls[indexes.pop()]["status"] = _signed_status(
                        match.group(1)
                    )

    windows: list[dict[str, object]] = []
    for index, command in enumerate(commands):
        if command["command"] != "0x03":
            continue
        start = max(0, index - WINDOW_RADIUS)
        end = min(len(commands), index + WINDOW_RADIUS + 1)
        windows.append(
            {
                "command_3_index": index,
                "commands": [
                    {"relative_index": position - index, **commands[position]}
                    for position in range(start, end)
                ],
            }
        )

    return {
        "schema_version": 1,
        "identifiers_redacted": True,
        "raw_values_retained": False,
        "output_capacity_observed": False,
        "total_commands": len(commands),
        "enrollment_calls": enrollment_calls,
        "command_3_windows": windows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_log", type=Path)
    args = parser.parse_args()
    try:
        result = sanitize(args.private_log)
    except (OSError, LogSanitizerError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
