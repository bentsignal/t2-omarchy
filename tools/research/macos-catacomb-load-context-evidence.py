#!/usr/bin/env python3
"""Verify current Intel macOS catacomb-load ABI and sensor prerequisites."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
EXPECTED_SHA256 = "248d4521007f95c916ae682c1a3d13d1c431626f4be4e84a0758d6dfbc94ce20"

REQUIRED = (
    b"performLoadCatacombCommand:inData:\0",
    b"performCommand:version:inValue:inData:inSize:outData:outSize:\0",
    b"performCommand:inValue:inData:inSize:outData:outSize:\0",
    b"checkSensorReadiness\0",
    b"cachePatch\0",
    b"provisioningState\0",
    b"resetSensor\0",
    b"cacheSensorInfo\0",
    b"setCalibrationData:source:\0",
    b"setMSRkData:\0",
    b"cacheAccessories\0",
    b"loadCatacomb\0",
)

# Address-independent instruction runs from installed 25G83 biometrickitd.
# The load zeroes both stack output arguments, sets command 0x40 and inValue 0,
# then passes NSData bytes/length in r8/r9 to the compatibility wrapper.
LOAD_COMMAND = bytes.fromhex(
    "0f57c00f1104244531ed4c89ffba4000000031c94d89e04989c1ffd3")

# The compatibility wrapper inserts command version 1 before forwarding all
# six original arguments to the explicit-version method.
VERSION_ONE_WRAPPER = bytes.fromhex(
    "410fb7d5450fb7c74c89e7b9010000004d89f1ff7518ff7510ff75c8")

# Pre-load sensor context established on the successful startup path.
READINESS_COMMAND = bytes.fromhex(
    "4889dfba5300000031c94531c04531c9415250")
PATCH_COMMAND = bytes.fromhex(
    "0f57c00f1104244c89efba2400000031c94989d84d89f9")
PROVISIONING_COMMAND = bytes.fromhex(
    "ba1000000031c94531c04531c9415250")
RESET_COMMAND = bytes.fromhex(
    "0f57c00f1104244889dfba02000000b9020000004531c04531c9")
SENSOR_INFO_COMMAND = bytes.fromhex(
    "41b90c0000004889dfba3500000031c9")
CALIBRATION_COMMAND = bytes.fromhex(
    "0f57c00f110424410fb7ce488b7da8ba200000004d89e84989c1")
MSRK_COMMAND = bytes.fromhex(
    "0f57c00f1104244c89f7ba5c00000031c94d89e04989c1")

# Only service statuses 0x8002/0x8003 and 0x192 are normalized to daemon
# status 0x10d. Status 0x101 (257) is returned unchanged.
LOAD_STATUS_MAPPING = bytes.fromhex(
    "4489e883e0fe3d02800000b80d0100004589ef440f44f8"
    "4181fd92010000440f44f8")


class EvidenceError(ValueError):
    pass


SEQUENCES = (
    READINESS_COMMAND,
    PATCH_COMMAND,
    PROVISIONING_COMMAND,
    RESET_COMMAND,
    SENSOR_INFO_COMMAND,
    CALIBRATION_COMMAND,
    MSRK_COMMAND,
    LOAD_COMMAND,
    VERSION_ONE_WRAPPER,
    LOAD_STATUS_MAPPING,
)


def inspect(data: bytes) -> dict[str, str | int]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise EvidenceError("input is not a thin x86_64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing catacomb-load evidence: " + ", ".join(missing))
    for sequence in SEQUENCES:
        if data.count(sequence) != 1:
            raise EvidenceError("missing one exact catacomb-load instruction sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "command": 0x40,
        "version": 1,
        "in_value": 0,
        "output_size": 0,
        "status_257": "unchanged",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default=EXPECTED_SHA256)
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("biometrickitd SHA-256 does not match the pinned x86_64 slice")
    print("verified current catacomb load context: "
          f"sha256={result['sha256']} command=0x{result['command']:x} "
          f"version={result['version']} in_value={result['in_value']} "
          f"output_size={result['output_size']} status_257={result['status_257']}")


if __name__ == "__main__":
    main()
