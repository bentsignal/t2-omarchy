#!/usr/bin/env python3
"""Verify the bridgeOS-side method-zero dispatch and reply implementation."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC = 0xFEEDFACE
CPU_TYPE_ARM = 12
CPU_SUBTYPE_ARM_V7K = 12

# BiometricKitBridge::getBridgeVersion: checks only whether the output pointer
# is non-null, stores literal version 2, clears _clientVersion, and returns 0.
# The sequence occurs once in bridgeOS 3.0 (14Y910) bkremoted.
UNCONDITIONAL_VERSION_REPLY = bytes.fromhex(
    "55b148f6a8700221c0f2000029607844002100684af80010"
)
# BiometricKitBridgeConnection::performMessage: accepts method values 0..10
# and dispatches through its jump table. Method zero therefore has no prior
# service-open or client-version state gate in this daemon.
METHOD_DISPATCH_0_TO_10 = bytes.fromhex("b8f10a0f5ad8dfe808f0")
REQUIRED = (
    b"BiometricKitBridgeConnection\0",
    b"BiometricKitBridgeTransport\0",
    b"performMessage:\0",
    b"getBridgeVersion:\0",
    b"setBridgeClientVersion:\0",
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O")
    magic, cpu_type, cpu_subtype = struct.unpack_from("<III", data)
    if (magic, cpu_type, cpu_subtype) != (
            MH_MAGIC, CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K):
        raise EvidenceError("input is not a thin armv7k Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing bridge daemon evidence: " + ", ".join(missing))
    if data.count(UNCONDITIONAL_VERSION_REPLY) != 1:
        raise EvidenceError("missing one exact unconditional version-reply sequence")
    if data.count(METHOD_DISPATCH_0_TO_10) != 1:
        raise EvidenceError("missing one exact method 0..10 dispatch sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "architecture": "armv7k",
        "method0": "unconditional-status0-version2",
        "dispatch": "methods0-through10",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("bkremoted SHA-256 does not match expected firmware")
    print("verified bridgeOS bkremoted: " + " ".join(
        f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
