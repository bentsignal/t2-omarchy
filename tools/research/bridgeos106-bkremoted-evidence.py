#!/usr/bin/env python3
"""Verify current bridgeOS 10.6 bkremoted method-zero behavior."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C

# -[BiometricKitBridge getBridgeVersion:] checks only for a non-null output
# pointer, stores literal version 3, clears clientVersion at self+0x48, and
# returns status zero.
UNCONDITIONAL_VERSION_REPLY = bytes.fromhex(
    "940000b468008052880200f97f2600f9e80f40f9490000f0296941f9"
    "290140f93f0108ebe100005400008052")

# -[BiometricKitBridgeServices getBridgeVersion:] calls the implementation,
# boxes its signed status and unsigned version, and creates a two-item array.
TWO_NUMBER_REPLY = bytes.fromhex(
    "000840f9e20300911f070094e20300aa330000f0601240f9cb070094"
    "fd031daaf8050094f40300aae00700f9601240f9e20340f9e4070094"
    "fd031daaf1050094f50300aae00b00f9280000f0006540f9e2230091"
    "4300805263060094fd031daae8050094")

# -performMessage: accepts integer methods through 12 and dispatches method 0
# directly to getBridgeVersion: through its jump table.
METHOD_ZERO_DISPATCH = bytes.fromhex(
    "df3200f128160054080000f008e11391890000100a69763829090a8b"
    "20011fd6e00314aae20313aa29080094fd031daa06070094")

REQUIRED = (
    b"BiometricKitBridge\0",
    b"BiometricKitBridgeServices\0",
    b"performMessage:\0",
    b"getBridgeVersion:\0",
    b"setBridgeClientVersion:\0",
    b"getBridgeVersion: <- %p -> 0\n\0",
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise EvidenceError("input is not a thin arm64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing current bridge daemon evidence: " +
                            ", ".join(missing))
    sequences = (
        (UNCONDITIONAL_VERSION_REPLY, "unconditional version reply"),
        (TWO_NUMBER_REPLY, "two-number reply construction"),
        (METHOD_ZERO_DISPATCH, "method-zero dispatch"),
    )
    for sequence, label in sequences:
        if data.count(sequence) != 1:
            raise EvidenceError(f"missing one exact {label} sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "architecture": "arm64",
        "bridgeos": "10.6-23P6068",
        "source_version": "10252.100.11.0.0",
        "method0": "unconditional-status0-version3",
        "reply": "array-int32-status-uint64-version",
        "dispatch": "method0-direct-no-biometric-state-gate",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("bkremoted SHA-256 does not match expected firmware")
    print("verified current bridgeOS bkremoted: " + " ".join(
        f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
