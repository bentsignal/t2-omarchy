#!/usr/bin/env python3
"""Verify installed Intel remoted's direct Multiverse service connect path."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007

# RSDRemoteMultiverseDevice::connectToService:withTcpOption: converts the
# advertised port string with atoi, then selects exactly one of these calls.
# The surrounding register assignments pass device, fd-out, uint16 port, and
# errno-out; the timeout form adds tcp_option.connect_timeout.
ATOI_RESULT_SEQUENCE = bytes.fromhex("4889d7e8937402004189c6")
CONNECT_WITH_TIMEOUT_SEQUENCE = bytes.fromhex(
    "418b4f10410fb7d6488d75bc4c8d45b84889c7e882750200"
)
CONNECT_SEQUENCE = bytes.fromhex(
    "410fb7d6488d75bc488d4db84889c7e866750200"
)
REQUIRED_STRINGS = (
    b"RSDRemoteMultiverseDevice\0",
    b"connectToService:withTcpOption:\0",
    b"Attempting to connect to service on port %d\0",
    b"Unable to open socket to service on port %d: %{errno}d\0",
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise EvidenceError("input is not a thin x86_64 Mach-O")
    if any(item not in data for item in REQUIRED_STRINGS):
        raise EvidenceError("input lacks the Multiverse service method/strings")
    for sequence, label in (
            (ATOI_RESULT_SEQUENCE, "port conversion"),
            (CONNECT_WITH_TIMEOUT_SEQUENCE, "timeout connect"),
            (CONNECT_SEQUENCE, "direct connect")):
        if data.count(sequence) != 1:
            raise EvidenceError(f"input lacks one exact {label} sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "class": "RSDRemoteMultiverseDevice",
        "method": "connectToService:withTcpOption:",
        "handoff": "direct-multiverse-connect",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("remoted SHA-256 does not match the expected installed slice")
    print("verified Intel remoted Multiverse service connect: "
          f"sha256={result['sha256']} class={result['class']} "
          f"method={result['method']} handoff={result['handoff']}")


if __name__ == "__main__":
    main()
