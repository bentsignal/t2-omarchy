#!/usr/bin/env python3
"""Verify installed Intel remoted's named NCM Bonjour endpoint construction."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
# needsConnect: three RIP-relative LEAs of "ncm", "_remoted._tcp", "local.",
# followed by nw_endpoint_create_bonjour_service and retention of its result.
BONJOUR_ENDPOINT_SEQUENCE = bytes.fromhex(
    "488d3deaa70400"
    "488d35e7a70400"
    "488d15eea70400"
    "e880c00300"
    "4989c7"
)
REQUIRED_STRINGS = (
    b"RSDRemoteNCMHostDevice\0",
    b"needsConnect\0",
    b"ncm\0_remoted._tcp\0local.\0",
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
        raise EvidenceError("input lacks the NCM host Bonjour class/method/strings")
    if data.count(BONJOUR_ENDPOINT_SEQUENCE) != 1:
        raise EvidenceError("input lacks one exact named Bonjour endpoint sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "instance": "ncm",
        "service": "_remoted._tcp",
        "domain": "local.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("remoted SHA-256 does not match the expected installed slice")
    print("verified Intel remoted NCM bootstrap: "
          f"sha256={result['sha256']} "
          f"instance={result['instance']} service={result['service']} "
          f"domain={result['domain']}")


if __name__ == "__main__":
    main()
