#!/usr/bin/env python3
"""Verify Intel remoted's fixed internal-T2 Multiverse directory bootstrap."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
DIRECTORY_PORT = 59602
MULTIVERSE_CONNECT_SEQUENCE = bytes.fromhex(
    "4889c7"          # movq %rax, %rdi
    "4c89fe"          # movq %r15, %rsi
    "bad2e80000"      # movl $0xe8d2, %edx
    "4c89e1"          # movq %r12, %rcx
    "e81e780100"      # callq _multiverse_device_connect stub
)
REQUIRED_STRINGS = (
    b"RSDRemoteMultiverseHostDevice\0",
    b"needsConnect\0",
    b"MultiverseHost\0",
    b"localbridge\0",
    b"multiverse_device_connect() completed successfully\0",
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str | int]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise EvidenceError("input is not a thin x86_64 Mach-O")
    if any(item not in data for item in REQUIRED_STRINGS):
        raise EvidenceError("input lacks the Multiverse host class/method/strings")
    if data.count(MULTIVERSE_CONNECT_SEQUENCE) != 1:
        raise EvidenceError("input lacks one exact Multiverse directory connect sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "class": "RSDRemoteMultiverseHostDevice",
        "method": "needsConnect",
        "port": DIRECTORY_PORT,
        "transport": "multiverse-internal-device",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("remoted SHA-256 does not match the expected installed slice")
    print("verified Intel remoted internal-T2 bootstrap: "
          f"sha256={result['sha256']} class={result['class']} "
          f"method={result['method']} transport={result['transport']} "
          f"port={result['port']}")


if __name__ == "__main__":
    main()
