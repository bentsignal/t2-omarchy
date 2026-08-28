#!/usr/bin/env python3
"""Verify current Intel BridgeXPC 39 framing in an extracted Mach-O."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
MESSAGE_HEADER_LOAD = b"\x48\xb8\x92\xb8\x01\x00\x02\x00\x00\x00"
HELO_HEADER_LOAD = b"\x48\xb8\x92\xb8\x01\x00\x01\x00\x00\x00"
BINARY_PLIST_FORMAT_LOAD = b"\xb9\xc8\x00\x00\x00\x45\x31\xc0\x45\x31\xc9"
REQUIRED = (
    b"BridgeXPCConnection\0",
    b"HELOMessage\0",
    b"writeHELO\0",
    b"sendMessage:\0",
    b"MaxSupportedProtocolVersion\0",
    b"OSBuild\0",
    b"BridgeXPCVersion\0",
    b"ProcessName\0",
    b"_OBJC_CLASS_$_NSPropertyListSerialization\0",
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str | int]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise EvidenceError("input is not a thin x86_64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing current BridgeXPC evidence: " + ", ".join(missing))
    for marker, label in ((HELO_HEADER_LOAD, "HELO header"),
                          (MESSAGE_HEADER_LOAD, "message header"),
                          (BINARY_PLIST_FORMAT_LOAD, "binary-plist format")):
        if data.count(marker) != 1:
            raise EvidenceError(f"input lacks one exact {label} instruction sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "magic": 0xB892,
        "version": 1,
        "helo_kind": 1,
        "message_kind": 2,
        "plist_format": 0xC8,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("BridgeXPC SHA-256 does not match the expected installed image")
    print("verified current Intel BridgeXPC framing: "
          f"sha256={result['sha256']} magic=0x{result['magic']:04x} "
          f"version={result['version']} helo={result['helo_kind']} "
          f"message={result['message_kind']} plist=0x{result['plist_format']:02x}")


if __name__ == "__main__":
    main()
