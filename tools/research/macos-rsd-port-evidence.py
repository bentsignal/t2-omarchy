#!/usr/bin/env python3
"""Verify the installed Intel remoted's fixed RSD NCM listener port."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
RSD_PORT = 58783
# lea -0x46(%rbp),%rax; movw $0xe59f,(%rax). The immediate bytes are 9f e5.
PORT_STORE = b"\x48\x8d\x45\xba\x66\xc7\x00\x9f\xe5"
REQUIRED = (b"RSDRemoteNCMDeviceDevice\0", b"createPortListener\0", PORT_STORE)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str | int]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise EvidenceError("input is not a thin x86_64 Mach-O")
    if b"RSDRemoteNCMDeviceDevice\0" not in data or b"createPortListener\0" not in data:
        raise EvidenceError("input lacks the NCM-device listener class/method")
    if data.count(PORT_STORE) != 1:
        raise EvidenceError("input lacks one exact RSD port-58783 store")
    return {"sha256": hashlib.sha256(data).hexdigest(), "port": RSD_PORT}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("remoted SHA-256 does not match the expected installed slice")
    print(f"verified installed Intel RSD listener: sha256={result['sha256']} "
          f"class=RSDRemoteNCMDeviceDevice method=createPortListener port={result['port']}")


if __name__ == "__main__":
    main()
