#!/usr/bin/env python3
"""Verify the architecture split at Apple's SEP endpoint message ABI."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C

# Intel AppleSEPEndpoint::sendMessage(void *, void *, bool) forwards both
# pointers, but AppleSEPManager::_sendMessageGated never reads the second one.
# It reads a qword and the following dword from the first pointer, inserts the
# endpoint byte, builds a zero fourth word locally, and posts 12 payload bytes.
INTEL_ENDPOINT_FORWARD = bytes.fromhex(
    "4889d04889f24c8b4f708b7760498b394c8b9f78080000440fb6c14c89cf"
    "4889c1"
)
INTEL_FIRST_POINTER_RECORD = bytes.fromhex(
    "458b00488b0a8b42084889ca41f6c00275030fb6164183e0014881e100ffffff"
    "0fb6f24809ce488d55d8488932894208c7420c00000000"
)

# The available arm64e GenericTransfer's sendRawMessage stores only its qword
# argument and calls its endpoint with (&qword, nullptr, true). That proves its
# endpoint ABI cannot establish the Intel-only dword copied after the qword.
ARM_STORE_QWORD = bytes.fromhex("f60301aaf40300aaa1831df8c1feff97")
ARM_ENDPOINT_CALL_ARGS = bytes.fromhex(
    "a1a300d1e00315aa020080d223008052f10308aa1161f5f231093fd7"
)


class EvidenceError(ValueError):
    pass


def _require_macho(data: bytes, cpu: int, label: str) -> None:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError(f"{label} is not a complete Mach-O")
    if struct.unpack_from("<II", data) != (MH_MAGIC_64, cpu):
        raise EvidenceError(f"{label} has the wrong architecture")


def inspect(manager: bytes, generic: bytes) -> dict[str, str]:
    _require_macho(manager, CPU_X86_64, "SEP manager")
    _require_macho(generic, CPU_ARM64, "GenericTransfer")
    sequences = (
        (manager, INTEL_ENDPOINT_FORWARD, "Intel endpoint forwarding"),
        (manager, INTEL_FIRST_POINTER_RECORD, "Intel first-pointer record copy"),
        (generic, ARM_STORE_QWORD, "arm64e qword storage"),
        (generic, ARM_ENDPOINT_CALL_ARGS, "arm64e endpoint call arguments"),
    )
    for binary, sequence, label in sequences:
        if binary.count(sequence) != 1:
            raise EvidenceError(f"missing one exact {label} sequence")
    return {
        "manager_sha256": hashlib.sha256(manager).hexdigest(),
        "generic_sha256": hashlib.sha256(generic).hexdigest(),
        "intel_record": "qword-plus-dword-from-first-pointer",
        "intel_second_pointer": "ignored",
        "arm_call": "qword-pointer-null-true",
        "third_word": "not-established-cross-architecture",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manager", type=Path, help="thin x86_64 AppleSEPManager")
    parser.add_argument("generic", type=Path,
                        help="thin arm64e AppleSEPGenericTransfer")
    args = parser.parse_args()
    result = inspect(args.manager.read_bytes(), args.generic.read_bytes())
    print("verified SEP endpoint ABI split: " + " ".join(
        f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
