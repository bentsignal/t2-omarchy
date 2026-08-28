#!/usr/bin/env python3
"""Verify Catalina Intel BiometricKit match-command evidence offline."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007

DAEMON_STRINGS = (
    b"BiometricMatchOperationMesa\0",
    b"performMatchCommand:\0",
    b"performEnrollCommand:\0",
    b"performPresenceDetectCommand:\0",
    b"performCancelCommand\0",
    b"performGetIdentitiesListCommand:outBuffer:\0",
    b"performRemoveIdentityCommand:\0",
    b"performRequestMaxIdentityCountCommand:\0",
    b"performGetFreeIdentityCountCommand:outCount:\0",
    b"performCommand:inValue:inData:inSize:outData:outSize:\0",
    b"processedFlags\0",
    b"userID\0",
    b"forCredentialSet\0",
    b"forExtendEnrollment\0",
    b"noBioLockout\0",
    b"matchResult:timestamp:\0",
)

# These are address-independent instruction runs from Mesa-605.100.11 in
# biometrickitd 19H15. They jointly prove the zeroed 68-byte input and command
# constants without depending on disassembler output or symbol addresses.
DAEMON_PATTERNS = {
    "zeroed 48-byte enrollment input": bytes.fromhex(
        "0f57c00f2945c00f2945b00f2945a04885c00f84ca000000"),
    "enrollment command 3 with 48-byte input": bytes.fromhex(
        "31c041b9300000004c89e7ba03000000b9000000004989d85050"),
    "zeroed 68-byte match input": bytes.fromhex(
        "0f57c00f2945b00f2945a00f2945900f294580c745c000000000"),
    "match command 4 with 68-byte input": bytes.fromhex(
        "31c04c8d458041b9440000004c89e7ba04000000b9000000005050"),
    "presence command 0x26 without input": bytes.fromhex(
        "31c04889dfba26000000b9000000004531c04531c95050"),
    "cancel command 0x0c without input": bytes.fromhex(
        "31c04c89f7ba0c000000b9000000004531c04531c95050"),
    "legacy wrapper supplies version 1": bytes.fromhex(
        "0fb7d3450fb7c44c89efb901000000"),
    "match result has 0xc70 base and count at 0xc6c": bytes.fromhex(
        "418b8d6c0c0000488d0c8d700c00004839c8"),
    "identity list command 0x42 with 4-byte user ID": bytes.fromhex(
        "41b9040000004c89ffba42000000b9000000004d89e0415650"),
    "identity list uses 20-byte records": bytes.fromhex(
        "48bacdcccccccccccccc4889c848f7e248c1ea024883e2fc"),
    "remove identity command 0x0d with 20-byte record": bytes.fromhex(
        "41b9140000004c89f7ba0d000000b9000000005050"),
    "maximum identity count command 0x0f": bytes.fromhex(
        "ba0f000000b9000000004531c04531c9"),
    "free identity count command 0x41 with 4-byte user ID": bytes.fromhex(
        "41b9040000004c89f7ba41000000b9000000005350"),
}

SUPPORT_STRINGS = (
    b"BiometricMatchOperation\0",
    b"processedFlags\0",
    b"setProcessedFlags:\0",
    b"userID\0",
    b"forCredentialSet\0",
    b"noBioLockout\0",
)
SUPPORT_PATTERNS = {
    "default user IDs are UINT32_MAX": bytes.fromhex(
        "baffffffff891408488b0d"),
}


class CommandEvidenceError(ValueError):
    pass


def _thin_x86_64(data: bytes, label: str) -> None:
    if not isinstance(data, bytes) or len(data) < 32:
        raise CommandEvidenceError(f"{label} is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise CommandEvidenceError(f"{label} is not a thin x86_64 Mach-O")


def _require(data: bytes, strings: tuple[bytes, ...],
             patterns: dict[str, bytes], label: str) -> None:
    missing_strings = [item.rstrip(b"\0").decode() for item in strings
                       if item not in data]
    missing_patterns = [name for name, pattern in patterns.items()
                        if data.count(pattern) != 1]
    if missing_strings or missing_patterns:
        details = missing_strings + missing_patterns
        raise CommandEvidenceError(f"missing or ambiguous {label} evidence: "
                                   + ", ".join(details))


def inspect(daemon: bytes, support: bytes) -> dict[str, object]:
    _thin_x86_64(daemon, "biometrickitd")
    _thin_x86_64(support, "BiometricSupport")
    _require(daemon, DAEMON_STRINGS, DAEMON_PATTERNS, "daemon command")
    _require(support, SUPPORT_STRINGS, SUPPORT_PATTERNS, "operation default")
    return {
        "daemon_sha256": hashlib.sha256(daemon).hexdigest(),
        "support_sha256": hashlib.sha256(support).hexdigest(),
        "command_version": 1,
        "enroll_command": 3,
        "enroll_payload_size": 48,
        "match_command": 4,
        "match_payload_size": 68,
        "ordinary_processed_flags": 0,
        "default_user_id": 0xFFFFFFFF,
        "presence_command": 0x26,
        "cancel_command": 0x0C,
        "identity_list_command": 0x42,
        "identity_record_size": 20,
        "remove_identity_command": 0x0D,
        "max_identity_count_command": 0x0F,
        "free_identity_count_command": 0x41,
        "match_result_base_size": 0xC70,
        "match_result_lotl_count_offset": 0xC6C,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("biometrickitd", type=Path)
    parser.add_argument("biometric_support", type=Path)
    args = parser.parse_args()
    result = inspect(args.biometrickitd.read_bytes(),
                     args.biometric_support.read_bytes())
    print("verified Catalina Intel biometric commands: "
          f"enroll={result['enroll_command']} match={result['match_command']} "
          f"match_payload={result['match_payload_size']} "
          f"presence={result['presence_command']:#x} cancel={result['cancel_command']:#x} "
          f"daemon_sha256={result['daemon_sha256']}")


if __name__ == "__main__":
    main()
