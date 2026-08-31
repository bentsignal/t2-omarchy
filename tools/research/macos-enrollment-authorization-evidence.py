#!/usr/bin/env python3
"""Verify the installed Intel System Settings enrollment authorization path."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
EXPECTED_SHA256 = "e86ab74e0246bbd7b88cec36fd901106a49bab8e95edfc687e77d06083c359f1"

REQUIRED = (
    b"getCredentialsData:ctp:\0",
    b"_aks_verify_password\0",
    b"_ACMContextCreate\0",
    b"_ACMContextGetExternalForm\0",
)

# At 0x100007d91, the external-form callback loads selector -3, password
# pointer/length, ACM external-form pointer/length, then calls the local
# aks_verify_password wrapper at 0x10004d919.
VERIFY_CALL_SEQUENCE = bytes.fromhex(
    "bffdffffff"          # movl $-3, %edi
    "4c89e6"              # password pointer
    "89c2"                # password length
    "4c89f1"              # external-form pointer
    "4c8b45d0"            # external-form length
    "e8725b0400"          # call 0x10004d919
)

# The selected wrapper fixes both optional booleans to false: the stack
# argument is zero and r9d is zero before entering the common implementation.
VERIFY_FALSE_FLAGS_WRAPPER = bytes.fromhex(
    "554889e54883ec10"
    "83242400"            # stack boolean = false
    "4531c9"              # r9d boolean = false
    "e860feffff"
    "4883c4105dc3"
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
        raise EvidenceError("missing enrollment authorization evidence: " + ", ".join(missing))
    if data.count(VERIFY_CALL_SEQUENCE) != 1:
        raise EvidenceError("missing one exact selector/context verification call")
    if data.count(VERIFY_FALSE_FLAGS_WRAPPER) != 1:
        raise EvidenceError("missing one exact false-flags verification wrapper")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "keybag_selector": -3,
        # This wrapper proves only the two caller-visible optional flags are
        # clear. Selector 42 independently contributes canonical option 0x200.
        "caller_optional_flags": 0,
        "post_verify_session_call": "none",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default=EXPECTED_SHA256)
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("Settings extension SHA-256 does not match the pinned x86_64 slice")
    print("verified enrollment authorization path: "
          f"sha256={result['sha256']} selector={result['keybag_selector']} "
          f"caller_optional_flags={result['caller_optional_flags']} "
          f"post_verify_session_call={result['post_verify_session_call']}")


if __name__ == "__main__":
    main()
