#!/usr/bin/env python3
"""Verify static transport evidence in a thin x86_64 macOS biometrickitd."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
REQUIRED = (
    b"/System/Library/PrivateFrameworks/RemoteServiceDiscovery.framework/",
    b"/System/Library/PrivateFrameworks/BridgeXPC.framework/",
    b"_remote_device_copy_service\0",
    b"_OBJC_CLASS_$_BridgeXPCConnection\0",
    b"com.apple.eos.BiometricKit\0",
    b"com.apple.eos.BiometricKit.ta\0",
    b"initForRemoteService:\0",
    b"activateConnection:\0",
    b"BiometricKitBridgeConnection\0",
    b"BiometricKitBridgeTransport\0",
    b"BiometricKitBridgeServices\0",
    b"sendMessage:\0",
    b"sendMessage:andWaitForReply:\0",
    b"handleEnvelope:\0",
    b"handleEventWithMessage:error:\0",
    b"getBridgeVersion:\0",
    b"getServiceOpened:\0",
    b"setBridgeClientVersion:\0",
    b"performCommand:input:output:capacity:\0",
)

# BiometricKitXPCServerMesa::serviceMatchBridgeWithIterator: first invokes
# getBridgeVersion: and stores its result. Only later, when that version is
# greater than one, it invokes setBridgeClientVersion: with literal version 2.
# This proves method 10 is not a prerequisite for the initial method-0 reply.
GET_BRIDGE_VERSION_SEQUENCE = bytes.fromhex(
    "488b05a9c50f00488b3c034c8b2d5ec60f004901dd"
    "488b35f4ad0f004c89eaff157b960d00"
)
SET_CLIENT_VERSION_TWO_SEQUENCE = bytes.fromhex(
    "488b051bc40f00488b3c03488b3580ac0f00ba02000000ff15f5940d00"
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O header")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_X86_64:
        raise EvidenceError("input is not a thin x86_64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing installed transport evidence: " + ", ".join(missing))
    if data.count(GET_BRIDGE_VERSION_SEQUENCE) != 1:
        raise EvidenceError("missing one exact initial bridge-version call sequence")
    if data.count(SET_CLIENT_VERSION_TWO_SEQUENCE) != 1:
        raise EvidenceError("missing one exact later client-version call sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "service": "com.apple.eos.BiometricKit",
        "directory": "RemoteServiceDiscovery",
        "connection": "BridgeXPCConnection",
        "transport": "BiometricKitBridgeTransport",
        "logical_abi": "methods 0,1,3",
        "setup_order": "method0-before-method10",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("biometrickitd SHA-256 does not match the expected installed slice")
    print("verified installed Intel biometric route: "
          f"sha256={result['sha256']} directory={result['directory']} "
          f"service={result['service']} connection={result['connection']}")


if __name__ == "__main__":
    main()
