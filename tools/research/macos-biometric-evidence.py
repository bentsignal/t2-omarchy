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
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "service": "com.apple.eos.BiometricKit",
        "directory": "RemoteServiceDiscovery",
        "connection": "BridgeXPCConnection",
        "transport": "BiometricKitBridgeTransport",
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
