#!/usr/bin/env python3
"""Verify the Intel RSD client-side service-socket handoff contract."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007

# remote_service_create_connected_socket builds {cmd: "connect",
# connect_timeout: ...}, sends it synchronously to the service-specific XPC
# endpoint, duplicates the returned "fd", then only polls that fd for connect.
CONNECT_REQUEST_SEQUENCE = bytes.fromhex(
    "31ff31f631d2e8c74e0000"      # xpc_dictionary_create(NULL, NULL, 0)
    "4989c6"
    "488d35b5550000"            # "cmd"
    "488d15b2550000"            # "connect"
    "4889c7e8f04e0000"          # xpc_dictionary_set_string
    "418b542428"
    "488d35a6550000"            # "connect_timeout"
    "4c89f7e8e24e0000"          # xpc_dictionary_set_uint64
    "498b7c24184c89f6e8694e0000" # synchronous request on per-service endpoint
)
RETURNED_FD_SEQUENCE = bytes.fromhex(
    "488d357b550000"            # "fd"
    "4c89ffe8654e0000"          # xpc_dictionary_dup_fd
    "83f8ff74354189c5"
    "e8a9c4ffff4889c3"
    "4489ef4889c6e88d390000"    # remote_socket_poll_connect_sync(fd, log)
)
REQUIRED_STRINGS = (
    b"cmd\0connect\0connect_timeout\0fd\0",
    b"remote_service_create_connected_socket\0",
    b"remote_socket_poll_connect_sync\0",
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
        raise EvidenceError("input lacks the service-socket symbols/keys")
    if data.count(CONNECT_REQUEST_SEQUENCE) != 1:
        raise EvidenceError("input lacks one exact service CONNECT request sequence")
    if data.count(RETURNED_FD_SEQUENCE) != 1:
        raise EvidenceError("input lacks one exact returned-fd polling sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "request_keys": "cmd,connect_timeout",
        "reply_key": "fd",
        "post_handoff": "poll-connect-only",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("RSD framework SHA-256 does not match expected image")
    print("verified Intel RSD service socket handoff: "
          f"sha256={result['sha256']} request_keys={result['request_keys']} "
          f"reply_key={result['reply_key']} post_handoff={result['post_handoff']}")


if __name__ == "__main__":
    main()
