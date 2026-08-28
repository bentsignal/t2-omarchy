#!/usr/bin/env python3
"""Verify the current bridgeOS 10.6 BridgeXPC 39 state machine."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C

# -connected: state 2 -> state 3, writeHELO, readMessage, flushQueue.
CONNECTED_2_TO_3 = bytes.fromhex(
    "1f0900f16101005468008052681200f9e00313aa221a0094e00313aa"
    "b0190094e00313aafd7b41a9f44fc2a804190014")

# -send: accepts state 3 directly, queues in state 2, and triggers a connect
# then queues in state 1. All other states enter the invalid-state path.
SEND_STATE_1_2_3 = bytes.fromhex(
    "881240f91f0d00f1a00600541f0900f1400300541f0500f1c10a0054")

# Completed-body dispatch loads the frame kind, branches on kind 1 (HELO),
# then kind 2 (ordinary message).
FRAME_KIND_1_THEN_2 = bytes.fromhex(
    "883240b91f050071800500541f09007161090054")

# The complete kind-1 arm initializes NSString with encoding 4, logs it, then
# falls through to the common readMessage continuation. It contains no store
# to the connection state at self+0x20 and no HELO-field comparison.
HELO_DESERIALIZE_AND_REJOIN = bytes.fromhex(
    "284f02f000d941f90b9e2595e20313aa830080524a150094f50300aa"
    "9cfcff97fd031daa439e2595f60300aa210080526a9e259540020034"
    "881240f9090000f0209146fde00300bde84300f808088152e81b0079"
    "f5e300f8e0ffffb0000000912300009063c42091e4030091e10316aa"
    "22008052c5028052b99d2595159e2595119e2595801240f9bd150094")

REQUIRED = (
    b"BridgeXPCConnection\0",
    b"writeHELO\0",
    b"readMessage\0",
    b"flushQueue\0",
    b"Received HELO message: %@\0",
    b"Send pended on connect, enqueueing message\0",
    b"Pushing %d queued messages\0",
)


class EvidenceError(ValueError):
    pass


def inspect(data: bytes) -> dict[str, str]:
    if not isinstance(data, bytes) or len(data) < 32:
        raise EvidenceError("input is not a complete Mach-O")
    magic, cpu_type = struct.unpack_from("<II", data)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise EvidenceError("input is not a thin arm64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing BridgeXPC 39 evidence: " + ", ".join(missing))
    sequences = (
        (CONNECTED_2_TO_3, "connected state transition"),
        (SEND_STATE_1_2_3, "send state dispatch"),
        (FRAME_KIND_1_THEN_2, "HELO/message kind dispatch"),
        (HELO_DESERIALIZE_AND_REJOIN, "HELO deserialize/rejoin path"),
    )
    for sequence, label in sequences:
        if data.count(sequence) != 1:
            raise EvidenceError(f"missing one exact {label} sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "architecture": "arm64",
        "bridgeos": "10.6-23P6068",
        "bridge_xpc": "39",
        "connect": "state2-to-state3-writeHELO-readMessage-flushQueue",
        "send": "states1-and2-queue-state3-write",
        "receive": "kind1-HELO-kind2-message",
        "helo": "deserialize-and-log-no-field-or-state-gate",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("BridgeXPC SHA-256 does not match expected firmware")
    print("verified current bridgeOS BridgeXPC: " + " ".join(
        f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
