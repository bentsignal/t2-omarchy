#!/usr/bin/env python3
"""Verify the legacy bridgeOS BridgeXPC handshake state machine."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct


MH_MAGIC = 0xFEEDFACE
CPU_TYPE_ARM = 12
CPU_SUBTYPE_ARM_V7K = 12

# -connected requires state 2, writes state 3, then invokes writeHELO,
# readMessage, and flushQueue. Selector references vary with cache layout, so
# this pins the surrounding state transition and the three consecutive calls.
CONNECTED_2_TO_3 = bytes.fromhex(
    "0068215802291ed147f6ee310322c0f24301225079442046096804f086eb"
    "47f6e030c0f2430078440168204604f07eeb47f6d230c0f243007844"
    "01682046bde8d04004f01aba"
)

# -send: accepts only states 1, 2, and 3. States 1/2 queue the message; state 3
# writes it. The exact call targets are deliberately included.
SEND_STATE_1_2_3 = bytes.fromhex(
    "2858032800f09f8002284dd0012840f0fd80"
)

# The completed payload reader compares the frame kind with 1 (HELO), then 2
# (ordinary message). The kind-1 arm maps the payload, asks Foundation to
# deserialize it with option 4, logs it, releases it, and joins the common read
# continuation; there is no JSON-field comparison or state mutation in it.
FRAME_KIND_1_THEN_2 = bytes.fromhex(
    "dbf82400012800f0f28041f2ae550228c0f231057d442d682d6840f05181"
)
HELO_DESERIALIZE_PREFIX = bytes.fromhex(
    "46f2cc30c0f2430046f2a642c0f2430278447a440168106802f09cef"
    "46f220414246c0f2430104237944096802f092ef"
)

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
    if struct.unpack_from("<III", data) != (
            MH_MAGIC, CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K):
        raise EvidenceError("input is not a thin armv7k Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in data]
    if missing:
        raise EvidenceError("missing BridgeXPC evidence: " + ", ".join(missing))
    sequences = (
        (CONNECTED_2_TO_3, "connected state transition"),
        (SEND_STATE_1_2_3, "send state dispatch"),
        (FRAME_KIND_1_THEN_2, "HELO/message kind dispatch"),
        (HELO_DESERIALIZE_PREFIX, "HELO deserialization"),
    )
    for sequence, label in sequences:
        if data.count(sequence) != 1:
            raise EvidenceError(f"missing one exact {label} sequence")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "architecture": "armv7k",
        "connect": "state2-to-state3-writeHELO-readMessage-flushQueue",
        "send": "states1-and2-queue-state3-write",
        "receive": "kind1-HELO-kind2-message",
        "helo": "deserialize-and-log-no-field-gate",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--expect-sha256", default="")
    args = parser.parse_args()
    result = inspect(args.binary.read_bytes())
    if args.expect_sha256 and result["sha256"] != args.expect_sha256.lower():
        raise SystemExit("BridgeXPC SHA-256 does not match expected firmware")
    print("verified legacy bridgeOS BridgeXPC: " + " ".join(
        f"{key}={value}" for key, value in result.items()))


if __name__ == "__main__":
    main()
