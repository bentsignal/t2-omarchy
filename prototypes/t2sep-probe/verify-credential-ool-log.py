#!/usr/bin/env python3
"""Verify one bounded ACM/AKS OOL acknowledgement transcript from stdin."""

from __future__ import annotations

import re
import sys


class VerificationError(ValueError):
    pass


REQUEST = re.compile(
    r"OOL registration request: opcode=(2|3) tag=(\d+) words="
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) 00000000")
ACK = re.compile(
    r"OOL acknowledgement: request_opcode=(2|3) tag=(\d+) raw="
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) "
    r"decoded_endpoint=(\d+) decoded_tag=(\d+) decoded_opcode=(\d+) decoded_target=(\d+)")


def verify(text: str, expected_endpoint: int
           ) -> tuple[tuple[int, int], tuple[int, int]]:
    if not isinstance(text, str):
        raise VerificationError("credential OOL transcript must be text")
    if expected_endpoint not in (7, 10):
        raise VerificationError("credential endpoint must be AKS 7 or ACM 10")
    nop = False
    pending: tuple[int, int] | None = None
    profiles: list[tuple[int, int]] = []
    stopped = False
    cleaned = False
    for line in text.splitlines():
        if "t2sep_probe" not in line:
            continue
        if any(marker in line for marker in
               ("transport error", "timed out", "failed:", "result=-")):
            raise VerificationError("transcript contains a failure marker")
        if "control NOP response passed strict validation" in line:
            if nop or pending is not None or profiles:
                raise VerificationError("validated NOP is duplicated or out of order")
            nop = True
            continue
        match = REQUEST.search(line)
        if match:
            if not nop or pending is not None or stopped:
                raise VerificationError("credential registration request is out of order")
            opcode, tag = int(match[1]), int(match[2])
            if opcode != 2 + len(profiles) or tag == 0:
                raise VerificationError("credential registration opcode/tag is invalid")
            word0, page, size = (int(match[index], 16) for index in (3, 4, 5))
            if (word0 != (expected_endpoint << 24 | opcode << 16 | tag << 8)
                    or page == 0 or size != 0x4000):
                raise VerificationError("credential registration words are invalid")
            pending = opcode, tag
            continue
        match = ACK.search(line)
        if match:
            if pending is None or stopped:
                raise VerificationError("credential acknowledgement lacks a request")
            request_opcode, tag = int(match[1]), int(match[2])
            words = tuple(int(match[index], 16) for index in (3, 4, 5, 6))
            decoded = tuple(int(match[index]) for index in (7, 8, 9, 10))
            if (request_opcode, tag) != pending:
                raise VerificationError("credential acknowledgement correlation changed")
            fields = (words[0] & 0xff, (words[0] >> 8) & 0xff,
                      (words[0] >> 16) & 0xff, (words[0] >> 24) & 0xff)
            if decoded != fields:
                raise VerificationError("decoded credential acknowledgement disagrees")
            if fields[0] != 0 or fields[1] != tag or words[1] != 0:
                raise VerificationError("credential acknowledgement status/tag failed")
            if words[3] & ((1 << 18) | (1 << 19)):
                raise VerificationError("credential acknowledgement transport failed")
            profiles.append((fields[2], fields[3]))
            pending = None
            continue
        if "issued Apple CPU-stop value 5" in line:
            if pending is not None or len(profiles) != 2 or stopped:
                raise VerificationError("credential transport stopped out of order")
            stopped = True
            continue
        if "OOL buffers scrubbed and released after CPU stop; result=0" in line:
            if not stopped or cleaned:
                raise VerificationError("credential cleanup is out of order")
            cleaned = True
    if not nop or pending is not None or len(profiles) != 2:
        raise VerificationError("credential transcript is incomplete")
    if not stopped or not cleaned:
        raise VerificationError("credential transcript lacks stop and cleanup")
    return profiles[0], profiles[1]


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: verify-credential-ool-log.py ENDPOINT", file=sys.stderr)
        raise SystemExit(2)
    try:
        endpoint = int(sys.argv[1], 0)
        send, receive = verify(sys.stdin.read(), endpoint)
    except (ValueError, VerificationError) as error:
        print(f"credential OOL verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("verified credential OOL reply profile: "
          f"endpoint={endpoint} send_opcode={send[0]} send_target={send[1]} "
          f"receive_opcode={receive[0]} receive_target={receive[1]}")


if __name__ == "__main__":
    main()
