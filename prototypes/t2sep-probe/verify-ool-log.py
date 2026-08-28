#!/usr/bin/env python3
"""Verify one cursor-bounded OOL acknowledgement transcript from stdin."""

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


def verify(text: str) -> tuple[tuple[int, int], tuple[int, int]]:
    if not isinstance(text, str):
        raise VerificationError("OOL transcript must be text")
    phase = "discovery"
    pending: tuple[int, int] | None = None
    profiles: list[tuple[int, int]] = []
    stopped = False
    cleaned = False

    for line in text.splitlines():
        if "t2sep_probe" not in line:
            continue
        if any(marker in line for marker in (
                "transport error", "timed out", "failed:", "result=-")):
            raise VerificationError("transcript contains a failure marker")
        if "bounded discovery complete:" in line:
            if phase != "discovery" or "sbio=yes limits=yes result=0" not in line:
                raise VerificationError("OOL session lacks successful usable sbio discovery")
            phase = "registration"
            continue
        match = REQUEST.search(line)
        if match:
            if phase != "registration" or pending is not None or stopped:
                raise VerificationError("registration request is out of order")
            opcode, tag = int(match[1]), int(match[2])
            expected_opcode = 2 + len(profiles)
            if opcode != expected_opcode or tag == 0:
                raise VerificationError("registration opcode/tag sequence is invalid")
            word0, page, size = (int(match[index], 16) for index in (3, 4, 5))
            expected_size = 0x4000 if opcode == 2 else 0x4B000
            if word0 != (0x08 << 24 | opcode << 16 | tag << 8) or not page or size != expected_size:
                raise VerificationError("registration request words are not the recovered sbio shape")
            pending = opcode, tag
            continue
        match = ACK.search(line)
        if match:
            if phase != "registration" or pending is None or stopped:
                raise VerificationError("acknowledgement has no ordered request")
            request_opcode, tag = int(match[1]), int(match[2])
            words = tuple(int(match[index], 16) for index in (3, 4, 5, 6))
            decoded = tuple(int(match[index]) for index in (7, 8, 9, 10))
            if (request_opcode, tag) != pending:
                raise VerificationError("acknowledgement request correlation changed")
            endpoint = words[0] & 0xFF
            wire_tag = (words[0] >> 8) & 0xFF
            opcode = (words[0] >> 16) & 0xFF
            target = (words[0] >> 24) & 0xFF
            if decoded != (endpoint, wire_tag, opcode, target):
                raise VerificationError("decoded acknowledgement fields disagree with raw words")
            if endpoint != 0 or wire_tag != tag or words[1] != 0:
                raise VerificationError("acknowledgement endpoint/tag/status validation failed")
            if words[3] & ((1 << 18) | (1 << 19)):
                raise VerificationError("acknowledgement has transport error flags")
            profiles.append((opcode, target))
            pending = None
            continue
        if "issued Apple CPU-stop value 5" in line:
            if pending is not None or len(profiles) != 2 or stopped:
                raise VerificationError("transport stopped before both acknowledgements")
            stopped = True
            continue
        if "OOL buffers scrubbed and released after CPU stop; result=0" in line:
            if not stopped or cleaned:
                raise VerificationError("OOL cleanup is missing, duplicated, or before stop")
            cleaned = True

    if phase != "registration" or pending is not None or len(profiles) != 2:
        raise VerificationError("transcript does not contain exactly two complete registrations")
    if not stopped or not cleaned:
        raise VerificationError("transcript lacks ordered stop and successful cleanup")
    return profiles[0], profiles[1]


def main() -> None:
    try:
        incoming, outgoing = verify(sys.stdin.read())
    except VerificationError as error:
        print(f"OOL verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("verified OOL reply profile: "
          f"in_opcode={incoming[0]} in_target={incoming[1]} "
          f"out_opcode={outgoing[0]} out_target={outgoing[1]}")


if __name__ == "__main__":
    main()
