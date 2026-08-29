#!/usr/bin/env python3
"""Verify one cursor-bounded Intel T2 control-NOP probe transcript."""

from __future__ import annotations

import re
import sys


class VerificationError(ValueError):
    pass


RESPONSE = re.compile(
    r"control NOP response after (\d+) ms: "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})")
MSI = re.compile(r"MSI observations: vector0=(\d+) vector1=(\d+)")


def verify(text: str) -> int:
    if not isinstance(text, str):
        raise VerificationError("control-NOP transcript must be text")
    state = 0
    latency = None
    for line in text.splitlines():
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        if any(marker in line for marker in
               ("transport error", "timed out", "failed", "skipped")):
            raise VerificationError("control-NOP transcript contains a failure marker")
        if any(marker in line for marker in
               ("OOL registration", "pinned OOL buffers", "discovery candidate",
                "bounded discovery complete", "AKS capabilities")):
            raise VerificationError("control-NOP transcript contains another operation")
        if "temporarily enabled PCI memory decoding for this probe" in line:
            if state != 0:
                raise VerificationError("PCI enable is duplicated or out of order")
            state = 1
            continue
        if "allocated MSI vectors " in line:
            if state != 1:
                raise VerificationError("MSI allocation is duplicated or out of order")
            state = 2
            continue
        match = RESPONSE.search(line)
        if match:
            if state != 2:
                raise VerificationError("control-NOP response is duplicated or out of order")
            latency = int(match[1])
            words = tuple(int(value, 16) for value in match.groups()[1:])
            if latency > 5000 or words[:3] != (0x00010100, 0, 0):
                raise VerificationError("control-NOP response fields are invalid")
            if words[3] & ((1 << 18) | (1 << 19)):
                raise VerificationError("control-NOP response has transport failure flags")
            state = 3
            continue
        if "control NOP response passed strict validation" in line:
            if state != 3:
                raise VerificationError("control-NOP validation is duplicated or out of order")
            state = 4
            continue
        if "issued Apple CPU-stop value 5" in line:
            if state != 4:
                raise VerificationError("transport stop is duplicated or out of order")
            state = 5
            continue
        match = MSI.search(line)
        if match:
            if state != 5 or not int(match[1]) or not int(match[2]):
                raise VerificationError("MSI evidence is missing, zero, or out of order")
            state = 6
            continue
        if "restored PCI command word " in line:
            if state != 6:
                raise VerificationError("PCI restoration is duplicated or out of order")
            state = 7
            continue
        if "temporary PCI enable released before probe returned" in line:
            if state != 7:
                raise VerificationError("PCI release is duplicated or out of order")
            state = 8
            continue
        if "read-only probe removed" in line:
            if state != 8:
                raise VerificationError("probe removal is duplicated or out of order")
            state = 9
    if state != 9 or latency is None:
        raise VerificationError("control-NOP transcript is incomplete")
    return latency


def main() -> None:
    try:
        latency = verify(sys.stdin.read())
    except VerificationError as error:
        print(f"control-NOP verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(f"verified control NOP: latency_ms={latency}")


if __name__ == "__main__":
    main()
