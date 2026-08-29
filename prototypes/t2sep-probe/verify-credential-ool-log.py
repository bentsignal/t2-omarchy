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
PINNED = re.compile(
    r"pinned OOL buffers: target=(\d+) "
    r"in_dma=0x([0-9a-fA-F]+) in_size=(\d+) "
    r"out_dma=0x([0-9a-fA-F]+) out_size=(\d+)")
MSI = re.compile(r"MSI observations: vector0=(\d+) vector1=(\d+)")


def verify(text: str, expected_endpoint: int
           ) -> tuple[tuple[int, int], tuple[int, int]]:
    if not isinstance(text, str):
        raise VerificationError("credential OOL transcript must be text")
    if expected_endpoint not in (7, 10):
        raise VerificationError("credential endpoint must be AKS 7 or ACM 10")
    nop = False
    enabled = False
    msi_allocated = False
    pages: tuple[int, int] | None = None
    pending: tuple[int, int] | None = None
    profiles: list[tuple[int, int]] = []
    stopped = False
    cleaned = False
    msi_observed = False
    pci_restored = False
    pci_released = False
    removed = False
    for line in text.splitlines():
        # Ignore kernel-loader diagnostics such as the expected unsigned
        # out-of-tree-module taint warning. Only the bound PCI probe emits the
        # state-machine evidence accepted below.
        if "t2sep_probe 0000:04:00.2:" not in line:
            continue
        if any(marker in line for marker in
               ("transport error", "timed out", "failed:", "result=-")):
            raise VerificationError("transcript contains a failure marker")
        if "temporarily enabled PCI memory decoding for this probe" in line:
            if enabled or nop:
                raise VerificationError("PCI enable is duplicated or out of order")
            enabled = True
            continue
        if "allocated MSI vectors " in line:
            if not enabled or msi_allocated or nop:
                raise VerificationError("MSI allocation is duplicated or out of order")
            msi_allocated = True
            continue
        if "control NOP response passed strict validation" in line:
            if not msi_allocated or nop or pending is not None or profiles:
                raise VerificationError("validated NOP is duplicated or out of order")
            nop = True
            continue
        match = PINNED.search(line)
        if match:
            if not nop or pages is not None or pending is not None or profiles:
                raise VerificationError("credential buffers are duplicated or out of order")
            target, in_dma, in_size, out_dma, out_size = (
                int(match[1]), int(match[2], 16), int(match[3]),
                int(match[4], 16), int(match[5]))
            if (target != expected_endpoint or in_size != 0x4000 or
                    out_size != 0x4000 or not in_dma or not out_dma or
                    in_dma == out_dma or in_dma & 0xfff or out_dma & 0xfff or
                    in_dma >> 44 or out_dma >> 44):
                raise VerificationError("credential OOL buffer evidence is invalid")
            pages = in_dma >> 12, out_dma >> 12
            continue
        match = REQUEST.search(line)
        if match:
            if pages is None or pending is not None or stopped:
                raise VerificationError("credential registration request is out of order")
            opcode, tag = int(match[1]), int(match[2])
            if opcode != 2 + len(profiles) or tag != opcode:
                raise VerificationError("credential registration opcode/tag is invalid")
            word0, page, size = (int(match[index], 16) for index in (3, 4, 5))
            if (word0 != (expected_endpoint << 24 | opcode << 16 | tag << 8)
                    or page != pages[opcode - 2] or size != 0x4000):
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
            if (fields[0] != 0 or fields[1] != tag or words[1] != 0 or
                    words[2] != 0):
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
            continue
        match = MSI.search(line)
        if match:
            if not cleaned or msi_observed or not int(match[1]) or not int(match[2]):
                raise VerificationError("MSI evidence is missing, zero, or out of order")
            msi_observed = True
            continue
        if "restored PCI command word " in line:
            if not msi_observed or pci_restored:
                raise VerificationError("PCI restoration is duplicated or out of order")
            pci_restored = True
            continue
        if "temporary PCI enable released before probe returned" in line:
            if not pci_restored or pci_released:
                raise VerificationError("PCI release is duplicated or out of order")
            pci_released = True
            continue
        if "read-only probe removed" in line:
            if not pci_released or removed:
                raise VerificationError("probe removal is duplicated or out of order")
            removed = True
    if not enabled or not msi_allocated or not nop or pages is None:
        raise VerificationError("credential transcript lacks setup evidence")
    if pending is not None or len(profiles) != 2:
        raise VerificationError("credential transcript is incomplete")
    if not all((stopped, cleaned, msi_observed, pci_restored, pci_released, removed)):
        raise VerificationError("credential transcript lacks complete teardown evidence")
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
