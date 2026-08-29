#!/usr/bin/env python3
"""Verify one bounded simultaneous AKS/ACM OOL transcript from stdin."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys


def _load_single():
    path = Path(__file__).with_name("verify-credential-ool-log.py")
    spec = importlib.util.spec_from_file_location("dual_ool_single", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


single = _load_single()


class VerificationError(ValueError):
    pass


EXPECTED = ((7, 2, 2), (7, 3, 3), (10, 2, 4), (10, 3, 5))


def verify(text: str) -> tuple[tuple[int, int, int], ...]:
    if not isinstance(text, str):
        raise VerificationError("dual credential transcript must be text")
    enabled = msi_allocated = nop = stopped = cleaned = False
    msi_observed = pci_restored = pci_released = removed = False
    pages: dict[int, tuple[int, int]] = {}
    pending: tuple[int, int, int] | None = None
    profiles: list[tuple[int, int, int]] = []
    for line in text.splitlines():
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
            if not msi_allocated or nop or pages or profiles:
                raise VerificationError("validated NOP is duplicated or out of order")
            nop = True
            continue
        match = single.PINNED.search(line)
        if match:
            if not nop or pending is not None or profiles:
                raise VerificationError("dual buffers are out of order")
            target, in_dma, in_size, out_dma, out_size = (
                int(match[1]), int(match[2], 16), int(match[3]),
                int(match[4], 16), int(match[5]))
            if (target not in (7, 10) or target in pages or
                    in_size != 0x4000 or out_size != 0x4000 or
                    not in_dma or not out_dma or in_dma == out_dma or
                    in_dma & 0xfff or out_dma & 0xfff or
                    in_dma >> 44 or out_dma >> 44):
                raise VerificationError("dual OOL buffer evidence is invalid")
            new_range = ((in_dma, in_dma + 0x4000),
                         (out_dma, out_dma + 0x4000))
            old_ranges = tuple(
                (page << 12, (page << 12) + 0x4000)
                for pair in pages.values() for page in pair)
            if any(start < old_end and old_start < end
                   for start, end in new_range
                   for old_start, old_end in old_ranges):
                raise VerificationError("dual OOL buffers overlap")
            pages[target] = in_dma >> 12, out_dma >> 12
            continue
        match = single.REQUEST.search(line)
        if match:
            if set(pages) != {7, 10} or pending is not None or stopped:
                raise VerificationError("dual registration request is out of order")
            if len(profiles) >= len(EXPECTED):
                raise VerificationError("unexpected extra dual registration")
            target, opcode, tag = EXPECTED[len(profiles)]
            if (int(match[1]), int(match[2])) != (opcode, tag):
                raise VerificationError("dual registration opcode/tag changed")
            word0, page, size = (int(match[index], 16) for index in (3, 4, 5))
            if (word0 != target << 24 | opcode << 16 | tag << 8 or
                    page != pages[target][opcode - 2] or size != 0x4000):
                raise VerificationError("dual registration words are invalid")
            pending = target, opcode, tag
            continue
        match = single.ACK.search(line)
        if match:
            if pending is None or stopped:
                raise VerificationError("dual acknowledgement lacks a request")
            target, opcode, tag = pending
            if (int(match[1]), int(match[2])) != (opcode, tag):
                raise VerificationError("dual acknowledgement correlation changed")
            words = tuple(int(match[index], 16) for index in (3, 4, 5, 6))
            decoded = tuple(int(match[index]) for index in (7, 8, 9, 10))
            fields = (words[0] & 0xff, (words[0] >> 8) & 0xff,
                      (words[0] >> 16) & 0xff, (words[0] >> 24) & 0xff)
            if decoded != fields or fields != (0, tag, 1, target):
                raise VerificationError("dual acknowledgement profile changed")
            if words[1] or words[2] or words[3] & ((1 << 18) | (1 << 19)):
                raise VerificationError("dual acknowledgement status failed")
            profiles.append((target, fields[2], fields[3]))
            pending = None
            continue
        if "issued Apple CPU-stop value 5" in line:
            if pending is not None or len(profiles) != 4 or stopped:
                raise VerificationError("dual transport stopped out of order")
            stopped = True
            continue
        if "OOL buffers scrubbed and released after CPU stop; result=0" in line:
            if not stopped or cleaned:
                raise VerificationError("dual cleanup is out of order")
            cleaned = True
            continue
        match = single.MSI.search(line)
        if match:
            if not cleaned or msi_observed or not int(match[1]) or not int(match[2]):
                raise VerificationError("MSI evidence is missing, zero, or out of order")
            msi_observed = True
            continue
        if "restored PCI command word " in line:
            if not msi_observed or pci_restored:
                raise VerificationError("PCI restoration is out of order")
            pci_restored = True
            continue
        if "temporary PCI enable released before probe returned" in line:
            if not pci_restored or pci_released:
                raise VerificationError("PCI release is out of order")
            pci_released = True
            continue
        if "read-only probe removed" in line:
            if not pci_released or removed:
                raise VerificationError("probe removal is out of order")
            removed = True
    if not all((enabled, msi_allocated, nop, set(pages) == {7, 10},
                stopped, cleaned, msi_observed, pci_restored,
                pci_released, removed)):
        raise VerificationError("dual credential transcript is incomplete")
    if pending is not None or len(profiles) != 4:
        raise VerificationError("dual credential acknowledgements are incomplete")
    return tuple(profiles)


def main() -> None:
    try:
        profiles = verify(sys.stdin.read())
    except VerificationError as error:
        print(f"dual credential OOL verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("verified simultaneous AKS/ACM OOL profiles: " + repr(profiles))


if __name__ == "__main__":
    main()
