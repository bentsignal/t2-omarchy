#!/usr/bin/env python3
"""Verify exact bridgeOS 23P6068 keybag store-type call-site evidence."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


KEYBAGD_SHA256 = "9e05a68827a6be486e2cf14a592dbc493a53161df4d51695b3e35666677d31ba"
MOBILE_KEYBAG_SHA256 = "6500d9ad97f1dd5518dad5b8773164f8efd41938ef58e0786ba52acd5a379420"

# AArch64 `mov w2, #imm` immediately followed by BL at each pinned call site.
EVIDENCE = (
    ("device/user-session", 0x100000000, 0x10000CC24,
     bytes.fromhex("02008052f41d0094")),
    ("backup", 0x188B50000, 0x188B55258,
     bytes.fromhex("22008052300ab894")),
    ("OTA backup", 0x188B50000, 0x188B553A0,
     bytes.fromhex("62008052de09b894")),
)


def verify(path: Path, expected_hash: str, records: tuple[tuple, ...]) -> None:
    data = path.read_bytes()
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(f"{path}: SHA-256 mismatch: {actual_hash}")
    for label, image_base, address, expected in records:
        offset = address - image_base
        actual = data[offset:offset + len(expected)]
        if actual != expected:
            raise ValueError(f"{path}: {label} call site mismatch at {address:#x}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("keybagd", type=Path)
    parser.add_argument("mobile_keybag", type=Path)
    args = parser.parse_args()
    verify(args.keybagd, KEYBAGD_SHA256, EVIDENCE[:1])
    verify(args.mobile_keybag, MOBILE_KEYBAG_SHA256, EVIDENCE[1:])
    print("bridgeOS keybag store types verified: device=0 backup=1 ota-backup=3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
