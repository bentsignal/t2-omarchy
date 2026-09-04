#!/usr/bin/env python3
"""Audit recovered Catalina enrollment status switches in an attested image.

Offline only. Addresses are file offsets as well as VAs in this exact image's
__TEXT segment. No Apple binary bytes or private device data are emitted.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


EXPECTED_SHA256 = "de1ccb67d244dd90001235141bac4484df7697bc6f73e56ef61733b29dfdb991"
OBSERVED_NONADVANCING = (55, 63, 64, 72, 81, 89, 90, 91)


def inspect(path: Path) -> dict:
    if path.stat().st_size != 421200:
        raise ValueError("expected exact Catalina framework size")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise ValueError("framework digest does not match recovered evidence")

    def target(base: int, index: int) -> int:
        return base + struct.unpack_from("<i", data, base + index * 4)[0]

    rows = []
    for status in range(51, 100):
        generic = target(0x27960, status - 51) if status <= 80 else (
            0x278A3 if status == 99 else 0x278E2
        )
        enrollment = target(0x286F0, status - 66) if 66 <= status <= 70 else 0x28643
        capture_error = (target(0x2B6E8, status - 78) != 0x2B6CE) if 78 <= status <= 88 else status == 98
        row = {
            "status": status,
            "generic_target": hex(generic),
            "enrollment_target": hex(enrollment),
            "capture_error": capture_error,
            "enrollment_forwarded": enrollment == 0x28643,
            "generic_no_action": generic == 0x278E2,
            "presence_notification": generic == 0x277F9,
        }
        if status in OBSERVED_NONADVANCING and not (
            row["enrollment_forwarded"] and not capture_error
            and (row["generic_no_action"] or row["presence_notification"])
        ):
            raise ValueError("observed status did not follow the expected nonadvancing path")
        rows.append(row)
    return {
        "source_build": "19H15", "source_version": "187.140.1",
        "source_sha256": EXPECTED_SHA256,
        "observed_nonadvancing_statuses": list(OBSERVED_NONADVANCING),
        "wire_version_claimed": False,
        "statuses": rows,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.image), indent=2))
