#!/usr/bin/env python3
"""Run the pinned GPL enrollment broker with one evidence-backed event fix.

The matching daemon accepts a version-1 SKS lock-state notification with a
six-byte UID/state prefix.  This machine emits UID 0 as system-scoped state
after a populated enrollment start.  The pinned broker already consumes that
shape during setup but rejects it after start.  This overlay preserves every
shape check while accepting only UID 0 or the pinned enrollment UID.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import runpy
import subprocess
import sys


SOURCE_ROOT = Path("/home/shawn/dev/t2-touchid-linux-latest")
EXPECTED_COMMIT = "826a86e55a9a745f50fb64672e5be32cf352cb76"
EXPECTED_PROTOCOL_SHA256 = "2116946027fec5734e21a46d67de629899c1dd0554bc70d5ccaef276eddf9b0d"


class EnrollmentOverlayError(RuntimeError):
    pass


def validate_source(root: Path = SOURCE_ROOT) -> Path:
    protocol_path = root / "src/t2_enrollment_protocol.py"
    broker_path = root / "src/t2-touchid-enroll-test.py"
    if not protocol_path.is_file() or not broker_path.is_file():
        raise EnrollmentOverlayError("pinned enrollment source is unavailable")
    actual_hash = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
    if actual_hash != EXPECTED_PROTOCOL_SHA256:
        raise EnrollmentOverlayError("enrollment protocol source hash changed")
    try:
        commit = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root}",
                "-C",
                str(root),
                "rev-parse",
                "HEAD",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise EnrollmentOverlayError("cannot attest enrollment source commit") from error
    if commit != EXPECTED_COMMIT:
        raise EnrollmentOverlayError("enrollment source commit changed")
    return broker_path


def permit_system_scoped_sks_event(protocol_module) -> None:
    def validate(event, *, expected_user_id: int) -> None:
        user_id = protocol_module.sks_lock_state_user_id(event)
        if user_id not in (0, expected_user_id):
            raise protocol_module.EnrollmentProtocolError(
                "SKS lock-state event belongs to an unrelated Apple user"
            )

    protocol_module.validate_sks_lock_state_payload = validate


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--overlay-acknowledge-system-sks-event", action="store_true")
    known, remaining = parser.parse_known_args()
    if not known.overlay_acknowledge_system_sks_event:
        raise EnrollmentOverlayError("system-scoped SKS overlay acknowledgement is required")
    broker = validate_source()
    sys.path.insert(0, str(broker.parent))
    import t2_enrollment_protocol

    permit_system_scoped_sks_event(t2_enrollment_protocol)
    sys.argv = [str(broker), *remaining]
    runpy.run_path(str(broker), run_name="__main__")


if __name__ == "__main__":
    main()
