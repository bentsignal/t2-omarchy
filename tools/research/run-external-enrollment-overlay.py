#!/usr/bin/env python3
"""Run the pinned GPL enrollment broker with evidence-backed event fixes.

The matching daemon accepts a version-1 SKS lock-state notification with a
six-byte UID/state prefix.  This machine emits UID 0 as system-scoped state
after a populated enrollment start.  The pinned broker already consumes that
shape during setup but rejects it after start.  This overlay preserves every
shape check while accepting only UID 0 or the pinned enrollment UID.

The T2 also emits generic status 90 immediately after enrollment starts.
Apple's enrollment operation forwards unhandled statuses to its superclass,
whose recovered status switch leaves 90 as a no-op.  The pinned reducer
instead freezes on every unlisted status.  The second overlay restores only
that exact no-op while retaining framing, ordering, operation, generation,
duplicate, cancellation, and neighboring-ordinal checks.
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


def permit_system_lifecycle_status_90(protocol_module) -> None:
    """Mirror Apple's generic-operation no-op for exact status ordinal 90."""
    machine_type = protocol_module.EnrollmentStateMachine
    if getattr(machine_type.accept, "_t2_status_90_overlay", False):
        return
    original_accept = machine_type.accept

    def accept(self, event, *, connection_generation: str, operation_id: str):
        prior_state = self.state
        try:
            return original_accept(
                self,
                event,
                connection_generation=connection_generation,
                operation_id=operation_id,
            )
        except protocol_module.EnrollmentProtocolError as error:
            exact_status_90 = (
                prior_state is protocol_module.EnrollmentState.ACTIVE
                and event.envelope_type == protocol_module.SERVICE_STATUS
                and event.version == 1
                and event.ordinal == 90
                and str(error) == "unknown enrollment status 90"
                and self.state is protocol_module.EnrollmentState.FROZEN
            )
            if not exact_status_90:
                raise
            # original_accept has already validated the generic-status payload,
            # generation, operation ID, monotonic sequence, and duplicate hash.
            # Retain its accepted sequence/hash and undo only its terminal freeze.
            self.state = protocol_module.EnrollmentState.ACTIVE
            return protocol_module.EnrollmentTransition(
                protocol_module.EnrollmentAction.IGNORE_AUXILIARY,
                self.state,
            )

    accept._t2_status_90_overlay = True
    machine_type.accept = accept


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--overlay-acknowledge-system-sks-event", action="store_true")
    parser.add_argument("--overlay-acknowledge-status-90-noop", action="store_true")
    known, remaining = parser.parse_known_args()
    if not known.overlay_acknowledge_system_sks_event:
        raise EnrollmentOverlayError("system-scoped SKS overlay acknowledgement is required")
    if not known.overlay_acknowledge_status_90_noop:
        raise EnrollmentOverlayError("status-90 no-op overlay acknowledgement is required")
    broker = validate_source()
    sys.path.insert(0, str(broker.parent))
    import t2_enrollment_protocol

    permit_system_scoped_sks_event(t2_enrollment_protocol)
    permit_system_lifecycle_status_90(t2_enrollment_protocol)
    sys.argv = [str(broker), *remaining]
    runpy.run_path(str(broker), run_name="__main__")


if __name__ == "__main__":
    main()
