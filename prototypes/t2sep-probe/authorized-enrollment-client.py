#!/usr/bin/env python3
"""Consume one root-supplied ACM form and run one bounded enrollment.

The credential is accepted only on standard input, is never printed, and is
immediately transferred into the scrub-owned current-format command object.
Live access remains impossible by importing this module alone.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def _load():
    path = Path(__file__).with_name("enrollment-probe.py")
    spec = importlib.util.spec_from_file_location("authorized_live_enrollment", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


enrollment = _load()
CONFIRMATION = "I_UNDERSTAND_THIS_CREATES_ONE_FINGERPRINT_IDENTITY"


def progress_instruction(event: tuple[int, int, int]) -> None:
    status, version, length = event
    print(f"enrollment event status={status:#x} version={version} length={length}",
          flush=True)
    if status == enrollment.READY_STATUS:
        print("TOUCH NOW: place the new finger flat on Touch ID.", flush=True)
    elif status in enrollment.PROGRESS_MINIMUMS:
        print("LIFT, reposition slightly, then touch again.", flush=True)


def consume_stdin_credential() -> bytearray:
    line = bytearray(sys.stdin.buffer.readline(34))
    try:
        if len(line) != 33 or line[-1:] != b"\n":
            raise ValueError("credential handoff had the wrong length")
        try:
            credential = bytearray.fromhex(line[:-1].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("credential handoff was not canonical hex") from error
        if len(credential) != 16:
            credential[:] = bytes(len(credential))
            raise ValueError("credential handoff decoded to the wrong length")
        return credential
    finally:
        line[:] = bytes(len(line))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"live enrollment requires --confirm={CONFIRMATION}")

    credential = consume_stdin_credential()
    request = enrollment.biometric.consume_builtin_enrollment_credential(
        user_id=args.user_id, credential_set=credential)
    enrollment.LIVE_ENROLLMENT_ENABLED = True
    try:
        result = enrollment.live_probe(
            user_id=args.user_id, interface=args.interface,
            event_timeout=60.0, authorized_request=request,
            progress=progress_instruction)
    finally:
        request.close()
        enrollment.LIVE_ENROLLMENT_ENABLED = False
    print("authorized enrollment completed: "
          f"identities_before={result.identities_before} "
          f"identities_after={result.identities_after} "
          f"cancel_status={result.cancel_status}")


if __name__ == "__main__":
    main()
