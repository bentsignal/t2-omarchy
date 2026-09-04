#!/usr/bin/env python3
"""Run one authorized enrollment with crash-safe three-component persistence."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import sys
import time
import uuid


def _load(name: str, filename: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


enrollment = _load("transactional_live_enrollment", "enrollment-probe.py")
transaction_module = _load(
    "transactional_enrollment_store", "enrollment-transaction.py"
)

CONFIRMATION = "I_UNDERSTAND_THIS_TRANSACTIONALLY_CREATES_ONE_FINGERPRINT_IDENTITY"


def progress_instruction(event: tuple[int, int, int]) -> None:
    status, version, length = event
    print(
        f"enrollment event status={status:#x} version={version} length={length}",
        flush=True,
    )
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
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"live enrollment requires --confirm={CONFIRMATION}")
    if os.geteuid() != 0:
        parser.error("transactional enrollment requires root")

    operation_id = str(uuid.uuid4())
    transaction = transaction_module.EnrollmentTransaction(
        args.state_root,
        apple_user_id=args.user_id,
        operation_id=operation_id,
    )
    baseline_count: list[int] = []

    def begin(before, maximum: int, free: int) -> None:
        baseline_count.append(len(before))
        transaction.begin(
            live_identity_count=len(before),
            maximum_identity_count=maximum,
            free_identity_count=free,
        )

    def terminal(identity) -> None:
        transaction.record_terminal_identity(identity.uuid)

    def commit() -> None:
        if len(baseline_count) != 1:
            raise transaction_module.EnrollmentTransactionError(
                "enrollment baseline was not uniquely established"
            )
        transaction.commit(
            identity_name=f"Linux Finger {baseline_count[0] + 1}",
            apple_time=time.time() - transaction_module.APPLE_EPOCH_OFFSET,
        )

    credential = consume_stdin_credential()
    request = enrollment.biometric.consume_builtin_enrollment_credential(
        user_id=args.user_id, credential_set=credential
    )
    enrollment.LIVE_ENROLLMENT_ENABLED = True
    try:
        result = enrollment.live_probe(
            user_id=args.user_id,
            interface=args.interface,
            event_timeout=60.0,
            authorized_request=request,
            establish_sensor_context=True,
            mutation_begin=begin,
            terminal_sink=terminal,
            component_sink=transaction.stage_secure_component,
            persistence_commit=commit,
            progress=progress_instruction,
        )
    finally:
        request.close()
        enrollment.LIVE_ENROLLMENT_ENABLED = False
    print(
        "transactional enrollment completed: "
        f"identities_before={result.identities_before} "
        f"identities_after={result.identities_after} "
        f"components_saved={3 if result.catacomb_saved else 0} "
        f"cancel_status={result.cancel_status}"
    )


if __name__ == "__main__":
    main()
