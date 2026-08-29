#!/usr/bin/env python3
"""Create one authorized Linux user policy and immediately attempt enrollment."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


client = _load("policy_enrollment_input", "authorized-enrollment-client.py")
enrollment = client.enrollment
store = _load("policy_enrollment_store", "catacomb-store.py")
CONFIRMATION = "I_UNDERSTAND_THIS_CREATES_ONE_USER_POLICY_AND_FINGERPRINT_IDENTITY"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--catacomb-output", type=Path, required=True)
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        parser.error(f"live policy enrollment requires --confirm={CONFIRMATION}")

    credential = client.consume_stdin_credential()
    policy_credential = bytearray(credential)
    enroll_request = policy_request = None
    try:
        enroll_request = enrollment.biometric.consume_builtin_enrollment_credential(
            user_id=args.user_id, credential_set=credential)
        policy_request = enrollment.biometric.consume_user_policy_credential(
            user_id=args.user_id,
            policy=enrollment.biometric.UserProtectedPolicy(1, 1, 1, 0),
            credential_set=policy_credential)
        enrollment.LIVE_ENROLLMENT_ENABLED = True
        result = enrollment.live_probe(
            user_id=args.user_id, interface=args.interface, event_timeout=60.0,
            authorized_request=enroll_request, policy_request=policy_request,
            catacomb_sink=lambda blob: store.save(
                args.catacomb_output, user_id=args.user_id, blob=blob),
            progress=client.progress_instruction)
    finally:
        credential[:] = bytes(len(credential))
        policy_credential[:] = bytes(len(policy_credential))
        if enroll_request is not None:
            enroll_request.close()
        if policy_request is not None:
            policy_request.close()
        enrollment.LIVE_ENROLLMENT_ENABLED = False
    print("authorized policy enrollment completed: "
          f"policy_initialized={result.policy_initialized} "
          f"catacomb_saved={result.catacomb_saved} "
          f"identities_before={result.identities_before} "
          f"identities_after={result.identities_after} "
          f"cancel_status={result.cancel_status}")


if __name__ == "__main__":
    main()
