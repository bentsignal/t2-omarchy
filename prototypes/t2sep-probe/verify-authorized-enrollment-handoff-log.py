#!/usr/bin/env python3
"""Fail-closed verifier for the live ACM-to-BiometricKit handoff."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def _load_base():
    path = Path(__file__).with_name("verify-ephemeral-keybag-authorization-log.py")
    spec = importlib.util.spec_from_file_location("handoff_base_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load_base()
HANDOFF = (
    "authorized enrollment handoff ready: credential_bytes=not-logged",
    "authorized enrollment handoff completed without logging credential bytes",
)
POLICY_PREFLIGHT = (
    "ACM enrollment-policy request: endpoint=10 message_type=1 selector=3 "
    "length=51 policy=TouchIdEnrollment preflight=yes context_bytes=not-logged",
    "ACM enrollment-policy reply passed strict validation: preflight=yes "
    "satisfied=no requirement_present=yes requirement_type=1",
)
POLICY_COMMIT = (
    "ACM enrollment-policy request: endpoint=10 message_type=1 selector=3 "
    "length=51 policy=TouchIdEnrollment preflight=no context_bytes=not-logged",
    "ACM enrollment-policy reply passed strict validation: preflight=no "
    "satisfied=yes",
)
FORBIDDEN = (
    "handoff timed out", "credential=", "enrollment_credential=",
)


def _ordered_once(log: str, markers: tuple[str, ...], start: int, end: int) -> int:
    cursor = start
    for marker in markers:
        found = log.find(marker, cursor, end)
        if found < 0 or log.find(marker, found + 1) >= 0:
            raise ValueError(f"missing, duplicated, or out-of-order marker: {marker}")
        cursor = found + len(marker)
    return cursor


def verify(log: str, *, require_enrollment_policy: bool = False) -> None:
    base.verify(log)
    promote_marker = log.index(
        "AKS make-system-keybag reply passed strict validation: promoted=yes")
    verify_marker = log.index(
        "AKS verify-secret reply passed strict validation: authorized=yes")
    unload_marker = log.index(
        "AKS unload-keybag reply passed strict validation: role=system")
    cursor = verify_marker
    if require_enrollment_policy:
        _ordered_once(log, POLICY_PREFLIGHT, promote_marker, verify_marker)
        cursor = _ordered_once(log, POLICY_COMMIT, verify_marker, unload_marker)
        if "policy_required=yes policy_preflight=0 enrollment_policy=0" not in log:
            raise ValueError("successful enrollment policy summary is missing")
    else:
        for marker in POLICY_PREFLIGHT + POLICY_COMMIT:
            if marker in log:
                raise ValueError("unexpected enrollment-policy mutation in non-policy mode")
    _ordered_once(log, HANDOFF, cursor, unload_marker)
    for marker in FORBIDDEN:
        if marker in log:
            raise ValueError(f"forbidden transcript content: {marker}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-enrollment-policy", action="store_true")
    args = parser.parse_args()
    try:
        verify(sys.stdin.read(), require_enrollment_policy=args.require_enrollment_policy)
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("authorized enrollment handoff transcript passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
