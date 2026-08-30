#!/usr/bin/env python3
"""Establish the bounded pre-enrollment context without sending enrollment."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


def _load():
    path = Path(__file__).with_name("enrollment-probe.py")
    spec = importlib.util.spec_from_file_location("enrollment_context_tested", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


enrollment = _load()
CONFIRMATION = "I_UNDERSTAND_THIS_INITIALIZES_BUT_DOES_NOT_ENROLL"
LIVE_CONTEXT_ENABLED = False


class EnrollmentContextError(RuntimeError):
    pass


def probe_socket(sock) -> None:
    session = enrollment.coupled.bridge_query.BridgeSession(sock)
    enrollment._initialize_current_bridge(session)
    enrollment._establish_enrollment_sensor_context(session)


def live_probe(*, interface: str = "enp4s0f1u1", timeout: float = 5.0) -> None:
    if not LIVE_CONTEXT_ENABLED:
        raise EnrollmentContextError("live enrollment-context probe is disabled")

    def run(sock):
        probe_socket(sock)

    original = enrollment.coupled.bridge_query.query_connected_socket
    original_gate = enrollment.coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        enrollment.coupled.bridge_query.query_connected_socket = run
        enrollment.coupled.LIVE_COUPLED_QUERY_ENABLED = True
        enrollment.coupled.live_query(interface, timeout)
    finally:
        enrollment.coupled.bridge_query.query_connected_socket = original
        enrollment.coupled.LIVE_COUPLED_QUERY_ENABLED = original_gate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: no enrollment command is sent")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    global LIVE_CONTEXT_ENABLED
    LIVE_CONTEXT_ENABLED = True
    try:
        live_probe(interface=args.interface)
    finally:
        LIVE_CONTEXT_ENABLED = False
    print("pre-enrollment context passed; enrollment command was not sent")


if __name__ == "__main__":
    main()
