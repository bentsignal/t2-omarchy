#!/usr/bin/env python3
"""Initialize one empty in-memory T2 catacomb, then query sanitized state shapes."""

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


state = _load("no_catacomb_state", "user-state-probe.py")
CONFIRMATION = "I_UNDERSTAND_THIS_INITIALIZES_ONE_EMPTY_IN_MEMORY_CATACOMB"
LIVE_NO_CATACOMB_ENABLED = False


class NoCatacombProbeError(RuntimeError):
    pass


def probe_socket(sock, *, user_id: int):
    session = state.coupled.bridge_query.BridgeSession(sock)
    state._initialize(session)
    status, output = state._perform(
        session, state.biometric.no_catacomb_fields(user_id=user_id))
    if status != 0 or output is not None:
        raise NoCatacombProbeError(
            f"empty catacomb initialization failed: status={status} output={output is not None}")

    protected_status, protected = state._perform(
        session, state.biometric.protected_config_fields(user_id=user_id))
    catacomb_status, catacomb = state._perform(
        session, state.biometric.catacomb_state_fields())
    group_status, groups = state._perform(
        session, state.biometric.catacomb_group_state_fields())
    protected_length = None
    requested_policy = effective_policy = None
    if protected_status == 0:
        if not isinstance(protected, bytes) or len(protected) != 32:
            raise NoCatacombProbeError("protected config success shape is invalid")
        protected_length = len(protected)
        words = state.struct.unpack("<8I", protected)
        requested_policy, effective_policy = words[:4], words[4:]
    catacomb_records = group_records = None
    if catacomb_status == 0:
        catacomb_records = state.biometric.validate_opaque_record_array(
            catacomb or b"", record_size=8, maximum_records=256)
    if group_status == 0:
        group_records = state.biometric.validate_opaque_record_array(
            groups or b"", record_size=56, maximum_records=64)
    return status, state.UserStateResult(
        protected_status, protected_length, requested_policy, effective_policy,
        -1, None, -1, None, -1, None, -1, None,
        catacomb_status, catacomb_records, group_status, group_records)


def live_probe(*, user_id: int, interface: str = "enp4s0f1u1", timeout: float = 5.0):
    if not LIVE_NO_CATACOMB_ENABLED:
        raise NoCatacombProbeError("live empty-catacomb initialization is disabled")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock, user_id=user_id)
        return result

    original = state.coupled.bridge_query.query_connected_socket
    original_gate = state.coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        state.coupled.bridge_query.query_connected_socket = run
        state.coupled.LIVE_COUPLED_QUERY_ENABLED = True
        state.coupled.live_query(interface, timeout)
    finally:
        state.coupled.bridge_query.query_connected_socket = original
        state.coupled.LIVE_COUPLED_QUERY_ENABLED = original_gate
    if result is None:
        raise NoCatacombProbeError("empty-catacomb probe produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: empty in-memory catacomb initialization plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    global LIVE_NO_CATACOMB_ENABLED
    LIVE_NO_CATACOMB_ENABLED = True
    try:
        init_status, result = live_probe(user_id=args.user_id, interface=args.interface)
    finally:
        LIVE_NO_CATACOMB_ENABLED = False
    print("empty catacomb initialized: "
          f"status={init_status} protected_status={result.protected_status} "
          f"protected_length={result.protected_length} "
          f"catacomb_status={result.catacomb_status} "
          f"catacomb_records={result.catacomb_records} "
          f"group_status={result.group_status} group_records={result.group_records}")


if __name__ == "__main__":
    main()
