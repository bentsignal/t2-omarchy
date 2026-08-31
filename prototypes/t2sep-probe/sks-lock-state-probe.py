#!/usr/bin/env python3
"""Read only the bounded SKS lock-state status/value for one user."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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


coupled = _load("sks_lock_coupled", "coupled-bridge-query.py")
biometric = _load("sks_lock_biometric", "biometric-command.py")
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_SKS_LOCK_STATE"
LIVE_SKS_LOCK_QUERY_ENABLED = False


class SKSLockStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class SKSLockStateResult:
    version: int
    status: int
    state: int | None
    output_length: int | None


def _perform(session, fields):
    protocol = coupled.bridge_query.protocol
    logical = session.call(list(protocol.biometric_perform_request(*fields)))
    return protocol.decode_perform_command_reply(tuple(logical), max_output=fields[4])


def probe_socket(sock, *, user_id: int,
                 versions: tuple[int, ...] = (0, 1, 2)) -> tuple[SKSLockStateResult, ...]:
    session = coupled.bridge_query.BridgeSession(sock)
    protocol = coupled.bridge_query.protocol
    if session.call([protocol.GET_BRIDGE_VERSION]) != [0, 3]:
        raise SKSLockStateError("expected current bridge generation 3")
    if session.call([protocol.SET_BRIDGE_CLIENT_VERSION, 2]) != [0]:
        raise SKSLockStateError("client-version negotiation failed")
    if session.call([protocol.GET_SERVICE_OPENED]) != [0, True]:
        raise SKSLockStateError("biometric service did not report opened")
    results = []
    for version in versions:
        status, output = _perform(
            session, biometric.sks_lock_state_fields(
                user_id=user_id, version=version))
        state = None
        output_length = len(output) if isinstance(output, bytes) else None
        if status == 0:
            try:
                state = biometric.decode_sks_lock_state(output or b"")
            except biometric.BiometricCommandError as error:
                raise SKSLockStateError(
                    "successful SKS lock-state reply had an invalid shape") from error
        elif output is not None and len(output) != 4:
            raise SKSLockStateError(
                "failed SKS lock-state reply had an unexpected output shape")
        results.append(SKSLockStateResult(version, status, state, output_length))
    return tuple(results)


def live_probe(*, user_id: int, interface: str = "enp4s0f1u1",
               timeout: float = 5.0) -> tuple[SKSLockStateResult, ...]:
    if not LIVE_SKS_LOCK_QUERY_ENABLED:
        raise SKSLockStateError("live SKS lock-state query is disabled")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock, user_id=user_id)
        return result

    original = coupled.bridge_query.query_connected_socket
    original_gate = coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        coupled.bridge_query.query_connected_socket = run
        coupled.LIVE_COUPLED_QUERY_ENABLED = True
        coupled.live_query(interface, timeout)
    finally:
        coupled.bridge_query.query_connected_socket = original
        coupled.LIVE_COUPLED_QUERY_ENABLED = original_gate
    if result is None:
        raise SKSLockStateError("SKS lock-state query produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: read-only SKS lock-state plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live query requires --confirm={CONFIRMATION}")
    global LIVE_SKS_LOCK_QUERY_ENABLED
    LIVE_SKS_LOCK_QUERY_ENABLED = True
    try:
        results = live_probe(user_id=args.user_id, interface=args.interface)
    finally:
        LIVE_SKS_LOCK_QUERY_ENABLED = False
    print("SKS lock state: " + " ".join(
        f"version={item.version},status={item.status},state={item.state},"
        f"output_length={item.output_length}"
        for item in results))


if __name__ == "__main__":
    main()
