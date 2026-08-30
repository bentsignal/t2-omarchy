#!/usr/bin/env python3
"""Read current T2 sensor-initialization state without reset or secret inputs."""

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


coupled = _load("sensor_context_coupled", "coupled-bridge-query.py")
biometric = _load("sensor_context_biometric", "biometric-command.py")

CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_SENSOR_CONTEXT"
LIVE_SENSOR_CONTEXT_ENABLED = False


class SensorContextProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class SensorContextResult:
    readiness_status: int
    readiness: int | None
    provisioning_status: int
    provisioning_state: int | None
    sensor_info_status: int
    sensor_info_length: int | None


def _perform(session, fields):
    protocol = coupled.bridge_query.protocol
    logical = session.call(list(protocol.biometric_perform_request(*fields)))
    return protocol.decode_perform_command_reply(tuple(logical), max_output=fields[4])


def _initialize(session) -> None:
    protocol = coupled.bridge_query.protocol
    version = session.call([protocol.GET_BRIDGE_VERSION])
    if version != [0, 3]:
        raise SensorContextProbeError("expected current bridge generation 3")
    if session.call([protocol.SET_BRIDGE_CLIENT_VERSION, 2]) != [0]:
        raise SensorContextProbeError("client-version negotiation failed")
    if session.call([protocol.GET_SERVICE_OPENED]) != [0, True]:
        raise SensorContextProbeError("biometric service did not report opened")


def _decode_success(status, output, decoder, label):
    if status != 0:
        return None
    try:
        return decoder(output if output is not None else b"")
    except biometric.BiometricCommandError as error:
        raise SensorContextProbeError(f"successful {label} reply has invalid shape") from error


def probe_socket(sock) -> SensorContextResult:
    session = coupled.bridge_query.BridgeSession(sock)
    _initialize(session)
    readiness_status, readiness_output = _perform(
        session, biometric.sensor_readiness_fields())
    readiness = _decode_success(
        readiness_status, readiness_output, biometric.decode_sensor_readiness,
        "sensor readiness")
    provisioning_status, provisioning_output = _perform(
        session, biometric.provisioning_state_fields())
    provisioning = _decode_success(
        provisioning_status, provisioning_output,
        biometric.decode_provisioning_state, "provisioning state")
    sensor_info_status, sensor_info_output = _perform(
        session, biometric.sensor_info_fields())
    sensor_info_length = _decode_success(
        sensor_info_status, sensor_info_output,
        biometric.decode_sensor_info_shape, "sensor information")
    return SensorContextResult(
        readiness_status, readiness, provisioning_status, provisioning,
        sensor_info_status, sensor_info_length)


def live_probe(*, interface: str = "enp4s0f1u1", timeout: float = 5.0):
    if not LIVE_SENSOR_CONTEXT_ENABLED:
        raise SensorContextProbeError("live sensor-context probing is disabled in source")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock)
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
        raise SensorContextProbeError("sensor-context probe produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: read-only sensor-context plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    global LIVE_SENSOR_CONTEXT_ENABLED
    LIVE_SENSOR_CONTEXT_ENABLED = True
    try:
        result = live_probe(interface=args.interface)
    finally:
        LIVE_SENSOR_CONTEXT_ENABLED = False
    print("sensor context: "
          f"readiness_status={result.readiness_status} readiness={result.readiness} "
          f"provisioning_status={result.provisioning_status} "
          f"provisioning_state={result.provisioning_state} "
          f"sensor_info_status={result.sensor_info_status} "
          f"sensor_info_length={result.sensor_info_length}")


if __name__ == "__main__":
    main()
