#!/usr/bin/env python3
"""Perform one bounded current sensor reset and sanitized context readback."""

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


context = _load("sensor_reset_context", "sensor-context-probe.py")
CONFIRMATION = "I_UNDERSTAND_THIS_RESETS_THE_T2_FINGERPRINT_SENSOR_ONCE"
LIVE_SENSOR_RESET_ENABLED = False


class SensorResetProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class SensorResetResult:
    reset_attempts: int
    reset_status: int
    sensor_info_length: int
    biometrickitd_info_length: int
    calibration_present: bool
    device_records: int
    builtin_records: int


def probe_socket(sock) -> SensorResetResult:
    session = context.coupled.bridge_query.BridgeSession(sock)
    context._initialize(session)
    readiness_status, readiness_output = context._perform(
        session, context.biometric.sensor_readiness_fields())
    if (readiness_status != 0
            or context.biometric.decode_sensor_readiness(readiness_output or b"") != 1):
        raise SensorResetProbeError("sensor is not ready")
    provisioning_status, provisioning_output = context._perform(
        session, context.biometric.provisioning_state_fields())
    if provisioning_status != 0:
        raise SensorResetProbeError("provisioning-state read failed")
    context.biometric.decode_provisioning_state(provisioning_output or b"")
    reset_status = -1
    attempts = 0
    for attempts in range(1, 4):
        reset_status, output = context._perform(
            session, context.biometric.reset_sensor_fields())
        if reset_status == 0:
            if output is not None:
                raise SensorResetProbeError("successful reset returned output")
            break
    if reset_status != 0:
        raise SensorResetProbeError(
            f"sensor reset failed after {attempts} attempts with status {reset_status}")
    info_status, info_output = context._perform(
        session, context.biometric.sensor_info_fields())
    if info_status != 0:
        raise SensorResetProbeError("sensor-info read failed after reset")
    context.biometric.decode_sensor_info(info_output or b"")
    daemon_info_status, daemon_info_output = context._perform(
        session, context.biometric.biometrickitd_info_fields())
    if daemon_info_status != 0:
        raise SensorResetProbeError("biometrickitd-info read failed after reset")
    daemon_info = context.biometric.decode_biometrickitd_info_summary(
        daemon_info_output or b"")
    devices_status, devices_output = context._perform(
        session, context.biometric.bio_device_list_fields())
    if devices_status != 0:
        raise SensorResetProbeError("bio-device-list read failed after reset")
    summary = context.biometric.decode_bio_device_list_summary(devices_output or b"")
    return SensorResetResult(
        attempts, reset_status, context.biometric.SENSOR_INFO_SIZE,
        context.biometric.BIOMETRICKITD_INFO_SIZE,
        daemon_info.calibration_present,
        summary.record_count, summary.builtin_record_count)


def live_probe(*, interface: str = "enp4s0f1u1", timeout: float = 5.0):
    if not LIVE_SENSOR_RESET_ENABLED:
        raise SensorResetProbeError("live sensor reset is disabled in source")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock)
        return result

    original = context.coupled.bridge_query.query_connected_socket
    original_gate = context.coupled.LIVE_COUPLED_QUERY_ENABLED
    try:
        context.coupled.bridge_query.query_connected_socket = run
        context.coupled.LIVE_COUPLED_QUERY_ENABLED = True
        context.coupled.live_query(interface, timeout)
    finally:
        context.coupled.bridge_query.query_connected_socket = original
        context.coupled.LIVE_COUPLED_QUERY_ENABLED = original_gate
    if result is None:
        raise SensorResetProbeError("sensor reset produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: bounded sensor-reset plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    global LIVE_SENSOR_RESET_ENABLED
    LIVE_SENSOR_RESET_ENABLED = True
    try:
        result = live_probe(interface=args.interface)
    finally:
        LIVE_SENSOR_RESET_ENABLED = False
    print("sensor reset: "
          f"attempts={result.reset_attempts} status={result.reset_status} "
          f"sensor_info_length={result.sensor_info_length} "
          f"biometrickitd_info_length={result.biometrickitd_info_length} "
          f"calibration_present={result.calibration_present} "
          f"device_records={result.device_records} "
          f"builtin_records={result.builtin_records}")


if __name__ == "__main__":
    main()
