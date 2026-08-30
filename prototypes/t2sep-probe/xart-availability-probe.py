#!/usr/bin/env python3
"""Read xART availability after the proven same-session sensor initialization."""

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


context = _load("xart_availability_context", "external-catacomb-load-probe.py")
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_XART_AVAILABILITY"
LIVE_XART_QUERY_ENABLED = False


class XartAvailabilityError(RuntimeError):
    pass


def probe_socket(sock, *, version: int = 0) -> bool:
    session = context.state.coupled.bridge_query.BridgeSession(sock)
    context.state._initialize(session)
    try:
        context._establish_nonsecret_context(session)
        status, output = context.state._perform(
            session, context.state.biometric.xart_available_fields(version=version))
        if status != 0:
            raise XartAvailabilityError(
                f"xART availability query failed with status {status}")
        return context.state.biometric.decode_xart_available(output or b"")
    except (context.ExternalCatacombLoadError,
            context.state.biometric.BiometricCommandError) as error:
        raise XartAvailabilityError(
            "xART availability context or result was invalid") from error


def live_probe(*, version: int = 0, interface: str = "enp4s0f1u1",
               timeout: float = 5.0) -> bool:
    if not LIVE_XART_QUERY_ENABLED:
        raise XartAvailabilityError("live xART availability query is disabled")
    result = None

    def run(sock):
        nonlocal result
        result = probe_socket(sock, version=version)
        return result

    coupled = context.state.coupled
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
        raise XartAvailabilityError("xART availability query produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--version", type=int, choices=(0, 1, 2), default=0)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: xART availability read plan")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live query requires --confirm={CONFIRMATION}")
    global LIVE_XART_QUERY_ENABLED
    LIVE_XART_QUERY_ENABLED = True
    try:
        available = live_probe(version=args.version, interface=args.interface)
    finally:
        LIVE_XART_QUERY_ENABLED = False
    print(f"xART available: {available}")


if __name__ == "__main__":
    main()
