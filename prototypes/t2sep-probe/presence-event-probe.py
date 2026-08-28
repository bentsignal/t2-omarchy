#!/usr/bin/env python3
"""Bounded T2 presence-event probe with mandatory same-session cancellation."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import socket
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


coupled = _load("presence_coupled", "coupled-bridge-query.py")
biometric = _load("presence_biometric", "biometric-command.py")

LIVE_PRESENCE_ENABLED = False


@dataclass(frozen=True)
class PresenceResult:
    start_status: int
    event_types: tuple[str, ...] | None
    event_lengths: tuple[int | None, ...] | None
    event_integers: tuple[int | None, ...] | None
    event_status: int | None
    event_version: int | None
    event_ordinal: int | None
    event_data_length: int | None
    cancel_status: int


def _perform(session, fields):
    request = list(session_protocol(session).biometric_perform_request(*fields))
    logical = session.call(request)
    return session_protocol(session).decode_perform_command_reply(
        tuple(logical), max_output=fields[4])


def session_protocol(_session):
    return coupled.bridge_query.protocol


def probe_socket(sock) -> PresenceResult:
    """Start presence detection, observe at most one event, and always cancel."""
    session = coupled.bridge_query.BridgeSession(sock)
    start_status, _ = _perform(session, biometric.presence_detect_fields())
    event_types = None
    event_lengths = None
    event_integers = None
    event_status = event_version = event_ordinal = event_data_length = None
    cancel_status = -1
    try:
        try:
            event = session.receive_event()
            event_types = tuple(type(item).__name__ for item in event.message)
            event_lengths = tuple(len(item) if isinstance(item, (bytes, str, list))
                                  else None for item in event.message)
            event_integers = tuple(item if type(item) is int else None
                                   for item in event.message)
            decoded = biometric.decode_bridge_service_event(event.message)
            event_status = decoded.status
            event_version = decoded.version
            event_ordinal = decoded.ordinal
            event_data_length = len(decoded.data)
        except (socket.timeout, TimeoutError):
            pass
    finally:
        cancel_status, _ = _perform(session, biometric.cancel_fields())
    return PresenceResult(start_status, event_types, event_lengths,
                          event_integers, event_status, event_version,
                          event_ordinal, event_data_length, cancel_status)


def live_probe(interface: str = "enp4s0f1u1", timeout: float = 5.0) -> PresenceResult:
    if not LIVE_PRESENCE_ENABLED:
        raise RuntimeError("live presence probe is disabled in source")
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
    assert result is not None
    return result
