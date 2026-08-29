#!/usr/bin/env python3
"""Fail-closed Linux-native T2 enrollment state machine (live gate closed)."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import socket
import sys
import math
from typing import Callable


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


coupled = _load("enroll_probe_coupled", "coupled-bridge-query.py")
biometric = _load("enroll_probe_biometric", "biometric-command.py")

LIVE_ENROLLMENT_ENABLED = False
MAX_EVENTS = 256
READY_STATUS = 0xE3FF8001
# Minimum payload sizes enforced by Catalina's service-status jump-table arms.
PROGRESS_MINIMUMS = {
    0xE3FF8004: 12,
    0xE3FF8005: 17,
    0xE3FF8006: 0,
    0xE3FF8007: 0,
    0xE3FF8008: 0,
    0xE3FF8009: 0,
    0xE3FF800A: 6,
}


class EnrollmentProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class EnrollmentProbeResult:
    user_id: int
    identities_before: int
    identities_after: int
    observed_statuses: tuple[int, ...]
    observed_events: tuple[tuple[int, int, int], ...]
    cancel_status: int


def _perform(session, fields):
    protocol = coupled.bridge_query.protocol
    request = list(protocol.biometric_perform_request(*fields))
    logical = session.call(request)
    return protocol.decode_perform_command_reply(tuple(logical),
                                                  max_output=fields[4])


def _identities(session, user_id: int):
    status, output = _perform(session, biometric.identity_list_fields(user_id=user_id))
    if status != 0:
        raise EnrollmentProbeError(f"identity enumeration failed with status {status}")
    identities = biometric.decode_identity_list(output or b"")
    if any(identity.user_id != user_id for identity in identities):
        raise EnrollmentProbeError("sensor returned an identity for a different user")
    return identities


def probe_socket(sock, *, user_id: int,
                 progress: Callable[[tuple[int, int, int]], None] | None = None
                 ) -> EnrollmentProbeResult:
    """Enroll one token-free identity and prove an exact terminal/list delta."""
    session = coupled.bridge_query.BridgeSession(sock)
    before = _identities(session, user_id)
    statuses: list[int] = []
    events: list[tuple[int, int, int]] = []
    terminal_identity = None
    cancel_status = -1
    after = None
    try:
        start_status, output = _perform(
            session, biometric.ordinary_enroll_fields(user_id=user_id))
        if start_status != 0 or output is not None:
            output_length = len(output) if isinstance(output, bytes) else None
            raise EnrollmentProbeError(
                "enrollment command did not start cleanly: "
                f"status={start_status} output_length={output_length}")
        for _ in range(MAX_EVENTS):
            try:
                envelope = session.receive_event()
                event = biometric.decode_bridge_service_event(envelope.message)
            except (socket.timeout, TimeoutError) as error:
                raise EnrollmentProbeError(
                    "enrollment timed out before a terminal result") from error
            except (coupled.bridge_query.QueryError,
                    biometric.BiometricCommandError) as error:
                raise EnrollmentProbeError("enrollment event transport was invalid") from error
            statuses.append(event.status)
            metadata = (event.status, event.version, len(event.data))
            events.append(metadata)
            if progress is not None:
                progress(metadata)
            if event.status == biometric.SERVICE_EVENT_ENROLL_RESULT:
                try:
                    terminal_identity = biometric.decode_catalina_enroll_result_event(
                        status=event.status, version=event.version, data=event.data)
                except biometric.BiometricCommandError as error:
                    raise EnrollmentProbeError(
                        "terminal enrollment result was invalid: "
                        f"version={event.version} length={len(event.data)} "
                        f"events={events!r}") from error
                break
            if event.status == READY_STATUS:
                if event.version not in (1, 2) or len(event.data) > 4096:
                    raise EnrollmentProbeError("ready event has an unsupported shape")
                continue
            minimum = PROGRESS_MINIMUMS.get(event.status)
            if minimum is None or event.version != 1 or len(event.data) < minimum:
                raise EnrollmentProbeError(
                    f"unexpected enrollment status {event.status:#x}")
        if terminal_identity is None:
            raise EnrollmentProbeError("no terminal enrollment result within the event limit")
        after = _identities(session, user_id)
        try:
            added = biometric.identify_enrollment_delta(
                before, after, expected_user_id=user_id)
        except biometric.BiometricCommandError as error:
            raise EnrollmentProbeError("identity snapshot delta rejected enrollment") from error
        if added != terminal_identity:
            raise EnrollmentProbeError(
                "terminal identity does not equal the newly enumerated identity")
    finally:
        try:
            cancel_status, _ = _perform(session, biometric.cancel_fields())
        except Exception:
            cancel_status = -1
    assert after is not None
    return EnrollmentProbeResult(user_id, len(before), len(after),
                                 tuple(statuses), tuple(events), cancel_status)


def live_probe(*, user_id: int, interface: str = "enp4s0f1u1",
               timeout: float = 5.0, event_timeout: float = 30.0,
               progress: Callable[[tuple[int, int, int]], None] | None = None
               ) -> EnrollmentProbeResult:
    if not LIVE_ENROLLMENT_ENABLED:
        raise EnrollmentProbeError("live enrollment is disabled in source")
    if (isinstance(event_timeout, bool)
            or not isinstance(event_timeout, (int, float))
            or not math.isfinite(event_timeout)
            or not 1.0 <= event_timeout <= 60.0):
        raise EnrollmentProbeError("event timeout must be finite and in 1..60 seconds")
    result = None

    def run(sock):
        nonlocal result
        sock.settimeout(event_timeout)
        result = probe_socket(sock, user_id=user_id, progress=progress)
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
        raise EnrollmentProbeError("enrollment produced no result")
    return result
