#!/usr/bin/env python3
"""Fail-closed T2 match runner with trusted identity correlation.

The live gate is false by default. Results never expose sensor identity UUIDs.
"""

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


coupled = _load("match_probe_coupled", "coupled-bridge-query.py")
biometric = _load("match_probe_biometric", "biometric-command.py")
authentication = _load("match_probe_authentication", "authentication-result.py")

LIVE_MATCH_ENABLED = False
MAX_EVENTS = 32
NONTERMINAL_READY = 0xE3FF8001
NONTERMINAL_MINIMUMS = {
    0xE3FF8004: 12,
    0xE3FF8005: 17,
    0xE3FF8006: 0,
    0xE3FF8007: 0,
    0xE3FF8008: 0,
    0xE3FF8009: 0,
    0xE3FF800A: 6,
}


class MatchProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class MatchProbeResult:
    matched: bool
    matched_user_id: int | None
    trusted_identity_count: int
    observed_statuses: tuple[int, ...]
    observed_events: tuple[tuple[int, int, int], ...]
    cancel_status: int


def _perform(session, fields):
    protocol = coupled.bridge_query.protocol
    request = list(protocol.biometric_perform_request(*fields))
    logical = session.call(request)
    return protocol.decode_perform_command_reply(tuple(logical),
                                                  max_output=fields[4])


def _trusted_identities(session, user_id: int):
    fields = biometric.identity_list_fields(user_id=user_id)
    status, output = _perform(session, fields)
    if status != 0:
        raise MatchProbeError(f"identity enumeration failed with status {status}")
    identities = biometric.decode_identity_list(output or b"")
    if not identities:
        raise MatchProbeError("no trusted sensor identity exists for this user")
    if any(identity.user_id != user_id for identity in identities):
        raise MatchProbeError("sensor returned an identity for a different user")
    return identities


def probe_socket(sock, *, user_id: int) -> MatchProbeResult:
    """Run one match, bind its terminal event to a fresh trusted snapshot."""
    session = coupled.bridge_query.BridgeSession(sock)
    identities = _trusted_identities(session, user_id)
    trusted = tuple(authentication.biometric.BiometricIdentity(
        identity.user_id, identity.uuid) for identity in identities)
    operation = authentication.MatchAuthentication(
        expected_user_id=user_id, trusted_identities=trusted)
    statuses: list[int] = []
    events: list[tuple[int, int, int]] = []
    cancel_status = -1
    terminal = None
    decision = None
    try:
        start_status, output = _perform(
            session, biometric.ordinary_match_fields())
        if start_status != 0 or output is not None:
            operation.abort()
            raise MatchProbeError("match command did not start cleanly")
        for _ in range(MAX_EVENTS):
            try:
                envelope = session.receive_event()
                event = biometric.decode_bridge_service_event(envelope.message)
            except (socket.timeout, TimeoutError) as error:
                operation.abort()
                raise MatchProbeError(
                    "match timed out before a terminal result; statuses="
                    + ",".join(f"{status:#x}" for status in statuses)
                    + " events=" + repr(events)) from error
            except (coupled.bridge_query.QueryError,
                    biometric.BiometricCommandError) as error:
                operation.abort()
                raise MatchProbeError("match event transport was invalid") from error
            statuses.append(event.status)
            events.append((event.status, event.version, len(event.data)))
            if event.status == biometric.SERVICE_EVENT_MATCH_RESULT:
                try:
                    terminal = operation.accept_terminal(
                        status=event.status, version=event.version, data=event.data)
                except authentication.AuthenticationResultError as error:
                    offsets = biometric.trusted_identity_offsets(
                        event.data,
                        tuple(biometric.BiometricIdentity(i.user_id, i.uuid)
                              for i in identities))
                    raise MatchProbeError(
                        "terminal match result was rejected: "
                        f"version={event.version} length={len(event.data)} "
                        f"trusted_identity_offsets={offsets!r} "
                        f"events={events!r}") from error
                break
            if event.status == NONTERMINAL_READY:
                continue
            if event.status == biometric.SERVICE_EVENT_MATCH_ACTIVITY:
                if event.version != 1 or len(event.data) < 9:
                    operation.abort()
                    raise MatchProbeError("match activity event has an unsupported shape")
                continue
            minimum = NONTERMINAL_MINIMUMS.get(event.status)
            if minimum is not None:
                if event.version != 1 or len(event.data) < minimum:
                    operation.abort()
                    raise MatchProbeError("match progress event has an unsupported shape")
                continue
            operation.abort()
            raise MatchProbeError(f"unexpected service status {event.status:#x}")
        if terminal is None:
            operation.abort()
            raise MatchProbeError("no terminal match result within the event limit")
        decision = operation.finish()
    finally:
        try:
            cancel_status, _ = _perform(session, biometric.cancel_fields())
        except Exception:
            # Cancellation is best-effort after a transport failure; never turn
            # its failure into authentication success.
            cancel_status = -1
    assert decision is not None
    return MatchProbeResult(
        decision.matched,
        decision.identity.user_id if decision.identity is not None else None,
        len(identities), tuple(statuses), tuple(events), cancel_status)


def live_probe(*, user_id: int, interface: str = "enp4s0f1u1",
               timeout: float = 5.0) -> MatchProbeResult:
    if not LIVE_MATCH_ENABLED:
        raise MatchProbeError("live match probe is disabled in source")
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
        raise MatchProbeError("match probe produced no result")
    return result
