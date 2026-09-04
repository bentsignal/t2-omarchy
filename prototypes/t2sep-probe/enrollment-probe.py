#!/usr/bin/env python3
"""Fail-closed Linux-native T2 enrollment state machine (live gate closed)."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import socket
import sys
import math
import struct
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
sensor_context = _load(
    "enroll_probe_sensor_context", "external-catacomb-load-probe.py")

LIVE_ENROLLMENT_ENABLED = False
MAX_EVENTS = 256
KIORETURN_BAD_ARGUMENT = -536870206
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
    policy_initialized: bool = False
    catacomb_saved: bool = False


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


def _identity_capacity(session, user_id: int) -> tuple[int, int]:
    maximum_status, maximum_output = _perform(
        session, biometric.max_identity_count_fields()
    )
    free_status, free_output = _perform(
        session, biometric.free_identity_count_fields(user_id=user_id)
    )
    if maximum_status != 0 or free_status != 0:
        raise EnrollmentProbeError("identity capacity query failed")
    try:
        maximum = biometric.decode_identity_count(maximum_output or b"")
        free = biometric.decode_identity_count(free_output or b"")
    except biometric.BiometricCommandError as error:
        raise EnrollmentProbeError("identity capacity reply was invalid") from error
    if free > maximum:
        raise EnrollmentProbeError("identity capacity reply is inconsistent")
    return maximum, free


def _persist_catacomb(session, *, user_id: int, component_name: str,
                       catacomb_sink: Callable[[str, bytes], None],
                       stage: str) -> None:
    """Durably sink one service snapshot before acknowledging its save."""
    prepare_status, prepared_size = _perform(
        session, biometric.prepare_save_catacomb_fields(user_id=user_id))
    if prepare_status != 0:
        raise EnrollmentProbeError(
            f"{stage} catacomb save preparation failed with status {prepare_status}")
    try:
        blob_size = biometric.decode_prepared_catacomb_size(prepared_size or b"")
    except biometric.BiometricCommandError as error:
        raise EnrollmentProbeError(
            f"{stage} catacomb save size was invalid") from error
    original_body_cap = coupled.bridge_query.BODY_CAP
    try:
        # The binary plist adds bounded metadata around the opaque blob.
        coupled.bridge_query.BODY_CAP = max(
            original_body_cap, blob_size + 64 * 1024)
        complete_status, blob = _perform(
            session, biometric.complete_save_catacomb_fields(
                user_id=user_id, blob_size=blob_size))
    finally:
        coupled.bridge_query.BODY_CAP = original_body_cap
    if complete_status != 0 or not isinstance(blob, bytes) or len(blob) != blob_size:
        raise EnrollmentProbeError(
            f"{stage} catacomb save completion failed with status {complete_status}")
    try:
        biometric.load_catacomb_fields(user_id=user_id, blob=blob)
        catacomb_sink(component_name, blob)
    except Exception as error:
        raise EnrollmentProbeError(f"{stage} catacomb persistence sink failed") from error
    confirm_status, confirm_output = _perform(
        session, biometric.confirm_save_catacomb_fields(user_id=user_id))
    if confirm_status != 0 or confirm_output is not None:
        raise EnrollmentProbeError(
            f"{stage} catacomb save confirmation failed with status {confirm_status}")


def _initialize_current_bridge(session) -> None:
    """Mirror biometrickitd's current per-connection initialization exactly."""
    protocol = coupled.bridge_query.protocol
    version_reply = session.call([protocol.GET_BRIDGE_VERSION])
    if (len(version_reply) != 2 or version_reply[0] != 0
            or isinstance(version_reply[1], bool)
            or not isinstance(version_reply[1], int)
            or version_reply[1] < 1):
        raise EnrollmentProbeError("bridge version reply was invalid")
    if version_reply[1] > 1:
        client_reply = session.call([protocol.SET_BRIDGE_CLIENT_VERSION, 2])
        if client_reply != [0]:
            raise EnrollmentProbeError("bridge client-version negotiation failed")
    opened_reply = session.call([protocol.GET_SERVICE_OPENED])
    if opened_reply != [0, True]:
        raise EnrollmentProbeError("biometric service did not report opened")


def _establish_enrollment_sensor_context(session, *, catacomb_populated: bool) -> None:
    """Mirror the daemon's non-secret state reads on the enrollment session."""
    sensor_context._establish_nonsecret_context(session)
    status, output = _perform(session, biometric.system_protected_config_fields())
    if status != 0:
        raise EnrollmentProbeError(
            f"system protected-config query failed with status {status}")
    biometric.decode_system_protected_config(output or b"")
    status, output = _perform(session, biometric.catacomb_state_fields())
    if status not in (0, KIORETURN_BAD_ARGUMENT):
        raise EnrollmentProbeError(
            f"catacomb-state query failed with status {status}")
    if status == 0:
        biometric.validate_opaque_record_array(
            output or b"", record_size=biometric.CATACOMB_STATE_RECORD_SIZE,
            maximum_records=biometric.MAX_CATACOMB_STATE_RECORDS)
    catacomb_state_absent = status == KIORETURN_BAD_ARGUMENT
    status, output = _perform(session, biometric.catacomb_group_state_fields())
    if status not in (0, KIORETURN_BAD_ARGUMENT):
        raise EnrollmentProbeError(
            f"catacomb-group-state query failed with status {status}")
    if status == 0:
        biometric.validate_opaque_record_array(
            output or b"", record_size=biometric.CATACOMB_GROUP_STATE_RECORD_SIZE,
            maximum_records=biometric.MAX_CATACOMB_GROUP_STATE_RECORDS)
    group_state_absent = status == KIORETURN_BAD_ARGUMENT
    if catacomb_state_absent != group_state_absent:
        raise EnrollmentProbeError("catacomb state availability is inconsistent")
    if catacomb_state_absent and not catacomb_populated:
        status, output = _perform(
            session, biometric.no_catacomb_fields(
                user_id=biometric.DEFAULT_USER_ID))
        if status != 0 or output is not None:
            raise EnrollmentProbeError(
                f"cold global catacomb initialization failed with status {status}")
    status, output = _perform(
        session, biometric.xart_available_fields(version=1))
    if status != 0:
        raise EnrollmentProbeError(
            f"xART availability query failed with status {status}")
    if not biometric.decode_xart_available(output or b""):
        raise EnrollmentProbeError("xART is unavailable for enrollment")


def probe_socket(sock, *, user_id: int,
                 authorized_request=None,
                 policy_request=None,
                 establish_sensor_context: bool = False,
                 catacomb_sink: Callable[[bytes], None] | None = None,
                 component_sink: Callable[[str, bytes], None] | None = None,
                 mutation_begin: Callable[[tuple[biometric.BiometricIdentity, ...], int, int], None] | None = None,
                 terminal_sink: Callable[[biometric.BiometricIdentity], None] | None = None,
                 persistence_commit: Callable[[], None] | None = None,
                 progress: Callable[[tuple[int, int, int]], None] | None = None
                 ) -> EnrollmentProbeResult:
    """Enroll one token-free identity and prove an exact terminal/list delta."""
    session = coupled.bridge_query.BridgeSession(sock)
    _initialize_current_bridge(session)
    before = None
    if establish_sensor_context:
        before = _identities(session, user_id)
        try:
            _establish_enrollment_sensor_context(
                session, catacomb_populated=bool(before)
            )
        except (sensor_context.ExternalCatacombLoadError,
                sensor_context.state.biometric.BiometricCommandError) as error:
            raise EnrollmentProbeError(
                "same-session sensor initialization failed") from error
    policy_initialized = False
    if policy_request is not None:
        if not isinstance(policy_request, biometric.AuthorizedPolicyRequest):
            raise EnrollmentProbeError("policy request has the wrong type")
        policy_payload = bytes(policy_request.view())
        expected_policy = struct.unpack_from("<4I", policy_payload, 4)
        global_status, global_output = _perform(
            session, biometric.no_catacomb_fields(
                user_id=biometric.DEFAULT_USER_ID))
        if global_status != 0 or global_output is not None:
            policy_request.close()
            raise EnrollmentProbeError(
                f"empty global catacomb initialization failed with status {global_status}")
        no_catacomb_status, no_catacomb_output = _perform(
            session, biometric.no_catacomb_fields(user_id=user_id))
        if no_catacomb_status != 0 or no_catacomb_output is not None:
            policy_request.close()
            raise EnrollmentProbeError(
                f"empty catacomb initialization failed with status {no_catacomb_status}")
        try:
            policy_status, policy_output = _perform(
                session, biometric.authorized_user_policy_fields(policy_request))
        finally:
            policy_request.close()
        if policy_status != 0 or policy_output is not None:
            raise EnrollmentProbeError(
                f"protected policy creation failed with status {policy_status}")
        read_status, read_output = _perform(
            session, biometric.protected_config_fields(user_id=user_id))
        if read_status != 0 or not isinstance(read_output, bytes) or len(read_output) != 32:
            raise EnrollmentProbeError(
                f"protected policy readback failed with status {read_status}")
        if struct.unpack_from("<4I", read_output) != expected_policy:
            raise EnrollmentProbeError("protected policy readback did not match the requested policy")
        policy_initialized = True
    if before is None or policy_initialized:
        before = _identities(session, user_id)
    full_transaction = component_sink is not None
    if full_transaction != all(
        callback is not None
        for callback in (mutation_begin, terminal_sink, persistence_commit)
    ):
        raise EnrollmentProbeError(
            "three-component persistence requires every transaction callback"
        )
    if catacomb_sink is not None and full_transaction:
        raise EnrollmentProbeError("legacy and three-component persistence conflict")
    if mutation_begin is not None:
        maximum, free = _identity_capacity(session, user_id)
        if free < 1 or len(before) >= maximum:
            raise EnrollmentProbeError("identity capacity is exhausted")
        mutation_begin(before, maximum, free)
    statuses: list[int] = []
    events: list[tuple[int, int, int]] = []
    terminal_identity = None
    cancel_status = -1
    after = None
    catacomb_saved = False
    try:
        if authorized_request is None:
            fields = biometric.ordinary_enroll_fields(user_id=user_id)
        else:
            fields = biometric.authorized_enroll_fields(authorized_request)
        try:
            start_status, output = _perform(session, fields)
        finally:
            if authorized_request is not None:
                authorized_request.close()
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
        if terminal_sink is not None:
            terminal_sink(terminal_identity)
        if component_sink is not None:
            _persist_catacomb(
                session,
                user_id=user_id,
                component_name=f"user_{user_id:08x}.cat",
                catacomb_sink=component_sink,
                stage="enrolled user",
            )
            _persist_catacomb(
                session,
                user_id=biometric.DEFAULT_USER_ID,
                component_name="master.cat",
                catacomb_sink=component_sink,
                stage="enrolled master",
            )
            lockout_status, lockout_blob = _perform(
                session, biometric.save_biolockout_fields()
            )
            if lockout_status != 0:
                raise EnrollmentProbeError(
                    "bio-lockout save failed with status "
                    f"{lockout_status}"
                )
            try:
                lockout_blob = biometric.decode_saved_biolockout(
                    lockout_blob or b""
                )
                component_sink("biolockout.cat", lockout_blob)
                persistence_commit()
            except Exception as error:
                raise EnrollmentProbeError(
                    "three-component persistence finalization failed"
                ) from error
            catacomb_saved = True
        if catacomb_sink is not None:
            _persist_catacomb(session, user_id=user_id,
                              component_name=f"user_{user_id:08x}.cat",
                              catacomb_sink=lambda _name, blob: catacomb_sink(blob),
                              stage="enrolled")
            catacomb_saved = True
    finally:
        try:
            cancel_status, _ = _perform(session, biometric.cancel_fields())
        except Exception:
            cancel_status = -1
    assert after is not None
    return EnrollmentProbeResult(user_id, len(before), len(after),
                                 tuple(statuses), tuple(events), cancel_status,
                                 policy_initialized, catacomb_saved)


def live_probe(*, user_id: int, interface: str = "enp4s0f1u1",
               timeout: float = 5.0, event_timeout: float = 30.0,
               authorized_request=None,
               policy_request=None,
               establish_sensor_context: bool = False,
               catacomb_sink: Callable[[bytes], None] | None = None,
               component_sink: Callable[[str, bytes], None] | None = None,
               mutation_begin=None,
               terminal_sink=None,
               persistence_commit=None,
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
        result = probe_socket(sock, user_id=user_id,
                              authorized_request=authorized_request,
                              policy_request=policy_request,
                              establish_sensor_context=establish_sensor_context,
                              catacomb_sink=catacomb_sink,
                              component_sink=component_sink,
                              mutation_begin=mutation_begin,
                              terminal_sink=terminal_sink,
                              persistence_commit=persistence_commit,
                              progress=progress)
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
