#!/usr/bin/env python3
"""Read-only T2 per-user biometric-state shape probe; opaque records stay hidden."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import struct
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


coupled = _load("user_state_coupled", "coupled-bridge-query.py")
biometric = _load("user_state_biometric", "biometric-command.py")

CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_BIOMETRIC_STATE_SHAPES"
LIVE_USER_STATE_ENABLED = False


class UserStateProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class UserStateResult:
    protected_status: int
    protected_length: int | None
    requested_policy: tuple[int, int, int, int] | None
    effective_policy: tuple[int, int, int, int] | None
    max_identity_status: int
    max_identity_count: int | None
    free_identity_status: int
    free_identity_count: int | None
    identity_list_status: int
    identity_count: int | None
    catacomb_uuid_status: int
    catacomb_uuid_length: int | None
    catacomb_status: int
    catacomb_records: int | None
    group_status: int
    group_records: int | None


def _perform(session, fields):
    protocol = coupled.bridge_query.protocol
    logical = session.call(list(protocol.biometric_perform_request(*fields)))
    return protocol.decode_perform_command_reply(tuple(logical), max_output=fields[4])


def _initialize(session) -> None:
    protocol = coupled.bridge_query.protocol
    if session.call([protocol.GET_BRIDGE_VERSION]) != [0, 3]:
        raise UserStateProbeError("expected current bridge generation 3")
    if session.call([protocol.SET_BRIDGE_CLIENT_VERSION, 2]) != [0]:
        raise UserStateProbeError("client-version negotiation failed")
    if session.call([protocol.GET_SERVICE_OPENED]) != [0, True]:
        raise UserStateProbeError("biometric service did not report opened")


def probe_socket(sock, *, user_id: int) -> UserStateResult:
    session = coupled.bridge_query.BridgeSession(sock)
    _initialize(session)
    protected_status, protected = _perform(
        session, biometric.protected_config_fields(user_id=user_id))
    if protected_status == 0 and (
            not isinstance(protected, bytes)
            or len(protected) != biometric.PROTECTED_CONFIG_SIZE):
        raise UserStateProbeError("successful protected config has invalid size")
    requested_policy = None
    effective_policy = None
    if protected_status == 0:
        words = struct.unpack("<8I", protected)
        requested_policy = words[:4]
        effective_policy = words[4:]
    max_status, max_output = _perform(session, biometric.max_identity_count_fields())
    max_count = None
    if max_status == 0:
        try:
            max_count = biometric.decode_identity_count(max_output or b"")
        except biometric.BiometricCommandError as error:
            raise UserStateProbeError("maximum identity count has invalid shape") from error
    free_status, free_output = _perform(
        session, biometric.free_identity_count_fields(user_id=user_id))
    free_count = None
    if free_status == 0:
        try:
            free_count = biometric.decode_identity_count(free_output or b"")
        except biometric.BiometricCommandError as error:
            raise UserStateProbeError("free identity count has invalid shape") from error
    list_status, list_output = _perform(
        session, biometric.identity_list_fields(user_id=user_id))
    identity_count = None
    if list_status == 0:
        try:
            identities = biometric.decode_identity_list(list_output or b"")
        except biometric.BiometricCommandError as error:
            raise UserStateProbeError("identity list has invalid shape") from error
        if any(identity.user_id != user_id for identity in identities):
            raise UserStateProbeError("identity list contains a foreign user")
        identity_count = len(identities)
    uuid_status, uuid_output = _perform(
        session, biometric.catacomb_uuid_fields(user_id=user_id))
    uuid_length = None
    if uuid_status == 0:
        if not isinstance(uuid_output, bytes) or len(uuid_output) != 16:
            raise UserStateProbeError("catacomb UUID has invalid shape")
        uuid_length = len(uuid_output)
    catacomb_status, catacomb = _perform(session, biometric.catacomb_state_fields())
    catacomb_records = None
    if catacomb_status == 0:
        try:
            catacomb_records = biometric.validate_opaque_record_array(
                catacomb or b"", record_size=biometric.CATACOMB_STATE_RECORD_SIZE,
                maximum_records=biometric.MAX_CATACOMB_STATE_RECORDS)
        except biometric.BiometricCommandError as error:
            raise UserStateProbeError("catacomb state has invalid shape") from error
    group_status, groups = _perform(session, biometric.catacomb_group_state_fields())
    group_records = None
    if group_status == 0:
        try:
            group_records = biometric.validate_opaque_record_array(
                groups or b"", record_size=biometric.CATACOMB_GROUP_STATE_RECORD_SIZE,
                maximum_records=biometric.MAX_CATACOMB_GROUP_STATE_RECORDS)
        except biometric.BiometricCommandError as error:
            raise UserStateProbeError("catacomb group state has invalid shape") from error
    return UserStateResult(
        protected_status,
        len(protected) if protected_status == 0 and isinstance(protected, bytes) else None,
        requested_policy, effective_policy,
        max_status, max_count, free_status, free_count, list_status, identity_count,
        uuid_status, uuid_length,
        catacomb_status, catacomb_records, group_status, group_records)


def live_probe(*, user_id: int, interface: str = "enp4s0f1u1",
               timeout: float = 5.0) -> UserStateResult:
    if not LIVE_USER_STATE_ENABLED:
        raise UserStateProbeError("live user-state probing is disabled in source")
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
        raise UserStateProbeError("user-state probe produced no result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: read-only per-user state shape probe")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    global LIVE_USER_STATE_ENABLED
    LIVE_USER_STATE_ENABLED = True
    try:
        result = live_probe(user_id=args.user_id, interface=args.interface)
    finally:
        LIVE_USER_STATE_ENABLED = False
    print("user biometric state: "
          f"protected_status={result.protected_status} "
          f"protected_length={result.protected_length} "
          f"requested_policy={result.requested_policy} "
          f"effective_policy={result.effective_policy} "
          f"max_identity_status={result.max_identity_status} "
          f"max_identity_count={result.max_identity_count} "
          f"free_identity_status={result.free_identity_status} "
          f"free_identity_count={result.free_identity_count} "
          f"identity_list_status={result.identity_list_status} "
          f"identity_count={result.identity_count} "
          f"catacomb_uuid_status={result.catacomb_uuid_status} "
          f"catacomb_uuid_length={result.catacomb_uuid_length} "
          f"catacomb_status={result.catacomb_status} "
          f"catacomb_records={result.catacomb_records} "
          f"group_status={result.group_status} "
          f"group_records={result.group_records}")


if __name__ == "__main__":
    main()
