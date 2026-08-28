#!/usr/bin/env python3
"""Fail-closed offline codec for ordinary Intel Touch ID operations.

The command ABI comes from Catalina 10.15.7 (19H15) x86_64 BiometricKit.
Nothing in this module opens a socket or accesses USB, PCI, or SEP hardware.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct


class BiometricCommandError(ValueError):
    pass


COMMAND_VERSION = 1
COMMAND_ENROLL = 0x03
COMMAND_MATCH = 0x04
COMMAND_CANCEL = 0x0C
COMMAND_REMOVE_IDENTITY = 0x0D
COMMAND_MAX_IDENTITY_COUNT = 0x0F
COMMAND_PRESENCE_DETECT = 0x26
COMMAND_FREE_IDENTITY_COUNT = 0x41
COMMAND_IDENTITY_LIST = 0x42
DEFAULT_USER_ID = 0xFFFFFFFF
ORDINARY_MATCH_FLAGS = 0
MATCH_PAYLOAD = struct.Struct("<II60s")
ENROLL_PAYLOAD = struct.Struct("<IIII32s")
CATALINA_MATCH_RESULT_BASE_SIZE = 0xC70
CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET = 0xC6C
CATALINA_MATCH_RESULT_LOTL_OFFSET = 0xC70
MAX_LOTL_USER_IDS = 64
IDENTITY = struct.Struct("<I16s")
MAX_IDENTITIES = 64
SERVICE_EVENT_MATCH_RESULT = 0xE3FF8002
SERVICE_EVENT_ENROLL_RESULT = 0xE3FF8003
SERVICE_EVENT_MATCH_ACTIVITY = 0xE3FF800B
SERVICE_EVENT_VERSION = 1


@dataclass(frozen=True)
class OrdinaryMatchPayload:
    processed_flags: int
    user_id: int


@dataclass(frozen=True)
class OrdinaryEnrollPayload:
    processed_flags: int
    user_id: int
    using_auth_token: int
    token_length: int


@dataclass(frozen=True)
class CatalinaMatchIdentity:
    user_id: int
    uuid: bytes
    lotl_user_ids: tuple[int, ...]


@dataclass(frozen=True)
class BiometricIdentity:
    user_id: int
    uuid: bytes


def _u32(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BiometricCommandError(f"{field} must be an integer")
    if not 0 <= value <= 0xFFFFFFFF:
        raise BiometricCommandError(f"{field} does not fit in 32 bits")
    return value


def encode_ordinary_match_payload(*, user_id: int = DEFAULT_USER_ID) -> bytes:
    """Encode only Apple's zero-flag, 68-byte ordinary-match input.

    Special modes share the trailing union. Keeping all 60 bytes zero makes
    credential-set, enrollment-extension, and lockout-bypass inputs impossible
    to express through this API.
    """
    user_id = _u32(user_id, "user ID")
    return MATCH_PAYLOAD.pack(ORDINARY_MATCH_FLAGS, user_id, bytes(60))


def encode_ordinary_enroll_payload(*, user_id: int) -> bytes:
    """Encode only Catalina's token-free 48-byte enrollment input."""
    user_id = _u32(user_id, "user ID")
    return ENROLL_PAYLOAD.pack(0, user_id, 0, 0, bytes(32))


def decode_ordinary_enroll_payload(payload: bytes) -> OrdinaryEnrollPayload:
    """Reject authorization-token and unknown enrollment variants."""
    if not isinstance(payload, bytes) or len(payload) != ENROLL_PAYLOAD.size:
        raise BiometricCommandError("ordinary enrollment payload must be exactly 48 bytes")
    flags, user_id, using_token, token_length, token = ENROLL_PAYLOAD.unpack(payload)
    if flags != 0:
        raise BiometricCommandError("special or unknown enrollment flags are forbidden")
    if using_token != 0 or token_length != 0 or token != bytes(32):
        raise BiometricCommandError("authorization-token enrollment is forbidden")
    return OrdinaryEnrollPayload(flags, user_id, using_token, token_length)


def decode_ordinary_match_payload(payload: bytes) -> OrdinaryMatchPayload:
    """Accept only the exact ordinary form and reject all special variants."""
    if not isinstance(payload, bytes) or len(payload) != MATCH_PAYLOAD.size:
        raise BiometricCommandError("ordinary match payload must be exactly 68 bytes")
    flags, user_id, special = MATCH_PAYLOAD.unpack(payload)
    if flags != ORDINARY_MATCH_FLAGS:
        raise BiometricCommandError("special or unknown match flags are forbidden")
    if special != bytes(60):
        raise BiometricCommandError("special match union must be all zero")
    return OrdinaryMatchPayload(flags, user_id)


def ordinary_match_fields(*, user_id: int = DEFAULT_USER_ID) -> tuple[int, int, int, bytes, int]:
    """Return arguments for bridge_protocol.biometric_perform_request()."""
    return (COMMAND_MATCH, COMMAND_VERSION, 0,
            encode_ordinary_match_payload(user_id=user_id), 0)


def ordinary_enroll_fields(*, user_id: int) -> tuple[int, int, int, bytes, int]:
    """Return token-free enrollment fields for offline Bridge composition."""
    return (COMMAND_ENROLL, COMMAND_VERSION, 0,
            encode_ordinary_enroll_payload(user_id=user_id), 0)


def presence_detect_fields() -> tuple[int, int, int, bytes, int]:
    """Return Catalina's no-input presence-detect command fields."""
    return COMMAND_PRESENCE_DETECT, COMMAND_VERSION, 0, b"", 0


def cancel_fields() -> tuple[int, int, int, bytes, int]:
    """Return Catalina's no-input cancellation command fields."""
    return COMMAND_CANCEL, COMMAND_VERSION, 0, b"", 0


def max_identity_count_fields() -> tuple[int, int, int, bytes, int]:
    return COMMAND_MAX_IDENTITY_COUNT, COMMAND_VERSION, 0, b"", 4


def free_identity_count_fields(*, user_id: int) -> tuple[int, int, int, bytes, int]:
    user_id = _u32(user_id, "user ID")
    return COMMAND_FREE_IDENTITY_COUNT, COMMAND_VERSION, 0, struct.pack("<I", user_id), 4


def identity_list_fields(*, user_id: int,
                         max_identities: int = MAX_IDENTITIES) -> tuple[int, int, int, bytes, int]:
    user_id = _u32(user_id, "user ID")
    if (isinstance(max_identities, bool) or not isinstance(max_identities, int)
            or not 1 <= max_identities <= MAX_IDENTITIES):
        raise BiometricCommandError(f"max identities must be in 1..{MAX_IDENTITIES}")
    return (COMMAND_IDENTITY_LIST, COMMAND_VERSION, 0,
            struct.pack("<I", user_id), IDENTITY.size * max_identities)


def decode_identity_count(output: bytes) -> int:
    if not isinstance(output, bytes) or len(output) != 4:
        raise BiometricCommandError("identity count output must be exactly 4 bytes")
    count = struct.unpack("<I", output)[0]
    if count > MAX_IDENTITIES:
        raise BiometricCommandError("identity count exceeds the supported safety cap")
    return count


def decode_identity_list(output: bytes) -> tuple[BiometricIdentity, ...]:
    if not isinstance(output, bytes):
        raise BiometricCommandError("identity list output must be bytes")
    if len(output) % IDENTITY.size:
        raise BiometricCommandError("identity list is not a sequence of 20-byte records")
    if len(output) > IDENTITY.size * MAX_IDENTITIES:
        raise BiometricCommandError("identity list exceeds the supported safety cap")
    identities = tuple(BiometricIdentity(*IDENTITY.unpack_from(output, offset))
                       for offset in range(0, len(output), IDENTITY.size))
    if len(set(identities)) != len(identities):
        raise BiometricCommandError("identity list contains duplicates")
    return identities


def remove_identity_fields(identity: BiometricIdentity) -> tuple[int, int, int, bytes, int]:
    """Return offline fields for Catalina's mutating identity removal."""
    if not isinstance(identity, BiometricIdentity):
        raise BiometricCommandError("identity must be a BiometricIdentity")
    user_id = _u32(identity.user_id, "user ID")
    if not isinstance(identity.uuid, bytes) or len(identity.uuid) != 16:
        raise BiometricCommandError("identity UUID must be exactly 16 bytes")
    return (COMMAND_REMOVE_IDENTITY, COMMAND_VERSION, 0,
            IDENTITY.pack(user_id, identity.uuid), 0)


def identify_enrollment_delta(
        before: tuple[BiometricIdentity, ...],
        after: tuple[BiometricIdentity, ...], *,
        expected_user_id: int) -> BiometricIdentity:
    """Require one new identity and no unrelated list mutation.

    This is an offline completion check, not proof that an enrollment event is
    authentic. A live caller must obtain both snapshots through its own
    correlated operation and successful terminal-status state machine.
    """
    expected_user_id = _u32(expected_user_id, "expected user ID")
    if not isinstance(before, tuple) or not isinstance(after, tuple):
        raise BiometricCommandError("identity snapshots must be tuples")
    if any(not isinstance(item, BiometricIdentity) for item in before + after):
        raise BiometricCommandError("identity snapshots contain an invalid record")
    if len(set(before)) != len(before) or len(set(after)) != len(after):
        raise BiometricCommandError("identity snapshots contain duplicates")
    removed = set(before) - set(after)
    added = set(after) - set(before)
    if removed or len(added) != 1:
        raise BiometricCommandError("enrollment must add exactly one identity")
    identity = next(iter(added))
    if identity.user_id != expected_user_id:
        raise BiometricCommandError("new identity belongs to an unexpected user")
    return identity


def decode_catalina_match_identity(blob: bytes) -> CatalinaMatchIdentity:
    """Decode only identity fields proven in Catalina's async match result.

    This does not authenticate a user by itself. A caller must also prove the
    event belongs to its active operation, validate completion status, and map
    the returned identity against a separately enumerated trusted identity.
    """
    if not isinstance(blob, bytes):
        raise BiometricCommandError("match result must be bytes")
    if len(blob) < CATALINA_MATCH_RESULT_BASE_SIZE:
        raise BiometricCommandError("match result is shorter than Catalina's base struct")
    lotl_count = struct.unpack_from("<I", blob,
                                    CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET)[0]
    if lotl_count > MAX_LOTL_USER_IDS:
        raise BiometricCommandError("match result has too many lockout-list user IDs")
    expected = CATALINA_MATCH_RESULT_BASE_SIZE + 4 * lotl_count
    if len(blob) != expected:
        raise BiometricCommandError("match result size does not exactly match its count")
    user_id = struct.unpack_from("<I", blob, 0)[0]
    uuid = blob[4:20]
    lotl_user_ids = struct.unpack_from(f"<{lotl_count}I", blob,
                                       CATALINA_MATCH_RESULT_LOTL_OFFSET)
    return CatalinaMatchIdentity(user_id, uuid, lotl_user_ids)


def decode_catalina_enroll_result_event(
        *, status: int, version: int, data: bytes) -> BiometricIdentity:
    """Decode Catalina's terminal identity-created service event.

    The daemon accepts a longer NSData object but consumes only the first
    20-byte identity. This research boundary requires the exact consumed size.
    """
    if status != SERVICE_EVENT_ENROLL_RESULT or version != SERVICE_EVENT_VERSION:
        raise BiometricCommandError("not a supported enrollment-result event")
    identities = decode_identity_list(data)
    if len(identities) != 1:
        raise BiometricCommandError("enrollment result must contain one identity")
    return identities[0]


def decode_catalina_match_result_event(
        *, status: int, version: int, data: bytes) -> CatalinaMatchIdentity:
    """Bind a raw match result to Catalina's proven service event/version."""
    if status != SERVICE_EVENT_MATCH_RESULT or version != SERVICE_EVENT_VERSION:
        raise BiometricCommandError("not a supported match-result event")
    return decode_catalina_match_identity(data)


def decode_terminal_biometric_event(
        *, active_operation: str, status: int, version: int,
        data: bytes) -> BiometricIdentity | CatalinaMatchIdentity:
    """Decode a result only when it matches the sole host-tracked operation."""
    if active_operation == "enroll":
        return decode_catalina_enroll_result_event(
            status=status, version=version, data=data)
    if active_operation == "match":
        return decode_catalina_match_result_event(
            status=status, version=version, data=data)
    raise BiometricCommandError("there is no supported active biometric operation")
