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
COMMAND_MATCH = 0x04
COMMAND_CANCEL = 0x0C
COMMAND_PRESENCE_DETECT = 0x26
DEFAULT_USER_ID = 0xFFFFFFFF
ORDINARY_MATCH_FLAGS = 0
MATCH_PAYLOAD = struct.Struct("<II60s")
CATALINA_MATCH_RESULT_BASE_SIZE = 0xC70
CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET = 0xC6C
CATALINA_MATCH_RESULT_LOTL_OFFSET = 0xC70
MAX_LOTL_USER_IDS = 64


@dataclass(frozen=True)
class OrdinaryMatchPayload:
    processed_flags: int
    user_id: int


@dataclass(frozen=True)
class CatalinaMatchIdentity:
    user_id: int
    uuid: bytes
    lotl_user_ids: tuple[int, ...]


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


def presence_detect_fields() -> tuple[int, int, int, bytes, int]:
    """Return Catalina's no-input presence-detect command fields."""
    return COMMAND_PRESENCE_DETECT, COMMAND_VERSION, 0, b"", 0


def cancel_fields() -> tuple[int, int, int, bytes, int]:
    """Return Catalina's no-input cancellation command fields."""
    return COMMAND_CANCEL, COMMAND_VERSION, 0, b"", 0


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
