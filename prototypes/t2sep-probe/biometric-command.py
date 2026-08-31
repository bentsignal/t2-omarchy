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
CURRENT_COMMAND_VERSION = 2
COMMAND_RESET_SENSOR = 0x02
COMMAND_ENROLL = 0x03
COMMAND_MATCH = 0x04
COMMAND_CANCEL = 0x0C
COMMAND_REMOVE_IDENTITY = 0x0D
COMMAND_MAX_IDENTITY_COUNT = 0x0F
COMMAND_PROVISIONING_STATE = 0x10
COMMAND_PRESENCE_DETECT = 0x26
COMMAND_GET_SKS_LOCK_STATE = 0x27
COMMAND_GET_BIOMETRICKITD_INFO = 0x28
COMMAND_GET_PROTECTED_CONFIG = 0x2E
COMMAND_SET_PROTECTED_CONFIG = 0x2F
COMMAND_NO_CATACOMB = 0x31
COMMAND_SENSOR_INFO = 0x35
COMMAND_GET_CATACOMB_UUID = 0x38
COMMAND_GET_CATACOMB_STATE = 0x3C
COMMAND_PREPARE_SAVE_CATACOMB = 0x3D
COMMAND_COMPLETE_SAVE_CATACOMB = 0x3E
COMMAND_CONFIRM_SAVE_CATACOMB = 0x3F
COMMAND_LOAD_CATACOMB = 0x40
COMMAND_FREE_IDENTITY_COUNT = 0x41
COMMAND_IDENTITY_LIST = 0x42
COMMAND_GET_SYSTEM_PROTECTED_CONFIG = 0x43
COMMAND_IS_XART_AVAILABLE = 0x4C
COMMAND_GET_CATACOMB_GROUP_STATE = 0x50
COMMAND_GET_BIO_DEVICE_LIST = 0x52
COMMAND_SENSOR_READINESS = 0x53
DEFAULT_USER_ID = 0xFFFFFFFF
ORDINARY_MATCH_FLAGS = 0
MATCH_PAYLOAD = struct.Struct("<II60s")
ENROLL_PAYLOAD = struct.Struct("<IIII32s")
CURRENT_ENROLL_PAYLOAD = struct.Struct("<IIII32sI16s")
ACM_EXTERNAL_FORM_SIZE = 16
BUILTIN_DEVICE_GROUP = 1
CATALINA_MATCH_RESULT_BASE_SIZE = 0xC70
CATALINA_MATCH_RESULT_LOTL_COUNT_OFFSET = 0xC6C
CATALINA_MATCH_RESULT_LOTL_OFFSET = 0xC70
CURRENT_MATCH_RESULT_V2_SIZE = 0xC9C
MAX_LOTL_USER_IDS = 64
IDENTITY = struct.Struct("<I16s")
MAX_IDENTITIES = 64
SYSTEM_PROTECTED_CONFIG = struct.Struct("<9I")
PROTECTED_CONFIG_SIZE = 32
SET_PROTECTED_CONFIG_PAYLOAD = struct.Struct("<IIIIIII32s")
CATACOMB_STATE_RECORD_SIZE = 8
CATACOMB_GROUP_STATE_RECORD_SIZE = 56
MAX_CATACOMB_STATE_RECORDS = 256
MAX_CATACOMB_GROUP_STATE_RECORDS = 64
CATACOMB_SAVE_CONTEXT = struct.Struct("<II16s")
CATACOMB_HEADER_MINIMUM_SIZE = 33
# The recovered biometric outbound SBIO aperture is exactly 75 4-KiB pages.
MAX_CATACOMB_BLOB_SIZE = 75 * 4096
SERVICE_EVENT_MATCH_RESULT = 0xE3FF8002
SERVICE_EVENT_ENROLL_RESULT = 0xE3FF8003
SERVICE_EVENT_MATCH_ACTIVITY = 0xE3FF800B
SERVICE_EVENT_VERSION = 1
MATCH_SERVICE_EVENT_VERSIONS = (1, 2)
BRIDGE_SERVICE_EVENT_METHOD = 9
BRIDGE_SERVICE_EVENT_CHANNEL = 0xE3FF8000
SERVICE_RECORD_HEADER_SIZE = 40
MAX_SERVICE_EVENT_DATA = 64 * 1024
PROVISIONING_STATE_SIZE = 4
SENSOR_INFO_SIZE = 12
BIOMETRICKITD_INFO_SIZE = 23
BIO_DEVICE_RECORD = struct.Struct("<I16sI16sI")
MAX_BIO_DEVICE_RECORDS = 6
BIO_DEVICE_LIST_CAPACITY = BIO_DEVICE_RECORD.size * MAX_BIO_DEVICE_RECORDS
BUILTIN_ACCESSORY_TYPE = 1
BUILTIN_DEVICE_GROUP_TYPE = 1


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


class AuthorizedEnrollRequest:
    """One mutable current-format enrollment request with explicit scrubbing."""

    def __init__(self, payload: bytearray) -> None:
        if not isinstance(payload, bytearray) or len(payload) != CURRENT_ENROLL_PAYLOAD.size:
            raise BiometricCommandError("authorized enrollment payload is invalid")
        self._payload = payload
        self.closed = False

    def __repr__(self) -> str:
        return f"AuthorizedEnrollRequest(length={len(self._payload)}, closed={self.closed})"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def view(self) -> memoryview:
        if self.closed:
            raise BiometricCommandError("authorized enrollment request is closed")
        return memoryview(self._payload).toreadonly()

    def close(self) -> None:
        if not getattr(self, "closed", True):
            self._payload[:] = bytes(len(self._payload))
            self.closed = True


@dataclass(frozen=True)
class CatalinaMatchIdentity:
    user_id: int
    uuid: bytes
    lotl_user_ids: tuple[int, ...]


@dataclass(frozen=True)
class BiometricIdentity:
    user_id: int
    uuid: bytes


@dataclass(frozen=True)
class SystemProtectedConfig:
    unlock_token_max_lifetime: int
    reserved_1: int
    reserved_2: int
    biometry_enabled: int
    unlock_enabled: int
    identification_enabled: int
    login_enabled: int
    bio_match_lifespan: int
    passcode_input_lifespan: int


@dataclass(frozen=True)
class UserProtectedPolicy:
    unlock_enabled: int
    identification_enabled: int
    login_enabled: int
    apple_pay_enabled: int


@dataclass(frozen=True)
class SensorInfo:
    version: int
    struct_size: int
    sensor_type: int


@dataclass(frozen=True)
class BioDeviceListSummary:
    record_count: int
    builtin_record_count: int


@dataclass(frozen=True)
class BiometrickitdInfoSummary:
    calibration_present: bool


class AuthorizedPolicyRequest:
    """One mutable current-format per-user policy request with scrubbing."""

    def __init__(self, payload: bytearray) -> None:
        if not isinstance(payload, bytearray) or len(payload) != SET_PROTECTED_CONFIG_PAYLOAD.size:
            raise BiometricCommandError("authorized policy payload is invalid")
        self._payload = payload
        self.closed = False

    def __repr__(self) -> str:
        return f"AuthorizedPolicyRequest(length={len(self._payload)}, closed={self.closed})"

    def view(self) -> memoryview:
        if self.closed:
            raise BiometricCommandError("authorized policy request is closed")
        return memoryview(self._payload).toreadonly()

    def close(self) -> None:
        if not getattr(self, "closed", True):
            self._payload[:] = bytes(len(self._payload))
            self.closed = True

    def __del__(self) -> None:
        self.close()


def system_protected_config_fields():
    """Encode the current read-only generation-3 protected-config query."""
    return (COMMAND_GET_SYSTEM_PROTECTED_CONFIG, CURRENT_COMMAND_VERSION, 0,
            b"", SYSTEM_PROTECTED_CONFIG.size)


def sensor_readiness_fields():
    """Encode the current one-byte, read-only sensor-readiness query."""
    return (COMMAND_SENSOR_READINESS, COMMAND_VERSION, 0, b"", 1)


def decode_sensor_readiness(output: bytes) -> int:
    if not isinstance(output, bytes) or len(output) != 1:
        raise BiometricCommandError("sensor readiness must be exactly one byte")
    return output[0]


def provisioning_state_fields():
    """Encode the current four-byte, read-only provisioning-state query."""
    return (COMMAND_PROVISIONING_STATE, COMMAND_VERSION, 0,
            b"", PROVISIONING_STATE_SIZE)


def sks_lock_state_fields(*, user_id: int, version: int = 0):
    """Encode Catalina's read-only per-user Secure Key Store lock-state query."""
    if isinstance(version, bool) or version not in (0, 1, 2):
        raise BiometricCommandError("SKS lock-state version must be 0, 1, or 2")
    return (COMMAND_GET_SKS_LOCK_STATE, version, 0,
            struct.pack("<I", _u32(user_id, "user ID")), 4)


def decode_sks_lock_state(output: bytes) -> int:
    if not isinstance(output, bytes) or len(output) != 4:
        raise BiometricCommandError("SKS lock state must be exactly four bytes")
    return struct.unpack("<I", output)[0]


def decode_provisioning_state(output: bytes) -> int:
    if not isinstance(output, bytes) or len(output) != PROVISIONING_STATE_SIZE:
        raise BiometricCommandError("provisioning state must be exactly four bytes")
    return struct.unpack("<I", output)[0]


def reset_sensor_fields():
    """Encode one current reset attempt; retry policy belongs to the caller."""
    return (COMMAND_RESET_SENSOR, COMMAND_VERSION, 2, b"", 0)


def sensor_info_fields():
    """Encode the current 12-byte, read-only sensor-information query."""
    return (COMMAND_SENSOR_INFO, COMMAND_VERSION, 0, b"", SENSOR_INFO_SIZE)


def decode_sensor_info(output: bytes) -> SensorInfo:
    if not isinstance(output, bytes) or len(output) != SENSOR_INFO_SIZE:
        raise BiometricCommandError("sensor information must be exactly 12 bytes")
    result = SensorInfo(*struct.unpack("<3I", output))
    if result.struct_size != SENSOR_INFO_SIZE:
        raise BiometricCommandError("sensor information declares the wrong size")
    return result


def bio_device_list_fields():
    """Encode the current bounded, read-only accessory/device-group query."""
    return (COMMAND_GET_BIO_DEVICE_LIST, COMMAND_VERSION, 0,
            b"", BIO_DEVICE_LIST_CAPACITY)


def biometrickitd_info_fields():
    """Encode the current bounded daemon-information read."""
    return (COMMAND_GET_BIOMETRICKITD_INFO, COMMAND_VERSION, 0,
            b"", BIOMETRICKITD_INFO_SIZE)


def decode_biometrickitd_info_summary(output: bytes) -> BiometrickitdInfoSummary:
    """Expose only the statically identified final calibration-present flag."""
    if not isinstance(output, bytes) or len(output) != BIOMETRICKITD_INFO_SIZE:
        raise BiometricCommandError(
            "biometrickitd information must be exactly 23 bytes")
    if output[22] not in (0, 1):
        raise BiometricCommandError("calibration-present flag is not boolean")
    return BiometrickitdInfoSummary(bool(output[22]))


def decode_bio_device_list_summary(output: bytes) -> BioDeviceListSummary:
    """Classify bounded device records without returning UUIDs or record bytes."""
    if not isinstance(output, bytes):
        raise BiometricCommandError("bio-device list must be bytes")
    if len(output) > BIO_DEVICE_LIST_CAPACITY:
        raise BiometricCommandError("bio-device list exceeds its capacity")
    if len(output) % BIO_DEVICE_RECORD.size:
        raise BiometricCommandError("bio-device list has a partial record")
    builtin = 0
    for offset in range(0, len(output), BIO_DEVICE_RECORD.size):
        accessory_type, _, group_type, _, _ = BIO_DEVICE_RECORD.unpack_from(
            output, offset)
        if (accessory_type == BUILTIN_ACCESSORY_TYPE
                and group_type == BUILTIN_DEVICE_GROUP_TYPE):
            builtin += 1
    return BioDeviceListSummary(len(output) // BIO_DEVICE_RECORD.size, builtin)


def decode_system_protected_config(output: bytes) -> SystemProtectedConfig:
    if not isinstance(output, bytes) or len(output) != SYSTEM_PROTECTED_CONFIG.size:
        raise BiometricCommandError("system protected config must be exactly 36 bytes")
    return SystemProtectedConfig(*SYSTEM_PROTECTED_CONFIG.unpack(output))


def protected_config_fields(*, user_id: int):
    return (COMMAND_GET_PROTECTED_CONFIG, COMMAND_VERSION, 0,
            struct.pack("<I", _u32(user_id, "user ID")), PROTECTED_CONFIG_SIZE)


def no_catacomb_fields(*, user_id: int):
    """Initialize one empty in-memory user catacomb using the current KDK ABI."""
    return (COMMAND_NO_CATACOMB, COMMAND_VERSION, 0,
            struct.pack("<I", _u32(user_id, "user ID")), 0)


def catacomb_uuid_fields(*, user_id: int):
    """Query only the opaque catacomb identifier's exact response shape."""
    return (COMMAND_GET_CATACOMB_UUID, 0, 0,
            struct.pack("<I", _u32(user_id, "user ID")), 16)


def consume_user_policy_credential(*, user_id: int, policy: UserProtectedPolicy,
                                   credential_set: bytearray) -> AuthorizedPolicyRequest:
    """Consume an ACM form into the exact current 60-byte policy-setter input."""
    try:
        user_id = _u32(user_id, "user ID")
        if not isinstance(policy, UserProtectedPolicy):
            raise BiometricCommandError("user policy has the wrong type")
        values = tuple(getattr(policy, field) for field in (
            "unlock_enabled", "identification_enabled", "login_enabled",
            "apple_pay_enabled"))
        if any(isinstance(value, bool) or value not in (0, 1) for value in values):
            raise BiometricCommandError("each user policy value must be integer zero or one")
        if not isinstance(credential_set, bytearray):
            raise BiometricCommandError("credential set must be a mutable bytearray")
        if len(credential_set) != ACM_EXTERNAL_FORM_SIZE:
            raise BiometricCommandError("credential set must be exactly 16 bytes")
        payload = bytearray(SET_PROTECTED_CONFIG_PAYLOAD.size)
        struct.pack_into("<IIIII", payload, 0, user_id, *values)
        struct.pack_into("<II", payload, 20, 0, ACM_EXTERNAL_FORM_SIZE)
        payload[28:44] = credential_set
        return AuthorizedPolicyRequest(payload)
    finally:
        if isinstance(credential_set, bytearray):
            credential_set[:] = bytes(len(credential_set))


def authorized_user_policy_fields(
        request: AuthorizedPolicyRequest) -> tuple[int, int, int, bytes, int]:
    if not isinstance(request, AuthorizedPolicyRequest) or request.closed:
        raise BiometricCommandError("authorized policy request is unavailable")
    payload = bytes(request.view())
    words = struct.unpack_from("<7I", payload)
    if (len(payload) != SET_PROTECTED_CONFIG_PAYLOAD.size or
            any(value not in (0, 1) for value in words[1:5]) or
            words[5:7] != (0, ACM_EXTERNAL_FORM_SIZE) or
            payload[44:] != bytes(16)):
        raise BiometricCommandError("authorized policy request shape changed")
    return COMMAND_SET_PROTECTED_CONFIG, COMMAND_VERSION, 0, payload, 0


def catacomb_state_fields():
    return (COMMAND_GET_CATACOMB_STATE, 0, 0, b"",
            CATACOMB_STATE_RECORD_SIZE * MAX_CATACOMB_STATE_RECORDS)


def catacomb_group_state_fields():
    return (COMMAND_GET_CATACOMB_GROUP_STATE, 0, 0, b"",
            CATACOMB_GROUP_STATE_RECORD_SIZE * MAX_CATACOMB_GROUP_STATE_RECORDS)


def xart_available_fields(*, version: int = 0):
    """Query Catalina's read-only one-byte xART availability result."""
    if isinstance(version, bool) or version not in (0, 1, 2):
        raise BiometricCommandError("xART query version must be 0, 1, or 2")
    return (COMMAND_IS_XART_AVAILABLE, version, 0, b"", 1)


def decode_xart_available(output: bytes) -> bool:
    if not isinstance(output, bytes) or len(output) != 1 or output[0] not in (0, 1):
        raise BiometricCommandError(
            "xART availability must be exactly one canonical boolean byte")
    return bool(output[0])


def builtin_catacomb_save_context(*, user_id: int) -> bytes:
    """Encode generation-3 UID plus built-in device-group save context."""
    return CATACOMB_SAVE_CONTEXT.pack(
        _u32(user_id, "user ID"), BUILTIN_DEVICE_GROUP, bytes(16))


def prepare_save_catacomb_fields(*, user_id: int):
    return (COMMAND_PREPARE_SAVE_CATACOMB, CURRENT_COMMAND_VERSION, 0,
            builtin_catacomb_save_context(user_id=user_id), 4)


def decode_prepared_catacomb_size(output: bytes) -> int:
    if not isinstance(output, bytes) or len(output) != 4:
        raise BiometricCommandError("prepared catacomb size must be exactly four bytes")
    size = struct.unpack("<I", output)[0]
    if not CATACOMB_HEADER_MINIMUM_SIZE <= size <= MAX_CATACOMB_BLOB_SIZE:
        raise BiometricCommandError("prepared catacomb size is outside safe bounds")
    return size


def complete_save_catacomb_fields(*, user_id: int, blob_size: int):
    if (isinstance(blob_size, bool) or not isinstance(blob_size, int)
            or not CATACOMB_HEADER_MINIMUM_SIZE <= blob_size <= MAX_CATACOMB_BLOB_SIZE):
        raise BiometricCommandError("catacomb blob size is outside safe bounds")
    return (COMMAND_COMPLETE_SAVE_CATACOMB, CURRENT_COMMAND_VERSION, 0,
            builtin_catacomb_save_context(user_id=user_id), blob_size)


def confirm_save_catacomb_fields(*, user_id: int):
    return (COMMAND_CONFIRM_SAVE_CATACOMB, CURRENT_COMMAND_VERSION, 0,
            builtin_catacomb_save_context(user_id=user_id), 0)


def load_catacomb_fields(*, user_id: int, blob: bytes):
    """Validate a bounded opaque CompleteSave blob for current LoadCatacomb."""
    if (not isinstance(blob, bytes)
            or not CATACOMB_HEADER_MINIMUM_SIZE <= len(blob) <= MAX_CATACOMB_BLOB_SIZE):
        raise BiometricCommandError("catacomb blob is outside safe bounds")
    if struct.unpack_from("<I", blob, 8)[0] != _u32(user_id, "user ID"):
        raise BiometricCommandError("catacomb blob belongs to a different user")
    return COMMAND_LOAD_CATACOMB, COMMAND_VERSION, 0, blob, 0


def current_catacomb_secure_data_fields(blob: bytes):
    """Encode current macOS's decoded opaque CatacombSecureData object."""
    if (not isinstance(blob, bytes) or not blob
            or len(blob) > MAX_CATACOMB_BLOB_SIZE):
        raise BiometricCommandError("current catacomb secure data is outside safe bounds")
    return COMMAND_LOAD_CATACOMB, COMMAND_VERSION, 0, blob, 0


def validate_opaque_record_array(output: bytes, *, record_size: int,
                                 maximum_records: int) -> int:
    """Validate only an opaque array's shape; never decode or expose records."""
    if (not isinstance(record_size, int) or isinstance(record_size, bool)
            or record_size <= 0 or not isinstance(maximum_records, int)
            or isinstance(maximum_records, bool) or maximum_records <= 0):
        raise BiometricCommandError("opaque record bounds are invalid")
    if not isinstance(output, bytes) or len(output) % record_size:
        raise BiometricCommandError("opaque state output has invalid alignment")
    count = len(output) // record_size
    if count > maximum_records:
        raise BiometricCommandError("opaque state output exceeds its record cap")
    return count


@dataclass(frozen=True)
class ServiceStatusEvent:
    status: int
    version: int
    ordinal: int
    data: bytes
    reference_timestamp: int
    continuous_time_delta: int


def trusted_identity_offsets(blob: bytes,
                             identities: tuple[BiometricIdentity, ...]
                             ) -> tuple[tuple[int, ...], ...]:
    """Locate trusted identity records without returning their contents.

    This is a layout-research helper, not an authentication decoder.  Its
    output is deliberately limited to byte offsets so live diagnostics never
    print identity UUIDs or opaque biometric result bytes.
    """
    if not isinstance(blob, bytes):
        raise BiometricCommandError("match result must be bytes")
    if not isinstance(identities, tuple) or any(
            not isinstance(identity, BiometricIdentity) for identity in identities):
        raise BiometricCommandError("trusted identities must be a tuple of identities")
    offsets = []
    for identity in identities:
        record = IDENTITY.pack(_u32(identity.user_id, "user ID"), identity.uuid)
        found = []
        start = 0
        while True:
            offset = blob.find(record, start)
            if offset < 0:
                break
            found.append(offset)
            start = offset + 1
        offsets.append(tuple(found))
    return tuple(offsets)


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


def consume_builtin_enrollment_credential(
        *, user_id: int, credential_set: bytearray) -> AuthorizedEnrollRequest:
    """Consume a verified 16-byte ACM external form into current command 3.

    The input is zeroed on every outcome. The returned mutable request must be
    closed after serialization/send; its representation never exposes bytes.
    Only the statically and live-proven built-in device group is expressible.
    """
    try:
        user_id = _u32(user_id, "user ID")
        if not isinstance(credential_set, bytearray):
            raise BiometricCommandError("credential set must be a mutable bytearray")
        if len(credential_set) != ACM_EXTERNAL_FORM_SIZE:
            raise BiometricCommandError("credential set must be exactly 16 bytes")
        payload = bytearray(CURRENT_ENROLL_PAYLOAD.size)
        struct.pack_into("<IIII", payload, 0, 0, user_id, 0,
                         ACM_EXTERNAL_FORM_SIZE)
        payload[16:32] = credential_set
        struct.pack_into("<I", payload, 48, BUILTIN_DEVICE_GROUP)
        return AuthorizedEnrollRequest(payload)
    finally:
        if isinstance(credential_set, bytearray):
            credential_set[:] = bytes(len(credential_set))


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


def authorized_enroll_fields(
        request: AuthorizedEnrollRequest) -> tuple[int, int, int, bytes, int]:
    """Serialize one owned ACM-authorized request for BridgeXPC method 3.

    The caller must close ``request`` immediately after the synchronous socket
    send.  Returning ``bytes`` is required by the binary-plist serializer; its
    short-lived serialization copies are owned and discarded by that layer.
    """
    if not isinstance(request, AuthorizedEnrollRequest) or request.closed:
        raise BiometricCommandError("authorized enrollment request is unavailable")
    payload = bytes(request.view())
    if len(payload) != CURRENT_ENROLL_PAYLOAD.size:
        raise BiometricCommandError("authorized enrollment request size changed")
    flags, user_id, using_token, token_length = struct.unpack_from("<IIII", payload)
    device_group = struct.unpack_from("<I", payload, 48)[0]
    if (flags != 0 or using_token != 0 or
            token_length != ACM_EXTERNAL_FORM_SIZE or
            device_group != BUILTIN_DEVICE_GROUP or payload[52:] != bytes(16)):
        raise BiometricCommandError("authorized enrollment request shape changed")
    return COMMAND_ENROLL, CURRENT_COMMAND_VERSION, 0, payload, 0


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


def decode_current_match_identity_v2(blob: bytes) -> CatalinaMatchIdentity:
    """Decode the identity prefix observed in bridgeOS 10.6 match v2.

    A live, freshly enumerated trusted identity was observed exactly once at
    offset zero of an exact 0xc9c-byte terminal record.  The remaining bytes
    are intentionally opaque until their current layout is independently
    proven; they cannot influence the identity comparison performed by the
    authentication state machine.
    """
    if not isinstance(blob, bytes) or len(blob) != CURRENT_MATCH_RESULT_V2_SIZE:
        raise BiometricCommandError(
            "current v2 match result must be exactly 0xc9c bytes")
    user_id, identity_uuid = IDENTITY.unpack_from(blob, 0)
    return CatalinaMatchIdentity(user_id, identity_uuid, ())


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
    if status != SERVICE_EVENT_MATCH_RESULT or version not in MATCH_SERVICE_EVENT_VERSIONS:
        raise BiometricCommandError("not a supported match-result event")
    if version == 1:
        return decode_catalina_match_identity(data)
    return decode_current_match_identity_v2(data)


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


def decode_bridge_service_event(message: list[object], *,
                                max_data: int = MAX_SERVICE_EVENT_DATA
                                ) -> ServiceStatusEvent:
    """Decode current bkremoted's method-9 service-status record."""
    if (isinstance(max_data, bool) or not isinstance(max_data, int)
            or not 0 <= max_data <= MAX_SERVICE_EVENT_DATA):
        raise BiometricCommandError("service event cap is invalid")
    if not isinstance(message, list) or len(message) != 5:
        raise BiometricCommandError("service event must contain five objects")
    method, channel, record, reference, delta = message
    if type(method) is not int or method != BRIDGE_SERVICE_EVENT_METHOD:
        raise BiometricCommandError("message is not a service event")
    if type(channel) is not int or channel != BRIDGE_SERVICE_EVENT_CHANNEL:
        raise BiometricCommandError("service event channel is unsupported")
    if not isinstance(record, bytes) or len(record) < SERVICE_RECORD_HEADER_SIZE:
        raise BiometricCommandError("service event record is shorter than its header")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF
           for value in (reference, delta)):
        raise BiometricCommandError("service event timestamps are invalid")
    status, version = struct.unpack_from("<II", record, 8)
    ordinal = struct.unpack_from("<Q", record, 24)[0]
    data_size = struct.unpack_from("<Q", record, 32)[0]
    if data_size > max_data:
        raise BiometricCommandError("service event data exceeds the cap")
    if len(record) != SERVICE_RECORD_HEADER_SIZE + data_size:
        raise BiometricCommandError("service event record size does not match its data size")
    return ServiceStatusEvent(status, version, ordinal,
                              record[SERVICE_RECORD_HEADER_SIZE:], reference, delta)
