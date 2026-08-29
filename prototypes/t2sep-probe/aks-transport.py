#!/usr/bin/env python3
"""Pure, fail-closed codec for AppleKeyStore's T2 SEP mailbox envelope."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import struct


AKS_ENDPOINT = 0x07
OOL_CAPACITY = 0x4000
ENVELOPE_SIZE = 12
REPLY_BIT = 0x80
GET_CAPABILITIES = 0x4D
SET_ENVIRONMENT = 0x2A
VERIFY_SECRET_V1 = 0x21
CREATE_KEYBAG_V1 = 0x01
COPY_KEYBAG = 0x02
UNLOAD_KEYBAG = 0x05
MAX_HEADER_VERSION = 2
SERIALIZED_HEADER_SIZE = 0x54
IPC_HEADER_SIZE = 0x50
IPC_DIGEST_SIZE = 16
CDHASH_SIZE = 20
ACM_CONTEXT_SIZE = 16
CAPABILITIES_SERIALIZED_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8 + 4
COMPACT_V1_HEADER_SIZE = 0x48
COMPACT_CAPABILITIES_REPLY_SIZE = 4 + COMPACT_V1_HEADER_SIZE + 4 + 8 + 4
STARTUP_ENVIRONMENT_BLOB_SIZE = 0x40C
STARTUP_ENVIRONMENT_REQUEST_SIZE = (
    SERIALIZED_HEADER_SIZE + 4 + 8 + 4 + STARTUP_ENVIRONMENT_BLOB_SIZE)
SET_ENVIRONMENT_REPLY_SIZE = SERIALIZED_HEADER_SIZE + 4
VERIFY_SECRET_REPLY_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8
CREATE_KEYBAG_REPLY_SIZE = SERIALIZED_HEADER_SIZE + 4 + 4
UNLOAD_KEYBAG_REQUEST_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8 + 4
UNLOAD_KEYBAG_REPLY_SIZE = SERIALIZED_HEADER_SIZE + 4
COPY_KEYBAG_REQUEST_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8 + 4


class AKSTransportError(ValueError):
    pass


def build_identity_header(version: int, *, continuous_usec: int,
                          process_unique_id: int, audit_session_id: int,
                          cdhash: bytes,
                          calendar_seconds: int | None = None) -> bytes:
    """Build the recovered header from explicit, source-authentic identity data.

    Callers must not substitute guessed Linux identity values for Apple's
    kernel-process fields. The explicit API makes that boundary auditable.
    """
    if version not in (1, 2):
        raise AKSTransportError("AKS IPC header version must be 1 or 2")
    continuous_usec = _uint(continuous_usec, 64, "continuous usec")
    process_unique_id = _uint(process_unique_id, 64, "process unique ID")
    audit_session_id = _uint(audit_session_id, 32, "audit session ID")
    if not isinstance(cdhash, bytes) or len(cdhash) != CDHASH_SIZE:
        raise AKSTransportError("code-directory hash must be exactly 20 bytes")
    if version == 1 and calendar_seconds is not None:
        raise AKSTransportError("version 1 header has no calendar timestamp")
    if version == 2:
        if calendar_seconds is None:
            raise AKSTransportError("version 2 header requires calendar seconds")
        calendar_seconds = _uint(calendar_seconds, 64, "calendar seconds")

    header = bytearray(IPC_HEADER_SIZE)
    struct.pack_into("<I", header, 0x10, version)
    struct.pack_into("<Q", header, 0x14, continuous_usec)
    struct.pack_into("<Q", header, 0x28, process_unique_id)
    struct.pack_into("<I", header, 0x30, audit_session_id)
    header[0x34:0x48] = cdhash
    if version == 2:
        struct.pack_into("<Q", header, 0x48, calendar_seconds)
    return bytes(header)


def _uint(value: int, bits: int, label: str) -> int:
    if (isinstance(value, bool) or not isinstance(value, int)
            or not 0 <= value < (1 << bits)):
        raise AKSTransportError(f"{label} must be an unsigned {bits}-bit integer")
    return value


def payload_digest(header: bytes, payload: bytes) -> bytes:
    """Reproduce AppleKeyStore's SHA-256 IPC digest, truncated to 16 bytes.

    This intentionally does not construct the process-identity-bearing header.
    It only models the integrity primitive recovered from ``_payload_hash``.
    """
    if not isinstance(header, bytes) or len(header) not in (
            COMPACT_V1_HEADER_SIZE, IPC_HEADER_SIZE):
        raise AKSTransportError("AKS IPC header must be exactly 0x48 or 0x50 bytes")
    if not isinstance(payload, bytes):
        raise AKSTransportError("AKS IPC payload must be bytes")
    version = struct.unpack_from("<I", header, 0x10)[0]
    if version == 1:
        protected_end = 0x48
    elif version == 2:
        if len(header) != IPC_HEADER_SIZE:
            raise AKSTransportError("version 2 AKS IPC header must be 0x50 bytes")
        protected_end = 0x50
    else:
        raise AKSTransportError("AKS IPC header version must be 1 or 2")
    return hashlib.sha256(header[0x10:protected_end] + payload).digest()[:IPC_DIGEST_SIZE]


def protect_header(header: bytes, payload: bytes) -> bytes:
    """Return a copy with the recovered truncated digest in bytes 0..15."""
    digest = payload_digest(header, payload)
    return digest + header[IPC_DIGEST_SIZE:]


def validate_protected_header(header: bytes, payload: bytes) -> None:
    """Fail closed if a protected header's digest does not match its payload."""
    expected = payload_digest(header, payload)
    if not hmac.compare_digest(header[:IPC_DIGEST_SIZE], expected):
        raise AKSTransportError("AKS IPC payload digest mismatch")


def encode_capabilities_request(identity_header: bytes) -> bytes:
    """Encode operation 0x4d's empty-input request body exactly."""
    _require_plain_identity_header(identity_header)
    payload = struct.pack("<IQI", 0, 1, 0)
    protected = protect_header(identity_header, payload)
    wire = struct.pack("<I", IPC_HEADER_SIZE) + protected + payload
    if len(wire) != CAPABILITIES_SERIALIZED_SIZE:
        raise AssertionError("capabilities request size invariant failed")
    return wire


def startup_environment_blob(no_effaceable_storage: int) -> bytes:
    """Build AppleKeyStore's normal-boot, non-secret ``set_env`` blob."""
    no_effaceable_storage = _uint(
        no_effaceable_storage, 32, "no-effaceable-storage property")
    blob = bytearray(STARTUP_ENVIRONMENT_BLOB_SIZE)
    struct.pack_into("<IIIQ", blob, 0, 1, no_effaceable_storage, 4, 0)
    return bytes(blob)


def encode_startup_environment_request(identity_header: bytes,
                                       no_effaceable_storage: int) -> bytes:
    """Encode operation 0x2a after header negotiation for normal boot."""
    _require_plain_identity_header(identity_header)
    blob = startup_environment_blob(no_effaceable_storage)
    payload = struct.pack("<IQI", 0, 1, len(blob)) + blob
    protected = protect_header(identity_header, payload)
    wire = struct.pack("<I", IPC_HEADER_SIZE) + protected + payload
    if len(wire) != STARTUP_ENVIRONMENT_REQUEST_SIZE:
        raise AssertionError("startup environment request size invariant failed")
    return wire


@dataclass(frozen=True)
class CapabilitiesReply:
    status: int
    remote_version: int


@dataclass(frozen=True)
class VerifySecretReply:
    device_state: int


@dataclass(frozen=True)
class KeybagStoreType:
    """Opaque Apple keybag store type; no guessed default is permitted."""
    value: int


# Exact values recovered from bridgeOS 23P6068's keybagd and MobileKeyBag.
# These are named constants rather than codec defaults: callers must still
# deliberately select the semantics appropriate to their operation.
DEVICE_KEYBAG_STORE = KeybagStoreType(0)
BACKUP_KEYBAG_STORE = KeybagStoreType(1)
OTA_BACKUP_KEYBAG_STORE = KeybagStoreType(3)


@dataclass(frozen=True)
class CreateKeybagReply:
    selector: "SessionKeybagSelector"


@dataclass(frozen=True)
class SessionKeybagHandle:
    """Opaque AKS client handle derived from one boot/session namespace."""
    value: int


@dataclass(frozen=True)
class SessionKeybagSelector:
    """Opaque selector derived from an authenticated login-session identity."""
    value: int


@dataclass(frozen=True)
class VerifySecretMetadata:
    keybag_handle: SessionKeybagHandle
    selector: SessionKeybagSelector


@dataclass(frozen=True)
class VerifySecretLayout:
    total_size: int
    variant_offset: int
    keybag_offset: int
    selector_offset: int
    password_length_offset: int
    password_data_offset: int
    password_padded_end: int
    context_length_offset: int
    context_data_offset: int
    context_padded_end: int
    device_state_offset: int


@dataclass(frozen=True)
class CreateKeybagLayout:
    total_size: int
    variant_offset: int
    namespace_offset: int
    store_type_offset: int
    requested_selector_offset: int
    primary_length_offset: int
    primary_data_offset: int
    primary_padded_end: int
    secondary_length_offset: int
    secondary_data_offset: int
    secondary_padded_end: int


class CreateKeybagRequest:
    """Single-owner create-keybag request with explicit secret erasure."""

    __slots__ = ("_wire", "_closed")

    def __init__(self, wire: bytearray) -> None:
        if not isinstance(wire, bytearray):
            raise AKSTransportError("create-keybag request storage must be mutable")
        self._wire = wire
        self._closed = False

    def view(self) -> memoryview:
        if self._closed:
            raise AKSTransportError("create-keybag request is already scrubbed")
        return memoryview(self._wire)

    def close(self) -> None:
        if not self._closed:
            self._wire[:] = b"\0" * len(self._wire)
            self._closed = True

    def __enter__(self) -> "CreateKeybagRequest":
        if self._closed:
            raise AKSTransportError("create-keybag request is already scrubbed")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        return (f"CreateKeybagRequest(length={len(self._wire)}, "
                f"closed={self._closed})")


class VerifySecretRequest:
    """Single-owner mutable request whose storage can be explicitly scrubbed.

    The object deliberately offers a memoryview rather than an immutable
    ``bytes`` conversion.  A transport must finish DMA/copy use before calling
    ``close``; context-manager exit scrubs the complete serialized request.
    """

    __slots__ = ("_wire", "_closed")

    def __init__(self, wire: bytearray) -> None:
        if not isinstance(wire, bytearray):
            raise AKSTransportError("secret request storage must be mutable")
        self._wire = wire
        self._closed = False

    def view(self) -> memoryview:
        if self._closed:
            raise AKSTransportError("verify-secret request is already scrubbed")
        return memoryview(self._wire)

    def close(self) -> None:
        if not self._closed:
            self._wire[:] = b"\0" * len(self._wire)
            self._closed = True

    def __enter__(self) -> "VerifySecretRequest":
        if self._closed:
            raise AKSTransportError("verify-secret request is already scrubbed")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort fallback only; callers must still use close/context exit.
        self.close()

    def __repr__(self) -> str:
        return (f"VerifySecretRequest(length={len(self._wire)}, "
                f"closed={self._closed})")


def decode_capabilities_reply(wire: bytes) -> CapabilitiesReply:
    """Validate and decode the fixed empty-blob operation-0x4d response."""
    if not isinstance(wire, bytes) or len(wire) not in (
            COMPACT_CAPABILITIES_REPLY_SIZE, CAPABILITIES_SERIALIZED_SIZE):
        raise AKSTransportError("AKS capabilities reply must be exactly 92 or 100 bytes")
    header_size = struct.unpack_from("<I", wire, 0)[0]
    if header_size not in (COMPACT_V1_HEADER_SIZE, IPC_HEADER_SIZE):
        raise AKSTransportError("AKS capabilities reply has the wrong header length")
    payload_offset = 4 + header_size
    if len(wire) - payload_offset != 16:
        raise AKSTransportError("AKS capabilities header/length pairing is invalid")
    header = wire[4:payload_offset]
    payload = wire[payload_offset:]
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS capabilities reply has unsupported header flags")
    validate_protected_header(header, payload)
    status, remote_version, blob_length = struct.unpack("<iQI", payload)
    if blob_length != 0:
        raise AKSTransportError("AKS capabilities reply blob must be empty")
    return CapabilitiesReply(status, remote_version)


def decode_set_environment_reply(wire: bytes,
                                 expected_header_version: int) -> None:
    """Accept only operation 0x2a's exact protected zero-status response."""
    if expected_header_version not in (1, 2):
        raise AKSTransportError("expected AKS IPC header version must be 1 or 2")
    if not isinstance(wire, bytes) or len(wire) != SET_ENVIRONMENT_REPLY_SIZE:
        raise AKSTransportError("AKS set-environment reply must be exactly 88 bytes")
    if struct.unpack_from("<I", wire, 0)[0] != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS set-environment reply has the wrong header length")
    header = wire[4:SERIALIZED_HEADER_SIZE]
    payload = wire[SERIALIZED_HEADER_SIZE:]
    if struct.unpack_from("<I", header, 0x10)[0] != expected_header_version:
        raise AKSTransportError("AKS set-environment reply changed header version")
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS set-environment reply has unsupported header flags")
    validate_protected_header(header, payload)
    if struct.unpack("<i", payload)[0] != 0:
        raise AKSTransportError("AKS set-environment reply reports failure")


def decode_verify_secret_reply(wire: bytes, expected_header_version: int) -> VerifySecretReply:
    """Validate operation 0x21 variant-1's successful response body."""
    if expected_header_version not in (1, 2):
        raise AKSTransportError("expected AKS IPC header version must be 1 or 2")
    if not isinstance(wire, bytes) or len(wire) != VERIFY_SECRET_REPLY_SIZE:
        raise AKSTransportError("AKS verify-secret reply must be exactly 96 bytes")
    if struct.unpack_from("<I", wire, 0)[0] != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS verify-secret reply has the wrong header length")
    header = wire[4:SERIALIZED_HEADER_SIZE]
    payload = wire[SERIALIZED_HEADER_SIZE:]
    version = struct.unpack_from("<I", header, 0x10)[0]
    if version != expected_header_version:
        raise AKSTransportError("AKS verify-secret reply changed header version")
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS verify-secret reply has unsupported header flags")
    validate_protected_header(header, payload)
    variant, device_state = struct.unpack("<IQ", payload)
    if variant != 1:
        raise AKSTransportError("AKS verify-secret reply is not variant 1")
    return VerifySecretReply(device_state)


def decode_create_keybag_reply(wire: bytes,
                               expected_header_version: int) -> CreateKeybagReply:
    """Validate operation 0x01 variant-1's exact successful response."""
    if expected_header_version not in (1, 2):
        raise AKSTransportError("expected AKS IPC header version must be 1 or 2")
    if not isinstance(wire, bytes) or len(wire) != CREATE_KEYBAG_REPLY_SIZE:
        raise AKSTransportError("AKS create-keybag reply must be exactly 92 bytes")
    if struct.unpack_from("<I", wire, 0)[0] != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS create-keybag reply has the wrong header length")
    header = wire[4:SERIALIZED_HEADER_SIZE]
    payload = wire[SERIALIZED_HEADER_SIZE:]
    if struct.unpack_from("<I", header, 0x10)[0] != expected_header_version:
        raise AKSTransportError("AKS create-keybag reply changed header version")
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS create-keybag reply has unsupported header flags")
    validate_protected_header(header, payload)
    variant, selector = struct.unpack("<Ii", payload)
    if variant != 1:
        raise AKSTransportError("AKS create-keybag reply is not variant 1")
    if selector < 0:
        raise AKSTransportError("AKS create-keybag reply returned an invalid selector")
    return CreateKeybagReply(SessionKeybagSelector(selector))


def encode_unload_keybag_request(identity_header: bytes, *,
                                 namespace: SessionKeybagHandle,
                                 selector: SessionKeybagSelector) -> bytes:
    """Encode operation 0x05 variant 0 for one exact namespace/selector."""
    _require_plain_identity_header(identity_header)
    metadata = verify_secret_metadata(namespace, selector)
    payload = struct.pack("<IQi", 0, metadata.keybag_handle.value,
                          metadata.selector.value)
    protected = protect_header(identity_header, payload)
    wire = struct.pack("<I", IPC_HEADER_SIZE) + protected + payload
    if len(wire) != UNLOAD_KEYBAG_REQUEST_SIZE:
        raise AssertionError("unload-keybag request size invariant failed")
    return wire


def encode_copy_keybag_request(identity_header: bytes, *,
                               namespace: SessionKeybagHandle,
                               selector: SessionKeybagSelector) -> bytes:
    """Encode operation 0x02 variant 0 for a bounded presence check."""
    _require_plain_identity_header(identity_header)
    metadata = verify_secret_metadata(namespace, selector)
    payload = struct.pack("<IQi", 0, metadata.keybag_handle.value,
                          metadata.selector.value)
    protected = protect_header(identity_header, payload)
    wire = struct.pack("<I", IPC_HEADER_SIZE) + protected + payload
    if len(wire) != COPY_KEYBAG_REQUEST_SIZE:
        raise AssertionError("copy-keybag request size invariant failed")
    return wire


def decode_copy_keybag_reply(wire: bytes, expected_header_version: int,
                             *, max_blob_size: int = 64 * 1024) -> bytes:
    """Decode operation 0x02 variant 0's bounded length-prefixed bag copy."""
    if expected_header_version not in (1, 2):
        raise AKSTransportError("expected AKS IPC header version must be 1 or 2")
    max_blob_size = _uint(max_blob_size, 32, "maximum keybag blob size")
    if not isinstance(wire, bytes) or len(wire) < SERIALIZED_HEADER_SIZE + 8:
        raise AKSTransportError("AKS copy-keybag reply is truncated")
    if struct.unpack_from("<I", wire, 0)[0] != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS copy-keybag reply has the wrong header length")
    header = wire[4:SERIALIZED_HEADER_SIZE]
    payload = wire[SERIALIZED_HEADER_SIZE:]
    if struct.unpack_from("<I", header, 0x10)[0] != expected_header_version:
        raise AKSTransportError("AKS copy-keybag reply changed header version")
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS copy-keybag reply has unsupported header flags")
    validate_protected_header(header, payload)
    variant, blob_length = struct.unpack_from("<II", payload)
    if variant != 0:
        raise AKSTransportError("AKS copy-keybag reply is not variant 0")
    if blob_length > max_blob_size:
        raise AKSTransportError("AKS copy-keybag reply exceeds the configured bound")
    expected_size = 8 + _align4(blob_length)
    if len(payload) != expected_size:
        raise AKSTransportError("AKS copy-keybag reply has inconsistent blob length")
    if any(payload[8 + blob_length:]):
        raise AKSTransportError("AKS copy-keybag reply has nonzero padding")
    return payload[8:8 + blob_length]


def decode_unload_keybag_reply(wire: bytes,
                               expected_header_version: int) -> None:
    """Validate operation 0x05's exact protected variant-0 success body."""
    if expected_header_version not in (1, 2):
        raise AKSTransportError("expected AKS IPC header version must be 1 or 2")
    if not isinstance(wire, bytes) or len(wire) != UNLOAD_KEYBAG_REPLY_SIZE:
        raise AKSTransportError("AKS unload-keybag reply must be exactly 88 bytes")
    if struct.unpack_from("<I", wire, 0)[0] != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS unload-keybag reply has the wrong header length")
    header = wire[4:SERIALIZED_HEADER_SIZE]
    payload = wire[SERIALIZED_HEADER_SIZE:]
    if struct.unpack_from("<I", header, 0x10)[0] != expected_header_version:
        raise AKSTransportError("AKS unload-keybag reply changed header version")
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS unload-keybag reply has unsupported header flags")
    validate_protected_header(header, payload)
    if struct.unpack("<I", payload)[0] != 0:
        raise AKSTransportError("AKS unload-keybag reply is not variant 0")


def _require_plain_identity_header(header: bytes) -> None:
    if not isinstance(header, bytes) or len(header) != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS IPC header must be exactly 0x50 bytes")
    if header[:IPC_DIGEST_SIZE] != bytes(IPC_DIGEST_SIZE):
        raise AKSTransportError("identity header already contains a digest")
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("identity header flags must be zero")


@dataclass(frozen=True)
class AKSEnvelope:
    selector: int
    tag: int
    payload_length: int
    reply: bool


def _u8(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xff:
        raise AKSTransportError(f"{label} must be an unsigned byte")
    return value


def encode_request(selector: int, tag: int, payload_length: int) -> bytes:
    selector = _u8(selector, "selector")
    tag = _u8(tag, "tag")
    if selector & REPLY_BIT:
        raise AKSTransportError("request selector occupies the reply bit")
    if (isinstance(payload_length, bool) or not isinstance(payload_length, int)
            or not 0 <= payload_length <= OOL_CAPACITY):
        raise AKSTransportError("payload length exceeds the AKS OOL buffer")
    return struct.pack("<BBBBHHI", AKS_ENDPOINT, selector, tag, 0,
                       0, payload_length, 0)


def decode_envelope(data: bytes) -> AKSEnvelope:
    if not isinstance(data, bytes) or len(data) != ENVELOPE_SIZE:
        raise AKSTransportError("AKS envelope must be exactly 12 bytes")
    endpoint, wire_selector, tag, reserved_byte, reserved_word, length, tail = (
        struct.unpack("<BBBBHHI", data))
    if endpoint != AKS_ENDPOINT:
        raise AKSTransportError("AKS envelope has the wrong endpoint")
    if reserved_byte != 0 or reserved_word != 0 or tail != 0:
        raise AKSTransportError("AKS envelope has nonzero reserved data")
    if length > OOL_CAPACITY:
        raise AKSTransportError("AKS envelope exceeds the OOL buffer")
    return AKSEnvelope(wire_selector & ~REPLY_BIT, tag, length,
                       bool(wire_selector & REPLY_BIT))


def validate_reply(request: AKSEnvelope, reply_data: bytes) -> AKSEnvelope:
    if not isinstance(request, AKSEnvelope) or request.reply:
        raise AKSTransportError("reply validation requires a request envelope")
    reply = decode_envelope(reply_data)
    if not reply.reply:
        raise AKSTransportError("AKS response does not set the reply bit")
    if (reply.selector, reply.tag) != (request.selector, request.tag):
        raise AKSTransportError("AKS response does not correlate to the request")
    return reply


def negotiated_header_version(capabilities_status: int,
                              remote_version: int | None) -> int:
    """Mirror AppleKeyStore's fail-compatible initial header negotiation."""
    if isinstance(capabilities_status, bool) or not isinstance(capabilities_status, int):
        raise AKSTransportError("capabilities status must be an integer")
    if capabilities_status != 0:
        if remote_version is not None:
            raise AKSTransportError("failed capabilities query cannot supply a version")
        return 1
    if (isinstance(remote_version, bool) or not isinstance(remote_version, int)
            or not 0 <= remote_version <= 0xffffffffffffffff):
        raise AKSTransportError("remote header version must be an unsigned qword")
    return min(remote_version, MAX_HEADER_VERSION)


def verify_secret_serialized_size(password_length: int,
                                  context_length: int = ACM_CONTEXT_SIZE) -> int:
    """Plan the protected IPC size without accepting either secret blob."""
    return verify_secret_layout(password_length, context_length).total_size


def create_keybag_layout(primary_length: int,
                         secondary_length: int = 0) -> CreateKeybagLayout:
    """Return operation 0x01 variant-1 boundaries without accepting secrets."""
    primary_length = _length(primary_length, "primary keybag secret")
    secondary_length = _length(secondary_length, "secondary keybag secret")
    if not 1 <= primary_length <= 256:
        raise AKSTransportError("primary keybag secret must contain 1..256 bytes")
    if secondary_length > 256:
        raise AKSTransportError("secondary keybag secret exceeds 256 bytes")
    variant_offset = SERIALIZED_HEADER_SIZE
    namespace_offset = variant_offset + 4
    store_type_offset = namespace_offset + 8
    requested_selector_offset = store_type_offset + 4
    primary_length_offset = requested_selector_offset + 4
    primary_data_offset = primary_length_offset + 4
    primary_padded_end = primary_data_offset + _align4(primary_length)
    secondary_length_offset = primary_padded_end
    secondary_data_offset = secondary_length_offset + 4
    secondary_padded_end = secondary_data_offset + _align4(secondary_length)
    if secondary_padded_end > OOL_CAPACITY:
        raise AKSTransportError("serialized create-keybag request exceeds OOL")
    return CreateKeybagLayout(
        secondary_padded_end, variant_offset, namespace_offset,
        store_type_offset, requested_selector_offset, primary_length_offset,
        primary_data_offset, primary_padded_end, secondary_length_offset,
        secondary_data_offset, secondary_padded_end)


def consume_create_keybag_inputs(identity_header: bytes, primary: bytearray,
                                 secondary: bytearray, *,
                                 namespace: SessionKeybagHandle,
                                 store_type: KeybagStoreType,
                                 requested_selector: SessionKeybagSelector
                                 ) -> CreateKeybagRequest:
    """Serialize variant 1 while consuming and wiping both secret inputs."""
    _require_plain_identity_header(identity_header)
    metadata = verify_secret_metadata(namespace, requested_selector)
    if not isinstance(store_type, KeybagStoreType):
        raise AKSTransportError("keybag store type must be an opaque typed value")
    store_type_value = _uint(store_type.value, 32, "keybag store type")
    if not isinstance(primary, bytearray) or not isinstance(secondary, bytearray):
        raise AKSTransportError("keybag secrets must be caller-owned bytearrays")
    layout = create_keybag_layout(len(primary), len(secondary))
    wire = bytearray(layout.total_size)
    try:
        struct.pack_into("<I", wire, 0, IPC_HEADER_SIZE)
        wire[4:SERIALIZED_HEADER_SIZE] = identity_header
        struct.pack_into("<IQIiI", wire, layout.variant_offset, 1,
                         metadata.keybag_handle.value, store_type_value,
                         metadata.selector.value, len(primary))
        wire[layout.primary_data_offset:
             layout.primary_data_offset + len(primary)] = primary
        struct.pack_into("<I", wire, layout.secondary_length_offset,
                         len(secondary))
        wire[layout.secondary_data_offset:
             layout.secondary_data_offset + len(secondary)] = secondary
        header = memoryview(wire)[4:SERIALIZED_HEADER_SIZE]
        payload = memoryview(wire)[SERIALIZED_HEADER_SIZE:]
        version = struct.unpack_from("<I", header, 0x10)[0]
        if version not in (1, 2):
            raise AKSTransportError("AKS IPC header version must be 1 or 2")
        protected_end = 0x48 if version == 1 else 0x50
        digest = hashlib.sha256()
        digest.update(header[0x10:protected_end])
        digest.update(payload)
        wire[4:4 + IPC_DIGEST_SIZE] = digest.digest()[:IPC_DIGEST_SIZE]
    except Exception:
        wire[:] = b"\0" * len(wire)
        primary[:] = b"\0" * len(primary)
        secondary[:] = b"\0" * len(secondary)
        raise
    primary[:] = b"\0" * len(primary)
    secondary[:] = b"\0" * len(secondary)
    return CreateKeybagRequest(wire)


def verify_secret_layout(password_length: int,
                         context_length: int = ACM_CONTEXT_SIZE) -> VerifySecretLayout:
    """Return exact field boundaries without accepting secret material."""
    password_length = _length(password_length, "password")
    context_length = _length(context_length, "ACM context")
    if context_length != ACM_CONTEXT_SIZE:
        raise AKSTransportError("ACM external form must be exactly 16 bytes")
    # Header, variant word, keybag qword, selector word, two length-prefixed
    # four-byte-aligned blobs, and the variant-1 device-state qword. The
    # in-memory option at offset 0x88 is not serialized by this variant.
    variant_offset = SERIALIZED_HEADER_SIZE
    keybag_offset = variant_offset + 4
    selector_offset = keybag_offset + 8
    password_length_offset = selector_offset + 4
    password_data_offset = password_length_offset + 4
    password_padded_end = password_data_offset + _align4(password_length)
    context_length_offset = password_padded_end
    context_data_offset = context_length_offset + 4
    context_padded_end = context_data_offset + _align4(context_length)
    device_state_offset = context_padded_end
    total = device_state_offset + 8
    if total > OOL_CAPACITY:
        raise AKSTransportError("serialized verify-secret request exceeds OOL")
    return VerifySecretLayout(
        total, variant_offset, keybag_offset, selector_offset,
        password_length_offset, password_data_offset, password_padded_end,
        context_length_offset, context_data_offset, context_padded_end,
        device_state_offset)


def consume_verify_secret_inputs(identity_header: bytes, password: bytearray,
                                 context: bytearray, *,
                                 keybag_handle: SessionKeybagHandle,
                                 selector: SessionKeybagSelector,
                                 device_state_active: bool) -> VerifySecretRequest:
    """Serialize variant 1 while transferring and scrubbing secret inputs.

    This mirrors the recovered request fields while imposing a stricter Linux
    ownership rule than Apple's OSData caller: both mutable input arrays are
    zeroed once copied, and the returned single-owner buffer must itself be
    closed after transport completion.  No immutable object contains either
    secret as a result of this function.
    """
    _require_plain_identity_header(identity_header)
    metadata = verify_secret_metadata(keybag_handle, selector)
    if not isinstance(password, bytearray):
        raise AKSTransportError("password must be a caller-owned bytearray")
    if not isinstance(context, bytearray):
        raise AKSTransportError("ACM context must be a caller-owned bytearray")
    if not isinstance(device_state_active, bool):
        raise AKSTransportError("device-state input must be a boolean")
    layout = verify_secret_layout(len(password), len(context))
    wire = bytearray(layout.total_size)
    try:
        struct.pack_into("<I", wire, 0, IPC_HEADER_SIZE)
        wire[4:SERIALIZED_HEADER_SIZE] = identity_header
        struct.pack_into("<IQiI", wire, layout.variant_offset, 1,
                         metadata.keybag_handle.value, metadata.selector.value,
                         len(password))
        wire[layout.password_data_offset:
             layout.password_data_offset + len(password)] = password
        struct.pack_into("<I", wire, layout.context_length_offset, len(context))
        wire[layout.context_data_offset:
             layout.context_data_offset + len(context)] = context
        struct.pack_into("<Q", wire, layout.device_state_offset,
                         0x80 if device_state_active else 0)

        header = memoryview(wire)[4:SERIALIZED_HEADER_SIZE]
        payload = memoryview(wire)[SERIALIZED_HEADER_SIZE:]
        version = struct.unpack_from("<I", header, 0x10)[0]
        if version not in (1, 2):
            raise AKSTransportError("AKS IPC header version must be 1 or 2")
        protected_end = 0x48 if version == 1 else 0x50
        digest = hashlib.sha256()
        digest.update(header[0x10:protected_end])
        digest.update(payload)
        wire[4:4 + IPC_DIGEST_SIZE] = digest.digest()[:IPC_DIGEST_SIZE]
    except Exception:
        wire[:] = b"\0" * len(wire)
        password[:] = b"\0" * len(password)
        context[:] = b"\0" * len(context)
        raise
    password[:] = b"\0" * len(password)
    context[:] = b"\0" * len(context)
    return VerifySecretRequest(wire)


def _length(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AKSTransportError(f"{label} length must be a nonnegative integer")
    return value


def derive_session_keybag_handle(namespace_nonce: int,
                                 client_unique_id: int) -> SessionKeybagHandle:
    """Mirror AppleKeyStore's per-client handle construction.

    The KDK implementation fills one service-instance qword with ``read_random``
    and adds ``proc_uniqueid(current_proc())`` for each user client.  The x86-64
    addition is modulo 2**64.  Linux must source the nonce from its kernel CSPRNG
    once per driver lifetime and allocate a non-reused client-unique ID; a PID,
    UID, audit ID, constant, or value recovered from macOS is not equivalent.
    """
    namespace_nonce = _uint(namespace_nonce, 64, "keybag namespace nonce")
    client_unique_id = _uint(client_unique_id, 64, "client unique ID")
    return SessionKeybagHandle((namespace_nonce + client_unique_id) & ((1 << 64) - 1))


def derive_session_keybag_selector(session_uid: int) -> SessionKeybagSelector:
    """Mirror ``evaluate_session_keybag_handle`` for a login session.

    Apple maps session UID zero to the special selector ``-4`` and UIDs from
    10 through INT32_MAX-1 to their negation.  Values outside those domains
    fail.  The caller must supply an authenticated session identity; this
    function intentionally never consults the ambient process UID.
    """
    session_uid = _uint(session_uid, 32, "session UID")
    if session_uid == 0:
        return SessionKeybagSelector(-4)
    if 10 <= session_uid <= (1 << 31) - 2:
        return SessionKeybagSelector(-session_uid)
    raise AKSTransportError("session UID has no AppleKeyStore session selector")


def verify_secret_metadata(keybag_handle: SessionKeybagHandle,
                           selector: SessionKeybagSelector) -> VerifySecretMetadata:
    """Validate non-secret, session-derived fields without inventing defaults."""
    if not isinstance(keybag_handle, SessionKeybagHandle):
        raise AKSTransportError(
            "keybag handle must come from the session-handle derivation")
    _uint(keybag_handle.value, 64, "keybag handle")
    if not isinstance(selector, SessionKeybagSelector):
        raise AKSTransportError(
            "verify-secret selector must come from the session selector policy")
    if (isinstance(selector.value, bool) or not isinstance(selector.value, int)
            or not -(1 << 31) <= selector.value < (1 << 31)):
        raise AKSTransportError("verify-secret selector must be a signed 32-bit integer")
    return VerifySecretMetadata(keybag_handle, selector)


def _align4(value: int) -> int:
    return (value + 3) & ~3


class AuthorizationPlan:
    """Order capabilities, environment, and verify-secret without secret bytes."""

    def __init__(self) -> None:
        self.capabilities_request: AKSEnvelope | None = None
        self.header_version: int | None = None
        self.environment_request: AKSEnvelope | None = None
        self.environment_initialized = False
        self.verify_metadata: VerifySecretMetadata | None = None
        self.verify_request: AKSEnvelope | None = None
        self.verify_payload_built = False
        self.verify_reply: VerifySecretReply | None = None

    def request_capabilities(self, tag: int) -> bytes:
        if self.capabilities_request is not None or self.header_version is not None:
            raise AKSTransportError("capabilities request is out of order")
        wire = encode_request(GET_CAPABILITIES, tag, CAPABILITIES_SERIALIZED_SIZE)
        self.capabilities_request = decode_envelope(wire)
        return wire

    def accept_capabilities_transport(self, reply_data: bytes,
                                      payload: bytes) -> int:
        if self.capabilities_request is None or self.header_version is not None:
            raise AKSTransportError("capabilities reply is out of order")
        envelope = validate_reply(self.capabilities_request, reply_data)
        if envelope.payload_length != len(payload):
            raise AKSTransportError("capabilities envelope length does not match payload")
        reply = decode_capabilities_reply(payload)
        remote = reply.remote_version if reply.status == 0 else None
        self.header_version = negotiated_header_version(reply.status, remote)
        return self.header_version

    def request_startup_environment(self, tag: int) -> bytes:
        if (self.header_version not in (1, 2) or
                self.environment_request is not None or
                self.environment_initialized):
            raise AKSTransportError("set-environment request is out of order")
        wire = encode_request(SET_ENVIRONMENT, tag,
                              STARTUP_ENVIRONMENT_REQUEST_SIZE)
        self.environment_request = decode_envelope(wire)
        return wire

    def accept_startup_environment(self, reply_data: bytes,
                                   payload: bytes) -> None:
        if (self.environment_request is None or
                self.header_version not in (1, 2) or
                self.environment_initialized):
            raise AKSTransportError("set-environment reply is out of order")
        envelope = validate_reply(self.environment_request, reply_data)
        if envelope.payload_length != len(payload):
            raise AKSTransportError(
                "set-environment envelope length does not match payload")
        decode_set_environment_reply(payload, self.header_version)
        self.environment_initialized = True

    def plan_verify_secret(self, tag: int, password_length: int, *,
                           keybag_handle: SessionKeybagHandle,
                           selector: SessionKeybagSelector) -> bytes:
        if (not self.environment_initialized or self.header_version is None or
                self.verify_request is not None):
            raise AKSTransportError("verify-secret request is out of order")
        metadata = verify_secret_metadata(keybag_handle, selector)
        size = verify_secret_serialized_size(password_length)
        wire = encode_request(VERIFY_SECRET_V1, tag, size)
        self.verify_metadata = metadata
        self.verify_request = decode_envelope(wire)
        return wire

    def consume_verify_secret_payload(self, identity_header: bytes,
                                      password: bytearray,
                                      context: bytearray, *,
                                      device_state_active: bool) -> VerifySecretRequest:
        if (self.verify_request is None or self.verify_metadata is None or
                self.header_version not in (1, 2) or self.verify_payload_built):
            raise AKSTransportError("verify-secret payload is out of order")
        if (not isinstance(identity_header, bytes) or
                len(identity_header) != IPC_HEADER_SIZE or
                struct.unpack_from("<I", identity_header, 0x10)[0] !=
                self.header_version):
            raise AKSTransportError(
                "verify-secret identity header changed negotiated version")
        request = consume_verify_secret_inputs(
            identity_header, password, context,
            keybag_handle=self.verify_metadata.keybag_handle,
            selector=self.verify_metadata.selector,
            device_state_active=device_state_active)
        if len(request.view()) != self.verify_request.payload_length:
            request.close()
            raise AKSTransportError(
                "verify-secret payload changed the planned request length")
        self.verify_payload_built = True
        return request

    def accept_verify_secret_success(self, reply_data: bytes,
                                     payload: bytes) -> VerifySecretReply:
        if (self.verify_request is None or self.header_version not in (1, 2)
                or not self.verify_payload_built or
                self.verify_reply is not None):
            raise AKSTransportError("verify-secret reply is out of order")
        envelope = validate_reply(self.verify_request, reply_data)
        if envelope.payload_length != len(payload):
            raise AKSTransportError("verify-secret envelope length does not match payload")
        self.verify_reply = decode_verify_secret_reply(payload, self.header_version)
        return self.verify_reply
