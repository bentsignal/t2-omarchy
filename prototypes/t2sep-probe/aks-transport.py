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
VERIFY_SECRET_V1 = 0x21
MAX_HEADER_VERSION = 2
SERIALIZED_HEADER_SIZE = 0x54
IPC_HEADER_SIZE = 0x50
IPC_DIGEST_SIZE = 16
CDHASH_SIZE = 20
ACM_CONTEXT_SIZE = 16
CAPABILITIES_SERIALIZED_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8 + 4
VERIFY_SECRET_REPLY_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8


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
    if not isinstance(header, bytes) or len(header) != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS IPC header must be exactly 0x50 bytes")
    if not isinstance(payload, bytes):
        raise AKSTransportError("AKS IPC payload must be bytes")
    version = struct.unpack_from("<I", header, 0x10)[0]
    if version == 1:
        protected_end = 0x48
    elif version == 2:
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


@dataclass(frozen=True)
class CapabilitiesReply:
    status: int
    remote_version: int


@dataclass(frozen=True)
class VerifySecretReply:
    device_state: int


@dataclass(frozen=True)
class VerifySecretMetadata:
    keybag_handle: int
    selector: int


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


def decode_capabilities_reply(wire: bytes) -> CapabilitiesReply:
    """Validate and decode the fixed empty-blob operation-0x4d response."""
    if not isinstance(wire, bytes) or len(wire) != CAPABILITIES_SERIALIZED_SIZE:
        raise AKSTransportError("AKS capabilities reply must be exactly 100 bytes")
    if struct.unpack_from("<I", wire, 0)[0] != IPC_HEADER_SIZE:
        raise AKSTransportError("AKS capabilities reply has the wrong header length")
    header = wire[4:SERIALIZED_HEADER_SIZE]
    payload = wire[SERIALIZED_HEADER_SIZE:]
    if struct.unpack_from("<I", header, 0x1c)[0] != 0:
        raise AKSTransportError("AKS capabilities reply has unsupported header flags")
    validate_protected_header(header, payload)
    status, remote_version, blob_length = struct.unpack("<iQI", payload)
    if blob_length != 0:
        raise AKSTransportError("AKS capabilities reply blob must be empty")
    return CapabilitiesReply(status, remote_version)


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


def _length(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AKSTransportError(f"{label} length must be a nonnegative integer")
    return value


def verify_secret_metadata(keybag_handle: int,
                           selector: int) -> VerifySecretMetadata:
    """Validate non-secret, session-derived fields without inventing defaults."""
    keybag_handle = _uint(keybag_handle, 64, "keybag handle")
    if (isinstance(selector, bool) or not isinstance(selector, int)
            or not -(1 << 31) <= selector < (1 << 31)):
        raise AKSTransportError("verify-secret selector must be a signed 32-bit integer")
    return VerifySecretMetadata(keybag_handle, selector)


def _align4(value: int) -> int:
    return (value + 3) & ~3


class AuthorizationPlan:
    """Order capability negotiation and verify-secret without secret bytes."""

    def __init__(self) -> None:
        self.capabilities_request: AKSEnvelope | None = None
        self.header_version: int | None = None
        self.verify_metadata: VerifySecretMetadata | None = None
        self.verify_request: AKSEnvelope | None = None
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

    def plan_verify_secret(self, tag: int, password_length: int, *,
                           keybag_handle: int,
                           selector: int) -> bytes:
        if self.header_version is None or self.verify_request is not None:
            raise AKSTransportError("verify-secret request is out of order")
        metadata = verify_secret_metadata(keybag_handle, selector)
        size = verify_secret_serialized_size(password_length)
        wire = encode_request(VERIFY_SECRET_V1, tag, size)
        self.verify_metadata = metadata
        self.verify_request = decode_envelope(wire)
        return wire

    def accept_verify_secret_success(self, reply_data: bytes,
                                     payload: bytes) -> VerifySecretReply:
        if (self.verify_request is None or self.header_version not in (1, 2)
                or self.verify_reply is not None):
            raise AKSTransportError("verify-secret reply is out of order")
        envelope = validate_reply(self.verify_request, reply_data)
        if envelope.payload_length != len(payload):
            raise AKSTransportError("verify-secret envelope length does not match payload")
        self.verify_reply = decode_verify_secret_reply(payload, self.header_version)
        return self.verify_reply
