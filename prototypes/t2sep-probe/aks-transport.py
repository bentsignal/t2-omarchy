#!/usr/bin/env python3
"""Pure, fail-closed codec for AppleKeyStore's T2 SEP mailbox envelope."""

from __future__ import annotations

from dataclasses import dataclass
import struct


AKS_ENDPOINT = 0x07
OOL_CAPACITY = 0x4000
ENVELOPE_SIZE = 12
REPLY_BIT = 0x80
GET_CAPABILITIES = 0x4D
VERIFY_SECRET_V1 = 0x21
MAX_HEADER_VERSION = 2
SERIALIZED_HEADER_SIZE = 0x54
ACM_CONTEXT_SIZE = 16
CAPABILITIES_SERIALIZED_SIZE = SERIALIZED_HEADER_SIZE + 4 + 8 + 4


class AKSTransportError(ValueError):
    pass


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
    password_length = _length(password_length, "password")
    context_length = _length(context_length, "ACM context")
    if context_length != ACM_CONTEXT_SIZE:
        raise AKSTransportError("ACM external form must be exactly 16 bytes")
    # Header, variant word, keybag qword, selector word, two length-prefixed
    # four-byte-aligned blobs, and the variant-1 device-state qword. The
    # in-memory option at offset 0x88 is not serialized by this variant.
    total = (SERIALIZED_HEADER_SIZE + 4 + 8 + 4
             + 4 + _align4(password_length)
             + 4 + _align4(context_length) + 8)
    if total > OOL_CAPACITY:
        raise AKSTransportError("serialized verify-secret request exceeds OOL")
    return total


def _length(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AKSTransportError(f"{label} length must be a nonnegative integer")
    return value


def _align4(value: int) -> int:
    return (value + 3) & ~3


class AuthorizationPlan:
    """Order capability negotiation and verify-secret without secret bytes."""

    def __init__(self) -> None:
        self.capabilities_request: AKSEnvelope | None = None
        self.header_version: int | None = None
        self.verify_request: AKSEnvelope | None = None

    def request_capabilities(self, tag: int) -> bytes:
        if self.capabilities_request is not None or self.header_version is not None:
            raise AKSTransportError("capabilities request is out of order")
        wire = encode_request(GET_CAPABILITIES, tag, CAPABILITIES_SERIALIZED_SIZE)
        self.capabilities_request = decode_envelope(wire)
        return wire

    def accept_capabilities_transport(self, reply_data: bytes,
                                      *, status: int,
                                      remote_version: int | None) -> int:
        if self.capabilities_request is None or self.header_version is not None:
            raise AKSTransportError("capabilities reply is out of order")
        validate_reply(self.capabilities_request, reply_data)
        self.header_version = negotiated_header_version(status, remote_version)
        return self.header_version

    def plan_verify_secret(self, tag: int, password_length: int) -> bytes:
        if self.header_version is None or self.verify_request is not None:
            raise AKSTransportError("verify-secret request is out of order")
        size = verify_secret_serialized_size(password_length)
        wire = encode_request(VERIFY_SECRET_V1, tag, size)
        self.verify_request = decode_envelope(wire)
        return wire
