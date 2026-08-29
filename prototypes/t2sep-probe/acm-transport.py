#!/usr/bin/env python3
"""Pure codec for the recovered AppleCredentialManager T2 SEP envelope."""

from __future__ import annotations

from dataclasses import dataclass
import struct


ACM_ENDPOINT = 0x0A
OOL_CAPACITY = 0x4000
ENVELOPE_SIZE = 12
COMMAND_MESSAGE_TYPE = 1
SCRD_MAGIC = b"DRCS\n"
COMMAND_MAGIC = b"DRCS"
CONTEXT_CREATE_SELECTOR = 1
COMMAND_VERSION = 1
CONTEXT_RESPONSE_SIZE = 17


class ACMTransportError(ValueError):
    pass


@dataclass(frozen=True)
class ACMEnvelope:
    message_type: int
    payload_length: int
    value: int


def _integer(value: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ACMTransportError(f"{label} is outside its unsigned wire field")
    return value


def encode_envelope(message_type: int, payload_length: int, value: int) -> bytes:
    message_type = _integer(message_type, 0xff, "message type")
    payload_length = _integer(payload_length, OOL_CAPACITY, "payload length")
    value = _integer(value, 0xffffffff, "value")
    return struct.pack("<BBHII", ACM_ENDPOINT, message_type,
                       payload_length, value, 0)


def decode_envelope(data: bytes) -> ACMEnvelope:
    if not isinstance(data, bytes) or len(data) != ENVELOPE_SIZE:
        raise ACMTransportError("ACM envelope must be exactly 12 bytes")
    endpoint, message_type, length, value, reserved = struct.unpack("<BBHII", data)
    if endpoint != ACM_ENDPOINT:
        raise ACMTransportError("ACM envelope has the wrong endpoint")
    if reserved != 0:
        raise ACMTransportError("ACM envelope has nonzero reserved data")
    if length > OOL_CAPACITY:
        raise ACMTransportError("ACM envelope exceeds the OOL buffer")
    return ACMEnvelope(message_type, length, value)


def validate_reply(request: ACMEnvelope, reply_data: bytes,
                   *, maximum_reply: int) -> ACMEnvelope:
    if not isinstance(request, ACMEnvelope):
        raise ACMTransportError("reply validation requires a request envelope")
    maximum_reply = _integer(maximum_reply, OOL_CAPACITY, "maximum reply")
    reply = decode_envelope(reply_data)
    if reply.message_type != request.message_type:
        raise ACMTransportError("ACM reply message type does not match")
    if reply.payload_length > maximum_reply:
        raise ACMTransportError("ACM reply exceeds the caller's output buffer")
    return reply


def scrd_initialization_payload(version: int) -> bytes:
    version = _integer(version, 0xff, "SCRD version")
    return SCRD_MAGIC + bytes((version, 0, 0))


def scrd_initialization_envelope(version: int) -> tuple[bytes, bytes]:
    payload = scrd_initialization_payload(version)
    return encode_envelope(COMMAND_MESSAGE_TYPE, len(payload), 0), payload


def context_create_command() -> bytes:
    return COMMAND_MAGIC + bytes((CONTEXT_CREATE_SELECTOR, 0, 0, COMMAND_VERSION))


def validate_context_create_response_length(length: int) -> None:
    length = _integer(length, OOL_CAPACITY, "context-create response length")
    if length != CONTEXT_RESPONSE_SIZE:
        raise ACMTransportError("context-create response must be exactly 17 bytes")


class ContextCreatePlan:
    """Order SCRD init and token-free context creation without storing a handle."""

    def __init__(self) -> None:
        self.initialized = False
        self.context_created = False

    def initialize(self, version: int) -> tuple[bytes, bytes]:
        if self.initialized or self.context_created:
            raise ACMTransportError("SCRD initialization is out of order")
        result = scrd_initialization_envelope(version)
        self.initialized = True
        return result

    def context_request(self) -> tuple[bytes, bytes]:
        if not self.initialized or self.context_created:
            raise ACMTransportError("context creation is out of order")
        payload = context_create_command()
        return encode_envelope(COMMAND_MESSAGE_TYPE, len(payload), 0), payload

    def accept_context_response_length(self, length: int) -> None:
        if not self.initialized or self.context_created:
            raise ACMTransportError("context response is out of order")
        validate_context_create_response_length(length)
        self.context_created = True
