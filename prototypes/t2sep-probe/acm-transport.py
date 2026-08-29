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
SCRD_VERSION = 0x28
COMMAND_MAGIC = b"DRCS"
CONTEXT_CREATE_SELECTOR = 1
CONTEXT_DELETE_SELECTOR = 2
COMMAND_VERSION = 1
CONTEXT_RESPONSE_SIZE = 17
CONTEXT_EXTERNAL_FORM_SIZE = 16
CONTEXT_DELETE_COMMAND_SIZE = 8 + CONTEXT_EXTERNAL_FORM_SIZE


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


def validate_success_reply(request: ACMEnvelope, reply_data: bytes,
                           payload: bytes | bytearray,
                           *, expected_length: int) -> None:
    """Accept only a correlated, zero-status reply and its exact OOL bytes."""
    expected_length = _integer(expected_length, OOL_CAPACITY,
                               "expected reply length")
    if not isinstance(payload, (bytes, bytearray)):
        raise ACMTransportError("ACM reply payload must be bytes-like")
    reply = validate_reply(request, reply_data, maximum_reply=expected_length)
    if reply.value != 0:
        raise ACMTransportError("ACM reply reports a nonzero SEP status")
    if reply.payload_length != expected_length or len(payload) != expected_length:
        raise ACMTransportError("ACM reply payload length does not match")


def scrd_initialization_payload() -> bytes:
    return SCRD_MAGIC + bytes((SCRD_VERSION, 0, 0))


def scrd_initialization_envelope() -> tuple[bytes, bytes]:
    payload = scrd_initialization_payload()
    return encode_envelope(COMMAND_MESSAGE_TYPE, len(payload), 0), payload


def context_create_command() -> bytes:
    return COMMAND_MAGIC + bytes((CONTEXT_CREATE_SELECTOR, 0, 0, COMMAND_VERSION))


def context_delete_command_into(context_response: bytearray,
                                command: bytearray) -> None:
    """Build delete in caller-owned mutable memory, without returning a secret copy."""
    if not isinstance(context_response, bytearray):
        raise ACMTransportError("context response must be a mutable bytearray")
    if len(context_response) != CONTEXT_RESPONSE_SIZE:
        raise ACMTransportError("context response must be exactly 17 bytes")
    if not isinstance(command, bytearray):
        raise ACMTransportError("context-delete command must be a mutable bytearray")
    if len(command) != CONTEXT_DELETE_COMMAND_SIZE:
        raise ACMTransportError("context-delete command must be exactly 24 bytes")
    command[:8] = COMMAND_MAGIC + bytes((
        CONTEXT_DELETE_SELECTOR, 0, CONTEXT_EXTERNAL_FORM_SIZE,
        COMMAND_VERSION))
    command[8:] = context_response[:CONTEXT_EXTERNAL_FORM_SIZE]


def context_external_form_for_authorization(
        context_response: bytearray) -> bytearray:
    """Copy only the 16-byte external form for one consuming AKS request.

    The original 17-byte create response remains owned by the ACM lifecycle so
    it can identify and delete the same context later.  The returned mutable
    copy is intended for ``consume_verify_secret_inputs``, which scrubs it.
    """
    if not isinstance(context_response, bytearray):
        raise ACMTransportError("context response must be a mutable bytearray")
    if len(context_response) != CONTEXT_RESPONSE_SIZE:
        raise ACMTransportError("context response must be exactly 17 bytes")
    return bytearray(memoryview(context_response)[:CONTEXT_EXTERNAL_FORM_SIZE])


def scrub_context_material(context_response: bytearray,
                           command: bytearray) -> None:
    """Zero both caller-owned buffers after delete attempt or transport stop."""
    if not isinstance(context_response, bytearray) or not isinstance(command, bytearray):
        raise ACMTransportError("context material must remain in mutable bytearrays")
    if (len(context_response) != CONTEXT_RESPONSE_SIZE or
            len(command) != CONTEXT_DELETE_COMMAND_SIZE):
        raise ACMTransportError("context material has an unexpected size")
    context_response[:] = b"\0" * len(context_response)
    command[:] = b"\0" * len(command)


def validate_context_create_response_length(length: int) -> None:
    length = _integer(length, OOL_CAPACITY, "context-create response length")
    if length != CONTEXT_RESPONSE_SIZE:
        raise ACMTransportError("context-create response must be exactly 17 bytes")


class ContextCreatePlan:
    """Order SCRD init and one create/delete lifecycle without storing a handle."""

    def __init__(self) -> None:
        self.initialization_request: ACMEnvelope | None = None
        self.initialized = False
        self.context_create_request: ACMEnvelope | None = None
        self.context_created = False
        self.context_delete_request: ACMEnvelope | None = None
        self.context_deleted = False

    def initialize(self) -> tuple[bytes, bytes]:
        if self.initialization_request is not None or self.initialized:
            raise ACMTransportError("SCRD initialization is out of order")
        envelope, payload = scrd_initialization_envelope()
        self.initialization_request = decode_envelope(envelope)
        return envelope, payload

    def accept_initialization_reply(self, reply_data: bytes,
                                    payload: bytes) -> None:
        if self.initialization_request is None or self.initialized:
            raise ACMTransportError("SCRD initialization reply is out of order")
        validate_success_reply(self.initialization_request, reply_data, payload,
                               expected_length=0)
        self.initialized = True

    def context_request(self) -> tuple[bytes, bytes]:
        if (not self.initialized or self.context_create_request is not None or
                self.context_created):
            raise ACMTransportError("context creation is out of order")
        payload = context_create_command()
        envelope = encode_envelope(COMMAND_MESSAGE_TYPE, len(payload), 0)
        self.context_create_request = decode_envelope(envelope)
        return envelope, payload

    def accept_context_response(self, reply_data: bytes,
                                payload: bytearray) -> None:
        if (not self.initialized or self.context_create_request is None or
                self.context_created):
            raise ACMTransportError("context response is out of order")
        if not isinstance(payload, bytearray):
            raise ACMTransportError("context response must be a mutable bytearray")
        validate_success_reply(self.context_create_request, reply_data, payload,
                               expected_length=CONTEXT_RESPONSE_SIZE)
        self.context_created = True

    def delete_request(self, context_response: bytearray,
                       command: bytearray) -> bytes:
        if (not self.context_created or self.context_delete_request is not None or
                self.context_deleted):
            raise ACMTransportError("context deletion is out of order")
        context_delete_command_into(context_response, command)
        envelope = encode_envelope(COMMAND_MESSAGE_TYPE, len(command), 0)
        self.context_delete_request = decode_envelope(envelope)
        return envelope

    def accept_delete_response(self, reply_data: bytes, payload: bytes) -> None:
        if (not self.context_created or self.context_delete_request is None or
                self.context_deleted):
            raise ACMTransportError("context-delete response is out of order")
        validate_success_reply(self.context_delete_request, reply_data, payload,
                               expected_length=0)
        self.context_deleted = True
