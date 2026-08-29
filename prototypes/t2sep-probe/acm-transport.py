#!/usr/bin/env python3
"""Pure codec for the recovered AppleCredentialManager T2 SEP envelope."""

from __future__ import annotations

from dataclasses import dataclass
import struct


ACM_ENDPOINT = 0x0A
OOL_CAPACITY = 0x4000
ENVELOPE_SIZE = 12


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
