#!/usr/bin/env python3
"""Pure, fail-closed codec for AppleKeyStore's T2 SEP mailbox envelope."""

from __future__ import annotations

from dataclasses import dataclass
import struct


AKS_ENDPOINT = 0x07
OOL_CAPACITY = 0x4000
ENVELOPE_SIZE = 12
REPLY_BIT = 0x80


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
