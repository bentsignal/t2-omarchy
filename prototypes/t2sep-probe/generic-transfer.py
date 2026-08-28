#!/usr/bin/env python3
"""Strict offline codec for Apple's SEP generic-transfer framing."""

from __future__ import annotations
import argparse
import struct
from dataclasses import dataclass

VERSION = 1
HEADER = struct.Struct("<7I")
HEADER_SIZE = HEADER.size
GENERIC_TRANSFER_MESSAGE_TYPE = 0xFC
MESSAGE_FIRST = 0xFC
MESSAGE_NEXT_IN = 0xFD
MESSAGE_NEXT_OUT = 0xFE
MESSAGE_ERROR = 0xFF


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Notification:
    sequence: int
    command: int
    message_type: int


class SequenceTracker:
    """Validate the 16-bit per-direction notification sequence, including wrap."""

    def __init__(self):
        self.previous: int | None = None

    def accept(self, notification: Notification) -> None:
        if self.previous is not None and notification.sequence != (self.previous + 1) & 0xFFFF:
            raise ProtocolError("notification sequence skipped, repeated, or went backwards")
        self.previous = notification.sequence


class Reassembler:
    """Fail-closed reassembly of first (0xfc) and continuation (0xfd) packets."""

    def __init__(self, maximum: int):
        _u32("maximum", maximum)
        self.maximum = maximum
        self.packet: Packet | None = None
        self.data = bytearray()

    def add(self, message_type: int, raw: bytes) -> bytes | None:
        packet = decode_packet(raw)
        if self.packet is None:
            if message_type != MESSAGE_FIRST or packet.offset != 0:
                raise ProtocolError("transaction must begin with a 0xfc packet at offset zero")
            if packet.total_length > self.maximum:
                raise ProtocolError("transaction exceeds configured maximum")
            self.packet = packet
        else:
            if message_type != MESSAGE_NEXT_IN:
                raise ProtocolError("continuation must use message type 0xfd")
            if (packet.total_length, packet.flags, packet.command) != (
                    self.packet.total_length, self.packet.flags, self.packet.command):
                raise ProtocolError("continuation header changed transaction metadata")
            if packet.offset != len(self.data):
                raise ProtocolError("continuation is overlapping, duplicated, or out of order")
        self.data.extend(packet.payload)
        if len(self.data) == packet.total_length:
            return bytes(self.data)
        if not packet.payload:
            raise ProtocolError("incomplete transaction made no progress")
        return None


def _u32(name: str, value: int) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError(f"{name} is not an unsigned 32-bit value")


@dataclass(frozen=True)
class Packet:
    total_length: int
    offset: int
    flags: int
    command: int
    payload: bytes

    def encode(self) -> bytes:
        for name in ("total_length", "offset", "flags", "command"):
            _u32(name, getattr(self, name))
        if self.offset > self.total_length:
            raise ProtocolError("offset exceeds total length")
        if len(self.payload) > self.total_length - self.offset:
            raise ProtocolError("payload extends past total length")
        return HEADER.pack(VERSION, self.total_length, self.offset, self.flags,
                           0, self.command, len(self.payload)) + self.payload


def decode_packet(data: bytes) -> Packet:
    if len(data) < HEADER_SIZE:
        raise ProtocolError("packet is shorter than the 28-byte header")
    version, total, offset, flags, reserved, command, chunk = HEADER.unpack_from(data)
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if reserved != 0:
        raise ProtocolError("reserved header field is nonzero")
    if chunk != len(data) - HEADER_SIZE:
        raise ProtocolError("chunk length does not match packet size")
    if offset > total or chunk > total - offset:
        raise ProtocolError("chunk lies outside the declared transaction")
    return Packet(total, offset, flags, command, data[HEADER_SIZE:])


def encode_mailbox_notification(sequence: int, command: int,
                                message_type: int = GENERIC_TRANSFER_MESSAGE_TYPE) -> int:
    if not 0 <= sequence <= 0xFFFF:
        raise ProtocolError("sequence is not an unsigned 16-bit value")
    _u32("command", command)
    if not 0 <= message_type <= 0xFF:
        raise ProtocolError("message type is not an unsigned 8-bit value")
    return sequence << 48 | command << 16 | message_type << 8


def decode_mailbox_notification(word: int) -> tuple[int, int, int, int]:
    if not 0 <= word <= 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError("mailbox word is not an unsigned 64-bit value")
    return word >> 48, (word >> 16) & 0xFFFFFFFF, (word >> 8) & 0xFF, word & 0xFF


def decode_generic_notification(word: int) -> Notification:
    sequence, command, message_type, reserved = decode_mailbox_notification(word)
    if reserved:
        raise ProtocolError("notification reserved low byte is nonzero")
    if message_type not in (MESSAGE_FIRST, MESSAGE_NEXT_IN, MESSAGE_NEXT_OUT, MESSAGE_ERROR):
        raise ProtocolError("notification is not a generic-transfer message")
    return Notification(sequence, command, message_type)


def decode_notified_packet(word: int, raw: bytes) -> tuple[Notification, Packet]:
    notification = decode_generic_notification(word)
    if notification.message_type not in (MESSAGE_FIRST, MESSAGE_NEXT_IN):
        raise ProtocolError("notification does not announce an inbound data packet")
    packet = decode_packet(raw)
    if packet.command != notification.command:
        raise ProtocolError("mailbox command does not match packet command")
    return notification, packet


def decode_error_code(raw: bytes) -> int:
    # Apple's _gt_read_error requires a buffer larger than the 28-byte common
    # header and reads the status from word four (offset 16).
    if len(raw) <= HEADER_SIZE:
        raise ProtocolError("error packet is not larger than the common header")
    return struct.unpack_from("<I", raw, 16)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hex_packet", help="packet as hexadecimal bytes")
    args = parser.parse_args()
    packet = decode_packet(bytes.fromhex(args.hex_packet))
    print(f"version={VERSION} total={packet.total_length} offset={packet.offset} "
          f"flags=0x{packet.flags:08x} command=0x{packet.command:08x} "
          f"chunk={len(packet.payload)} payload={packet.payload.hex()}")


if __name__ == "__main__":
    main()
