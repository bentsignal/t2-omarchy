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


class ProtocolError(ValueError):
    pass


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
