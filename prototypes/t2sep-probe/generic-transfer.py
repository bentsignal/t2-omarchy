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


class RemoteError(ProtocolError):
    def __init__(self, code: int):
        _u32("remote error code", code)
        self.code = code
        super().__init__(f"SEP generic-transfer error 0x{code:08x}")


@dataclass(frozen=True)
class Notification:
    sequence: int
    command: int
    message_type: int


@dataclass(frozen=True)
class OutboundRecord:
    notification_word: int
    packet: bytes | None


@dataclass(frozen=True)
class TransactionResult:
    outbound: OutboundRecord | None = None
    response: bytes | None = None


class SequenceTracker:
    """Validate the 16-bit per-direction notification sequence, including wrap."""

    def __init__(self):
        self.previous: int | None = None

    def validate(self, notification: Notification) -> None:
        if not isinstance(notification, Notification):
            raise ProtocolError("sequence tracker requires a Notification")
        if (isinstance(notification.sequence, bool)
                or not isinstance(notification.sequence, int)
                or not 0 <= notification.sequence <= 0xFFFF):
            raise ProtocolError("notification sequence is not an unsigned 16-bit value")
        _u32("notification command", notification.command)
        if notification.message_type not in (
                MESSAGE_FIRST, MESSAGE_NEXT_IN, MESSAGE_NEXT_OUT, MESSAGE_ERROR):
            raise ProtocolError("notification has an unsupported message type")
        if self.previous is not None and notification.sequence != (self.previous + 1) & 0xFFFF:
            raise ProtocolError("notification sequence skipped, repeated, or went backwards")

    def accept(self, notification: Notification) -> None:
        self.validate(notification)
        self.previous = notification.sequence


class Reassembler:
    """Fail-closed reassembly of first (0xfc) and continuation (0xfd) packets."""

    def __init__(self, maximum: int):
        _u32("maximum", maximum)
        self.maximum = maximum
        self.packet: Packet | None = None
        self.data = bytearray()
        self.complete = False

    def add(self, message_type: int, raw: bytes) -> bytes | None:
        if self.complete:
            raise ProtocolError("transaction received data after completion")
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
            self.complete = True
            return bytes(self.data)
        if not packet.payload:
            raise ProtocolError("incomplete transaction made no progress")
        return None


def _u32(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
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
        if not isinstance(self.payload, bytes):
            raise ProtocolError("payload must be bytes")
        if self.offset > self.total_length:
            raise ProtocolError("offset exceeds total length")
        if len(self.payload) > self.total_length - self.offset:
            raise ProtocolError("payload extends past total length")
        return HEADER.pack(VERSION, self.total_length, self.offset, self.flags,
                           0, self.command, len(self.payload)) + self.payload


def decode_packet(data: bytes) -> Packet:
    if not isinstance(data, bytes):
        raise ProtocolError("packet must be bytes")
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
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 0xFFFF:
        raise ProtocolError("sequence is not an unsigned 16-bit value")
    _u32("command", command)
    if (isinstance(message_type, bool) or not isinstance(message_type, int)
            or not 0 <= message_type <= 0xFF):
        raise ProtocolError("message type is not an unsigned 8-bit value")
    return sequence << 48 | command << 16 | message_type << 8


def decode_mailbox_notification(word: int) -> tuple[int, int, int, int]:
    if (isinstance(word, bool) or not isinstance(word, int)
            or not 0 <= word <= 0xFFFFFFFFFFFFFFFF):
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
    if not isinstance(raw, bytes) or len(raw) <= HEADER_SIZE:
        raise ProtocolError("error packet is not larger than the common header")
    return struct.unpack_from("<I", raw, 16)[0]


class InboundTransaction:
    """Couple mailbox sequence, command, packet, and reassembly validation."""

    def __init__(self, maximum: int):
        self.sequence = SequenceTracker()
        self.reassembler = Reassembler(maximum)

    def accept(self, notification_word: int, raw: bytes) -> bytes | None:
        notification = decode_generic_notification(notification_word)
        self.sequence.accept(notification)
        if notification.message_type == MESSAGE_ERROR:
            raise RemoteError(decode_error_code(raw))
        notification, _ = decode_notified_packet(notification_word, raw)
        # Reassembler decodes again intentionally: its public boundary must
        # remain independently safe when used without this coupled wrapper.
        return self.reassembler.add(notification.message_type, raw)


class OutboundTransaction:
    """Offline planner for Apple's host-to-SEP generic-transfer handshake.

    ``first`` emits the initial 0xfc record.  Further 0xfd records are emitted
    only in response to an ordered 0xfe notification from SEP.  This class
    plans immutable bytes; it performs no DMA, mailbox, or device access.
    """

    def __init__(self, payload: bytes, command: int, flags: int,
                 buffer_capacity: int, initial_sequence: int = 0):
        if not isinstance(payload, bytes):
            raise ProtocolError("payload must be bytes")
        _u32("command", command)
        _u32("flags", flags)
        _u32("buffer capacity", buffer_capacity)
        if buffer_capacity <= HEADER_SIZE:
            raise ProtocolError("buffer capacity must exceed the 28-byte header")
        if len(payload) > 0xFFFFFFFF:
            raise ProtocolError("payload exceeds the protocol length field")
        if (isinstance(initial_sequence, bool)
                or not isinstance(initial_sequence, int)
                or not 0 <= initial_sequence <= 0xFFFF):
            raise ProtocolError("initial sequence is not an unsigned 16-bit value")
        self._payload = payload
        self.command = command
        self.flags = flags
        self.capacity = buffer_capacity - HEADER_SIZE
        self._next_sequence = initial_sequence
        self._offset = 0
        self._started = False
        self.complete = False
        self.requests = SequenceTracker()

    def _emit(self, message_type: int) -> OutboundRecord:
        remaining = len(self._payload) - self._offset
        chunk_length = min(remaining, self.capacity)
        packet = Packet(len(self._payload), self._offset, self.flags, self.command,
                        self._payload[self._offset:self._offset + chunk_length]).encode()
        word = encode_mailbox_notification(self._next_sequence, self.command, message_type)
        self._next_sequence = (self._next_sequence + 1) & 0xFFFF
        self._offset += chunk_length
        self.complete = self._offset == len(self._payload)
        return OutboundRecord(word, packet)

    def _emit_notification(self, message_type: int) -> OutboundRecord:
        word = encode_mailbox_notification(self._next_sequence, self.command, message_type)
        self._next_sequence = (self._next_sequence + 1) & 0xFFFF
        return OutboundRecord(word, None)

    def first(self) -> OutboundRecord:
        if self._started:
            raise ProtocolError("first outbound packet was already emitted")
        self._started = True
        return self._emit(MESSAGE_FIRST)

    def accept_next_request(self, notification_word: int) -> OutboundRecord:
        if not self._started:
            raise ProtocolError("outbound transaction has not started")
        if self.complete:
            raise ProtocolError("outbound transaction received request after completion")
        notification = decode_generic_notification(notification_word)
        if notification.message_type != MESSAGE_NEXT_OUT:
            raise ProtocolError("outbound continuation requires message type 0xfe")
        if notification.command != self.command:
            raise ProtocolError("continuation request changed transaction command")
        self.requests.accept(notification)
        return self._emit(MESSAGE_NEXT_IN)


class TransactionSession:
    """Couple one host request with its SEP response, entirely offline."""

    def __init__(self, request: bytes, command: int, flags: int,
                 send_capacity: int, maximum_response: int,
                 initial_sequence: int = 0):
        self.outbound = OutboundTransaction(
            request, command, flags, send_capacity, initial_sequence)
        self.command = command
        self.inbound = Reassembler(maximum_response)
        self.peer_sequence = SequenceTracker()
        self.started = False
        self.complete = False

    def start(self) -> OutboundRecord:
        if self.started:
            raise ProtocolError("transaction session was already started")
        self.started = True
        return self.outbound.first()

    def accept(self, notification_word: int, raw: bytes | None = None) -> TransactionResult:
        if not self.started:
            raise ProtocolError("transaction session has not started")
        if self.complete:
            raise ProtocolError("transaction session received data after completion")
        notification = decode_generic_notification(notification_word)

        if notification.message_type == MESSAGE_NEXT_OUT:
            if raw is not None:
                raise ProtocolError("0xfe continuation request must not carry packet bytes")
            if self.outbound.complete:
                raise ProtocolError("SEP requested outbound data after request completion")
            if notification.command != self.command:
                raise ProtocolError("continuation request changed transaction command")
            self.peer_sequence.accept(notification)
            # The session owns the peer-wide sequence tracker.  Emit directly
            # after all request validation so the narrower helper cannot track
            # only the 0xfe subset as if it were a separate wire stream.
            return TransactionResult(self.outbound._emit(MESSAGE_NEXT_IN))

        if notification.message_type == MESSAGE_ERROR:
            if notification.command != self.command:
                raise ProtocolError("error notification changed transaction command")
            if raw is None:
                raise ProtocolError("error notification is missing packet bytes")
            code = decode_error_code(raw)
            self.peer_sequence.accept(notification)
            raise RemoteError(code)

        if notification.message_type not in (MESSAGE_FIRST, MESSAGE_NEXT_IN):
            raise ProtocolError("unsupported transaction-session notification")
        if not self.outbound.complete:
            raise ProtocolError("SEP response began before request upload completed")
        if raw is None:
            raise ProtocolError("response notification is missing packet bytes")
        decoded_notification, packet = decode_notified_packet(notification_word, raw)
        if packet.command != self.command:
            raise ProtocolError("response command does not match request command")
        # Validate sequence before mutating the reassembler, then commit the
        # tracker only after packet validation succeeds.
        self.peer_sequence.validate(decoded_notification)
        response = self.inbound.add(decoded_notification.message_type, raw)
        self.peer_sequence.accept(decoded_notification)
        if response is not None:
            self.complete = True
            return TransactionResult(response=response)
        return TransactionResult(
            outbound=self.outbound._emit_notification(MESSAGE_NEXT_OUT))


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
