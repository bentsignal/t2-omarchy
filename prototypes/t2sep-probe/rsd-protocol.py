#!/usr/bin/env python3
"""Strict offline codec for the modern remoted/RSD directory path.

Nothing in this module opens a socket. A macOS boot trace proves the address
roles and that both directory and service ports are boot-dynamic.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct
import uuid
from typing import Any


class RSDProtocolError(ValueError):
    pass


LINUX_CDC_DESCRIPTOR_MAC = bytes.fromhex("acde48001122")
T2_NCM_MAC = bytes.fromhex("acde48334455")


def ncm_link_local_address(mac: bytes, *, peer: bool) -> str:
    """Reproduce current macOS remoted's NCM IPv6 address construction."""
    if not isinstance(mac, bytes) or len(mac) != 6:
        raise RSDProtocolError("NCM MAC address must contain exactly six bytes")
    if not isinstance(peer, bool):
        raise RSDProtocolError("NCM peer selector must be boolean")
    interface_id = bytearray(mac[:3] + b"\xff\xfe" + mac[3:])
    interface_id[0] ^= 0x02
    if peer:
        interface_id[-1] ^= 0xFF
    return str(ipaddress.IPv6Address(b"\xfe\x80" + b"\0" * 6 + interface_id))


LINUX_DESCRIPTOR_LINK_LOCAL_ADDRESS = ncm_link_local_address(
    LINUX_CDC_DESCRIPTOR_MAC, peer=False)
HOST_LINK_LOCAL_ADDRESS = LINUX_DESCRIPTOR_LINK_LOCAL_ADDRESS
T2_LINK_LOCAL_ADDRESS_CANDIDATE = ncm_link_local_address(T2_NCM_MAC, peer=False)
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_DATA = 0
HTTP2_HEADERS = 1
HTTP2_SETTINGS = 4
HTTP2_WINDOW_UPDATE = 8
HTTP2_ACK = 1
HTTP2_END_STREAM = 1
HTTP2_END_HEADERS = 4
ROOT_CHANNEL = 1
REPLY_CHANNEL = 3

XPC_WRAPPER_MAGIC = 0x29B00B92
XPC_OBJECT_MAGIC = 0x42133742
XPC_PROTOCOL_VERSION = 5
XPC_ALWAYS_SET = 0x00000001
XPC_PING = 0x00000002
XPC_DATA_PRESENT = 0x00000100
XPC_CHANNEL_TERMINATOR = 0x00000200
XPC_WANTING_REPLY = 0x00010000
XPC_REPLY = 0x00020000
XPC_FILE_TX_STREAM_REQUEST = 0x00100000
XPC_FILE_TX_STREAM_RESPONSE = 0x00200000
XPC_INIT_HANDSHAKE = 0x00400000
XPC_KNOWN_FLAGS = (XPC_ALWAYS_SET | XPC_PING | XPC_DATA_PRESENT
                   | XPC_CHANNEL_TERMINATOR
                   | XPC_WANTING_REPLY | XPC_REPLY
                   | XPC_FILE_TX_STREAM_REQUEST | XPC_FILE_TX_STREAM_RESPONSE
                   | XPC_INIT_HANDSHAKE)
XPC_DICTIONARY = 0x0000F000
XPC_ARRAY = 0x0000E000
XPC_STRING = 0x00009000
XPC_DATA = 0x00008000
XPC_BOOL = 0x00002000
XPC_INT64 = 0x00003000
XPC_UINT64 = 0x00004000
XPC_UUID = 0x0000A000
XPC_NULL = 0x00001000
XPC_WRAPPER_HEADER = struct.Struct("<IIQ")
XPC_MESSAGE_ID = struct.Struct("<Q")
XPC_PAYLOAD_HEADER = struct.Struct("<II")
MAX_PROTOCOL_DEPTH = 12


@dataclass(frozen=True)
class UInt64:
    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise RSDProtocolError("UInt64 value must be an integer")
        if not 0 <= self.value < 1 << 64:
            raise RSDProtocolError("UInt64 value is out of range")


@dataclass(frozen=True)
class Int64:
    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise RSDProtocolError("Int64 value must be an integer")
        if not -(1 << 63) <= self.value < 1 << 63:
            raise RSDProtocolError("Int64 value is out of range")


@dataclass(frozen=True)
class XPCMessage:
    flags: int
    message_id: int
    value: Any | None


def observed_rsd_sockaddr(interface_index: int,
                          directory_port: int) -> tuple[str, int, int, int]:
    """Build an endpoint from a same-boot observed directory port, offline."""
    if isinstance(interface_index, bool) or not isinstance(interface_index, int):
        raise RSDProtocolError("interface index must be an integer")
    if not 1 <= interface_index < 1 << 32:
        raise RSDProtocolError("interface index is out of range")
    if isinstance(directory_port, bool) or not isinstance(directory_port, int):
        raise RSDProtocolError("directory port must be an integer")
    if not 1 <= directory_port <= 65535:
        raise RSDProtocolError("directory port is out of range")
    return (T2_LINK_LOCAL_ADDRESS_CANDIDATE, directory_port, 0, interface_index)


class PassiveRSDTranscript:
    """Incrementally validate one bounded, passive RSD server transcript.

    This consumes caller-supplied bytes only.  It has no socket and cannot send
    the candidate client handshake.  A successful result means only that the
    supplied transcript advertised the requested named service.
    """

    def __init__(self, *, wanted_service: str, max_frame: int = 65536,
                 max_frames: int = 16, max_total: int = 262144,
                 max_xpc_body: int = 65536):
        if not isinstance(wanted_service, str) or not wanted_service:
            raise RSDProtocolError("wanted service must be a nonempty string")
        for value, name in ((max_frame, "frame"), (max_frames, "frame count"),
                            (max_total, "total"), (max_xpc_body, "XPC body")):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise RSDProtocolError(f"{name} cap must be a positive integer")
        self.wanted_service = wanted_service
        self.max_frame = max_frame
        self.max_frames = max_frames
        self.max_total = max_total
        self.max_xpc_body = max_xpc_body
        self._wire = bytearray()
        self._streams = {ROOT_CHANNEL: bytearray(), REPLY_CHANNEL: bytearray()}
        self._total = 0
        self._frame_count = 0
        self._settings_seen = False
        self._settings_count = 0
        self._ignored_controls = 0
        self._port: int | None = None

    def feed(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise RSDProtocolError("transcript chunks must be bytes")
        if self._port is not None and chunk:
            raise RSDProtocolError("RSD transcript contains bytes after its directory")
        self._total += len(chunk)
        if self._total > self.max_total:
            raise RSDProtocolError("RSD transcript exceeds the total byte cap")
        self._wire += chunk
        while len(self._wire) >= 9:
            length = int.from_bytes(self._wire[:3], "big")
            if length > self.max_frame:
                raise RSDProtocolError("RSD transcript frame exceeds its cap")
            frame_size = 9 + length
            if len(self._wire) < frame_size:
                return
            frame = bytes(self._wire[:frame_size])
            del self._wire[:frame_size]
            self._frame_count += 1
            if self._frame_count > self.max_frames:
                raise RSDProtocolError("RSD transcript exceeds its frame-count cap")
            self._accept_frame(*decode_http2_frame(frame, max_payload=self.max_frame))

    def _accept_frame(self, frame_type: int, flags: int, stream_id: int,
                      payload: bytes) -> None:
        if self._port is not None:
            raise RSDProtocolError("RSD transcript contains a frame after its directory")
        if frame_type == HTTP2_SETTINGS:
            self._accept_settings(flags, stream_id, payload)
            return
        if frame_type == HTTP2_WINDOW_UPDATE:
            self._accept_window_update(flags, stream_id, payload)
            return
        if frame_type == HTTP2_HEADERS:
            if (not self._settings_seen or stream_id not in self._streams
                    or flags != HTTP2_END_HEADERS or payload):
                raise RSDProtocolError("unexpected RSD HTTP/2 headers frame")
            return
        if frame_type != HTTP2_DATA:
            raise RSDProtocolError("unsupported frame in passive RSD transcript")
        if not self._settings_seen or stream_id not in self._streams:
            raise RSDProtocolError("RSD data arrived before settings or on a wrong stream")
        if flags & ~HTTP2_END_STREAM:
            raise RSDProtocolError("RSD data frame contains unsupported flags")
        stream = self._streams[stream_id]
        stream += payload
        if len(stream) > self.max_xpc_body + XPC_WRAPPER_HEADER.size + 8:
            raise RSDProtocolError("fragmented RSD XPC message exceeds its cap")
        self._consume_xpc_messages(stream)
        if flags & HTTP2_END_STREAM and stream:
            raise RSDProtocolError("RSD stream ended with a partial XPC message")

    def _accept_settings(self, flags: int, stream_id: int, payload: bytes) -> None:
        if stream_id != 0 or flags & ~HTTP2_ACK:
            raise RSDProtocolError("malformed RSD settings frame")
        if flags & HTTP2_ACK:
            if payload:
                raise RSDProtocolError("an acknowledged settings frame must be empty")
        elif len(payload) % 6:
            raise RSDProtocolError("RSD settings payload is not a sequence of entries")
        identifiers: set[int] = set()
        for offset in range(0, len(payload), 6):
            identifier, value = struct.unpack_from(">HI", payload, offset)
            if not 1 <= identifier <= 6 or identifier in identifiers:
                raise RSDProtocolError("RSD settings contain an invalid or duplicate ID")
            if identifier == 2 and value not in (0, 1):
                raise RSDProtocolError("RSD ENABLE_PUSH setting is invalid")
            if identifier == 4 and value > 0x7FFFFFFF:
                raise RSDProtocolError("RSD initial window setting is invalid")
            if identifier == 5 and not 16384 <= value <= 0xFFFFFF:
                raise RSDProtocolError("RSD maximum frame setting is invalid")
            identifiers.add(identifier)
        self._settings_count += 1
        if self._settings_count > 2:
            raise RSDProtocolError("RSD transcript contains too many settings frames")
        if not flags & HTTP2_ACK:
            self._settings_seen = True

    def _accept_window_update(self, flags: int, stream_id: int,
                              payload: bytes) -> None:
        if flags or stream_id not in (0, ROOT_CHANNEL, REPLY_CHANNEL) or len(payload) != 4:
            raise RSDProtocolError("malformed RSD window-update frame")
        increment = int.from_bytes(payload, "big")
        if increment & 0x80000000 or increment == 0:
            raise RSDProtocolError("invalid RSD window-update increment")
        self._ignored_controls += 1
        if self._ignored_controls > 4:
            raise RSDProtocolError("RSD transcript contains too many control frames")

    def _consume_xpc_messages(self, stream: bytearray) -> None:
        while len(stream) >= XPC_WRAPPER_HEADER.size + 8:
            body_size = int.from_bytes(stream[8:16], "little")
            if body_size > self.max_xpc_body:
                raise RSDProtocolError("RSD XPC body exceeds its cap")
            message_size = XPC_WRAPPER_HEADER.size + 8 + body_size
            if len(stream) < message_size:
                return
            encoded = bytes(stream[:message_size])
            del stream[:message_size]
            message = decode_xpc_message(encoded, max_body=self.max_xpc_body)
            if message.value is None:
                if message.flags & XPC_DATA_PRESENT:
                    raise RSDProtocolError("empty RSD XPC control claims to carry data")
                self._ignored_controls += 1
                if self._ignored_controls > 4:
                    raise RSDProtocolError("RSD transcript contains too many control messages")
                continue
            if not message.flags & XPC_DATA_PRESENT:
                raise RSDProtocolError("RSD directory XPC message lacks DATA_PRESENT")
            self._port = validate_service_directory(
                message.value, wanted_service=self.wanted_service
            )
            if stream or any(self._streams[channel] for channel in self._streams
                             if self._streams[channel] is not stream):
                raise RSDProtocolError("RSD directory was interleaved with surplus XPC data")

    def finish(self) -> int:
        if self._wire or any(self._streams.values()):
            raise RSDProtocolError("RSD transcript ended with a partial frame or XPC message")
        if not self._settings_seen or self._port is None:
            raise RSDProtocolError("RSD transcript ended before a service directory")
        return self._port

    @property
    def peer_settings_seen(self) -> bool:
        return self._settings_seen

    @property
    def complete(self) -> bool:
        return self._port is not None


def _pad4(length: int) -> int:
    return (-length) & 3


def _encode_string_payload(value: str) -> bytes:
    if not isinstance(value, str) or "\0" in value:
        raise RSDProtocolError("XPC strings must be NUL-free strings")
    raw = value.encode("utf-8") + b"\0"
    return struct.pack("<I", len(raw)) + raw + b"\0" * _pad4(len(raw))


def _encode_key(value: str) -> bytes:
    if not isinstance(value, str) or not value or "\0" in value:
        raise RSDProtocolError("XPC dictionary keys must be nonempty NUL-free strings")
    raw = value.encode("utf-8") + b"\0"
    return raw + b"\0" * _pad4(len(raw))


def _encode_object(value: Any, depth: int = 0) -> bytes:
    if depth > MAX_PROTOCOL_DEPTH:
        raise RSDProtocolError("XPC object nesting exceeds the depth cap")
    if value is None:
        return struct.pack("<I", XPC_NULL)
    if isinstance(value, bool):
        return struct.pack("<II", XPC_BOOL, int(value))
    if isinstance(value, UInt64):
        return struct.pack("<IQ", XPC_UINT64, value.value)
    if isinstance(value, Int64):
        return struct.pack("<Iq", XPC_INT64, value.value)
    if isinstance(value, uuid.UUID):
        return struct.pack("<I", XPC_UUID) + value.bytes
    if isinstance(value, str):
        return struct.pack("<I", XPC_STRING) + _encode_string_payload(value)
    if isinstance(value, bytes):
        return (struct.pack("<II", XPC_DATA, len(value)) + value
                + b"\0" * _pad4(len(value)))
    if isinstance(value, list):
        if len(value) > 4096:
            raise RSDProtocolError("XPC array exceeds the entry cap")
        entries = b"".join(_encode_object(item, depth + 1) for item in value)
        payload = struct.pack("<I", len(value)) + entries
        return struct.pack("<II", XPC_ARRAY, len(payload)) + payload
    if isinstance(value, dict):
        if len(value) > 4096:
            raise RSDProtocolError("XPC dictionary exceeds the entry cap")
        entries = bytearray()
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise RSDProtocolError("XPC dictionary keys must be nonempty strings")
            entries += _encode_key(key)
            entries += _encode_object(item, depth + 1)
        payload = struct.pack("<I", len(value)) + entries
        return struct.pack("<II", XPC_DICTIONARY, len(payload)) + payload
    raise RSDProtocolError(f"unsupported XPC object type: {type(value).__name__}")


def encode_xpc_message(value: dict[str, Any] | None, *, message_id: int,
                       flags: int | None = None, max_body: int = 65536) -> bytes:
    """Encode one bounded RemoteXPC wrapper, without HTTP/2 framing."""
    if isinstance(message_id, bool) or not isinstance(message_id, int):
        raise RSDProtocolError("message ID must be an integer")
    if not 0 <= message_id < 1 << 64:
        raise RSDProtocolError("message ID is out of range")
    if isinstance(max_body, bool) or not isinstance(max_body, int) or max_body < 0:
        raise RSDProtocolError("max_body must be a nonnegative integer")
    if value is not None and not isinstance(value, dict):
        raise RSDProtocolError("top-level XPC value must be a dictionary or None")
    if flags is None:
        flags = XPC_ALWAYS_SET | (XPC_DATA_PRESENT if value else 0)
    if isinstance(flags, bool) or not isinstance(flags, int) or not 0 <= flags < 1 << 32:
        raise RSDProtocolError("XPC flags are out of range")
    if not flags & XPC_ALWAYS_SET or flags & ~XPC_KNOWN_FLAGS:
        raise RSDProtocolError("XPC flags are missing ALWAYS_SET or contain unknown bits")
    payload = b""
    if value is not None:
        payload = XPC_PAYLOAD_HEADER.pack(XPC_OBJECT_MAGIC, XPC_PROTOCOL_VERSION)
        payload += _encode_object(value)
    if len(payload) > max_body:
        raise RSDProtocolError("XPC message exceeds the body cap")
    # Apple's wire length excludes the always-present 8-byte message ID.
    return (XPC_WRAPPER_HEADER.pack(XPC_WRAPPER_MAGIC, flags, len(payload))
            + XPC_MESSAGE_ID.pack(message_id) + payload)


class _Reader:
    def __init__(self, data: bytes, *, max_string: int, max_entries: int,
                 max_blob: int):
        self.data = data
        self.offset = 0
        self.max_string = max_string
        self.max_entries = max_entries
        self.max_blob = max_blob

    def read(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise RSDProtocolError("truncated XPC object")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def string(self) -> str:
        length = self.u32()
        if length == 0 or length > self.max_string:
            raise RSDProtocolError("XPC string length is invalid or exceeds its cap")
        raw = self.read(length)
        self.read(_pad4(length))
        if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
            raise RSDProtocolError("XPC string is not canonically NUL terminated")
        try:
            return raw[:-1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise RSDProtocolError("XPC string is not valid UTF-8") from error

    def key(self) -> str:
        end = self.data.find(b"\0", self.offset)
        if end < 0 or end - self.offset + 1 > self.max_string:
            raise RSDProtocolError("XPC dictionary key is unterminated or exceeds its cap")
        raw = self.read(end - self.offset + 1)
        padding = self.read(_pad4(len(raw)))
        if any(padding):
            raise RSDProtocolError("XPC dictionary key padding is nonzero")
        try:
            return raw[:-1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise RSDProtocolError("XPC dictionary key is not valid UTF-8") from error


def _decode_object(reader: _Reader, depth: int = 0) -> Any:
    if depth > MAX_PROTOCOL_DEPTH:
        raise RSDProtocolError("XPC object nesting exceeds the depth cap")
    object_type = reader.u32()
    if object_type == XPC_NULL:
        return None
    if object_type == XPC_BOOL:
        value = reader.u32()
        if value not in (0, 1):
            raise RSDProtocolError("XPC boolean is not canonical")
        return bool(value)
    if object_type == XPC_UINT64:
        return UInt64(struct.unpack("<Q", reader.read(8))[0])
    if object_type == XPC_INT64:
        return Int64(struct.unpack("<q", reader.read(8))[0])
    if object_type == XPC_UUID:
        return uuid.UUID(bytes=reader.read(16))
    if object_type == XPC_STRING:
        return reader.string()
    if object_type == XPC_DATA:
        length = reader.u32()
        if length > reader.max_blob:
            raise RSDProtocolError("XPC data exceeds the blob cap")
        value = reader.read(length)
        if any(reader.read(_pad4(length))):
            raise RSDProtocolError("XPC data padding is nonzero")
        return value
    if object_type == XPC_ARRAY:
        payload_size = reader.u32()
        payload = _Reader(reader.read(payload_size), max_string=reader.max_string,
                          max_entries=reader.max_entries, max_blob=reader.max_blob)
        count = payload.u32()
        if count > reader.max_entries:
            raise RSDProtocolError("XPC array exceeds the entry cap")
        result = [_decode_object(payload, depth + 1) for _ in range(count)]
        if payload.offset != len(payload.data):
            raise RSDProtocolError("XPC array contains trailing bytes")
        return result
    if object_type == XPC_DICTIONARY:
        payload_size = reader.u32()
        payload = _Reader(reader.read(payload_size), max_string=reader.max_string,
                          max_entries=reader.max_entries, max_blob=reader.max_blob)
        count = payload.u32()
        if count > reader.max_entries:
            raise RSDProtocolError("XPC dictionary exceeds the entry cap")
        result: dict[str, Any] = {}
        for _ in range(count):
            key = payload.key()
            if not key or key in result:
                raise RSDProtocolError("XPC dictionary has an empty or duplicate key")
            result[key] = _decode_object(payload, depth + 1)
        if payload.offset != len(payload.data):
            raise RSDProtocolError("XPC dictionary contains trailing bytes")
        return result
    raise RSDProtocolError(f"unsupported XPC object type 0x{object_type:08x}")


def decode_xpc_message(data: bytes, *, max_body: int = 65536,
                       max_string: int = 4096,
                       max_entries: int = 4096,
                       max_blob: int = 65536) -> XPCMessage:
    """Decode exactly one wrapper and reject truncation, surplus, and broad types."""
    if not isinstance(data, bytes) or len(data) < XPC_WRAPPER_HEADER.size + 8:
        raise RSDProtocolError("XPC wrapper is truncated")
    for cap, name in ((max_body, "body"), (max_string, "string"),
                      (max_entries, "entry"), (max_blob, "blob")):
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
            raise RSDProtocolError(f"{name} cap must be a nonnegative integer")
    magic, flags, body_size = XPC_WRAPPER_HEADER.unpack_from(data)
    if magic != XPC_WRAPPER_MAGIC:
        raise RSDProtocolError("invalid XPC wrapper magic")
    if not flags & XPC_ALWAYS_SET or flags & ~XPC_KNOWN_FLAGS:
        raise RSDProtocolError("XPC flags are missing ALWAYS_SET or contain unknown bits")
    if body_size > max_body:
        raise RSDProtocolError("XPC wrapper body size is invalid or exceeds its cap")
    if len(data) != XPC_WRAPPER_HEADER.size + 8 + body_size:
        raise RSDProtocolError("XPC wrapper length does not match its body size")
    message_id = XPC_MESSAGE_ID.unpack_from(data, XPC_WRAPPER_HEADER.size)[0]
    payload = data[XPC_WRAPPER_HEADER.size + 8:]
    if not payload:
        return XPCMessage(flags, message_id, None)
    if len(payload) < XPC_PAYLOAD_HEADER.size:
        raise RSDProtocolError("XPC payload header is truncated")
    magic, version = XPC_PAYLOAD_HEADER.unpack_from(payload)
    if magic != XPC_OBJECT_MAGIC or version != XPC_PROTOCOL_VERSION:
        raise RSDProtocolError("invalid XPC payload magic or version")
    reader = _Reader(payload[XPC_PAYLOAD_HEADER.size:], max_string=max_string,
                     max_entries=max_entries, max_blob=max_blob)
    value = _decode_object(reader)
    if reader.offset != len(reader.data):
        raise RSDProtocolError("XPC payload contains trailing bytes")
    if not isinstance(value, dict):
        raise RSDProtocolError("top-level XPC object is not a dictionary")
    return XPCMessage(flags, message_id, value)


def encode_http2_frame(frame_type: int, flags: int, stream_id: int,
                       payload: bytes = b"") -> bytes:
    """Encode one bounded HTTP/2 frame header plus payload."""
    for value, bits, name in ((frame_type, 8, "frame type"),
                              (flags, 8, "frame flags"),
                              (stream_id, 31, "stream ID")):
        if isinstance(value, bool) or not isinstance(value, int):
            raise RSDProtocolError(f"{name} must be an integer")
        if not 0 <= value < 1 << bits:
            raise RSDProtocolError(f"{name} is out of range")
    if not isinstance(payload, bytes) or len(payload) >= 1 << 24:
        raise RSDProtocolError("HTTP/2 payload is invalid or too large")
    return (len(payload).to_bytes(3, "big")
            + bytes((frame_type, flags))
            + stream_id.to_bytes(4, "big") + payload)


def decode_http2_frame(data: bytes, *, max_payload: int = 65536) -> tuple[int, int, int, bytes]:
    if not isinstance(data, bytes) or len(data) < 9:
        raise RSDProtocolError("HTTP/2 frame is truncated")
    if isinstance(max_payload, bool) or not isinstance(max_payload, int) or max_payload < 0:
        raise RSDProtocolError("max_payload must be a nonnegative integer")
    length = int.from_bytes(data[:3], "big")
    frame_type, flags = data[3], data[4]
    raw_stream_id = int.from_bytes(data[5:9], "big")
    if raw_stream_id & 0x80000000:
        raise RSDProtocolError("HTTP/2 reserved stream bit is set")
    if length > max_payload or len(data) != 9 + length:
        raise RSDProtocolError("HTTP/2 frame length is invalid or exceeds its cap")
    return frame_type, flags, raw_stream_id, data[9:]


def candidate_rsd_transport_opening() -> bytes:
    """Build client preface/channel setup sent before peer SETTINGS."""
    settings = struct.pack(">HIHI", 3, 100, 4, 16 * 1024 * 1024)
    empty = encode_xpc_message({}, message_id=0)
    terminator = encode_xpc_message(
        None, message_id=0, flags=XPC_ALWAYS_SET | XPC_CHANNEL_TERMINATOR
    )
    init = encode_xpc_message(None, message_id=0,
                              flags=XPC_ALWAYS_SET | XPC_INIT_HANDSHAKE)
    return b"".join((
        HTTP2_PREFACE,
        encode_http2_frame(HTTP2_SETTINGS, 0, 0, settings),
        encode_http2_frame(HTTP2_WINDOW_UPDATE, 0, 0,
                           struct.pack(">I", 16 * 1024 * 1024 - 65535)),
        encode_http2_frame(HTTP2_HEADERS, HTTP2_END_HEADERS, ROOT_CHANNEL),
        encode_http2_frame(HTTP2_DATA, 0, ROOT_CHANNEL, empty),
        encode_http2_frame(HTTP2_HEADERS, HTTP2_END_HEADERS, REPLY_CHANNEL),
        encode_http2_frame(HTTP2_DATA, 0, ROOT_CHANNEL, terminator),
        encode_http2_frame(HTTP2_DATA, 0, REPLY_CHANNEL, init),
    ))


def candidate_rsd_settings_ack() -> bytes:
    """Build the empty SETTINGS ACK sent only after peer SETTINGS arrives."""
    return encode_http2_frame(HTTP2_SETTINGS, HTTP2_ACK, 0)


def candidate_rsd_device_handshake(client_uuid: uuid.UUID) -> bytes:
    """Build the device handshake sent only after acknowledging peer SETTINGS."""
    if not isinstance(client_uuid, uuid.UUID):
        raise RSDProtocolError("client_uuid must be a UUID")
    handshake = encode_xpc_message({
        "MessageType": "Handshake",
        "MessagingProtocolVersion": UInt64(7),
        "UUID": client_uuid,
        "Properties": {
            "RemoteXPCVersionFlags": UInt64(0x0100000000000006),
            "SensitivePropertiesVisible": True,
        },
        "Services": {},
    }, message_id=1)
    return encode_http2_frame(HTTP2_DATA, 0, ROOT_CHANNEL, handshake)


def validate_service_directory(value: Any, *, wanted_service: str) -> int:
    """Return only a named advertised port from a decoded passive directory."""
    if not isinstance(wanted_service, str) or not wanted_service:
        raise RSDProtocolError("wanted service must be a nonempty string")
    if not isinstance(value, dict) or set(value) - {
        "MessageType", "MessagingProtocolVersion", "Properties", "Services", "UUID"
    }:
        raise RSDProtocolError("unexpected top-level RSD directory shape")
    if value.get("MessageType") != "Handshake":
        raise RSDProtocolError("RSD directory is not a handshake")
    protocol_version = value.get("MessagingProtocolVersion")
    if protocol_version is not None and not isinstance(protocol_version, (Int64, UInt64)):
        raise RSDProtocolError("RSD messaging protocol version is malformed")
    if "Properties" in value and not isinstance(value["Properties"], dict):
        raise RSDProtocolError("RSD directory properties are malformed")
    if "UUID" in value and not isinstance(value["UUID"], uuid.UUID):
        raise RSDProtocolError("RSD directory UUID is malformed")
    services = value.get("Services")
    if not isinstance(services, dict) or len(services) > 4096:
        raise RSDProtocolError("RSD Services is missing, invalid, or oversized")
    service = services.get(wanted_service)
    if not isinstance(service, dict) or set(service) - {"Entitlement", "Port", "Properties"}:
        raise RSDProtocolError("wanted RSD service is absent or malformed")
    port = service.get("Port")
    if isinstance(port, UInt64):
        port_number = port.value
    elif isinstance(port, str) and port.isascii() and port.isdecimal() \
            and (port == "0" or not port.startswith("0")):
        port_number = int(port)
    else:
        raise RSDProtocolError("RSD service port is invalid")
    if not 1 <= port_number <= 65535:
        raise RSDProtocolError("RSD service port is invalid")
    properties = service.get("Properties", {})
    if not isinstance(properties, dict):
        raise RSDProtocolError("RSD service properties are malformed")
    entitlement = service.get("Entitlement")
    if entitlement is not None and not isinstance(entitlement, str):
        raise RSDProtocolError("RSD service entitlement is malformed")
    return port_number
