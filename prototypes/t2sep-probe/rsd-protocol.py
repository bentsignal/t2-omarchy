#!/usr/bin/env python3
"""Strict offline codec for the candidate modern remoted/RSD directory path.

Nothing in this module opens a socket.  Port 58783 and this RemoteXPC framing
are recovered from independent open implementations of Apple's modern RSD
protocol, but have not yet been verified against this Mac's T2 bridgeOS.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
import uuid
from typing import Any


class RSDProtocolError(ValueError):
    pass


RSD_PORT_CANDIDATE = 58783
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_DATA = 0
HTTP2_HEADERS = 1
HTTP2_SETTINGS = 4
HTTP2_WINDOW_UPDATE = 8
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


def candidate_rsd_handshake(client_uuid: uuid.UUID) -> bytes:
    """Build the offline modern RSD client preface; never connect or send it."""
    if not isinstance(client_uuid, uuid.UUID):
        raise RSDProtocolError("client_uuid must be a UUID")
    settings = struct.pack(">HIHI", 3, 100, 4, 16 * 1024 * 1024)
    empty = encode_xpc_message({}, message_id=0)
    terminator = encode_xpc_message(
        None, message_id=0, flags=XPC_ALWAYS_SET | XPC_CHANNEL_TERMINATOR
    )
    init = encode_xpc_message(None, message_id=0,
                              flags=XPC_ALWAYS_SET | XPC_INIT_HANDSHAKE)
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
        encode_http2_frame(HTTP2_DATA, 0, ROOT_CHANNEL, handshake),
    ))


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
