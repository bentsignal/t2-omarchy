#!/usr/bin/env python3
"""Offline codec for the recovered Intel BiometricKit BridgeXPC envelope.

This models the logical Foundation-object message and the BridgeXPC 39 record
framing verified in the installed macOS 26.6.2 x86_64 framework.  It does not
connect to a service or access a device.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import plistlib
import struct
from typing import TypeAlias


class BridgeProtocolError(ValueError):
    pass


BridgeAtom: TypeAlias = int | bool | bytes | str | None

GET_BRIDGE_VERSION = 0
GET_SERVICE_OPENED = 1
GET_SYSTEM_BOOT_TIME = 2
PERFORM_COMMAND = 3
SET_IOREGISTRY_PROPERTY = 4
CALIBRATION_DATA_FROM_EEPROM = 5
MACH_CONTINUOUS_TIME = 6
GET_MACH_TIMEBASE_INFO = 7
GET_OS_VERSION = 8
SET_BRIDGE_CLIENT_VERSION = 10
CALIBRATION_DATA_FROM_FDR = 11
SET_OS_TRANSACTION_RETAINED = 12

BIOMETRIC_REQUEST_MAGIC = 0x4D42
BIOMETRIC_REQUEST_HEADER = struct.Struct("<HHHH")
BRIDGE_FRAME_MAGIC = 0xB892
BRIDGE_PROTOCOL_VERSION = 1
BRIDGE_FRAME_HEADER = struct.Struct("<HHIQ")
FRAME_NOOP = 0
FRAME_HELO = 1
FRAME_MESSAGE = 2
T2_LINK_LOCAL_ADDRESS = "fe80::aede:48ff:fe33:4455"
BIOMETRIC_KIT_PORT = 52032


@dataclass(frozen=True)
class BiometricRequest:
    command: int
    version: int
    value: int
    payload: bytes


@dataclass(frozen=True)
class BridgeFrameHeader:
    kind: int
    body_size: int


def biometric_sockaddr(interface_index: int) -> tuple[str, int, int, int]:
    """Return the recovered IPv6 target tuple without creating a socket."""
    interface_index = _unsigned(interface_index, 32, "interface index")
    if interface_index == 0:
        raise BridgeProtocolError("a link-local endpoint requires an interface index")
    return T2_LINK_LOCAL_ADDRESS, BIOMETRIC_KIT_PORT, 0, interface_index


def _unsigned(value: int, bits: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BridgeProtocolError(f"{field} must be an integer")
    if not 0 <= value < 1 << bits:
        raise BridgeProtocolError(f"{field} does not fit in {bits} bits")
    return value


def _signed(value: int, bits: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BridgeProtocolError(f"{field} must be an integer")
    minimum, maximum = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if not minimum <= value <= maximum:
        raise BridgeProtocolError(f"{field} does not fit in {bits} signed bits")
    return value


def encode_biometric_request(command: int, version: int, value: int,
                             payload: bytes = b"") -> bytes:
    """Encode biometrickitd's exact 8-byte header followed by request bytes."""
    command = _unsigned(command, 16, "command")
    version = _unsigned(version, 16, "version")
    value = _unsigned(value, 16, "value")
    if not isinstance(payload, bytes):
        raise BridgeProtocolError("payload must be bytes")
    return BIOMETRIC_REQUEST_HEADER.pack(
        BIOMETRIC_REQUEST_MAGIC, command, version, value
    ) + payload


def decode_biometric_request(message: bytes, *, max_payload: int) -> BiometricRequest:
    """Decode an inner request fail-closed and enforce a caller-selected cap."""
    if not isinstance(message, bytes):
        raise BridgeProtocolError("message must be bytes")
    if not isinstance(max_payload, int) or isinstance(max_payload, bool) or max_payload < 0:
        raise BridgeProtocolError("max_payload must be a nonnegative integer")
    if len(message) < BIOMETRIC_REQUEST_HEADER.size:
        raise BridgeProtocolError("biometric request is shorter than its header")
    if len(message) - BIOMETRIC_REQUEST_HEADER.size > max_payload:
        raise BridgeProtocolError("biometric request exceeds the payload cap")
    magic, command, version, value = BIOMETRIC_REQUEST_HEADER.unpack_from(message)
    if magic != BIOMETRIC_REQUEST_MAGIC:
        raise BridgeProtocolError("invalid biometric request magic")
    return BiometricRequest(command, version, value,
                            message[BIOMETRIC_REQUEST_HEADER.size:])


def perform_command_request(command: int, payload: bytes | None,
                            output_capacity: int) -> tuple[BridgeAtom, ...]:
    """Build Bridge method 3: [method, command, NSData/BTNil, capacity]."""
    command = _unsigned(command, 32, "bridge command")
    output_capacity = _unsigned(output_capacity, 64, "output capacity")
    if payload is not None and not isinstance(payload, bytes):
        raise BridgeProtocolError("payload must be bytes or None")
    return (PERFORM_COMMAND, command, payload, output_capacity)


def biometric_perform_request(command: int, version: int, value: int,
                              payload: bytes = b"",
                              output_capacity: int = 0) -> tuple[BridgeAtom, ...]:
    """Wrap biometrickitd's inner request in its observed Bridge command 0."""
    inner = encode_biometric_request(command, version, value, payload)
    return perform_command_request(0, inner, output_capacity)


def encode_frame_header(kind: int, body_size: int) -> bytes:
    """Encode BridgeXPC's 16-byte little-endian TCP record header."""
    kind = _unsigned(kind, 32, "frame kind")
    if kind not in (FRAME_NOOP, FRAME_HELO, FRAME_MESSAGE):
        raise BridgeProtocolError("unsupported frame kind")
    body_size = _unsigned(body_size, 64, "body size")
    if kind == FRAME_NOOP and body_size:
        raise BridgeProtocolError("a no-op frame cannot carry a body")
    return BRIDGE_FRAME_HEADER.pack(
        BRIDGE_FRAME_MAGIC, BRIDGE_PROTOCOL_VERSION, kind, body_size
    )


def decode_frame_header(header: bytes, *, max_body: int) -> BridgeFrameHeader:
    """Validate a complete header before a caller reads its advertised body."""
    if not isinstance(header, bytes) or len(header) != BRIDGE_FRAME_HEADER.size:
        raise BridgeProtocolError("BridgeXPC frame header must be exactly 16 bytes")
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    magic, version, kind, body_size = BRIDGE_FRAME_HEADER.unpack(header)
    if magic != BRIDGE_FRAME_MAGIC:
        raise BridgeProtocolError("invalid BridgeXPC frame magic")
    if version != BRIDGE_PROTOCOL_VERSION:
        raise BridgeProtocolError("unsupported BridgeXPC protocol version")
    if kind not in (FRAME_NOOP, FRAME_HELO, FRAME_MESSAGE):
        raise BridgeProtocolError("unsupported frame kind")
    if kind == FRAME_NOOP and body_size:
        raise BridgeProtocolError("a no-op frame cannot carry a body")
    if body_size > max_body:
        raise BridgeProtocolError("BridgeXPC frame exceeds the body cap")
    return BridgeFrameHeader(kind, body_size)


def encode_perform_command_frame(request: tuple[BridgeAtom, ...],
                                 *, max_body: int) -> bytes:
    """Serialize a method-3 request as the binary-plist BridgeXPC message body."""
    if not isinstance(request, tuple) or len(request) != 4 or request[0] != PERFORM_COMMAND:
        raise BridgeProtocolError("request is not a method-3 BridgeXPC tuple")
    _, command, payload, capacity = request
    command = _unsigned(command, 32, "bridge command")
    capacity = _unsigned(capacity, 64, "output capacity")
    # The recovered biometric call always supplies NSData. BTNil's property-list
    # representation is not yet recovered, so refuse to guess it here.
    if not isinstance(payload, bytes):
        raise BridgeProtocolError("framed method-3 input must be bytes")
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    body = plistlib.dumps([PERFORM_COMMAND, command, payload, capacity],
                          fmt=plistlib.FMT_BINARY, sort_keys=False)
    if len(body) > max_body:
        raise BridgeProtocolError("serialized BridgeXPC message exceeds the body cap")
    return encode_frame_header(FRAME_MESSAGE, len(body)) + body


def encode_helo_frame(os_build: str, bridge_xpc_version: float,
                      process_name: str, *, max_body: int) -> bytes:
    """Encode the four-key HELO JSON observed in Catalina BridgeXPC 37."""
    if not isinstance(os_build, str) or not os_build:
        raise BridgeProtocolError("OS build must be a nonempty string")
    if (isinstance(bridge_xpc_version, bool)
            or not isinstance(bridge_xpc_version, (int, float))
            or not math.isfinite(bridge_xpc_version)
            or bridge_xpc_version < 0):
        raise BridgeProtocolError("BridgeXPC version must be finite and nonnegative")
    if not isinstance(process_name, str) or not process_name:
        raise BridgeProtocolError("process name must be a nonempty string")
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    body = json.dumps({
        "MaxSupportedProtocolVersion": BRIDGE_PROTOCOL_VERSION,
        "OSBuild": os_build,
        "BridgeXPCVersion": bridge_xpc_version,
        "ProcessName": process_name,
    }, separators=(",", ":")).encode("utf-8")
    if len(body) > max_body:
        raise BridgeProtocolError("serialized HELO exceeds the body cap")
    return encode_frame_header(FRAME_HELO, len(body)) + body


def decode_helo_body(body: bytes, *, max_body: int) -> dict[str, object]:
    """Strictly validate the four-key BridgeXPC HELO JSON object."""
    if not isinstance(body, bytes):
        raise BridgeProtocolError("HELO body must be bytes")
    if isinstance(max_body, bool) or not isinstance(max_body, int) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    if len(body) > max_body:
        raise BridgeProtocolError("HELO exceeds the body cap")
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise BridgeProtocolError("HELO contains a duplicate JSON key")
            result[key] = item
        return result

    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeProtocolError("HELO is not valid UTF-8 JSON") from error
    expected = {"MaxSupportedProtocolVersion", "OSBuild",
                "BridgeXPCVersion", "ProcessName"}
    if not isinstance(value, dict) or set(value) != expected:
        raise BridgeProtocolError("HELO does not have the exact expected keys")
    if (type(value["MaxSupportedProtocolVersion"]) is not int
            or value["MaxSupportedProtocolVersion"] != BRIDGE_PROTOCOL_VERSION):
        raise BridgeProtocolError("HELO protocol version is unsupported")
    for key, limit in (("OSBuild", 128), ("ProcessName", 256)):
        if (not isinstance(value[key], str) or not value[key]
                or len(value[key].encode("utf-8")) > limit or "\0" in value[key]):
            raise BridgeProtocolError(f"HELO {key} is invalid")
    version = value["BridgeXPCVersion"]
    if (isinstance(version, bool) or not isinstance(version, (int, float))
            or not math.isfinite(version) or version < 0):
        raise BridgeProtocolError("HELO BridgeXPCVersion is invalid")
    return value


def encode_bridge_version_query_frame(*, max_body: int) -> bytes:
    """Encode the passive BiometricKit bridge-version request [0]."""
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    body = plistlib.dumps([GET_BRIDGE_VERSION], fmt=plistlib.FMT_BINARY,
                          sort_keys=False)
    if len(body) > max_body:
        raise BridgeProtocolError("serialized bridge-version query exceeds the body cap")
    return encode_frame_header(FRAME_MESSAGE, len(body)) + body


def encode_service_opened_query_frame(*, max_body: int) -> bytes:
    """Encode current BiometricKit bridge method 1's read-only query."""
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    body = plistlib.dumps([GET_SERVICE_OPENED], fmt=plistlib.FMT_BINARY,
                          sort_keys=False)
    if len(body) > max_body:
        raise BridgeProtocolError("serialized service-opened query exceeds the body cap")
    return encode_frame_header(FRAME_MESSAGE, len(body)) + body


def decode_bridge_version_reply_body(body: bytes, *, max_body: int) -> tuple[int, int]:
    """Validate method 0's exact [int32 status, uint64 version] reply."""
    if not isinstance(body, bytes):
        raise BridgeProtocolError("reply body must be bytes")
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    if len(body) > max_body:
        raise BridgeProtocolError("bridge-version reply exceeds the body cap")
    try:
        reply = plistlib.loads(body)
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise BridgeProtocolError("bridge-version reply is not a property list") from error
    if not isinstance(reply, list) or len(reply) != 2:
        raise BridgeProtocolError("bridge-version reply must contain two objects")
    return _signed(reply[0], 32, "status"), _unsigned(reply[1], 64, "version")


def decode_service_opened_reply_body(body: bytes, *, max_body: int) -> tuple[int, bool]:
    """Validate current method 1's exact [int32 status, bool opened] reply."""
    if not isinstance(body, bytes):
        raise BridgeProtocolError("reply body must be bytes")
    if not isinstance(max_body, int) or isinstance(max_body, bool) or max_body < 0:
        raise BridgeProtocolError("max_body must be a nonnegative integer")
    if len(body) > max_body:
        raise BridgeProtocolError("service-opened reply exceeds the body cap")
    try:
        reply = plistlib.loads(body)
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise BridgeProtocolError("service-opened reply is not a property list") from error
    if not isinstance(reply, list) or len(reply) != 2:
        raise BridgeProtocolError("service-opened reply must contain two objects")
    status = _signed(reply[0], 32, "status")
    if type(reply[1]) is not bool:
        raise BridgeProtocolError("service-opened state must be boolean")
    return status, reply[1]


def decode_perform_command_reply(reply: tuple[BridgeAtom, ...],
                                 *, max_output: int) -> tuple[int, bytes | None]:
    """Validate method 3's observed [status NSNumber, data/BTNil] reply."""
    if not isinstance(reply, tuple) or len(reply) != 2:
        raise BridgeProtocolError("perform-command reply must contain two objects")
    status, output = reply
    status = _signed(status, 32, "status")
    if output is not None and not isinstance(output, bytes):
        raise BridgeProtocolError("reply output must be bytes or None")
    if not isinstance(max_output, int) or isinstance(max_output, bool) or max_output < 0:
        raise BridgeProtocolError("max_output must be a nonnegative integer")
    if output is not None and len(output) > max_output:
        raise BridgeProtocolError("reply output exceeds the caller's cap")
    return status, output
