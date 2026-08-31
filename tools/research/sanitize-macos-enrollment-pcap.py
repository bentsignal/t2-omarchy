#!/usr/bin/env python3
"""Emit a credential-free BridgeXPC transcript from private macOS T2 pcaps."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import plistlib
import struct
from typing import Any


MAX_PCAP_BYTES = 256 * 1024 * 1024
MAX_PACKETS = 2_000_000
MAX_FRAME_BODY = 16 * 1024 * 1024
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
BRIDGE_HEADER = struct.Struct("<HHIQ")
BIOMETRIC_HEADER = struct.Struct("<HHHH")
BRIDGE_MAGIC = 0xB892
BIOMETRIC_MAGIC = 0x4D42
NIL_OUTPUT_SENTINEL = "d4161201-daf5-4bbd-ae4f-9bf319fabbe0"


class SanitizerError(ValueError):
    pass


def _regular_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SanitizerError("capture input must be a regular non-symlink file")
    size = path.stat().st_size
    if not 24 <= size <= MAX_PCAP_BYTES:
        raise SanitizerError("capture input is outside the bounded pcap size")
    return path.read_bytes()


def _ipv6_tcp(packet: bytes, network: int) -> tuple[
    tuple[str, int, str, int], int, bytes
] | None:
    if network == 1:
        if len(packet) < 14 or packet[12:14] != b"\x86\xdd":
            return None
        frame = packet[14:]
    else:
        frame = packet
    if len(frame) < 40 or frame[0] >> 4 != 6:
        return None
    payload_length = int.from_bytes(frame[4:6], "big")
    if len(frame) < 40 + payload_length:
        return None
    next_header = frame[6]
    offset = 40
    for _ in range(8):
        if next_header not in {0, 43, 60}:
            break
        if offset + 2 > 40 + payload_length:
            return None
        extension_size = (frame[offset + 1] + 1) * 8
        if offset + extension_size > 40 + payload_length:
            return None
        next_header = frame[offset]
        offset += extension_size
    if next_header != 6 or offset + 20 > 40 + payload_length:
        return None
    source_port, destination_port, sequence = struct.unpack_from("!HHI", frame, offset)
    tcp_size = (frame[offset + 12] >> 4) * 4
    if tcp_size < 20 or offset + tcp_size > 40 + payload_length:
        return None
    source = str(ipaddress.IPv6Address(frame[8:24]))
    destination = str(ipaddress.IPv6Address(frame[24:40]))
    payload = frame[offset + tcp_size : 40 + payload_length]
    return (source, source_port, destination, destination_port), sequence, payload


def _pcap_streams(path: Path) -> dict[tuple[str, int, str, int], list[tuple[int, bytes]]]:
    data = _regular_file(path)
    if data[:4] not in PCAP_MAGICS:
        raise SanitizerError("capture input has an unsupported pcap header")
    endian = PCAP_MAGICS[data[:4]]
    _, _, _, _, snaplen, network = struct.unpack_from(endian + "HHIIII", data, 4)
    if snaplen == 0 or network not in {1, 12, 101}:
        raise SanitizerError("capture must use Ethernet or raw IPv6 packets")
    streams: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = {}
    offset = 24
    packet_count = 0
    while offset < len(data):
        if packet_count >= MAX_PACKETS or offset + 16 > len(data):
            raise SanitizerError("capture has invalid or excessive packet records")
        _, _, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if included > snaplen or included > original or offset + included > len(data):
            raise SanitizerError("capture contains an invalid packet length")
        decoded = _ipv6_tcp(data[offset : offset + included], network)
        offset += included
        packet_count += 1
        if decoded is None:
            continue
        key, sequence, payload = decoded
        if payload:
            streams.setdefault(key, []).append((sequence, payload))
    return streams


def _reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    ordered = sorted(segments, key=lambda item: item[0])
    if not ordered:
        return b""
    base = ordered[0][0]
    result = bytearray()
    for sequence, payload in ordered:
        relative = sequence - base
        if relative < 0:
            raise SanitizerError("TCP sequence wrap is unsupported in bounded capture")
        if relative > len(result):
            raise SanitizerError("TCP stream contains a capture gap")
        overlap = len(result) - relative
        compared = min(overlap, len(payload))
        if compared and result[relative : relative + compared] != payload[:compared]:
            raise SanitizerError("TCP retransmission disagrees with captured bytes")
        if compared < len(payload):
            result.extend(payload[compared:])
    return bytes(result)


def _bridge_frames(stream: bytes) -> list[tuple[int, bytes]]:
    marker = struct.pack("<HH", BRIDGE_MAGIC, 1)
    best: list[tuple[int, bytes]] = []
    search = 0
    while True:
        start = stream.find(marker, search)
        if start < 0:
            break
        offset = start
        frames: list[tuple[int, bytes]] = []
        while offset + BRIDGE_HEADER.size <= len(stream):
            magic, version, kind, body_size = BRIDGE_HEADER.unpack_from(stream, offset)
            if (
                magic != BRIDGE_MAGIC
                or version != 1
                or kind not in (0, 1, 2)
                or body_size > MAX_FRAME_BODY
            ):
                break
            end = offset + BRIDGE_HEADER.size + body_size
            if end > len(stream):
                break
            frames.append((kind, stream[offset + BRIDGE_HEADER.size : end]))
            offset = end
        if len(frames) > len(best):
            best = frames
        search = start + 1
    return best


def _helo_role(frames: list[tuple[int, bytes]]) -> str | None:
    for kind, body in frames:
        if kind != 1:
            continue
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if type(value) is dict and value.get("ProcessName") == "bkremoted":
            return "t2"
        if type(value) is dict and isinstance(value.get("ProcessName"), str):
            return "host"
    return None


def _output_shape(value: object) -> dict[str, object]:
    if value is None or value == NIL_OUTPUT_SENTINEL:
        return {"output_kind": "nil", "output_length": 0}
    if type(value) is bytes:
        return {"output_kind": "data", "output_length": len(value)}
    if type(value) in (int, bool):
        return {"output_kind": type(value).__name__, "output_length": 0}
    return {"output_kind": "other-redacted", "output_length": 0}


def _enrollment_shape(payload: bytes) -> dict[str, object]:
    if len(payload) not in (48, 68):
        return {"shape_valid": False}
    flags, user_id, using_token, token_length = struct.unpack_from("<4I", payload)
    credential = payload[16:48]
    result: dict[str, object] = {
        "shape_valid": token_length <= len(credential),
        "flags": flags,
        "user_id": user_id,
        "using_auth_token": using_token,
        "token_length": token_length,
        "credential_present": any(credential[:token_length]),
        "credential_padding_zero": not any(credential[token_length:]),
        "request_generation": 1 if len(payload) == 48 else 2,
    }
    if len(payload) == 68:
        group_type = struct.unpack_from("<I", payload, 48)[0]
        result.update(
            group_type=group_type,
            group_uuid_zero=not any(payload[52:68]),
        )
    return result


def _protected_config_shape(payload: bytes) -> dict[str, object]:
    if len(payload) != 60:
        return {"shape_valid": False}
    words = struct.unpack_from("<7I", payload)
    credential = payload[28:60]
    token_length = words[6]
    return {
        "shape_valid": token_length <= len(credential),
        "user_id": words[0],
        "policy": list(words[1:5]),
        "using_auth_token": words[5],
        "token_length": token_length,
        "credential_present": any(credential[:token_length]),
        "credential_padding_zero": not any(credential[token_length:]),
    }


def _command_summary(message: object) -> dict[str, object] | None:
    if type(message) is not list or not message:
        return None
    method = message[0]
    if type(method) is not int:
        return None
    if method != 3:
        summary: dict[str, object] = {"bridge_method": method}
        if method == 10 and len(message) == 2 and type(message[1]) is int:
            summary["client_version"] = message[1]
        return summary
    if (
        len(message) != 4
        or message[1] != 0
        or type(message[2]) is not bytes
        or type(message[3]) is not int
        or len(message[2]) < BIOMETRIC_HEADER.size
    ):
        return {"bridge_method": 3, "shape_valid": False}
    magic, command, version, value = BIOMETRIC_HEADER.unpack_from(message[2])
    payload = message[2][BIOMETRIC_HEADER.size :]
    summary = {
        "bridge_method": 3,
        "shape_valid": magic == BIOMETRIC_MAGIC,
        "command": f"0x{command:02x}",
        "version": version,
        "value": value,
        "input_length": len(payload),
        "output_capacity": message[3],
    }
    if command == 0x03:
        summary["enrollment"] = _enrollment_shape(payload)
    elif command == 0x2F:
        summary["protected_config"] = _protected_config_shape(payload)
    elif command in (0x2E, 0x31) and len(payload) == 4:
        summary["user_id"] = struct.unpack("<I", payload)[0]
    return summary


def _event_summary(message: object) -> dict[str, object] | None:
    if (
        type(message) is not list
        or len(message) != 5
        or message[0] != 9
        or type(message[1]) is not int
        or type(message[2]) is not bytes
        or len(message[2]) < 24
    ):
        return None
    reserved, event_type, version, timestamp = struct.unpack_from(
        "<QIIQ", message[2]
    )
    if reserved != 0 or timestamp == 0:
        return None
    payload = message[2][24:]
    ordinal = 0
    if event_type == 0xE3FF8001 and len(payload) >= 4:
        ordinal = struct.unpack_from("<I", payload)[0]
    return {
        "type": f"0x{event_type:08x}",
        "version": version,
        "ordinal": ordinal,
        "payload_length": len(payload),
    }


def _messages(frames: list[tuple[int, bytes]]) -> list[object]:
    result: list[object] = []
    for kind, body in frames:
        if kind != 2:
            continue
        try:
            value = plistlib.loads(body)
        except (plistlib.InvalidFileException, ValueError, TypeError):
            continue
        result.append(value)
    return result


def sanitize(path: Path) -> dict[str, object]:
    directed = {
        key: _bridge_frames(_reassemble(segments))
        for key, segments in _pcap_streams(path).items()
    }
    directed = {key: frames for key, frames in directed.items() if frames}
    connections: dict[frozenset[tuple[str, int]], dict[str, list[tuple[int, bytes]]]] = {}
    for key, frames in directed.items():
        source = (key[0], key[1])
        destination = (key[2], key[3])
        connection = connections.setdefault(frozenset((source, destination)), {})
        role = _helo_role(frames)
        if role is not None:
            connection[role] = frames

    sanitized_connections: list[dict[str, object]] = []
    for connection in connections.values():
        if "host" not in connection or "t2" not in connection:
            continue
        host_messages = _messages(connection["host"])
        t2_messages = _messages(connection["t2"])
        replies: dict[str, object] = {}
        events: list[dict[str, object]] = []
        for envelope in t2_messages:
            if type(envelope) is not list or len(envelope) != 4 or envelope[0] != 1:
                continue
            if envelope[1] is True and type(envelope[2]) is str:
                replies[envelope[2]] = envelope[3]
            elif envelope[1] is False:
                event = _event_summary(envelope[3])
                if event is not None:
                    events.append(event)
        commands: list[dict[str, object]] = []
        for envelope in host_messages:
            if (
                type(envelope) is not list
                or len(envelope) != 4
                or envelope[0] != 1
                or envelope[1] is not False
                or type(envelope[2]) is not str
            ):
                continue
            summary = _command_summary(envelope[3])
            if summary is None:
                continue
            reply = replies.get(envelope[2])
            if type(reply) is list and reply and type(reply[0]) is int:
                summary["reply_status"] = reply[0]
                if len(reply) == 1:
                    summary.update(output_kind="nil", output_length=0)
                elif len(reply) == 2:
                    summary.update(_output_shape(reply[1]))
            else:
                summary["reply_observed"] = False
            commands.append(summary)
        if commands or events:
            sanitized_connections.append(
                {
                    "commands": commands,
                    "service_events": events,
                }
            )
    return {
        "schema_version": 1,
        "identifiers_redacted": True,
        "raw_payloads_retained": False,
        "connection_count": len(sanitized_connections),
        "connections": sanitized_connections,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    args = parser.parse_args()
    try:
        result = sanitize(args.pcap)
    except (OSError, SanitizerError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
