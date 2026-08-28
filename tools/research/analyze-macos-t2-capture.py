#!/usr/bin/env python3
"""Bounded, offline summary of capture-live-macos-t2.sh output."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import struct
from typing import Any


MAX_PCAP_BYTES = 128 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_PACKETS = 1_000_000
INTERESTING_PORTS = {52032, 58783}
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


class CaptureError(ValueError):
    pass


def _regular_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise CaptureError(f"not a regular capture file: {path.name}")
    size = path.stat().st_size
    if size > maximum:
        raise CaptureError(f"capture file exceeds {maximum} bytes: {path.name}")
    return path.read_bytes()


def _tcp_flags(value: int) -> list[str]:
    names = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
             (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
             (0x40, "ECE"), (0x80, "CWR"))
    return [name for bit, name in names if value & bit]


def _decode_ethernet_ipv6(packet: bytes) -> dict[str, Any] | None:
    if len(packet) < 14 or packet[12:14] != b"\x86\xdd":
        return None
    frame = packet[14:]
    if len(frame) < 40 or frame[0] >> 4 != 6:
        return None
    payload_length = int.from_bytes(frame[4:6], "big")
    if len(frame) < 40 + payload_length:
        return None
    next_header = frame[6]
    offset = 40
    # Walk only bounded, length-explicit IPv6 extension headers.
    for _ in range(8):
        if next_header not in {0, 43, 60}:
            break
        if offset + 2 > len(frame):
            return None
        header_length = (frame[offset + 1] + 1) * 8
        if offset + header_length > len(frame):
            return None
        next_header = frame[offset]
        offset += header_length
    result: dict[str, Any] = {
        "ethernet_source": ":".join(f"{byte:02x}" for byte in packet[6:12]),
        "ipv6_source": str(ipaddress.IPv6Address(frame[8:24])),
        "ipv6_destination": str(ipaddress.IPv6Address(frame[24:40])),
        "next_header": next_header,
    }
    if next_header in {6, 17} and offset + 4 <= len(frame):
        source_port, destination_port = struct.unpack_from("!HH", frame, offset)
        result.update(source_port=source_port, destination_port=destination_port)
        if next_header == 6 and offset + 14 <= len(frame):
            result["tcp_flags"] = _tcp_flags(frame[offset + 13])
    elif next_header == 58 and offset < len(frame):
        result["icmpv6_type"] = frame[offset]
    return result


def summarize_pcap(path: Path) -> dict[str, Any]:
    data = _regular_file(path, maximum=MAX_PCAP_BYTES)
    if len(data) < 24 or data[:4] not in PCAP_MAGICS:
        raise CaptureError(f"unsupported or truncated pcap: {path.name}")
    endian = PCAP_MAGICS[data[:4]]
    _, _, _, _, snaplen, network = struct.unpack_from(endian + "HHIIII", data, 4)
    if snaplen == 0 or network != 1:
        raise CaptureError(f"pcap must use Ethernet link type: {path.name}")
    offset = 24
    packets = 0
    decoded: list[dict[str, Any]] = []
    while offset < len(data):
        if packets >= MAX_PACKETS or offset + 16 > len(data):
            raise CaptureError(f"invalid or excessive packet records: {path.name}")
        _, _, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if included > snaplen or included > original or offset + included > len(data):
            raise CaptureError(f"invalid packet length: {path.name}")
        item = _decode_ethernet_ipv6(data[offset:offset + included])
        if item is not None:
            item["packet_index"] = packets
            decoded.append(item)
        offset += included
        packets += 1
    endpoints = sorted({
        (item["ipv6_source"], item["source_port"],
         item["ipv6_destination"], item["destination_port"])
        for item in decoded
        if item.get("source_port") in INTERESTING_PORTS
        or item.get("destination_port") in INTERESTING_PORTS
    })
    return {
        "file": path.name,
        "packet_count": packets,
        "ipv6_packet_count": len(decoded),
        "ethernet_sources": sorted({item["ethernet_source"] for item in decoded}),
        "ipv6_sources": sorted({item["ipv6_source"] for item in decoded}),
        "interesting_flows": [
            {"source": source, "source_port": source_port,
             "destination": destination, "destination_port": destination_port}
            for source, source_port, destination, destination_port in endpoints
        ],
        "tcp_resets": sum("RST" in item.get("tcp_flags", []) for item in decoded),
    }


def _matching_lines(path: Path, needles: tuple[str, ...], *, limit: int = 200) -> list[str]:
    if not path.exists():
        return []
    data = _regular_file(path, maximum=MAX_TEXT_BYTES)
    text = data.decode("utf-8", errors="replace")
    matches = [line for line in text.splitlines()
               if any(needle.casefold() in line.casefold() for needle in needles)]
    return matches[:limit]


def analyze(directory: Path) -> dict[str, Any]:
    if directory.is_symlink() or not directory.is_dir():
        raise CaptureError("capture path must be a directory, not a symlink")
    pcaps = sorted(directory.glob("*.pcap"))
    if len(pcaps) > 32:
        raise CaptureError("capture contains too many pcap files")
    listener_files = ("tcp-listeners-before.txt", "tcp-listeners-after.txt",
                      "tcp-processes-before.txt", "tcp-processes-after.txt")
    return {
        "capture_directory": str(directory),
        "pcaps": [summarize_pcap(path) for path in pcaps],
        "interesting_listener_lines": {
            name: _matching_lines(directory / name, ("52032", "58783"))
            for name in listener_files
        },
        "activation_log_lines": _matching_lines(
            directory / "unified-log.ndjson",
            ("biometric", "remote", "52032", "58783", "bridge")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_directory", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.capture_directory)
    except (CaptureError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
