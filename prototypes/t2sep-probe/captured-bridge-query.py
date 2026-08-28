#!/usr/bin/env python3
"""Read-only BridgeXPC version query derived from a validated RSD capture.

Default execution validates a private capture and prints no private bytes.
Live execution is source-gated and has no caller-controlled address or port.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import plistlib
import socket
import struct
import sys


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(filename))
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rsd_query = _load("captured_bridge_rsd_query", "rsd-query.py")
rsd = rsd_query.protocol
bridge_query = _load("captured_bridge_query_transport", "bridge-query.py")

CAPTURE_CAP = 1024 * 1024
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_THE_T2_BRIDGE_VERSION"
LIVE_CAPTURED_BRIDGE_QUERY_ENABLED = False
CHECKIN_CAP = 64 * 1024


class CapturedBridgeError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise CapturedBridgeError("peer closed during RSD check-in")
        result += chunk
    return bytes(result)


def _recv_prefixed_plist(sock: socket.socket, prefix: bytes | None = None) -> dict:
    prefix = _recv_exact(sock, 4) if prefix is None else prefix
    if not isinstance(prefix, bytes) or len(prefix) != 4:
        raise CapturedBridgeError("RSD check-in prefix is invalid")
    size = struct.unpack(">I", prefix)[0]
    if not 1 <= size <= CHECKIN_CAP:
        raise CapturedBridgeError(
            f"RSD check-in plist size is invalid (prefix={prefix.hex()})")
    try:
        value = plistlib.loads(_recv_exact(sock, size))
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise CapturedBridgeError("RSD check-in reply is not a plist") from error
    if not isinstance(value, dict):
        raise CapturedBridgeError("RSD check-in reply is not a dictionary")
    return value


def perform_rsd_checkin(sock: socket.socket) -> dict | None:
    """Perform only the check-in required by UsesRemoteXPC=false services."""
    request = {
        "Label": "biometrickitd",
        "ProtocolVersion": "2",
        "Request": "RSDCheckin",
    }
    payload = plistlib.dumps(request, fmt=plistlib.FMT_XML, sort_keys=False)
    if len(payload) > CHECKIN_CAP:
        raise CapturedBridgeError("RSD check-in request exceeds its cap")
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    prefix = _recv_exact(sock, 4)
    bridge_prefix = struct.pack(
        "<HH", bridge_query.protocol.BRIDGE_FRAME_MAGIC,
        bridge_query.protocol.BRIDGE_PROTOCOL_VERSION)
    if prefix == bridge_prefix:
        header_bytes = prefix + _recv_exact(
            sock, bridge_query.protocol.BRIDGE_FRAME_HEADER.size - len(prefix))
        try:
            header = bridge_query.protocol.decode_frame_header(
                header_bytes, max_body=bridge_query.BODY_CAP)
            if header.kind != bridge_query.protocol.FRAME_HELO:
                raise CapturedBridgeError(
                    "checked-in service emitted a non-HELO BridgeXPC frame")
            body = _recv_exact(sock, header.body_size)
            peer_helo = bridge_query.protocol.decode_helo_body(
                body, max_body=bridge_query.BODY_CAP)
        except bridge_query.protocol.BridgeProtocolError as error:
            raise CapturedBridgeError(
                "checked-in service emitted an invalid BridgeXPC HELO") from error
        return peer_helo
    first = _recv_prefixed_plist(sock, prefix)
    if first.get("Request") != "RSDCheckin" or first.get("Error") is not None:
        raise CapturedBridgeError("peer rejected RSD check-in")
    second = _recv_prefixed_plist(sock)
    if second.get("Request") != "StartService" or second.get("Error") is not None:
        raise CapturedBridgeError("peer did not start the checked-in service")
    return None


def receive_server_first_helo(sock: socket.socket) -> dict:
    """Receive the HELO that current bkremoted emits immediately on accept."""
    try:
        header, body = bridge_query.recv_frame(sock)
        if header.kind != bridge_query.protocol.FRAME_HELO:
            raise CapturedBridgeError("BiometricKit did not begin with a HELO")
        return bridge_query.protocol.decode_helo_body(
            body, max_body=bridge_query.BODY_CAP)
    except bridge_query.protocol.BridgeProtocolError as error:
        raise CapturedBridgeError("BiometricKit server-first HELO is invalid") from error


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CapturedBridgeError("capture JSON contains a duplicate key")
        result[key] = value
    return result


def validate_capture(path: Path) -> tuple[int, bytes]:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise CapturedBridgeError("capture must be one regular non-symlink file")
    if path.stat().st_mode & 0o077:
        raise CapturedBridgeError("capture permissions expose private evidence")
    raw_json = path.read_bytes()
    if len(raw_json) > CAPTURE_CAP:
        raise CapturedBridgeError("capture file exceeds its size cap")
    try:
        payload = json.loads(raw_json, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapturedBridgeError("capture is not strict JSON") from error
    expected = {"advertised_port", "server_transcript_hex",
                "server_transcript_sha256", "validation_error"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise CapturedBridgeError("capture has unexpected fields")
    if payload["validation_error"] is not None:
        raise CapturedBridgeError("capture did not pass its original validation")
    try:
        transcript = bytes.fromhex(payload["server_transcript_hex"])
    except (TypeError, ValueError) as error:
        raise CapturedBridgeError("capture transcript is not hexadecimal") from error
    digest = hashlib.sha256(transcript).hexdigest()
    if payload["server_transcript_sha256"] != digest:
        raise CapturedBridgeError("capture transcript checksum does not match")
    parser = rsd.PassiveRSDTranscript(
        wanted_service=rsd_query.BIOMETRIC_SERVICE,
        max_frame=rsd_query.FRAME_CAP,
        max_frames=rsd_query.FRAME_LIMIT,
        max_total=rsd_query.TOTAL_CAP,
        max_xpc_body=rsd_query.FRAME_CAP,
    )
    try:
        parser.feed(transcript)
        port = parser.finish()
    except rsd.RSDProtocolError as error:
        raise CapturedBridgeError("capture transcript failed independent validation") from error
    if payload["advertised_port"] != port:
        raise CapturedBridgeError("capture port disagrees with its transcript")
    return port, transcript


def live_query(capture_path: Path, interface: str, timeout: float) -> tuple[int, int]:
    if not LIVE_CAPTURED_BRIDGE_QUERY_ENABLED:
        raise CapturedBridgeError("live captured BridgeXPC query is disabled in source")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise CapturedBridgeError("timeout must be finite, positive, and at most five seconds")
    port, _ = validate_capture(capture_path)
    try:
        ifindex = rsd_query.verify_t2_interface(interface)
        target = rsd.observed_rsd_sockaddr(ifindex, port)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(target)
            receive_server_first_helo(sock)
            return bridge_query.query_connected_socket(sock)
    except (OSError, rsd_query.QueryError, bridge_query.QueryError) as error:
        raise CapturedBridgeError("bounded BridgeXPC version query failed") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    port, transcript = validate_capture(args.capture)
    if not args.live:
        print(f"offline validated BiometricKit endpoint port={port} "
              f"transcript_sha256={hashlib.sha256(transcript).hexdigest()}")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    status, version = live_query(args.capture, args.interface, args.timeout)
    print(f"bridge status={status} version={version}")


if __name__ == "__main__":
    main()
