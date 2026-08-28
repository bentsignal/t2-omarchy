#!/usr/bin/env python3
"""Hard-gated passive RSD directory query for the internal T2 link.

Default execution prints deterministic offline fixtures. Live execution is
mechanically disabled pending a supervised Linux run. The verified installed
Intel Multiverse path supplies the T2 directory port; the only request here is
the RemoteXPC service-directory handshake.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import importlib.util
import math
from pathlib import Path
import socket
import sys
import uuid


MODULE_PATH = Path(__file__).with_name("rsd-protocol.py")
SPEC = importlib.util.spec_from_file_location("rsd_protocol", MODULE_PATH)
assert SPEC and SPEC.loader
protocol = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol
SPEC.loader.exec_module(protocol)

BIOMETRIC_SERVICE = "com.apple.eos.BiometricKit"
FRAME_CAP = 64 * 1024
FRAME_LIMIT = 16
TOTAL_CAP = 256 * 1024
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_READS_THE_T2_RSD_DIRECTORY"
# The installed x86_64 remoted slice (SHA-256 88e78e65...4056) uniquely loads
# 0xe8d2 before RSDRemoteMultiverseHostDevice::needsConnect calls
# multiverse_device_connect. The macOS boot trace independently observed the
# same T2 directory port. Port 58783 belongs to a different NCM device role.
SAME_BOOT_DIRECTORY_PORT_VERIFICATION = (
    59602,
    "installed Intel remoted Multiverse connect sequence plus macOS boot trace",
)
# A supervised post-rebind Ethernet capture proves bridgeOS source MAC
# ac:de:48:33:44:55 and source IPv6 fe80::aede:48ff:fe33:4455 directly.
CURRENT_T2_ADDRESS_VERIFICATION = (
    protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE,
    "supervised bridgeOS MLDv2 source address observed on the T2 NCM wire",
)
# Deliberately remains false until a supervised passive-directory experiment.
LIVE_DIRECTORY_CAPTURE_ENABLED = False


class QueryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PassiveDirectoryCapture:
    advertised_port: int
    server_transcript: bytes


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise QueryError("peer closed during an RSD frame")
        if not isinstance(chunk, bytes):
            raise QueryError("socket returned a non-bytes value")
        chunks += chunk
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 9)
    length = int.from_bytes(header[:3], "big")
    if length > FRAME_CAP:
        raise QueryError("peer advertised an oversized RSD frame")
    frame = header + recv_exact(sock, length)
    try:
        protocol.decode_http2_frame(frame, max_payload=FRAME_CAP)
    except protocol.RSDProtocolError as error:
        raise QueryError("peer sent a malformed RSD frame") from error
    return frame


def capture_connected_socket(sock: socket.socket,
                             client_uuid: uuid.UUID) -> PassiveDirectoryCapture:
    """Return the validated port and exact bounded server transcript."""
    if not isinstance(client_uuid, uuid.UUID):
        raise QueryError("client UUID must be a UUID")
    parser = protocol.PassiveRSDTranscript(
        wanted_service=BIOMETRIC_SERVICE,
        max_frame=FRAME_CAP,
        max_frames=FRAME_LIMIT,
        max_total=TOTAL_CAP,
        max_xpc_body=FRAME_CAP,
    )
    transcript = bytearray()
    sock.sendall(protocol.candidate_rsd_transport_opening())
    handshake_sent = False
    for _ in range(FRAME_LIMIT):
        try:
            frame = recv_frame(sock)
            transcript += frame
            parser.feed(frame)
        except protocol.RSDProtocolError as error:
            raise QueryError("peer RSD transcript failed validation") from error
        if parser.peer_settings_seen and not handshake_sent:
            sock.sendall(protocol.candidate_rsd_settings_ack())
            sock.sendall(protocol.candidate_rsd_device_handshake(client_uuid))
            handshake_sent = True
        if parser.complete:
            try:
                return PassiveDirectoryCapture(parser.finish(), bytes(transcript))
            except protocol.RSDProtocolError as error:
                raise QueryError("peer RSD directory failed final validation") from error
    raise QueryError("no RSD directory within the frame limit")


def query_connected_socket(sock: socket.socket,
                           client_uuid: uuid.UUID) -> int:
    """Compatibility wrapper returning only the validated advertised port."""
    return capture_connected_socket(sock, client_uuid).advertised_port


def _read_sysfs(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError as error:
        raise QueryError(f"cannot read {path}") from error


def verify_t2_interface(name: str) -> int:
    if (not isinstance(name, str) or not name
            or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
                   for character in name)):
        raise QueryError("network interface name is invalid")
    base = Path("/sys/class/net") / name
    try:
        resolved = base.resolve(strict=True)
    except OSError as error:
        raise QueryError(f"network interface {name!r} does not exist") from error
    usb = resolved
    while usb != usb.parent and not (usb / "idVendor").exists():
        usb = usb.parent
    if (_read_sysfs(usb / "idVendor"), _read_sysfs(usb / "idProduct")) != ("05ac", "8233"):
        raise QueryError("interface is not the Apple T2 Controller 05ac:8233")
    if _read_sysfs(base / "carrier") != "1":
        raise QueryError("T2 NCM interface has no carrier")
    if "0000:04:00.1" not in str(resolved):
        raise QueryError("interface does not descend from the expected T2 bridge PCI function")
    return socket.if_nametoindex(name)


def live_capture(interface: str, timeout: float) -> PassiveDirectoryCapture:
    if not LIVE_DIRECTORY_CAPTURE_ENABLED:
        raise QueryError("live RSD query disabled: supervised capture not enabled")
    address_verification = CURRENT_T2_ADDRESS_VERIFICATION
    port_verification = SAME_BOOT_DIRECTORY_PORT_VERIFICATION
    if (not isinstance(address_verification, tuple) or len(address_verification) != 2
            or address_verification[0] != protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE
            or not isinstance(address_verification[1], str) or not address_verification[1]
            or not isinstance(port_verification, tuple) or len(port_verification) != 2
            or isinstance(port_verification[0], bool)
            or not isinstance(port_verification[0], int)
            or not 1 <= port_verification[0] <= 65535
            or not isinstance(port_verification[1], str) or not port_verification[1]):
        raise QueryError("live RSD query disabled: malformed endpoint verification")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise QueryError("timeout must be finite, positive, and no more than five seconds")
    ifindex = verify_t2_interface(interface)
    target = protocol.observed_rsd_sockaddr(ifindex, port_verification[0])
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(target)
        return capture_connected_socket(sock, uuid.uuid4())


def live_query(interface: str, timeout: float) -> int:
    """Compatibility wrapper returning only the live advertised port."""
    return live_capture(interface, timeout).advertised_port


def main() -> None:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--live", action="store_true")
    argument_parser.add_argument("--interface", default="enp4s0f1u1")
    argument_parser.add_argument("--timeout", type=float, default=2.0)
    argument_parser.add_argument("--confirm", default="")
    args = argument_parser.parse_args()

    if not args.live:
        identifier = uuid.UUID(int=0)
        opening = protocol.candidate_rsd_transport_opening()
        acknowledgment = protocol.candidate_rsd_settings_ack()
        handshake = protocol.candidate_rsd_device_handshake(identifier)
        print("offline only: T2 address="
              f"{protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE}%<interface>")
        print("offline only: verified Multiverse directory port=59602")
        print(f"offline only: opening={opening.hex()}")
        print(f"offline only: settings-ack={acknowledgment.hex()}")
        print(f"offline only: device-handshake={handshake.hex()}")
        return

    if args.confirm != CONFIRMATION:
        argument_parser.error(f"live mode requires --confirm={CONFIRMATION}")
    if not 0 < args.timeout <= 5:
        argument_parser.error("timeout must be greater than zero and no more than five seconds")
    port = live_query(args.interface, args.timeout)
    print(f"RSD advertised {BIOMETRIC_SERVICE} on port {port}")


if __name__ == "__main__":
    main()
