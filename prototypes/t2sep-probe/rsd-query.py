#!/usr/bin/env python3
"""Hard-gated passive RSD directory query for the internal T2 link.

Default execution prints deterministic offline fixtures.  Live execution is
mechanically disabled until current installed-macOS evidence verifies the T2
RSD address and port.  Even after that source gate is filled, the only request
implemented here is the RemoteXPC service-directory handshake.
"""

from __future__ import annotations

import argparse
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
# macOS 26.6.2 build 25G83 x86_64 remoted, SHA-256
# 88e78e65b77e3c2338ca95c9ab201bfa0be90ce81e58ece1c4d1ad11273f4056,
# RSDRemoteNCMDeviceDevice::createPortListener at 0x10001628a stores 0xe59f.
CURRENT_RSD_PORT_VERIFICATION = (
    protocol.RSD_PORT_CANDIDATE,
    "installed macOS 26.6.2 remoted NCM-device listener",
)
# Must become (address, evidence-note) only after current installed-macOS or a
# passive trace verifies the T2 peer address. No live path exists with this unset.
CURRENT_T2_ADDRESS_VERIFICATION = None


class QueryError(RuntimeError):
    pass


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


def query_connected_socket(sock: socket.socket,
                           client_uuid: uuid.UUID) -> int:
    """Perform only the bounded service-directory exchange on a supplied socket."""
    if not isinstance(client_uuid, uuid.UUID):
        raise QueryError("client UUID must be a UUID")
    parser = protocol.PassiveRSDTranscript(
        wanted_service=BIOMETRIC_SERVICE,
        max_frame=FRAME_CAP,
        max_frames=FRAME_LIMIT,
        max_total=TOTAL_CAP,
        max_xpc_body=FRAME_CAP,
    )
    sock.sendall(protocol.candidate_rsd_transport_opening())
    handshake_sent = False
    for _ in range(FRAME_LIMIT):
        try:
            parser.feed(recv_frame(sock))
        except protocol.RSDProtocolError as error:
            raise QueryError("peer RSD transcript failed validation") from error
        if parser.peer_settings_seen and not handshake_sent:
            sock.sendall(protocol.candidate_rsd_settings_ack())
            sock.sendall(protocol.candidate_rsd_device_handshake(client_uuid))
            handshake_sent = True
        if parser.complete:
            try:
                return parser.finish()
            except protocol.RSDProtocolError as error:
                raise QueryError("peer RSD directory failed final validation") from error
    raise QueryError("no RSD directory within the frame limit")


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


def live_query(interface: str, timeout: float) -> int:
    if CURRENT_T2_ADDRESS_VERIFICATION is None:
        raise QueryError("live RSD query disabled: verify current T2 peer address")
    expected = (protocol.T2_LINK_LOCAL_ADDRESS_CANDIDATE,
                protocol.RSD_PORT_CANDIDATE)
    address_verification = CURRENT_T2_ADDRESS_VERIFICATION
    port_verification = CURRENT_RSD_PORT_VERIFICATION
    if (not isinstance(address_verification, tuple) or len(address_verification) != 2
            or address_verification[0] != expected[0]
            or not isinstance(address_verification[1], str) or not address_verification[1]
            or not isinstance(port_verification, tuple) or len(port_verification) != 2
            or port_verification[0] != expected[1]
            or not isinstance(port_verification[1], str) or not port_verification[1]):
        raise QueryError("live RSD query disabled: malformed endpoint verification")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise QueryError("timeout must be finite, positive, and no more than five seconds")
    ifindex = verify_t2_interface(interface)
    target = protocol.candidate_rsd_sockaddr(ifindex)
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(target)
        return query_connected_socket(sock, uuid.uuid4())


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
        print(f"offline only: candidate endpoint={protocol.candidate_rsd_sockaddr(1)}")
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
