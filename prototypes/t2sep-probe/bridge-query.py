#!/usr/bin/env python3
"""Gated, read-only BridgeXPC version query for the T2 BiometricKit service.

Without --live this only emits offline fixtures.  Live mode never configures
an interface and can issue only Bridge method 0; it has no method-3/SBIO path.
"""

from __future__ import annotations

import argparse
import importlib.util
import math
from pathlib import Path
import plistlib
import socket
import sys


MODULE_PATH = Path(__file__).with_name("bridge-protocol.py")
SPEC = importlib.util.spec_from_file_location("bridge_protocol", MODULE_PATH)
assert SPEC and SPEC.loader
protocol = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol
SPEC.loader.exec_module(protocol)

BODY_CAP = 64 * 1024
# The current macOS trace records an exact 119-byte HELO.  With its five-byte
# OS build and 13-byte process name, that requires JSON integer 39, not 39.0.
CURRENT_BRIDGE_VERSION = 39
CURRENT_OS_BUILD = "25G83"
CURRENT_PROCESS_NAME = "biometrickitd"
CONFIRMATION = "I_UNDERSTAND_THIS_OPENS_T2_BIOMETRIC_SERVICE"
# Must become (52032, nonempty-evidence-note) only after a current macOS binary
# or trace confirms the named service still owns Catalina's port.
CURRENT_PORT_VERIFICATION = None


class QueryError(RuntimeError):
    pass


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise QueryError("peer closed the socket during a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> tuple[protocol.BridgeFrameHeader, bytes]:
    raw_header = recv_exact(sock, protocol.BRIDGE_FRAME_HEADER.size)
    header = protocol.decode_frame_header(raw_header, max_body=BODY_CAP)
    return header, recv_exact(sock, header.body_size)


def query_connected_socket(sock: socket.socket) -> tuple[int, int]:
    """Send only HELO and method 0, then accept one bounded message reply."""
    helo = protocol.encode_helo_frame(CURRENT_OS_BUILD, CURRENT_BRIDGE_VERSION,
                                      CURRENT_PROCESS_NAME,
                                      max_body=BODY_CAP)
    query = protocol.encode_bridge_version_query_frame(max_body=BODY_CAP)
    # Catalina's -connected writes HELO, starts its read, and immediately
    # flushes requests queued before activation.  Preserve that wire order.
    sock.sendall(helo)
    sock.sendall(query)

    for _ in range(4):
        header, body = recv_frame(sock)
        if header.kind == protocol.FRAME_NOOP:
            continue
        if header.kind == protocol.FRAME_HELO:
            protocol.decode_helo_body(body, max_body=BODY_CAP)
            continue
        if header.kind == protocol.FRAME_MESSAGE:
            return protocol.decode_bridge_version_reply_body(body,
                                                              max_body=BODY_CAP)
    raise QueryError("no message reply within the four-frame limit")


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


def live_query(interface: str, timeout: float) -> tuple[int, int]:
    if CURRENT_PORT_VERIFICATION is None:
        raise QueryError("live query disabled: verify BiometricKit's port on current bridgeOS")
    verification = CURRENT_PORT_VERIFICATION
    if (not isinstance(verification, tuple) or len(verification) != 2
            or verification[0] != protocol.BIOMETRIC_KIT_PORT
            or not isinstance(verification[1], str) or not verification[1]):
        raise QueryError("live query disabled: malformed current-port verification")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise QueryError("timeout must be finite, positive, and no more than five seconds")
    ifindex = verify_t2_interface(interface)
    target = protocol.biometric_sockaddr(ifindex)
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(target)
        result = query_connected_socket(sock)
        # Require EOF/no trailing application message only by closing immediately;
        # no second command is ever constructed by this program.
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()

    if not args.live:
        helo = protocol.encode_helo_frame(CURRENT_OS_BUILD, CURRENT_BRIDGE_VERSION,
                                          CURRENT_PROCESS_NAME,
                                          max_body=BODY_CAP)
        query = protocol.encode_bridge_version_query_frame(max_body=BODY_CAP)
        print(f"offline only: HELO={helo.hex()}")
        print(f"offline only: query={query.hex()}")
        return

    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    if not 0 < args.timeout <= 5:
        parser.error("timeout must be greater than zero and no more than five seconds")
    status, version = live_query(args.interface, args.timeout)
    print(f"bridge status={status} version={version}")


if __name__ == "__main__":
    main()
