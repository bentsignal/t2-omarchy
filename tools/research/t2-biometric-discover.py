#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the evidenced Intel T2 directory without scanning dynamic ports.

Only the service port is written to stdout, for a private caller pipe. No
biometric commands, cache writes, or authentication decisions are made here.
The 59602 directory hint comes from the installed Intel remoted evidence and
macOS boot trace in docs/macos-touch-id-findings.md, not a universal T2 claim.
"""
import asyncio
import os
from pathlib import Path
import runpy
import sys

DIRECTORY_PORT = 59602
SERVICE = "com.apple.eos.BiometricKit"


def advertised_port(peer):
    if not isinstance(peer, dict) or not isinstance(peer.get("Services"), dict):
        raise ValueError("missing directory services")
    service = peer["Services"].get(SERVICE)
    if not isinstance(service, dict):
        raise ValueError("missing biometric service")
    port = service.get("Port")
    if isinstance(port, bool) or not isinstance(port, (str, int)):
        raise ValueError("invalid service port type")
    if isinstance(port, str) and (not port.isascii() or not port.isdecimal()):
        raise ValueError("invalid service port encoding")
    port = int(port)
    if not 49152 <= port <= 65535:
        raise ValueError("invalid service port range")
    return port


async def query(host, interface, factory=None):
    if factory is None:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
        factory = RemoteXPCConnection
    connection = factory((f"{host}%{interface}", DIRECTORY_PORT))
    try:
        async with asyncio.timeout(2.0):
            await connection.connect()
            await connection.send_device_handshake()
            return advertised_port(await connection.receive_response())
    finally:
        try:
            await asyncio.wait_for(connection.close(), 0.5)
        except (OSError, TimeoutError):
            pass


def main():
    recovery = runpy.run_path(str(Path(__file__).with_name("t2-ncm-recover.py")))
    host, interface, _ = recovery["parse_endpoint"](
        recovery["private_read"](recovery["CONFIG"]),
        recovery["private_read"](recovery["PORT"]),
    )
    recovery["validate_target"](interface)
    fd = recovery["lock_operation"](0)
    try:
        print(asyncio.run(query(host, interface)))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Direct T2 directory lookup unavailable; private details suppressed.", file=sys.stderr)
        raise SystemExit(1)
