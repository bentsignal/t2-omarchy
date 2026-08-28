#!/usr/bin/env python3
"""Hard-gated, bounded `_remoted._tcp.local` discovery on the T2 link."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import struct
import sys


MODULE_PATH = Path(__file__).with_name("rsd-mdns.py")
SPEC = importlib.util.spec_from_file_location("rsd_mdns", MODULE_PATH)
assert SPEC and SPEC.loader
mdns = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mdns
SPEC.loader.exec_module(mdns)

MULTICAST_ADDRESS = "ff02::fb"
MULTICAST_PORT = 5353
HOST_ADDRESS = "fe80::aede:48ff:fe00:1122"
CONFIRMATION = "I_UNDERSTAND_THIS_ONLY_DISCOVERS_THE_T2_RSD_PORT"
LIVE_MDNS_DISCOVERY_ENABLED = False


class QueryError(RuntimeError):
    pass


def capture_socket(sock: socket.socket, interface_index: int) -> mdns.DiscoveredRSDEndpoint:
    """Send one PTR query and consume only bounded T2-sourced responses."""
    if (isinstance(interface_index, bool) or not isinstance(interface_index, int)
            or not 1 <= interface_index < 1 << 32):
        raise QueryError("interface index is out of range")
    query = mdns.build_srv_query(unicast_response=True)
    destination = (MULTICAST_ADDRESS, MULTICAST_PORT, 0, interface_index)
    sent = sock.sendto(query, destination)
    if sent != len(query):
        raise QueryError("mDNS query was not sent in full")
    parser = mdns.PassiveMDNSDiscovery()
    for _ in range(mdns.MAX_DATAGRAMS):
        try:
            packet, source = sock.recvfrom(mdns.MAX_DATAGRAM + 1)
        except (TimeoutError, socket.timeout) as error:
            raise QueryError("no complete T2 RSD advertisement before timeout") from error
        if not isinstance(packet, bytes) or not isinstance(source, tuple) or len(source) < 4:
            raise QueryError("socket returned malformed mDNS data")
        if source[1] != MULTICAST_PORT or source[3] != interface_index:
            raise QueryError("mDNS response has the wrong source port or interface scope")
        if len(packet) > mdns.MAX_DATAGRAM:
            raise QueryError("mDNS datagram exceeds cap")
        try:
            parser.feed(packet, source_address=source[0])
            evidence = parser.finish()
        except mdns.MDNSIncompleteError:
            # A valid response may split PTR, SRV, and AAAA across datagrams.
            continue
        except mdns.MDNSError as error:
            raise QueryError("T2 mDNS evidence failed validation") from error
        return mdns.DiscoveredRSDEndpoint(
            (evidence.source_address, evidence.port, 0, interface_index), evidence)
    raise QueryError("no complete T2 RSD advertisement within datagram cap")


def _read_sysfs(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError as error:
        raise QueryError(f"cannot read {path}") from error


def verify_t2_interface(name: str) -> int:
    if (not isinstance(name, str) or not name
            or any(character not in
                   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
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


def live_capture(interface: str, timeout: float) -> mdns.DiscoveredRSDEndpoint:
    if not LIVE_MDNS_DISCOVERY_ENABLED:
        raise QueryError("live T2 mDNS discovery disabled in source")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise QueryError("timeout must be finite, positive, and no more than five seconds")
    interface_index = verify_t2_interface(interface)
    group = socket.inet_pton(socket.AF_INET6, MULTICAST_ADDRESS)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        group + struct.pack("@I", interface_index))
        sock.bind((HOST_ADDRESS, MULTICAST_PORT, 0, interface_index))
        sock.settimeout(timeout)
        return capture_socket(sock, interface_index)


def write_capture(path: Path, result: mdns.DiscoveredRSDEndpoint) -> None:
    """Create one private JSON evidence file without replacing anything."""
    if not isinstance(path, Path) or path.exists() or path.is_symlink():
        raise QueryError("capture output path must not already exist")
    evidence = result.evidence
    payload = {
        "endpoint": list(result.endpoint),
        "instance": evidence.instance,
        "target": evidence.target,
        "source_address": evidence.source_address,
        "server_datagrams": [
            {"hex": packet.hex(), "sha256": hashlib.sha256(packet).hexdigest()}
            for packet in evidence.server_datagrams
        ],
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
    except OSError as error:
        raise QueryError(f"cannot create capture output {path}") from error


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--interface", default="enp4s0f1u1")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--confirm", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.live:
        print(f"offline only: srv-query={mdns.build_srv_query().hex()}")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    if args.output is None:
        parser.error("live mode requires --output with a new private file path")
    if args.output.exists() or args.output.is_symlink():
        parser.error("live output path must not already exist")
    result = live_capture(args.interface, args.timeout)
    write_capture(args.output, result)
    print(f"T2 advertised RSD at [{result.endpoint[0]}]:{result.endpoint[1]}")


if __name__ == "__main__":
    main()
