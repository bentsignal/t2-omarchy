#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure one T2-only NetworkManager reactivation; no biometric operations.

Changes only ipv6.addr-gen-mode in the exact validated manual-address profile.
Successful runs retain the requested mode. Failed runs restore the previous
mode and try to reactivate it. Run root-owned/under a bounded systemd service.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import time


def restore_sysctls(values):
    first_error = None
    for path, value in values.items():
        try:
            path.write_text(value)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error


def terminate(signum, frame):
    # Let finally restore settings on a bounded systemd service's SIGTERM.
    # SIGKILL/power loss still require manual inspection of the named profile.
    raise SystemExit(124)


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError("network command failed; private output suppressed")
    return result.stdout.strip()


def eui64_address(mac):
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise ValueError("invalid MAC address")
    octets = bytes.fromhex(mac.replace(":", ""))
    interface_id = bytes([octets[0] ^ 2]) + octets[1:3] + b"\xff\xfe" + octets[3:]
    return ipaddress.IPv6Address(bytes.fromhex("fe80000000000000") + interface_id)


def validate_profile(fields, interface, mac):
    if len(fields) != 6:
        raise ValueError("unexpected profile shape")
    profile_interface, ipv4, ipv6, addresses, mode, token = fields
    if profile_interface != interface or ipv4 != "disabled" or ipv6 != "manual" or token:
        raise ValueError("profile is not the expected dedicated manual T2 link")
    address = ipaddress.IPv6Interface(addresses)
    if address.network.prefixlen != 64 or address.ip != eui64_address(mac):
        raise ValueError("configured address does not equal the T2 link EUI64 address")
    if mode not in ("default", "eui64"):
        raise ValueError("unreviewed address generation mode")
    return mode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("default", "eui64"), required=True)
    parser.add_argument("--optimistic", action="store_true", help="temporarily test interface-only optimistic DAD")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("root required")
    recovery = runpy.run_path(str(Path(__file__).with_name("t2-ncm-recover.py")))
    host, interface, port = recovery["parse_endpoint"](
        recovery["private_read"](recovery["CONFIG"]), recovery["private_read"](recovery["PORT"]),
    )
    target = recovery["validate_target"](interface)
    uuid = command("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", interface)
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
        raise ValueError("no unique active connection")
    fields = command("nmcli", "-e", "no", "-g", "connection.interface-name,ipv4.method,ipv6.method,ipv6.addresses,ipv6.addr-gen-mode,ipv6.token", "connection", "show", "uuid", uuid).split("\n")
    # command.strip() removes the empty final token; reject nonempty tokens.
    if len(fields) == 5:
        fields.append("")
    previous = validate_profile(fields, interface, Path(f"/sys/class/net/{interface}/address").read_text().strip())
    fd = recovery["lock_operation"](0)
    modified = False
    process = None
    restored = False
    sysctls = {}
    try:
        if recovery["validate_target"](interface) != target:
            raise RuntimeError("target changed")
        if not recovery["transport_reachable"](host, interface, port):
            raise RuntimeError("baseline link not healthy")
        recovery["publish"]("transport", "recovering")
        modified = True
        command("nmcli", "connection", "modify", "uuid", uuid, "ipv6.addr-gen-mode", args.mode)
        command("nmcli", "--wait", "15", "device", "disconnect", interface)
        if args.optimistic:
            if recovery["validate_target"](interface, require_up=False) != target:
                raise RuntimeError("target changed before interface tuning")
            directory = Path(f"/proc/sys/net/ipv6/conf/{interface}")
            if int((directory / "dad_transmits").read_text()) < 1 or int((directory / "accept_dad").read_text()) < 1:
                raise RuntimeError("duplicate-address checks must remain enabled")
            for name in ("optimistic_dad", "use_optimistic"):
                path = directory / name
                sysctls[path] = path.read_text()
                path.write_text("1\n")
        started = time.monotonic()
        process = subprocess.Popen(
            ["nmcli", "--wait", "15", "connection", "up", "uuid", uuid, "ifname", interface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        first_reachable = None
        deadline = started + 18
        while time.monotonic() < deadline:
            if first_reachable is None and recovery["transport_reachable"](host, interface, port, timeout=0.05):
                first_reachable = time.monotonic() - started
            if process.poll() is not None:
                break
            time.sleep(0.05)
        process.communicate(timeout=1)
        if process.returncode or first_reachable is None:
            raise RuntimeError("activation/transport did not complete")
        activation_seconds = time.monotonic() - started
        if recovery["validate_target"](interface) != target:
            raise RuntimeError("target changed during activation")
        addresses = json.loads(command("ip", "-j", "-6", "addr", "show", "dev", interface))[0]["addr_info"]
        if args.mode == "eui64" and len(addresses) != 1:
            raise RuntimeError("expected single-address result not achieved")
        recovery["publish"]("transport", "available")
        restored = True
        print(json.dumps({"mode": args.mode, "previous_mode": previous, "optimistic": args.optimistic,
                          "first_reachable_seconds": round(first_reachable, 3),
                          "activation_seconds": round(activation_seconds, 3),
                          "ipv6_address_count": len(addresses),
                          "biometric_commands_sent": False, "identifiers_redacted": True}))
    finally:
        try:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
        finally:
            try:
                if modified and not restored:
                    command("nmcli", "connection", "modify", "uuid", uuid, "ipv6.addr-gen-mode", previous)
                    command("nmcli", "--wait", "15", "connection", "up", "uuid", uuid, "ifname", interface)
                    restored = recovery["transport_reachable"](host, interface, port)
                    recovery["publish"]("transport", "available" if restored else "unavailable")
            except BaseException:
                recovery["publish"]("transport", "unavailable")
                raise
            finally:
                try:
                    restore_sysctls(sysctls)
                except BaseException:
                    recovery["publish"]("transport", "unavailable")
                    raise
                finally:
                    os.close(fd)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    try:
        main()
    except Exception:
        print("T2 activation measurement failed; private details suppressed.", flush=True)
        raise SystemExit(1)
