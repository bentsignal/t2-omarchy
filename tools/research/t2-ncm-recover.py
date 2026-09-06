#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded post-resume recovery of the internal T2BCE CDC-NCM link only.

No BridgeXPC commands, parent USB resets, biometric resets, or store writes.
Run from the root-owned systemd service, never from an authentication request.
"""
from __future__ import annotations

import errno
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import sys
import time

CONFIG = Path("/etc/t2-touchid.conf")
PORT = Path("/var/lib/t2-touchid/biometric-port")
LOCK = Path("/run/t2-touchid/operation.lock")
SYS = Path("/sys")


class RecoveryError(RuntimeError):
    pass


class InterfaceNotReady(RecoveryError):
    """The exact validated T2 interface is still being brought up after wake."""


def private_read(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RecoveryError("configuration/cache must be root-only regular files")
        value = stream.read(16385)
        if len(value) > 16384:
            raise RecoveryError("configuration/cache exceeds size limit")
        return value


def parse_endpoint(config: str, port_text: str) -> tuple[str, str, int]:
    values = {}
    for line in config.splitlines():
        parts = shlex.split(line, comments=True)
        if not parts:
            continue
        name, sep, value = parts[0].partition("=")
        if name not in ("T2_TOUCHID_HOST", "T2_TOUCHID_INTERFACE", "T2_TOUCHID_PORT_FILE"):
            continue
        if len(parts) != 1 or not sep or name in values:
            raise RecoveryError("ambiguous endpoint configuration")
        values[name] = value
    host = values.get("T2_TOUCHID_HOST", "")
    interface = values.get("T2_TOUCHID_INTERFACE", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", interface):
        raise RecoveryError("invalid network interface")
    if "%" in host or not ipaddress.IPv6Address(host).is_link_local:
        raise RecoveryError("endpoint must be an unscoped link-local IPv6 address")
    if values.get("T2_TOUCHID_PORT_FILE", str(PORT)) != str(PORT):
        raise RecoveryError("nonstandard port cache requires review")
    port = int(port_text.strip())
    if not 49152 <= port <= 65535:
        raise RecoveryError("invalid cached service port")
    return host, interface, port


def validate_target(interface: str, sys_root: Path = SYS) -> tuple[Path, str]:
    net = sys_root / "class/net" / interface
    device = (net / "device").resolve(strict=True)
    driver = (device / "driver").resolve(strict=True)
    if "t2bce_vhci" not in device.parts:
        raise RecoveryError("network device is not on T2BCE virtual USB")
    expected_driver = sys_root / "bus/usb/drivers/cdc_ncm"
    if driver != expected_driver.resolve(strict=True):
        raise RecoveryError("network device is not bound to cdc_ncm")
    if not re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*:1\.0", device.name):
        raise RecoveryError("unexpected USB interface shape")
    parent = device.parent
    if parent.name != device.name.split(":", 1)[0]:
        raise RecoveryError("unexpected USB parent")
    if (parent / "idVendor").read_text().strip() != "05ac" or (
        parent / "idProduct"
    ).read_text().strip() != "8233":
        raise RecoveryError("not the validated Apple T2 internal USB network device")
    if (net / "operstate").read_text().strip() != "up":
        raise InterfaceNotReady("network interface is not up; leave setup to NetworkManager")
    return driver, device.name


def wait_for_target(interface: str) -> tuple[Path, str]:
    deadline = time.monotonic() + 10
    reported = False
    while True:
        try:
            return validate_target(interface)
        except InterfaceNotReady:
            # NetworkManager.service being active does not mean this interface
            # has finished its independent resume. Never bring it up ourselves.
            if time.monotonic() >= deadline:
                raise RecoveryError("T2 interface still down after 10s; no rebind attempted") from None
            if not reported:
                print("Waiting up to 10s for NetworkManager to bring up the validated T2 interface.", flush=True)
                reported = True
            time.sleep(0.5)


def transport_reachable(host: str, interface: str, port: int) -> bool:
    try:
        index = socket.if_nametoindex(interface)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect((host, port, 0, index))
        return True
    except OSError as error:
        # A closed/stale service port is a reachable peer, not a stalled NIC.
        if error.errno == errno.ECONNREFUSED:
            return True
        if isinstance(error, TimeoutError) or error.errno in (
            errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH,
            errno.EADDRNOTAVAIL, errno.ENODEV, errno.ENXIO,
        ):
            return False
        raise


def lock_operation(wait_seconds: float = 20) -> int:
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RecoveryError("operation lock is not a private root-owned regular file")
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RecoveryError("operation busy; no recovery attempted") from None
                time.sleep(0.25)
    except BaseException:
        os.close(fd)
        raise


def rebind(driver: Path, device_name: str) -> None:
    # Bind is attempted even when unbind reports an error. Never touch the
    # USB parent, t2bce module, sensor, or another network driver.
    try:
        (driver / "unbind").write_text(device_name)
    finally:
        if not (driver / device_name).exists():
            (driver / "bind").write_text(device_name)


def tx_errors(interface: str) -> int:
    return int((SYS / "class/net" / interface / "statistics/tx_errors").read_text())


def recover(host: str, interface: str, port: int) -> bool:
    target = wait_for_target(interface)
    for attempt in range(3):
        if transport_reachable(host, interface, port):
            print("T2 network reachable; no rebind performed.", flush=True)
            return False
        if attempt < 2:
            time.sleep(1)
    if tx_errors(interface) <= 0:
        # On the first real wake, cached EHOSTUNREACH made the three probes
        # finish before the NIC's ~5-second TX watchdog fired. Keep checking
        # briefly, but never remove the requirement for actual TX evidence.
        print("T2 peer unreachable; allowing up to 12s for delayed TX-error evidence.", flush=True)
        evidence_deadline = time.monotonic() + 12
        while tx_errors(interface) <= 0:
            if time.monotonic() >= evidence_deadline:
                raise RecoveryError("peer unreachable without TX-error evidence; no rebind attempted")
            time.sleep(1)
            if transport_reachable(host, interface, port):
                print("T2 network became reachable during watchdog grace; no rebind performed.", flush=True)
                return False
            if validate_target(interface) != target:
                raise RecoveryError("network target changed while awaiting TX errors")
    if validate_target(interface) != target:
        raise RecoveryError("network target changed during checks")
    print("T2 link unreachable with TX errors; rebinding its CDC-NCM interface once.", flush=True)
    rebind(*target)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        time.sleep(1)
        if transport_reachable(host, interface, port):
            validate_target(interface)
            print("T2 transport recovered; no biometric commands sent.", flush=True)
            return True
    raise RecoveryError("interface rebound but peer still unreachable; no further reset attempted")


def main() -> int:
    if os.geteuid() != 0:
        raise RecoveryError("root is required")
    endpoint = parse_endpoint(private_read(CONFIG), private_read(PORT))
    fd = lock_operation()
    try:
        recover(*endpoint)
    finally:
        os.close(fd)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RecoveryError, OSError, ValueError) as error:
        # Do not log endpoint addresses or config values from exception strings.
        detail = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print(f"T2 network recovery stopped: {detail}", file=sys.stderr, flush=True)
        raise SystemExit(1)
