#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded post-resume recovery of the internal T2BCE CDC-NCM link only.

No BridgeXPC commands, parent USB resets, biometric resets, or store writes.
Run from the root-owned systemd service, never from an authentication request.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import sys
import tempfile
import time

from t2_touchid_status import publish

CONFIG = Path("/etc/t2-touchid.conf")
PORT = Path("/var/lib/t2-touchid/biometric-port")
LOCK = Path("/run/t2-touchid/operation.lock")
SYS = Path("/sys")
RESUME_TICKET = Path("/run/t2-touchid/resume-ticket.json")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SUSPEND_SUCCESS = Path("/sys/power/suspend_stats/success")


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


def validate_target(interface: str, sys_root: Path = SYS, *, require_up: bool = True) -> tuple[Path, str]:
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
    if require_up and (net / "operstate").read_text().strip() != "up":
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


def transport_reachable(host: str, interface: str, port: int, *, timeout: float = 2) -> bool:
    try:
        index = socket.if_nametoindex(interface)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
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


def ticket_directory_safe() -> None:
    info = RESUME_TICKET.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RecoveryError("resume ticket directory must be private and root-owned")


def prepare_sleep() -> None:
    """Record a local one-use guard, not a network/device operation."""
    publish("transport", "sleeping")
    temporary = None
    try:
        ticket_directory_safe()
        RESUME_TICKET.unlink(missing_ok=True)
        host, interface, _ = parse_endpoint(private_read(CONFIG), private_read(PORT))
        # NetworkManager may have already lowered the link before sleep.target.
        # Validate hardware here; require the link up again before recovery.
        target = validate_target(interface, require_up=False)
        record = {
            "schema_version": 1, "boot_id": BOOT_ID.read_text().strip(),
            "suspend_success": int(SUSPEND_SUCCESS.read_text().strip()),
            "monotonic": time.monotonic(), "host": host, "interface": interface,
            "target": [str(target[0]), target[1]],
        }
        fd, temporary = tempfile.mkstemp(prefix=".resume-", dir=RESUME_TICKET.parent)
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(record, stream)
            stream.write("\n")
        os.replace(temporary, RESUME_TICKET)
        temporary = None
        print("T2 resume guard prepared; no device commands sent.", flush=True)
    except (OSError, ValueError, RecoveryError):
        # A missing optional optimization must not prevent ordinary suspend.
        print("T2 resume guard unavailable; retain watchdog-gated recovery.", flush=True)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def consume_resume_ticket(host: str, interface: str, target: tuple[Path, str]) -> bool:
    """Consume once; only an actual successful suspend qualifies for fast repair."""
    try:
        ticket_directory_safe()
        try:
            record = json.loads(private_read(RESUME_TICKET))
        finally:
            RESUME_TICKET.unlink(missing_ok=True)
        if not isinstance(record, dict):
            return False
        stamp = record.get("monotonic")
        count = record.get("suspend_success")
        if type(stamp) not in (float, int) or not math.isfinite(stamp) or type(count) is not int or count < 0:
            return False
        # CLOCK_MONOTONIC excludes time asleep; long sleeps remain eligible,
        # but a stale awake hook or ticket from a different boot does not.
        return bool(
            record.get("schema_version") == 1
            and record.get("boot_id") == BOOT_ID.read_text().strip()
            and int(SUSPEND_SUCCESS.read_text().strip()) == count + 1
            and 0 <= time.monotonic() - stamp <= 120
            and record.get("host") == host
            and record.get("interface") == interface
            and record.get("target") == [str(target[0]), target[1]]
        )
    except (OSError, ValueError, RecoveryError):
        return False


def recover(host: str, interface: str, port: int, *, after_resume: bool = False) -> bool:
    target = wait_for_target(interface)
    early = after_resume and consume_resume_ticket(host, interface, target)
    if after_resume:
        print("T2 successful-resume guard verified; checking link before early recovery." if early
              else "T2 resume guard not applicable; retaining watchdog-gated recovery.", flush=True)
    for attempt in range(3):
        if transport_reachable(host, interface, port, timeout=0.35 if early else 2):
            print("T2 network reachable; no rebind performed.", flush=True)
            return False
        if attempt < 2:
            time.sleep(0.25 if early else 1)
    if not early and tx_errors(interface) <= 0:
        # On the first real wake, cached EHOSTUNREACH made the three probes
        # finish before the NIC's ~5-second TX watchdog fired. Keep checking
        # briefly, but never remove the requirement for actual TX evidence.
        print("T2 peer unreachable; allowing up to 12s for delayed TX-error evidence.", flush=True)
        evidence_deadline = time.monotonic() + 12
        while tx_errors(interface) <= 0:
            if time.monotonic() >= evidence_deadline:
                raise RecoveryError("peer unreachable without TX-error evidence; no rebind attempted")
            # Keep observing the watchdog instead of hiding its arrival behind
            # a full two-second connection timeout plus a one-second sleep.
            time.sleep(0.25)
            if transport_reachable(host, interface, port, timeout=0.25):
                print("T2 network became reachable during watchdog grace; no rebind performed.", flush=True)
                return False
            if validate_target(interface) != target:
                raise RecoveryError("network target changed while awaiting TX errors")
    if validate_target(interface) != target:
        raise RecoveryError("network target changed during checks")
    if early:
        print("Confirmed resume with three failed probes; rebinding T2 CDC-NCM once before watchdog.", flush=True)
    else:
        print("T2 link unreachable with TX errors; rebinding its CDC-NCM interface once.", flush=True)
    started = time.monotonic()
    rebind(*target)
    print(f"T2 recovery timing: rebind elapsed_ms={(time.monotonic() - started) * 1000:.1f}", flush=True)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        time.sleep(0.1 if early else 1)
        if transport_reachable(host, interface, port, timeout=0.25 if early else 2):
            try:
                validate_target(interface)
            except InterfaceNotReady:
                continue
            print("T2 transport recovered; no biometric commands sent.", flush=True)
            return True
    raise RecoveryError("interface rebound but peer still unreachable; no further reset attempted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-sleep", action="store_true")
    mode.add_argument("--after-resume", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RecoveryError("root is required")
    if args.prepare_sleep:
        prepare_sleep()
        return 0
    publish("transport", "recovering")
    endpoint = parse_endpoint(private_read(CONFIG), private_read(PORT))
    fd = lock_operation()
    try:
        started = time.monotonic()
        recover(*endpoint, after_resume=args.after_resume)
        print(f"T2 recovery timing: recovery elapsed_ms={(time.monotonic() - started) * 1000:.1f}", flush=True)
    finally:
        os.close(fd)
    publish("transport", "available")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RecoveryError, OSError, ValueError) as error:
        publish("transport", "unavailable")
        # Do not log endpoint addresses or config values from exception strings.
        detail = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print(f"T2 network recovery stopped: {detail}", file=sys.stderr, flush=True)
        raise SystemExit(1)
