#!/usr/bin/env python3
"""Fail-closed reset helper for only the internal T2 NCM USB device."""

from __future__ import annotations

import argparse
import fcntl
from pathlib import Path


USB_DEVICE = Path("/sys/bus/usb/devices/7-1")
EXPECTED_ANCESTRY = "0000:04:00.1/t2bce_core"
USBDEVFS_RESET = 0x5514
CONFIRMATION = "I_UNDERSTAND_THIS_RESETS_ONLY_T2_NCM_USB"
LIVE_T2_NCM_DEVICE_RESET_ENABLED = False


class ResetError(RuntimeError):
    pass


def _read(name: str) -> str:
    try:
        return (USB_DEVICE / name).read_text().strip()
    except OSError as error:
        raise ResetError(f"cannot read T2 USB identity field {name}") from error


def verified_devnode() -> Path:
    try:
        resolved = USB_DEVICE.resolve(strict=True)
    except OSError as error:
        raise ResetError("the exact T2 NCM USB device is absent") from error
    if EXPECTED_ANCESTRY not in str(resolved):
        raise ResetError("USB device does not descend from the T2 bridge function")
    if (_read("idVendor"), _read("idProduct")) != ("05ac", "8233"):
        raise ResetError("USB identity is not Apple T2 Controller 05ac:8233")
    if (_read("bNumConfigurations"), _read("bConfigurationValue")) != ("1", "1"):
        raise ResetError("T2 NCM USB configuration is not the exact expected singleton")
    bus, device = int(_read("busnum")), int(_read("devnum"))
    if not 1 <= bus <= 999 or not 1 <= device <= 999:
        raise ResetError("USB bus/device number is outside the accepted range")
    node = Path(f"/dev/bus/usb/{bus:03d}/{device:03d}")
    if not node.exists() or not node.is_char_device():
        raise ResetError("verified T2 usbfs device node is absent")
    return node


def reset() -> None:
    if not LIVE_T2_NCM_DEVICE_RESET_ENABLED:
        raise ResetError("live T2 NCM device reset is disabled in source")
    node = verified_devnode()
    with node.open("rb", buffering=0) as handle:
        fcntl.ioctl(handle, USBDEVFS_RESET, 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.live:
        print("offline only: exact target 05ac:8233 below PCI 0000:04:00.1")
        return
    if args.confirm != CONFIRMATION:
        parser.error(f"live mode requires --confirm={CONFIRMATION}")
    reset()
    print("verified T2 NCM USB device reset completed")


if __name__ == "__main__":
    main()
