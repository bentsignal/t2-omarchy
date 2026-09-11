#!/usr/bin/env python3
"""Apply the opt-in Intel-primary AMD low policy on MacBookPro16,1."""

import os
from pathlib import Path
import sys
import time


def check_topology(sysroot=Path('/sys'), cmdline=None):
    if cmdline is None:
        cmdline = Path('/proc/cmdline').read_text()
    if 't2.graphics=hybrid' not in cmdline.split():
        raise RuntimeError('Hybrid test boot was not selected')
    if (sysroot / 'class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
        raise RuntimeError('Unexpected Mac model')
    pci = sysroot / 'bus/pci/devices'
    intel = pci / '0000:00:02.0'
    amd = pci / '0000:03:00.0'
    for dev, vendor, device, driver in (
        (intel, '0x8086', '0x3e9b', 'i915'),
        (amd, '0x1002', '0x7340', 'amdgpu'),
    ):
        if (dev / 'vendor').read_text().strip() != vendor or (dev / 'device').read_text().strip() != device:
            raise RuntimeError('Unexpected GPU identity')
        if (dev / 'driver').resolve(strict=True).name != driver:
            raise RuntimeError('Unexpected GPU driver')
    lines = (sysroot / 'kernel/debug/vgaswitcheroo/switch').read_text().splitlines()
    if not any(line.split(':')[1:4] == ['IGD', '+', 'Pwr']
               and line.endswith(':0000:00:02.0') for line in lines):
        raise RuntimeError('Intel is not the active powered display GPU')
    panels = list((intel / 'drm').glob('card[0-9]*/card*-eDP-*/status'))
    if not any(panel.read_text().strip() == 'connected' for panel in panels):
        raise RuntimeError('No connected Intel internal panel')
    if (amd / 'power_state').read_text().strip() != 'D0':
        raise RuntimeError('AMD is not powered; check the old dGPU-off service')
    return amd / 'power_dpm_force_performance_level'


def main():
    if sys.argv[1:] not in ([], ['--check']):
        raise RuntimeError('Usage: t2-hybrid-low.py [--check]')
    if os.geteuid() != 0:
        raise RuntimeError('Root is required to read the mux state')
    deadline = time.monotonic() + (0 if '--check' in sys.argv else 30)
    while True:
        try:
            control = check_topology()
            before = control.read_text().strip()
            break
        except (OSError, RuntimeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    if '--check' in sys.argv:
        print(f'Intel-primary topology verified; AMD DPM={before}; no change')
        return
    control.write_text('low\n')
    if control.read_text().strip() != 'low':
        raise RuntimeError('Driver did not retain low DPM')
    print(f'Intel-primary topology verified; AMD DPM {before} -> low')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f't2-hybrid-low: {error}', file=sys.stderr)
        sys.exit(1)
