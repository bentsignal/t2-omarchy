#!/usr/bin/env python3
"""Bounded manual diagnostic for the unused AMD eDP in Intel-routed hybrid mode."""
from pathlib import Path
import sys

if len(sys.argv) != 2 or sys.argv[1] not in ('off', 'detect'):
    raise SystemExit('Usage: probe-phantom-panel.py off|detect')
if Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
    raise SystemExit('Unexpected model')
cmdline = Path('/proc/cmdline').read_text().split()
if not {'t2.graphics=hybrid', 'apple_gmux.force_igd=1'} <= set(cmdline):
    raise SystemExit('Requires Intel-routed hybrid boot')
intel = Path('/sys/class/drm/card1-eDP-1')
amd = Path('/sys/class/drm/card2-eDP-2')
for panel, pci, driver in [(intel, '0000:00:02.0', 'i915'), (amd, '0000:03:00.0', 'amdgpu')]:
    device = (panel / 'device').resolve()
    # Connector device symlink points to the DRM card; its device points to PCI.
    if device.name.startswith('card'):
        device = (device / 'device').resolve()
    if device.name != pci or (device / 'driver').resolve().name != driver:
        raise SystemExit('Unexpected connector owner: ' + str(device))
if (intel / 'enabled').read_text().strip() != 'enabled' or (amd / 'enabled').read_text().strip() != 'disabled':
    raise SystemExit('Requires enabled Intel panel and already-disabled AMD panel')
(amd / 'status').write_text(sys.argv[1] + '\n')
print('AMD unused panel:', (amd / 'status').read_text().strip())
