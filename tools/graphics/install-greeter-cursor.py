#!/usr/bin/env python3
"""Install a scoped SDDM cursor mitigation without restarting the display manager."""
from pathlib import Path
import os
import shutil

if os.geteuid() != 0:
    raise SystemExit('Requires root')
if Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
    raise SystemExit('Unexpected machine')
if not Path('/usr/share/sddm/hyprland.lua').is_file():
    raise SystemExit('Packaged Hyprland greeter config missing')
source = Path(__file__).resolve().parent
pairs = [('sddm-hybrid.lua', '/etc/sddm/hyprland-t2.lua'),
         ('99-t2-greeter.conf', '/etc/sddm.conf.d/99-t2-greeter.conf')]
for name, dest in pairs:
    p = Path(dest)
    if p.exists() or p.is_symlink():
        raise SystemExit('Destination exists; inspect before replacing: ' + dest)
for name, dest in pairs:
    p = Path(dest)
    p.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / name, p)
    p.chmod(0o644)
print('Installed greeter cursor mitigation for next login screen. SDDM was not restarted.')
