#!/usr/bin/env python3
"""Install model-specific GPU controls and boot maintenance; no reboot."""
from pathlib import Path
import os
import shutil
import subprocess

source = Path(__file__).resolve().parent
if os.geteuid() != 0 or Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
    raise SystemExit('Requires root on MacBookPro16,1')
pairs = {
    'maintain-boot.py': '/usr/local/libexec/t2-maintain-boot.py',
    't2-gpu-policy.py': '/usr/local/libexec/t2-gpu-policy.py',
    't2-gpu-policy.service': '/etc/systemd/system/t2-gpu-policy.service',
    't2-gpu': '/usr/local/bin/t2-gpu',
}
hook = Path('/etc/boot/hooks/post.d/85-t2-hybrid-menu')
for target in [*pairs.values(), str(hook)]:
    if Path(target).exists() or Path(target).is_symlink():
        raise SystemExit('Destination exists; inspect before reinstalling: ' + target)
# Repair boot entries before exposing performance controls.
subprocess.run(['/usr/bin/python3', str(source / 'maintain-boot.py')], check=True)
for name, target in pairs.items():
    path = Path(target)
    shutil.copyfile(source / name, path)
    path.chmod(0o755 if name == 't2-gpu' else 0o644)
hook.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/local/libexec/t2-maintain-boot.py\n')
hook.chmod(0o755)
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemctl', 'enable', '--now', 't2-gpu-policy.service'], check=True)
print('Installed GPU mode service, client and post-update boot maintenance hook.')
