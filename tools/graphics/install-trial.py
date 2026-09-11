#!/usr/bin/env python3
"""Install the reviewed, opt-in trial; never reboot or start GPU policy."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess


def trial_block(original):
    match = re.search(r'^  //linux-t2 \(Intel graphics test\)\n(.*?)(?=^\s*//|^/|\Z)',
                      original, re.M | re.S)
    if not match:
        raise RuntimeError('Expected existing Intel test entry is absent')
    body = match.group(1)
    fields = {}
    for key in ('protocol', 'path', 'cmdline'):
        values = re.findall(r'^\s*' + key + r': (.+)$', body, re.M)
        if len(values) != 1:
            raise RuntimeError(f'Ambiguous Intel entry {key}')
        fields[key] = values[0]
    if fields['protocol'] != 'efi' or 'apple_gmux.force_igd=1' not in fields['cmdline'].split():
        raise RuntimeError('Unexpected Intel boot arrangement')
    return ('# BEGIN T2 HYBRID TRIAL\n/T2 Intel-primary hybrid test\n'
            'comment: Intel display, AMD available at low DPM; experimental\n'
            f"protocol: efi\npath: {fields['path']}\n"
            f"cmdline: {fields['cmdline']} t2.graphics=hybrid\n"
            '# END T2 HYBRID TRIAL\n\n')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run with pkexec or sudo')
    if Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
        raise RuntimeError('Unexpected machine')
    source = Path(__file__).resolve().parent
    boot = Path('/boot/limine.conf')
    original = boot.read_text()
    if 'T2 HYBRID TRIAL' in original:
        raise RuntimeError('Trial entry already exists; inspect before reinstalling')
    block = trial_block(original)
    if original.count('\n/EFI fallback\n') != 1:
        raise RuntimeError('Expected insertion point is absent or ambiguous')
    destinations = {
        source / 't2-hybrid-low.py': Path('/usr/local/libexec/t2-hybrid-low.py'),
        source / 't2-hybrid-low.service': Path('/etc/systemd/system/t2-hybrid-low.service'),
        source / '70-t2-hybrid-drm.rules': Path('/etc/udev/rules.d/70-t2-hybrid-drm.rules'),
    }
    drops = [Path('/etc/systemd/system') / (unit + '.service.d/skip-hybrid.conf')
             for unit in ('t2-intel-dgpu-off', 't2-graphics-mode-policy')]
    for path in [*destinations.values(), *drops]:
        if path.exists() or path.is_symlink():
            raise RuntimeError(f'Refusing to overwrite {path}')
    # Preserve boot recovery material outside this checkout.
    backup = Path('/var/lib/t2-hybrid-trial') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(boot, backup / 'limine.conf')
    created = []
    boot_changed = False
    try:
        for src, dest in [*destinations.items(), *((source / 'skip-hybrid.conf', p) for p in drops)]:
            dest.parent.mkdir(parents=True, exist_ok=True)
            created.append(dest)
            shutil.copyfile(src, dest)
            dest.chmod(0o644)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['udevadm', 'control', '--reload-rules'], check=True)
        subprocess.run(['systemctl', 'enable', 't2-hybrid-low.service'], check=True)
        # Existing boot text, image, hashes and default selection are retained.
        updated = original.replace('\n/EFI fallback\n', '\n' + block + '/EFI fallback\n')
        boot_changed = True
        boot.write_text(updated)
        if boot.read_text() != updated:
            raise RuntimeError('Boot configuration readback mismatch')
        (backup / 'installed-files.txt').write_text('\n'.join(map(str, created)) + '\n')
        print(f'Trial installed. Boot backup: {backup}/limine.conf')
        print('No service start, graphics switch, or reboot performed.')
    except BaseException:
        if boot_changed:
            shutil.copy2(backup / 'limine.conf', boot)
        subprocess.run(['systemctl', 'disable', 't2-hybrid-low.service'], check=False)
        for path in reversed(created):
            path.unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=False)
        subprocess.run(['udevadm', 'control', '--reload-rules'], check=False)
        raise


if __name__ == '__main__':
    main()
