#!/usr/bin/env python3
"""Select the installed hybrid entry by placing it first; retain recovery entries."""
from datetime import datetime, timezone
from pathlib import Path
import os
import re
import shutil


def select_hybrid(text):
    pattern = r'^# BEGIN T2 HYBRID TRIAL\n/T2 Intel-primary hybrid test\n.*?^# END T2 HYBRID TRIAL\n\n?'
    matches = list(re.finditer(pattern, text, re.M | re.S))
    if len(matches) != 1:
        raise RuntimeError('Expected exactly one installed hybrid entry')
    block = matches[0].group()
    command = re.search(r'^cmdline: (.+)$', block, re.M)
    if not command or not {'apple_gmux.force_igd=1', 't2.graphics=hybrid'} <= set(command[1].split()):
        raise RuntimeError('Hybrid entry lacks required boot options')
    remaining = text[:matches[0].start()] + text[matches[0].end():]
    entry = re.search(r'^/', remaining, re.M)
    if not entry:
        raise RuntimeError('No recovery entries found')
    updated = remaining[:entry.start()] + block.rstrip() + '\n\n' + remaining[entry.start():]
    updated, count = re.subn(r'^default_entry:.*$', 'default_entry: 1', updated, flags=re.M)
    if count != 1:
        raise RuntimeError('Expected one explicit default_entry')
    return updated


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('Run with pkexec or sudo')
    if Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
        raise SystemExit('Unexpected machine')
    path = Path('/boot/limine.conf')
    original = path.read_text()
    updated = select_hybrid(original)
    backup = Path('/var/lib/t2-hybrid-trial') / ('default-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(path, backup / 'limine.conf')
    try:
        path.write_text(updated)
        if path.read_text() != updated:
            raise RuntimeError('Boot configuration readback mismatch')
    except BaseException:
        shutil.copy2(backup / 'limine.conf', path)
        raise
    print('Verified: hybrid entry is first and default_entry is 1; recovery entries retained.')
    print(f'Backup: {backup}/limine.conf')
