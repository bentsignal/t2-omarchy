#!/usr/bin/env python3
"""Maintain the model-specific hybrid menu after trusted UKI regeneration."""
from pathlib import Path
import hashlib
import re
import shutil
import sys
from datetime import datetime, timezone

IMAGE = 'boot():/EFI/Linux/omarchy_linux-t2.efi'
HYBRID = 'T2 Linux — Hybrid'


def update_config(text, digest):
    # Split headers from their properties; snapshots remain distinct entries.
    text = re.sub(r'^# (?:BEGIN|END) T2 HYBRID TRIAL\n', '', text, flags=re.M)
    parts = re.split(r'(^[ \t]*/[^\n]*\n)', text, flags=re.M)
    entries = [(parts[i], parts[i + 1]) for i in range(1, len(parts), 2)]
    candidates = [(h, b) for h, b in entries if h.strip().startswith('//')
                  and not h.strip().startswith('///') and 'kernel-id=linux-t2 ' in b
                  and re.search(r'^\s*path: ' + re.escape(IMAGE) + '#', b, re.M)]
    if len(candidates) != 1:
        raise RuntimeError('Expected one generated live linux-t2 entry')
    header, generated = candidates[0]
    path = re.search(r'^\s*path: (.+)$', generated, re.M)[1]
    if path != IMAGE + '#' + digest:
        raise RuntimeError('Generated entry does not match actual UKI; refusing to bless an unexplained image change')
    command = re.search(r'^\s*cmdline: (.+)$', generated, re.M)[1]
    base = ' '.join(p for p in command.split() if not p.startswith(('apple_gmux.force_igd=', 't2.graphics=')))
    seen = 0
    result = []
    for h, b in entries:
        title = h.strip().lstrip('/+')
        if title in ('T2 Intel-primary hybrid test', HYBRID):
            seen += 1
            continue
        depth = len(h.strip()) - len(h.strip().lstrip('/'))
        if h == header:
            h = '  //T2 Linux — AMD graphics\n'
        if depth == 2 and title in ('linux-t2 (Intel graphics test)', 'T2 Linux — GPU disabled'):
            h = '  //T2 Linux — GPU disabled\n'
            b = re.sub(r'^(\s*cmdline: ).*$', lambda m: m[1] + base + ' apple_gmux.force_igd=1', b, flags=re.M)
        # Only live-image references; snapshot images retain their own hashes.
        b = re.sub(re.escape(IMAGE) + r'#[0-9a-fA-F]+', lambda m: IMAGE + '#' + digest, b)
        result.append(h + b)
    if seen != 1:
        raise RuntimeError('Expected exactly one existing hybrid entry')
    global_text, n = re.subn(r'^default_entry:.*$', 'default_entry: 1', parts[0], flags=re.M)
    if n != 1:
        raise RuntimeError('Expected one default_entry')
    hybrid = (f'/{HYBRID}\ncomment: Intel desktop with selectable AMD performance\n'
              f'protocol: efi\npath: {IMAGE}#{digest}\n'
              f'cmdline: {base} apple_gmux.force_igd=1 t2.graphics=hybrid\n\n')
    return global_text + hybrid + ''.join(result)


def main():
    if Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MacBookPro16,1':
        raise RuntimeError('Unexpected model')
    image = Path('/boot/EFI/Linux/omarchy_linux-t2.efi')
    with image.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'blake2b').hexdigest()
    config = Path('/boot/limine.conf')
    original = config.read_text()
    updated = update_config(original, digest)
    if updated != original:
        backup = Path('/var/lib/t2-hybrid-trial') / ('menu-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.mkdir(parents=True, mode=0o700)
        shutil.copy2(config, backup / 'limine.conf')
        temporary = config.with_name('limine.conf.t2-new')
        try:
            temporary.write_text(updated)
            temporary.replace(config)
            if config.read_text() != updated:
                raise RuntimeError('Configuration readback failed')
        except BaseException:
            shutil.copy2(backup / 'limine.conf', config)
            temporary.unlink(missing_ok=True)
            raise
        print('Backup:', backup / 'limine.conf')
    print('Verified hybrid default, recovery names and live UKI hashes:', digest)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f't2 boot maintenance: {error}', file=sys.stderr)
        sys.exit(100)
