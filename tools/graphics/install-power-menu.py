#!/usr/bin/env python3
"""Extend an Omarchy-owned clone, retaining upstream UI in the user config."""
from pathlib import Path
import shutil
from datetime import datetime

source = Path(__file__).resolve().parent / 'power-menu'
path = Path.home() / '.config/omarchy/plugins/shawn.power/Panel.qml'
text = path.read_text()
if 'property var gpuState:' in text:
    raise SystemExit('GPU controls already installed; inspect before changing')
for marker in ['  property var batteryInfo:', '    if (!batteryPresent) return',
               '        // ---------- Power profile picker ----------',
               '    id: actionProc\n    onExited: root.refresh()']:
    if text.count(marker) != 1:
        raise SystemExit('Upstream panel changed; cannot locate ' + marker)
backup = path.with_name('Panel.qml.bak.' + datetime.now().strftime('%Y%m%d-%H%M%S'))
shutil.copy2(path, backup)
text = text.replace('  property var batteryInfo:', (source / 'state.qml').read_text() + '\n  property var batteryInfo:')
text = text.replace('    if (!batteryPresent) return', '    if (!gpuStatusProc.running) gpuStatusProc.running = true\n    if (!batteryPresent) return')
text = text.replace('        // ---------- Power profile picker ----------', (source / 'controls.qml').read_text() + '\n        // ---------- Power profile picker ----------')
path.write_text(text)
print('Installed GPU controls; backup:', backup)
