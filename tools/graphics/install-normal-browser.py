#!/usr/bin/env python3
"""Install a user-owned normal-browser launch override, preserving its profile."""
from pathlib import Path
from datetime import datetime
import shutil

source = Path(__file__).resolve().parent
upstream = Path('/usr/share/applications/helium.desktop')
launcher = Path.home() / '.local/libexec/t2-graphics/helium-browser'
desktop = Path.home() / '.local/share/applications/helium.desktop'
text = upstream.read_text()
lines = text.splitlines(keepends=True)
exec_lines = [line for line in lines if line.startswith('Exec=')]
if not exec_lines or any(not (line.startswith('Exec=helium-browser ') or line.strip() == 'Exec=helium-browser') for line in exec_lines):
    raise SystemExit('Unexpected packaged browser launcher; inspect before overriding')
if any(c in str(launcher) for c in ' %"\\`$'):
    raise SystemExit('Launcher path needs desktop-entry escaping')
for target in (launcher, desktop):
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.copy2(target, target.with_name(target.name + '.bak.' + datetime.now().strftime('%Y%m%d-%H%M%S')))
shutil.copyfile(source / 'helium-hybrid-launcher', launcher)
launcher.chmod(0o755)
desktop.write_text(''.join(line.replace('Exec=helium-browser', 'Exec=' + str(launcher), 1) if line.startswith('Exec=') else line for line in lines))
print('Installed normal-profile launcher:', desktop)
