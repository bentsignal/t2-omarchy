#!/usr/bin/env python3
"""Bounded AMD low/high control for the Intel-primary T2 topology."""
import grp
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sys

SOCKET = '/run/t2-gpu/control.sock'
MODES = ('auto', 'performance', 'saver')


def desired_level(mode, ac, profile):
    if mode not in MODES:
        raise ValueError('Unknown GPU mode')
    return 'high' if mode == 'performance' or (mode == 'auto' and ac and profile == 'performance') else 'low'


def power_source():
    supplies = list(Path('/sys/class/power_supply').glob('*/online'))
    return any(p.read_text().strip() == '1' for p in supplies)


_profile_bus = None


def profile():
    # Query D-Bus directly: avoid spawning a Python CLI every polling interval.
    global _profile_bus
    from gi.repository import Gio, GLib
    try:
        if _profile_bus is None:
            _profile_bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        return _profile_bus.call_sync(
            'org.freedesktop.UPower.PowerProfiles',
            '/org/freedesktop/UPower/PowerProfiles',
            'org.freedesktop.DBus.Properties', 'Get',
            GLib.Variant('(ss)', ('org.freedesktop.UPower.PowerProfiles', 'ActiveProfile')),
            GLib.VariantType('(v)'), Gio.DBusCallFlags.NONE, 1000, None
        ).unpack()[0]
    except GLib.Error:
        _profile_bus = None
        return 'unknown'


class Policy:
    def __init__(self, topology):
        self.topology = topology
        self.mode = 'auto'
        self.ac = power_source()
        self.error = ''
        self.status = {}

    def refresh(self, request=None):
        ac = power_source()
        if ac != self.ac:
            self.mode = 'auto'  # A cable transition clears the temporary override.
        self.ac = ac
        if request is not None:
            if request not in MODES:
                raise ValueError('Unknown GPU mode')
            self.mode = request
        active_profile = profile()
        target = desired_level(self.mode, ac, active_profile)
        actual = 'unknown'
        self.error = ''
        try:
            control = self.topology()
            actual = control.read_text().strip()
            if actual != target:
                control.write_text(target + '\n')
                actual = control.read_text().strip()
                if actual != target:
                    raise RuntimeError('AMD driver did not retain requested level')
                print(f'AMD DPM={actual}; mode={self.mode}; AC={ac}', flush=True)
        except (OSError, RuntimeError) as error:
            self.error = str(error)
        self.status = dict(mode=self.mode, ac=ac, profile=active_profile,
                           requested=target, level=actual, error=self.error)
        return self.status


def main():
    spec = importlib.util.spec_from_file_location('topology', '/usr/local/libexec/t2-hybrid-low.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy = Policy(module.check_topology)
    runtime = Path(SOCKET).parent
    runtime.mkdir(mode=0o755, exist_ok=True)
    Path(SOCKET).unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(SOCKET)
    os.chown(SOCKET, 0, grp.getgrnam('wheel').gr_gid)
    os.chmod(SOCKET, 0o660)
    server.listen(4)
    server.settimeout(3)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        while True:
            policy.refresh()
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(1)
                try:
                    command = connection.recv(64).decode().strip()
                    if command == 'status':
                        result = policy.status
                    elif command in MODES:
                        result = policy.refresh(command)
                    else:
                        result = {'error': 'Unsupported command'}
                    connection.sendall(json.dumps(result).encode() + b'\n')
                except (OSError, UnicodeError):
                    pass
    finally:
        # Return to low on intentional service stop while topology is valid.
        try:
            module.check_topology().write_text('low\n')
        except (OSError, RuntimeError):
            pass
        server.close()
        Path(SOCKET).unlink(missing_ok=True)


if __name__ == '__main__':
    main()
