# SPDX-License-Identifier: MIT
import asyncio
import fcntl
import hashlib
import importlib.util
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from t2_fprintd_owner import OwnerTracker, owner_aware_bus


class OwnerTests(unittest.TestCase):
    def fixture(self):
        ns = dict(MessageType=SimpleNamespace(METHOD_CALL=1, SIGNAL=2),
                  Message=SimpleNamespace(new_method_return=lambda m: 'reply'), DEVICE_PATH='/device')
        tracker = OwnerTracker(ns)
        tracker.device = SimpleNamespace(Claim=Mock(), _stop_verification=AsyncMock(), claimed_user='root')
        return tracker

    def claim(self, sender=':1.2'):
        return SimpleNamespace(message_type=1, path='/device', interface='net.reactivated.Fprint.Device',
                               member='Claim', signature='s', body=['root'], sender=sender)

    def lost(self, owner=':1.2', sender='org.freedesktop.DBus'):
        return SimpleNamespace(message_type=2, sender=sender, path='/org/freedesktop/DBus',
                               interface='org.freedesktop.DBus', member='NameOwnerChanged',
                               signature='sss', body=[owner, owner, ''])

    def test_failed_claim_does_not_replace_owner(self):
        tracker = self.fixture()
        self.assertEqual(tracker.handle(self.claim()), 'reply')
        tracker.device.Claim.side_effect = RuntimeError('rejected')
        with self.assertRaises(RuntimeError):
            tracker.handle(self.claim(':1.3'))
        self.assertEqual(tracker.owner, ':1.2')
        self.assertEqual(tracker.generation, 1)

    def test_only_bus_authenticated_owner_loss_cleans_up(self):
        async def run():
            tracker = self.fixture()
            tracker.handle(self.claim())
            for message in (self.lost(':1.3'), self.lost(sender=':1.9')):
                self.assertFalse(tracker.handle(message))
            self.assertFalse(tracker.tasks)
            tracker.handle(self.lost())
            await asyncio.gather(*tracker.tasks)
            tracker.device._stop_verification.assert_awaited_once()
            self.assertIsNone(tracker.device.claimed_user)
            self.assertIsNone(tracker.owner)
        asyncio.run(run())

    def test_stale_cleanup_does_not_stop_new_claim(self):
        async def run():
            tracker = self.fixture()
            tracker.handle(self.claim())
            old_generation = tracker.generation
            tracker.handle(self.claim())  # Same bus connection, later transaction.
            await tracker.release_disconnected(':1.2', old_generation)
            tracker.device._stop_verification.assert_not_awaited()
        asyncio.run(run())

    def test_cleanup_rechecks_generation_after_waiting_for_stop_lock(self):
        async def run():
            tracker = self.fixture()
            tracker.handle(self.claim())
            async def stop(**kwargs):
                tracker.handle(self.claim(':1.3'))
                self.assertFalse(kwargs['owner_check']())
                return False
            tracker.device._stop_verification.side_effect = stop
            await tracker.release_disconnected(':1.2', 1)
            self.assertEqual(tracker.owner, ':1.3')
            self.assertEqual(tracker.device.claimed_user, 'root')
        asyncio.run(run())

    def test_failed_cleanup_retains_claim(self):
        tracker = self.fixture()
        tracker.handle(self.claim())
        tracker.device._stop_verification.side_effect = RuntimeError('private error')
        asyncio.run(tracker.release_disconnected(':1.2', 1))
        self.assertEqual(tracker.owner, ':1.2')
        self.assertEqual(tracker.device.claimed_user, 'root')

    def test_real_private_bus_disconnect_reaps_child_and_releases_lock(self):
        try:
            from dbus_next import Message, MessageType
            from dbus_next.aio import MessageBus
        except ImportError:
            self.skipTest('installed runtime venv required')
        if not shutil.which('dbus-daemon'):
            self.skipTest('private dbus-daemon required')
        spec = importlib.util.spec_from_file_location('owner_runtime', Path(__file__).with_name('t2-fprintd-runtime.py'))
        overlay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(overlay)
        self.assertEqual(hashlib.sha256(overlay.SOURCE.read_bytes()).hexdigest(), overlay.EXPECTED_SHA256)
        namespace = runpy.run_path(str(overlay.SOURCE), run_name='_owner_integration')
        overlay.install_overlay(namespace)
        daemon = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--print-address=1'],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            address = daemon.stdout.readline().strip()
            with tempfile.TemporaryDirectory() as directory:
                lock = Path(directory) / 'operation.lock'
                lock.touch(mode=0o600)

                async def run():
                    service = await owner_aware_bus(namespace)(bus_address=address).connect()
                    client = await MessageBus(bus_address=address).connect()
                    stranger = await MessageBus(bus_address=address).connect()
                    backend = namespace['T2Backend'].__new__(namespace['T2Backend'])
                    backend.process = None
                    backend.notify_feedback = AsyncMock()
                    started = asyncio.Event()
                    children = []
                    async def verify():
                        child = await asyncio.create_subprocess_exec(
                            'flock', '--exclusive', '--no-fork', str(lock), sys.executable,
                            '-c', 'import time; print("ready", flush=True); time.sleep(60)',
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                        children.append(child)
                        backend.process = child
                        try:
                            self.assertEqual(await child.stdout.readline(), b'ready\n')
                            started.set()
                            await child.wait()
                        finally:
                            backend.process = None
                    backend.verify = verify
                    device = namespace['FprintDevice'](backend)
                    service.export(namespace['DEVICE_PATH'], device)
                    await service.request_name(namespace['BUS_NAME'])
                    async def call(member, signature='', body=None):
                        reply = await client.call(Message(destination=namespace['BUS_NAME'],
                            path=namespace['DEVICE_PATH'], interface='net.reactivated.Fprint.Device',
                            member=member, signature=signature, body=body or []))
                        self.assertEqual(reply.message_type, MessageType.METHOD_RETURN)
                    try:
                        await call('Claim', 's', ['root'])
                        await call('VerifyStart', 's', [namespace['ENROLLED_FINGER']])
                        await asyncio.wait_for(started.wait(), 3)
                        stranger.disconnect()
                        await asyncio.sleep(0.02)
                        self.assertIsNotNone(device.verify_task)
                        with lock.open('r+') as stream:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        client.disconnect()  # No VerifyStop or Release.
                        async def stopped():
                            while device.claimed_user is not None:
                                await asyncio.sleep(0.01)
                        await asyncio.wait_for(stopped(), 3)
                        self.assertIsNone(device.verify_task)
                        self.assertIsNotNone(children[0].returncode)
                        backend.notify_feedback.assert_not_awaited()
                        with lock.open('r+') as stream:
                            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        for child in children:
                            if child.returncode is None:
                                child.kill()
                            await child.wait()
                        for bus in (client, stranger, service):
                            bus.disconnect()
                            await bus.wait_for_disconnect()
                            # This pinned dbus-next shuts down but does not
                            # close its socket on disconnect. Close test FDs.
                            bus._stream.close()
                            bus._sock.close()
                asyncio.run(run())
        finally:
            daemon.terminate()
            daemon.wait(timeout=3)
            daemon.stdout.close()
