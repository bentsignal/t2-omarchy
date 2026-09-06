# SPDX-License-Identifier: MIT
import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from t2_fprintd_process import own_backend_subprocesses


class ProcessTests(unittest.TestCase):
    def test_reap_failure_is_recorded_for_stop_acknowledgement(self):
        async def original(self):
            await asyncio.create_subprocess_exec('unused')
        backend = SimpleNamespace(process=None)
        with patch('t2_fprintd_process.asyncio.create_subprocess_exec', AsyncMock(return_value=object())), \
                patch('t2_fprintd_process.reap', AsyncMock(side_effect=TimeoutError)):
            with self.assertRaises(TimeoutError):
                asyncio.run(own_backend_subprocesses(original)(backend))
        self.assertTrue(backend._t2_child_cleanup_failed)

    def test_cancelled_child_is_reaped_and_pointer_cleared(self):
        async def original(self):
            self.child = await asyncio.create_subprocess_exec(
                sys.executable, '-c', 'import time; print("ready", flush=True); time.sleep(60)',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await self.child.stdout.readline()
            self.started.set()
            await self.child.wait()
        async def run():
            backend = SimpleNamespace(started=asyncio.Event(), process=None)
            task = asyncio.create_task(own_backend_subprocesses(original)(backend))
            await asyncio.wait_for(backend.started.wait(), 3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)
            self.assertIsNotNone(backend.child.returncode)
            self.assertIsNone(backend.process)
        asyncio.run(run())

    def test_creation_race_does_not_lose_eventual_child(self):
        async def original(self):
            await asyncio.create_subprocess_exec('unused')
        async def run():
            started = asyncio.Event()
            release = asyncio.Event()
            process = SimpleNamespace(returncode=None, terminate=lambda: None,
                communicate=AsyncMock(return_value=(b'', b'')), wait=AsyncMock())
            async def spawn(*args, **kwargs):
                started.set()
                await release.wait()
                return process
            with patch('t2_fprintd_process.asyncio.create_subprocess_exec', side_effect=spawn):
                task = asyncio.create_task(own_backend_subprocesses(original)(SimpleNamespace(process=None)))
                await started.wait()
                task.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            process.communicate.assert_awaited_once()
            process.wait.assert_awaited_once()
        asyncio.run(run())

    def test_success_preserves_result_and_command_options(self):
        async def original(self, value, *, option):
            process = await asyncio.create_subprocess_exec(sys.executable, '-c', 'print(50123)',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            return int(stdout), value, option, stderr
        result = asyncio.run(own_backend_subprocesses(original)(SimpleNamespace(process=None), 4, option=5))
        self.assertEqual(result, (50123, 4, 5, b''))

    def test_cancel_drains_full_pipes(self):
        async def original(self):
            self.child = await asyncio.create_subprocess_exec(sys.executable, '-c',
                'import sys,time; sys.stdout.write("x"*262144); sys.stdout.flush(); time.sleep(60)',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            self.started.set()
            await asyncio.Future()
        async def run():
            backend = SimpleNamespace(started=asyncio.Event(), process=None)
            task = asyncio.create_task(own_backend_subprocesses(original)(backend))
            await backend.started.wait()
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 3)
            self.assertIsNotNone(backend.child.returncode)
        asyncio.run(run())
