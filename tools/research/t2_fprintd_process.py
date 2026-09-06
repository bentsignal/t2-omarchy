# SPDX-License-Identifier: MIT
"""Give pinned backend subprocesses an owner across coroutine cancellation."""
import asyncio
import types


async def reap(process):
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        # Drain remaining pipes so a full output buffer cannot prevent exit.
        # Original readers have completed or been cancelled by this point.
        await asyncio.wait_for(process.communicate(), 2)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await asyncio.wait_for(process.communicate(), 0.5)
    await asyncio.wait_for(process.wait(), 0.5)


def own_backend_subprocesses(original):
    async def owned(self, *args, **kwargs):
        processes = []

        class AsyncioView:
            def __getattr__(self, name):
                return getattr(asyncio, name)

            async def create_subprocess_exec(self_view, *argv, **options):
                # Cancelling process creation must not lose the eventual child.
                startup = asyncio.create_task(asyncio.create_subprocess_exec(*argv, **options))
                try:
                    process = await asyncio.shield(startup)
                except asyncio.CancelledError:
                    process = await startup
                    processes.append(process)
                    raise
                processes.append(process)
                self.process = process
                return process

        # Use the original function code and arguments with a per-call asyncio
        # view. Never patch asyncio globally or modify the external source.
        globals_view = dict(original.__globals__, asyncio=AsyncioView())
        delegated = types.FunctionType(original.__code__, globals_view,
                                       original.__name__, original.__defaults__, original.__closure__)
        delegated.__kwdefaults__ = original.__kwdefaults__
        try:
            return await delegated(self, *args, **kwargs)
        finally:
            for process in processes:
                try:
                    await reap(process)
                except BaseException:
                    # The pinned stop gathers task exceptions. Retain an
                    # explicit failure flag so it cannot acknowledge cleanup.
                    self._t2_child_cleanup_failed = True
                    raise
                if getattr(self, 'process', None) is process:
                    self.process = None
    return owned
