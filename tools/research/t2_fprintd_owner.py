# SPDX-License-Identifier: MIT
"""Release an abandoned fprintd transaction when its D-Bus client disappears.

The bus supplies the unique sender identity. This observes ownership for cleanup
only; the pinned Claim implementation still decides whether a claim is accepted.
"""
import asyncio
from t2_touchid_status import publish

MATCH = "type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'"


class OwnerTracker:
    def __init__(self, namespace):
        self.ns = namespace
        self.device = None
        self.owner = None
        self.generation = 0
        self.tasks = set()

    def handle(self, message):
        ns = self.ns
        device = self.device
        if device is None:
            return False
        if (message.message_type == ns['MessageType'].METHOD_CALL
                and message.path == ns['DEVICE_PATH']
                and message.interface == 'net.reactivated.Fprint.Device'
                and message.member == 'Claim' and message.signature == 's'
                and len(message.body) == 1
                and isinstance(message.sender, str) and message.sender.startswith(':')):
            # Claim is synchronous in the pinned facade. Do not record failed
            # claims, and return exactly its existing empty successful reply.
            device.Claim(message.body[0])
            self.owner = message.sender
            self.generation += 1
            return ns['Message'].new_method_return(message)
        if (message.message_type == ns['MessageType'].SIGNAL
                and message.sender == 'org.freedesktop.DBus'
                and message.path == '/org/freedesktop/DBus'
                and message.interface == 'org.freedesktop.DBus'
                and message.member == 'NameOwnerChanged'
                and message.signature == 'sss'
                and self.owner is not None
                and message.body == [self.owner, self.owner, '']):
            task = asyncio.create_task(self.release_disconnected(self.owner, self.generation))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        return False

    async def release_disconnected(self, owner, generation):
        if (owner, generation) != (self.owner, self.generation):
            return
        device = self.device
        try:
            print('Touch ID claiming client disconnected; stopping abandoned verification.', flush=True)
            stopped = await device._stop_verification(
                require_running=False,
                owner_check=lambda: (owner, generation) == (self.owner, self.generation),
            )
            if stopped is False:
                return
            if (owner, generation) == (self.owner, self.generation):
                device.claimed_user = None
                self.owner = None
            print('Touch ID abandoned verification stopped; claim released.', flush=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Retain the claim on failed cleanup. Never claim quiescence or
            # include exception text that might contain private protocol data.
            print('Touch ID abandoned verification cleanup failed; claim retained.', flush=True)
            publish('scan', 'unavailable')


def owner_aware_bus(namespace):
    original_bus = namespace['MessageBus']

    class OwnerAwareBus(original_bus):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.t2_owner_tracker = OwnerTracker(namespace)
            self.add_message_handler(self.t2_owner_tracker.handle)

        async def connect(self):
            await super().connect()
            reply = await self.call(namespace['Message'](
                destination='org.freedesktop.DBus', path='/org/freedesktop/DBus',
                interface='org.freedesktop.DBus', member='AddMatch',
                signature='s', body=[MATCH],
            ))
            if reply.message_type != namespace['MessageType'].METHOD_RETURN:
                self.disconnect()
                raise RuntimeError('cannot subscribe to fingerprint client disconnects')
            return self

        def export(self, path, interface):
            if path == namespace['DEVICE_PATH'] and isinstance(interface, namespace['FprintDevice']):
                self.t2_owner_tracker.device = interface
            return super().export(path, interface)

    return OwnerAwareBus
