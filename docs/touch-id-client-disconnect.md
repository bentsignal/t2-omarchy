# Touch ID client-disconnect cleanup and OUT diagnostics

September 6, 2026, 18:53 EDT. Latest measured readiness remains **4.982 s**.
These changes have not had a live sleep or fingerprint acceptance control.

## Missing cancellation trigger

The 18:37 control had a pre-sleep UI/PAM abort but no backend verification-stop
entry. The pinned facade does not track the claiming D-Bus connection or react
to its disappearance. Fixing the order inside VerifyStop cannot help when the
client exits without sending that method.

`t2_fprintd_owner.py` now subscribes to the system bus's NameOwnerChanged signal
before the facade acquires its public bus name. It records the bus-supplied
unique sender only after the original synchronous Claim method succeeds. Failed
claims do not change ownership. All original Claim argument/user checks remain.
Only an exact signal from `org.freedesktop.DBus` that the claiming unique name
has vanished schedules cleanup. Other clients' exits and lookalike signals do
nothing. No unique sender names or user identities are logged.

Cleanup enters the existing stop path, which cancels the verification coroutine
before terminating/reaping its child. It clears the abandoned claim after stop
completes. Stop operations are serialized; ownership/generation is checked again
inside that serialization so delayed cleanup cannot stop a newer claim. A failed
cleanup retains the claim and reports failure without private exception text.
The handler adds cleanup, not new authentication or enrollment permissions.

The expected pre-sleep sequence is now UI abort, client disconnect, backend stop,
child exit/lock release, then freeze. A real test must establish that Omarchy's
PAM abort actually disconnects in time. There is no new logind delay inhibitor
or pre-freeze acknowledgement from the daemon in this change. If the client
survives the abort, explicit bounded backend preparation remains necessary.

## Child ownership across cancellation

The original fallback discovery child was not assigned to `backend.process`.
Cancellation of its coroutine could leave it running. Process creation also has
an await boundary at which cancellation can lose the eventual child.

`t2_fprintd_process.py` delegates the pinned discovery/probe functions through a
per-call asyncio view that tracks spawned children. It executes their original
code and preserves command arguments and result parsing; it neither edits the
reference source nor patches asyncio globally. Creation is shielded until the
child is tracked. Finally cleanup terminates the child if needed, drains its
remaining output privately, and reaps it. There is a two-second termination
window, then kill and a 0.5-second drain/wait bound. Failed cleanup propagates and sets a sticky backend failure flag because the
pinned stop gathers task exceptions. Stop refuses acknowledgement while that
flag is set; daemon restart is required after investigating such a failure. Direct-directory creation also
retains/reaps an eventual child on cancellation.

Output is discarded during cleanup, never journalled. The original endpoint
validation, cached retry on genuine failures, negative-match behavior, operation
lock, identity checks, and original positive verdict remain in force. No PAM
configuration, fingerprint store, enrollment, or network state was changed.

## Validation and deployed files

- 208 research tests completed, five expected environment/platform skips.
- All 31 fprintd-specific tests passed under the installed runtime virtualenv.
  Earlier unchanged pre-arm runtime tests also passed during this work.
- An isolated dbus-daemon test runs the pinned FprintDevice with a harmless child
  holding a temporary flock. Disconnecting the owning client without VerifyStop
  terminates/reaps the child and frees the lock; disconnecting another client
  leaves it running. No sensor or system bus is used by this test.
- Additional tests execute the real pinned discovery/probe functions against
  harmless temporary children, verify cancellation during creation, drain full
  pipes, preserve successful outputs, reject spoofed/stale owner-loss events,
  and preserve claims when cleanup fails. Existing positive/negative decisions
  and the stop-order regression continue to pass.
- The final installed daemon accepted two successive root idle Claim/disconnect
  checks on the real system bus. Both logged stop/claim release; neither sent
  VerifyStart, requested a finger, or sent a device command. This validates live
  bus subscription and claim cleanup, not a real probe cancellation or wake.

Installed root-owned mode 0755 under `/usr/local/libexec`:
`t2-fprintd-runtime.py`, `t2_fprintd_owner.py`, `t2_fprintd_process.py`.
Repository and installed bytes match. Deployment and service restart were under
the operation lock while the desktop was unlocked and not authenticating.
fprintd is active. No desktop-shell restart was required.

Full pre-change facade backup:
`/usr/local/libexec/t2-owner-backup-20260906-184854/t2-fprintd-runtime.py`.
While unlocked/idle, restore that file under the operation lock and restart
fprintd to roll back this entire change. The unused helper modules can remain.
An intermediate owner-only checkpoint is preserved separately under
`/usr/local/libexec/t2-owner-complete-backup-20260906-185324/`.

## Driver OUT-completion investigation

The read-only reference is `deqrocks/t2bce` at
`a973d53c8278e9db5ff8314b816d6880309ed39e`. The baseline `transfer.c` SHA-256 is
`4c6ec4d63d1f7bd8f9bdcdb721022ba7de81a3c15f1ef5177e56e1180306f53c`.

The OUT path waits for a firmware transfer request, reserves a submission,
increments `sq_out_pending`, and rings the DMA doorbell. DMA completion dispatch
validates the completion queue/index before reaching the VHCI callback. That
callback accounts OUT completions and wakes the pending-output wait. Thus an
active/resumed endpoint flag does not establish that this whole path progresses.
The next trace needs to distinguish missing requests, submissions without
completions, and callback/accounting problems. No source-level candidate has yet
been established as the cause of the live stall.

`tools/research/t2bce-bulk-out-trace.patch` adds diagnostic logging only for bulk
OUT queues: firmware request, before/after submission doorbell, normal/aborted/
no-URB completion, and resume of an existing URB. Records contain stage, physical
virtual-port mapping, firmware device number, endpoint, state flags and pending
count. They omit DMA addresses, data buffers and protocol/biometric payloads.
The logging is dynamic-debug gated and rate-limited. Missing lines alone cannot
prove missing events because the rate limiter can suppress records.

Firmware device numbers are not Linux USB devnums: the reference maps
`udev->portnum` through `port_to_device[]`. The diagnostic includes the virtual
port to avoid identifying a queue from its firmware device number alone. The
validated network USB device is `7-1`, Apple `05ac:8233`; inspect the exact mapping
again in a future kernel test.

Validation: patch applies cleanly to the pinned reference. A clean `git archive`
of its tracked source was extracted to `/tmp/t2bce-bulk-out-build-iyw2ym3a`, and
the patch was applied only there. A resource-bounded `make -j2 modules` for
`t2bce_vhci` against the running kernel headers completed through compile, link,
modpost and BTF. The diagnostic module is **not installed or loaded**. Full source
identity with the packaged module is not established by a successful build.
External reference checkouts and kernel binaries remain unchanged.

Do not hot-unload the shared T2 controller to try this diagnostic: it also serves
input devices. A future kernel test needs a separately prepared boot/rollback
path and Shawn ready. Check the client cleanup change first with the installed
kernel; that experiment can clarify whether quiescing traffic before sleep
changes the network failure without introducing a driver replacement.

All four earlier suspend/resume debug sites are still disabled. No new trace
sites are armed, and no new sleep was initiated during this work.
