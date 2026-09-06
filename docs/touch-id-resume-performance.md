# Touch ID: toward subsecond resume readiness

September 6, 2026, 18:28 EDT checkpoint.

Shawn explicitly rejected five-to-eight-second readiness as the usability target.
The target is sensor readiness within one second of wake, followed by successful
matching; do not count a UI cue or a running service as authentication. Current
measurements start at Linux's return-from-suspend event, not the wake keypress.
Keypress-to-visible-frame and keypress-to-unlock remain separate measurements.

## What the evidence establishes

The latest 8.382-second control spent 7.584 seconds reaching the T2 network peer,
then about 0.8 seconds discovering and preparing verification. Earlier cached
verification-to-ready was 525.8 ms. This supports investigating transport first;
it does not establish that subsecond wake is attainable or a hardware minimum.
See [full timing](touch-id-prearm-latency.md).

The latest kernel log reports stateful resume completing successfully, but the
network still needed a rebind. Rebind took 2076.7 ms and logged an endpoint-01
pause timeout waiting for one output. In the read-only reference
`a973d53`, `t2bce_vhci/transfer.c`, queue pause waits up to 2000 ms for pending
OUT completions before requesting firmware pause. Removing that wait would not
explain why the queue stopped making progress. Inspect ownership and completion
flow before changing queue/DMA behavior.

Installed driver: `t2bce_vhci`, module version 0.02, source version
`B8FCE43DDFBFB6770941DC0`, from `linux-t2 7.1.8.arch1-3`, running kernel
`7.1.8-arch1-Watanare-T2-3-t2`. Its dynamic-debug catalog has the same relevant
suspend/resume trace sites and line numbers as the reference. This is useful
correspondence, not proof of complete source identity. The upstream driver is
[deqrocks/t2bce](https://github.com/deqrocks/t2bce); older apple-bce unloading
recipes do not describe this installed split-driver stack.

## Cancellation race reproduced and fixed

The pinned facade's stop method terminated the child and awaited its exit before
cancelling the verification coroutine. A child-exit failure could therefore run
through the stale-cache retry and start discovery while stop was still pending.
A mocked-child test executing the actual pinned facade reproduces two discovery
calls with the original ordering and one with the overlay fix. No hardware I/O
is used in this test.

The repo overlay now cancels the verification task before entering the original
stop method. There is no intervening await: the original backend cancellation
captures the child before the cancelled probe's finally block clears its pointer.
Original child termination/reaping, claim cleanup, errors, match checks, and
negative-match semantics are retained. Stop entry/completion timing is logged.

This is a confirmed source-level race, **not a confirmed explanation for the
18:20 wake**. The pre-sleep PAM abort may never have delivered VerifyStop at all.
New stop timing will distinguish receipt from absence. In-flight subprocess
creation and client-disconnect cleanup also need review if the probe persists.
No new positive/negative scan or suspend control has validated this deployment.

Recovery also logs operation-lock acquisition and interface-up duration
separately. Prior logs combined these into the unaccounted interval before the
resume guard. Instrumentation uses perf_counter independently of deadline clocks;
all deadlines, target checks, probe counts, and rebind limits remain unchanged.

Deployed root-owned wrappers under the operation lock while unlocked and idle;
fprintd restarted successfully. Previous copies are in
`/usr/local/libexec/t2-latency-backup-20260906-182830/`. Installed files match
repository sources. Research suite: 194 tests, three expected skips (macOS and
two installed-venv tests). All 27 runtime tests pass in the installed venv,
including the new original-versus-fixed cancellation regression.

## Next supervised diagnostic control

Four existing dynamic-debug sites were enabled only after checking the loaded
source version and that all four previously had no flags. They report queue
state/ownership at suspend and resume, not transfer payloads or biometric data:

- `transfer.c:480`: system resume (pause owners before/after, firmware resume,
  returned state, active flag).
- `transfer.c:504,515,551`: system suspend (already paused, mark-only, or firmware
  pause).

No transfer-event or per-packet logging is enabled. Changes affect the current
boot only. Exact enabling selectors were:

```text
module t2bce_vhci format "t2bce_vhci: system resume dev=" +p
module t2bce_vhci format "t2bce_vhci: system suspend dev=" +p
```

After the next supervised control, write the same two selectors with `-p`
instead of `+p` to `/sys/kernel/debug/dynamic_debug/control` as root. They were
disabled before this experiment; restore them even if the control fails.

When Shawn is ready, use the normal secure-lock-then-suspend path, verify the
lock, then sleep. Wake by keyboard after roughly 30 seconds asleep, keep the
finger off until the genuine ready cue, then use the enrolled finger. Correlate:

1. Did verification-stop complete before freeze? Did an old probe/discovery
   survive? Do not treat successful UI preparation as backend cancellation.
2. How long did recovery wait for the operation lock versus interface-up?
3. Did the network OUT endpoint clear its suspend pause owner and become active?
   An active flag alone does not prove successful data transfer.
4. Is the rebind still required, and where does post-rebind addressing time go?
5. Measure resume-to-ready separately from touch-to-unlock and user reaction.

Then restore trace flags and record results. A separate supervised negative
finger/password control remains required. No surprise sleep or touch was started
for this investigation. Do not repeatedly tune small waits while leaving the
transport defect unexplained, and keep native enrollment as the next main task.

## Rollback

While unlocked with no active verification/enrollment, take the operation lock,
restore both wrappers from the named backup with root ownership and mode 0755,
and restart fprintd. Remove the four tracing flags as above. No biometric stores,
PAM configuration, external source checkouts, or kernel binaries were changed.
