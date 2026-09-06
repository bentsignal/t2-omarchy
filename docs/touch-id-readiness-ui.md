# Touch ID readiness UX and Touch Bar investigation — 2026-09-06

## 17:32 control: old ready cue persists; pre-freeze preparation added

Shawn explicitly observed the premature ready cue again. Do not mark the
previous file-watcher fix visually accepted. The journal places root
`sleeping` publication at 17:20:15.982061, followed by user.slice freeze at
17:20:16.010360: only **28.3 ms** later. An asynchronous watcher/redraw is not
guaranteed in that interval; after thaw, the prior rendered surface can still
be visible before callbacks run. This is the leading timing explanation, not
a captured frame-by-frame proof.

New implementation, following the Omarchy skill's user-owned customization
boundary (no packaged edits):

- A supplementary user service `t2-touchid-sleep-ui.service` holds a **delay**
  inhibitor and listens for logind's `PrepareForSleep(true)`. It does not
  replace or weaken Omarchy's existing secure-lock monitor.
- Before user.slice freezes, it calls the cloned lock's `prepareTouchIdSleep`
  IPC method with a one-second subprocess timeout and an 0.8-second IPC timeout.
  The view synchronously latches non-ready, advances its scan epoch, stops
  fingerprint retries, and aborts the old PAM fingerprint attempt. Password
  authentication and the session lock remain intact. Late fingerprint-finished
  callbacks cannot unlock while this preparation latch is active.
- After the exact `prepared` reply, allow **250 ms before sleep** for rendering,
  then release the inhibitor. Failure releases it without the grace. logind's
  overall delay ceiling remains authoritative; nothing blocks sleep indefinitely.
- The latch survives stale file reloads and clears only after a root-published
  `available` transport timestamp newer than preparation. Readiness still needs
  a fresh actual scan cue. Password unlock also clears the latch. A failed or
  cancelled sleep without fresh recovery metadata may therefore require password;
  this is a conservative fallback, not an authentication failure.

This uses the synchronous-preparation pattern described in systemd's
[inhibitor-lock documentation](https://systemd.io/INHIBITOR_LOCKS/). Low-level
sleep that bypasses logind will not deliver this signal. A 250-ms render grace
is not proof that a compositor/output which is already off has displayed a new
frame; the next real wake still needs visual acceptance.

Installed root-owned helper: `/usr/local/libexec/t2-touchid-sleep-ui.py` (0755).
User-owned enabled unit: `~/.config/systemd/user/t2-touchid-sleep-ui.service`.
Both sources are under `tools/research/`. The monitor uses the installed stock
monitor's one-signal/process-exit/restart pattern, with `RestartSec=2`, a 64-MiB
memory cap, 16-task cap, and 50% CPU quota. It blocks on D-Bus input when idle;
observed idle memory was 6.8 MiB. No new Omarchy hook exists for this phase, so
the supplementary user unit is used rather than modifying a stock script.

During deployment, hot reload did not expose the new IPC/status field, and a
plugin rescan temporarily left the lock IPC target absent. The desktop was
confirmed unlocked before editing and remained unlocked. `omarchy restart shell`
restored the live handler; status then explicitly included
`fingerprintSleepPrepared=false`. Future agents must verify that field and not
assume a successful file save means the new Service.qml is active. Never restart
the shell while actually locked.

Without sleeping or requesting a finger, the real IPC acknowledged preparation
and status showed `fingerprintSleepPrepared=true`, `fingerprintReady=false`,
and no active authentication. A healthy root recovery check subsequently
published fresh availability, cleared the latch, and performed **no rebind**
or biometric commands. Service activation, inhibitor registration, plugin
validation, reverse patch dry-run, and 193 research tests (two expected skips)
passed. This proves metadata/control flow, not wake presentation or a new scan.

Rollback: while unlocked, `systemctl --user disable --now t2-touchid-sleep-ui.service`.
If the UI latch remains from interrupted preparation, perform a healthy recovery
check or use password unlock; do not fabricate a ready status. To restore the
previous presentation entirely, restore this clone's Service.qml/TouchIdStatus.js
from the previous repository patch checkpoint and restart the shell while
unlocked. Do not remove the normal Omarchy secure-lock sleep service.

The combined next test also includes finer interface-up polling; measured
5.240-second wake and remaining delay breakdown are in
[pre-arm latency](touch-id-prearm-latency.md). No further suspend has been issued.

## September 6 follow-up: clear stale readiness across sleep

The first guarded early-recovery run reached actual sensor-ready in **5.666 s**
after resume, down from 12.724 s. Shawn saw a misleading initial touch cue before
the waiting message. The plugin cached both its status files and its `Date.now()`
value in a timer that freezes with the session; it did not watch status changes.
Also, sleeping metadata older than 90 seconds stopped deferring verification.
The four-minute sleep in this run exposed that latter issue: a premature
discovery attempt raced recovery, failed, and was subsequently retried after
transport returned. No false-match decision was made.

The user-owned `shawn.lock` plugin now:

- Watches both status files and refreshes its clock in load callbacks.
- Hides readiness while fresh status reads are pending, including a paired
  refresh after a transport change or a long timer gap.
- Requires a scan cue newer than the current lock request; previous-lock ready
  records cannot advertise a usable sensor.
- Keeps a sleeping transport non-ready even after a long sleep, until the
  recovery hook publishes the next state. The password path stays available.

No continuous animation loop, additional sound, packaged Omarchy edit, or PAM
success-rule change was added. Per the Omarchy skill, the patch is applied only
to the existing user-owned clone and persisted in
`tools/research/omarchy-touchid-status.patch` plus `TouchIdStatus.js`.
The clone hot-reloaded successfully while unlocked. Plugin validation, reverse
patch dry-run, and 173 research tests (two expected skips) passed. Shared-model
tests cover pending refresh, previous-lock timestamps, long-sleep deferral, and
current sensor readiness. The absence of a stale cue on the very first visible
frame still needs a supervised wake; do not claim that visual check passed yet.

## Current scope decision

The active order is now documented in [implementation priorities](touch-id-roadmap.md):
verification/resume performance first, Linux-native enrollment next, Touch Bar
work deferred. That roadmap includes the measured 36-second wake-to-ready trace.

Shawn accepted the lock-screen presentation and explicitly deferred Touch Bar
work. Leave its hardware mode, native function row, drivers, and renderer alone.
The research below is retained as a future reference, not an active installation
plan. Focus on the underlying Touch ID implementation and wake latency.

The next user-approved action is a timed sleep/wake with the visible readiness
hint. The status publisher now logs only “Touch ID sensor accepted scan; UI
ready.” when it publishes a real accepted scan cue, so the first post-wake cue
can be correlated with suspend/resume and recovery journal timestamps. This
contains no biometric identity or authentication verdict. It is needed because
the live status file is replaced by `idle` after completion. Do not infer a new
negative control or an exact wake time from the user's acceptance of the UI.

## Confirmed automatic recovery

Shawn confirmed an enrolled-finger unlock after the third supervised sleep/wake
test. The journal shows suspend at 13:23:46 EDT, resume at 13:32:10, first CDC-NCM
TX watchdog at 13:32:17, interface rebind at 13:32:20, and transport recovered at
13:32:22. This was **automatic** recovery with no manual intervention or fprintd
restart after wake. The measured transport delay was about 12 seconds; the
30-second instruction was a test margin, not a measured requirement.

Shawn correctly identified two remaining problems: slow recovery and no visible
distinction between an enrolled sensor and one actually ready to scan. Custom
Touch Bar prompts are also requested. Native enrollment remains paused at the
status-55 event-overlay checkpoint while this verification UX is validated.

## Changes deployed

### Coarse, non-authoritative status feed

Root-owned helpers publish two atomic, world-readable metadata files under
root-owned `/run/t2-touchid-ui` (0755). Files are mode 0644 and contain only
`schema_version`, `channel`, `state`, and a timestamp. They contain no fingerprint
UUID, password, user identifier, biometric template, network address, operation
ID, or authentication token. **These files never authorize a login.**

- `transport.json`: `sleeping`, `recovering`, `available`, or `unavailable`.
- `scan.json`: `starting`, `ready`, `idle`, or `unavailable`.

The sleep-target hook publishes `sleeping` before sleep. Recovery publishes its
start and result. The pinned fprintd wrapper publishes `ready` only from the
original parser's exact accepted-start cue, not when fprintd starts or lists an
enrolled finger. Cancellation/completion clears readiness, and exceptions mark
the scan unavailable. The original pinned matcher still owns every positive
identity/lifecycle verdict. Failure to publish UI metadata must not change an
authentication result. The original external runtime is unmodified.

`t2_touchid_status.py` is installed under `/usr/local/libexec` alongside both
runtime wrappers. The three systemd units/drop-in declare the runtime directory;
the fprintd drop-in permits writes only to this additional directory within its
otherwise read-only filesystem. The metadata directory is preserved across unit
stops, but scan readiness is timestamp-limited and transport recovery has a
finite presentation lifetime, so stale status does not advertise readiness.

### User-owned Omarchy lock screen

Following the Omarchy skill, `omarchy plugin clone omarchy.lock` created
`~/.config/omarchy/plugins/shawn.lock`. No `/usr/share/omarchy` file was changed.
The settings backup before cloning is
`/home/shawn/.local/state/t2-touchid-ui-backup.2vGHUK/shell.json`.

The clone now shows a persistent hint below the password field:

- “Touch ID waking up — password available” during recovery.
- “Touch ID preparing — password available” until the scan has been accepted.
- “Touch and hold your finger to unlock” only after the real sensor cue.
- “Touch ID unavailable — use password” for unavailable/missing status.

The fingerprint icon also requires current scan readiness. The existing password
flow is unchanged. New fingerprint attempts are deferred while the transport
explicitly reports a bounded recovery, then resumed on the waiting-to-available
transition. UI polling does not bypass the existing retry timer. The display
blank timer is 15 seconds rather than five when fingerprint login is configured;
locking remains immediate and secure. This does not turn off system sleep.

Source changes are persisted as `tools/research/omarchy-touchid-status.patch`
plus `TouchIdStatus.js`; they are not a fork of the entire Omarchy tree. Exact
original file hashes for this patch:

```text
Service.qml  3f0a265a09f7957e8f5d74666595d3136ec64899c414426190460f9e2098e701
LockView.qml ddc05881b571c1ffc526d751a83002649d873969a2fd66297b347c152ac6111b
```

To reproduce, check those source hashes, clone the packaged lock plugin with
Omarchy's command, review/apply the patch inside the clone with `patch -p1`,
and place the shared JS beside its QML files. Install the root-owned status
publisher, matching/recovery wrappers, and updated unit templates together.
Reload systemd, restart fprintd under its operation lock, and run the healthy
recovery check to initialize transport status. Do not copy a username-specific
full `shell.json` onto another machine.

On this installation, hot reload retained old IPC handlers; a desktop-shell
restart **while unlocked** was necessary. Verify `omarchy shell lock status`
exposes `fingerprintReady` and `fingerprintStatus`, and that password PAM remains
available. Never restart the desktop shell while the actual lock is active.

Rollback while unlocked: disable `shawn.lock`, enable `omarchy.lock` using
Omarchy's plugin commands, and restart the shell. This preserves the clone for
inspection. The status feed can remain installed harmlessly. Removing the daemon
overlay uses the earlier [resume recovery rollback](touch-id-resume-recovery.md).
Restoring the entire saved shell configuration would also revert unrelated later
desktop edits; prefer the targeted plugin rollback.

### Latency adjustment, not an instant-wake claim

The successful trace had roughly three seconds between the first watchdog and
the rebind. The evidence loop previously slept one second and could block two
more seconds in each TCP probe. It now uses 250 ms intervals and a 250 ms probe
timeout **only during that evidence-wait phase**. The initial probes, exact
hardware validation, actual TX-error requirement, operation lock, and one-rebind
limit remain. This should reduce avoidable observation delay, but a faster
post-wake time has not yet been measured. The underlying driver stall and its
roughly five-second watchdog still need a transport/kernel-level fix for truly
immediate readiness. No broad T2 reset or speculative kernel replacement was
performed.

## Touch Bar: primary-source findings, not installed yet

The requested Grok headless CLI was available. A bounded read-only research run
reported that X search was not available in that invocation and returned no
usable original post citations. Do not claim that Twitter was exhaustively
searched or invent social-post evidence. Public GitHub sources were checked
directly instead.

Promising sources:

- [AsahiLinux/tiny-dfr](https://github.com/AsahiLinux/tiny-dfr), inspected at
  `eb711c87fcbddda67be3fd5ff45385b139e8fb34`. Its
  [udev rule](https://github.com/AsahiLinux/tiny-dfr/blob/eb711c87fcbddda67be3fd5ff45385b139e8fb34/etc/udev/rules.d/99-touchbar-tiny-dfr.rules)
  switches Apple USB `05ac:8302` from configuration 1 through 0 to 2 and associates
  the graphics/input devices with the renderer service.
- [niraj-envision/touch-bar](https://github.com/niraj-envision/touch-bar), inspected
  at `e484037829bf3c6d41932d735522da18e71d0837`. Its
  [renderer controller](https://github.com/niraj-envision/touch-bar/blob/e484037829bf3c6d41932d735522da18e71d0837/src/omarchy-touchbar)
  updates tiny-dfr's live configuration and generated SVG graphics from desktop
  context. This provides a concrete dynamic-text/rendering approach, not evidence
  that it already implements our authenticated Touch ID readiness protocol.
  Its installer also changes ownership of `/etc/tiny-dfr`, adds user integration,
  and installs a display-specific post-resume rebind. None of that installer was
  executed here.

Local read-only inventory: USB Touch Bar display `7-6` is `05ac:8302`, exposes two
configurations, and currently selects configuration 1. The HID Touch Bar keyboard
and backlight modules are present. `appletbdrm` is available for this kernel but
not loaded, no Touch Bar DRM card is exposed, and no tiny-dfr package/service is
installed. The existing two DRM cards are the normal laptop GPUs, not the bar.

Next Touch Bar work: establish a separately reversible configuration-2/renderer
test, retain a way back to the existing native function row, then render the same
coarse readiness feed. Lock-screen rendering must take precedence over app titles
or contextual shortcuts; never make a rendered “ready” label or a bar tap grant
authentication. Do not copy an external reset script wholesale or confuse display
USB `7-6` with the biometric transport interface `7-1:1.0`.

## Verification and next human checkpoint

- 153 research tests pass, two expected environment/platform skips. Seven
  matcher-overlay tests also pass in the installed runtime's Python environment.
- Shared JavaScript model tests reject stale/future/pre-recovery cues and absent
  transport state. Publisher tests cover allowed states, public-only fields,
  root-only writes, atomic replacement, and nonfatal publication failures.
- The real runtime import and original positive/negative verdict checks pass;
  cancellation/error clears a previously emitted readiness cue.
- Omarchy plugin validation, systemd unit validation, and reverse-patch dry run
  pass. Live IPC exposes the new hint and confirms password PAM remains available.
- A non-locking preview was visually inspected, then closed. It showed the new
  hint correctly. This is layout validation, not a successful authentication test.
- Run tests with `tools/research/run-bounded.sh`, which limits real memory via a
  cgroup. A 1-GiB virtual-address-space `ulimit` caused Node/V8's reserved address
  space initialization to fail; the same tests passed under the proper cgroup
  limit. No whole-system out-of-memory event was observed during this work.

Next: the user-approved sleep/wake using the visible readiness message instead
of a counted 30-second wait. Measure resume-to-transport and resume-to-first-ready
separately; user reaction time is not device startup time. Touch Bar work is
explicitly deferred, and no Touch Bar hardware mode change has been made.
