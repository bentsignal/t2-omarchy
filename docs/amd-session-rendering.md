# Session-wide AMD rendering trial

**Current outcome: battery acceptance failed. Intel-first rendering has been
restored and verified active after Shawn logged in on September 12. The Dell
output is active again at 2560×1440, 59.951 Hz; Shawn confirmed the Dell is displaying again.** The live controller was returned to Auto after the dock recovery checks (high
on AC with the Performance profile).
The seamless performance/battery requirement remains unresolved.

September 11, 2026: Shawn confirmed approximately **28 FPS in the normal Intel
browser and 60 FPS in the separate AMD browser**. The offload configuration
restored performance but failed the usability requirement: the same normal
browser and applications must retain access to AMD without separate profiles
or relaunching them each time the power mode changes.

## Installed configuration

`~/.config/uwsm/env-hyprland` now contains the repository's
`tools/graphics/env-hyprland-amd-render.fragment`. It applies only in the hybrid
boot and selects:

- AMD first, Intel second in Aquamarine's DRM device list.
- AMD as Mesa's default render-offload device via `DRI_PRIME`.
- AMD as Mesa Vulkan's preferred device via `MESA_VK_DEVICE_SELECT`.

Intel still owns the physical internal panel through the existing gmux boot
option. The experiment moves compositor rendering to AMD and makes AMD the
normal application-rendering preference. The existing controller continues to
change AMD low/high DPM live. This changes the earlier Intel-first rendering
assumption; **battery consumption and actual application selection must be
remeasured**. It is not a claim of migrating live graphics contexts between
GPUs, and applications with explicit device selection may ignore the defaults.

Shawn logged out and back in on September 11. **The desktop and normal browser
now select AMD**, and a live low/high cycle preserved their processes. No reboot
was needed for this session change. Whether the normal browser matches the prior
60 FPS game result remains a live acceptance test.

Saved original environment:
`~/.config/uwsm/env-hyprland.intel-backup.20260911-171229`.

The popup has been simplified now: removed the duplicate `AMD: Performance
(override)` status line, the separate-browser launch button and its description.
Driver/control errors remain visible only on failure. The AMD header,
Auto/Performance/Power saver buttons, and a short automatic-policy description
remain. The separate browser profile is preserved as user data; the CLI remains
available for diagnostics but is no longer presented as the intended workflow.

## Why this is a power-level switch, not GPU migration

Chromium's `SwitchableGPUsSupported` implementation returns false outside its
macOS build path. Mesa's DRI_PRIME and Vulkan selection variables select a
rendering device when applications establish their graphics resources. These
mechanisms do not provide a system-wide migration service for existing contexts.

Sources:
- [Chromium switching implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/gpu/config/gpu_switching.cc)
- [Mesa environment variables](https://docs.mesa3d.org/envvars.html)
- [Hyprland multi-GPU configuration](https://wiki.hypr.land/configuring/extra/multi-gpu/)

Keeping apps on AMD allows power-level changes without GPU migration, but keeps
AMD involved in normal rendering on battery. The previous 18–19 W quiet samples
cannot be carried over as a promised result. Truly transparent Intel/AMD
migration across arbitrary applications would require support beyond this
menu, environment configuration and DPM controller.

## Acceptance after the initial login

1. Check the actual Aquamarine primary renderer and Mesa device selection.
2. Check WebGL renderer in the normal browser with its original user profile.
   No new browser profile or browser-specific launcher should be needed.
3. Keep the same game tab open and change AMD Performance → Power saver →
   Performance. Confirm recovery toward 60 FPS without relaunching the browser,
   context-loss errors, GPU resets or display disruption.
4. Verify a representative native accelerated application, not only Chromium.
5. Measure battery draw under matched brightness and screen activity; unplug
   to verify automatic low and plug in to check the AC policy. Record any
   increase over the previous Intel-rendered baseline.

## Post-login verification

After Shawn's logout/login:

- Hyprland's environment contains all three AMD selection variables. Aquamarine
  logs explicitly select card2 (amdgpu) as primary, with Intel secondary.
- Both the internal eDP-1 (3072×1920, 60 Hz) and external Dell DP-10
  (2560×1440, approximately 75 Hz) are active. Hyprland reports no config errors.
- Opening a local WebGL check with ordinary `/usr/bin/helium-browser`, without
  special launch flags or a separate profile, reports WebGL2 enabled and
  `ANGLE (AMD, AMD Radeon Graphics …)`. Its GPU process opens renderD129.
- At 20:11 EDT, the controller switched Power saver → Performance → Auto on AC.
  Both socket status and the kernel's DPM attribute confirmed low then high.
  Hyprland PID 2191398 and normal Helium GPU PID 2314397 stayed unchanged,
  including their DRM device handles. Auto restored high because the AC power
  profile was Performance. No GPU warnings appeared during this bounded test.

There were earlier amdgpu `Adding stream … to context failed with err 28!`
messages during login/output setup around 20:02. Both outputs were subsequently
active; these warnings are recorded rather than treating the entire login as
error-free. Process survival alone does not prove absence of WebGL context loss.

Game FPS, a representative native application's renderer, actual cable-change
behavior and matched battery draw remain unverified in this AMD-first session.
The test was on AC with an external display, so it provides no comparable idle
battery measurement. Syntax checks and popup reload had already passed before
logout. Logout/login also does not validate the repaired boot-menu hash warning;
that still needs the next actual reboot.

## Rollback

Restore the original renderer for the next login:

```bash
cp tools/graphics/env-hyprland.fragment ~/.config/uwsm/env-hyprland
```

Then log out/in when ready. The previous Intel-rendered hybrid configuration
returns, retaining the cleaned-up popup and live AMD power controller. If the
experimental session cannot display a usable desktop, the existing AMD boot
entry does not include the hybrid marker, so this conditional environment
configuration does not apply there. The GPU-disabled recovery entry also
remains available. Do not delete either browser profile as part of rollback.


## Battery regression and rollback preparation

Shawn subsequently reported expected game performance on AC, but approximately
40 W after unplugging and reopening the normal browser. Auto, Performance and
Power saver appeared ineffective, with the game still reaching 60 FPS. This is
a user observation, not a controlled idle comparison. The previous roughly
20 W browsing behavior is the desired battery target.

Read-only service logs confirm an actual cable transition selected low at
20:14:21 (AC=False), followed by high on reconnect at 20:17:14. During diagnosis
the machine was charging, so battery current cannot be interpreted as total
system consumption. GPU telemetry showed 15–18 W in high. Setting Power saver
was accepted by the controller and kernel; after eight seconds AMD still
reported 14 W and 750 MHz memory, despite a low DPM readback. Five subsequent
samples reported 14–15 W and 750 MHz. These are AMD sensor measurements, not
whole-system measurements. Sustaining 60 FPS alone does not establish that a
power limit failed; the GPU power readings establish that this configuration
has an excessive GPU baseline for the stated battery goal.

A newly enumerated Dell DP-11 output appeared at 0×0 in Hyprland while the kernel
reported its connector connected but disabled. Repeated stream-add err 28
messages accompanied the cable changes. Temporarily disabling DP-11 through
Hyprland did not lower the measured GPU power. The original monitor rules were
then restored with reload and produced no config errors. This experiment does
not establish the cause of the pinned memory clock; rendering topology and
driver/display state remain possible contributors.

The installed env-hyprland now matches the Intel-first fragment, which explicitly
unsets the two AMD application-selection variables from the trial. The AMD
configuration was backed up alongside it. No session termination, GPU reset,
unbind or reboot was performed. The rollback needs a user-initiated logout/login
and a fresh battery measurement before calling the earlier baseline recovered.
Normal apps will again default to Intel, so this rollback sacrifices the trial's
automatic AMD rendering; the existing low/high menu cannot migrate their live
graphics contexts. A complete dynamic solution remains outstanding.


## Dock display regression: recovery still pending

Shawn confirmed the dock provides both charging power and the external display,
and that the Dell now shows no signal. This identifies the 0×0 output as an
actual user-visible regression, not a harmless phantom. The previous fixed
DP-10 rule no longer matched DP-11 after reconnection. The installed monitor
rule now matches `desc:Dell Inc. DELL S2721DS 6RW0VY3` and requests 2560×1440 at
59.95 Hz with the existing layout. The reproducible snippet is
`tools/graphics/monitors-dell-dock.fragment.lua`. The original local file was
backed up. Description matching follows the
[Hyprland output-selection documentation](https://wiki.hypr.land/configuring/core/monitors/output-selection/).

Reload and config validation passed, but **the external display is not yet
restored**. Setting AMD high and requesting the conservative mode still left
DP-11 at 0×0. Aquamarine reports failed atomic modeset tests/commits with Invalid
argument, alongside the kernel stream-add failures. The connector-name fix
addresses persistent configuration but does not repair the current driver state.
The next bounded recovery step is a user-initiated dock unplug/replug, followed
by checking actual output size, kernel connector enable state and visible signal.
If that fails, the already-prepared Intel-first configuration needs logout/login.
Do not claim either step succeeded before observing it.

Shawn completed the requested dock unplug/replug; the display remained dark.
At 20:26 the driver again emitted stream-add err 28 failures. DP-11 remained
0×0 in Hyprland and connected/disabled in DRM, while AMD was confirmed high
(Auto, AC, Performance profile). Thus reconnecting and raising GPU power did
not restore the display. Intel-first next-login configuration was rechecked;
the next recovery checkpoint is a user-initiated logout/login with the dock
attached. Display recovery and battery savings remain unverified.


## September 12: Intel-first session active, artifacts reported

Shawn logged out/in with the dock connected, reporting a transient large black
square on the login screen and pink rectangles when switching T3 Code threads
the previous evening. Neither artifact was captured or reproduced by the agent.

The new Hyprland PID 2739454 has Intel-first AQ_DRM_DEVICES and no DRI_PRIME or
MESA_VK_DEVICE_SELECT trial variables. Aquamarine confirms card1 primary. T3 Code
GPU PID 2741510 opens Intel renderD128. The internal panel is active at
3072×1920/60 Hz; Dell DP-11 is now 2560×1440/59.951 Hz at the saved position.
Config errors are empty. This verifies output activation, not user-visible
artifact resolution or dock hotplug reliability.

The transition exposed two symbolized SIGSEGV records: the old session Hyprland
PID 2191398 at 11:51:37, and UID 962 Hyprland PID 2739132 at 11:51:46. Both crash
in Aquamarine CDRMBackend::flushAsyncCommitEvents, called by cancelAsyncOutput,
SDRMConnector::disconnect, backend destructors and process exit. The evidence
places these crashes in display-backend teardown, rather than proving a live
rendering fault caused the reported colored rectangles. Other recorded threads
are waiting on commit queues or GLib/IPC loops. The second process's core itself
is inaccessible to this user; the journal-provided symbolic stack is available.
WirePlumber SIGSEGV and an old T3 Code SIGBUS also coincide with session exit;
no causal relationship or data loss was established. No OOM messages appeared
in the inspected transition window; current available RAM is 8.6 GiB.

Repeated amdgpu stream-add err 28 messages occur during the transition through
11:51:48. The new session's recent compositor log tail has no ERR entries.
Installed graphics versions: Hyprland 0.56.2-2, Aquamarine 0.15.0-2, Mesa
26.2.2-1, linux-t2 7.2.4.arch1-1. All four were upgraded September 11 around
09:35–09:36, before the renderer trial, so configuration changes are not the only
changed variable. The artifact cause remains unresolved. No driver toggles,
package changes, resets or session restarts were performed for this diagnosis.
Next checks: user-visible Dell output and whether T3 thread-switch artifacts
still occur in this Intel-rendered session; battery measurement remains pending.


## September 12: cross-display cursor mitigation

Shawn confirmed the Dell works and reported no recurrence of the earlier pink
T3 thread artifacts in the current session. Moving the pointer to the Dell
briefly produced a large black square; crossing back and forth cleared it.
This specifically implicates cursor presentation as a hypothesis, without
proving its root cause or explaining the earlier login-screen square.

Installed `tools/graphics/cursor-hybrid.fragment.lua` at the end of the user's
`~/.config/hypr/looknfeel.lua`, after backing up that file. It sets
`cursor.no_hardware_cursors = 1` only with the hybrid boot marker. Reload passed
with no config errors. Both eDP-1 and DP-11 retain their resolutions and report
`hardwareCursorsInUse: false`. No logout or app restart was needed.

This uses the documented
[Hyprland cursor option](https://wiki.hypr.land/configuring/core/config-options/#cursor).
Visual acceptance still requires moving the pointer between screens; software
cursor rendering may add work during pointer motion and its battery impact is
unmeasured. It applies to Shawn's desktop, not the separate login greeter.
Rollback: remove the appended cursor block from looknfeel.lua and reload.
The display teardown crashes and original seamless GPU-switching requirement
remain unresolved; this is a scoped cursor workaround.
