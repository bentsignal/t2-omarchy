# Session-wide AMD rendering trial

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
