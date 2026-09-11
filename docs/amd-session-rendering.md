# Session-wide AMD rendering trial

September 11, 2026: Shawn confirmed approximately **28 FPS in the normal Intel
browser and 60 FPS in the separate AMD browser**. The offload configuration
restored performance but failed the usability requirement: the same normal
browser and applications must retain access to AMD without separate profiles
or relaunching them each time the power mode changes.

## What is prepared

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

The change is **prepared for the next graphical login, not yet validated**.
The running session still uses the old renderer environment. No logout or
reboot has been performed by the agent. One initial logout/login is needed to
start the compositor and normal browser in the new configuration. Subsequent
low/high toggles should leave those same processes and contexts running.
Whether this matches the prior 60 FPS result remains a live acceptance test.

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

Syntax was checked for the installed environment; the running shell reloaded
without QML errors after the popup cleanup. Hardware acceptance above is still
pending and cannot be replaced by syntax checks.

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
