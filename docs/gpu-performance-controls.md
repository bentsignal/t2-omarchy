# T2 GPU performance controls and maintained boot entries

Current state (September 12): the AMD-first desktop trial failed battery and
dock acceptance and was rolled back. Intel-first browsing measured 26.2 W.
See [current evidence](amd-session-rendering.md). The separate-browser launch
button was removed; the historical launcher section below is diagnostic only.

Implemented September 11, 2026 on MacBookPro16,1, following the
[Intel-primary hybrid measurements](intel-primary-hybrid.md).

## Using the battery popup

The user-owned `shawn.power` clone adds an **AMD graphics** section:

- **Auto:** AMD high DPM on AC, low DPM on battery, independent of CPU profile.
- **Performance:** AMD high DPM, including on battery.
- **Power saver:** AMD low DPM, including on AC.

Manual selections remain selected across cable and CPU-profile changes.
Select Auto explicitly to resume automatic cable policy. Service restart or
reboot currently initializes Auto; cross-reboot manual persistence is not
implemented. CPU-profile popup actions no longer reset AMD selection.
The CPU's existing Omarchy AC/battery profile preferences continue to apply.

“Power saver” means low DPM, not electrical GPU shutdown. “Performance” enables
AMD high DPM; Intel still renders the desktop. An already running application's
rendering device does not migrate when the DPM setting changes. Native
applications can be explicitly offloaded with Mesa's
`DRI_PRIME=pci-0000_03_00_0` environment variable; this must be verified per app.
Cross-GPU frame transfer can impose overhead, so equivalence to the old
AMD-owned desktop's frame rate is not assumed.

The launcher uses `--use-gl=angle --use-angle=gl --ozone-platform=x11`
with DRI_PRIME and a dedicated
`~/.local/share/t2-gpu-browser` profile. The profile avoids Chromium forwarding
new windows to the already running Intel browser process. It never disables
Chromium's sandbox or changes the existing browser profile.

## Implementation and installation

Repository files under `tools/graphics/`:

| File | Purpose |
| --- | --- |
| `t2-gpu-policy.py` | Root-owned controller; validates the existing topology guard before changing DPM |
| `t2-gpu-policy.service` | Enabled service, restricted to the hybrid boot; depends on the early low-DPM service |
| `t2-gpu` | User CLI and AMD browser launcher |
| `power-menu/state.qml`, `power-menu/controls.qml` | Custom popup additions |
| `install-power-menu.py` | Applies additions to the user-owned Omarchy power clone |
| `maintain-boot.py` | Refreshes manual live-image hashes, command lines, default ordering and display names |
| `install-gpu-controls.py` | Installs root-owned files and the post-update hook, then enables the controller |

The controller reads the current power profile over D-Bus directly, avoiding
repeated Python CLI startup overhead. A root-owned Unix socket at
`/run/t2-gpu/control.sock`, group `wheel`, mode 0660, accepts only status and
three enumerated policy selections. It accepts no arbitrary paths or commands.
Selections are reported separately from actual driver readback; topology or
write failures appear in the popup. No policy path writes AMD DPM `auto`.
Intentional controller shutdown attempts to restore low after validating the
same topology. No GPU driver unload or mux transition is performed.

Install on this machine from the project root, after checking existing files:

```bash
sudo python tools/graphics/install-gpu-controls.py
omarchy plugin clone omarchy.power
python tools/graphics/install-power-menu.py
omarchy restart shell
```

The root installer refuses existing destinations; it is not a general upgrade
manager. The popup installer targets Shawn's clone and preserves a backup before
editing. It requires the installed upstream panel structure to match its
insertion points. The packaged Omarchy files remain untouched. Reusing this on
another user or model requires adapting and reviewing these assumptions.

## Boot warning and naming

The screenshot's warning was a stale BLAKE2b hash after a kernel update from
7.1.8 to 7.2.4. The generated linux-t2 entry's hash matched the actual UKI;
the two manual entries still had the previous hash. `maintain-boot.py` refuses
to update entries unless the generated live entry agrees with the on-disk
image hash. This prevents silently accepting an unexplained image change.

The installed post-update hook is:
`/etc/boot/hooks/post.d/85-t2-hybrid-menu`.
It runs before the existing hash-warning and configuration-enrollment hooks.
It synchronizes the manual live entries' hashes and command lines with the
current generated entry. Snapshot images and their hashes remain distinct.
It restores Hybrid as the first entry and `default_entry: 1`.

The main boot labels are now:

- **T2 Linux — Hybrid** (default)
- **T2 Linux — AMD graphics** (original display ownership)
- **T2 Linux — GPU disabled** (original explicit AMD-off behavior)

The GPU-disabled entry still uses force_igd without the hybrid marker, so its
existing early OFF service remains effective. This change does not remove hash
checking. Backup before the repair:
`/var/lib/t2-hybrid-trial/menu-20260911T205806765243Z/limine.conf`.

The older `install-trial.py` and `set-hybrid-default.py` document the original
installation stage. Do not rerun them against the renamed maintained layout.
Use the maintained hook for updates.

## Validation and limits

- 21 offline tests passed, including automatic AC/battery selection, manual
  overrides, topology failure, stale-image refusal, recovery
  preservation, snapshot preservation and boot-maintenance idempotence.
- Initial live service startup selected high on AC + Performance. Explicit
  saver, performance and auto commands produced low, high and high readback.
  No new SMU failure, GPU-reset or timeout messages appeared in that check.
- A separately launched headless Helium WebGL 2 probe with the launcher GPU
  flags reported `ANGLE (AMD, AMD Radeon Graphics (radeonsi navi14 ACO),
  OpenGL ES 3.2)`. This proves AMD WebGL selection, not the user's game FPS.
- A visible WebGL test exposed an important difference: the ordinary Wayland
  browser selected Intel despite DRI_PRIME. The X11-backed browser selected AMD.
  The final launcher therefore explicitly uses X11 through Xwayland; headless
  success alone was insufficient to establish the real browser result.
- At 17:07 EDT, the installed launcher was checked after updating it and
  closing only the agent-created diagnostic browser instances. The launched
  visible WebGL page reported AMD Radeon with WebGL 2 enabled. Installed
  launcher bytes match the repository source. Shawn will check game FPS.
- The user-owned popup was visually checked after restarting the shell;
  controls and actual AMD state were visible alongside the existing profiles.
- Actual cable unplug/reconnect, full game performance and a fresh boot without
  the warning still require user acceptance. The boot-file repair is verified
  by readback and by agreement with the current generated entry/image hash.
- Suspend/resume remains separately unverified; the controller rechecks topology
  and DPM on its next iteration, but that does not prove driver recovery.

## Rollback

First select GPU Auto or Power saver. Disable `t2-gpu-policy.service` to stop
adaptive control; its shutdown attempts to restore low. The existing
`t2-hybrid-low.service` remains enabled for subsequent hybrid boots.
Restore `omarchy.power` in the user bar layout to remove the custom popup, and
remove only the installed controller/client files after disabling the service.
Do not delete the separate browser profile if it contains wanted user data.

The maintained boot entries can be kept independently of the GPU controller.
Removing the maintenance hook requires manually checking hashes after future
UKI changes. Do not restore a stale boot backup's image hashes following a
kernel update; restore menu choices while retaining current verified hashes.

References:
- [Mesa environment variables](https://docs.mesa3d.org/envvars.html)
- [AMD power controls](https://docs.kernel.org/gpu/amdgpu/thermal.html)
- [Chromium headless hardware GPU testing](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/gpu/using-gpu-hardware-in-headless-chrome.md)
- [ANGLE debugging flags](https://chromium.googlesource.com/angle/angle/+/HEAD/doc/DebuggingTips.md)
