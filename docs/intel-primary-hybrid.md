# Intel-primary hybrid investigation — September 10, 2026

Status: configuration **installed; first hybrid boot and internal-display
operation verified**. External-display reconnect and suspend validation remain
pending. Eleven offline tests, shell syntax, udev validation and systemd unit
checks passed. Installed system files match repository sources and are
root-owned. The first reboot into the hybrid configuration succeeded.

## First boot and power follow-up, September 10, 21:35–21:41 EDT

The user rebooted into the trial. Its service succeeded, verifying Intel mux
ownership and writing AMD DPM from auto to low. Current readback remains low;
AMD hwmon reports **3 W**. Aquamarine logs identify Intel card1 as primary,
the compositor environment contains both stable aliases in Intel-first order,
and Intel's real eDP-1 is enabled. No external display was connected during
these measurements. Battery charge was 79% during the pass.

Two installed adjustments:

- `omarchy powerprofiles set battery power-saver` saved power-saver as the
  remembered battery profile (previous active profile balanced). CPU EPP
  readback changed from balance_power to power. AC preference was not edited.
  Revert with `omarchy powerprofiles set battery balanced` while on battery.
- Hyprland had exposed a phantom AMD eDP-2 with 0×0 resolution. Added the
  conditional fragment in `tools/graphics/monitors-hybrid.fragment.lua` to
  `~/.config/hypr/monitors.lua`, disabling only this verified phantom in the
  hybrid boot. Reload succeeded, configuration errors are empty, and only
  real eDP-1 remains active. Backup:
  `~/.config/hypr/monitors.lua.bak.20260910-213735`.

Battery power uses current_now × voltage_now / 1e12; these are short,
non-randomized observations under varying interactive activity:

| Interval | Observed result |
| --- | --- |
| Initial balanced sample, 12 s | Mean 33.93 W; range 27.18–41.89 W |
| After power-saver, 30 s | Mean 26.33 W; range 23.57–32.39 W |
| After phantom disable, 30 s | Mean 22.18 W; several readings 17.91–18.61 W, one 39.09 W spike; Intel RC6 92% |
| Empty workspace, 30 s | Mean 22.29 W; final seven mean 21.22 W; last three 18.61, 18.35, 18.58 W; Intel RC6 99.7% |

Brightness was already low: 13261/65535, approximately 20%. Before adjustment,
Intel graphics reached 1150–1200 MHz. Browser GPU and renderer processes used
52.1% and 46.0% of one CPU core in the first 12-second sample; in the later
phantom-fixed interval they used 6.4% and 15.6%. The transcription Python
sidecar was not among the busy processes in those delta samples; its lifetime
CPU percentage was misleading for current idle diagnosis. No user processes
were stopped. No independent causal attribution between profile, phantom fix,
and changing browser activity is established by these samples.

Shawn authorized the empty-workspace comparison, but also switched manually;
the manual activity overlapped the automated test. The automated script
verified empty workspace 99 after switching and restored workspace 1 in its
finally block. Treat this as a limited idle observation, not a clean A/B test.
The first attempt used unsupported legacy dispatch syntax and did not switch;
the successful attempt used `hl.dispatch(hl.dsp.focus(...))` via hyprctl eval.

The user was told they could reconnect AC after measurements. At 18.5 W,
80 Wh corresponds to about 4.3 theoretical hours from full; at 25 W, about
3.2 hours, before workload variation and usable-capacity limits. No 4 W
whole-system result is claimed. Intel still logs missing VBT. The old AMD-off
baseline is approximately 16 W, with different brightness and workload; this
trial has not beaten it. Full AMD power-off, more aggressive Intel limits,
and VBT changes were not attempted during this pass.

## Original installation, September 10 at 21:26 EDT

Boot backup:
`/var/lib/t2-hybrid-trial/20260911T012630Z/limine.conf`.
The installer verified the full modified boot configuration by readback.
The new top-level menu entry is **T2 Intel-primary hybrid test**; existing
entries and `default_entry: 2` are retained. Both old modes and the trial use
the same hashed EFI image. The known-working Intel entry already passes its
force_igd option through Limine, so this trial duplicates that mechanism with
an additional opt-in marker. No UKI rebuild was needed.

At installation time, `t2-hybrid-low.service` was enabled without starting it;
it subsequently ran successfully on the first hybrid boot. The two old
services have conditional exclusion drop-ins, and the new UWSM environment
file is conditional on the trial marker. The udev rules were reloaded without
triggering current devices; aliases were created during the first hybrid boot.

## What the linked post means

[Novuon's reply](https://x.com/novuon_ai/status/2094064287522160661) describes
keeping Intel as the permanent display GPU and AMD loaded at low DPM. This
avoids changing display ownership every time AC is unplugged. The author's
[routing notes](https://github.com/novuon/mbp2019-omarchy/blob/main/docs/fixes/01-gpu-routing.md)
explicitly require an initial reboot. Their
[power notes](https://github.com/novuon/mbp2019-omarchy/blob/main/docs/fixes/02-amd-power-management.md)
identify the approximately 4 W as **AMD GPU power**, not total battery draw.
They observed a reset after an `auto` transition; this is same-model evidence,
not proof that every such transition fails.

[Dan Wahlin's same-model experiment](https://blog.codewithdan.com/how-i-cut-gpu-power-from-18-w-to-4-w-on-an-omarchy-macbook-pro-with-github-copilot-cli/)
also measured 4 W AMD power. One external display worked with Intel primary
and AMD available; a quiet two-display battery sample was 44.3 W total. Full
login with the two-GPU list and suspend were still unverified in that report.
Do not promise a 4 W laptop or a working dock/suspend configuration from it.

## This machine's observed starting point

- MacBookPro16,1; `7.1.8-arch1-Watanare-T2-3-t2`.
- Intel `0000:00:02.0`, `8086:3e9b`, i915; AMD `0000:03:00.0`,
  `1002:7340`, amdgpu.
- AMD owns internal `eDP-1` and the connected Dell `DP-10`.
- AMD D0, runtime status active, power control `on`, DPM `auto`.
- One AMD sensor sample: 14 W, 74 C. This is not an idle average.
- Battery full on AC, current zero: battery telemetry cannot establish total
  system consumption in this state.
- Current-boot journal: AMD `Runtime PM not available`; i915 missing VBT.
- Existing Intel boot uses `apple_gmux.force_igd=1`; its
  `t2-intel-dgpu-off.service` explicitly switches AMD off.
- `t2-graphics-mode-policy.service` also keys off that option, permanently
  applying battery settings including disabling Bluetooth in that boot.
- No user UWSM environment files were present; `supergfxd` inactive.

The previous 15.98 W screen-on battery baseline already had AMD switched off.
Leaving AMD powered at low DPM is a convenience experiment, not evidence that
we can beat that baseline. Missing Intel display power features remain a
separate investigation.

## Installed configuration

The trial uses the existing kernel with a third selectable boot entry containing
`apple_gmux.force_igd=1 t2.graphics=hybrid`. The AMD default and Intel-off entries
remain recovery choices. No new kernel source is required for the mechanism:
the existing Intel boot already proves force_igd. On another machine, inspect
the actual Limine/UKI command-line arrangement before reusing the installer.

Installed files:

| Repository source under `tools/graphics/` | Destination |
| --- | --- |
| `t2-hybrid-low.py` | `/usr/local/libexec/t2-hybrid-low.py` (root-owned) |
| `t2-hybrid-low.service` | `/etc/systemd/system/t2-hybrid-low.service` |
| `70-t2-hybrid-drm.rules` | `/etc/udev/rules.d/70-t2-hybrid-drm.rules` |
| `skip-hybrid.conf` | `skip-hybrid.conf` in both existing services' `.service.d/` directories |
| `env-hyprland.fragment` | Append to user `~/.config/uwsm/env-hyprland` |

The negative condition skips both old services **only** in the hybrid trial.
The new service verifies model, GPU identities/drivers, Intel mux ownership,
a connected Intel panel, and AMD D0 before writing `low`. Its bounded startup
wait never issues mux commands or writes `auto`. A failed guard leaves the
existing GPU state untouched and reports a service failure; it does not prevent
the desktop from starting. Suspend reapplication is not implemented or tested.

The UWSM fragment sets Intel first and includes AMD so the Dell's output stays
available. Stable aliases avoid varying card numbers and PCI-path colons,
which conflict with the Aquamarine device-list separator. See
[Hyprland multi-GPU documentation](https://wiki.hypr.land/configuring/extra/multi-gpu/).
This is a hybrid trial; listing Intel alone would lose the AMD external outputs.

Before deployment, back up any existing destination files, record service
enablement, install root-owned system files, reload systemd/udev, and enable
the trial service. Avoid broad udev triggers during the current session; the
aliases can be created naturally at the next boot. Do not start the policy in
an AMD-owned session. The environment takes effect at a new login.

`tools/graphics/install-trial.py` performed this installation. It refuses
existing destination files and duplicate trial entries, saves the original
boot file, and attempts rollback on installation failure. The UWSM fragment
was installed separately as Shawn, into a previously absent file.

## Acceptance and rollback

The initial reboot and internal-display checks passed. For subsequent verification:

1. Check current cmdline, mux ownership, the Intel internal connector, the
   actual Hyprland renderer, service journal and `low` readback.
2. Check both real displays and Hyprland configuration errors. If a zero-size
   phantom AMD eDP appears, identify it before adding a conditional monitor
   disable rule; do not disable an unverified connector name.
3. Unplug AC and the external display when Shawn is ready. Measure multiple
   battery-current × voltage samples separately from AMD hwmon power, at
   controlled brightness and low screen activity. Reconnect the Dell within
   the same session and verify its resolution and refresh rate.
4. Check kernel logs for SMU, SDMA, GPU reset and display errors. Separately
   test suspend/resume only when Shawn is ready, including DPM readback.

AMD remains performance-limited even on AC. A tested workload-specific way to
raise its performance is future work; do not implement an automatic `auto`
transition or imply that full gaming performance has been preserved.

If the trial fails, select the preserved AMD boot entry: the new service and
environment override are opt-in, and the old policy applies again. Remove the
trial entry and only the installed trial files/drop-ins/environment fragment
to uninstall, restoring backups as appropriate; reload systemd and udev.

Offline checks: `python -m unittest discover -s tools/graphics -p 'test_*.py'`
exercises topology rejection and a dynamic-card-number success fixture.
Shell syntax and systemd unit checks do not establish hardware success.
