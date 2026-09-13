# macOS Touch ID comparison after Linux SEP timeout

## Superseded by macOS boot failure, September 13

Shawn attempted the normal macOS startup twice using Option and the macOS
startup volume. Both attempts took longer than usual, then fans surged for
one or two seconds and the machine powered off. macOS login/Touch ID control
was not reached. Shawn returned to Linux. Do not repeat the requested unlock
control until the boot failure is assessed. See
[incident evidence and experimental-driver pause](macos-boot-shutdown-2026-09-13.md).


Prepared by the Linux thread September 13, 2026. This is a proposed supervised
control; macOS has not yet been tested or booted as part of it. Hybrid remains
the required Linux configuration. Do not replace it with an AMD-only setup.

## Requested control

After Shawn is ready, boot macOS normally and sign in using the password. Then
lock the screen and try the already-enrolled finger with normal macOS Touch ID.
Record whether the sensor becomes available and whether it unlocks. Record any
exact error wording without exposing account details. Do not delete/re-enroll
fingers, reset the sensor/SMC/SEP, change protected state, extract keybags or
credentials, or run the old research probes for this control.

If a macOS agent assists, fetch GitHub main and review this handoff first.
Commit/push only the result and relevant nonsecret diagnostics before returning
to Linux. A manual result reported by Shawn is sufficient for the initial
control; there is no requirement to run another agent merely to test unlock.

When ready to return, use the usual T2 Linux Hybrid entry. The Linux thread
cannot work while this physical machine is running macOS. On return, fetch and
review any macOS handoff, then inspect startup logs before requesting a scan or
retrying services. Keep the current driver/configuration for this comparison.

## Evidence from Linux

- Kernel 7.2.4, Hybrid profile. SEP PCI function is D0, bus mastering enabled,
  power control on. No IOMMU fault seen in inspected kernel journal.
- Missing custom module after a kernel update was repaired via pinned DKMS.
  The older original mailbox timeout remained independently of that repair.
- Last known successful production startup was September 10 at 21:30, already
  using Hybrid; therefore graphics options alone are not an established cause.
- Baseline version-2 requests and optional version-1 capabilities timed out.
- Start1 enabled transport control from 0x7f to 0x7a and installed two MSI
  handlers. Capability still timed out. Buffers were all above 4 GiB.
- Start2 kept that sequence but selected 32-bit coherent DMA. On September 13
  at 13:51 it again timed out. A source-version-gated read-only observation
  confirmed all four registered buffers below 4 GiB and control still 0x7a.
- No biometric match, identity enumeration, or enrollment result was obtained
  in these trials. Failure is before exposing authentication devices. Password
  fallback remains required.

Installed/loaded start2 srcversion: `509B887928226059FBC3264`.
DKMS version: `t2-sep-transport/0.1.0_826a86e_start2`.
Config: `/etc/modprobe.d/t2-sep-startup-trial.conf` (`start_transport=1`), plus
the earlier capability diagnostic and original platform options.
Both previous source snapshots are retained for rollback. Full rollback is in
`docs/touch-id-sep-startup-trial.md`.

No live driver unload/reset is appropriate: SEP retains registered DMA and the
driver pins itself. The observer is unloaded; no tracing or scan is armed.

If macOS works, that shows its normal stack can authenticate; it does not by
itself prove a specific Linux bug or rule out state-dependent firmware issues.
If Linux then works without another change, record the OS-transition effect
and verify repeatability before claiming permanent recovery. If macOS also
fails, preserve that result and investigate the broader failure before making
more speculative Linux startup changes.
