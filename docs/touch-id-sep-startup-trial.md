# SEP transport startup trial, September 13, 2026

Hybrid remains the target boot profile. Its running kernel is 7.2.4. The SEP
driver loads, but the optional version-1 capability handshake and subsequent
keybag load both time out. The September 11 and September 12 boots exercised
that handshake; it is no longer an untried diagnostic.

## New observation

The PCI function is D0, runtime active, with power control on and bus mastering
enabled. No IOMMU fault was found in the current kernel journal. Review of the
graphics policies found no SEP power-control action. These observations do not
exclude every graphics/power interaction.

A narrowly scoped read-only helper, `tools/research/sep-status-readonly`, checked
five fixed status/control registers under the normal operation lock. It does
not bind a driver, enable PCI, allocate DMA, read a payload FIFO, or write MMIO.
It requires MacBookPro16,1, the exact SEP PCI function/IDs, the installed driver,
D0, and a sufficiently sized memory BAR. It built against the running headers,
loaded once, printed the following, and immediately unloaded:

```
inbox=0x24401 outbox=0x21101 control=0x7f reset=0x0 start=0x0
```

Earlier prototype hardware experiments identified control 0x7f as the stopped
transport state and observed 0x7a after Apple's enable sequence. See
`docs/touch-id.md` around the AppleSEPIntelIOP startCPU observations and
`prototypes/t2sep-probe/README.md` for the two-MSI experiment. The production
driver contains no corresponding transport-start sequence. This is a candidate
startup omission, not yet proven to cause or fix the current timeout. Control
endpoint OOL registration can succeed in the observed state.

An initial userspace resource4 read attempt failed with EINVAL while opening
the resource, before any MMIO access. The helper above provided the observation
without removing the active driver.

## Prepared implementation

`tools/research/t2-sep-startup-trial.patch` applies to the exact source pinned by
the existing SEP installer. It is opt-in through `start_transport=1`. Before
exposing either misc device, after new OOL buffers are registered and pinned:

- require the exact model, control/reset/start state, empty inbox and non-full
  outbox; refuse other states without draining traffic;
- allocate two MSI vectors with handlers that never read FIFO data;
- issue the recovered sequence (reset register 0, start register 1, control 5),
  flush by reading control and require 0x7a;
- require the existing integrity-checked version-1 capability response before
  exposing clients; normal credential/biometric prerequisites remain required.

The ordering after OOL registration is new and awaits hardware validation.
Earlier prototypes enabled the transport before OOL registration. Here buffers
are valid before enabling traffic. Failure retains the already-pinned module
and DMA and exposes no authentication devices. No live reset, stop, forced
unload, FIFO drain, credential mutation or authentication bypass is added.
There is no resume repair in this trial.

`install-t2-sep-dkms.sh --startup-trial` verifies base source hashes, applies
the patch with zero fuzz, and installs DKMS version `0.1.0_826a86e_start1`.
Existing snapshots must byte-match staged sources and configuration. The base
DKMS version remains built for rollback. Installation uses --force only for
the explicitly requested trial to replace the same-named on-disk module.

Independent scratch build and DKMS build/install passed on 7.2.4, including
compile/link/modpost/BTF; shell syntax and diff whitespace checks passed.
Installed trial source version is `C3E877B6001A0109956ED9C`. The currently loaded
driver remains baseline `4EDFE0F7DD5A0556A7C8094`. No live replacement occurred.
The status observer is no longer loaded. No new fingerprint or sleep test ran.

Installed `/etc/modprobe.d/t2-sep-startup-trial.conf` enables the trial on the
next supervised Hybrid boot. Existing diagnostic and platform options remain.
The SEP module is not explicitly included in current mkinitcpio MODULES; it is
loaded through its ordinary startup path. No boot profile or EFI image changed.

## Next boot and rollback

After Shawn is ready, reboot into the usual Hybrid entry. Check module source
version, startup state/result, capability reply, and the normal prerequisite
chain. A passed capability reply alone is not fingerprint acceptance. Only
after readiness succeeds should a supervised positive/negative finger control
be performed. If the gate refuses or capability still times out, preserve logs
and reassess the transport hypothesis rather than repeatedly retrying keybags.

To roll back the trial for a subsequent boot, remove only
`/etc/modprobe.d/t2-sep-startup-trial.conf`, then run as root:

```
dkms remove -m t2-sep-transport -v 0.1.0_826a86e_start1 --all
dkms install -m t2-sep-transport -v 0.1.0_826a86e -k "$(uname -r)" --force
```

Verify modprobe resolution before rebooting. Never force-unload registered DMA
to apply either version. The earlier capability-only config can separately be
removed once its diagnostic purpose is finished.
