# SEP transport startup trial, September 13, 2026

## Latest result, September 13, 14:02 EDT

The supervised Hybrid boot loaded start2 (`509B887928226059FBC3264`). At
13:51:30 it selected 32-bit coherent DMA, registered OOL, and enabled control
0x7a. At 13:51:42 the version-1 capability query still timed out (-110).
Authentication devices were not exposed; fprintd remains inactive.

A one-shot read-only observation confirmed all four registered buffers below
4 GiB (`above32=0,0,0,0`, registered=1111), control=0x7a, reset=0, start=1,
inbox=0x2cc01 and outbox=0x2bb01. The observer unloaded immediately. This
establishes that the intended trial ran and that lowering buffer addresses
alone did not restore replies. No further live requests, resets, or driver
changes were made after this result.

Next proposed control is ordinary macOS Touch ID operation, followed by return
to the unchanged Hybrid trial. See [macOS diagnostic handoff](macos-touch-id-sep-timeout-check.md).
The purpose is to compare with Apple's stack and check whether a normal macOS
visit changes the persistent state; no such effect is assumed in advance.


## Current result and second trial, 12:30 EDT

The supervised Hybrid reboot loaded start1 (`C3E877B6001A0109956ED9C`). At
12:22:26 its control changed from 0x7f to 0x7a, but the capability request timed
out at 12:22:37. No authentication devices were exposed. The transport unit
also raced the in-progress PCI probe and failed before the capability timeout;
its later retries confirm the final absence of devices. This service race does
not explain the driver's independent capability timeout.

The read-only observer then measured control=0x7a, reset=0, start=1, inbox empty,
and outbox not full. Interrupt totals were inbox 0, outbox 1. Thus transport
enable alone did not restore communication. The earlier stopped-state finding
was not sufficient to establish the cause.

A source-version-gated observer extension reads only the four DMA address
fields and registration flags from the exact pinned driver structure prefix.
It emits booleans, never addresses or buffer contents. All four buffers were
registered and **above 4 GiB**. The earlier successful prototype explicitly
used a 32-bit coherent DMA mask. The production driver uses a 44-bit mask;
the 32-bit page-frame-number wire field does not itself prove whether the
firmware can access every encodable address. No working-production-boot DMA
placement measurement exists, so this remains a hypothesis.

Prepared and installed `0.1.0_826a86e_start2`, source version
`509B887928226059FBC3264`. Compared directly with the installed start1 source,
its only behavioral change is selection of a 32-bit coherent DMA mask when
`start_transport=1`; it also logs that selection. The startup ordering and
capability gate are unchanged to isolate the memory-placement question.
Baseline mode retains the original mask. DKMS compile/link/modpost/BTF and
installation passed. The loaded module remains start1, with its registered DMA
retained. The observer unloaded after reading; no live resets or retries ran.

The first patch-generation attempt found its pre-reboot /tmp scratch directory
gone and made no source edit. A following installer invocation reinstalled the
unchanged start1 on disk. Generation was corrected using a fresh temporary
copy and the checked-in patch, then start2 built and replaced the on-disk file.

Next: one supervised boot into the usual Hybrid profile. Verify start2, the
32-bit DMA log, startup/capability results and prerequisite chain. If the same
timeout remains, do not assume address placement caused it or repeat the same
control. The historical start1 preparation below remains as evidence.

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
dkms remove -m t2-sep-transport -v 0.1.0_826a86e_start2 --all
dkms install -m t2-sep-transport -v 0.1.0_826a86e -k "$(uname -r)" --force
```

Verify modprobe resolution before rebooting. Never force-unload registered DMA
to apply either version. The earlier capability-only config can separately be
removed once its diagnostic purpose is finished.
