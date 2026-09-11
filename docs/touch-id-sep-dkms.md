# SEP driver across kernel updates — September 11, 2026

After the user's full shutdown/update, the running kernel changed from
`7.1.8-arch1-Watanare-T2-3-t2` to `7.2.4-arch1-Watanare-T2-1-t2`.
The custom SEP module had only been manually installed for 7.1.8. The new
boot's transport service failed with `Module t2_sep_transport not found`, so
keybag loading, readiness and fprintd never started. Omarchy correctly reported
fingerprint unavailable and hid the icon. Its user-owned TouchIdStatus.js still
matched repository source; no lock-screen modification was needed.

## Implemented repair

Installed the distribution's `dkms` package and registered
`t2-sep-transport/0.1.0_826a86e` with AUTOINSTALL enabled. The new module built and
installed successfully for 7.2.4. A second invocation of the installer verified
the snapshot and skipped the already-installed module successfully.

The reproducible installer is `tools/research/install-t2-sep-dkms.sh`. Run it as
root from this checkout after installing DKMS and the running kernel's headers.
It takes no arguments and does not load or replace an active SEP driver.

It copies only five required source/build files from the pinned read-only
reference `t2-touchid-linux-latest`, at revision
`826a86e55a9a745f50fb64672e5be32cf352cb76`. Copied bytes must match the checked-in
`t2-sep-transport-source.sha256` manifest before installation. An existing source
snapshot must match both that manifest and the DKMS config or installation
stops; there is no silent revision substitution or overwrite. This is an
installed GPL source snapshot, not a modified external Git checkout.

Installed source: `/usr/src/t2-sep-transport-0.1.0_826a86e`.
Current module: `/usr/lib/modules/7.2.4-arch1-Watanare-T2-1-t2/updates/dkms/t2_sep_transport.ko.zst`.
The source version remains `4EDFE0F7DD5A0556A7C8094`; no driver behavior changed.
DKMS generated its normal local signing certificate/key; those private files
were neither read nor added to the project.

The installer bounds its initial DKMS operation with a 1-GiB memory limit,
256-MiB swap limit and 64-task cap. The DKMS Make command uses two build jobs.
Future distribution kernel/header transactions invoke the packaged DKMS hook,
which rebuilds AUTOINSTALL modules. This depends on matching headers and future
kernel API compatibility; a failed build must remain visible rather than
force-loading a mismatched module. Future builds do not need this checkout:
the validated source snapshot is retained under /usr/src.

Validation: independent scratch build completed compile/link/modpost/BTF;
DKMS build/install and modprobe resolution passed; shell syntax validation and
idempotent second installation passed. The old kernel's module and external
reference checkout were untouched. No tests of fingerprint matching or sleep
were triggered.

To stop future automatic builds, remove this DKMS registration with
`dkms remove -m t2-sep-transport -v 0.1.0_826a86e --all` when deliberately rolling
back. This is not a live transport reset. Do not unload an instance with
SEP-registered DMA; use a supervised boot change if runtime removal is needed.

## Remaining SEP timeout after the driver repair

Starting the normal fprintd prerequisite chain loaded the rebuilt transport and
registered EP7 buffers successfully at 09:47:23 EDT. Keybag loading then timed
out at 09:47:35. The prior mailbox failure therefore remains after this cold
start, independently of the now-fixed missing-module problem.

A temporary isolated trace instance recorded only return codes from
`t2_sep_send` and `t2_sep_receive` during one read-only capability query, under
the operation lock and a 20-second timeout with two-second kill grace:

- send returned 0;
- receive returned -110 (ETIMEDOUT), about 12.56 seconds later;
- the capability tool exited 1 with the ioctl timeout.

This means the request was posted according to the driver's send routine and
no incoming mailbox response arrived during the receive loop. It does not
prove that firmware consumed or accepted the request, or establish why it
remained silent. It also does not indicate invalid credentials or erased
fingerprints. Tracing collected no request/reply payloads or secrets, and all
temporary probe events and the trace instance were removed in finally cleanup.
An initial trace setup failed before sending any device request and also cleaned
up its empty instance.

The next investigation is SEP/AKS endpoint initialization and firmware response
progress, not repeated keybag retries or another blind reboot. The driver has
no validated live reset path. Current state: SEP transport active, keybag loader
failed, fprintd inactive, password fallback available. The fingerprint icon is
still absent for this reason. The September 6 single-cancel wake fix remains
pending live acceptance, and last successful measured readiness remains 4.982 s.

## Startup-handshake control prepared September 11

Historical journal comparison narrows the regression: boot
`eba19a65afd44359bdf2f5c18f9e3b9d` successfully loaded the keybag on September 10
at 21:30:07, with kernel 7.1.8 and the same graphics/IOMMU command-line settings
as the subsequent failing 7.1.8 boot. That successful boot suspended at 01:46
on September 11. This is chronology, not proof that sleep caused the failure.
The current PCI function is D0, bus mastering enabled, in an identity IOMMU
domain; no second SEP driver is loaded.

The normal driver exchange always constructs version-2 envelopes. Its existing
optional `probe_capabilities` path instead sends one read-only version-1
capability request before exposing the character devices, validating the
compact version-1 reply and digest. This separates initial protocol negotiation
from the currently failing version-2 requests. Earlier successful production
boots also skipped this optional query, so its absence is not a proven cause.
No environment-setup or new authentication operation has been enabled.

Installed `tools/research/t2-sep-startup-diagnostic.conf` as
`/etc/modprobe.d/t2-sep-startup-diagnostic.conf`. Verified modprobe resolves the
DKMS module with `probe_capabilities=1` while preserving OOL/ACM and platform
options. The running module remains unchanged; this takes effect on the next
user-supervised reboot. No reboot has been initiated. This is a diagnostic
control, not a claimed repair of the remaining timeout.

After reboot, read the kernel's capability result and the normal prerequisite
service results before sending another request. If the capability query passes
and keybag loading still fails, investigate version-2/environment initialization.
If the version-1 query itself times out, the missing version negotiation alone
cannot explain the failure; pursue transport/firmware state. If startup works,
verify the visible icon and obtain a supervised positive/negative fingerprint
control before claiming recovery. Do not repeat the same startup retry.

Rollback of this diagnostic is removal of only
`/etc/modprobe.d/t2-sep-startup-diagnostic.conf`; its effect ends on a later boot.
Never force-unload the registered module to apply or roll back this option.
