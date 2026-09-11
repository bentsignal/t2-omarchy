# SEP startup timeout — September 11, 2026

The supervised sleep test was not started: fprintd was already inactive while
awake. Its prerequisite `t2-keybag-load.service` failed with
`T2_AKS_IOC_EXCHANGE: Connection timed out`. The loader failed during initial
startup at 02:19 EDT and again later that morning. A normal fprintd start at
09:22 also failed on the same dependency.

The SEP transport unit is active/exited, `/dev/t2-aks` and `/dev/t2-acm` exist,
and both OOL registrations are enabled. PCI function `0000:04:00.2` is runtime
active with power control on. No process held either device node open during
inspection. No systemd-suspend event is recorded in this boot. Therefore this
failure precedes the fingerprint cancellation/wake experiment; do not present
it as a new outcome of the single-cancel correction.

A single read-only `t2-aks-tool capabilities` request, serialized under the
operation lock and bounded by a 20-second timeout with a two-second kill grace,
also returned the ioctl connection timeout. This establishes a failure beyond
the keybag-load operation; it does not identify the hardware/firmware cause or
show that stored credentials are invalid. No credential bytes, keybag contents,
biometric identifiers, or payloads were read into the transcript or repository.

Installed kernel: `7.1.8-arch1-Watanare-T2-3-t2`.
Installed SEP module source version: `4EDFE0F7DD5A0556A7C8094`.
The module is byte-identical to the build in the read-only reference
`.local/references/t2-touchid-linux-latest/src/t2_sep_transport.ko`, SHA-256
`2b0048612030b4ce5c49e63a47dd9e5df56ddda294aafc62cee464862a97c7cf`.
The older reference checkout's module has a different source version and must
not be substituted.

The matching driver source provides mailbox exchange and probe/remove paths,
not a live recovery/reset or suspend/resume callback. Its remove path retains
registered DMA memory until reboot rather than freeing memory still registered
with SEP. The installed transport-loader script also avoids replacing an active
OOL-enabled instance. Do not unload/reload it, issue a PCI reset, or substitute
the CDC-NCM rebind: the SEP mailbox is a different transport.

## Recovery checkpoint

Normal service startup and the bounded capability query failed. There is no
validated live recovery path established for this state. The next recovery
attempt is a supervised full shutdown and power-on into Linux, following the
previously accepted cold-boot path. This is an attempt, not a guaranteed fix.
Shawn must be ready before shutdown; it ends access to this running OS/session.
No shutdown, reboot, suspend, kernel replacement, sensor reset, credential
reprovisioning, enrollment mutation, or biometric test was performed here.

After power-on, inspect the SEP transport and keybag/credential/readiness service
results before manually retrying anything. If the prerequisite chain completes,
check fprintd and fingerprint configuration without a scan. Then perform the
already-planned supervised fingerprint/sleep control when Shawn is ready.
If capability exchange still times out, preserve the cold-start evidence and
investigate SEP initialization rather than repeatedly loading keybags or
weakening the prerequisite gates.

Current state: fprintd inactive; password authentication remains available.
Last successful measured wake readiness remains 4.982 seconds on September 6.
The subsequent single-cancel correction still awaits live acceptance.
