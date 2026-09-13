# macOS startup power-off, September 13, 2026

Shawn reports two macOS startup attempts through Option/startup-volume
selection. Each was slower than usual, followed by a very loud fan surge for
one or two seconds and power-off. He powered on again and returned to Linux.
No macOS Touch ID result was obtained. The precise startup screen reached is
awaiting clarification. Do not equate fan surge with proven thermal shutdown,
SEP failure, corrupted storage, or permanent hardware damage.

## Read-only findings after return

Current Linux boot: `a02e27793a1749e088d2383c122b746a`, kernel 7.2.4, Hybrid.
Previous Linux boot: `6f2fb3ac6e22461b80056b749b255ec9`. Start2 remains loaded
and its capability handshake still timed out on both boots.

The current kernel reports bank-12 and bank-13 machine-check records during
early boot, before loading SEP. The same status/address pattern is present on
September 5's boot `2792821be773426aa353f82a8d301a02`, when production Touch ID
worked, and September 12 before the new transport-start trials. These are
pre-existing observations, not proof of the new shutdown's cause or evidence
exonerating any later experiment. No attempt was made to suppress error logs.

Both `/sys/fs/pstore` and `/var/lib/systemd/pstore` are empty. No saved macOS
panic report is available through those Linux stores. Current inspected kernel
logs contain no critical thermal trip or NVMe timeout/reset explaining the
macOS events. A Linux sensor snapshot showed CPU package 74 C against reported
100 C critical, GPU edge 68 C/junction 72 C, battery about 35 C, and physical
fans about 5378/4953 RPM. This measures the subsequent Linux session, not the
temperature at the macOS failure. Some SMC sensor labels return implausible
values; do not extrapolate unvalidated sensor channels into a diagnosis.

## Containment

Further SEP/fingerprint experiments are paused. Installed
`tools/research/t2-sep-diagnostic-pause.conf` as
`/etc/modprobe.d/t2-sep-diagnostic-pause.conf`, containing a blacklist and an
`install t2_sep_transport /usr/bin/false` rule. `modprobe --show-depends`
resolves to that rule; installed bytes match repository source.

The current EFI image's initramfs listing contains the old SEP options file
but no SEP driver module, so the root-filesystem modprobe block applies to
the next ordinary Linux startup. No EFI image or boot profile was modified.
The installed trial modules, source snapshots, credentials and biometric state
are preserved. No running driver was unloaded; its registered DMA remains
valid for this session. No live reset, hardware write, firmware update,
filesystem repair, or stress test was performed during this incident review.

This block only prevents later Linux driver loading. It cannot undo hardware
state already established, nor is it a claimed fix for macOS boot failure.
To deliberately resume research later, remove only the pause config after
deciding which driver/configuration to test; no automatic unpause is scheduled.

## Next proposed check

Run Apple's built-in diagnostics before further authentication experiments.
This requires Shawn's participation and a supervised shutdown/startup. Per
[Apple's Intel Mac instructions](https://support.apple.com/en-us/102550), shut
down, disconnect unnecessary external devices, keep AC power and ventilation,
then power on holding D. Use Option-D if D does not launch diagnostics. Record
the reference code, or whether diagnostics itself also powers off. No test has
been initiated yet. A passing diagnostic is not proof that every hardware or
firmware fault is absent.

Do not initiate an SMC/NVRAM reset, DFU restore, macOS reinstall, or disk repair
as an unreviewed next step. Preserve accessible data and the current evidence
before considering recovery operations. Hardware service/Apple Support may be
needed depending on the diagnostics and ability to enter Recovery.
