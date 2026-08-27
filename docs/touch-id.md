# Touch ID on Linux: T2 research notes

Status as of 2026-08-27: **transport working; biometric path not working yet**. This document records the
machine-specific evidence, current public research, safety boundaries, and a
concrete bring-up plan for the built-in Touch ID sensor on this repository's
`MacBookPro16,1`.

## Prototype progress

`prototypes/t2sep-probe/` contains the first out-of-tree kernel prototype. It
builds against the installed `linux-t2` 7.1.8 headers and has been loaded and
unloaded successfully on this machine. The live probe bound only to
`04:00.2`, reported PCI command `0x0006`, status `0x0010`, and all three BARs,
then returned the device to its original unbound state. Its linked-symbol
audit showed no PCI/MMIO write, device-enable, IRQ, DMA, or reset functions.

The second experiment, gated by `read_mailbox_status=1`, maps BAR4 and reads
only the hypothesized 32-bit mailbox send/receive status registers at offsets
`0x4008` and `0x4020`. Two runs returned `send=0x00000000` and
`receive=0x00000000`, then unloaded cleanly with no new kernel warnings. In
PongoOS's T8012 implementation, receive bit `0x20000` means empty; a clear bit
therefore suggests an inbound message may be waiting if the BAR translation is
correct.

The third experiment is gated by both `read_mailbox_status=1` and
`read_one_message=1`. It reads and decodes at most one waiting 64-bit inbound
message from offsets `0x4034`/`0x4038`, in PongoOS's documented order. This
still links no MMIO-write function, but reading may advance the receive FIFO.
It returned an all-zero word, and the receive status remained zero before and
after the read. The alternative BAR4 base-zero status offsets were also zero.
This indicates BAR4 is inert at these locations rather than holding a queued
zero-valued message.

The next status-only gate, `scan_apertures=1`, compares the documented T8012
status offsets across BAR0, BAR2, and BAR4 to identify which PCI aperture, if
any, translates the native SEP register window.

That scan returned all ones from BAR0/BAR2 and zeros from BAR4, with no kernel
warnings. The next gate, `temporarily_enable_device=1`, uses Linux's standard
PCI enable API before repeating the scan and disables the function before
probe returns. It preserves and restores the firmware-provided PCI command
word exactly.

## What the live machine exposes

The machine is running Omarchy 4.0.1 with
`7.1.8-arch1-Watanare-T2-3-t2`. Linux enumerates the following PCI functions:

| Function | Device | Linux state |
| --- | --- | --- |
| `04:00.0` | Apple ANS2 NVMe (`106b:2005`) | bound to `nvme` |
| `04:00.1` | Apple T2 Bridge (`106b:1801`) | bound to `t2bce_core` |
| `04:00.2` | Apple T2 Secure Enclave Processor (`106b:1802`) | **unbound** |
| `04:00.3` | Apple audio (`106b:1803`) | bound to `t2bce_audio` |

The SEP function has these BARs:

```text
BAR 0: 4 MiB   at 0xc0c00000
BAR 2: 512 KiB at 0xc1500000
BAR 4: 64 KiB  at 0xc1620000
```

All four functions are in IOMMU group 10. Do **not** use VFIO to claim this
group on the installed system: doing so would also detach the internal NVMe,
T2 bridge (keyboard/trackpad/Touch Bar), and audio. The first probe should be a
small PCI kernel driver that matches only `106b:1802` and initially performs
no MMIO writes.

The standard Linux fingerprint path cannot help yet. No Apple fingerprint
device is exposed through USB, no kernel driver binds the SEP, and no
`libfprint`/`fprintd` stack was installed when this baseline was recorded.
Installing `fprintd` before a transport driver exists would not create device
support.

The internal 1 TB SSD now contains the original 2 GB FAT32 EFI partition, the
shortened LUKS2/Btrfs Linux partition, and a 128 GiB APFS container. macOS was
installed through Internet Recovery, booted successfully, and used to enroll
one fingerprint. Linux then booted successfully with the original LUKS and
Btrfs UUIDs intact and zero Btrfs device error counters. This provides genuine
Apple-initialized SEP/APFS state for the next phase; keep the APFS container.

## Public state of the work

- The [t2linux support matrix](https://wiki.t2linux.org/state/) still marks the
  T2 Secure Enclave red/not working.
- A T1 MacBook Touch ID proof was [announced on
  2026-08-26](https://www.reddit.com/r/linux_on_mac/comments/1vyzeno/i_got_touchid_t1_201617_working_on_omarchy_linux/).
  Its author reports enrollment and matching through Apple's Secure Enclave,
  but has not released code yet and says T2 is a separate next target.
- [Aurora Silicon's Touch ID research](https://aurorasilicon.org/research/security/touch-id/)
  documents the AP-to-SEP mailbox, Secure Biometrics (`SBIO`, endpoint `0x08`),
  xART (`0x13`), and sensor transport. Its current implementation has not
  authenticated a fingerprint; enrollment and matching remain unimplemented.
- [Asahi's SEP notes](https://asahilinux.org/docs/hw/soc/sep/) are useful
  protocol documentation, but target Apple Silicon rather than this T2 PCI
  presentation.

The important architectural rule is that raw fingerprint images and templates
must stay inside Apple's Secure Enclave. Linux should relay authenticated
commands and consume a match result, not attempt to read fingerprint pixels.

## Recovered Intel T2 register layout

The x86_64 slice of `AppleSEPManager` from Apple's macOS 14.5 (23F79) Kernel
Debug Kit contains symbols and executable code for `AppleSEPIntelIOP`. Its
`start(IOService *)` method maps the PCI device memory selected by config
register `0x20`, which is PCI BAR4. The mailbox methods then use this layout:

| BAR4 offset | Apple driver use |
| --- | --- |
| `0x108` | inbound FIFO status; bit 17 means empty |
| `0x10c` | outbound FIFO status; bit 16 means full |
| `0x810`–`0x81c` | four inbound 32-bit words |
| `0x820`–`0x82c` | four outbound 32-bit words |
| `0x8024` | transport status/interrupt set; Apple writes `5` during stop |
| `0x8028` | transport status/interrupt clear; Apple writes `5` during start |
| `0x8040` | transport interrupt mask/disable; Apple writes `0` |
| `0x8048` | transport interrupt enable; Apple writes `1` |

This is a different PCIe FIFO presentation from the T8012/PongoOS mailbox
offsets initially tested. The earlier all-zero reads at BAR4 `+0x4000` neither
showed that the T2 was dead nor described this interface. The next experiment
reads only the recovered status and CPU-control registers.

The bounded write experiment refined those labels. Apple's method is named
`startCPU`, but the observed behavior shows that it enables the PCIe FIFO
transport rather than loading SEP firmware. Writing `5` to `0x8028` changed
its readback from `0x7f` to `0x7a`; Apple's matching stop write of `5` to
`0x8024` restored the state.

With two MSI vectors allocated, Linux sent the control endpoint's NOP wire
message and received a valid response in 10 ms:

```text
request:  00000100 00000000 00000000 00000000
response: 00010100 00000000 00000000 00100100
MSI:      vector 0 = 1, vector 1 = 1
```

This is the first confirmed bidirectional Linux-to-T2-SEP transaction. The
probe then issued Apple's stop sequence, freed both vectors, restored the PCI
command word, and unloaded. No biometric endpoint command or xART operation
was involved.

## SBIO and the storage prerequisite

Static analysis of `AppleMesaSEPDriver` and `AppleSEPGenericTransfer` confirms
that built-in Touch ID is SEP endpoint `sbio` (`0x08`). The Apple driver asks
for a 16 KiB host-to-SEP buffer and a `0x4b000`-byte SEP-to-host buffer. It
registers their DMA page-frame addresses through control opcodes `2` and `3`,
then uses generic-transfer message type `0xfc` for transactions. The first
packet has a 28-byte header followed by request data. These details are now
recovered well enough to implement the transport without guessing.

SBIO is not expected to become available until xART is online. xART is the
SEP's anti-replay store and is backed by a machine-specific GigaLocker `.gl`
file on APFS-backed storage. The machine now has an Apple-created APFS
container and a macOS-enrolled fingerprint, removing the earlier absence of
Apple storage as a blocker. Linux still needs a safe xART implementation; the
available forensic APFS reader explicitly does not support T2 encryption, so
the presence of the GigaLocker file cannot yet be confirmed from Linux by
mounting the macOS data volume.

Do not solve this by fabricating an xART response, registering DMA buffers and
freeing them while SEP may retain their addresses, or sending guessed SBIO
commands. A safe continuation needs the machine's xART volume/material (or a
macOS Recovery-supported initialization of new xART state) preserved before
Linux implements the endpoint.

## Safety boundary

Do not experiment with xART/gigalocker writes on this daily-driver machine.
xART provides anti-replay storage used by the SEP. Public reverse-engineering
notes warn that an incorrect write can invalidate protected state and lose
FileVault-encrypted data. Also avoid:

- `/dev/mem` MMIO pokes;
- binding the shared IOMMU group to VFIO;
- sending guessed mailbox commands;
- replacing, resetting, or re-pairing the factory Touch ID sensor;
- enabling fingerprint PAM modules until password fallback and recovery have
  been tested.

Read-only PCI enumeration is safe. A later mailbox probe is acceptable only if
it has a strict read-only mode, a device/model allowlist, bounded timeouts, and
never acknowledges or advances an unknown state machine.

## Bring-up plan

1. Preserve the machine-specific macOS recovery and fingerprint calibration
   material. Keep a current offline backup and confirm macOS recovery works.
2. Obtain the T1 implementation when published and separate reusable
   userspace/PAM concepts from T1-specific USB/iBridge transport.
3. Recover the T2 PCI register map from the matching macOS
   `AppleSEPManager`/biometric kexts or a trace. Do not assume Apple Silicon
   physical offsets apply to T2 BARs.
4. Build an out-of-tree, model-allowlisted PCI probe for `106b:1802`. Milestone
   zero is probe/remove plus BAR sizing and power/interrupt reporting, with no
   MMIO writes. Milestone one is a known-safe status/mailbox read.
5. Capture and compare a genuine macOS boot/enrollment/match exchange on a
   disposable or fully backed-up test installation. Filter for SBIO rather
   than tracing all SEP traffic.
6. Implement the transport and a single non-mutating query before enrollment.
   Only after the response format is verified should sensor capture, match,
   enrollment, and cancellation be attempted.
7. Expose successful matches through a narrow userspace daemon/libfprint
   backend. Add PAM last, with fingerprint marked `sufficient` and ordinary
   password authentication retained as an immediate fallback.

## Post-macOS checkpoint

The Apple installer created one GPT partition without changing either Linux
partition:

```text
/dev/nvme0n1p3
size:     137440149504 bytes (about 128 GiB)
type:     APFS
UUID:     b673d4d8-c2b7-4c15-8e58-268ade21a855
PARTUUID: a0aeaaa2-eb54-41f5-bedb-cbf6055b8b43
```

macOS set itself first in UEFI BootOrder. Linux restored the order to
`0002,0080,0001`: Limine first, macOS second, and the stale systemd-boot entry
last. The reversible change used `efibootmgr`; no EFI or APFS files changed.

`prototypes/t2sep-probe/run-control-nop.sh` is the fail-closed post-macOS
comparison runner. It validates the exact model and PCI identity, refuses an
already-bound SEP, sends only the previously proven control NOP, and guarantees
module cleanup. Its first invocation was canceled while waiting for polkit and
did not load the module. The successful invocation after fingerprint enrollment
returned the same valid response as the pre-macOS baseline:

```text
response: 00010100 00000000 00000000 00100100
latency:  10 ms
MSI:      vector 0 = 1, vector 1 = 1
```

The runner then stopped the transport, restored PCI command `0x0006`, unloaded,
and left the SEP unbound. This confirms that Apple initialization did not break
the recovered PCI transport. A control NOP does not enumerate endpoints or
prove that xART/SBIO is online, so the next milestone remains a bounded
discovery/status transaction after preserving the enrolled APFS baseline.

`tools/system-backup/capture-enrolled-apfs.sh` captures that baseline. It is
pinned to the internal APFS UUID/PARTUUID/size and the Seagate serial/Btrfs
UUID, saves post-install GPT and EFI-variable inventories, hashes the source
before a sparse raw copy, then independently hashes the saved image. The final
read also exercises Btrfs's checksums for every stored extent in the image.

## Useful baseline commands

```bash
uname -a
lspci -s 04:00.2 -nnvv
readlink -f /sys/bus/pci/devices/0000:04:00.2/iommu_group
for d in /sys/kernel/iommu_groups/10/devices/*; do basename "$d"; done
journalctl -k -b --no-pager | grep -Ei 't2|bce|secure enclave|sep'
```

Re-check the PCI address after firmware or hardware changes rather than
assuming it will always remain `04:00.2`.
