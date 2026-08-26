# Touch ID on Linux: T2 research notes

Status as of 2026-08-26: **not working yet**. This document records the
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

The next experiment is separately gated by `read_mailbox_status=1`. Based on
PongoOS's T8012 support, it maps BAR4 and reads only the hypothesized 32-bit
mailbox send/receive status registers at offsets `0x4008` and `0x4020`. It
does not read a receive payload or write/acknowledge any register. This second
stage was built but had not yet run when these notes were updated because it
requires a fresh interactive root authorization.

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

The internal 1 TB SSD currently contains only a 2 GB FAT32 EFI partition and
a LUKS2/Btrfs Linux partition. There is no macOS/APFS partition on the internal
disk. Any macOS tracing or extraction phase must therefore use external media
or a deliberately prepared test installation; it must not repartition or
overwrite the current Linux system as an incidental experiment.

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
