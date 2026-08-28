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

## SBIO and the Intel xART split

Static analysis of `AppleMesaSEPDriver` and `AppleSEPGenericTransfer` confirms
that built-in Touch ID is SEP endpoint `sbio` (`0x08`). The Apple driver asks
for a 16 KiB host-to-SEP buffer and a `0x4b000`-byte SEP-to-host buffer. It
registers their DMA page-frame addresses through control opcodes `2` and `3`,
then uses generic-transfer message type `0xfc` for transactions. The first
packet has a 28-byte header followed by request data. These details are now
recovered well enough to implement the transport without guessing.

Disassembly of `_gt_write_next_packet` gives the exact seven-word,
little-endian header: protocol version (`1`), total transaction length, byte
offset, flags, reserved zero, 32-bit command, and this packet's payload
length. `_gt_send_transact_message` constructs the mailbox notification with
a 16-bit sequence in bits 63–48, the same command in bits 47–16, the
message type in bits 15–8, and zero in bits 7–0. The strict offline
`generic-transfer.py` codec and tests capture these invariants and perform no
device I/O.

`AppleMesaSEPDriver::initSbioCommunication()` also establishes the first SBIO
transaction in Apple's ordering: after generic-transfer setup, it sends
command `0x73` with one little-endian 32-bit input value, `3`, and requests no
reply payload. This resembles protocol-version initialization, but that
meaning is not yet proven. It must not be sent live until passive `sbio`
discovery, OOL limits, DMA registration lifetime, and completion semantics
have all been validated.

The generic-transfer endpoint setup is likewise ordered and stateful.
`enableEndpoint()` obtains the named service through `AppleSEPDeviceService`,
allocates two page-aligned shared-memory objects through `IOSlaveProcessor`,
and passes the outbound and inbound objects to two different
`AppleSEPEndpoint` registration methods. Only after both registrations succeed
does `getEndpoint()` consider the channel usable; it waits for the endpoint's
enabled state before returning it to `transact()`. Linux must reproduce that
ownership and teardown contract rather than merely DMA-map two allocations and
send their addresses. The current prototype intentionally has no DMA path.

The earlier assumption that T2 requires an APFS-backed GigaLocker before SBIO
can appear came from Apple-silicon SEP work. The universal macOS 14.5 KDK shows
that this is an architecture split, not a common requirement. Its arm64e slice
contains `AppleSEPXARTService`, `_gigalocker_state`, `gl_initialize`, and
SEP-driven GigaLocker handling. The x86_64 slice contains none of them. Instead
Intel `AppleSEPManager::start()` creates `AppleSEPXART` directly at fixed SEP
endpoint `0x10`; its operations use bounded OOL buffers but have no AP-side
GigaLocker service.

This distinction is confirmed on the enrolled machine. A read-only
`apfsprogs` inventory of the verified APFS image found Data, Preboot, Recovery,
System, Update, and VM volumes only. There is no XART-role volume in the
container. Fingerprint enrollment nevertheless works in macOS, so Intel/T2
enrollment state is not dependent on the Apple-silicon XART-volume design.
Linux should not invent an APFS/GigaLocker service for this machine.

The next question is therefore empirical and bounded: does the already-running
T2 advertise `sbio` on passive discovery endpoint `0xfd` after the known-safe
control NOP? Only after that record and its OOL limits are observed should DMA
buffer registration be considered. Do not fabricate an xART response, free
registered DMA while SEP may retain its address, or send guessed SBIO commands.

## Safety boundary

Do not experiment with xART or anti-replay writes on this daily-driver machine.
The x86 path is not the Apple-silicon GigaLocker path, but an incorrect
anti-replay operation can still invalidate protected state. Also avoid:

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

The x86_64 KDK implementation shows that discovery is passive. macOS creates
an `AppleSEPEndpoint` for endpoint `0xfd`; it does not send a guessed discovery
request. Its callback accepts exactly two message opcodes. Opcode 0 advertises
an endpoint ID in the parameter byte and its four-character name in the data
word. Opcode 1 supplies four one-byte OOL page limits for that same endpoint.
The driver rejects messages not addressed to `0xfd`, unknown opcodes, duplicate
or inconsistent advertisements, and more than 253 endpoint records. Therefore
the next probe should only collect and validate bounded `0xfd` advertisements
that SEP emits after the known NOP. It must stop on any other message instead
of interpreting it as discovery.

`tools/system-backup/capture-enrolled-apfs.sh` captures that baseline. It is
pinned to the internal APFS UUID/PARTUUID/size and the Seagate serial/Btrfs
UUID, saves post-install GPT and EFI-variable inventories, hashes the source
before a sparse raw copy, then independently hashes the saved image. The final
read also exercises Btrfs's checksums for every stored extent in the image.

The first baseline attempt exposed an external-transport problem before an
image was created. Seagate enclosure `0bc2:231a` (serial `NAA959T1`) was routed
through the Dell dock and two USB hubs using UAS. Repeated command timeouts and
host resets caused 6 write and 2 read I/O errors, after which Btrfs correctly
aborted the transaction and forced the backup read-only. Btrfs recorded no
corruption or generation errors. The filesystem was unmounted; use a direct
USB connection, validate it read-only, and scrub before retrying. If direct
connection is unavailable, a device-specific `usb-storage` UAS quirk is safer
than retrying the same failing UAS path.

The retry used the Seagate on USB path `4-1.3`, bypassing the Dell dock chain.
A read-only Btrfs scrub first verified 41.43 GiB with no errors and the kernel
reported no new UAS resets or I/O faults. The verified post-enrollment capture
is stored at:

```text
OMARCHY_BACKUP/apfs-baselines/20260827-post-enrollment/nvme0n1p3.apfs.img
logical size: 137440149504 bytes
allocated size: about 23 GiB (sparse)
SHA-256: 2ab37cd4ad9c859f7a90e7a32828cc3c7a3da178d58978fdebad3c523733c72a
```

The source and independently reread image hashes matched. The backup remained
mounted read-write and no new transport errors appeared during capture or
verification. This completes the required rollback checkpoint before bounded
SEP endpoint discovery; it does not by itself back up SEP anti-replay state.

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
