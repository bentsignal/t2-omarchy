# Touch ID on Linux: T2 research notes

> **Current result:** the macOS boot capture in
> [`macos-touch-id-findings.md`](macos-touch-id-findings.md) supersedes earlier
> fixed-port and host-address candidates retained below as research history.
> macOS uses host `fe80::aede:48ff:fe00:1122` and the Intel Multiverse internal-
> device path to reach the directory on fixed port `59602`. The directory
> returned boot-dynamic BiometricKit port `49165`. Linux may pin only the
> directory port to the verified installed binary; the service port must come
> from the validated directory transcript.

The current offline continuation is `rsd-mdns.py`: a bounded DNS-SD codec for
the exact `ncm._remoted._tcp.local.` endpoint constructed by installed macOS
`remoted`. It binds a strictly
validated, T2-sourced PTR/SRV transcript to the RSD endpoint without accepting
a caller-selected port. No multicast socket or live query is enabled yet.
The companion `rsd-mdns-query.py` now contains the bounded multicast wrapper,
but `LIVE_MDNS_DISCOVERY_ENABLED` remains false in source. Tests prove that its
kill switch precedes interface and socket access and that only correctly
scoped UDP/5353 responses from the proven T2 address can become endpoint
evidence.

Supervised Linux PTR, named SRV, named SRV/QU, and independent Avahi queries
from `fe80::aede:48ff:fe00:1122` all transmitted successfully but received no
T2 DNS response. ICMPv6 remained healthy. Read-only macOS follow-up established
that this internal T2 does not require that separate NCM DNS-SD route:
`RSDRemoteMultiverseHostDevice::needsConnect` passes literal port `59602` to
`multiverse_device_connect`. `macos-multiverse-bootstrap-evidence.py` pins that
exact sequence in the installed Intel binary; the next Linux step is therefore
the bounded directory-only connection to verified port 59602.

`discovered-rsd-query.py` now composes discovery into the passive directory
handshake offline. The connector receives only the endpoint derived from the
validated SRV transcript, and the result preserves both discovery datagrams
and the exact bounded RSD server transcript. Tests use independent fake UDP and
TCP sockets to prove the observed directory port cannot be replaced by a
caller-selected value.

Status as of 2026-08-28: **Linux transport and synchronous read-only biometric
commands work; enrollment and asynchronous event delivery remain**. This document records the
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

The finished workflow must be Linux-native. A user starting from Omarchy on a
T2 Mac should be able to enroll a finger through `fprintd`, store the resulting
machine-bound template inside the T2/SEP, and use it for login, unlock, `sudo`,
and Polkit without installing or booting macOS. This machine's macOS install and
enrolled finger are reverse-engineering fixtures only; depending on an Apple-
created template would not satisfy the project goal.

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

The x86_64 `_postMailboxGated` implementation does not copy an arbitrary
128-bit host record. After confirming outbox bit 16 is clear, it writes only
input words 0, 1, and 2 to `0x820`, `0x824`, and `0x828`; it always writes a
literal zero to `0x82c`, then reads `0x10c` as the final ordered access. Receive
checks inbox bit 17 and reads `0x810`, `0x814`, `0x818`, then `0x81c`. Bits 18
and 19 of that received fourth word are error/fatal transport metadata rather
than host payload. `intel-fifo.py` records this asymmetry as a pure MMIO-action
planner and rejects full/empty state, a nonzero host fourth word, malformed
u32 records, and received transport errors. It performs no mapping, polling,
or I/O.

The same Intel slice fixes the MSI mapping. Interrupt source index/vector 0 is
`intr_inbox_nempty`; vector 1 is `intr_outbox_empty`. Both handlers require the
serialized work-loop gate. Inbox invokes the installed doorbell callback (the
manager drains records until `getMailbox` stops succeeding), or wakes the
inbox condition if no callback exists. Outbox wakes the condition used by a
sender blocked on the full bit. A Linux transport therefore must not interpret
the two vectors as interchangeable completion interrupts, and must serialize
FIFO drain/post state outside hard-IRQ context. The offline FIFO model exposes
only these two named vectors and rejects every other index.

After discovery, `AppleSEPManager::_doorbellAction` drains the inbox until the
mailbox getter returns an error. It copies only FIFO words 0–2 into the
12-byte `AppleSEPMessage`, rejects endpoint values with any of bits 5–7 set,
looks up the remaining endpoint in a fixed 32-entry table, and drops records
for an absent entry. Each endpoint owns a 32-index circular FIFO; because the
producer treats `next == consumer` as full, its usable capacity is 31 records.
Queueing never overwrites the oldest record. A disabled endpoint retains its
pending records but does not dispatch them. `endpoint-router.py` models these
bounds offline, rejects transport-error metadata before routing, preserves
FIFO order, and fails on the 32nd undrained record. Discovery endpoint `0xfd`
is intentionally outside this normal router; it belongs to the earlier
discovery callback phase.

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

## Recovered Intel biometric bridge path

The Catalina 10.15.7 x86_64 `biometrickitd` changes the likely architecture
for Intel Macs. It imports `BridgeXPC.framework`, constructs a
`BiometricKitBridgeConnection`, and opens the remote service
`com.apple.eos.BiometricKit`. This is direct evidence that the host daemon's
high-level biometric path crosses BridgeXPC into bridgeOS. It does **not** yet
prove whether bridgeOS ultimately reaches `sbio` through the same generic SEP
transfer recovered below, and it does not provide BridgeXPC's byte-level USB
serialization.

The bridge connection sends Foundation-object arrays whose first element is a
method number. Static disassembly recovers these method IDs:

| ID | Method |
| --- | --- |
| `0` | get bridge version |
| `1` | get service-open state |
| `2` | get system boot time |
| `3` | perform command |
| `4` | set IORegistry property |
| `5` | read calibration data from EEPROM |
| `6` | get continuous Mach time |
| `7` | get Mach timebase information |
| `8` | get OS version |
| `10` | set bridge client version |
| `11` | read calibration data from FDR |
| `12` | set OS-transaction retained state |

Method `3` has the exact logical request
`[3, command:uint32, input:NSData-or-BTNil, outputCapacity:uint64]` and expects
`[status:NSNumber, output:NSData-or-BTNil]`. The host biometric wrapper invokes
it with bridge command zero. Its input begins with four little-endian 16-bit
fields followed by opaque input bytes:

```text
offset  size  field
0       2     magic 0x4d42 (bytes 42 4d)
2       2     biometric command
4       2     command version
6       2     input value
8       ...   input data
```

`bridge-protocol.py` captures this verified logical envelope. It enforces
integer widths, the inner magic, explicit input/output caps, reply arity, and
object types. Its later framing helpers serialize the supported subset as a
binary property list, but nothing in the module opens BridgeXPC, USB, PCI, or
SEP. Sending raw SBIO application commands from the x86 host may bypass
required bridgeOS state.

### Recovered enrollment, identity, match, presence, and cancel commands

Static disassembly of Catalina 19H15 `biometrickitd` and its
`BiometricSupport` framework now recovers the first complete operation request.
`BiometricMatchOperation` initializes both user IDs to `0xffffffff`; Objective-C
allocation zero-initializes `processedFlags`. The daemon zeroes a 68-byte input,
writes the operation's processed flags and user ID into its first two
little-endian words, and sends command `4`, value zero, with no output buffer.
The generic wrapper supplies command version `1`:

```text
offset  size  ordinary-match field
0       4     processedFlags = 0
4       4     userID = 0xffffffff by default
8       60    zero (special-mode union)
```

That trailing union can instead carry an ACM credential-set context,
extend-enrollment identity/authentication data, or biometric-lockout-bypass
credentials. Those are not ordinary matching and are intentionally forbidden
by `biometric-command.py`. The module accepts only flags zero and a completely
zero special union. This is stricter than Apple's internal object and prevents
the research codec from becoming a generic privileged-command constructor.

The same daemon calls presence detection as command `0x26` and cancellation as
command `0x0c`, each with value zero and no input/output. These calls return
only whether the operation started; match progress and identity results arrive
as later asynchronous BiometricKit service-status events. A separate
BridgeXPC connection-control envelope is an array of exactly four objects, but
it is not the biometric result discriminator.

The Linux-native enrollment entry point is also now recovered. Ordinary,
token-free enrollment is command `3`, version `1`, value zero, with this exact
48-byte input and no synchronous output buffer:

```text
offset  size  ordinary-enrollment field
0       4     flags/reserved = 0
4       4     userID
8       4     usingAuthToken = 0
12      4     tokenLength = 0
16      32    authorization token = zero
```

This starts a multi-stage asynchronous enrollment; command acceptance alone is
not enrollment success. The offline codec deliberately cannot express Apple's
authorization-token form. It also recovers the operations needed to manage
Linux-created templates:

| Command | Input | Output |
| --- | --- | --- |
| `0x0f` maximum identity count | none | exactly one 32-bit count |
| `0x41` free identity count | 32-bit user ID | exactly one 32-bit count |
| `0x42` identity list | 32-bit user ID | zero or more 20-byte identity records |
| `0x0d` remove identity | one 20-byte identity record | none |

Each identity record is a 32-bit user ID followed by a 16-byte UUID. The
research codec caps lists/counts at 64, rejects malformed or duplicate records,
and can verify that an enrollment snapshot added exactly one identity for the
requested Linux user without removing or changing anything else. That snapshot
delta is still only one condition: a live implementation must additionally
correlate the asynchronous event with the active enrollment and require a
known-success terminal status before persisting or exposing the new identity.

Catalina's `serviceStatus:version:ordinal:data:timestamp:` dispatch is now
partially mapped. Status `0xe3ff8002`, version `1`, carries a match result;
status `0xe3ff8003`, version `1`, carries a terminal enrollment result whose
first 20 bytes are the newly created identity. The daemon adds that identity to
its list, notifies the enrollment client, and advances its operation queue.
Status `0xe3ff800b`, version `1`, is a separate match-activity event with at
least nine bytes. The offline boundary accepts only exact supported
result/version pairs and does not interpret the activity event as success.
The result handlers select the first object from the daemon's serialized
`activeBioOpsQueue`; enrollment then calls `switchToNextBioOperation:`. They do
not use the service callback's ordinal as a request identifier. Consequently,
the narrow Linux model permits exactly one active biometric operation and
accepts a terminal event only when its type matches that host-tracked
operation. Cancellation, timeout, connection loss, an unexpected event type,
or a second concurrent request must clear/fail the operation rather than reuse
an event.

The daemon's eventual match-result parser does expose a strict identity core.
It requires at least `0xc70` bytes, reads a 32-bit user ID at offset zero and a
16-byte identity UUID at offset four, then reads a lockout-list count at
`0xc6c`. It requires at least `0xc70 + 4 * count` bytes and resolves a match by
looking up the returned user-ID/UUID pair in its separately maintained identity
list. User ID `0xffffffff` is the no-identity value. The offline codec accepts a
stricter exact-length form and caps that list at 64 entries. A decoded pair is
**not authentication proof by itself**. Disassembly now pins the daemon's
actual success branch: it compares the result's first dword with
`0xffffffff`; that value goes to `NO-MATCH`, while any other value enters the
identity lookup path. Linux must still bind the event to the active request and
compare the returned user-ID/UUID pair with a trusted identity obtained from a
separate sensor enumeration.

`authentication-result.py` makes those authorization conditions mechanical
without adding I/O. Construction arms one match for one expected Unix user and
requires a nonempty, duplicate-free trusted identity snapshot containing only
that user. It accepts only service event `0xe3ff8002`, version `1`, and the
strict Catalina result shape. `0xffffffff` completes as an explicit no-match;
an exact trusted user-ID/UUID completes as a match; a different user, unknown
UUID, malformed result, activity event, repeated terminal event, or missing
terminal event fails closed. A rejected event permanently poisons that attempt,
and timeout, cancellation, or transport loss can explicitly abort it. This is
the first complete offline decision model
that could eventually sit behind fprintd/PAM, but it is not connected to either
until the current bridgeOS ABI and live event transport are verified.

Current bridgeOS compatibility and the live transport still must be proven
before a result can be interpreted on Linux.

`macos-biometric-command-evidence.py` verifies these constants and instruction
sequences directly in the retained binaries. The finding is exact for Catalina
19H15 but is not yet a claim that macOS 26.6.2 or its current bridgeOS retained
the same operation ABI. No command is connected to the live query runner.

The Catalina `BridgeXPC` framework resolves a named EmbeddedOS remote service
to an IPv6 socket. Every record starts with this exact 16-byte little-endian
header:

```text
offset  size  field
0       2     magic 0xb892
2       2     protocol version 1
4       4     kind (0 = no-op, 1 = HELO JSON, 2 = binary-plist message)
8       8     body length
```

The initial HELO body is JSON and advertises maximum protocol version `1`, the
OS build, BridgeXPC framework version, and process name. Normal Foundation
messages are serialized with `NSPropertyListBinaryFormat_v1_0` (format value
`0xc8`), so their body starts as an Apple binary property list. The offline
codec now produces the four-key HELO, the exact record header, and a
binary-plist method-3 body. The receive side validates magic, protocol version,
kind, no-op length, and a caller-selected body cap before parsing. It
intentionally refuses to serialize a missing input because the private
`BTNil` representation has not been recovered.

That endpoint is now statically recovered too. Catalina's
`EmbeddedOSSupportHost` uses the fixed T2 link-local address
`fe80::aede:48ff:fe33:4455`, scoped to the iBridge NCM interface. Its service
table assigns enum `kEOSServiceBiometricKit` (index `19`) host port `52032`
(`0xcb40`); the sockaddr constructor byte-swaps that value into `sin6_port`.
On this Linux installation the already-loaded `t2bce_vhci` exposes USB device
`05ac:8233` (“Apple T2 Controller”) through `cdc_ncm` as `enp4s0f1u1`. It has
carrier, MAC `ac:de:48:00:11:22`, and no configured IP address. Its sysfs path
descends directly from PCI function `04:00.1`, confirming it is the internal
T2 link rather than an external Ethernet adapter.

`bridge-protocol.py` can form the standard Python IPv6 tuple
`(address, 52032, 0, interface_index)` entirely offline. It does not create or
connect a socket. Before any live query, Linux still needs a narrowly scoped
link-local configuration on that interface, a bounded connect/read timeout,
HELO negotiation, and strict response validation. Those actions are deferred
because they change live network/device state.

The safest first application-level request is now identified. Bridge method
`0` sends the one-element binary-plist array `[0]` and performs no biometric
command. Its reply must be exactly two `NSNumber` objects: a signed 32-bit
status and an unsigned bridge-version value. The offline codec constructs
that passive query and rejects malformed, oversized, incorrectly typed, or
out-of-range replies. A future live runner should send only HELO plus this
query, allow exactly one reply frame, enforce short deadlines, and close; it
must not fall through to method `3`, enrollment, matching, or any SBIO command.

That runner now exists as `bridge-query.py`, but has not been executed live.
Its default mode emits offline fixtures only. The gated path verifies the
exact internal USB/PCI ancestry and carrier, sets a maximum five-second socket
deadline, caps every body at 64 KiB, consumes at most four frames (to permit a
peer HELO/no-op), sends only method `0`, and validates the two-number reply.

### Sonoma cross-check and remaining endpoint gap

The official Sonoma 14.8.9 (`23J631`) InstallAssistant was also inspected
offline. Its post-install BOM confirms a 1.4 MB `usr/libexec/biometrickitd`
and the BridgeXPC and EmbeddedOSSupportHost framework stubs. The framework
executables themselves are zero-length dyld-shared-cache placeholders, so the
installer does not expose them as ordinary Mach-O files.

The x86_64 software-update ramdisk contains current
`RemoteServiceDiscovery.framework` (`RemoteServiceDiscovery-131.120.2`) and
`RemoteXPC.framework`. Its strings identify the `ncm-device`, `ncm-host`, and
`bridge` transports. The current framework exposes named operations including
`list_services`, `get_service`, and `check_service`; its client-side API sends
those requests through `com.apple.remoted.control` and receives a connected
service socket from `remoted`. In other words, the current host architecture
delegates endpoint selection and connection setup to the daemon rather than
publishing a fixed port in this framework. These artifacts do not confirm
Catalina's fixed BiometricKit port `52032` for the bridgeOS version currently
installed on this machine.

The Sonoma payload was scanned one archive at a time in separate user scopes,
each capped at 1 GiB RAM and 256 MiB swap. The only directly materialized
BiometricKit daemon records were its launchd plist and manual page. The daemon
binary is an AppleArchive asset reconstructed from split payload/patch records,
not a standalone file in any one `payload.NNN`. Standard YAA listing therefore
cannot recover it, and `ipsw` delegates that reconstruction to Apple's macOS
`aa` tool. This is a tooling boundary, not evidence that the binary is absent.
The same check found an 808 KB final `usr/libexec/remoted` in the BOM but no
standalone copy in any individual payload, so it has the same reconstruction
boundary. The macOS collector therefore captures both daemons.

That installer-era evidence gap is now resolved by the post-enrollment APFS
image. Its sealed System snapshot identifies the actual installation as macOS
26.6.2 build `25G83`, not Sonoma. A disposable, read-only `apfs-fuse` build was
used only to bypass its obsolete container-keybag parser; System, Preboot, and
Recovery are unencrypted, while the FileVault Data volume was not opened.

The installed universal `usr/libexec/biometrickitd` has SHA-256
`636dd137dace867359f389437c198d8c4cd9dc12896e9017d94cb6c567e84e4b`;
its extracted x86_64 slice is
`248d4521007f95c916ae682c1a3d13d1c431626f4be4e84a0758d6dfbc94ce20`.
That slice links RemoteServiceDiscovery version `219.160.4` and BridgeXPC
version `39.0.0`, imports `_remote_device_copy_service` and
`BridgeXPCConnection`, contains both `com.apple.eos.BiometricKit` and its
`.ta` companion, and contains selectors `initForRemoteService:` and
`activateConnection:`. Disassembly around `0x100049df6..0x100049f4c` proves
the order: copy the named RSD service, initialize a BridgeXPC connection from
that remote-service object, then activate the connection. This is stronger
current evidence than Catalina's fixed table and establishes the host-side
named-service route.

`macos-biometric-evidence.py` makes those coupled facts reproducible against a
thin x86_64 slice and optionally pins its SHA-256. It rejects the wrong
architecture or any missing framework, import, service name, or selector.

The same installed slice also resolves whether Catalina's logical method ABI
survived. Its Objective-C metadata maps these current implementations:

```text
0x1000263d0  getBridgeVersion:
0x100026767  getServiceOpened:
0x100026b03  performCommand:input:output:capacity:
```

Their bodies still construct `[0]`, `[1]`, and
`[3, command:uint32, input:NSData-or-BTNil, capacity:uint64]`. Methods 0 and 1
each require a two-element reply; the first object is an `NSNumber` converted
with `intValue`, while the second uses `unsignedIntegerValue` for method 0 and
`boolValue` for method 1. Method 3 likewise requires two reply objects and
accepts only `NSData` or the private `BTNil` singleton for output. This proves
the logical array ABI on macOS 26.6.2.

The installed System Cryptex also supplies the current x86_64 BridgeXPC 39
framework, whose extracted slice has SHA-256
`d1246e1a9061f226605ef86cfa5cd0c3b54b08bde76dd8c22ffa14af59f2212d`.
Its exact instruction sequences load `0x10001b892` for HELO and
`0x20001b892` for ordinary messages: little-endian magic `0xb892`, protocol
version 1, and kinds 1 and 2. It stores the payload length at header offset 8,
reads a 16-byte header, requests property-list format `0xc8` (binary), and
retains the same four HELO keys. Thus the framing and serialization recovered
from Catalina are directly confirmed in the installed current framework.
`macos-bridgexpc-evidence.py` makes those binary facts reproducible and can pin
the slice checksum; it performs no network or device access.

The offline codec now includes strict current method-1 request/reply handling.
It requires an actual property-list boolean—not integer `0`/`1`—and preserves
signed-32 status, arity, type, and body-size checks. It still refuses to encode
`BTNil`.

Linux has now completed that bounded directory exchange against the verified
Multiverse port `59602`. A strict 7,560-byte server transcript advertised
`com.apple.eos.BiometricKit` on boot-dynamic port `49165`, matching the macOS
boot observation. The private transcript is stored outside the repository
with mode `0600`; its SHA-256 is
`5fb049a9a94f6e0238183a738fc6ab70ed905d2a6f1681fe985fe025a84bf47d`.
The parser also records that current Multiverse uses an empty dictionary,
rather than null, for its initial no-data channel-control record.

A first Linux connection to the transcript-derived service port completed its
TCP handshake, but the peer returned no BridgeXPC bytes within the three-second
bound after an exact current 119-byte HELO and method-0 version request. This
narrows the remaining gap to service activation or pre-BridgeXPC transport;
it does not justify sending method 3. The capture-bound runner is disabled in
source after the supervised attempt and contains no method-3 or SBIO send path.

The advertised entry says `UsesRemoteXPC: false`, `EncryptSocketData: false`,
and carries entitlement `com.apple.private.bmk.remote.allow`. Following the
public RSD client's lockdown-style path, Linux sent one length-prefixed XML
`RSDCheckin`. The T2 immediately emitted a valid BridgeXPC HELO identifying
`bkremoted`, bridgeOS build `23P6068`, and BridgeXPC version `39`. It did not
emit the generic `RSDCheckin`/`StartService` plist pair. Sending either the
macOS-sized client HELO or a HELO mirroring the peer then caused an immediate
TCP reset, before method 0. This is strong evidence that the check-in-shaped
write wakes or advances the listener, but it is not yet proof that generic
RSD check-in is the correct activation record. The next experiment must recover
the exact macOS handoff/first-write boundary rather than guessing another
biometric command.

A clean follow-up established the actual ordering without that speculative
prefix: the listener is server-first and immediately emits the same 101-byte
HELO on accept. Linux now consumes and validates it before writing anything.
The connection remains open after the exact reconstructed client HELO, but the
subsequent method-0 request receives no bytes within three seconds. Thus the
check-in experiment's reset came from contaminating the stream, while the live
remaining mismatch is specifically in the reconstructed client HELO or first
serialized method request. Exact current macOS outbound bytes are required
before any further live command class is justified.

Read-only macOS reconstruction with the current Foundation serializers narrowed
the logical-message encoding. `NSPropertyListSerialization` produces an exact
46-byte binary plist body for `[0]`; with BridgeXPC's 16-byte header the
historical raw 62-byte test frame was byte-for-byte identical to
`bridge-query.py` and had SHA-256
`a60083fc2ec4be95418906235ac3024e9d01eb8661d82a34c2dea0bf3d0f4b1d`.
This established the inner message bytes, but did not establish that the inner
array was itself the top-level transport object. Current `bkremoted` later
proved that assumption false.

The HELO has no single process-independent byte encoding. Across 24 fresh
Foundation processes, `NSJSONSerialization` emitted 15 different permutations
of the same four dictionary keys. Every body was 103 bytes and every complete
frame 119 bytes. This is expected NSDictionary enumeration behavior; JSON
object member order is not semantic. The Linux ordering is one member of the
24-permutation native equivalence class. `macos-bridge-wire-compare.py` now
reports exact fields, exact bytes, and membership in that native key-order
class separately. A live macOS frame is still needed to name the one ordering
chosen by the current `biometrickitd` process, but key order itself cannot be a
sound BridgeXPC compatibility requirement.

A subsequent Linux experiment also tested the stricter alternative handshake
barrier: send the client HELO, consume and validate the peer HELO, and only then
release method 0. The T2 acknowledged all 62 request bytes but returned no
application data during the five-second bound. A metadata-only packet trace
showed a clean handshake, the 119-byte client HELO, the peer's 117-byte framed
HELO, the 62-byte method-zero request, ACKs in both directions, and an orderly
FIN after the local timeout—no retransmission or reset. Catalina BridgeXPC
disassembly independently shows that `-connected` writes its HELO, starts a
read, and immediately flushes its queued request without waiting for the peer
HELO. The prototype therefore retains that native back-to-back send order.
Together these results rule out TCP delivery and either plausible HELO/request
barrier. The remaining gap is now above a healthy raw TCP stream and below the
known BridgeXPC method ABI, most likely in remote-service activation/handoff or
bridgeOS policy state. Method 3 remains gated.

The directory-session lifetime has also been tested directly. A new coupled
runner performed fresh Multiverse discovery, retained that exact directory TCP
connection, opened the newly advertised BiometricKit port, and issued only
HELO plus method 0 before allowing the directory context to close. The service
again supplied its valid HELO but no method reply within five seconds. Thus a
saved stale port or prematurely closed RSD directory is not the cause.

Catalina's Intel RemoteServiceDiscovery framework further constrains the local
handoff. Its exact `remote_service_create_connected_socket` implementation
sends `{cmd: "connect", connect_timeout: ...}` over a service-specific local
XPC endpoint, duplicates the returned `fd`, and invokes only
`remote_socket_poll_connect_sync` on that descriptor. The reproducible verifier
pins framework SHA-256
`48d1c6ca89f7a774d02689b4bf662578669f4b81dfeccc26f26be22a8c20351f`.
This proves the client library injects no post-handoff network preamble; it does
not yet rule out an activation action performed inside macOS `remoted` before
the descriptor is returned.

Inspection of the exact installed `remoted` now rules that out too. Its
`RSDRemoteMultiverseDevice::connectToService:withTcpOption:` converts the
directory-advertised port with `atoi` and directly calls either
`multiverse_device_connect` or `multiverse_device_connect_with_timeout`; the
only local service-handler additions are bounded connect timeout/TCP keepalive
options and fd duplication. `macos-multiverse-service-connect-evidence.py`
pins those unique instruction sequences in the installed x86_64 slice. No
RSDCheckin, StartService, entitlement token, or other service-specific bytes
are written to the network before BridgeXPC.

The current `biometrickitd` setup order also rules out method 10 as the missing
first request. In `serviceMatchBridgeWithIterator:` it calls
`getBridgeVersion:` first; only after a successful version greater than one
does it call `setBridgeClientVersion:2`. The enhanced static verifier pins both
ordered call sites. Linux is therefore correct to expect method 0 to work
without a preceding method 1, method 10, or biometric command.

A final bounded coupled test used the machine's SMBIOS UUID, rather than a
fresh random UUID, in the RemoteXPC handshake. Directory discovery and service
connection again succeeded, the T2 emitted its valid BridgeXPC HELO, and the
byte-exact method-0 frame again received no application reply in five seconds.
The source gate was restored false. This makes the handshake UUID choice a poor
explanation and leaves the behavioral difference inside Multiverse socket
construction or BridgeXPC connection state, not an omitted application method.

The exact installed Intel MultiverseSupport socket routine was then
disassembled directly from the dyld cache. It uses IPv6 TCP, nonblocking mode,
the device IPv6 address and scope ID, and Darwin `SO_INTCOPROC_ALLOW`; it does
not bind a source address or write a preamble. Linux has no equivalent for that
Apple internal-coprocessor option. The gated coupled probe mirrored every
portable behavior, including `SO_BINDTODEVICE` on both sockets and a bounded
nonblocking connect. The T2 again supplied HELO but did not answer method 0 in
five seconds, after which the live source gate was restored false. Ordinary
socket selection and blocking state are therefore no longer plausible causes.

The bridgeOS side is no longer inferred solely from host code. The Catalina
`EmbeddedOSFirmware.pkg` contains an LZFSE-compressed `osrd` IM4P for
`iBridge1,1`; after bounded extraction, its HFS+ recovery root supplies the
actual armv7k `/usr/libexec/bkremoted` from bridgeOS 3.0 (`14Y910`). The new
`bridgeos-bkremoted-evidence.py` pins SHA-256
`453e1b81a9ea0a0fc7a3011b84d770a055340f7e7b47d132f23dbe76dcb08b8c`
and two unique instruction sequences. `BiometricKitBridge::getBridgeVersion:`
checks only whether its output pointer exists, stores literal version `2`,
clears `_clientVersion`, and returns status zero. Separately,
`BiometricKitBridgeConnection::performMessage:` accepts a nonempty array,
extracts its first integer, and dispatches method values 0 through 10 through
a jump table. There is no enrollment, service-open, sensor-ready, or preceding
method-10 gate on method 0 in this real bridge daemon.

This is historical server code rather than the current `23P6068` binary, so it
cannot prove current implementation identity. It does establish the design
boundary: a valid method-zero message that reaches the daemon dispatcher has
an immediate reply independent of biometric state. Linux receives no reply,
so the remaining mismatch is below `bkremoted` method dispatch—inside
BridgeXPC's connection/HELO state or an equivalent current transport gate—not
inside Touch ID initialization.

The matching bridgeOS 3.0 BridgeXPC framework was reconstructed from that
same recovery dyld cache with corrected Mach-O section offsets. Its connection
state machine is more permissive than the remaining hypothesis suggested:
`-connected` changes state 2 to state 3, writes its own HELO, starts the read,
and flushes queued messages. `-send:` queues only in states 1/2 and writes in
state 3. On receive, frame kind 1 is mapped, deserialized by Foundation with
option 4, and logged as the peer HELO; frame kind 2 goes to ordinary message
processing. The kind-1 arm contains no HELO-field comparison and no connection
state mutation before it rejoins the common read loop. The checksum-pinned
`bridgeos-bridgexpc-evidence.py` verifier records the four exact instruction
sequences against framework SHA-256
`df97ee9ee6f37383303e153bc92f3528f1478fa1268f89b50c5e666c747c3b37`.

The historical-version caveat is now removed. Apple's 742,609,165-byte restore
IPSW for `iBridge2,14` has SHA-1
`19e51a77d7d74c956f7aad83b724c46221502c3e`; its manifest identifies bridgeOS
10.6 build `23P6068`, exactly matching the live T2. Read-only extraction of its
APFS system image yielded current arm64 `bkremoted` (SHA-256
`29b99cb5ba41ef18122d1920986707d5fc7893bf097e343d41f4ec0a87b32630`)
and BridgeXPC 39 (SHA-256
`f72baee6445b2d894e49b889055aebd57318332afdb5c11f24df4f7474cd002a`).

The current framework retains the same exact logic. `-connected` changes state
2 to 3, calls `writeHELO`, `readMessage`, and `flushQueue` in that order.
`-send:` queues in states 1/2 and writes in state 3. Completed-body dispatch
branches first on kind 1 and then kind 2. The entire kind-1 arm initializes a
string with encoding 4, logs `Received HELO message`, and rejoins the common
`readMessage` continuation without comparing a HELO field or changing
connection state; kind 2 calls `processIncomingMessage:`. The checksum-pinned
`bridgeos39-bridgexpc-evidence.py` verifier makes those current-firmware facts
reproducible. Therefore HELO negotiation or a BridgeXPC connection-state gate
cannot explain Linux's silent method 0.

The exact current `bkremoted` removes the daemon-version caveat as well.
Objective-C relative-method metadata maps `getBridgeVersion:` to the arm64
implementation at `0x100001958` and the service wrapper at `0x1000057f8`.
The implementation checks only whether its output pointer is non-null, stores
literal bridge version `3`, clears `_clientVersion`, and returns status zero.
The wrapper boxes that signed status and unsigned version into the exact
two-element array already expected by the Linux codec. `performMessage:`
accepts method zero and dispatches it directly through its jump table. The
checksum-pinned `bridgeos106-bkremoted-evidence.py` verifier records all three
instruction sequences against the current daemon. Thus a valid method-zero
message reaching the current daemon must produce `[0, 3]`; silence means the
message has not reached that dispatcher, concentrating the remaining gap in
the RSD service handoff before `bkremoted` rather than Touch ID state.

Apple's XNU `xnu-12377.1.9` source closes `SO_INTCOPROC_ALLOW` as a
peer-visible candidate.
`sosetopt` gates the option on `PRIV_NET_RESTRICTED_INTCOPROC`, then sets only
the local inpcb flag `INP2_INTCOPROC_ALLOWED`. IPv6 send/receive policy rejects
sockets lacking that flag on interfaces classified as internal coprocessors.
It is not placed in a TCP option, IPv6 extension, BridgeXPC frame, or payload.
Linux already sends, ACKs, and receives on this interface, so it has satisfied
the behavior the Darwin flag unlocks. `xnu-intcoproc-evidence.py` makes this
source chain reproducible. The remaining boundary is now above the proven TCP
delivery but outside BridgeXPC's HELO state machine—most likely the exact RSD
service handoff context or the current daemon's message/reply path—not a
missing Linux socket mark.

A fresh same-boot run after the current-firmware recovery reconfirmed the
boundary on a newly advertised service port. Packet metadata showed distinct
119-byte client-HELO and 62-byte method-zero segments, both acknowledged by
the T2, followed by its 117-byte HELO and no application reply. Sending method
zero only after first receiving the server HELO also timed out, so the client
HELO cannot be poisoning the stream. A 250 ms post-HELO delay ruled out the
small interval between BridgeXPC listener activation and `bkremoted` installing
its accepted-connection event handler.

Two remaining peer-visible socket differences from the successful macOS boot
were tested independently and restored immediately. Raising the T2 interface
MTU from Linux's 1500 to macOS's observed 16000 did not change method zero.
Binding the directory and service sockets to macOS's recorded source ports
49153 and 49174 likewise did not change it. The T2 continued to acknowledge
the request and send its HELO in every case.

The exact current bridgeOS 10.6 service definition and `remoted` binary were
then recovered read-only from the same IPSW. The launchd definition exposes
`com.apple.eos.BiometricKit` with `UsesRemoteXPC=false`; its entitlement is a
host-side local-client check. Current bridgeOS `remoted` source version
219.160.4 creates a raw service listener, and its
`shouldExposeRemoteService:` implementation returns true unconditionally.
The service listener is therefore not waiting for an additional RemoteXPC
message on the service socket. The next bounded runtime discriminator is a
true power-off/cold start, because ordinary macOS-to-Linux reboots do not fully
remove T2 power. If that still fails, further progress requires targeted
successful-path observation from macOS rather than another guessed Linux
application message.

That cold-start discriminator has now been run. After a complete shutdown,
external-power removal, and direct Linux boot, the host had 93 seconds of
uptime when inspected. Linux restored only the proven
`fe80::aede:48ff:fe00:1122/64` address; carrier, peer neighbor discovery, and
two scoped ICMPv6 replies then confirmed the internal link. A fresh directory
exchange on port 59602 advertised BiometricKit on boot-dynamic port 49223.
The bounded service connection again sent separate 119-byte HELO and 62-byte
method-zero TCP segments. bridgeOS acknowledged both, sent its valid 117-byte
HELO, emitted periodic keepalive probes, and returned no application reply
within five seconds. The cold-start hypothesis is therefore closed. TCP
timestamps are deliberately not used as bridgeOS uptime evidence because
modern stacks apply per-connection timestamp offsets.

The silent-reply boundary is now solved. Disassembly of the exact current
`bkremoted` (`23P6068`) shows that `BiometricKitBridgeTransport` requires every
logical call to be wrapped in a four-object array:
`[1, false, replyUUID, logicalMessage]`. Replies are
`[1, true, sameReplyUUID, logicalReply]`. The previously transmitted `[0]` was
a syntactically valid property list, so BridgeXPC kept the connection open, but
`handleEnvelope:` rejected its array count before BiometricKit method dispatch.

Linux now emits `[1, false, UUID, [0]]`, validates all four reply fields, rejects
the daemon's no-reply sentinel, and requires exact UUID correlation. On
2026-08-28 a bounded coupled query on a freshly directory-advertised port
returned `(status=0, bridgeVersion=3)`. Packet metadata recorded a 119-byte
client HELO, a 113-byte enveloped request, the peer's 117-byte HELO, and a
132-byte enveloped reply, followed by an orderly close. This is the first
confirmed working Linux BridgeXPC request/reply exchange with T2 BiometricKit
in this investigation. Earlier 62-byte timeout experiments remain documented
above as the evidence trail, but their conclusion that the method request was
complete is superseded.

A second fresh coupled connection sent only enveloped read-only method 1
(`getServiceOpened:`). It returned `(status=0, opened=true)`. Packet metadata
showed a 110-byte request and 131-byte reply. Thus the daemon is not merely
reachable: its BiometricKit service is active and reports itself open. The
prototype exposes this query as a separate typed function; its command-line
live path remains method-zero-only.

The first method-3 biometric command is also confirmed. Linux wrapped the
Catalina-derived command `0x0f` in the exact `0x4d42` header and received
status zero plus a maximum identity count of 5. Command `0x41` returned a free
count of 3 for UID 1000. Read-only command `0x42` returned no identities for
Linux UID 1000 and exactly one identity belonging to macOS UID 501, consistent
with the one fingerprint enrolled during reverse engineering. Identity UUID
bytes were not logged or committed. The free count is not simply maximum minus
identity records, so it is not used as an enrollment-completion predicate.

This live exchange also identifies BridgeXPC's private `BTNil` property-list
encoding: current bridgeOS serializes it as the lower-case reserved UUID string
`d4161201-daf5-4bbd-ae4f-9bf319fabbe0`. The strict method-3 decoder maps only
that exact value to `None`; other strings remain invalid.

Persistent BridgeXPC sessions and unsolicited service events are now proven
too. A single live connection successfully carried method 0 followed by the
maximum-identity biometric query without a second HELO. A bounded presence
detection command then returned synchronous status zero, immediately delivered
a server-initiated no-reply envelope, and accepted same-session cancellation
with status zero. The event's exact logical shape was
`[9, 0xe3ff8000, record, referenceTimestamp, continuousTimeDelta]`. Its 40-byte
record decoded to inner status `0xe3ff8001`, version 1, ordinal 59, and zero
data bytes. The decoder enforces five-object arity, exact channel/method,
unsigned timestamps, a 64 KiB data cap, and exact `40 + dataSize` length. The
presence probe reports only types, integer metadata, and data length—never raw
event bytes—collects at most two records, and always cancels in a `finally`
block.

The authentication path is now proven live in
`match-authentication-probe.py`, with its live source gate closed. On one
persistent connection it freshly enumerates identities for exactly one UID,
arms one `MatchAuthentication`, starts only the ordinary zero-special-mode
match command, accepts the proven zero-data `0xe3ff8001` ready event and the
minimum-nine-byte `0xe3ff800b` activity event as nonterminal, and requires
exactly one `0xe3ff8002` terminal result. A non-`0xffffffff` result succeeds
only when both its UID and 16-byte sensor UUID match the fresh trusted snapshot.
No-match is an explicit false decision; another UID, unknown UUID, malformed
record, unexpected status, timeout, event flood, or transport loss fails the
operation permanently. Cancellation is attempted on every post-start exit.
The public result reports only the Boolean decision, UID, identity count,
status numbers, and cancel status; it never exposes UUID bytes.

On 2026-08-28 a coordinated scan with the macOS-enrolled finger reached a
bridgeOS 10.6 terminal match event: status `0xe3ff8002`, version 2, and exactly
`0xc9c` bytes. A privacy-limited layout probe searched only for the freshly
enumerated trusted 20-byte identity record and reported one occurrence at
offset zero; it did not print the record, UUID, or opaque result bytes. The
version-2 decoder consequently requires the exact `0xc9c` size and consumes
only that stable identity prefix, leaving the changed trailing metadata opaque.
A second coordinated scan then completed end to end as `matched=true` for UID
501 against the fresh trusted snapshot and cancelled with status zero. A third
run used a finger not enrolled in macOS; the same bounded version-2 terminal
shape resolved to `matched=false`, returned no matched UID, and cancelled with
status zero. This proves both the positive and explicit no-match paths without
logging either result record. These are the first confirmed successful and
rejected Linux-initiated T2 Touch ID decisions in this investigation.

Linux-native enrollment is now composed offline in `enrollment-probe.py`, also
with a closed live source gate. A checksum-pinned Catalina jump table maps
every service status from `0xe3ff8002` through `0xe3ff800b`; method-specific
minimum payload sizes for progress statuses are enforced. The runner takes a
fresh UID-scoped identity snapshot, starts only the 48-byte token-free ordinary
enrollment form, caps the operation at 256 events, requires version 1 and the
exact `0xe3ff8003` terminal identity, then independently enumerates again. It
completes only if exactly one identity was added, none changed or disappeared,
the new identity belongs to the requested Linux UID, and its UUID equals the
terminal event. Timeout, malformed/unknown progress, event flood, terminal
mismatch, or any other list delta fails closed; cancellation is attempted on
every post-start exit. Its result reports counts and statuses but not UUIDs.

The first live Linux enrollment start for UID 1000 was rejected synchronously
with status `-3`, before the sensor accepted a touch; UID 501 produced the same
result. Exact macOS initialization (`getBridgeVersion` returning 3, then
`setBridgeClientVersion:2`, then `getServiceOpened`) did not change it. Read-only
inspection of the installed macOS 26.6.2 `biometrickitd` (the previously pinned
x86_64 hash `248d4521...c94ce20`) shows that communication protocol versions
above 1 send command 3, version 2, with 68 bytes: the Catalina 48-byte enrollment
request followed by a 20-byte `deviceGroup`. Its Objective-C selector references
identify the copied fields as `userID`, `authData`, and `deviceGroup`; the
compiler-emitted type for `authData` remains two 32-bit words plus a 32-byte
token. A zero device group still returned `-3`. A bounded, immediately cancelled
probe established that group type 1 with a zero UUID selects the built-in sensor;
types 2 through 5 return status 257 as nonexistent/unsupported groups. The valid
built-in group still returns `-3`, isolating the remaining prerequisite to the
40-byte enrollment authorization data or its associated authenticated state.
No probe waited for a touch or added an identity. Reproducing Apple's legitimate
token acquisition path, rather than weakening or guessing it, is the next
enrollment milestone.

That macOS enrollment-authorization path is now statically recovered for
macOS 26.6.2 build 25G83. The built-in `Touch ID & Password` settings
extension (universal SHA-256 `14cc6fe7...e4798b3`, x86_64 slice SHA-256
`e86ab74e...c359f1`) creates a fresh ACM context, validates the password with
AppleKeyStore `_aks_verify_password`, and exports the authenticated context
with `ACMContextGetExternalForm`. The latter is exactly 16 bytes: its x86_64
implementation passes length `0x10` to the context serializer/copy callback.
The settings extension stores that `NSData` as `credset`, stores the current
UID as `userid`, and gives both to `BiometricKitUI`. The UI assigns the bytes
with `-[BKEnrollOperation setCredentialSet:]` before starting enrollment.

Current `BiometricSupport` recognizes the credential under the exact key
`BKOptionEnrollWithCredentialSet`. Its
`-[BiometricKitXPCServer parseAuthDict:toAuthData:]` also recognizes separate
credential-set keys for ordinary authentication and extend-enrollment, and
separate auth-token keys including `BKOptionEnrollWithAuthToken`. It requires
the selected object to be `NSData`, rejects lengths above 32, and accepts the
credential-set external form at length 16. For the ordinary settings path it
constructs the command-3 authorization field as:

```text
offset  size  value
0       4     usingAuthToken = 0
4       4     tokenLength = 16
8       16    opaque ACM context external form
24      16    zero padding
```

This closes the macOS request structure but does not make the opaque bytes a
portable password derivative. They are a reference to state created by
AppleCredentialManager/AppleKeyStore after successful password verification.
Linux must reproduce that authenticated ACM/AKS operation against the T2/SEP,
or use another Apple-supported credential provider, before submitting
enrollment. Capturing or replaying a macOS context across a reboot is not
treated as a design: validity across the macOS-to-Linux boot transition is
unproven and the context must be presumed boot/session-bound and fail closed.
No password or context bytes were observed during this analysis.

The Linux-side continuation now has symbol-rich Intel kernel evidence from the
matching macOS 14.5 KDK (`23F79`). Its AppleCredentialManager and AppleKeyStore
drivers were extracted read-only from the KDK payload. The universal binaries
hash respectively to
`bc205763bc595e5a62c408171668974cbd1ef1aea3602cf31d157105b2eb00f4`
and
`9a9370047244b9f14c24f04c9de247e920e882fbc89dc2440d279efff75eaff2`.
AppleCredentialManager exports `ACMKernContextCreate`,
`ACMKernContextCreateWithExternalForm`, the credential-add and policy-verification
entry points, and their `LibCall_*` serializers. AppleKeyStore's symbolized
`AppleKeyStore::verify_password` extracts the password and context `OSData`
buffers, calls `ipc_verify_secret_v1`, translates the secure-key-store result,
and only on success updates device state.

Crucially, AppleKeyStore does not obtain this credential through bridgeOS
BiometricKit. Its driver initializes an AppleSEPManager endpoint named exactly
`aks-endpoint`, allocates SEP-visible out-of-line buffers, and submits the
password-verification IPC to that endpoint. The matching KDK AppleSEPManager
binary (universal SHA-256
`cfa557d9afa5adec87ecc13bfd7175483c29c6c694b59e1bbcd401199c9ed72e`)
contains symbolized Intel implementations of endpoint discovery,
`AppleSEPIntelIOP::{getMailbox,postMailbox}`, `AppleSEPEndpoint` send/receive,
control-endpoint OOL setup, and named endpoint advertisement. This establishes
that producing the 16-byte enrollment credential on Linux requires the native
T2 SEP mailbox/endpoint transport plus the AKS/ACM serializers; the already
working Multiverse BiometricKit socket cannot issue it. The next offline task
is to recover those mailbox, endpoint-discovery, and OOL ABIs from the pinned
KDK binaries and connect them to the source-disabled PCI prototype before any
new live MMIO writes.

Further x86_64 analysis narrows that statement to two coordinated SEP
services. `AppleCredentialManager::getSEPEndpoint()` creates its endpoint at
fixed index `0x0a` and allocates separate `0x4000`-byte, page-aligned send and
receive OOL buffers. `LibCall_ACMContextCreate` submits ACM command `1`, expects
an exact 17-byte response, and copies its first 16 bytes into the opaque
context handle; the final byte is separate tracking metadata. Creating a
context therefore does not require inventing or persisting a token.

ACM's mailbox envelope is also exactly 12 bytes, but it is not the AKS format:
endpoint `0x0a`, an 8-bit message type, a little-endian 16-bit OOL payload
length, a 32-bit request value or response status, and a final reserved zero
word. The Intel endpoint layer inserts byte 0 and transmits the following
qword plus the zero third word. The receive callback rejects other endpoints,
bounds the announced length by the waiting caller's output buffer, and copies
only that many bytes from the receive OOL mapping. `acm-transport.py` models
this framing and adds strict message-type correlation before accepting a
reply; it performs no context creation or device I/O.

ACM also has an exact startup dependency. Before ordinary commands, the Intel
driver sends the eight-byte SCRD initialization payload `44 52 43 53 0a VV 00
00`, where `VV` is its one-byte negotiated version, using endpoint message
type 1, value 0. The token-free context-create command that follows is exactly
`44 52 43 53 01 00 00 01`: `DRCS`, selector 1, two zero fields, command
version 1, and no body. Its reply must be exactly 17 bytes (the 16-byte opaque
handle plus separate tracking metadata). The offline `ContextCreatePlan`
enforces SCRD-init → request → exact response length, never stores or returns
the opaque handle, and rejects repeats and out-of-order transitions.

`AppleKeyStore::verify_password`, in contrast, uses the service named
`aks-endpoint`, instantiated at fixed SEP endpoint `0x07`, with separate
`0x4000`-byte, page-aligned OOL buffers in each direction.
It calls `ipc_verify_secret_v1`, whose generated request is exactly `0x98`
bytes before pointer-to-blob serialization and is dispatched as operation
`0x21`. After the versioned IPC header, offset `0x50` is request variant `1`,
offset `0x58` is the keybag handle, offset `0x60` its 32-bit selector, offsets
`0x68`/`0x70` describe the password blob, offsets `0x78`/`0x80` describe the
ACM-context blob, offset `0x88` is the boolean option promoted to a qword, and
offset `0x90` is the 64-bit device state. For request variant 1 the codec
serializes the `0x90` state qword after the two blobs; it does not serialize
the in-memory option at `0x88`. The codec walks both blobs with explicit
lengths rather than transmitting kernel pointers. The caller
maps the secure-key-store result to an AKS result and updates device state only
after success. This explains how password verification authorizes the already
created ACM context without exposing password material to BiometricKit.

These offsets are structural evidence, not an invitation to capture secrets.
Any Linux implementation must accept the password through a locked,
short-lived buffer, apply the recovered AKS pointer-to-blob codec, scrub all
copies on every outcome, and keep the returned ACM handle in memory only for
the current SEP transport lifetime. No live AKS password request is enabled in
the prototype yet; header negotiation, exact endpoint OOL limits, reply
validation, and teardown must be recovered first.

Endpoint initialization first issues `ipc_get_capabilities` as AKS operation
`0x4d`. If that fails,
AppleKeyStore falls back to IPC header version 1. Otherwise it negotiates
`min(remote_version, 2)`. Only after fixing that global negotiated version does
it continue with environment and entropy initialization. A Linux client must
therefore not hard-code the richer version-2 header or send verify-secret as
its first AKS transaction. The offline transport model includes this exact
fallback/cap decision and names verify-secret operation `0x21`, but does not
encode either IPC payload.

The capabilities request's serialized size is exactly 100 bytes: the
`0x54`-byte IPC header, variant word, one qword, and an empty length-prefixed
blob. `AuthorizationPlan` now enforces correlated operation-`0x4d`
capabilities transport and successful version selection before it will even
plan an operation-`0x21` verify-secret envelope. It accepts only the password
length, not password bytes, and uses the bounded size calculation above. This
closes the ordering layer while deliberately leaving live process-identity
sourcing and secret-buffer serialization unwired.

The operation-`0x4d` body is now byte-exact as well. Both its empty-input
request and normal empty-blob reply are 100 bytes: a little-endian header
length of `0x50`, the 80-byte protected header, a signed 32-bit status, a
64-bit capability/header version, and a zero 32-bit blob length. The request
sets all three body values to zero. The offline decoder requires exact length,
header length, zero flags, a valid truncated-SHA-256 digest, and an empty blob
before exposing status or remote version. This gives a mechanical validator
for the first eventual AKS service response; it is not connected to device
I/O.

The IPC integrity primitive is now recovered exactly from AppleKeyStore's
`_payload_hash`. The external relocation at x86_64 call site `0x81cad`
resolves to `_ccsha256_di`: version 1 hashes header bytes `0x10..0x47`
followed by the payload, while version 2 extends the header range through byte
`0x4f`. Both store only the first 16 SHA-256 bytes at header offset zero. The
pure transport model implements generation and constant-time validation for
this digest and rejects every header version except 1 and 2. It intentionally
constructs the recovered layout only from explicit caller-supplied identity
data: version at `0x10`, `mach_continuous_time` converted to microseconds at
`0x14`, zero flags and reserved qword at `0x1c` and `0x20`, process unique ID
at `0x28`, the process credential's 32-bit field at `0x30`, and the 20-byte
code-directory hash at `0x34`. Version 2 adds calendar seconds at `0x48`.
`get_platform_cdhash` uses `cs_get_cdhash`; if that fails, Apple stores
SHA-1 of the process unique ID instead. The model deliberately has no Linux
identity defaults: these Apple kernel-process values must not be guessed for
a live SEP request.

AKS does not use the SBIO generic-transfer notification. Its Intel mailbox
envelope is exactly 12 bytes: endpoint `0x07`; a 7-bit selector in byte 1 with
bit 7 set only on replies; a wrapping correlation byte; zero at byte 3 and
bytes 4–5; the OOL payload length as a little-endian 16-bit value at bytes
6–7; and zero at bytes 8–11. Apple masks the request selector to seven bits,
copies the serialized request into the send OOL buffer, sends this envelope,
and correlates the response before consuming the receive OOL buffer.
`aks-transport.py` is a pure strict codec for that layer. It caps lengths at
`0x4000`, rejects reserved data and wrong endpoints, and requires the reply
bit, selector, and tag to match before exposing a response length. It has no
password input and no device-I/O path.

`credential-services-bootstrap.py` now composes the existing control-message
encoder and stop-before-free ownership model for both fixed services. It
creates distinct tagged opcode-2/opcode-3 registrations for two 16 KiB DMA
mappings, refuses any endpoint other than ACM `0x0a` or AKS `0x07`, and cannot
mark either service ready without an independently supplied, exactly matching
acknowledgement profile. A failed second acknowledgement commits neither
mapping. Successful mappings remain retained until transport stop, explicit
scrub, and release. This is still a pure plan: it allocates no memory and has
no route into the kernel probe.

The corresponding kernel capture path is now implemented but remains
default-off and unexecuted. It requires CPU start, both MSI vectors, a strictly
validated control NOP, endpoint exactly `7` or `10`, a credential-specific
64-bit confirmation value, and mutual exclusion from the older SBIO capture.
It allocates two zeroed 16 KiB coherent mappings under a 32-bit DMA mask,
captures only tagged OOL-registration acknowledgements, issues Apple's stop
before scrubbing/freeing either mapping, and never constructs an ACM or AKS
service envelope. The wrapper adds an independent cursor-bounded transcript
verifier and a separate human-readable confirmation. Privileged execution is
deferred until the user is present.

The same offline model computes the exact verify-secret serialized size
without accepting secret bytes: an `0x54`-byte serialized header, the variant
word, keybag qword, selector word, two 32-bit-length-prefixed blobs padded to
four-byte boundaries, and the final device-state qword. It requires the ACM
external form to be exactly 16 bytes and refuses any plan exceeding the
`0x4000` AKS OOL buffer.

Unit tests use a fragmented fake
socket to cover HELO, no-op, early EOF, malformed replies, and frame flooding.
Because `52032` is currently proven from Catalina 19H15 rather than this
machine's newer bridgeOS, the connection function is mechanically disabled in
source. A current macOS binary or successful-system trace must confirm that
the named BiometricKit service still owns that port before enabling it.
The old runner now also requires an exact `(52032, nonempty evidence note)`
source tuple, validates the peer's complete four-key HELO rather than accepting
arbitrary UTF-8, rejects traversal-capable interface names and nonfinite
timeouts, and proves all those gates run before sysfs or socket access.

The offline `discovered-bridge-plan.py` now joins the modern discovery and
BridgeXPC layers without weakening that gate. Its transcript entry point runs
the complete bounded RSD state machine, requires the named BiometricKit
service, and transfers the proven port directly into the plan. It combines
that port with the wire-observed link-local T2 address and a nonzero
interface index, then constructs only HELO, method 0 (`getBridgeVersion:`), and
method 1 (`getServiceOpened:`) frames. The module does not import or create
sockets. This prevents a caller-selected port from entering the modern
transcript-to-plan path.

The staged RSD runner retains that evidence boundary during capture. Its
fake-socket-tested core returns an immutable pair of the validated advertised
port and the exact, capped server transcript; the existing port-only function
is just a compatibility wrapper. A future supervised experiment can therefore
feed the captured transcript directly into the offline plan builder and prove
that the endpoint came from the peer's named-service directory.

The first supervised Linux attempt on 2026-08-28 did not reach RSD. A temporary
non-autoconnecting NetworkManager profile assigned the verified local address
`fe80::aede:48ff:fe00:1122/64`, and route selection chose the then-inferred
peer `fe80::aede:48ff:fe00:11dd`. That inference was later disproved by a wire
capture. The TCP connection timed out because
neighbor discovery never left the host: `ip -s link` showed zero transmitted
packets and increasing TX errors. Kernel history tied this to the immediately
preceding T2BCE preserved-state resume:

```text
t2bce_vhci: [01] pause timeout waiting for 1 outputs
cdc_ncm ... NETDEV WATCHDOG: transmit queue 0 timed out
```

Cycling only the NetworkManager connection did not recover the wedged USB
request. No RSD bytes, BridgeXPC frame, or biometric command reached the T2.
The narrow USB-interface unbind/rebind that followed recovered CDC-NCM TX and
captured the T2's unsolicited startup MLDv2 report. Its Ethernet source is
`ac:de:48:33:44:55` and IPv6 source is `fe80::aede:48ff:fe33:4455`. Neighbor
discovery and ICMPv6 echo then succeeded. Applying `remoted`'s peer transform
to that wire-observed T2 MAC gives the host address
`fe80::aede:48ff:fe33:44aa`; echo still succeeds with that host address.
Connections to candidate directory port `58783` and legacy BiometricKit port
`52032` were actively refused, and no `_remoted._tcp` mDNS answer appeared.
This proves the NCM transport and endpoint, while showing that neither
listener is active during this Linux boot. The next experiment must capture
macOS startup traffic to identify the activation sequence.

`tools/research/capture-live-macos-t2.sh` performs that experiment for a
bounded 60 seconds on macOS. It captures only interfaces whose current MAC is
in Apple's `ac:de:48` T2 range, plus `remoted`/`biometrickitd` unified logs and
listener snapshots; it does not modify enrollment. Its companion
`analyze-macos-t2-capture.py` is socket-free, caps every input and record
count, rejects symlinks and malformed pcaps, and reports wire addresses,
candidate-port flows, TCP resets, listener evidence, and activation log lines.
The collector fails before requesting packet capture when no T2-range
interface exists, and checks every `tcpdump` process before starting the
interaction window. Root-attributed `lsof` listener snapshots complement
`netstat`, so a missing or prematurely failed capture cannot be mistaken for
negative protocol evidence.

### Historical fixed-port candidate (superseded by the macOS boot capture)

The following section records how the earlier `58783` hypothesis was derived.
It is retained for provenance and for the other `remoted` role that owns that
literal; it is not a valid Linux directory endpoint.

There is now a second, explicitly candidate transport model for that next
capture. Two independent open implementations of Apple's modern Remote Service
Discovery protocol identify TCP port `58783`; pymobiledevice3 attributes it to
`-[RSDRemoteNCMDeviceDevice createPortListener]`, while go-ios implements the
same HTTP/2/RemoteXPC directory handshake. The inspected revisions were
pymobiledevice3 `a6bd794e0d8a` and go-ios `ced7e53d94a2`. Their shared wire
constants are:

```text
HTTP/2 connection preface: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
RemoteXPC wrapper magic:   0x29b00b92
XPC object magic/version:  0x42133742 / 5
root/reply streams:        1 / 3
candidate RSD port:        58783
```

`rsd-protocol.py` implements only this offline candidate handshake, a bounded
subset of the XPC object codec, strict HTTP/2 frame boundaries, and extraction
of one named service port from a decoded directory. Its encoder output was
checked byte-for-byte against pymobiledevice3 for the handshake and every
supported object type; the complete frame sequence was parsed independently
with `hyperframe`. The decoder caps wrapper bodies, strings, blobs, collection
sizes, and nesting; rejects duplicate keys, unknown types/flags, noncanonical
padding and booleans, surplus bytes, malformed ports, and unexpected directory
shapes.

The codec also has an incremental passive transcript validator. It accepts
arbitrarily fragmented caller-supplied bytes, but caps the total transcript,
frame count, frame payload, XPC body, ignored controls, strings, blobs,
collections, and nesting. It requires peer SETTINGS before DATA; permits only
the root/reply streams and the small SETTINGS/WINDOW_UPDATE/HEADERS/DATA subset;
reassembles XPC wrappers without mixing streams; and succeeds only when exactly
one complete handshake directory advertises the requested service. Partial
frames, early end-of-stream, duplicate or invalid settings, control floods,
unknown frames, interleaving, and all bytes after the directory fail closed.
A deterministic garbage corpus is also required to terminate only with a
protocol error, never an unexpected exception or false success. An additional
end-to-end check encoded a realistic directory with pymobiledevice3, framed it
with `hyperframe`, fragmented it independently, and recovered the expected port
through the local transcript validator.

The client-side fixture is now split at the real synchronization boundary:
transport preface/channel setup is sent first; a peer SETTINGS frame must be
received and validated; only then may the client SETTINGS ACK and RemoteXPC
device-handshake frame be emitted. `rsd-query.py` stages that exact exchange
against fragmented fake sockets. It sends no service-open request—successful
completion returns only the port named in the passive directory—and enforces a
five-second maximum timeout, 16-frame limit, 64 KiB frame/XPC caps, 256 KiB
transcript cap, exact internal USB/PCI ancestry, and a traversal-safe interface
name.

Normal `rsd-query.py` execution prints deterministic offline fixtures. Current
macOS `remoted` resolves one half of its former combined endpoint gate:
`RSDRemoteNCMDeviceDevice::createPortListener` at `0x10001628a` stores the
literal `0xe59f`, decimal `58783`, before creating the listener. The verified
x86_64 slice SHA-256 is
`88e78e65b77e3c2338ca95c9ab201bfa0be90ce81e58ece1c4d1ad11273f4056`.
`macos-rsd-port-evidence.py` independently requires the x86_64 Mach-O, class,
method, and unique exact `movw` port store.

The same binary's `RSDRemoteNCMDevice::local_address` and `remote_address`
methods call a shared six-byte-MAC helper with direction values 1 and 0. The
helper toggles MAC byte 0 with `0x02`, inserts `ff:fe`, and, for the remote
direction, XORs byte 5 with `0xff`, then prepends `fe80::/64`. Applied to the
T2's wire-observed NCM MAC `ac:de:48:33:44:55`, this yields:

```text
T2/local:  fe80::aede:48ff:fe33:4455
host/peer: fe80::aede:48ff:fe33:44aa
port:      58783
```

`rsd-protocol.py` implements this derivation with strict input checks, and the
runner records the address and port evidence independently. Live execution is
still mechanically impossible because the earlier missing-evidence gate has
been replaced by the explicit source kill switch
`LIVE_DIRECTORY_CAPTURE_ENABLED = False`. That switch is checked before sysfs
or socket work. Tests separately prove the kill switch, malformed evidence,
and invalid timeouts cannot construct a socket.

The address is wire-proven. The port remains a binary-derived candidate: its
listener was not active in the supervised Linux test. This does **not** establish that
the T2 directory currently advertises the host-requested
`com.apple.eos.BiometricKit` service. Neither the codec nor the disabled runner
has connected to it. The first future experiment remains a supervised,
bounded directory-only capture; it sends no service-open request.

Read-only extraction of the `iBridge1_1Customer.bundle` recovery OS included
with macOS 26.6.2 found the historical bridgeOS-side launch contract behind
that candidate. Its bridgeOS 3.0 (`14Y910`) launchd plist starts
`/usr/libexec/bkremoted` with an IPv4/IPv6 TCP socket on service `52032`, and
the daemon consumes `com.apple.bkremoted.socket`. This is strong provenance for
the legacy port, not current-port verification: the bundle is historical
recovery firmware, the current macOS trace used RSD and dynamic service ports,
and the live Linux transport received a TCP refusal on `52032`. Consequently
`CURRENT_PORT_VERIFICATION` remains unset and the legacy live query remains
mechanically disabled.

The current daemon also embeds code whose build paths identify it as
`bkremoted`. Its binary contains `BiometricKitBridgeConnection`,
`BiometricKitBridgeTransport`, and `BiometricKitBridgeServices`, along with
`sendMessage:`, `sendMessage:andWaitForReply:`, `handleEnvelope:`, and
`handleEventWithMessage:error:`. The installed-binary evidence checker now
requires this coupled set. It locates the next reverse-engineering boundary—the
biometric envelope above BridgeXPC—but does not yet prove the envelope's bytes,
message numbers, or whether any operation is safe to transmit.

## SBIO and the Intel xART split

Static analysis of `AppleMesaSEPDriver` and `AppleSEPGenericTransfer` confirms
that built-in Touch ID is SEP endpoint `sbio` (`0x08`). The Apple driver asks
for a 16 KiB host-to-SEP buffer and a `0x4b000`-byte SEP-to-host buffer. It
registers their DMA page-frame addresses through control opcodes `2` and `3`,
then uses generic-transfer message type `0xfc` for transactions. The first
packet has a 28-byte header followed by request data. These details are now
recovered well enough to implement the transport without guessing.

The Intel x86_64 `AppleSEPEndpoint` implementation removes another ambiguity.
`setSendOOLBuffer()` calls control opcode `2` (`SET_REMOTE_DMA_IN`), while
`setReceiveOOLBuffer()` calls opcode `3` (`SET_REMOTE_DMA_OUT`). Their exact
four-word request is:

```text
word 0: control endpoint 0x00 | opcode << 16 | target endpoint << 24
word 1: 32-bit DMA page-frame number (address >> 12)
word 2: buffer size in bytes
word 3: zero
```

Registration succeeds before Apple retains the memory object. The offline
encoder rejects reserved endpoint IDs, unaligned addresses/sizes, zero sizes,
page-frame overflow, and a multi-page range that would wrap beyond the final
32-bit page-frame number. A separate gate validates the exact four-byte limit
tuple and checks both sizes against the passively advertised ranges for that
endpoint. It performs no allocation, mapping, registration, or device access.

Control acknowledgement is tag-correlated, not merely “the next endpoint-zero
record.” `_cmsgSend` allocates a nonzero byte tag, inserts it in word 0, and
keeps the command active until `_cmsgAction` receives that tag. The reply's
word 1 is the remote result; nonzero values are errors. The observed NOP proves
reply opcode `1` and target `0` for that one command, but neither Apple’s
callback nor the current evidence proves the opcode/target returned for OOL
commands `2` and `3`. `tag_control_request()` and
`validate_control_reply()` now model the correlation and status rules, while
requiring the caller to supply independently verified reply opcode and target.
Consequently an OOL registration cannot yet be marked committed from a guessed
ack shape. The kernel prototype now has a default-off bounded capture path for
establishing those two fields. It requires successful passive `sbio` discovery
and a separate confirmation value, caps each response wait at five seconds,
and logs opcode/target without treating guessed values as success criteria.
The coherent mappings remain pinned across every outcome until CPU stop, after
which they are scrubbed and freed. This path is compile-tested only; it has not
yet been executed against the T2.

The offline `sbio-bootstrap.py` composition makes that evidence dependency
mechanical. Its caller must complete strict discovery, prepare both tagged OOL
requests, and supply independently observed reply opcode/target fields. Both
replies validate before either ownership transition is committed. Only then
does it expose the already-fixtured command `0x73`, value `3`, empty-response
generic-transfer initialization session. Skipping or repeating a phase fails.

The future capture is also checked independently by `verify-ool-log.py`. It
rejects mixed, incomplete, reordered, raw/decoded-inconsistent, nonzero-status,
transport-error, or pre-stop-cleanup transcripts. Its only output is the two
observed opcode/target pairs needed to instantiate the bootstrap reply profile.

Linux currently reports both `dma_mask_bits` and `consistent_dma_mask_bits`
as 32 for `0000:04:00.2`, consistent with this T2 wire format. A future live
implementation must explicitly establish a 32-bit coherent DMA mask, use the
DMA address returned by the kernel rather than a CPU physical address, reject
any address whose page-frame number exceeds the 32-bit field, and never assume
that membership in IOMMU group 10 makes sibling-device mappings interchangeable.

There is no corresponding control “unregister” in the Intel endpoint methods.
`clearSendOOL()` and `clearReceiveOOL()` zero the already-visible memory but do
not revoke the address from SEP; object destruction releases the host object
later. A Linux implementation must therefore keep every successfully
registered DMA mapping allocated, mapped, and non-reusable for the full SEP
transport lifetime, scrub it before teardown, and stop/reset the transport
before freeing it. Treating module unload as implicit OOL revocation would
create a use-after-free DMA hazard.

Replacement needs the same caution. `setSendOOLBuffer` and
`setReceiveOOLBuffer` first wait for a successful control registration, then
retain the new memory object and release the old host reference. That proves
the new address has replaced the endpoint's current address, but it does not
provide Linux with a wire-level revocation acknowledgement for the old one.
`endpoint-lifecycle.py` therefore retains every successful historical mapping
in its offline ownership model. Failed control registration changes nothing;
an endpoint becomes transaction-ready only after both directions succeed;
operations are balanced and must drain before sleep/stop; and no current or
retired mapping can be released until the entire SEP transport is stopped and
that mapping is scrubbed. This last stop-before-free rule is an explicit Linux
safety invariant built on the recovered absence of unregister, not a claim
that Apple's object-release alone performs a wire command.

Disassembly of `_gt_write_next_packet` gives the exact seven-word,
little-endian header: protocol version (`1`), total transaction length, byte
offset, flags, reserved zero, 32-bit command, and this packet's payload
length. `_gt_send_transact_message` constructs the mailbox notification with
a 16-bit sequence in bits 63–48, the same command in bits 47–16, the
message type in bits 15–8, and zero in bits 7–0. The strict offline
`generic-transfer.py` codec and tests capture these invariants and perform no
device I/O.

The notification state machine uses all four adjacent message types. The
handler dispatches `0xfc` to first-packet parsing, `0xfd` to continuation
parsing, `0xfe` to producing the next outbound packet, and `0xff` to error
parsing. A transfer is complete only when the accumulated byte count equals
the header's total length. The offline codec now includes a bounded reassembler
that rejects a nonzero first offset, changed metadata, gaps, overlap, duplicate
chunks, zero-progress continuations, and totals above its caller-supplied cap.
The strict notification decoder additionally requires a zero low byte and one
of the four recovered generic-transfer types. A separate sequence tracker can
reject skipped, repeated, or backward 16-bit sequence values while permitting
the defined wrap from `0xffff` to zero.

The Intel endpoint envelope is now separated from that architecture-neutral
notification. In the macOS 14.5 KDK x86_64 `AppleSEPManager`,
`AppleSEPEndpoint::sendMessage` at `0x6204` forwards the endpoint index and
record pointer to `AppleSEPManager::sendMessage` at `0x33fe`.
`_sendMessageGated` at `0x3458` copies a qword plus the following dword, clears
the qword's low byte, inserts the endpoint ID there, and passes the resulting
12-byte record to `AppleSEPIntelIOP::postMailbox`. Separately, arm64e
`AppleSEPGenericTransfer::_gt_send_transact_message` at `0x4090` proves the
64-bit sequence/command/type value, and `sendRawMessage` at `0x68bc` supplies
that value through the endpoint API. The Intel GenericTransfer provenance of
the following dword is not independently established by the available slice.

The two-pointer ABI is now pinned more precisely. On x86_64,
`AppleSEPEndpoint::sendMessage(void *, void *, bool)` forwards both pointers,
but `AppleSEPManager::_sendMessageGated` never reads the second pointer. It
loads the qword and following dword from the first pointer, inserts the endpoint
byte, constructs a separate zero fourth word on its own stack, and posts the
12-byte record. By contrast, the available arm64e
`AppleSEPGenericTransfer::sendRawMessage` stores only its qword argument and
calls its endpoint with `(&qword, nullptr, true)`. That architecture's endpoint
cannot establish what an Intel GenericTransfer caller placed after its qword.
`sep-endpoint-abi-evidence.py` pins both sides against x86_64 manager SHA-256
`6739c1e61ebba15534c4492c3ac4e11cd5d899588bb19a257d49c684f82037fa`
and arm64e GenericTransfer SHA-256
`174c5a98b49371976dc285d8ac522a2d075c748b04e94dfec14c45920139a0b9`.

`envelope_endpoint_notification()` therefore models the proven endpoint-byte
insertion but requires its third word as an explicit argument with no default.
It validates the normal routed endpoint range and refuses a notification whose
low byte is already occupied. This deliberately prevents the kernel prototype
from assuming that FIFO word two is zero merely because the recovered 64-bit
notification has no field for it.

The locally extracted Catalina `InstallESD` root and the Sonoma boot kernel
collection contain no separate x86_64 `AppleSEPGenericTransfer` fileset entry
from which to recover that third word. The Sonoma boot collection contains
`AppleSEPManager` but not `AppleMesaSEPDriver`; the latter appears only as a
string/personality reference there. The available KDK GenericTransfer slice is
arm64e. Thus zero remains plausible but unproved, and kernel SBIO initialization
stays intentionally unwired pending either an Intel binary or a bounded trace.

The full Catalina Core package has now been checked as well. Its 7.5 GiB PBZX
payload was streamed under a 1 GiB memory scope; only AppleSEPManager and the
`complzvn` prelinked kernel were extracted. A bounded decoder validated the
wrapper's 26,325,018-byte compressed and 72,273,920-byte expanded sizes and a
native x86_64 Mach-O result. Neither the prelink manifest nor its symbols and
strings contain AppleSEPGenericTransfer; AppleMesaSEPDriver appears only as a
personality/name reference. This closes the remaining obvious Catalina
installer location without changing the third-word conclusion above.

The matching Catalina 10.15.7 build 19H15 Kernel Debug Kit has now also been
checked. Its 94,351,258-byte DMG matches published SHA-1
`bec679d8e3eea7af93c7a3b770bce1b0e04b9627`; the bounded PBZX decoder expanded
the main KDK payload to 357,202,944 bytes. It contains public/debug kernel and
selected I/O-family kext artifacts, but no AppleSEPManager,
AppleSEPGenericTransfer, or AppleMesaSEPDriver binary or dSYM. This closes the
matching historical KDK as another possible Intel GenericTransfer source. The
third word remains deliberately caller-supplied and kernel SBIO transmission
remains unwired.

For inbound data, the mailbox command must also equal the command in the DMA
packet header. Error notification `0xff` uses word four (byte offset 16) of a
buffer larger than the common header as its 32-bit status. Both rules are now
represented by offline validators. `InboundTransaction` couples sequence,
notification type, mailbox command, packet header, bounded reassembly, and
remote-error parsing so callers cannot accidentally validate those layers in
isolation. Once complete it rejects every additional record, including an
empty duplicate continuation.

The outbound half is also recovered rather than inferred. Apple's
`transact()` calls `_gt_write_first_packet` and announces that packet with
`0xfc`. For a transaction larger than one OOL-buffer payload, SEP sends a
`0xfe` request; the handler writes the next packet and announces it with
`0xfd`. It sends no continuation notification after the byte offset reaches
the declared total. `OutboundTransaction` models precisely this pull-based
exchange offline: each chunk is at most `OOL capacity - 28`, the first offset
is zero, later offsets are contiguous, outgoing 16-bit sequence values wrap,
and peer requests have their own ordered sequence stream. It rejects a request
before the first packet, any type other than `0xfe`, a changed mailbox command,
a skipped/repeated peer sequence, and every request after completion. The
planner returns immutable packet and notification bytes and has no hardware
I/O path.

Apple does not signal `transact()` when request writing finishes:
`_gt_transfer_writing_complete` is a no-op. The waiter is signaled only after
the response reassembler reaches its declared total (or the error callback
stores a status). This means a Linux caller must treat upload completion and
transaction completion as different states. `TransactionSession` now couples
those states and uses one peer sequence tracker across `0xfe` upload pulls,
`0xfc`/`0xfd` response packets, and `0xff` errors. For every incomplete
response packet it emits a packetless `0xfe` pull from the same host sequence
stream used by request packets. It rejects a response before request upload is
complete, a response command different from the request, missing or unexpected
DMA bytes, cross-type sequence gaps, continuation after either half completes,
and malformed records before they can mutate reassembly state. This remains a
pure codec/state model, not an executable transport.

The passive discovery model and the not-yet-run kernel collector now enforce
the same stricter table grammar: exactly four 32-bit words; discovery endpoint
`0xfd`; zero tag/reserved fields; no transport error/fatal flags; service IDs
`1..0xfc`; printable unique fourcc names; and an identity immediately followed
by that endpoint's non-inverted OOL limits. Completion is success only if
`sbio` is exactly endpoint `0x08` and its limits cover Apple's recovered
4-page send and 75-page receive buffers. The privileged wrapper now requires
the final log to say `sbio=yes limits=yes result=0`; a merely clean timeout or
some unrelated endpoint table is no longer accepted.

That future result is now checked twice rather than trusted through grep. The
kernel validates while consuming the FIFO; afterward
`verify-discovery-log.py` consumes only the journal range captured after the
runner's cursor and independently replays every four-word candidate through
the offline `DiscoveryTable`. It requires one validated NOP before discovery,
zero-based contiguous record indices, an exact identity-or-limits detail for
every candidate, matching record/identity totals, usable `sbio`, a single
successful summary, and the CPU-stop record afterward. Missing, duplicated,
stale, reordered, truncated, internally inconsistent, or error-bearing logs
all fail before the wrapper reports success.

`AppleMesaSEPDriver::initSbioCommunication()` also establishes the first SBIO
transaction in Apple's ordering: after generic-transfer setup, it sends
command `0x73` with one little-endian 32-bit input value, `3`, and requests no
reply payload. This resembles protocol-version initialization, but that
meaning is not yet proven. It must not be sent live until passive `sbio`
discovery, OOL limits, DMA registration lifetime, and completion semantics
have all been validated.

The exact transaction is now represented by
`sbio_initialization_session()` in the offline generic-transfer model. Its
first packet is fixed byte-for-byte to command `0x73`, total length four,
flags zero, and payload `03 00 00 00`; the reply transaction must declare a
zero total and contain no payload. A nonempty reply, changed command, malformed
notification, or continuation after completion fails. This helper deliberately
does not expose any encoder for the state-mutating commands below and is not
called by the kernel module.

The early command sequence can now be separated by risk instead of treating
every small request as a harmless query:

| Command | Recovered use | Shape | Live-test classification |
| --- | --- | --- | --- |
| `0x73` | `initSbioCommunication()` | 4-byte value `3`, no output, flags `0` | required initialization; meaning still inferred |
| `0x17` | `prepareSession()` | 16-byte sensor-derived input, no output, flags `1` | session mutation; do not probe |
| `0x15` / `0x16` | `performKeyExchange()` | 4-byte input to 40-byte output, then 40-byte input | cryptographic session mutation; do not probe |
| `0x1b` | `prepareNotPairedSession()` | 4-byte state input, variable output, flags `1` | pairing/session state; do not probe |
| `0x42` | `initializeSequenceCounter()` | no input, 12- or 64-byte output, flags `1` | likely nonce/counter material; not safely repeatable |
| `0x18` | `initializeSequenceCounter()` | 64-byte sensor-processed input, no output, flags `1` | sequence-state mutation; do not probe |
| `0x48` | `sendDeviceSerialNumberToSbio()` | 12-byte input, flags `1` | identity/session mutation; do not probe |

Thus `0x42` is not an acceptable first “read-only” experiment merely because
it has no input: its output is immediately transformed by the sensor and fed
back through `0x18` as sequence state. No SBIO application command beyond the
required `0x73` initialization is currently classified safe for live use.

The generic-transfer endpoint setup is likewise ordered and stateful.
`enableEndpoint()` obtains the named service through `AppleSEPDeviceService`,
allocates two page-aligned shared-memory objects through `IOSlaveProcessor`,
and passes the outbound and inbound objects to two different
`AppleSEPEndpoint` registration methods. Only after both registrations succeed
does `getEndpoint()` consider the channel usable; it waits for the endpoint's
enabled state before returning it to `transact()`. Linux must reproduce that
ownership and teardown contract rather than merely DMA-map two allocations and
send their addresses. The current prototype has only the separately confirmed,
default-off, bounded OOL-acknowledgement capture path; it still has no generic
transfer or SBIO application-command DMA path.

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
5. Capture and compare genuine macOS boot, enrollment, and match exchanges on
   a disposable or fully backed-up test installation. Recover enrollment as
   well as matching because the deliverable cannot require macOS-created
   templates. Filter for SBIO rather than tracing all SEP traffic.
6. Implement the transport and a single non-mutating query before enrollment.
   Only after the response format is verified should sensor capture, match,
   enrollment, and cancellation be attempted.
7. Implement Linux-native enrollment and template enumeration/deletion through
   a narrow userspace daemon/libfprint backend, then expose matching. Add PAM
   last, with fingerprint marked `sufficient` and ordinary password
   authentication retained as an immediate fallback.

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

The bounded discovery collector was then run after a verified full cold boot
on 2026-08-28. It established the direct transport again: CPU start completed,
MSI inbox and outbox vectors each fired once, and the control NOP produced the
strictly validated response in 10 ms. No `0xfd` advertisement arrived during
the one-second passive collection window:

```text
bounded discovery complete: records=0 identities=0 sbio=no limits=no result=-11
MSI observations: vector0=1 vector1=1
```

Cleanup completed: the Apple CPU-stop value was issued, PCI command state was
restored, both MSI vectors were freed, and no driver remained bound. Therefore
the separately gated OOL-registration experiment was not entered. This rules
out the simple model that CPU start plus a control NOP causes T2 to replay its
dynamic service table. It does not prove that endpoint `0xfd` can never emit;
the driver may need to be present during an earlier SEP lifecycle transition,
or the Intel/T2 biometric path may not use this dynamic generic-transfer route
at all. The latter is consistent with the absence of an x86_64
`AppleSEPGenericTransfer` in the inspected Catalina and Sonoma artifacts and
with the independently recovered network BridgeXPC biometric path. Future
direct-SEP work must recover a demonstrated lifecycle trigger before another
write; it must not guess a discovery command or bypass the successful-
discovery gate on OOL DMA registration.

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
