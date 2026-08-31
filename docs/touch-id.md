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

Those ABI and live-decision prerequisites are now proven, so the local Linux
authorization boundary has been specified offline. This installation currently
has PAM 1.7.2 and Polkit 127 but neither `libfprint` nor `fprintd`; no package or
authentication configuration was changed. The least-privileged practical
shape is a long-lived root daemon that alone owns the SEP/BridgeXPC transports,
plus a tiny PAM client that never touches hardware. The client resolves
`PAM_USER` through the local account database, generates a nonzero random
request ID, and sends one bounded request over a root-owned Unix
`SOCK_SEQPACKET` socket. The daemon must derive the client's PID/UID/GID only
from `SO_PEERCRED`, accept a root peer, freshly enumerate the target UID's
sensor identities, run one ordinary match, cancel it on every exit, and return
only a correlated Boolean-class result. A wire-supplied peer identity, ambient
daemon UID, cached match, UUID, or raw biometric event must never authorize.

`linux-auth-broker.py` makes the non-I/O portion mechanical. Its request and
response are each fixed at 24 bytes with magic/version/opcode, zero reserved
fields, one 64-bit correlation ID, a target UID below `UINT32_MAX`, and a
timeout bounded to 60 seconds. The server state accepts one kernel-authenticated
root peer and one monotonic deadline. It emits match only for the existing
trusted `AuthenticationDecision` whose identity UID equals the request; exact
no-match is non-authenticating, while wrong UID, wrong request ID, malformed
decision type, timeout, abort, reuse, or unknown status fails permanently.
The PAM client-side decoder authenticates only correlated status zero. This
module deliberately creates no socket and changes no PAM files.

Once the hardware transport is production-stable, a small native daemon can
implement this boundary first. PAM should be enabled only after direct password
fallback and recovery are tested, using fingerprint as `sufficient` rather than
removing the password path. A later fprintd/libfprint-facing layer can expose
Linux-native enrollment and management without making the security-sensitive
PAM client depend on the much larger hardware protocol implementation.

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

That final handoff is now encoded offline rather than left as a prose-only
boundary. `consume_builtin_enrollment_credential` accepts only a mutable,
exactly 16-byte ACM external form and consumes it into the current 68-byte
command-3/version-2 layout: zero flags, requested UID, `usingAuthToken=0`,
length 16, the context, 16 zero padding bytes, built-in group type 1, and a
zero group UUID. The input is wiped on every outcome. The returned request is
mutable, hides its contents in representations, and wipes all 68 bytes on
explicit close, context-manager exit, or best-effort destruction. No caller
can select another group, token mode, padding, or flag through this API.

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
receive OOL buffers. `LibCall_ACMContextCreate` submits command `0x24` in
current mode and expects an exact 21-byte response. Only an immediate `-3`
selects Apple's legacy command-1 fallback with its exact 17-byte response.
Both forms copy their first 16 bytes into the opaque context handle; the
remaining bytes are tracking metadata. Creating a context therefore does not
require inventing or persisting a token.

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
00`, using endpoint message type 1, value 0. In the matching macOS 14.5 KDK,
`AppleCredentialManager::initImpl` initializes `VV` to the fixed byte `0x28`;
`performSCRDInitialization` copies that field into payload offset 5. The
offline codec therefore emits `44 52 43 53 0a 28 00 00` directly and exposes
no caller-selected version. The verified token-free legacy context-create
command is `44 52 43 53 01 00 04 01 00 00 00 00`: `DRCS`, selector 1, zero
flags, a four-byte body, command version 1, and domain zero. Its reply must be
exactly 17 bytes (the 16-byte opaque
handle plus separate tracking metadata). The offline `ContextCreatePlan`
enforces SCRD-init request → correlated zero-status empty reply → context-create
request → correlated zero-status exact 17-byte reply. It never stores or
returns the opaque handle, and rejects failed, repeated, short, oversized, or
out-of-order transitions. This distinction matters because the Intel receive
callback places the reply's upper 32-bit mailbox value into the waiting
request's status field; Apple's caller marks SCRD initialized only after the
synchronous command returns success, not merely after sending it.

The matching context teardown is now recovered from
`LibCall_ACMContextDelete`. When remote deletion is requested it invokes the
same transport callback with selector `2`, exactly the first 16 bytes of the
context as input, and no output buffer. `LibCall_BuildCommand` makes the
resulting 24-byte request `DRCS 02 00 10 01 || context[0:16]`. Irrespective of
the callback's result, Apple's caller then frees its 20-byte host context; the
17th create-response byte is tracking metadata and is not sent to SEP for
deletion. The offline plan now requires a successful create before it can
build this command, requires caller-owned exact-size `bytearray` buffers so no
immutable secret copy is returned, correlates an exact zero-status empty
delete response, and provides an exact-size scrub operation for both buffers.
A live implementation must attempt delete, stop the SEP transport even if
delete fails, and scrub the create response and delete command on every exit.

`AppleKeyStore::verify_password`, in contrast, uses the service named
`aks-endpoint`, instantiated at fixed SEP endpoint `0x07`, with separate
`0x4000`-byte, page-aligned OOL buffers in each direction.
It calls `ipc_verify_secret_v1`, whose generated request is exactly `0x98`
bytes before pointer-to-blob serialization and is dispatched as operation
`0x21`. After the versioned IPC header, offset `0x50` is request variant `1`,
offset `0x58` is the keybag handle, offset `0x60` its 32-bit selector, offsets
`0x68`/`0x70` describe the password blob, offsets `0x78`/`0x80` describe the
ACM-context blob, offset `0x88` is the input device-options qword, and offset
`0x90` is the returned device state. For request variant 1 the codec serializes
the `0x88` options qword after the two blobs; the reply uses `0x90`. The codec
walks both blobs with explicit
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
it call `set_env(false)`, then derive class-F public-key material through AKS
and mix the returned public bytes into the host kernel PRNG. The latter is not
an entropy upload to SEP. A Linux client must
therefore not hard-code the richer version-2 header or send verify-secret as
its first AKS transaction. The offline transport model includes this exact
fallback/cap decision, the intervening environment operation, and
verify-secret operation `0x21`.

The capabilities request's serialized size is exactly 100 bytes: the
`0x54`-byte IPC header, variant word, one qword, and an empty length-prefixed
blob. `AuthorizationPlan` enforces correlated operation-`0x4d` capabilities
transport and successful version selection before permitting environment
setup, and requires successful environment setup before it will even plan an
operation-`0x21` verify-secret envelope. It accepts only the password length,
not password bytes, and uses the bounded size calculation above. This closes
the ordering layer while deliberately leaving live process-identity sourcing
and secret-buffer serialization unwired.

The operation-`0x4d` body is now byte-exact as well. Both its empty-input
request and normal empty-blob reply are 100 bytes: a little-endian header
length of `0x50`, the 80-byte protected header, a signed 32-bit status, a
64-bit capability/header version, and a zero 32-bit blob length. The request
sets status and blob length to zero and sends local supported version `1` in
the qword; the response returns the remote version there. The offline decoder requires exact length,
header length, zero flags, a valid truncated-SHA-256 digest, and an empty blob
before exposing status or remote version. This gives a mechanical validator
for the first eventual AKS service response; it is not connected to device
I/O.

The mandatory normal-boot environment transaction is now byte-exact from the
pinned macOS 14.5 AppleKeyStore binary. It is AKS operation `0x2a`: a
`0x470`-byte request and an `0x58`-byte response. After the protected header,
the request contains a zero variant word, qword `1`, blob length `0x40c`, and
the environment blob. That blob begins with u32 values `1`, the explicit
`IODeviceTree:/defaults` property `no-effaceable-storage` (zero if absent),
and normal-mode value `4`, followed by a zero qword and `0x3f8` zero bytes.
The response contains only the protected header and a zero signed status. The
offline codec range-checks the device-tree property, constructs every reserved
byte as zero, validates the negotiated header version and digest, and rejects
nonzero status, extra bytes, and reordered replies. It is not yet connected to
device I/O.

A second, separately confirmed kernel path implements this
two-transaction startup prefix. It first performs the existing strictly
validated operation-`0x4d` exchange and caps the returned version at 2, exactly
as Apple does. If negotiation is unavailable, it follows Apple's explicit
fallback to version 1. Only then does it construct operation `0x2a` with a fresh
suspend-inclusive boot timestamp, a calendar timestamp for version 2, the
kernproc identity candidate, the missing-property default
`no-effaceable-storage=0`, normal mode 4, and zero reserved storage. It sends
selector `0x2a` at tag 2 and accepts only the correlated selector-`0xaa`, tag-2,
length-`0x58` response with the negotiated version, valid digest, zero flags,
and zero status. The path never sends password bytes, an ACM context, or a
reference-key request. The wrapper requires the exact confirmation phrase
`I_UNDERSTAND_NONSECRET_AKS_STARTUP_ENVIRONMENT_PROBE`; an independent
transcript verifier checks the OOL registration profile, both AKS exchanges,
version negotiation, CPU stop, DMA scrub/release, PCI restoration, unload, and
unbind.

The bounded live run on 2026-08-29 established two additional constraints.
Using Apple's actual first and second per-service correlation tags (`1` for
capabilities and `2` for environment), operation `0x4d` still produced no
mailbox reply. The prototype then applied Apple's version-1 fallback and sent
operation `0x2a`; that request also produced no mailbox reply. Both attempts
cleanly stopped the CPU, scrubbed and freed DMA, restored PCI state, and
unloaded. This rules out the previously incorrect correlation tags and the
missing capabilities fallback as the cause. Because two different protected
AKS operations are silently rejected while ACM exchanges succeed over the
same transport, the remaining mismatch is in the common protected AKS header
or its host identity, not either operation's body.

The following class-F PRNG contribution is best-effort rather than an
authorization gate. `init_sep_endpoint` calls both `set_env(false)` and
`add_class_f_entropy_to_kernel_prng()` as void functions and does not inspect
either result. The latter builds an AKS parameter dictionary with numeric key
`9` set to `0x80`, invokes `_aks_ref_key_create(-1, 13, 7, ...)`, obtains the
new reference key's public key, and passes only those returned public bytes to
the host `add_entropy_to_kernel_prng`. Every setup, create, and public-key
failure is logged and cleaned up before returning. Consequently this path
neither supplies host randomness to SEP nor carries a login secret, and it
must not be confused with the required transaction ordering enforced by the
authorization model. Reproducing it is not a prerequisite for the first
bounded capabilities or environment probes.

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
at `0x28`, the process credential's 32-bit audit-session ID at `0x30`, and the 20-byte
code-directory hash at `0x34`. Version 2 adds calendar seconds at `0x48`.
`get_platform_cdhash` uses `cs_get_cdhash`. More precisely, a null cdhash with
a valid `proc_self` is explicitly zero-filled and still returns success; the
SHA-1 fallback is reached only if acquiring the process itself fails. XNU
initializes `kernproc->p_uniqueid` to zero and defines the default audit
session ID as zero. Combined with the KDK load sequence through
`proc_self`/`kauth_cred_proc_ref` and the direct `ai_asid` load, this yields a
source-grounded candidate kernproc identity of unique ID 0, audit session 0,
and a zero 20-byte cdhash. It remains an inference that AppleKeyStore endpoint
startup executes in kernproc context, so the live path is separately gated.
Primary source anchors are XNU's
[`bsd_init.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/bsd_init.c)
and [`audit.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/bsm/audit.h).

The Catalina 10.15.7 build-19H15 AppleKeyStore image has now also been
recovered directly from its prelinked kernel and checked independently. Its
version-1 header layout, 100-byte capabilities request, operation `0x4d`,
version-1 fallback, endpoint-7 envelope, and protected hash input match the
Sonoma-derived model. Catalina additionally supports a later negotiated IPC
encryption session: only after a nonzero global session ID exists does header
flag bit zero become set and the session ID occupy offset `0x20`. That global
is initially zero and is not a prerequisite for capabilities negotiation.
This cross-version comparison rules out an omitted initial encryption session
as the reason Linux's first two protected requests receive no reply.

AKS does not use the SBIO generic-transfer notification. Its Intel mailbox
envelope is exactly 12 bytes: endpoint `0x07`; a 7-bit selector in byte 1 with
bit 7 set only on replies; a wrapping correlation byte; zero at byte 3 and
bytes 4–5; the OOL payload length as a little-endian 16-bit value at bytes
6–7; and zero at bytes 8–11. Apple masks the request selector to seven bits,
copies the serialized request into the send OOL buffer, sends this envelope,
and correlates the response before consuming the receive OOL buffer.
The correlation byte is independent of the control-plane OOL-registration
tags: Apple zero-initializes its per-service counter and pre-increments it, so
the first capabilities transaction uses correlation tag `1`.
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

The dual-service form closes the offline composition boundary between those
individually observed profiles. It reserves four globally distinct nonzero
control tags (default `2` through `5`) and four distinct, non-overlapping 16
KiB DMA ranges. All four replies are validated before ownership is committed
to either endpoint, and readiness requires both ACM and AKS. Teardown first
preflights both endpoints as idle, stops both, and only then scrubs and releases
any mapping; an active operation on either endpoint leaves both running and all
four mappings retained. This does not establish a live combined registration
sequence: the corresponding dual-endpoint kernel probe has not been executed.

A separately gated dual-endpoint probe is now prepared but remains
unexecuted. It is the minimal empirical test of that exact assumption: after
the already validated control NOP it allocates four zeroed 16 KiB coherent
mappings, registers AKS send/receive with global tags 2/3, then ACM
send/receive with tags 4/5, and sends no ACM or AKS service envelope. CPU stop
precedes scrubbing and freeing every mapping even on partial failure. The
wrapper requires the exact confirmation
`I_UNDERSTAND_NONSECRET_DUAL_CREDENTIAL_OOL_CAPTURE`, a fresh journal cursor,
the supported PCI identity with no bound driver, and post-run unload/unbind.
Its independent verifier binds all four request words to four distinct,
non-overlapping logged DMA ranges, requires the previously observed exact ACK
profiles and ordering, nonzero counts on both MSI vectors, stop-before-free,
PCI restoration/release, and probe removal. Passing would prove simultaneous
registration only—not AKS startup, ACM context creation, password verification,
or enrollment—and it will not be executed while the user is unavailable.

The exact next supervised invocation, after rebuilding as the ordinary user,
is:

```bash
cd ~/t2-mbp16-audio-recovery/prototypes/t2sep-probe
make
pkexec ./run-dual-credential-ool-capture.sh \
  I_UNDERSTAND_NONSECRET_DUAL_CREDENTIAL_OOL_CAPTURE
```

Success is only the verifier's final simultaneous profile
`((7, 1, 7), (7, 1, 7), (10, 1, 10), (10, 1, 10))` plus clean unload and
unbind. Any other result stops this branch; it must not be followed
automatically by a service request.

The supervised run on 2026-08-29 at 06:47 EDT passed exactly that gate. Four
distinct contiguous 16 KiB mappings were registered in the planned order;
AKS tags 2/3 returned `(opcode 1, target 7)` and ACM tags 4/5 returned
`(opcode 1, target 10)`, all with zero status/reserved words. Both MSI vectors
were observed five times. CPU stop preceded scrubbing and freeing all four
mappings, PCI command state was restored and released, the module unloaded,
and the independent cursor-bounded verifier emitted the exact simultaneous
profile above. No ACM or AKS service envelope, password, context, fingerprint
command, or biometric data was sent. Simultaneous endpoint registration is
therefore proven on this T2 rather than merely modeled offline.

The corresponding kernel capture path is default-off and was executed once
under direct user supervision on this MacBookPro16,1 at 2026-08-28 22:55 EDT.
It requires CPU start, both MSI vectors, a strictly
validated control NOP, endpoint exactly `7` or `10`, a credential-specific
64-bit confirmation value, and mutual exclusion from the older SBIO capture.
It allocates two zeroed 16 KiB coherent mappings under a 32-bit DMA mask,
captures only tagged OOL-registration acknowledgements, issues Apple's stop
before scrubbing/freeing either mapping, and never constructs an ACM or AKS
service envelope. The wrapper adds an independent cursor-bounded transcript
verifier and a separate human-readable confirmation.

That verifier now rejects a missing journal cursor instead of falling back to
recent kernel lines. It binds opcode-2/tag-2 and opcode-3/tag-3 requests to the
exact distinct, page-aligned 16 KiB DMA addresses logged for the same capture;
requires zero acknowledgement status and reserved word; and requires nonzero
counts on both MSI vectors, CPU stop before scrub/free, PCI-command restoration
and release, and final probe removal in order. The kernel path independently
rejects a nonzero acknowledgement reserved word. The complete historical
endpoint-7 transcript still passes these stronger rules. A separate
cursor-bounded endpoint-10 transcript also passes them; no profile is inferred
across endpoints.

That bounded endpoint-7 run passed the control NOP, received both registrations,
stopped the T2, scrubbed and released both buffers, observed three interrupts
on each MSI vector, restored the original PCI command word, and left neither a
driver binding nor loaded module. Both opcode-2/tag-2 send registration and
opcode-3/tag-3 receive registration returned acknowledgement opcode `1`, target
`7`, their original tag, and zero status. The independent verifier reproduces
the resulting fixed AKS profile `(send=1/7, receive=1/7)`, now named
`AKS_REPLY_PROFILE` in the offline bootstrap. Its first pass exposed a verifier
bug: the normal unsigned out-of-tree-module warning contains `verification
failed:`. The verifier now ignores loader-wide messages and admits evidence
only from the PCI-qualified `t2sep_probe 0000:04:00.2:` state machine; a
regression test preserves that boundary. No AKS service request was sent.

A separately supervised endpoint-10 run at 2026-08-28 23:36 EDT passed the
same bounded lifecycle. Both ACM registrations returned acknowledgement opcode
`1`, target `10`, their original tags, and zero status/reserved words. Three
interrupts arrived on each MSI vector; the probe then stopped the T2, scrubbed
and released both mappings, restored PCI state, and unloaded cleanly. The
independent verifier therefore establishes `ACM_REPLY_PROFILE` as
`(send=1/10, receive=1/10)`. No ACM service envelope, credential, or biometric
command was sent.

That profile gated a separate ACM context-lifecycle
kernel path. It is mutually exclusive with every discovery/capture/AKS mode
and requires its own 64-bit confirmation. After the two exact `(1/10, 1/10)`
registrations, it sends only the source-proven SCRD initialization, token-free
selector-1 context creation, and selector-2 deletion of that same ephemeral
context. The create reply must be exactly 17 bytes; only its first 16 bytes are
copied into the delete request, and neither portion is logged. Every request
and reply envelope is checked for endpoint 10, message type 1, exact phase
length, zero status/reserved word, and absent transport-error flags. Regardless
of the phase result, CPU stop precedes explicit scrubbing and freeing of both
16 KiB DMA mappings.

The first supervised service run on 2026-08-29 refined both prepared paths.
AKS OOL registration again returned the exact `(1/7, 1/7)` profile, but the
operation-`0x4d` envelope received no reply within the bounded five seconds;
the probe stopped the CPU, scrubbed/freed both buffers, restored PCI state, and
unloaded with timeout `-110`. It did not proceed to operation `0x2a`. The
request must not be repeated unchanged until activation/envelope assumptions
are rechecked.

The independent ACM run registered `(1/10, 1/10)` and its SCRD initialization
received an immediate exact zero-status empty reply, proving live endpoint-10
service traffic. The following legacy selector-1 create request received an
immediate correlated empty reply with status `-3`; no context was created and
delete was not sent. Teardown again completed cleanly, with five observations
on each MSI vector. Pinned `LibCall_ACMContextCreate` explains this result: when
its modern-mode argument is set Apple first sends command `0x24`, expects 21
bytes, and falls back to selector 1 expecting 17 bytes only if command `0x24`
itself returns `-3`. The Linux probe had skipped that modern-first branch. Its
next ACM revision must reproduce `0x24` then the exact Apple fallback rather
than retry selector 1.

That revision is now implemented offline and in the separately gated kernel
path. `CurrentContextCreatePlan` emits `DRCS 24 00 00 01`, accepts only an
exact zero-status 21-byte context, or treats only an empty status-`-3` reply as
the source-proven signal to emit legacy `DRCS 01 00 00 01` and require 17
bytes. Every other status, length, or ordering fails. Both context forms retain
only their first 16 bytes for external-form authorization and deletion, while
all 17 or 21 returned bytes remain mutable and are scrubbed at teardown. The
live verifier independently accepts exactly the modern lifecycle or that one
fallback sequence; no other branch is representable.

A revised supervised run then reproduced that full branch exactly. SCRD
initialization again succeeded, but current selector `0x24` returned an empty
correlated `-3` response and Apple's selector-1 fallback also returned an
empty correlated `-3` response. No context existed to delete. Teardown was
clean, with six observations on each MSI vector, CPU stop before DMA scrub and
release, PCI restoration, module unload, and driver rebind. The shared command
builder was subsequently checked byte-for-byte and confirms both Linux
requests already match Apple (`DRCS`, selector, zero flags/length, version 1).
This rules out the selector choice and eight-byte serializer as the
explanation; unchanged context retries are therefore prohibited.

The next bounded discriminator followed Apple's own non-secret
`ACMKernPrivPing` path. `LibCall_ACMPing` admits selector `0x1d`, supplies no
body or output buffer, and the shared builder emits `DRCS 1d 00 00 01`. The
gated lifecycle performs this zero-length ping after successful SCRD
initialization and requires a correlated zero-status, zero-length response
before attempting either context-create selector. A ping failure stops
immediately, distinguishing general ACM command readiness from a
context-specific prerequisite without creating a credential or handling a
secret.

The supervised ping returned an immediate correlated zero-status empty reply,
proving general ACM command readiness. Static dispatch-table analysis then
found the precise `-3`: both create selectors enter `CreateCredentialSet`,
whose first validation requires a four-byte body and reads it as a 32-bit
domain. Supplying domain zero changes the command to
`DRCS 24 00 04 01 00 00 00 00` and its envelope length to 12. On the next
supervised run the T2 returned the exact 21-byte current context with status
zero. Linux then sent selector 2 with only the opaque 16-byte external form;
deletion returned zero, and the independent verifier passed the complete
lifecycle. Seven interrupts arrived on each MSI vector and CPU stop preceded
scrub/release and clean unload. The pure model now includes the verified
domain field for both current and legacy creation. No context bytes were
logged or persisted.

`run-acm-context-lifecycle-probe.sh` adds the model/PCI/driver checks, exact
human confirmation, a fresh journal cursor, unload/unbind checks, and an
independent verifier. The verifier composes the proven endpoint-10 OOL
lifecycle, byte-exact non-secret envelope sequence, create-before-delete order,
no-context-logging markers, and the complete MSI/PCI/CPU-stop teardown. Its
live run has now validated SCRD initialization, ping, current context creation
with domain zero, and deletion on this T2. No context bytes were logged.

The AKS capabilities path has also run successfully. It constructs the exact
100-byte version-1 empty operation-`0x4d` request after the proven `(1/7,
1/7)` registrations. T2 returned a correlated selector-`0xcd` reply with a
declared `0x48` version-1 header and 92-byte total size. Parsing at that
declared boundary produced a valid constant-time digest comparison, zero
status, and remote version 2. A following version-2 operation-`0x2a`
environment request also validated. The codecs retain strict support for both
the observed compact reply and the 100-byte `0x50`-header form recovered from
Apple code; request and reply lengths are not assumed to match.

The same offline model computes the exact verify-secret serialized size
without accepting secret bytes: an `0x54`-byte serialized header, the variant
word, keybag qword, selector word, two 32-bit-length-prefixed blobs padded to
four-byte boundaries, and the final device-state qword. It requires the ACM
external form to be exactly 16 bytes and refuses any plan exceeding the
`0x4000` AKS OOL buffer.

Those two leading request fields are not safe constants. The symbolized
user-client path passes its 64-bit session keybag handle into
`AppleKeyStore::verify_password` and obtains the 32-bit selector through
`effective_bag_handle_actual`; `ipc_verify_secret_v1` then writes those values
at offsets `0x58` and `0x60` without deriving replacements. The offline
`AuthorizationPlan` now requires both as explicit, range-checked inputs before
it will plan operation `0x21`. It supplies no zero, root, current-UID, or other
Linux guess. It still accepts only secret lengths, not password or ACM-context
bytes.

The session-handle provenance is now recovered too. In the macOS 14.5 KDK,
`AppleKeyStore` initializes its object field at `0xe0` by passing exactly that
eight-byte field to `read_random`. `AppleKeyStoreUserClient::start` calls
`current_proc`, passes the result to `proc_uniqueid`, adds the random service
field with a native 64-bit `addq`, and stores the sum at user-client offset
`0xe0`. The same construction is repeated by kernel-facing call paths. Thus
the handle is a per-driver random namespace plus a non-reused client identity,
with modulo-2^64 addition; it is not a macOS enrollment artifact and does not
come from UID, PID, audit session, or the fingerprint database.

The pure model exposes that exact derivation and returns an opaque
`SessionKeybagHandle`. Metadata validation and `AuthorizationPlan` reject a
bare integer, so future Linux code cannot silently substitute a convenient
identity value. The eventual kernel implementation must obtain a fresh
64-bit nonce from its CSPRNG once per driver lifetime and allocate a stable,
non-reused 64-bit client ID. The model deliberately does not nominate Linux
PID as that ID.

The ordinary login-session selector policy is recovered as well.
`ImplicitHandleTranslate` changes an eligible operation's caller-supplied
implicit zero into `-3`, and `effective_bag_handle_actual` sends `-3` to
`evaluate_session_keybag_handle`. That function maps authenticated session UID
zero to special selector `-4`, maps session UIDs `10` through
`INT32_MAX - 1` to their signed negation, and rejects all other values. The
model exposes this mapping without consulting the ambient Linux process UID
and returns an opaque `SessionKeybagSelector`; the authorization planner now
rejects bare selector integers too. A future login broker must supply the UID
from its authenticated PAM/logind session rather than letting an untrusted
client choose it. This proves the arithmetic and policy boundary, not that a
Linux UID can reuse any macOS keybag.

There is an important operation-specific distinction: the two user-client
cases that feed `verify_password` (`0x6d` and `0x74`) pass their caller's first
32-bit scalar to `effective_bag_handle_actual`, but they are not members of
`ImplicitHandleTranslate`'s three-operation zero-to-`-3` allowlist (operations
7, 17, and 35). Their session-keybag caller therefore has to request special
handle `-3` explicitly; treating scalar zero as the login keybag would be
wrong for this path. The pure model exposes only the already-evaluated
session selector sent to SEP and does not model zero as an alias.

It also exposes a non-secret layout descriptor for later locked-buffer code.
For a 12-byte password, the variant, keybag, and selector begin at offsets
`84`, `88`, and `96`; the password length/data occupy `100`/`104`, the exact
four-byte-aligned password region ends at `116`, the 16-byte ACM context
length/data occupy `116`/`120`, and device options begin at `136`, producing
the proven 144-byte total. Other password lengths are derived with the same
checked arithmetic.

The ownership behavior is now recovered too. `__ipc_verify_secret_v1` creates
and zero-initializes a `0x98`-byte stack descriptor, stores password and ACM
context pointers and lengths at `0x68/0x70` and `0x78/0x80`, stores the input
device-options qword at `0x88`, and always wipes the complete descriptor after
the transport callback. `AppleKeyStore::verify_password` obtains both pointers
directly from its two `OSData` arguments; its boolean argument becomes exactly
bit `0x80` in the input device-state qword. On the receiving side,
`_post_process_ipc_verify_secret` wipes and frees both decoded blob allocations
for variants 0 and 1. Apple does not wipe the caller-owned `OSData` objects in
this function, so their lifetime remains a caller responsibility.

The offline model now adds a stricter ownership-transfer codec for future
Linux code. It accepts the two secrets only as mutable caller-owned
`bytearray`s, validates all non-secret metadata, copies them into one mutable
serialized request, computes the digest incrementally without concatenating an
immutable secret-bearing payload, and immediately zeros both inputs. The
returned `VerifySecretRequest` exposes only a memory view and an idempotent
`close`; context-manager exit wipes its complete backing buffer even when an
exception is raised. Its representation contains only length and closed state.
`AuthorizationPlan` correlates this buffer's negotiated header version and
exact planned OOL length and refuses both duplicate construction and a success
reply before construction. This is an offline memory-lifetime model, not a
claim that Python can provide production-grade locked memory, and there is
still no live authorization switch.

The successful operation-`0x21` variant-1 response is only 96 bytes: the same
`0x54`-byte serialized protected header, variant word `1`, and the returned
64-bit device-state value. The generated `_code_ipc_verify_secret` serializer
selects offset `0x90` for that variant's response qword; there is no embedded
status field in this successful payload, so an operation failure must never be
reinterpreted as a decodable success body. The strict decoder requires exact size, header
length, the already-negotiated header version, zero flags, valid digest, and
variant `1`. `AuthorizationPlan` additionally correlates selector, tag, and
OOL length and accepts the success reply only once. This models only the
strict response path; no live authorization call exists.

The returned device-state qword is not the password decision. A zero return
from the operation callback is already the success condition; only then does
`verify_password` pass the qword to `handle_device_state_return`, whose own
return value is ignored. That helper treats bits as asynchronous state work:
bit 0 schedules the lock timer, bit 1 tickles the system-keybag update port,
bits 2 and 6 emit state notifications, and bit 7 emits a client event. Bits
3, 4, and 5 select internal status values from the helper, but those values do
not replace the successful verify result. A Linux client must therefore retain
the raw qword for any future state synchronization without treating either
zero or nonzero as the biometric/password verdict.

No replacement ACM handle appears in the successful response. The caller
passes one copied 16-byte external form into operation `0x21`, wipes and
releases that copy after the call, and retains the original ACM context object
for subsequent policy or biometric work. Combined with the 96-byte response
layout, this shows that successful verification authorizes the existing
SEP-side context in place rather than returning a new context. The Linux flow
must retain the original 17-byte context-create result until eventual delete,
use only a mutable copy of its first 16 bytes for AKS serialization, and never
confuse the 17th tracking byte with the external form.

On 2026-08-29 the bounded ephemeral-keybag experiment succeeded on the live
MacBookPro16,1. AKS created a fresh store-type-0 bag and returned signed runtime
selector `1`; operation `0x21` authorized the existing current-format ACM
context; unload succeeded; a subsequent exact copy returned `-3`; context
delete, CPU stop, and DMA scrub all passed the independent transcript verifier.
This proves Linux can create a fresh SEP-backed password namespace and use it
to authorize an ACM context. It does not prove authentication against the
pre-existing macOS account keybag.

The first network-complete combined enrollment run then consumed that
authorized context but BiometricKit returned synchronous status `-3` before
sensor activation; therefore no touch was requested and no identity changed.
Teardown again passed unload, independent absence proof, context deletion, CPU
stop, and scrub. This was not a mistyped-password result: the freshly created
bag accepted verification of the same secret before enrollment began.

Reviewing the exact bridgeOS 23P6068 AppleKeyStore client exposed one concrete
difference in that run. Public `_aks_create_bag` supplies signed `-1` to the
internal create routine; its caller in `keybagd` supplies only secret pointer,
secret length, store type zero, and the returned-handle pointer. The Linux gate
had instead requested `-501`, conflating the negative login-session lookup
selector with this create-time field. It now requests Apple's exact `-1` and
continues to use only the SEP-returned runtime selector for verification and
teardown. A supervised rerun with that exact correction produced the same
result: create returned runtime selector `1`, verify-secret authorized the ACM
context, and BiometricKit synchronously returned `-3` before sensor activation.
Teardown passed in full. The create-time selector discrepancy is therefore
ruled out as the cause; the remaining gap is later user/system-bag association
or another post-create state transition performed by Apple's session path.

The matching KDK closes that next transition at the SEP wire boundary.
AppleKeyStore names operation `0x0d` `ipc_make_system_keybag`; its generated
variant-0 codec serializes the client namespace, a positive source runtime
handle, a negative target handle, and a length-prefixed passcode. The service
rejects a nonpositive source, targets at or above `-2`, and target `-5`, then
looks up the source bag, clones its serialized key store, reloads it under the
target, and applies the supplied passcode. This matches `keybagd`'s later
`_aks_set_system_with_passcode` call and explains why merely creating runtime
handle `1` is not equivalent to installing a `-501` user-session bag.

The bounded Linux experiment now inserts that exact operation between create
and verify. Verification uses the promoted `-UID` selector. Cleanup unloads
only a mapping whose copy operation first proves it present, and performs an
independent status-`-3` absence check for both the promoted target and original
runtime source before context deletion and CPU stop. The transcript verifier
distinguishes the two mappings by lifecycle role and fails if either teardown
is missing.

Static recovery of AppleKeyStore's operation `0x03` subsequently enabled a
closer session-lifecycle comparison. The Linux gate now copies the freshly
created bag as an opaque bounded blob, unloads and independently proves the
original selector absent, reloads that same blob to obtain a new positive
runtime selector, and only then performs `ipc_make_system_keybag`. No blob
bytes are emitted to logs or userspace, and the temporary allocation is
explicitly scrubbed after the load attempt and again on every exit path. This
tests whether SEP requires a persisted-and-reloaded bag rather than a newly
created in-memory bag before enrollment; it is not yet a live-positive result.

The supervised 2026-08-30 run completed this comparison. Operation `0x02`
returned a strictly validated 1424-byte opaque snapshot, operation `0x05`
unloaded runtime selector `3`, a second copy proved it absent with status `-3`,
and operation `0x03` reloaded the snapshot as selector `3`. Promotion to
`-501` and verify-secret both succeeded, proving the entered password was
accepted. Enrollment nevertheless returned synchronous status `261` before
requesting a touch. Cleanup independently removed both system and source
mappings, deleted the ACM context, stopped SEP, scrubbed DMA, and passed the
strict transcript verifier. Fresh-versus-reloaded AKS persistence is therefore
ruled out as the missing enrollment prerequisite.

The next static comparison returned to Catalina's symbolized
`BiometricSupport`. Its base `loadCatacomb` implementation clears the host
template list and calls `readCatacombState` before choosing either load or
`NoCatacomb`. After loading each selected user it calls
`syncTemplateListForUser:`, whose first remote operations cache the packed
biometrickitd information and enumerate identities. Only after that loop does
the host mark its private catacomb-loaded byte, validate users, and remove
unused host files. The byte, validation, and file cleanup are host-only and
must not be fabricated as Bridge commands. The actionable wire-level gap is
that Linux previously performed the system-config, catacomb-state, and
catacomb-group-state reads only in separate diagnostic sessions. Native
enrollment now requires all three bounded, read-only, shape-validated queries
on the actual enrollment connection before its already proven xART read and
identity synchronization. This change is offline-tested but deliberately not
run until the user is present, because successful command acceptance would
cross into a touch-capable enrollment transaction.

The non-enrolling live context probe then reproduced the known cold result:
both state getters returned bounded `kIOReturnBadArgument`. The client treats
that exact pair—not arbitrary failure—as the daemon's no-loaded-state branch,
sends the proven general `NoCatacomb(0xffffffff)` transition, and continues
through xART without sending command `3`. The full pre-enrollment context
completed. This validates the revised ordering while leaving the actual
enrollment attempt for a separately supervised run.

That supervised run then completed the same cold-state prefix under the fully
authorized copied/unloaded/reloaded/promoted keybag lifecycle. Verify-secret
returned `authorized=yes`, ruling out a password typo, but command `3` again
returned synchronous status `261` and never requested a touch. Both keybag
mappings, the ACM context, SEP CPU state, and DMA buffers passed complete
verified teardown. Same-session state reads plus the daemon's exact general
`NoCatacomb` cold transition are therefore not sufficient for enrollment.

The follow-up supervised transaction combined that exact cold-state prefix
with UID-501 authenticated protected-policy creation and readback on the same
Bridge session. Its opaque AKS bag was copied, unloaded, proven absent,
reloaded, promoted to `-501`, and verified; `authorized=yes` conclusively rules
out an incorrectly entered password. Command `3` still returned synchronous
status `261` before requesting a touch. Both keybag mappings, the ACM context,
SEP CPU state, and DMA buffers then passed the strict teardown verifier. Thus
neither prerequisite alone nor their same-session combination accounts for
the rejection.

Catalina's symbolized first-unlock path gives the number `261` additional—but
not yet dispositive—context. `handleFirstUnlock` returns literal `0x105` when
the host cannot access its class-C protected files. Once those files are
accessible it changes only daemon bookkeeping, calls the already analyzed
`restoreAndSyncTemplates`/`loadCatacomb` path, and posts a host notification.
The cold no-file branch of `loadCatacomb` adds no undiscovered Bridge command
beyond the reproduced general `NoCatacomb`; first unlock is not itself a wire
operation that Linux can safely imitate. The numerical match strengthens the
hypothesis that command 3 is rejecting protected-data/keybag readiness, but it
does not prove that the daemon's local error namespace and SEP's returned
status have identical meanings.

The first supervised promotion request did not reach verification because it
revealed asynchronous ordering that the initial receiver did not yet model.
T2 emitted two endpoint-7 notifications before the correlated reply: opcode
`0`, tag `1`, selector `-501`, then opcode `4` with the same tag and selector.
The eventual operation reply was observed later in the displaced queue as
`00048d07 00580001 ...`: status zero, operation `0x8d`, request tag `4`, body
size `0x58`, and low transport flag `1`. The old waiter consumed the first
notification as a malformed reply; subsequent cleanup reads were consequently
mis-correlated, so the run failed closed. CPU stop, OOL scrub, PCI restoration,
and module removal still completed, but message-level absence was not claimed.

The corrected waiter now requires those two exact notifications in order and
then the exact tagged reply. Cleanup first issues copy for each lifecycle role:
status `-3` proves it already absent, while only a valid successful copy proves
presence and permits unload followed by another absence check. This handles
both a moved source and a retained source without guessing after a partial
promotion. Another supervised run is required to prove the corrected promotion
and determine whether it changes BiometricKit's synchronous `-3`.

One subsequent attempt stopped even earlier because two replies from the
previous displaced queue remained pending across CPU stop. The stale ACM reply
was consumed where the new control NOP reply was expected, so strict NOP
validation aborted before OOL registration and before the password-backed
operation. This was a transport-resynchronization failure, not a password or
biometric result.

Startup now performs a tightly bounded recovery only when the CPU-control
register has Apple's observed stopped value `0x7f`. If the inbox is already
nonempty, it drains at most 16 mailbox records (never OOL payload data),
requires an empty inbox, and then executes the unchanged CPU-start and tagged
NOP sequence. Any other CPU state, read error, or record overflow fails before
startup. A password-free live probe drained exactly the remaining endpoint-7
copy reply and endpoint-0 control reply, after which a fresh NOP returned
`00010100 00000000 00000000 ...` and passed strict validation. CPU stop and
module removal then completed normally, proving the transport was resynchronized
without requiring a power cycle.

The next supervised run provided direct proof that make-system-keybag works.
It received both exact promotion notifications and then a correlated status-zero
`0x8d` reply whose low word was `0`; a strict copy of `-501` immediately
returned a valid 1612-byte bag. Thus the previous low value `1` is transient
queue state rather than a fixed reply flag, and both observed values are now
accepted only with the exact operation, tag, and `0x58` body size.

Teardown exposed one more asynchronous edge. Unloading `-501` first emitted an
endpoint-7 opcode-1/tag-0 notification carrying `-501`, then the tagged unload
reply. Because the initial waiter did not consume that event, the remaining
cleanup became displaced and the experiment again failed closed before ACM
verification or BiometricKit. The queued source copy later showed service
status `-13`, distinct from ordinary absent status `-3`; this is the observed
invalidated positive source after promotion moved it into the system selector.
The corrected cleanup requires the exact unload notification before its reply
and accepts `-13` as absence only for that source lifecycle. CPU stop, scrub,
PCI restoration, and module removal completed. A password-free follow-up
drained the remaining ACM delete reply and strictly validated a fresh NOP.

The first fully correlated promoted-bag run then completed the entire kernel
lifecycle. Creation returned runtime selector `3`; make-system-keybag installed
the authenticated copy at `-501`; verify-secret authorized the ACM context
against that promoted selector; and the enrollment client consumed the
credential handoff. BiometricKit no longer returned the earlier synchronous
`-3`: the same version-2, built-in-group request returned `261` (`0x105`). It
still did not start enrollment, request a touch, or create an identity. Teardown
proved a valid 1612-byte system copy, unloaded `-501`, proved status-`-3`
absence, then independently found the positive source still present in this
run, unloaded it, and proved its absence before deleting the ACM context and
stopping/scrubbing the SEP transport. Thus promotion is a necessary, observable
state transition, but it exposes one additional biometric prerequisite rather
than completing enrollment.

The matching KDK provides one bounded clue for interpreting `0x105`, although
it does not yet prove which component originated the live value. In symbolized
`AppleMesaSEPDriver`,
`AppleMesaSEPDriver::cacheSysProtectedConfigurationSpecific(bool)` returns the
literal `0x105` when it cannot obtain/cast the cached system-configuration
object; that routine otherwise sends biometric command `0x39`
(`GetSystemProtectedConfig`) and validates a 36-byte response. The common
`IOBiometricService::cacheSysProtectedConfiguration(bool)` path allocates and
caches that object, refreshes per-user protected configuration, and updates the
biometric-token, passcode-input, and match timers. This initially made missing
system or per-user protected configuration a candidate explanation, but a
subsequent read-only Linux query sent command `0x39` through the live
BiometricKit bridge and received status zero with the expected 36-byte output.
All nine 32-bit fields were zero. The object/query path therefore exists; the
stronger remaining hypothesis is that macOS populates policy/timer fields which
Linux has not initialized. The shared numeric value alone is still not a
definitive error name. Before any setter is attempted, the same 36-byte
structure must be captured on macOS and the exact command `0x3a`
(`SetSystemProtectedConfig`) ownership and mutation semantics recovered.

Installed macOS 26.6.2 user-space analysis subsequently showed that this
comparison used stale command numbers. Current x86_64 `biometrickitd` sends
`0x43` for `GetSystemProtectedConfig` and expects exactly 36 bytes; its setter
is `0x44`, not `0x3a`. Apple's entitlement-bearing, read-only
`bioutil --read --system` path reported functionality and unlock enabled,
unlock-token lifetime 172800 seconds, match lifetime 14400 seconds, and
passcode-input lifetime 561600 seconds. The current decoder maps those to
words 3, 4, 0, 7, and 8 respectively; words 1, 2, 5, and 6 are not exposed by
the CLI and must be read directly with current command `0x43`, not inferred.
Thus the successful all-zero Linux `0x39` result is legacy compatibility
evidence, not the current macOS policy. No setter was sent.

A Linux return query then mirrored the current connection setup (method `0`,
client-version method `10` with value `2`, and opened-state method `1`) and
sent read-only command `0x43`. Command version `2` returned status zero and
the exact nine words `(172800, 5, 5, 1, 1, 1, 1, 14400, 561600)`. Versions
`1` and `3` respectively produced the expected legacy 28-byte form and a
nonzero status. The current policy is therefore present and agrees with every
value exposed by macOS; sending setter `0x44` is neither necessary nor safe.
The numerical overlap between enrollment status `0x105` and the KDK cache
failure is not the live cause. The enrollment client now performs that same
strict per-connection initialization before identity enumeration and command
`3`, closing the next bounded protocol-state mismatch without changing policy.

The supervised run with that initialization still returned synchronous status
`261` before any service event or requested touch. Password-backed creation,
promotion to `-501`, ACM verification, credential handoff, both absence proofs,
context deletion, CPU stop, and DMA scrub all passed. Matching KDK disassembly
shows `commandStartEnroll` forwards command `3` with the exact 68-byte input
and returns the underlying perform-command status, so this result is not the
userspace client's response-length validation. Current bridgeOS strings expose
separate `GetProtectedConfig`/`SetProtectedConfig` and catacomb lifecycle
commands in addition to the now-proven system config. The next read-only
comparison must identify the current per-user getter and catacomb-state getter,
their versions and exact response shapes for UID 501; no setter or catacomb
mutation is justified yet.

The next-stage implementation retains that freshly authorized context only
inside the bounded kernel probe while a Linux BiometricKit enrollment client
runs. Its 16-byte external form is readable once through a root-only sysfs
parameter and is piped on standard input, never placed in an argument or log.
A separate write-only completion acknowledgement lets the probe retain the SEP
context through the transaction; two five-minute deadlines ensure eventual
teardown. The client uses the exact current 68-byte version-2 built-in-device
enrollment payload, and both the mutable request owner and kernel handoff buffer
are explicitly scrubbed. Build and offline lifecycle tests pass; the combined
hardware path remains unproven until its supervised enrollment run.

The first combined run reached and consumed the authorized handoff, but the
userspace enrollment client then failed with `ENETUNREACH` before opening the
RSD directory socket: NetworkManager showed the internal NCM interface as
disconnected with no IPv6 address or route. The kernel side nevertheless
received the completion acknowledgement and passed unload, independent
absence proof, context delete, CPU stop, and scrub. Reapplying the existing
non-autoconnecting internal-link profile with host address
`fe80::aede:48ff:fe00:1122/64` restored 2--5 ms scoped peer pings and the exact
read-only BiometricKit `(status=0, bridgeVersion=3)` exchange. The combined
runner now makes that query a mandatory pre-password preflight, preventing a
network-state failure from wasting another password prompt.

`credential-authorization.py` now composes these boundaries into one offline
lifecycle without importing any device, socket, PAM, or prompt implementation.
ACM initialization/context creation and AKS capabilities/environment setup may
occur independently, matching their driver-lifetime separation, but neither a
verification plan nor secret transfer is permitted until both the context and
AKS environment exist. The coordinator copies only the context's first 16
bytes into the consuming AKS serializer, retains the original 17-byte owner,
closes the complete verify request before accepting its reply, and marks the
existing context authorized only after the exact correlated success response.
Only then may it create the scrub-owned built-in enrollment request described
above. It copies the first 16 bytes directly from the retained context, never
the 17th tracking byte; rejects duplicate outstanding enrollment credentials;
and retains ownership so abort, context deletion, or transport-loss cleanup
wipes a request even if its caller forgot to close it.

Any malformed or reordered input permanently closes the authorization branch,
while preserving the original context solely so deletion can still be
attempted. Deletion remains available after failure; only its exact zero-status
reply scrubs and closes the normal lifecycle. If transport itself is lost, a
separate `scrub_after_transport_stop` path records failure and zeros the verify
request, context response, and pending delete command. Rejected mutable context
payloads are wiped before error return, representations expose state booleans
only, and destructor scrubbing is explicitly just a local fallback—not a
substitute for SEP deletion or CPU stop. Tests cover success, bad correlation,
reordering, abort, delete-after-failure, and stop-driven cleanup. This proves
offline composition; it does not enable operation `0x21` on hardware.

`credential-session.py` now closes the offline ownership gap between this
authorization lifecycle and the dual ACM/AKS OOL bootstrap. Authorization
traffic cannot start until all four independently profiled registration ACKs
have committed. The coordinator owns at most one ACM or AKS exchange at a
time, records it in the corresponding endpoint lifecycle, and drains that
operation before handing a reply to the strict decoder. Consequently a
malformed reply fails authorization without leaving teardown falsely blocked,
while an actually outstanding exchange prevents either endpoint from being
stopped. Normal shutdown refuses an undeleted SEP context; explicit abnormal
shutdown stops both endpoints and releases all four mappings before locally
scrubbing the retained context and secret buffers. Tests cover pre-readiness
rejection without state mutation, cross-endpoint serialization, full
authorization/delete/shutdown, undeleted-context refusal, abnormal cleanup,
and malformed-reply draining. The session has no allocator, I/O, prompt, PAM,
or live-send API and is not evidence that simultaneous registration works on
hardware.

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
module cleanup. It now also requires the exact
`I_UNDERSTAND_CONTROL_NOP_PROBE` argument, a freshly built module, and a fresh
journal cursor, with no recent-log fallback. Its first invocation was canceled while waiting for polkit and
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

The runner now independently verifies that whole lifecycle rather than
assuming a successful unload means the NOP passed. Its offline verifier
requires the exact tagged response, strict-validation record, both MSI counts,
CPU stop, PCI restoration/release, and final removal in order; failure or a
truncated cursor-bounded transcript makes the wrapper fail.

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

### Live AKS negotiation and environment milestone (2026-08-29)

The first bounded timing-class experiment overturned the prior timeout
interpretation. T2 immediately answered the zero-time operation-`0x4d`
request with this correlated envelope:

```text
AKS time candidate envelope: class=zero raw=0001cd07 005c0000 00000000 ...
AKS time candidate reply passed strict validation: class=zero status=0 remote_header_version=2 reply_size=92
```

The response declares `0x48`: the version-1 reply uses a compact 72-byte
header, followed by the same 16-byte capability body. Our fixed-100-byte
parser rejected that immediate response before checking its digest. The
kernel and offline codecs now honor the declared `0x48` or `0x50` header
boundary, require an exact 16-byte body, and validate the protected digest
before exposing status or version.

A fresh startup-prefix run then succeeded end to end. Operation `0x4d`
negotiated remote version 2, and normal-boot operation `0x2a` returned its
correlated 88-byte reply with a valid digest, zero status, and header version
2. CPU stop, DMA scrub/release, MSI observations, PCI restoration/release,
module unload, and device unbind all passed independent verification. No
password, fingerprint template, or biometric operation was used.

This proves Linux can initialize the live AKS endpoint through Apple's
non-secret prefix. A new default-off combined probe now joins that prefix to
the already validated ACM context lifecycle within one SEP CPU lifetime. It
registers four distinct AKS/ACM DMA buffers, requires AKS environment success
before ACM initialization, deletes the ephemeral context, stops the CPU, and
scrubs all four buffers. A composite verifier proves the dual transport and
both service state machines independently. The supervised live run succeeded:
AKS returned remote version 2 and accepted normal environment setup, ACM
initialization/ping/current-context creation/deletion all returned zero, and
both MSI vectors recorded 11 interrupts. CPU stop, four-buffer scrub/release,
PCI restoration/release, unload, and unbind passed the verifier. No password,
context bytes, or biometric data were logged. This closes simultaneous service
startup; the next boundary is a scrub-owned operation-`0x21` password
verification of the live ephemeral ACM context.

The password boundary is now implemented behind a separate one-attempt gate.
The privileged runner sends hidden prompt output directly to `keyctl padd`
with no intervening password variable and passes only the non-secret key
serial and explicit macOS session UID to the module. The kernel requires a
temporary `user` key, bounds its payload to 1..256 bytes, constructs the
variant-1 request with a fresh nonzero CSPRNG keybag handle and the recovered
negative session-UID selector, then revokes the key before issuing operation
`0x21`. No password, handle, context, or returned device-state value is logged.
After any received reply the AKS DMA buffers are erased immediately; if no
reply arrives, CPU stop retains precedence over DMA scrub. Context deletion is
attempted after the verification exchange, and the ordinary four-buffer
stop/scrub teardown remains mandatory. This implementation and its strict
success-transcript verifier pass offline tests.

The first live attempt on 2026-08-29 completed capabilities, environment
setup, ACM initialization, and creation of a fresh 21-byte context. T2 then
returned the correlated bodyless envelope `ff03a107 00000000 00000000 ...`
for operation `0x21`; ACM context deletion and the full stop/scrub/unbind path
still completed. The high byte is signed service status `-1`, not a malformed
mailbox tag.

This is not evidence of an incorrect password. In the checksum-pinned macOS
14.5 KDK AppleKeyStore x86_64 image
(`f1067b2a93022fa0dfa7ceb82b13478634a913a4f93124c8711c4aa2b24676b0`),
the service-side `_ipc_verify_secret_v1` at `0x738cb` calls
`_keybag_for_handle` at `0x7391c` before it inspects the supplied secret or ACM
external form. A null lookup branches at `0x7392a` to the return path with
status `-1`. The same function also maps an unlock failure to `-1`, so the
wire status alone is intentionally ambiguous; however, this Linux run had
created a fresh random client namespace and never created or loaded any
keybag under it. A keybag lookup therefore could not succeed regardless of
password correctness.

The earlier live gate incorrectly treated the per-client namespace handle and
negative macOS session selector as sufficient metadata. They identify a bag
that must already exist; they do not instantiate one. Repeating password
attempts in that state cannot add evidence and risks needless retry accounting.
The next Linux-native dependency is operation `0x01` keybag creation (or
operation `0x03` loading for compatibility with an existing macOS user), with
the returned runtime handle retained under the same namespace through
verify-secret and unloaded during bounded teardown.

Static recovery of that next request has begun without choosing a live store
type. AppleKeyStore's generated operation-`0x01` variant-1 codec serializes the
protected `0x54`-byte prefix followed by variant word `1`, the 64-bit client
namespace, a 32-bit store type, a signed 32-bit requested selector, and two
32-bit-length-prefixed blobs with four-byte padding. Its successful response is
exactly 92 bytes: the protected prefix, variant `1`, and one returned signed
runtime selector. `aks-transport.py` now encodes and scrubs that request and
strictly decodes the success form. The store value remains an opaque typed
input because guessing device/system/volume semantics would turn an exact
codec into an unsafe mutation policy. A live gate still requires exact store
semantics plus operation-`0x05` unload and proof that teardown removes the
created bag from the same namespace. The unload service returns success even
when it finds no matching bag, so that proof must come from a subsequent
operation-`0x02` copy returning the service's absent-bag status; unload success
alone is not evidence of removal.

The remaining store-type ambiguity is now closed for the relevant user-session
path. The official bridgeOS 23P6068 `keybagd` binary (SHA-256
`9e05a68827a6be486e2cf14a592dbc493a53161df4d51695b3e35666677d31ba`)
implements `createKeybagForUserSession...` with an immediate zero in the store
type argument immediately before its `_aks_create_bag` call at virtual address
`0x10000cc28`. The same build's extracted MobileKeyBag image (SHA-256
`6500d9ad97f1dd5518dad5b8773164f8efd41938ef58e0786ba52acd5a379420`)
independently passes `1` in `MKBKeyBagCreateBackup` and `3` in
`MKBKeyBagCreateOTABackup`. Thus device/user-session store type `0` is an exact
Apple-client value, not a gap filled by enumeration. The offline codec exposes
named typed constants for those three values but still requires explicit
selection and performs no live mutation.
`tools/research/verify-bridgeos-keybag-store-types.py` makes the two binary
hashes and the three immediate-plus-call instruction pairs reproducible and
fails closed on either an image or call-site mismatch.

A new default-off live gate now composes the evidence-backed lifecycle without
running it automatically: operation `0x01` creates exactly one type-0 bag under
a fresh nonzero namespace; its returned signed selector feeds operation `0x21`;
operation `0x05` unloads that exact namespace/selector; and operation `0x02`
must subsequently return service status `-3` with no body. The ACM context is
deleted and the SEP CPU stopped on the bounded path. Password input remains in
the temporary kernel user key until create has replied, then is revoked before
verify-secret is transmitted. The runner uses a distinct explicit confirmation
and `verify-ephemeral-keybag-authorization-log.py` rejects missing, duplicated,
out-of-order, or incomplete teardown markers.

This experiment has a deliberately narrow interpretation. A successful
verify-secret against a bag created moments earlier does not authenticate a
pre-existing macOS account; it proves only that Linux can create and unlock an
ephemeral user-session bag and obtain an ACM context. The next question is
whether the biometric enrollment service accepts that freshly authenticated
context. No enrollment command is chained into this gate, so authorization and
enrollment remain separate supervised steps.

### Current macOS per-user state and enrollment serializer (2026-08-29)

Static analysis of the installed macOS 26.6.2 `biometrickitd` closes another
wire-format ambiguity. Current `GetProtectedConfig` is command `0x2e`, with a
four-byte UID input and exact 32-byte reply. Its current Bridge command version
was subsequently proven live to be 1; the earlier version-0 interpretation
confused Apple's zero `inValue` argument with the Bridge version. `GetCatacombState` is
command `0x3c`, version 0, with no input and a variable reply whose length must
be divisible by 8. `GetCatacombUUID` is command `0x38`, version 0, with a
four-byte UID input and exact 16-byte reply. On protocol generation 2 or newer,
`GetCatacombGroupState` is command `0x50`, version 0, with no input and a
variable reply whose length must be divisible by 56. Sensitive returned values
were neither queried nor retained.

The current enrollment serializer also confirms command 3, version 2, and an
exact 68-byte input on this bridge-generation-3 machine. Its partition is four
bytes of flags, four bytes of UID, a 40-byte authorization/credential record,
and a 20-byte device-group record. This exactly matches Linux's current layout,
including the 16-byte ACM form in its 32-byte credential slot and the group
type plus UUID record. Further changes to command-3 size or version are not
supported by current macOS evidence.

A password-authorized Linux transaction subsequently proved the entire
per-user policy prefix live: current `NoCatacomb` returned zero,
`SetProtectedConfig` returned zero, and the corrected version-1 getter returned
the requested `(1, 1, 1, 0)` policy in an exact 32-byte reply. Command 3 still
returned synchronous status `261` before requesting a touch. A bounded attempt
to checkpoint that pristine policy-bearing component stopped at
`PrepareSaveCatacomb` status 22, before serialization or host storage. Empty
databases therefore cannot be made persistent through that save path.

A subsequent password-free live probe proved that `NoCatacomb` also accepts
the default/non-user UID `0xffffffff` with status zero. This provides an empty
initializer corresponding to macOS's observed two-stage startup order: load
the general component first and UID 501 second. The enrollment bootstrap now
mirrors that order with global then per-user `NoCatacomb`, followed by the
authenticated user policy and unchanged command 3. Successful enrollment is
still the only point at which the durable save protocol runs.

The supervised global-then-user transaction completed both initializers,
authenticated policy creation/readback, and credential handoff, but command 3
again returned synchronous status `261` without requesting a touch. Global
component absence is therefore not the cause. The remaining authorization
difference is below the BiometricKit serializer: Linux verifies the password
against a freshly created/promoted type-0 keybag, whereas macOS verifies the
ACM context in its established login-session lifecycle. The next static
comparison must determine the exact `_aks_verify_password` device-state input
used by the current Settings enrollment path and any keybag/session operation
between verification and command 3; repeating command 3 with the current
credential cannot add evidence.

The first macOS return-pass interpretation concluded that Settings used zero
for operation `0x21` and correctly found no hidden AKS call between password
verification and exporting the same ACM context. A later instruction-level
audit corrected the codec branch direction and selector-42 Boolean ordering:
the two caller-visible optional Booleans are false, but the wrapper supplies a
third plaintext-secret option, producing wire value `0x200`. The caller-facing
selector `-3` still resolves to the same SEP-side `-501` selector Linux uses.

An expanded read-only Linux state query then returned requested and effective
UID 501 policies both equal to `(1, 1, 1, 0)`, maximum identity count 5, free
identity count 3, and an empty UID 501 identity list. The exact catacomb-UUID
getter, state getter, and group-state getter all returned
`kIOReturnBadArgument`. Thus neither disabled effective policy nor exhausted
sensor capacity explains status 261. Two global slots are occupied while the
Linux user component has no addressable catacomb UUID, making recovery and a
local-only load of the existing macOS catacomb the next controlled comparison.
The opaque file must never be committed or printed because it contains
biometric database material.

The first macOS transfer pass stopped before mounting EFI because its required
format assumption was false. The active UID-501 `.cat` file is a 708-byte Apple
binary keyed archive, not a raw `CAT1` blob; neither it nor any data object in
the three current archives has `CAT1` magic. Current `biometrickitd` separates
archive metadata from `CatacombSecureData`. Its Mesa load path obtains the
decoded secure-data object's bytes and length and supplies those bytes directly
to outer command `0x40`; it does not send the keyed archive or synthesize a
host-side `CAT1` header. No transfer artifact was created.

The Linux `LoadCatacomb` codec's `CAT1` and UID-at-offset-8 requirements
therefore do not describe the current macOS persisted-file path. They must not
simply be removed: Linux first needs a fail-closed keyed-archive extractor and
must reconcile the earlier KDK handler interpretation with the installed
daemon's exact call path. Only then should a new macOS pass encrypt the archive
for local transfer and Linux extract its opaque secure-data field without
printing, hashing, or retaining unrelated archive contents. Exact constraints
and the return handoff are in `docs/macos-catacomb-transfer-handoff.md`.

The narrower current-format comparison later transferred only the decoded
104-byte UID-501 `CatacombSecureData` under CMS encryption. Linux decrypted it
into a root-only file and sent current command `0x40`; the service returned
status 257. All five temporary transfer/key artifacts were then removed. This
is a service-side semantic rejection, not a Bridge envelope error. Because
macOS always loads a non-user/general component before UID 501, the next
bounded comparison loads both decoded components in that exact order on one
connection before reading only policy length and identity count.

Linux subsequently added a distinct bounded loader for decoded current-macOS
`CatacombSecureData`, without weakening the separate KDK save-blob validator.
The authorized macOS follow-up revalidated the root-owned 708-byte UID-501
archive, decoded its single 104-byte secure-data object with Foundation, and
streamed those bytes directly into an AES-256 CMS envelope on EFI. No plaintext
temporary file was created. The resulting
`/Volumes/EFI/t2-touchid-transfer.cms` is 661 bytes and passed CMS structural
parsing without decryption. No source or encrypted content was printed, hashed,
committed, or uploaded. Linux can now perform the one-shot command-`0x40`
comparison and immediately remove both local transfer artifacts.

The single user-component load reached the biometric service but returned
status 257. A second authorized macOS pass therefore reproduced the daemon's
two-component ordering. Foundation identified general UID `-1` with a
599-byte archive and 148-byte secure-data object, followed by UID 501 with a
708-byte archive and 104-byte secure-data object. Each decoded object was
streamed directly into its own AES-256 CMS envelope on EFI without a plaintext
temporary file. The final general and user envelopes are 718 and 669 bytes,
respectively, and both passed CMS structural parsing. Linux can now load the
general object first and the user object second on one Bridge connection and
remove all transfer artifacts afterward.

That static comparison recovered the context lifetime but initially
misidentified the final options field. In the checksum-pinned current
Settings extension, `ACMContextGetExternalForm` invokes a callback that calls
the local `_aks_verify_password` wrapper with caller-facing keybag handle `-3`,
the bounded password, and the same ACM external form. The selected wrapper
hard-codes both optional Boolean arguments false. A later selector-42 audit
proved that a separate, unconditional third Boolean sets plaintext-secret
option `0x200`; it is not optional bit `0x80`. On success the callback copies
that same external form into `NSData`. No further AKS, keybag, or session call
occurs before the form is returned to the enrollment UI and BiometricKit.

Handle `-3` is AppleKeyStore's caller-facing current-login-session request, not
the selector serialized to SEP. The previously recovered authenticated session
mapping resolves it to `-501` for UID 501. Linux's promotion and verify-secret
against effective selector `-501` therefore match the macOS SEP-side operation.
Setting optional bit `0x80` or sending literal `-3` to SEP remains disproved,
but the canonical request must carry `0x200`. The installed x86_64 extension hash and exact
instruction sequences are enforced by
`tools/research/macos-enrollment-authorization-evidence.py` and its negative
tests. The password/ACM request framing became closed only after the `0x200`
correction.

Sanitized logs from the current boot establish the pre-client ordering:
bridge and sensor initialization, accessory caching, general catacomb load,
successful UID 501 catacomb load with user protected configuration present,
overall load completion, and only then XPC publication and initial lockout-state
queries. The existing user's per-user database is therefore loaded before
enrollment can be requested, not lazily by command 3. This observation does
not distinguish first-unlock from login availability on a pristine account,
but it makes missing preloaded per-user database state the leading remaining
difference on Linux. Exact sanitized details and constraints are in
`docs/macos-user-config-handoff.md`.

The first Linux read-only state-shape probe mirrored bridge generation-3
initialization and sent commands `0x2e`, `0x3c`, and `0x50`. Its then-version-0
`0x2e` envelope and the two state commands returned the identical host status `0xe00002c2`
(`kIOReturnBadArgument`) with no accepted result shape. The two no-input state
commands remain evidence that the service lacked initialized/loaded catacomb
state after Linux boot. The per-user result is not such evidence because its
Bridge version was wrong; later live version discrimination corrected it. The
probe is checked in and deliberately
reports only status, accepted length, and record counts; opaque records are
never decoded or printed.

Current KDK dispatch proves that Apple's pristine-database `NoCatacomb` path
is command `0x31`, version 1, with an exact four-byte UID input and no output.
A separately gated Linux probe sent that exact request for UID 501. It
succeeded with status zero. The two catacomb-state queries still returned
`kIOReturnBadArgument`; the accompanying per-user getter used the subsequently
disproved version-0 envelope and therefore cannot establish whether
`NoCatacomb` alone created a policy.

Linux can now initialize an empty in-memory catacomb context, but doing so does
not create a persisted biometric database. Whether it independently creates a
default protected-policy object was not established by that run. The
probe neither reads nor writes macOS's on-disk catacomb, and the state
disappears when the bridge or machine is restarted. Static analysis identifies
the next operation as current `SetProtectedConfig` command `0x2f`, version 1,
with an exact 60-byte input: four-byte UID, four 32-bit policy values, then a
40-byte authorization record. That setter must not be sent until the initial
policy values and authorization semantics are evidence-backed.

Catalina's fully symbolized implementation fixes the field names and
authorization representation. The policy words, in order, are `unlockEnabled`,
`identificationEnabled`, `loginEnabled`, and `applePayEnabled`. Its common
authorization parser encodes a credential-set request as `usingAuthToken=0`,
`length=16`, the 16-byte ACM external form, and 16 bytes of zero padding. It
rejects data longer than 32 bytes and distinguishes credential sets from auth
tokens. Current KDK dispatch independently retains the same exact 60-byte
setter size and forwards it as internal command `0x2c`.

The offline codec now expresses only complete Boolean policies and the proven
16-byte credential-set form; it rejects Apple's `-1` partial-update sentinel,
auth-token variants, non-Boolean values, and malformed lengths, and scrubs both
the caller's credential and its owned request. For a Linux-native account the
candidate policy `(1, 1, 1, 0)` intentionally enables unlock, identification,
and login while disabling the Apple-Pay-only capability. This is a Linux
policy choice, not a claim about macOS defaults. A live send remains gated
until it is composed with the already proven password-to-ACM lifecycle and an
immediate readback.

That composition is now implemented behind a distinct explicit confirmation.
One kernel authorization handoff supplies a verified ACM external form to a
single Bridge connection. The client initializes the empty UID catacomb,
sends the complete `(1, 1, 1, 0)` policy with one credential copy, requires a
successful exact-size getter reply whose first four set-policy words match,
and only then sends enrollment with the independently scrub-owned credential
copy. Both request buffers and the original handoff are zeroed, and every
failure still executes cancellation and the existing SEP/AKS teardown. The
transaction has 402 passing offline tests; its new policy-setting path has not
yet been run on hardware.

### Current catacomb persistence ABI

Current generation-3 KDK dispatch also recovers the complete save handshake.
`PrepareSaveCatacomb`, `CompleteSaveCatacomb`, and `ConfirmSaveCatacomb` are
outer commands `0x3d`, `0x3e`, and `0x3f`; all use command version 2 and the
same exact 24-byte context. That context is the UID followed by the 20-byte
built-in device-group record already established for enrollment. Prepare
forwards internal command `0x6c`, pins the resulting SBIO allocation, and
returns its four-byte blob length. Complete requires the byte-identical context,
copies exactly that many opaque bytes to the caller, and frees the pinned
allocation. Confirm again requires the same context and forwards internal
command `0x37`.

`LoadCatacomb` is current outer command `0x40`, version 1. It accepts the opaque
blob returned by Complete, requires more than the 32-byte catacomb header,
reads the UID at byte offset 8, and forwards the entire blob as internal
command `0x6d`. Linux codecs bound blobs to the independently recovered
75-page (300 KiB) biometric outbound SBIO aperture, correlate the UID,
and make every save phase explicit. A local storage envelope adds version,
UID, length, and SHA-256 corruption detection around the otherwise untouched
opaque SEP blob, uses mode `0600` beneath a mode-`0700` directory, and replaces
records with file-and-directory `fsync`. These codecs and storage behavior
bring the offline suite to 406 tests. Live save remains downstream of a
successful enrollment; no biometric template bytes have yet been captured or
written by Linux.

The supervised policy-enrollment transaction now includes persistence in the
same live Bridge session. Only after the terminal identity exactly matches a
one-record enumeration delta does it prepare the save, accept an exact bounded
blob, validate its embedded UID, atomically fsync the root-only record, and
send Confirm. A storage failure deliberately prevents confirmation. The
Bridge receive cap is expanded only around that one Complete reply and only to
the prepared size plus bounded binary-plist overhead, then restored. The root
record path is `/var/lib/t2-touchid/<uid>.catacomb`. This end-to-end path has
407 passing offline tests but still awaits its first supervised hardware run.

A separate default-off restart verifier now reads that root-only envelope,
checks its UID and integrity before opening the Bridge, sends the exact current
Load command, and requires both a 32-byte protected-policy reply and an
identity list containing no foreign UID. It prints only status, policy length,
and identity count. Together with the save transaction this provides the
bounded proof needed before treating a Linux enrollment as durable; the suite
now contains 409 passing tests.

The match state machine now mirrors current per-connection bridge
initialization before touching biometric state and can load a validated stored
catacomb before taking its trusted identity snapshot. A default-off command
line client reads only the root-owned envelope, issues a touch instruction
only after the sensor's ready event, binds a terminal match to the freshly
enumerated UID/identity pair, and exits unsuccessfully for a no-match. It logs
no UUID or template bytes. This supplies the direct post-restart match test
once enrollment succeeds; 412 offline tests pass.

The ordered current-macOS comparison later decrypted exact 148-byte general
and 104-byte user secure-data payloads, then sent the general component first.
The general command `0x40` returned service status 257, so the user payload was
not sent and all seven temporary transfer/key artifacts were removed. Ordering
is therefore not the cause. The next comparison is static-only: recover the
installed daemon's exact command-`0x40` Bridge version and any accessory or
device-group preparation performed before the first general load. No further
catacomb transfer is justified until those fields are closed.

That static comparison proves the Linux load envelope was already exact:
command `0x40`, compatibility-wrapper version 1, `inValue=0`, direct `NSData`
bytes/length, no output, and no device-group argument. Status 257 is passed
through unchanged by the host; only `0x8002`, `0x8003`, and `0x192` are mapped
to daemon status `0x10d`. No installed-host symbol directly names 257, though
its prior association with unsupported enrollment groups makes missing
accessory/device-group context the leading evidence-backed interpretation.

The successful macOS boot establishes that context earlier. After Bridge
methods 0, conditional 10 with client version 2, and 1, the sensor path uses
readiness `0x53` v1 (one-byte output), provisioning state `0x10` v1 (four-byte
output; observed state 5), reset `0x02` v2, sensor info `0x35` v1 (12-byte
output), and calibration `0x20` v1 (source in `inValue`, bytes as input;
observed source 0). Patch `0x24` v1 and MSRk `0x5c` v1 are conditional and
must not be sent with guessed data. Host-side `cacheAccessories` follows
sensor initialization and immediately precedes the general load; it is not a
separate recovered Bridge command. Linux should implement/test the read-only
shapes first and recover legitimate calibration/accessory inputs before
another load. The pinned verifier is
`tools/research/macos-catacomb-load-context-evidence.py`.

Linux now implements those four evidence-backed command shapes in
`biometric-command.py`. The reset codec remains offline-only; no reset was
needed for the first bounded live observation. The source-gated
`sensor-context-probe.py` sends only readiness, provisioning-state, and
sensor-info reads and reports no opaque sensor-info bytes. On the first live
run after activating the existing internal-NCM NetworkManager profile, all
three commands succeeded: readiness was 1, provisioning state was 5, and
sensor info had the required 12-byte shape. This independently matches the
successful macOS provisioning state and proves that Linux can already reach
this portion of current sensor initialization without a catacomb transfer.
The remaining evidence gap is the exact Bridge method 5/11 calibration-source
selection and reply ABI plus how the returned legitimate bytes feed command
`0x20` and host-side accessory caching. Do not reset or reload merely to repeat
the already-successful read results.

Static inspection closes both questions and corrects one earlier inference.
Bridge methods 5 (EEPROM) and 11 (FDR) take no arguments and accept only an
exact one-object `NSData` reply; neither wrapper bounds its length. The normal
observed boot's calibration-present flag bypassed both methods and command
`0x20`, leaving source 0 for the success log. If loading is required, the
non-Gibraltar path uses method 5 then `0x20` v1/source 2, while Gibraltar uses
method 11 then `0x20` v1/source 3. The daemon forwards returned bytes and
length unchanged, so Linux must bound them and must not upload calibration
when the presence flag says it is already installed.

Accessory caching is not purely host-side. On current protocol versions above
1, `performGetBioDeviceListCommand:` sends read-only command `0x52` v1 with no
input and a 264-byte output capacity. It accepts only a bounded length
divisible by the 44-byte device-record size, then constructs accessory and
device-group objects from those records. The protocol-1 fallback synthesizes
accessory type 1/zero UUID, group type 1/zero UUID, and flags 6. Separately,
the 12-byte sensor-info result is `{uint32 version, structSize, sensorType}`;
the getter validates `structSize == 12` and returns `sensorType`. Those bytes
do not themselves construct the accessory group. A sanitized read-only
`0x52` shape probe is the next Linux comparison; calibration and catacomb
writes remain unjustified. The pinned verifier is
`tools/research/macos-calibration-accessory-evidence.py`.

Linux's bounded `0x52` read then succeeded with one 44-byte built-in
accessory/group record, completing the non-secret pre-load context. The next
authorized macOS pass reproduced the two-component encrypted transfer. Among
40 files at the two expected archive sizes, exactly two were keyed archives
and each contained one unique data object of the established secure-data
length: 148 bytes in the 599-byte general archive and 104 bytes in the
708-byte user archive. The standalone helper could not instantiate the
private archive class to freshly decode `CatacombUserID`, so selection relied
on the previously proven 599 -> UID -1 and 708 -> UID 501 mapping; this is a
documented limitation. No plaintext temporary file was created. The resulting
CMS DER envelopes are 711 and 662 bytes and both passed independent structure
parsing. Linux can now run the same-session context-plus-ordered-load
comparison and immediately remove all ephemeral artifacts.

Linux's bounded `0x52` comparison returned status zero with exactly one
44-byte record, classified as the built-in accessory and built-in device
group. No UUID or record bytes were printed or retained. This confirms the
last non-secret pre-load query on the real T2. The external two-component
loader now requires, on the same Bridge session, readiness 1, valid
provisioning and sensor-info replies, and exactly that one built-in device
record before it can issue either command `0x40`. It still contains no reset,
calibration, patch, or MSRk path.

The ordered comparison then reproduced every successful non-secret read on one
session, but the general load still returned 257 and the user load was not
sent. All temporary transfer material was removed. The next known macOS
initialization step, reset `0x02` v2, was isolated without a catacomb: three
bounded attempts all returned `0xe00002c2` (`kIOReturnBadArgument`). A local
Catalina symbolized cross-check then corrected the envelope: reset uses the
compatibility wrapper with version 1 and `inValue=2`, not explicit version 2
and value 0. The current instruction bytes have the same register setup; the
earlier analysis had assigned `ecx=2` to the wrong selector argument.

The corrected reset succeeded live on the first attempt with status zero;
sensor-info and the one-record built-in device list also succeeded afterward
on the same session. Linux therefore reproduces the entire normal
no-calibration initialization sequence through accessory caching. One final
general-then-user catacomb comparison with this corrected reset is justified.

The follow-up macOS transfer for that corrected-reset comparison completed.
The same fail-closed structural selection yielded the established 148-byte
general and 104-byte UID-501 secure-data objects; the standalone helper still
relies on the previously proven 599 -> UID -1 and 708 -> UID 501 mapping rather
than freshly decoding the private archive class. The data was streamed without
a plaintext temporary file into 721-byte and 672-byte AES-256 CMS DER
envelopes, respectively, and both passed independent CMS structure parsing.
Linux may now run exactly one corrected-reset same-session general-then-user
load and immediately remove every ephemeral transfer artifact.

That corrected-reset comparison still returned 257 on the general component,
then removed every artifact. A checksum-known Catalina cross-check recovered
the remaining `performGetBiometrickitdInfoCommand:` read as command `0x28` v1,
value 0, no input, and an exact packed 23-byte output. Its final byte at offset
22 is the calibration-present boolean. The current T2 returned status zero,
an exact 23-byte shape, and `calibration_present=True`, proving that no
calibration retrieval/upload belongs in this machine's path. Linux now places
this read between sensor info and `0x52` and refuses to load if calibration is
reported absent.

The resulting development transfer was reproduced on macOS with the same
fail-closed 599/708-byte archive and unique 148/104-byte data-object checks.
The helper still relies on the previously proven size-to-UID mapping because
the private archive class cannot be instantiated standalone. It streamed the
objects without plaintext temporary files into 727-byte global and 678-byte
user AES-256 CMS DER envelopes, both of which passed independent structure
parsing. Linux may retain only the encrypted transfer set under the documented
mode-0700/mode-0600 LUKS-home controls and must unlink plaintext after every
bounded probe.

A checksum-known Catalina `BiometricSupport` comparison then recovered two
remaining startup details. Immediately after a successful reset, the daemon
sends the already-decoded command `0x0c` version 1/value 0 cancellation; that
command succeeded on the current T2 but the following retained general
component still returned status 257. In the daemon's cold-state branch, an
absent host-side general archive instead causes `NoCatacomb(0xffffffff)` before
normal processing. Reproducing that transition also returned status zero, but
the retained general component again returned 257. Neither post-reset
cancellation nor host catacomb-map/cold-state initialization is the missing
load prerequisite.

One final bounded comparison held Linux's password-verified system keybag and
authorized ACM context alive while attempting the ordered retained load. The
fresh type-0 bag was promoted to selector `-501`, password verification
succeeded, and all teardown and independent absence checks passed. The general
component nevertheless returned status 257 before the user component could be
sent. This disproves the narrow hypothesis that command `0x40` merely requires
any currently authorized system-bag lifecycle. It does not prove that the
retained database is usable with a freshly created Linux bag: that bag is
cryptographically distinct from the established macOS login keybag under which
the retained component was created. Because migration of a macOS identity is
not the project goal, further work should return to the Linux-native empty
catacomb enrollment path and isolate the independent synchronous status 261
rather than broadening extraction of macOS key material.

The next native-enrollment comparison closed a per-connection initialization
gap. On the very Bridge session used for `NoCatacomb`, authenticated policy
creation, and command `0x03`, Linux successfully performed readiness and
provisioning reads, corrected reset, post-reset cancellation, sensor-info and
calibration-present reads, and exact one-built-in-accessory enumeration. With
the password-verified system bag and ACM context still live, command `0x03`
nevertheless returned synchronous status 261 before requesting a touch. The
temporary system and source bags were independently proven absent afterward,
the ACM context was deleted, and the SEP transport was stopped and scrubbed.
Missing same-session sensor/accessory initialization is therefore not the
remaining native-enrollment prerequisite. The next comparison should isolate
the daemon's load-completion/catacomb-state transition after its per-component
load loop; repeating command `0x03` or altering its proven authorization bytes
cannot add evidence.

Static Catalina evidence then identified `IsXARTAvailable` as read-only command
`0x4c`, with a one-byte Boolean output. Current live version discrimination
showed that command version 1 returns status zero and canonical true after the
same-session sensor initialization; versions 0 and 2 return
`kIOReturnBadArgument`. Requiring that successful read on the authorized
enrollment session still left command `0x03` at synchronous status 261. xART
is therefore online, and neither absent xART nor omission of the daemon's
availability-cache read explains the enrollment rejection. The temporary AKS
and ACM lifecycle again passed complete teardown and scrub verification.

The next read-only comparison recovered `performGetSKSLockStateCommand:` as
command `0x27`. Versions 0 and 2 returned `kIOReturnBadArgument`; version 1
returned status zero, four bytes, and state `0x15`. The exact same value was
returned while the temporary UID-501 system bag had passed password
verification. The transcript reported `authorized=yes`, so a password typo is
ruled out; no enrollment or touch occurred and teardown passed. Command
`0x27` therefore does not expose a simple missing lock-state transition for
this lifecycle. Static driver analysis separately shows that asynchronous
`sbio` lock-state records can invoke a `passcodeValidated` callback when bit
`0x20` is set, but that does not establish command-`0x27` bit `0x08` or the
observed `0x15` as an enrollment gate.

A comparison with the independently developed
[`jmurth1234/t2-touchid-linux`](https://github.com/jmurth1234/t2-touchid-linux)
project then found the first direct omission in
our enrollment-authorization sequence. That project has live Linux matching
for an already-enrolled macOS identity, while its Linux enrollment code remains
research-only. Its recovered authorization path creates the ACM tracking
context for the explicit Apple numeric UID, observes policy 1007 preflight,
binds the password to that context through AKS selector 42, evaluates the
committed `TouchIdEnrollment` policy, and passes the context to exactly one
consumer only after the policy reports satisfied. Our prior sequence created
the context with subject zero and treated successful selector-42 password
binding as sufficient; it never evaluated the enrollment policy. That is a
much stronger explanation for synchronous status 261 than further catacomb or
sensor initialization guesses.

The live probe now independently encodes that exact 51-byte ACM command and
strict response parser. Enrollment-only runs create the context with UID 501,
require the preflight result to be unsatisfied with requirement type 1, perform
the already-proven password binding, require the committed policy result to be
satisfied, and only then release the 16-byte external form to BiometricKit.
The SKS-state and catacomb-load modes leave policy evaluation disabled. An
independent journal verifier requires both policy evaluations in order around
the successful AKS reply. All 450 offline tests pass and the kernel module
builds; hardware acceptance remains deliberately unclaimed until the next
password-authorized run.

Two bounded no-touch hardware runs then evaluated that exact policy sequence.
Both created the context with UID 501 and parsed the 24-byte preflight as
unsatisfied requirement type 1, state 1, flags `0x1`, payload length 4. The
first used the initially inferred zero trailing option; a corrected static
audit and an independent upstream correction established that selector 42's
canonical plaintext-secret option is `0x200`. The second run sent only
`0x200`. In both cases AKS reported `authorized=yes`, ruling out password
entry failure, but the committed policy returned the identical unsatisfied
requirement and no credential was released. All bags and the ACM context were
then independently torn down, DMA was scrubbed, and the module was removed.
No BiometricKit command or fingerprint touch occurred.

The exact option is therefore necessary but not sufficient. The strongest
remaining discriminator is subject keybag identity: Linux authorizes a newly
created type-0 bag that it promotes to `-501`, while macOS caller handle `-3`
resolves through the established UID-501 login session. A filesystem audit
found no exported `user.kb`, other `*.kb`, or private keybag archive on Linux,
and the encrypted 128 GiB APFS container is not mountable by the existing
Linux APFS path. The next controlled step is the encrypted macOS export in
`docs/macos-keybag-export-handoff.md`, followed by a policy-only comparison
with the genuine bag. Enrollment and touch remain gated off.

That macOS export completed on build 25G83. The upstream helper's first pass
hit a candidate-list permissions bug and produced an empty-candidate archive;
its 1,658-byte CMS was rejected and deleted. A temporary external checkout was
retried with the list read through `sudo` and a fail-closed requirement for an
anonymized candidate entry. The resulting 32,042-byte CMS passed independent
structure parsing. All plaintext and temporary macOS files were removed, no
source keybag changed, and no biometric operation occurred. Linux may now run
the policy-only genuine-keybag comparison described in the dedicated handoff.

Linux validated that CMS privately, found two byte-identical 1,572-byte
`user.kb` candidates, installed one with root-only permissions, and removed
the decrypted staging tree. The GPL reference transport loaded the genuine
bag and its `-501` alias with status zero; a visible password run then unlocked
both with status zero. Its ACM policy client initially failed before password
entry because it allocated a `0x1000`-byte response for opcode `0x03`, while
the kernel transport correctly requires `0x4000`. A local one-line correction
to the separate GPL checkout made all 172 upstream tests pass and allowed the
policy request to complete. Password verification against the genuine runtime
handle returned status zero, but policy 1007 still remained unsatisfied. The
genuine keybag therefore is necessary infrastructure, not the missing policy
input by itself.

The reference matching stack was then integrated without copying GPL source
into this repository. The T2 iBridge peer is reachable over a dedicated
link-local NetworkManager profile; transport, keybag load, biometric readiness,
and the custom fprintd service all reached their expected healthy states.
`fprintd-list` reported the macOS-enrolled `right-index-finger`, but this was
only local configuration metadata. The one supervised verification attempt
returned `verify-unknown-error` before evaluating the user's touch. A direct
privacy-safe trace explained why: bridge version negotiation, sensor reset,
cancel, and FDR calibration all returned status zero, while identity-list
command `0x42` returned status zero with no identity records. The client
therefore never issued match command `0x04`; the result says nothing about the
finger presented.

The current bridge advertises biometric protocol version 1, so the reference
inventory command's attested-version-2 enrollment gate also remains closed.
Previously captured global and UID-501 catacomb blobs still returned status
257 when loaded with the genuine unlocked keybag, including after the bounded
`NoCatacomb` initialization. Those older blobs cannot establish a current
daemon session. The next controlled discriminator is a fresh macOS catacomb
export plus a warm transition with `biometrickitd` frozen, documented in
`docs/macos-live-catacomb-handoff.md`. Boot-scoped AKS caller identities will
not be blindly replayed across the operating-system transition.

The installed `fprintd.service` and `t2-biometric-ready.service` were both
enabled at boot, which would have run sensor initialization before Linux's
first post-macOS observation. Linux disabled those two units before the warm
handoff while leaving transport, genuine-keybag load, and credential unlock
enabled. They remain deliberately disabled until the immediate identity-list
comparison is complete.

A temporary boot-time one-shot now closes the remaining observation race.
`t2-warm-identity-capture.service` runs before both reset-capable units and
fails closed unless they remain disabled and inactive. It negotiates the
Bridge version and sends only read-only UID-501 identity-list command `0x42`.
The root-only result retains only status, output length, record count, and a
structural-validity Boolean; peer identifiers, identity records, UUIDs, and
biometric bytes are discarded. Static safety tests and the complete 458-test
probe suite pass.

Because disabling a D-Bus service does not prevent explicit activation, both
reset-capable units also received a temporary condition requiring the absent
runtime marker `/run/t2-touchid/allow-reset-capable-services`. This preserves
any warm identity after the automatic capture until the supervised comparison.

The fresh macOS live-Catacomb export then passed the exact three-component
gate on build 25G83. The initial upstream checker decoded every component but
its neutral user round-trip failed because its deterministic encoder emitted
unreachable identity/accessory helpers for the valid zero-identity host graph.
A narrow fix in the temporary external GPL checkout preserved that already
validated graph while retaining strict primary and independent-oracle
readback; all 19 relevant tests passed. The guarded retry reported
`identity_count=0`, passed semantic equality and binding/envelope preservation,
and produced a 1,946-byte AES-256 CMS DER envelope that independently parsed.
All plaintext and temporary macOS files were removed. The encrypted artifact
now permits Linux to compare the fresh complete host state after its automatic
warm-transition read-only capture.

Linux's guarded warm-transition service completed before either reset-capable
biometric unit. Its initial cached-port connection raced interface assignment,
then its bounded discovery retry succeeded. The privacy-safe record was valid
but contained zero UID-501 identities. This matches the fresh macOS host
archive itself, whose strictly decoded identity list is also empty; the warm
reboot did not lose an archived identity because no archived identity existed.

Linux decrypted the 1,946-byte CMS only in a mode-0700 LUKS-home staging
directory and revalidated the exact three-component archive. The fresh master
and UID-501 secure envelopes are byte-identical to the older retained envelopes
that returned load status 257, while the newly included bio-lockout component
also passed its strict codec. A root-only hash-addressed backup remains under
`/var/lib/t2-touchid/backups`; no plaintext, component digest, UUID, or secure
envelope was printed or committed.

The current T2's stable read-only inventory identifies a different enrollment
shape from the reference project's proven protocol-2 machine. Direct protocol
query `0x01` returns exact `kIOReturnBadArgument` with a four-byte zero output,
global identity command `0x51` returns bkremoted's exact nil sentinel, and the
UID-501 list is likewise nil/empty. Capacity remains available (device maximum
five, configured-user free three). Catacomb hash state reports the selected
component absent, while `0x3c` still returns unique master and UID-501 state
records. SKS state remains `0x15`. The prior enrollment broker therefore failed
preflight because it required protocol 2, a global identity inventory, and an
already-present SEP Catacomb—not because the macOS export was invalid.

The separate GPL reference checkout is now based on upstream commit `936a980`
and has a local Linux branch `t2-v1-first-enrollment` at commit `703b287`.
That checkpoint adds fail-closed protocol-1 attestation and exact nil handling,
permits only the zero-identity/absent-Catacomb baseline, emits four-byte
protocol-1 user/master persistence descriptors, allows the successful first
enrollment to transition the SEP Catacomb from absent to present, and preserves
failure/no-change reconciliation. Its zero-identity codec preserves the
validated keyed-archive graph for neutral replacement and constructs canonical
built-in accessory metadata only behind an explicit built-in-enrollment gate.
The real decrypted macOS zero-identity component passed both the neutral and
first-identity offline paths. All 274 dependency-independent tests, Python
compilation, privacy scan, kernel-module build, and userspace-tool build pass;
the one unrun fprintd test imports an unavailable optional `dbus-next` package
and covers unchanged code. No GPL source was copied into this MIT repository.

Upstream also supplies the critical ACM correction absent from our earlier
status-261 experiments: after creating and preflighting the context it sends
ACM externalization opcode `0x13`, then binds the password, evaluates policy
1007, and releases the external form only when policy is satisfied. The latest
userspace and next-boot kernel module are staged locally, but the running kernel
still holds the older pinned module and cannot be safely unloaded. Before any
fingerprint touch, Linux must first install the protocol-1 checkpoint, pass a
read-only enrollment preflight, reboot once to load the opcode-`0x13`-capable
module, and run a password-authorized no-enrollment policy control. Only after
those gates pass may one explicitly supervised enrollment begin. PAM remains
out of scope until enrollment, durable readback, reboot persistence, and match
all succeed.

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
