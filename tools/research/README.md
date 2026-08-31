# Bounded research helpers

`macos-objc-methods.m` is a macOS-only, read-only shared-cache inspection
helper. It loads one framework and prints Objective-C method type encodings,
implementations, and image-relative offsets. Optional environment selectors
can print selector references, known NSString constants, or copy code bytes to
`/tmp/macos-objc-method.bin` for offline disassembly. It never invokes the
reported methods or reads their object state:

```bash
clang -fobjc-arc -framework Foundation \
  tools/research/macos-objc-methods.m -o /tmp/macos-objc-methods
MACOS_OBJC_PRINT_SELECTORS='parseAuthDict:toAuthData:' \
  /tmp/macos-objc-methods \
  /System/Library/PrivateFrameworks/BiometricSupport.framework/BiometricSupport \
  BiometricKitXPCServer parseAuthDict:
```

Run memory-heavy research commands through `run-bounded.sh`. It creates a
separate systemd user scope capped at 1 GiB RAM, 256 MiB swap, and 64 tasks, so
an unexpectedly hungry decoder or disassembler is killed without taking the
terminal session with it:

```bash
tools/research/run-bounded.sh command arg1 arg2
```

For a command known to need a different ceiling, override only that invocation:

```bash
T2_RESEARCH_MEMORY_MAX=2G T2_RESEARCH_SWAP_MAX=1G \
  tools/research/run-bounded.sh command arg1 arg2
```

Each archive payload must be launched through the helper separately. Wrapping
an entire loop in one scope allows retained memory to accumulate across loop
iterations and defeats that isolation.

`capture-macos-bridge.sh` is a read-only collector for the small set of
installed macOS artifacts needed to resolve the remaining current-version
bridge question. Run it from macOS with an output directory on a volume that
Linux can later read:

```bash
tools/research/capture-macos-bridge.sh /path/to/output-directory
```

It does not use `sudo`, inspect fingerprint templates, modify the sealed system
volume, start a biometric operation, or connect to the T2. It copies the host
biometric and `remoted` daemons when readable, their launchd plists, framework
version plists, dependency/signature metadata, OS build information, and
checksums.

`macos-biometric-evidence.py` verifies the coupled current Intel route in an
extracted thin x86_64 `biometrickitd`: RemoteServiceDiscovery, BridgeXPC, the
named BiometricKit services, and the two connection selectors. It also requires
the embedded `bkremoted` connection, transport, and services classes plus their
synchronous/asynchronous send and envelope/event handlers. This identifies the
post-discovery implementation boundary without claiming a wire layout. It
performs no device or network access and can pin a known installed-slice SHA-256.
The required selectors include current bridge methods 0, 1, and 3. Their
disassembled bodies establish the logical request and reply shapes documented
in `docs/touch-id.md`.

`macos-biometric-command-evidence.py` verifies the older Catalina 19H15 Intel
operation ABI against both `biometrickitd` and `BiometricSupport`. It requires
unique address-independent instruction runs for the zeroed 68-byte match
input, match command `4`, presence command `0x26`, cancel command `0x0c`, and
the legacy wrapper's command version `1`. It also pins the match-result branch
that treats first-dword user ID `0xffffffff` as no-match. The companion
framework establishes
the initialized `0xffffffff` user IDs and zero-initialized processed flags.
It reads ordinary files only and never contacts the sensor:

```bash
python tools/research/macos-biometric-command-evidence.py \
  /path/to/usr/libexec/biometrickitd \
  /path/to/BiometricSupport.framework/Versions/A/BiometricSupport
```

`extract-legacy-dyld-image.py` reconstructs one named 32-bit Mach-O from the
old unslid dyld-cache format used by bridgeOS 3 recovery firmware. It accepts
only bounded tables/mappings/segments, requires one exact image-path match,
supports only little-endian 32-bit Mach-O segments, rewrites each section's
cache-relative file offset into the reconstructed image, and creates a new
mode-0600 output without overwriting. It exists because modern dyld-cache
tooling rejects the cache magic `dyld_v1  armv7k`.

`sep-endpoint-abi-evidence.py` verifies why the Intel generic-transfer record's
third word must remain an explicit unknown. In x86_64 AppleSEPManager, the
endpoint forwards two pointers but `_sendMessageGated` ignores the second and
copies a qword plus the following dword from the first pointer. The available
arm64e GenericTransfer instead stores only a qword and calls its architecture's
endpoint with `(&qword, nullptr, true)`. Cross-architecture code therefore
cannot prove the Intel dword is zero:

```bash
python tools/research/sep-endpoint-abi-evidence.py \
  /path/to/x86_64/AppleSEPManager \
  /path/to/arm64e/AppleSEPGenericTransfer
```

`bridgeos-bkremoted-evidence.py` verifies the extracted armv7k bridge daemon
from bridgeOS 3.0 (`14Y910`). Its exact method-zero implementation stores
bridge version `2` when given an output pointer, clears the client-version
field, and returns status zero. A second unique sequence pins the dispatch
range covering methods 0 through 10. This proves the historical bridgeOS
server has no enrollment, service-open, or method-10 prerequisite for method
0; it does not claim that this old daemon is byte-identical to current
bridgeOS.

`bridgeos106-bkremoted-evidence.py` verifies the exact arm64 daemon recovered
from the current bridgeOS 10.6 (`23P6068`) IPSW. It pins the unconditional
status-zero/version-three implementation, its two-`NSNumber` reply wrapper,
and direct method-zero jump-table dispatch:

```bash
python tools/research/bridgeos106-bkremoted-evidence.py /path/to/bkremoted \
  --expect-sha256 \
  29b99cb5ba41ef18122d1920986707d5fc7893bf097e343d41f4ec0a87b32630
```

`bridgeos-bridgexpc-evidence.py` verifies the corresponding historical
armv7k BridgeXPC framework. It pins the connection transition from state 2 to
state 3 followed by `writeHELO`, `readMessage`, and `flushQueue`; the send
dispatch that queues in states 1/2 and writes in state 3; and the receive
dispatch for kind 1 HELO versus kind 2 ordinary messages. The HELO arm asks
Foundation to deserialize the JSON with option 4 and logs the result, with no
field comparison or state mutation before returning to the common read loop:

```bash
python tools/research/bridgeos-bridgexpc-evidence.py /path/to/BridgeXPC \
  --expect-sha256 df97ee9ee6f37383303e153bc92f3528f1478fa1268f89b50c5e666c747c3b37
```

`bridgeos39-bridgexpc-evidence.py` verifies the same four paths against the
current arm64 BridgeXPC 39 extracted from Apple's exact bridgeOS 10.6
`23P6068` restore image. The current receiver retains the historical state
machine: connection writes HELO, starts reading, and flushes its queue; states
1/2 queue while state 3 writes; kind 1 merely decodes/logs HELO and rejoins the
read loop; kind 2 is dispatched immediately. This removes the former caveat
that only bridgeOS 3 receiver behavior was available:

```bash
python tools/research/bridgeos39-bridgexpc-evidence.py /path/to/BridgeXPC \
  --expect-sha256 f72baee6445b2d894e49b889055aebd57318332afdb5c11f24df4f7474cd002a
```

`xnu-intcoproc-evidence.py` verifies the relevant path for Darwin's private
`SO_INTCOPROC_ALLOW` option in an Apple XNU source tree. The option is an
entitlement-gated local PCB flag that permits traffic on an otherwise
restricted internal-coprocessor interface. It is not a TCP option or an
application-visible handshake signal, so Linux needs no wire analogue once it
can already exchange packets on the T2 interface:

```bash
python tools/research/xnu-intcoproc-evidence.py /path/to/xnu
```

`macos-bridgexpc-evidence.py` verifies the current thin x86_64 BridgeXPC
framework's exact HELO/message header loads, binary-plist format load, HELO
keys, and serialization import. It rejects the wrong architecture, duplicate
or missing instruction evidence, and checksum drift. It performs no device or
network access:

```bash
python tools/research/macos-bridgexpc-evidence.py /path/to/BridgeXPC \
  --expect-sha256 EXPECTED_SHA256
```

`macos-bridge-wire-compare.py` is the private-capture boundary for the two
initial client writes. It accepts one complete client HELO frame and one
complete method-zero frame only from regular mode-0600 files, strictly decodes
both, and compares them with the Linux reconstruction. Its output is limited
to sizes, SHA-256 hashes, decoded non-private HELO fields, equality flags, and
first-difference offsets; it never prints the captured bytes.

`macos-rsd-port-evidence.py` verifies the companion x86_64 `remoted` evidence:
the NCM-device listener class/method and its unique exact instruction storing
port `58783`. It likewise performs no device or network access.

`macos-rsd-service-socket-evidence.py` verifies the Catalina Intel
RemoteServiceDiscovery client handoff. The exact function sends only local XPC
keys `cmd=connect` and `connect_timeout` to a service-specific endpoint,
duplicates the returned `fd`, and only polls that descriptor before giving it
to BridgeXPC. It does not prove what `remoted` does before returning the fd,
but proves the client framework adds no post-handoff activation bytes.

`macos-multiverse-service-connect-evidence.py` closes the daemon side of that
gap for the installed macOS 26.6.2 Intel `remoted`. It verifies
`RSDRemoteMultiverseDevice::connectToService:withTcpOption:` converts the
directory's port string and calls either `multiverse_device_connect` or its
timeout variant directly. There is no service-specific network preamble in
that method. `macos-biometric-evidence.py` additionally pins the current
daemon's setup order: method 0 (`getBridgeVersion:`) precedes method 10
(`setBridgeClientVersion:2`), so method 10 cannot unlock the first reply.

`macos-catacomb-load-context-evidence.py` pins the installed 25G83 daemon's
current command-`0x40` call shape and its sensor-preparation implementations.
It proves version 1, `inValue=0`, direct `NSData` bytes/length, no output, and
that service status 257 passes through unchanged. It also verifies the
readiness, optional patch, provisioning-state, reset, sensor-info,
calibration, and optional MSRk command shapes without reading a device or any
catacomb data.

`macos-calibration-accessory-evidence.py` pins the current calibration
retrieval methods 5/11, the three-field 12-byte sensor-info cache, and the
generation-3 read-only bio-device-list command `0x52`. It checks the daemon
SHA-256 plus the dyld-cached BiometricSupport UUID and `__TEXT,__text`
SHA-256, including the exact 44-byte built-in accessory/device-group record
construction. It reads only installed executable code through `dyld_info`.

`capture-macos-enrollment-bridge.sh` is the narrow cross-OS discriminator for
the remaining pre-touch command-3 rejection. On macOS it captures only network
interfaces whose Ethernet address is in the T2 `ac:de:48` range during one
bounded Add Fingerprint ceremony. The output directory is private and may
contain a live ACM external form, identifiers, and biometric service payloads;
never commit or copy its raw pcaps or logs. The script automatically runs
`sanitize-macos-enrollment-pcap.py` on each pcap. That offline sanitizer
reassembles bounded IPv6/TCP streams, validates BridgeXPC and binary-plist
framing, and emits only command order, public command/version/value, lengths,
synchronous status, callback-header metadata, and redacted structural checks.
It never emits raw credential, UUID, callback, address, port, or packet bytes.

```bash
tools/research/capture-macos-enrollment-bridge.sh \
  "$HOME/t2-enrollment-private-$(date +%Y%m%d-%H%M%S)"
```

Review only the resulting `*-sanitized-enrollment.json` through the macOS
thread. Keep the entire private directory out of Git even after sanitization;
commit only reproducible tooling and prose conclusions.

`capture-t2ncm-usb-startup.sh` captures one bounded Linux rebind from below
the transient network interface using binary `usbmon7`. It accepts only the
exact private output path, requires the exact bound `7-1:1.0` function, and
restores `cdc_ncm` through an exit trap. Its pcap can contain internal T2 frame
payloads and must not be committed. The first supervised capture contained
only the T2's complete MLDv2 report and no DNS-SD advertisement.

`capture-t2ncm-device-reset.sh` and `t2ncm-device-reset.py` model the narrower
follow-up distinction between interface rebind and a whole USB-device reset.
They validate the exact `05ac:8233` singleton below PCI `0000:04:00.1`, accept
only a private fixed capture path, and keep the reset source-disabled. A
supervised attempt showed that `t2bce_vhci` rejects `USBDEVFS_RESET` with
`EPERM` even for root after an exact unbind; the exit trap restored both NCM
interfaces. The generic usbfs route therefore cannot perform this transition.

`capture-t2ncm-reauthorize.sh` tests the supported broader alternative. It
temporarily changes only the exact T2 USB device's authorization state under an
exit trap, captures the resulting all-function enumeration, and verifies both
NCM interfaces recover. Its live switch remains false. The supervised capture
again contained only solicited-node MLDv2 traffic; subsequent healthy-link
multicast and direct RSD queries both timed out.

`pbzx-stream.py` incrementally decodes the PBZX payload inside older macOS
installer packages. It exists because a whole-payload decoder expanded a
roughly 15 GB archive in memory and caused `systemd-oomd` to kill the terminal
scope. The decoder rejects any compressed or expanded chunk above 256 MiB and
gives liblzma a 512 MiB memory limit.

`decode-complzvn.c` strictly unwraps an Apple `complzvn` prelinked kernel using
an external `lzvn_decode` implementation. It caps compressed input at 256 MiB
and output at 512 MiB, validates the wrapper's exact file length, refuses to
replace or follow the output path, and requires a decoded Mach-O signature.
This avoids the legacy LZVN CLI wrapper, whose malformed-input path double-
frees memory. The decoded Catalina 19H15 prelinked kernel was inspected without
committing it; its prelink manifest does not contain an x86_64
AppleSEPGenericTransfer image.

For an additional process-level ceiling, run archive work in its own user
scope and stream only selected paths to `bsdtar`:

```bash
T2_RESEARCH_MEMORY_MAX=2G T2_RESEARCH_SWAP_MAX=1G \
  tools/research/run-bounded.sh \
  bash -c 'python tools/research/pbzx-stream.py < Payload | \
    bsdtar -xpf - -C output "path/to/selected/file"'
```

This helper only transforms files supplied on stdin. It does not download an
installer or access T2 hardware.
