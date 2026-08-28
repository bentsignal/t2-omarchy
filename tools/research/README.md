# Bounded research helpers

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
the legacy wrapper's command version `1`. The companion framework establishes
the initialized `0xffffffff` user IDs and zero-initialized processed flags.
It reads ordinary files only and never contacts the sensor:

```bash
python tools/research/macos-biometric-command-evidence.py \
  /path/to/usr/libexec/biometrickitd \
  /path/to/BiometricSupport.framework/Versions/A/BiometricSupport
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
