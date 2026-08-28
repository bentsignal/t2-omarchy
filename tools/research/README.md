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

`macos-rsd-port-evidence.py` verifies the companion x86_64 `remoted` evidence:
the NCM-device listener class/method and its unique exact instruction storing
port `58783`. It likewise performs no device or network access.

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
