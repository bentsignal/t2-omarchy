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
