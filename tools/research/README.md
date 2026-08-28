# Bounded research helpers

`pbzx-stream.py` incrementally decodes the PBZX payload inside older macOS
installer packages. It exists because a whole-payload decoder expanded a
roughly 15 GB archive in memory and caused `systemd-oomd` to kill the terminal
scope. The decoder rejects any compressed or expanded chunk above 256 MiB and
gives liblzma a 512 MiB memory limit.

For an additional process-level ceiling, run archive work in its own user
scope and stream only selected paths to `bsdtar`:

```bash
systemd-run --user --scope --quiet \
  -p MemoryMax=2G -p MemorySwapMax=1G \
  bash -c 'python tools/research/pbzx-stream.py < Payload | \
    bsdtar -xpf - -C output "path/to/selected/file"'
```

This helper only transforms files supplied on stdin. It does not download an
installer or access T2 hardware.
