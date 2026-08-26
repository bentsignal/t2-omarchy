# T2 SEP read-only PCI probe

This is milestone zero of the Touch ID bring-up plan. It binds only to Apple
PCI device `106b:1802`, permits `MacBookPro16,1` by default, and reports the
PCI configuration and BAR resources already enumerated by the kernel.

By default it does **not** call `pci_enable_device()`, request or map BARs,
register interrupts, configure DMA, or write PCI/MMIO state. It cannot yet
communicate with the SEP or authenticate a fingerprint.

An explicitly enabled second-stage probe maps BAR4 and reads only the
hypothesized T8012 mailbox send/receive status registers. The offsets come from
checkra1n/PongoOS's 32-bit SEP mailbox layout. It does not read the receive
payload, enable interrupts, acknowledge anything, or send a message.

Build against the running kernel:

```bash
make
modinfo ./t2sep_probe.ko
```

Before loading, confirm the SEP function is still unbound:

```bash
readlink /sys/bus/pci/devices/0000:04:00.2/driver || true
```

Load, inspect, and unload interactively:

```bash
sudo insmod ./t2sep_probe.ko
sudo journalctl -k -n 30 --no-pager
sudo rmmod t2sep_probe
```

The first reversible state-changing experiment temporarily enables PCI memory
decoding through the kernel's normal PCI API, scans the status candidates, and
disables the function before probe returns. Because firmware left this
function's PCI command word enabled despite Linux's enable refcount being zero,
the probe saves and restores that word exactly:

```bash
sudo insmod ./t2sep_probe.ko temporarily_enable_device=1 scan_apertures=1
sudo rmmod t2sep_probe
```

Run the separately gated status-register experiment with:

```bash
sudo insmod ./t2sep_probe.ko read_mailbox_status=1
sudo journalctl -k -n 30 --no-pager
sudo rmmod t2sep_probe
```

If status bit `0x20000` is clear, PongoOS treats the receive mailbox as
non-empty. The next gate consumes and decodes at most one inbound message. It
still performs no MMIO write, but unlike the status-only probe this read may
advance the hardware receive FIFO:

```bash
sudo insmod ./t2sep_probe.ko read_mailbox_status=1 read_one_message=1
sudo rmmod t2sep_probe
```

If BAR4 is inert, the status-only aperture comparison reads the same PongoOS
status offsets in each PCI BAR. It does not read a payload:

```bash
sudo insmod ./t2sep_probe.ko scan_apertures=1
sudo rmmod t2sep_probe
```

Do not install this in the initramfs or configure it for automatic loading.
The PCI address may differ on another boot or machine; the device ID and DMI
allowlist, not the example address, are the safety checks.
