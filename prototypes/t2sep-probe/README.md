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

Run the separately gated status-register experiment with:

```bash
sudo insmod ./t2sep_probe.ko read_mailbox_status=1
sudo journalctl -k -n 30 --no-pager
sudo rmmod t2sep_probe
```

Do not install this in the initramfs or configure it for automatic loading.
The PCI address may differ on another boot or machine; the device ID and DMI
allowlist, not the example address, are the safety checks.
